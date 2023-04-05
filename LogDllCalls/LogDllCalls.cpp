#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <shlwapi.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <cassert>
#include <detours/detours.h>

#include <asmjit/asmjit.h>

using namespace asmjit;

typedef void(_stdcall* LogFunction)();

std::vector<void*> logFunctions;
std::vector<void*> hookFunctions;

void WINAPI Log(const char* pFunctionName)
{
	if (strcmp(pFunctionName, "GetLastError") == 0
         || strcmp(pFunctionName, "SetLastError") == 0
         || strcmp(pFunctionName, "WSAGetLastError") == 0
         || strcmp(pFunctionName, "WSASetLastError") == 0)
	{
		return;
	}

	char logLine[4096] = "";
	strcpy_s(logLine, pFunctionName);
	strcat_s(logLine, "\n");

	OutputDebugString(logLine);
}

void* AllocateLogFunctionBuffer()
{
	void* logFunctionBuffer = nullptr;

	VirtMem::alloc(&logFunctionBuffer, 4096, VirtMem::kAccessWrite | VirtMem::kAccessExecute);

	return logFunctionBuffer;
}

LogFunction GenerateLogFunction(void* pLogFunctionBuffer, const char* pFunctionName, void** ppOriginal)
{
	size_t functionNameLength = strlen(pFunctionName);

	char* pFunctionNameCopy = new char[functionNameLength + 1];
	strcpy_s(pFunctionNameCopy, functionNameLength + 1, pFunctionName);

	CodeHolder codeHolder;
	codeHolder.init(hostEnvironment());

	x86::Assembler assembler(&codeHolder);

	assembler.push(pFunctionNameCopy);
	assembler.call(Log);
	assembler.mov(x86::ecx, ppOriginal);
	assembler.mov(x86::eax, x86::ptr(x86::ecx));
	assembler.jmp(x86::eax);

	codeHolder.relocateToBase((uint64_t)pLogFunctionBuffer);

	const Section* pSection = codeHolder.sections()[0];
	const uint8_t* pSectionData = pSection->data();
	const size_t bufferSize = pSection->bufferSize();

	std::memcpy(pLogFunctionBuffer, pSectionData, bufferSize);

	return (LogFunction)pLogFunctionBuffer;
}

std::vector<std::string> GetExportedFunctions(HMODULE lib)
{
	std::vector<std::string> exportedFunctions;

	assert(((PIMAGE_DOS_HEADER)lib)->e_magic == IMAGE_DOS_SIGNATURE);
	PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)((BYTE*)lib + ((PIMAGE_DOS_HEADER)lib)->e_lfanew);
	assert(header->Signature == IMAGE_NT_SIGNATURE);
	assert(header->OptionalHeader.NumberOfRvaAndSizes > 0);
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)lib + header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (exports->AddressOfNames == 0)
	{
		return exportedFunctions;
	}

	assert(exports->AddressOfNames != 0);
	BYTE** names = (BYTE**)((int)lib + exports->AddressOfNames);

	for (DWORD i = 0; i < exports->NumberOfNames; i++)
	{
		auto exportedFunction = std::string((char*)lib + (int)names[i]);
		exportedFunctions.push_back(exportedFunction);
	}

	return exportedFunctions;
}

HMODULE GetLoadedModule(const std::string& moduleFileName)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());

	if (hProcess == NULL)
	{
		return NULL;
	}

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				std::string currentModuleFileName(PathFindFileName(szModName));

				if (currentModuleFileName == moduleFileName)
				{
					return hMods[i];
				}
			}
		}
	}

	CloseHandle(hProcess);

	return NULL;
}

bool HookDll(const std::string& moduleFileName)
{
	HMODULE hModule = GetLoadedModule(moduleFileName);

	if (hModule == NULL)
	{
		return false;
	}

	auto exportedFunctions = GetExportedFunctions(hModule);

	for (const auto& exportedFunction : exportedFunctions)
	{
		void* pLogFunction = AllocateLogFunctionBuffer();
		logFunctions.push_back(pLogFunction);

		auto hookFunction = GetProcAddress(hModule, exportedFunction.c_str());
		hookFunctions.push_back(hookFunction);
	}

	for (size_t i = 0; i < hookFunctions.size(); i++)
	{
		GenerateLogFunction(logFunctions[i], exportedFunctions[i].c_str(), &hookFunctions[i]);
	}

	for (size_t i = 0; i < hookFunctions.size(); i++)
	{
		DetourAttach(reinterpret_cast<void**>(&hookFunctions[i]), logFunctions[i]);
	}

	return true;
}

void Unhook()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	for (size_t i = 0; i < hookFunctions.size(); i++)
	{
		DetourDetach(reinterpret_cast<void**>(&hookFunctions[i]), logFunctions[i]);
	}

	DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (DetourIsHelperProcess())
	{
		return TRUE;
	}

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		char exePath[MAX_PATH];
		GetModuleFileNameA(NULL, exePath, _countof(exePath));

		char* exeFileName = PathFindFileNameA(exePath);

		std::string message("DLL_PROCESS_ATTACH: " + std::string(exePath));
		MessageBoxA(NULL, message.c_str(), ".", MB_OK);

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		if (!HookDll("WS2_32.dll"))
		{
			MessageBoxA(NULL, "HookDll failed", "", MB_OK);
			break;
		}

		if (DetourTransactionCommit() == NO_ERROR)
		{
			MessageBoxA(NULL, "DetourTransactionCommit successful", "", MB_OK);
		}

		break;
	}
	case DLL_PROCESS_DETACH:
	{
		Unhook();
		break;
	}
	}
	return TRUE;
}