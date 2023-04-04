#define WIN32_LEAN_AND_MEAN

#include <string>

#include <windows.h>
#include <detours\detours.h>

std::string ExePath()
{
	char moduleFilePath[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, moduleFilePath, MAX_PATH);
	std::string::size_type pos = std::string(moduleFilePath).find_last_of("\\/");
	return std::string(moduleFilePath).substr(0, pos);
}

int main(int argc, char** argv)
{
	if (argc == 1)
	{
		return 0;
	}

	auto exePath = ExePath();
	auto dllPath = exePath + "\\LogDllCalls.dll";

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	char cmdLine[MAX_PATH];
	strcpy_s(cmdLine, argv[1]);

	const char* detourDlls[] = { dllPath.c_str(), "WS2_32.dll" };

	DetourCreateProcessWithDllsA(
		NULL,
		cmdLine,
		NULL,
		NULL,
		FALSE,
		CREATE_DEFAULT_ERROR_MODE,
		NULL,
		NULL,
		&si,
		&pi,
		_countof(detourDlls),
		detourDlls,
		NULL
	);

	WaitForSingleObject(pi.hProcess, INFINITE);

	return 0;
}