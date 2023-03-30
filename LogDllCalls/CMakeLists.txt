cmake_minimum_required(VERSION 3.14)

add_library(
    LogDllCalls
    SHARED
    "LogDllCalls.cpp"
    "LogDllCalls.def"
)

find_path(DETOURS_INCLUDE detours/detours.h)
find_library(DETOURS_LIBRARY NAMES detours)
find_package(asmjit CONFIG REQUIRED)

target_include_directories(LogDllCalls PRIVATE ${DETOURS_INCLUDE})
target_link_libraries(LogDllCalls PRIVATE ws2_32 Shlwapi ${DETOURS_LIBRARY} asmjit::asmjit)

add_executable(Injector "Injector.cpp")
target_include_directories(Injector PRIVATE ${DETOURS_INCLUDE})
target_link_libraries(Injector PRIVATE ${DETOURS_LIBRARY} LogDllCalls)  