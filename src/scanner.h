#pragma once
#include <windows.h>
#include <tlhelp32.h>
struct ModuleInfo{
    ULONGLONG baseAddr;
    ULONGLONG size;
};
DWORD FindProcessid(const wchar_t* processName);
ModuleInfo GetModuleInfo(const wchar_t* moduleName, DWORD pid);
ULONGLONG FindPatternEx(HANDLE hProc, BYTE* pattern, const char* mask, SIZE_T patternSize, ULONGLONG start, ULONGLONG end);
