#include "scanner.h"
#include <iostream>
using namespace std;

DWORD FindProcessid(const wchar_t* processName){
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if(!Process32FirstW(hSnap, &pe)){
        cout << "Не удалось взять первый процесс" << endl;
        CloseHandle(hSnap);
        return 0;
    }
    do {
        if (wcscmp(processName, pe.szExeFile) == 0){
            CloseHandle(hSnap);
            return pe.th32ProcessID;
        } 
    } while(Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
    return 0;
}
ModuleInfo GetModuleInfo(const wchar_t* moduleName, DWORD pid) {
    ModuleInfo info = {0, 0};
    HANDLE hSnaproc = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,pid);
    if(hSnaproc==INVALID_HANDLE_VALUE) return info;
    MODULEENTRY32W me;
    me.dwSize = sizeof(MODULEENTRY32W);
    if(!Module32FirstW(hSnaproc,&me)){
        cout << "Не возможно снять первый модуль" << endl;
        CloseHandle(hSnaproc);
        return info;
    }
    do{
        if(wcscmp(moduleName,me.szModule)==0){
            CloseHandle(hSnaproc);
            info.baseAddr = (ULONGLONG)me.modBaseAddr;
            info.size = me.modBaseSize;
            break;
        }
    } while(Module32NextW(hSnaproc,&me));
    CloseHandle(hSnaproc);
    return info;
}
ULONGLONG FindPatternEx(HANDLE hProc, BYTE* pattern, const char* mask, SIZE_T patternSize,ULONGLONG start,ULONGLONG end) {

    MEMORY_BASIC_INFORMATION mbi;
    BYTE buffer[4096];

    for (ULONGLONG addr = start; addr < end; ) {
        if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
            addr += 4096;
            continue;
        }

        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE)) {

            for (ULONGLONG offset = 0; offset < mbi.RegionSize; offset += sizeof(buffer) - patternSize + 1) {
                SIZE_T bytesToread = (mbi.RegionSize-offset>sizeof(buffer)) ? sizeof(buffer) : (mbi.RegionSize-offset);
                SIZE_T bytesRead;
                if (!ReadProcessMemory(hProc, 
                                       (LPCVOID)((ULONGLONG)mbi.BaseAddress + offset),
                                       buffer, 
                                       bytesToread, 
                                       &bytesRead)) {
                    break;
                }

                if (bytesRead == 0) break;

                for (SIZE_T i = 0; i <= bytesRead - patternSize; i++) {
                    bool found = true;
                    for (SIZE_T j = 0; j < patternSize; j++) {
                        if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                            found = false;
                            break;
                        }
                    }
                    if (found) {
                        return (ULONGLONG)mbi.BaseAddress + offset + i;
                    }
                }
            }
        }

        addr += mbi.RegionSize;
    }

    return 0;
}
