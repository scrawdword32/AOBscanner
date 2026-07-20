#include "scanner.h"
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
using namespace std;

int main(){
    wchar_t programName[256];
    wcout << "please, enter the name of the program: ";
    wcin >> programName;
    DWORD PID = FindProcessid(programName);
    ModuleInfo info = GetModuleInfo(programName,PID);
    cout << "start address: 0x" << info.baseAddr << endl;
    cout << "end address: 0x" << info.baseAddr + info.size << endl;
    return 0;
}
