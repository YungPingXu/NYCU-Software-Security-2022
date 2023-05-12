#include "pch.h"

VOID MyFunction0() {
    puts("[+] MyFunction0()");
}

VOID MyFunction1() {
    puts("[+] MyFunction1()");
}

VOID MyFunction2() {
    puts("[+] MyFunction2()");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        puts("[+] DLL_PROCESS_ATTACH");
        break;
    case DLL_THREAD_ATTACH:
        puts("[+] DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        puts("[+] DLL_THREAD_DETACH");
        break;
    case DLL_PROCESS_DETACH:
        puts("[+] DLL_PROCESS_DETACH");
        break;
    }
    return TRUE;
}

