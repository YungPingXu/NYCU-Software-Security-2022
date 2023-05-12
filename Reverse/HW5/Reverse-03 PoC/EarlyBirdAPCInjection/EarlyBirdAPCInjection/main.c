#include "err.h"

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

int main(int argc, char** argv) {
    CHAR sTargetPath[] = "<Path to TargetApp.exe>";
    CHAR sDllName[] = "meow_dll.dll";
    CHAR sDllPath[100];
    memset(sDllPath, 0, sizeof(sDllPath));
    GetTempPathA(100, sDllPath);
    memcpy(sDllPath + strlen(sDllPath), sDllName, strlen(sDllName));
    printf("[+] Dll path: %s\n", sDllPath);

    /* Create remote process */
    STARTUPINFOA StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    memset(&StartupInfo, 0, sizeof(StartupInfo));
    memset(&ProcessInfo, 0, sizeof(ProcessInfo));
    CreateProcessA(0, sTargetPath, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &StartupInfo, &ProcessInfo);
    if (!ProcessInfo.hProcess) ERR("CreateProcessA");

    /* Allocate space on remote process */
    PVOID pRemoteBuffer = VirtualAllocEx(ProcessInfo.hProcess, NULL, sizeof(sDllPath), MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuffer) {
        ERR("VirtualAllocEx failed!");
    }
    printf("[+] Retmoe buffer: 0x%llx\n", pRemoteBuffer);

    /* Write the dll path to the space */
    if (!WriteProcessMemory(ProcessInfo.hProcess, pRemoteBuffer, sDllPath, sizeof(sDllPath), NULL)) {
        ERR("WriteProcessMemory failed!");
    }

    /* Get the LoadLibraryA function pointer */
    FARPROC fpLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!fpLoadLibraryA) {
        ERR("LoadLibraryA_ptr failed!");
    }
    printf("[+] LoadLibraryA: 0x%llx\n", fpLoadLibraryA);

    /* Register APC callback to trigger LoadlibraryA(dll_path) */
    QueueUserAPC(fpLoadLibraryA, ProcessInfo.hThread, pRemoteBuffer);

    /* Resume Thread */
    if (!ResumeThread(ProcessInfo.hThread)) ERR("ResumeThread");

    WaitForSingleObject(ProcessInfo.hThread, INFINITE);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);

    return 0;
}
