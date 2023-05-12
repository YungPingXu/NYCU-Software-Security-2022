#include "err.h"

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

INT GetPidByName(WCHAR* wcProcName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    INT dwPid = -1;
    BOOL hResult;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == -1) ERR("CreateToolhelp32Snapshot");

    pe.dwSize = sizeof(PROCESSENTRY32);

    hResult = Process32First(hSnapshot, &pe);

    while (hResult) {
        if (wcscmp(wcProcName, pe.szExeFile) == 0) {
            dwPid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }

    CloseHandle(hSnapshot);
    return dwPid;
}

int main(int argc, char** argv) {
    CHAR sDllName[] = "meow_dll.dll";
    CHAR sDllPath[100];
    memset(sDllPath, 0, sizeof(sDllPath));
    GetTempPathA(100, sDllPath);
    memcpy(sDllPath + strlen(sDllPath), sDllName, strlen(sDllName));

    INT pid = GetPidByName(L"TargetApp.exe");
    if (pid == -1) ERR("Target pid not found!");

    printf("[+] Dll path: %s\n", sDllPath);
    printf("[+] Target pid: %d\n", pid);

    // 1. Open remote process
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!pHandle) {
        ERR("OpenProcess failed!");
    }

    // 2. Allocate space on remote process
    PVOID pRemoteBuffer = VirtualAllocEx(pHandle, NULL, sizeof(sDllPath), MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuffer) {
        ERR("VirtualAllocEx failed!");
    }
    printf("[+] Retmoe buffer: 0x%llx\n", pRemoteBuffer);

    // 3. Write the dll path to the space
    if (!WriteProcessMemory(pHandle, pRemoteBuffer, sDllPath, sizeof(sDllPath), NULL)) {
        ERR("WriteProcessMemory failed!");
    }

    // 4. Get the LoadLibraryA function pointer
    printf("[+] LoadLibraryA: 0x%llx\n", LoadLibraryA);

    // 5. Create one remote thread to trigger LoadlibraryA(dll_path)
    HANDLE r_thread = CreateRemoteThread(pHandle, NULL, 0, LoadLibraryA, pRemoteBuffer, 0, NULL);
    if (!r_thread) {
        ERR("CreateRemoteThread failed!");
    }

    WaitForSingleObject(r_thread, INFINITE);
    CloseHandle(pHandle);
    CloseHandle(r_thread);

    return 0;
}
