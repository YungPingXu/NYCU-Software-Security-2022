#include "remotePE.h"

INT GetFunctions() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) ERR("LoadLibraryA");

    fpNtUnmapViewOfSection = GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (!fpNtUnmapViewOfSection) ERR("GetProcAddress(hNtdll, \"NtUnmapViewOfSection\")");

    fpNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!fpNtQueryInformationProcess) ERR("GetProcAddress(hNtdll, \"NtQueryInformationProcess\")");

    fpNtQuerySystemInformation = GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!fpNtQuerySystemInformation) ERR("GetProcAddress(hNtdll, \"NtQuerySystemInformation\")");
}

INT GetPidByNameW(WCHAR* procname) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    INT dwPid = -1;
    BOOL hResult;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == -1) ERR("CreateToolhelp32Snapshot");

    pe.dwSize = sizeof(PROCESSENTRY32);

    hResult = Process32First(hSnapshot, &pe);

    while (hResult) {
        if (wcscmp(procname, pe.szExeFile) == 0) {
            dwPid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }

    CloseHandle(hSnapshot);
    return dwPid;
}

PPEB GetRemotePEB(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    PPEB pPeb = malloc(sizeof(PEB));
    memset(pPeb, 0, sizeof(PEB));

    fpNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
    if (!pbi.PebBaseAddress) ERR("NtQueryInformationProcess");

    BOOL bStatus = ReadProcessMemory(hProcess, pbi.PebBaseAddress, pPeb, sizeof(PEB), 0);
    if (!bStatus) ERR("ReadProcessMemory");

    return pPeb;
}

PLOADED_IMAGE GetRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress) {
    BYTE* lpBuffer = malloc(IMAGE_BUFER_SIZE);
    BOOL bStatus = ReadProcessMemory(hProcess, lpImageBaseAddress, lpBuffer, IMAGE_BUFER_SIZE, 0);
    if (!bStatus) ERR("ReadProcessMemory");

    // Parse remote image
    PLOADED_IMAGE pImage = malloc(sizeof(LOADED_IMAGE));
    memset(pImage, 0, sizeof(LOADED_IMAGE));

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;
    pImage->FileHeader = (PIMAGE_NT_HEADERS64)(lpBuffer + pDOSHeader->e_lfanew);
    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
    pImage->Sections = (PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    return pImage;
}
