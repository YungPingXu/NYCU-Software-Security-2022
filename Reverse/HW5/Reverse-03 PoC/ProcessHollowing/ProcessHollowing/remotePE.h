#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include "err.h"
//#include "ntdll.h"
#include "ntdll_def.h"

#define IMAGE_BUFER_SIZE 0x2000

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );

typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
    DWORD SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

_NtUnmapViewOfSection fpNtUnmapViewOfSection;
_NtQueryInformationProcess fpNtQueryInformationProcess;
_NtQuerySystemInformation fpNtQuerySystemInformation;

INT InitFunctions();
INT GetPidByNameW(WCHAR* procname);
PPEB GetRemotePEB(HANDLE hProcess);
PLOADED_IMAGE GetRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress);
