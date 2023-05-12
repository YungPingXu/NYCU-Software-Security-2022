#pragma once
#include <Windows.h>

typedef HMODULE(WINAPI*_LoadLibraryA)(
  IN LPCSTR lpLibFileName
);

typedef FARPROC(WINAPI*_GetProcAddress_)(
    IN HMODULE hModule,
    IN LPCSTR  lpProcName
);

typedef BOOL(WINAPI* _DllMain)(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved);

typedef struct _LOADER_PARAM {
    LPVOID lpImageBase;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_BASE_RELOCATION pRelocation;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    _LoadLibraryA pLoadLibraryA;
    _GetProcAddress_ pGetProcAddress;
} LOADER_PARAM, * PLOADER_PARAM;

DWORD RemoteLibraryLoader(PLOADER_PARAM pLoaderParam);
//VOID RemoteLibraryLoader_END();
INT GetPidByName(WCHAR* wcProcName);
int main();