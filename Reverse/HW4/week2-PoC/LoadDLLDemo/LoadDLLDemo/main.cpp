#include "main.h"

void CallGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    FARPROC f = GetProcAddress(hModule, lpProcName);
    puts("");
    if (f == 0) {
        printf("[-] GetProcAddress(\"%s\") failed\n", lpProcName);
        return;
    }
    f();
}

DWORD WINAPI ThreadProc(_In_ LPVOID lpParameter) {
    puts("");
    ExitThread(0);
}

int main() {
    LPCSTR dllPath = "C:\\Users\\user\\Documents\\my_injection\\DLLDemo\\x64\\Debug\\DLLDemo.dll";
    
    // Test1: dllMain 
    HMODULE hDLLDemo = LoadLibraryA(dllPath);
    if (hDLLDemo == 0) {
        puts("[-] LoadLibraryA failed");
        exit(1);
    }
    puts("");
    HANDLE hThread = CreateThread(NULL, 0, ThreadProc, 0, 0, 0);
    if (hThread == 0) {
        puts("[-] CreateThread failed");
        exit(1);
    }
    WaitForSingleObject(hThread, 10); // wait for 10ms

    // Test2: GetProcAddress
    CallGetProcAddress(hDLLDemo, "MyFunction0");
    CallGetProcAddress(hDLLDemo, MAKEINTRESOURCEA(1));

    CallGetProcAddress(hDLLDemo, "MyFunction1");
    CallGetProcAddress(hDLLDemo, MAKEINTRESOURCEA(2));
    
    CallGetProcAddress(hDLLDemo, "MyFunction2");
    CallGetProcAddress(hDLLDemo, MAKEINTRESOURCEA(5));

    puts("");
}
