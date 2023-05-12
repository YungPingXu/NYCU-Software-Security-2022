#include <stdio.h>
#include <Windows.h>

#define ERR_MSG(msg) {\
    printf("[-] %s error: %d\n", msg, GetLastError());\
    exit(1);\
}

VOID MyThreadProc(BOOL bAlertable) {
    printf("[%d] MyThreadProc(%s)\n", GetCurrentThreadId(), bAlertable ? "TRUE" : "FALSE");

    DWORD dwRet = SleepEx(INFINITE, bAlertable);
    printf("[+] SleepEx return %d\n", dwRet);
}

VOID MyApcCallback(LPVOID lpParameter) {
    printf("[%d] MyApcCallBack(0x%x)\n", GetCurrentThreadId(), lpParameter);
}

int main() {
    /* SleepEx - bAlertable = FALSE */
    puts("\n[+] Test 1: SleepEx - bAlertable = FALSE");
    HANDLE hThread1 = CreateThread(NULL, 0, MyThreadProc, FALSE, 0, NULL);
    if (!hThread1) ERR_MSG("CreateThread");

    Sleep(500);
    if (!QueueUserAPC(MyApcCallback, hThread1, 0x1)) ERR_MSG("QueueUserAPC");
    Sleep(500);
    CloseHandle(hThread1);

    /* SleepEx - bAlertable = TRUE */
    puts("\n[+] Test 2: SleepEx - bAlertable = TRUE");
    HANDLE hThread2 = CreateThread(NULL, 0, MyThreadProc, TRUE, 0, NULL);
    if (!hThread2) ERR_MSG("CreateThread");

    Sleep(500);
    if (!QueueUserAPC(MyApcCallback, hThread2, 0x2)) ERR_MSG("QueueUserAPC");
    Sleep(500);
    CloseHandle(hThread2);

    /* CreateThread - THREAD_SUSPEND_RESUME */
    puts("\n[+] Test 3: CreateThread - THREAD_SUSPEND_RESUME");
    HANDLE hThread3 = CreateThread(NULL, 0, MyThreadProc, FALSE, THREAD_SUSPEND_RESUME, NULL);
    if (!hThread3) ERR_MSG("CreateThread");
    if (!QueueUserAPC(MyApcCallback, hThread3, 0x3)) ERR_MSG("QueueUserAPC");
    Sleep(500);
    ResumeThread(hThread3);
    Sleep(500);
    CloseHandle(hThread3);

    return 0;
}

