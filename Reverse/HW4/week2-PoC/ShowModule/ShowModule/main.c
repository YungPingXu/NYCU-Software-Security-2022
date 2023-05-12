#include "main.h"

VOID list_del(PLIST_ENTRY node) {
    node->Flink->Blink = node->Blink;
    node->Blink->Flink = node->Flink;
    node->Flink = NULL;
    node->Blink = NULL;
}

VOID ShowModule() {
    PPEB pPEB = __readgsqword(0x60); // gs:[0x60]
    printf("[+] PEB base address: 0x%016llx\n", (PVOID)pPEB);

    LDR_DATA_TABLE_ENTRY* pLdrDataTableEntry;

    printf("\n[+] Parse InLoadOrderModuleList\n    ");
    LIST_FOR_EACH_ENTRY(pLdrDataTableEntry, &(pPEB->Ldr->InLoadOrderModuleList), LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) {
        printf("-> \"%ls\"", pLdrDataTableEntry->BaseDllName.Buffer);
    }

    printf("\n[+] Parse InMemoryOrderModuleList\n    ");
    LIST_FOR_EACH_ENTRY(pLdrDataTableEntry, &(pPEB->Ldr->InMemoryOrderModuleList), LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) {
        printf("-> \"%ls\"", pLdrDataTableEntry->BaseDllName.Buffer);
    }

    printf("\n[+] Parse InInitializationOrderModuleList\n    ");
    LIST_FOR_EACH_ENTRY(pLdrDataTableEntry, &(pPEB->Ldr->InInitializationOrderModuleList), LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks) {
        printf("-> \"%ls\"", pLdrDataTableEntry->BaseDllName.Buffer);
    }
    puts("");
}

VOID UnlinkModuleW(PWCHAR wcDllName) {
    PPEB pPEB = __readgsqword(0x60); // gs:[0x60]

    PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
    LIST_FOR_EACH_ENTRY(pLdrDataTableEntry, &(pPEB->Ldr->InLoadOrderModuleList), LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) {
        if (_wcsicmp(wcDllName, pLdrDataTableEntry->BaseDllName.Buffer) == 0) {
            list_del(&pLdrDataTableEntry->InLoadOrderLinks);
            list_del(&pLdrDataTableEntry->InMemoryOrderLinks);
            list_del(&pLdrDataTableEntry->InInitializationOrderLinks);
            break; // must break here !!
        }
    }
}

int main() {
    BYTE buf[100];
    ShowModule();

    scanf_s("%s", buf, 10);

    UnlinkModuleW(L"kernel32.dll");
    ShowModule();
    
    scanf_s("%s", buf, 10);

    //__debugbreak();

    return 0;
}
