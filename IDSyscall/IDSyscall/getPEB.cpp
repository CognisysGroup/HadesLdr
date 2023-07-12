#include "commun.h"

struct LDR_MODULE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    HMODULE DllBase;
    void* EntryPoint;
    UINT SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};


DWORD CalculateHash(char* inputData) {
    DWORD hashValue = 0x99;

    for (int index = 0; index < strlen(inputData); index++) {
        hashValue += inputData[index] + (hashValue << 1);
    }
    
    return hashValue;
}


DWORD CalculateModuleHash(LDR_MODULE* moduleLinkList) {
    char moduleName[64];
    size_t index = 0;

    while (moduleLinkList->BaseDllName.Buffer[index] && index < sizeof(moduleName) - 1) {
        moduleName[index] = (char)moduleLinkList->BaseDllName.Buffer[index];
        index++;
    }
    moduleName[index] = 0;
    return CalculateHash((char*)CharLowerA(moduleName));
}


HMODULE getModuleBaseAddr(DWORD hashInput) {
    HMODULE ModuleBaseAddr;
    INT_PTR PEB = __readgsqword(0x60);
    INT_PTR Ldr = 0x18;
    INT_PTR FlinkOffset = 0x10;

    INT_PTR PEB_LDR_DATA = *(INT_PTR*)(PEB + Ldr);
    INT_PTR FistFlink = *(INT_PTR*)(PEB_LDR_DATA + FlinkOffset); // InLoadOrderModuleList
    LDR_MODULE* LDR_DATA_TABLE_ENTRY = (LDR_MODULE*)FistFlink;
    do {
        LDR_DATA_TABLE_ENTRY = (LDR_MODULE*)LDR_DATA_TABLE_ENTRY->InLoadOrderLinks.Flink;
        if (LDR_DATA_TABLE_ENTRY->DllBase != NULL) {

            if (CalculateModuleHash(LDR_DATA_TABLE_ENTRY) == hashInput) {
                break;
            }
        }
    } while (FistFlink != (INT_PTR)LDR_DATA_TABLE_ENTRY);

    ModuleBaseAddr = (HMODULE)LDR_DATA_TABLE_ENTRY->DllBase;
    return ModuleBaseAddr;
}


LPVOID getAPIAddr(HMODULE module, DWORD myHash) {

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((LPBYTE)module + DOSheader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY EXdir = (PIMAGE_EXPORT_DIRECTORY)(
        (LPBYTE)module + NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)module + EXdir->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)module + EXdir->AddressOfNames);
    PWORD  fOrdinals = (PWORD)((LPBYTE)module + EXdir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < EXdir->AddressOfFunctions; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
        DWORD hash = CalculateHash(pFuncName);
        if (hash == myHash) {
            //printf("functionName : %s\n", pFuncName);
            return (LPVOID)((LPBYTE)module + fAddr[fOrdinals[i]]);
        }
    }
    return NULL;
}