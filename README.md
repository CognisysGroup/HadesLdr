# HadesLdr

A demo of the relevant blog post: [Combining Indirect Dynamic Syscalls and API Hashing](https://labs.cognisys.group/posts/Combining-Indirect-Dynamic-Syscalls-and-API-Hashing/)

Shellcode Loader Implementing :
- Indirect Dynamic Syscall by resolving the SSN and the address pointing to a backed syscall instruction dynamically.
- API Hashing by resolving modules & APIs base address from PEB by hashes
- Fileless Chunked RC4 Shellcode retrieving using Winsock2

## Demo : 

https://github.com/CognisysGroup/HadesLdr/assets/123980007/38892f75-386c-4c18-97af-57f6024d4f86

## References :
https://github.com/am0nsec/HellsGate/tree/master   
https://cocomelonc.github.io/tutorial/2022/04/02/malware-injection-18.html   
https://blog.sektor7.net/#!res/2021/halosgate.md   

## License / Terms of Use

This software should only be used for authorised testing activity and not for malicious use.

By downloading this software you are accepting the terms of use and the licensing agreement.
