##### GetHash.py : is used to hash a module name or an API name

```bash
python3 GetHash.py NtCreateFile
104375567
```

##### xor.py : is used to xor each byte in a string with 0xaa and the output is a bytes array

```bash
python3 xor.py "ntdll.dll"
{ 0xc4, 0xde, 0xce, 0xc6, 0xc6, 0x84, 0xce, 0xc6, 0xc6, 0xaa };
```
##### rc4.py : is used to rc4 encode a binary and generate the key.bin and cipher.bin 

```bash
python3 rc4.py met.bin
```
