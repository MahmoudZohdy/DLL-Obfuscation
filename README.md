# DLL-Obfuscation

This Project is For Dll Obfuscation, the ida is to encrypt the code section of a dll, then at load time decrypt the code section and map the Dll to memory then fix the relocation and IAT

So the Dll will be always encrypted on disc, and gets decrypted only in memory.

# Usage
```
DLL-Obfuscation.exe <Operation Type> <PID, '-1' in case self inject> <Clean Dll Path> <Obfuscated Dll Path>

Operation Type: 
    1 Encrypt the DLL Code Section
    2 Load Encrypted Dll

DLL-Obfuscation.exe 1 CleanDll.dll ObfuscatedDll.dll
DLL-Obfuscation.exe 2 2552 ObfuscatedDll.dll
DLL-Obfuscation.exe 2 -1 ObfuscatedDll.dll
```
# Note:
it can Load only Dll encrypted by Operation Type 1, The encryption is simple XOR with the value 0xAB you can change it in the Utiliti.h file, or you can change the encryption function.

UPDATE:
you can see the [second version](https://github.com/MahmoudZohdy/DLL-Obfuscation-V2)