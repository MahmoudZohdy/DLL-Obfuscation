# DLL-Obfuscation

This Project is For Dll Obfuscation, the ida is to encrypt the code section of a dll, then at load time decrypt the code section and map the Dll to memory then fix the relocation and IAT

So the Dll will be encrypted always on disck, and gets decrypted only in memory.

# Usage
```
DLL-Obfuscation.exe <Operation Type> <PID, '-1' in case self inject> <Clean Dll Path> <Obfuscated Dll Path>

Operation Type: 
    1 Encrypt the DLL Code Section
    2 Load Encrypted Dll

DLL-Obfuscation.exe 1 CleanDll.dll ObfuscatedDll.dll\n");
DLL-Obfuscation.exe 2 2552 ObfuscatedDll.dll
DLL-Obfuscation.exe 2 -1 ObfuscatedDll.dll
```

