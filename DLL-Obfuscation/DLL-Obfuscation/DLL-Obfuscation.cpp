#pragma warning(disable : 4996)

#include "Utiliti.h"

void PrintUsage() {

    printf("DLL-Obfuscation.exe <Operation Type> <PID, '-1' in case self inject> <Clean Dll Path> <Obfuscated Dll Path>\n\n");
    printf("Operation Type:\n 1 Encrypt the DLL\n 2 Load Encrypted Dll\n");
    printf("DLL-Obfuscation.exe 1 CleanDll.dll ObfuscatedDll.dll\n");
    printf("DLL-Obfuscation.exe 2 2552 ObfuscatedDll.dll\n");
    printf("DLL-Obfuscation.exe 2 -1 ObfuscatedDll.dll\n");

    return;
}
int main(int argc,CHAR* argv[])
{
    if (argc < 2) {
        PrintUsage();
        return 0;
    }
    int type = atoi(argv[1]);    

    switch (type)
    {
    case 1:
        strcpy(ObfuscatedDllPath, argv[3]);
        strcpy(DllPath, argv[2]);
        GenerateEncryptedDLL(DllPath, ObfuscatedDllPath);
        break;
    
    case 2:
        PID = atoi(argv[2]);
        strcpy(DllPath, argv[3]);
        LoadEncryptedDll(DllPath);
       
        break;

    default:
        break;
    }

    printf("Finished\n");
    Sleep(5000);

    return 0;
}
