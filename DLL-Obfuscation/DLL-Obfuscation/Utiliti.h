#pragma once
#include <stdio.h>
#include <Windows.h>
#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")


#define BYTEKEY 0xAB


#if _WIN64			
#define DWORD64 unsigned long long
#else
#define DWORD64 unsigned long
#endif

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

#define CountRelocationEntries(dwBlockSize)		\
	(dwBlockSize -								\
	sizeof(BASE_RELOCATION_BLOCK)) /			\
	sizeof(BASE_RELOCATION_ENTRY)



CHAR DllPath[MAX_PATH];
CHAR ObfuscatedDllPath[MAX_PATH];
DWORD PID = -1;


BYTE* ReadDataFromFile(CHAR* FileName);
DWORD GenerateEncryptedDLL(CHAR* FileName, CHAR* OutputFileName);
DWORD LoadEncryptedDll(CHAR* DllPath);
PIMAGE_NT_HEADERS  GetNTHeaders(DWORD64 dwImageBase);
PLOADED_IMAGE  GetLoadedImage(DWORD64 dwImageBase);
DWORD  LoadDllFromMemory(HANDLE hProcess, BYTE* SourceFileData, LPVOID lpParameter);
void EncryptDecryptCodeSection(BYTE* Data);



BYTE* ReadDataFromFile(CHAR* FileName) {

    HANDLE hFile = NULL;
    BOOL bResult = FALSE;
    DWORD cbRead = 0;

    hFile = CreateFileA(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Failed To Open Handle To File %S Error Code is 0x%x\n", FileName, GetLastError());
        return NULL;
    }

    int FileSize = GetFileSize(hFile, 0);
    if (FileSize == INVALID_FILE_SIZE) {
        printf("Failed To get File size Error Code is 0x%x\n", GetLastError());
        return NULL;
    }

    BYTE* FileContents = new BYTE[FileSize];
    ZeroMemory(FileContents, FileSize);

    bResult = ReadFile(hFile, FileContents, FileSize, &cbRead, NULL);
    if (bResult == FALSE) {
        printf("Failed To Read File Data Error Code is 0x%x\n", GetLastError());
        return NULL;
    }

    CloseHandle(hFile);
    return FileContents;
}

DWORD GenerateEncryptedDLL(CHAR* FileName, CHAR* OutputFileName) {

    HANDLE hOutputFile;
    DWORD dwBytesWritten;
    BOOL bErrorFlag;

    BYTE* FileData = ReadDataFromFile(FileName);

    HANDLE hfile = CreateFileA(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    EncryptDecryptCodeSection(FileData);
    hOutputFile = CreateFileA(OutputFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hOutputFile == INVALID_HANDLE_VALUE) {
        printf("Faile TO open file for write Error Code %x\n", GetLastError());
        return -1;
    }

    DWORD FileSize = GetFileSize(hfile, NULL);
    bErrorFlag = WriteFile(hOutputFile, FileData, FileSize, &dwBytesWritten, NULL);

    if (FALSE == bErrorFlag) {
        printf("Failed To Write To File Error Code %x\n", GetLastError());
        return -1;
    }

    CloseHandle(hfile);
    CloseHandle(hOutputFile);

    return 0;
}

DWORD LoadEncryptedDll(CHAR* DllPath) {
    HANDLE ProcessHandle = GetCurrentProcess();
    if (PID != -1) {
        ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
        if (!ProcessHandle) {
            printf("Failed To Open Target Process PID %d Error Code %x   %x\n", PID, GetLastError(), ProcessHandle);
            return -1;
        }
    }
    BYTE* Data = ReadDataFromFile(DllPath);

    EncryptDecryptCodeSection(Data);
    DWORD Result = LoadDllFromMemory(ProcessHandle, Data, NULL);

    return Result;
}

PIMAGE_NT_HEADERS  GetNTHeaders(DWORD64 dwImageBase) {
    return (PIMAGE_NT_HEADERS)(dwImageBase + ((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
}

PLOADED_IMAGE  GetLoadedImage(DWORD64 dwImageBase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;

    PIMAGE_NT_HEADERS pNTHeaders = GetNTHeaders(dwImageBase);
    PLOADED_IMAGE pImage = new LOADED_IMAGE();

    pImage->FileHeader = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);

    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;

    pImage->Sections = (PIMAGE_SECTION_HEADER)(dwImageBase + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    return pImage;
}

DWORD  LoadDllFromMemory(HANDLE hProcess, BYTE* SourceFileData, LPVOID lpParameter)
{
    BOOL bSuccess = FALSE;
    LPVOID lpRemoteLibraryBuffer = NULL;
    LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
    HANDLE hThread = NULL;
    DWORD dwReflectiveLoaderOffset = 0;
    DWORD dwThreadId = 0;
    DWORD dwLength;

    PIMAGE_NT_HEADERS pSourceHeaders = GetNTHeaders((DWORD64)SourceFileData);
    PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD64)SourceFileData);

    dwLength = pSourceHeaders->OptionalHeader.SizeOfImage;
    lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!lpRemoteLibraryBuffer) {

        printf("Failed To allocate Memory in remote Process Error Code is %x\n", GetLastError());
        return -1;
    }


    DWORD64 dwDelta = (DWORD64)lpRemoteLibraryBuffer - pSourceHeaders->OptionalHeader.ImageBase;

    pSourceHeaders->OptionalHeader.ImageBase = (DWORD64)lpRemoteLibraryBuffer;

    if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, SourceFileData, pSourceHeaders->OptionalHeader.SizeOfHeaders, 0)) {

        printf("Failed writing process memory at address %p Error Code 0x%x\r\n", lpRemoteLibraryBuffer, GetLastError());
        return -1;
    }

    for (DWORD64 x = 0; x < pSourceImage->NumberOfSections; x++)
    {
        if (!pSourceImage->Sections[x].PointerToRawData)
            continue;

        PVOID pSectionDestination = (PVOID)((DWORD64)lpRemoteLibraryBuffer + pSourceImage->Sections[x].VirtualAddress);

        if (!WriteProcessMemory(hProcess, pSectionDestination, &SourceFileData[pSourceImage->Sections[x].PointerToRawData], pSourceImage->Sections[x].SizeOfRawData, 0)) {
            printf("Failed writing process memory at address %p Error Code 0x%x\r\n", pSectionDestination, GetLastError());
            return -1;
        }
    }

    //Fixing the relocation of PE File in Memory
    if (dwDelta) {
        for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
        {
            char pSectionName[] = ".reloc";

            if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
                continue;


            DWORD64 dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
            DWORD dwOffset = 0;

            IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

            while (dwOffset < relocData.Size)
            {
                PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&SourceFileData[dwRelocAddr + dwOffset];

                dwOffset += sizeof(BASE_RELOCATION_BLOCK);

                DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

                PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&SourceFileData[dwRelocAddr + dwOffset];

                for (DWORD y = 0; y < dwEntryCount; y++)
                {
                    dwOffset += sizeof(BASE_RELOCATION_ENTRY);

                    if (pBlocks[y].Type == 0)
                        continue;

                    DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;

                    DWORD64 dwBuffer = 0;
                    BOOL bSuccess;
                    bSuccess = ReadProcessMemory(hProcess, (PVOID)((DWORD64)lpRemoteLibraryBuffer + dwFieldAddress), &dwBuffer, sizeof(DWORD64), 0);
                    if (!bSuccess) {
                        printf("Failed reading memory at address %p  Erro code  0x%x\r\n", (PVOID)((DWORD64)lpRemoteLibraryBuffer + dwFieldAddress), GetLastError());
                        return -1;
                    }

                    dwBuffer += dwDelta;
                    bSuccess = WriteProcessMemory(hProcess, (LPVOID)((DWORD64)lpRemoteLibraryBuffer + dwFieldAddress), &dwBuffer, sizeof(DWORD64), 0);

                    if (!bSuccess) {
                        printf("Failed writing process memory at address %p Error Code 0x%x\r\n", (LPVOID)((DWORD64)lpRemoteLibraryBuffer + dwFieldAddress, GetLastError()));
                        return -1;
                    }
                }
            }

            break;
        }
    }

    //Resolve IAT API in remote Process
    //the Pe File Should depend only on kernel32 and ntdll.dll
    BYTE* RemoteDataBuffer = NULL;
    RemoteDataBuffer = new BYTE[dwLength];
    if (!RemoteDataBuffer) {
        printf("failed to allocate memory\n");
        return -1;
    }
    BOOL ret = ReadProcessMemory(hProcess, (PVOID)lpRemoteLibraryBuffer, RemoteDataBuffer, dwLength, 0);
    if (!ret) {
        printf("Failed reading memory at address %p  Erro code  0x%x\r\n", lpRemoteLibraryBuffer, GetLastError());
        return -1;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)RemoteDataBuffer);

    LPCSTR libraryName = "";
    HMODULE library = NULL;


    while (importDescriptor->Name != NULL)
    {

        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)RemoteDataBuffer;
        library = LoadLibraryA(libraryName);

        if (library)
        {

            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)RemoteDataBuffer + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData != NULL)
            {

                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)RemoteDataBuffer + thunk->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
                    thunk->u1.Function = functionAddress;
                }
                ++thunk;
            }
        }

        importDescriptor++;
    }


    if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, RemoteDataBuffer, dwLength, 0))
    {
        printf("Failed writing process memory at address %p Error Code 0x%x\r\n", lpRemoteLibraryBuffer, GetLastError());
        return -1;
    }

    DWORD64 dwEntrypoint = (DWORD64)lpRemoteLibraryBuffer + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

    hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, (LPTHREAD_START_ROUTINE)dwEntrypoint, lpParameter, (DWORD)NULL, &dwThreadId);
    if (!hThread) {
        printf("failed to create remote thread Erro Code %x\n", GetLastError());
        return -1;
    }

    CloseHandle(hThread);

    return NULL;
}

void EncryptDecryptCodeSection(BYTE* Data) {
    BOOL bSuccess = FALSE;
    LPVOID lpRemoteLibraryBuffer = NULL;
    LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
    HANDLE hThread = NULL;
    DWORD dwReflectiveLoaderOffset = 0;
    DWORD dwThreadId = 0;
    DWORD dwLength;

    PIMAGE_NT_HEADERS pSourceHeaders = GetNTHeaders((DWORD64)Data);
    PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD64)Data);

    for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
    {
        char pSectionName[] = "text";
        char* pch;
        pch = strstr((CHAR*)pSourceImage->Sections[x].Name, "text");
        if (pch == NULL) {
            pch = strstr((CHAR*)pSourceImage->Sections[x].Name, "code");
            if (pch == NULL)
                continue;
        }
        printf("in code section \n");
        for (DWORD i = 0; i < pSourceImage->Sections[x].SizeOfRawData; i++) {
            DWORD64* ByteTohange = (DWORD64*)((DWORD64)Data + (DWORD64)pSourceImage->Sections[x].PointerToRawData + (DWORD64)i);
            *(BYTE*)ByteTohange = *(BYTE*)ByteTohange ^ 0xab;

        }

        //break;
    }
}
