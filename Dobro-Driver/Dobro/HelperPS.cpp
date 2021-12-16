#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include "CRTLib.h"
#include "Common.h"

//////////////////////////////////////////////////////////////////////////
// Prototype NT API
//////////////////////////////////////////////////////////////////////////
extern "C" 
{
    NTKERNELAPI
        PCHAR
        NTAPI
        PsGetProcessImageFileName(
            _In_ PEPROCESS Process
        );

    NTKERNELAPI
        NTSTATUS
        PsLookupProcessByProcessId(
            _In_ HANDLE ProcessId,
            _Outptr_ PEPROCESS* Process
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        ZwQueryInformationProcess(
            _In_ HANDLE ProcessHandle,
            _In_ PROCESSINFOCLASS ProcessInformationClass,
            _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
            _In_ ULONG ProcessInformationLength,
            _Out_opt_ PULONG ReturnLength
        );

    NTKERNELAPI
        NTSTATUS
        ObOpenObjectByPointer(
            _In_ PVOID Object,
            _In_ ULONG HandleAttributes,
            _In_opt_ PACCESS_STATE PassedAccessState,
            _In_ ACCESS_MASK DesiredAccess,
            _In_opt_ POBJECT_TYPE ObjectType,
            _In_ KPROCESSOR_MODE AccessMode,
            _Out_ PHANDLE Handle
        );
}

//////////////////////////////////////////////////////////////////////////
// Defines
//////////////////////////////////////////////////////////////////////////
#define MAX_PATH (260)
#define SIZE_BUF (1024)

//////////////////////////////////////////////////////////////////////////
// Get process module name
//////////////////////////////////////////////////////////////////////////
BOOLEAN NTAPI HlpPsGetProcessName(HANDLE pid, PWCHAR procName, ULONG lenProcName)
{
    PEPROCESS eProcess = NULL;
    HANDLE hProcess = NULL;
    NTSTATUS status;
    BOOLEAN rc = FALSE;

    WCHAR buffer[(sizeof(UNICODE_STRING) / sizeof(WCHAR)) + SIZE_BUF + 2];
    PUNICODE_STRING usProcName;

    // Initialize Buffer -> UNICODE_STRING
    usProcName = (PUNICODE_STRING)buffer;
    usProcName->Buffer = &buffer[sizeof(UNICODE_STRING) / sizeof(WCHAR)];
    usProcName->Length = 0x0;
    usProcName->MaximumLength = SIZE_BUF * sizeof(WCHAR);

    // Get process name
    status = PsLookupProcessByProcessId(pid, &eProcess);
    if (NT_SUCCESS(status))
    {
        status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcess);
        if (NT_SUCCESS(status))
        {

            status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, buffer, sizeof(buffer), NULL);

            if (NT_SUCCESS(status) && usProcName->Buffer)
            {
                // Get WSZ
                usProcName->Buffer[usProcName->Length] = '\0';

                // Get only module name
                PWCHAR pProcessName = wcsrchr(usProcName->Buffer, L'\\');
                if (pProcessName == NULL)
                    pProcessName = usProcName->Buffer;
                else
                    pProcessName++;

                if (wcslen(pProcessName) < lenProcName)
                {
                    wcscpy_s(procName, lenProcName, pProcessName);

                    rc = TRUE;
                }

                // Close HANDLE
                ZwClose(hProcess);
            }

            ObDereferenceObject(eProcess);
        }
    }

    return rc;
}

//////////////////////////////////////////////////////////////////////////
// Check PS
//////////////////////////////////////////////////////////////////////////
BOOLEAN NTAPI HlpPsIsFilteredPSByPid(HANDLE pid, PWCHAR whatFind)
{
    // Get file name
    WCHAR wcProcName[MAX_PATH];
    if (HlpPsGetProcessName(pid, wcProcName, MAX_PATH) == FALSE)
        return FALSE;

    PWCHAR p = crt_wcstristr(wcProcName, whatFind);
    if (p)
        return FALSE;

    return TRUE;
}

BOOLEAN NTAPI HlpPsIsFilteredPSByName(PCUNICODE_STRING imgFileName, PWCHAR whatFind)
{
    if (imgFileName == NULL)
        return FALSE;

    WCHAR wcProcName[MAX_PATH * 2];
    RtlStringCbPrintfExW(wcProcName, _countof(wcProcName), NULL, NULL, STRSAFE_NULL_ON_FAILURE, L"%wZ", imgFileName);

    PWCHAR p = crt_wcstristr(wcProcName, whatFind);
    if (p)
        return FALSE;

    return TRUE;
}
