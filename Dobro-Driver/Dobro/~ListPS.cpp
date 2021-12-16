// #include <ntddk.h>
// #include <ntstrsafe.h>
// #include <stdlib.h>
// #include "CRTLib.h"
// #include "Common.h"
//
// 
// //////////////////////////////////////////////////////////////////////////
// // List PS
// //////////////////////////////////////////////////////////////////////////
// typedef struct _PS_INFO
// {
//     LIST_ENTRY  ListEntry;
//     HANDLE      ProcessId;
//     BOOLEAN     IsFiltered;
// } PS_INFO, * PPS_INFO;
// 
// FAST_MUTEX g_PsListFastMutexLock;
// LIST_ENTRY g_PsInfoListHead;
// 
// VOID
// HlpPsListInit(
//     VOID
// )
// {
//     ExInitializeFastMutex(&g_PsListFastMutexLock);
//     return;
// }
// 
// VOID NTAPI HlpPsListDestroy(VOID)
// {
//     PPS_INFO PsInfo = NULL;
//     PLIST_ENTRY Entry;
// 
//     ExAcquireFastMutex(&g_PsListFastMutexLock);
// 
//     Entry = g_PsInfoListHead.Flink;
//     while (Entry != &g_PsInfoListHead)
//     {
//         PsInfo = CONTAINING_RECORD(Entry,
//             PS_INFO,
//             ListEntry);
// 
//         Entry = Entry->Flink;
// 
//         ExFreePoolWithTag(PsInfo, DRIVER_TAG);
//     }
// 
//     ExReleaseFastMutex(&g_PsListFastMutexLock);
// }
// 
// PVOID
// HlpPsCreatePsList(
//     HANDLE ProcessId,
//     BOOLEAN IsFiltered
// )
// {
//     PPS_INFO PsInfo = NULL;
//     BOOLEAN Success = FALSE;
// 
//     PsInfo = (PPS_INFO)ExAllocatePoolZero(
//         NonPagedPoolNx,
//         sizeof(PS_INFO),
//         DRIVER_TAG);
// 
//     if (PsInfo == NULL)
//         goto Exit;
// 
//     PsInfo->ProcessId = ProcessId;
//     PsInfo->IsFiltered = IsFiltered;
// 
//     Success = TRUE;
// 
// Exit:
// 
//     if (Success == FALSE)
//     {
//         if (PsInfo != NULL)
//         {
//             ExFreePoolWithTag(PsInfo, DRIVER_TAG);
//             PsInfo = NULL;
//         }
//     }
// 
//     return PsInfo;
// }
// 
// BOOLEAN
// HlpPsInsertPsList(
//     PPS_INFO PsInfo
// )
// {
//     BOOLEAN Success = FALSE;
// 
//     ExAcquireFastMutex(&g_PsListFastMutexLock);
// 
//     InsertHeadList(&g_PsInfoListHead, &PsInfo->ListEntry);
//     Success = TRUE;
// 
//     ExReleaseFastMutex(&g_PsListFastMutexLock);
// 
//     return Success;
// }
// 
// BOOLEAN
// HlpPsCreateAndInsertPsList(
//     HANDLE ProcessId,
//     BOOLEAN IsFiltered
// )
// {
//     BOOLEAN Success = FALSE;
//     PPS_INFO PsInfo = NULL;
//     
//     PsInfo = (PPS_INFO)HlpPsCreatePsList(ProcessId, IsFiltered);
//     if (PsInfo == NULL)
//         goto Exit;
// 
//     Success = HlpPsInsertPsList(PsInfo);
// 
// Exit:
// 
//     return Success;
// }
// 
// BOOLEAN
// HlpPsFindAndCheckPsList(
//     HANDLE ProcessId
// )
// {
//     PPS_INFO PsInfo = NULL;
//     PLIST_ENTRY Entry;
//     BOOLEAN IsFiltered = FALSE;
// 
//     ExAcquireFastMutex(&g_PsListFastMutexLock);
// 
//     Entry = g_PsInfoListHead.Flink;
//     while (Entry != &g_PsInfoListHead)
//     {
// 
//         PsInfo = CONTAINING_RECORD(Entry,
//             PS_INFO,
//             ListEntry);
//         if (PsInfo->ProcessId == ProcessId)
//         {
//             IsFiltered = PsInfo->IsFiltered;
//             break;
//         }
// 
//         Entry = Entry->Flink;
//     }
// 
//     ExReleaseFastMutex(&g_PsListFastMutexLock);
// 
//     return IsFiltered;
// }
// 
// VOID
// HlpPsDeletePsList(
//     PPS_INFO PsInfo
// )
// {
//     if (PsInfo != NULL)
//     {
//         ExFreePoolWithTag(PsInfo, DRIVER_TAG);
//     }
// }
// 
// BOOLEAN
// HlpPsFindAndRemovePsList(
//     HANDLE ProcessId
// )
// {
//     PPS_INFO PsInfo = NULL;
//     PLIST_ENTRY Entry;
//     BOOLEAN Success = FALSE;
// 
//     ExAcquireFastMutex(&g_PsListFastMutexLock);
// 
//     Entry = g_PsInfoListHead.Flink;
//     while (Entry != &g_PsInfoListHead)
//     {
// 
//         PsInfo = CONTAINING_RECORD(
//             Entry,
//             PS_INFO,
//             ListEntry);
//         if (PsInfo->ProcessId == ProcessId)
//         {
//             RemoveEntryList(&PsInfo->ListEntry);
//             HlpPsDeletePsList(PsInfo);
//             Success = TRUE;
//             break;
//         }
//     }
// 
//     ExReleaseFastMutex(&g_PsListFastMutexLock);
// 
//     return Success;
// }
//////////////////////////////////////////////////////////////////////////

// //////////////////////////////////////////////////////////////////////////
// // List PS
// //////////////////////////////////////////////////////////////////////////
// typedef struct _PS_INFO
// {
//     LIST_ENTRY  ListEntry;
//     HANDLE      ProcessId;
//     BOOLEAN     IsFiltered;
// } PS_INFO, * PPS_INFO;
// 
// LIST_ENTRY g_PsInfoListHead = { 0 };
// FAST_MUTEX g_FastMutex = { 0 };
// 
// VOID NTAPI HlpPsListInit(VOID)
// {
//     return ExInitializeFastMutex(&g_FastMutex);
// }
// 
// VOID NTAPI HlpPsListDestroy(VOID)
// {
//     ExAcquireFastMutex(&g_FastMutex);
// 
//     PLIST_ENTRY NextEntry = g_PsInfoListHead.Flink;
// 
//     while (NextEntry != &g_PsInfoListHead)
//     {
//         PPS_INFO PsInfo = CONTAINING_RECORD(NextEntry, PS_INFO, ListEntry);
//         NextEntry = NextEntry->Flink;
// 
//         ExFreePoolWithTag(PsInfo, DRIVER_TAG);
//     }
// 
//     ExReleaseFastMutex(&g_FastMutex);
// }
// 
// NTSTATUS NTAPI HlpPsListCreateInjectionInfo(PPS_INFO* PsInfoIn, HANDLE ProcessId)
// {
//     PPS_INFO PsInfo;
// 
//     if (PsInfoIn && *PsInfoIn)
//     {
//         PsInfo = *PsInfoIn;
//     }
//     else
//     {
//         PsInfo = (PPS_INFO)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(PS_INFO), DRIVER_TAG);
// 
//         if (!PsInfo)
//         {
//             return STATUS_INSUFFICIENT_RESOURCES;
//         }
// 
//         if (PsInfo)
//         {
//             *PsInfoIn = PsInfo;
//         }
//     }
// 
//     RtlZeroMemory(PsInfo, sizeof(PS_INFO));
//     PsInfo->ProcessId = ProcessId;
// 
//     ExAcquireFastMutex(&g_FastMutex);
// 
//     InsertTailList(&g_PsInfoListHead, &PsInfo->ListEntry);
// 
//     ExReleaseFastMutex(&g_FastMutex);
// 
//     return STATUS_SUCCESS;
// }
// 
// VOID NTAPI HlpPsListRemoveInjectionInfo(PPS_INFO PsInfo, BOOLEAN FreeMemory)
// {
//     ExAcquireFastMutex(&g_FastMutex);
// 
//     RemoveEntryList(&PsInfo->ListEntry);
// 
//     ExReleaseFastMutex(&g_FastMutex);
// 
//     if (FreeMemory)
//     {
//         ExFreePoolWithTag(PsInfo, DRIVER_TAG);
//     }
// }
// 
// PPS_INFO NTAPI HlpPsListFindInjectionInfo(HANDLE ProcessId)
// {
//     ExAcquireFastMutex(&g_FastMutex);
// 
//     PPS_INFO fndPsInfo = NULL;
//     PLIST_ENTRY NextEntry = g_PsInfoListHead.Flink;
// 
//     while (NextEntry != &g_PsInfoListHead)
//     {
//         PPS_INFO PsInfo = CONTAINING_RECORD(NextEntry, PS_INFO, ListEntry);
// 
//         if (PsInfo->ProcessId == ProcessId)
//         {
//             fndPsInfo = PsInfo;
//             break;
//         }
// 
//         NextEntry = NextEntry->Flink;
//     }
// 
//     ExReleaseFastMutex(&g_FastMutex);
// 
//     return fndPsInfo;
// }
// 
// VOID NTAPI HlpPsListRemoveInjectionInfoByProcessId(HANDLE ProcessId, BOOLEAN FreeMemory)
// {
//     PPS_INFO PsInfo = HlpPsListFindInjectionInfo(ProcessId);
// 
//     if (PsInfo)
//     {
//         HlpPsListRemoveInjectionInfo(PsInfo, FreeMemory);
//     }
// }
// 
//////////////////////////////////////////////////////////////////////////