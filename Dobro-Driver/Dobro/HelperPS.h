#pragma once
BOOLEAN NTAPI HlpPsGetProcessName(HANDLE pid, PWCHAR procName, ULONG lenProcName);
BOOLEAN NTAPI HlpPsIsFilteredPSByPid(HANDLE pid, PWCHAR whatFind);
BOOLEAN NTAPI HlpPsIsFilteredPSByName(PCUNICODE_STRING imgFileName, PWCHAR whatFind);

// VOID HlpPsListInit(VOID);
// VOID NTAPI HlpPsListDestroy(VOID);
// BOOLEAN HlpPsCreateAndInsertPsList(HANDLE ProcessId, BOOLEAN IsFiltered);
// BOOLEAN HlpPsFindAndCheckPsList(HANDLE ProcessId);
// BOOLEAN HlpPsFindAndRemovePsList(HANDLE ProcessId);