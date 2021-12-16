#pragma once

VOID        FSH_Unload(PDRIVER_OBJECT  DriverObject);
NTSTATUS    FSH_DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

NTSTATUS    FSH_Hook(PUNICODE_STRING filterName);
NTSTATUS    FSH_UnHook();
ULONG       FSH_GetListFilters(PWCHAR *data);
PWCHAR      FSH_GetFSMinifilterByIndex(ULONG index);


