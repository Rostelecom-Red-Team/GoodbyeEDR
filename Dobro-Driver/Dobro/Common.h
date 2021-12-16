#pragma once

#define DRIVER_TAG      'rb0d'
#define DRIVER_NAME     "D0br0"

#define DEVICE_NAME             L"\\Device\\"   ## DRIVER_NAME
#define DEVICE_SYM_LINK         L"\\??\\"       ## DRIVER_NAME
#define DEVICE_WIN32_NAME       L"\\\\.\\"      ## DRIVER_NAME


#define EVIL_DRV    0x8000
#define IOCTL_BASE  0x800

#define CTL_CODE_HIDE(i)    CTL_CODE(EVIL_DRV, IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DOBRO_DBG_BSOD					CTL_CODE_HIDE(0)
#define IOCTL_DOBRO_DBG_LIST_MODULES			CTL_CODE_HIDE(1)

#define IOCTL_DOBRO_PROCESS_ZEROOUT_ARRAY       CTL_CODE_HIDE(2)
#define IOCTL_DOBRO_PROCESS_DELETE_CALLBACK     CTL_CODE_HIDE(3)
#define IOCTL_DOBRO_PROCESS_CALLBACK_RET	    CTL_CODE_HIDE(4)
#define IOCTL_DOBRO_PROCESS_ROLLBACK_RET	    CTL_CODE_HIDE(5)

#define IOCTL_DOBRO_THREAD_ZEROOUT_ARRAY	    CTL_CODE_HIDE(6)
#define IOCTL_DOBRO_THREAD_DELETE_CALLBACK      CTL_CODE_HIDE(7)
#define IOCTL_DOBRO_THREAD_CALLBACK_RET	        CTL_CODE_HIDE(8)
#define IOCTL_DOBRO_THREAD_ROLLBACK_RET	        CTL_CODE_HIDE(9)

#define IOCTL_DOBRO_HOOK_MINIFILTER             CTL_CODE_HIDE(100)
#define IOCTL_DOBRO_UNHOOK_MINIFILTER	        CTL_CODE_HIDE(101)

#define IOCTL_DOBRO_GET_LIST_ALL	            CTL_CODE_HIDE(102)

#define IOCTL_DOBRO_HOOK_CALLBACK_PS            CTL_CODE_HIDE(103)
#define IOCTL_DOBRO_HOOK_CALLBACK_THR           CTL_CODE_HIDE(104)
#define IOCTL_DOBRO_UNHOOK_CALLBACK_PS          CTL_CODE_HIDE(105)
#define IOCTL_DOBRO_UNHOOK_CALLBACK_THR         CTL_CODE_HIDE(106)

#define DEF_MOD_NAME_LEN_SYM    (64)
#define DEF_MOD_NAME_COUNT      (64)

#pragma pack(push, 1)
struct DobroData
{
	int list;
	int remove;
	int index;
    int rc;
    wchar_t wcModuleName[DEF_MOD_NAME_LEN_SYM];
};
#pragma pack(pop)

struct ModulesData
{
	CHAR ModuleName[256];
	ULONG64 ModuleBase;
};

enum TypeCallbackPSFS
{
    TYPE_CALLBACK_PS,
    TYPE_CALLBACK_THR,
    TYPE_CALLBACK_FS
};

#pragma pack(push, 1)
typedef struct _CALLBACK_PS_FS
{
    TypeCallbackPSFS    Type;
    unsigned long long  Index;
    unsigned long long  NotifyAddress;
    unsigned long long  ModuleBase;
    union
    {
        char    chModuleName[DEF_MOD_NAME_LEN_SYM];
        wchar_t wcModuleName[DEF_MOD_NAME_LEN_SYM];
    };
} CALLBACK_PS_FS, * PCALLBACK_PS_FS;
#pragma pack(pop)

enum TypeNotifyCallback
{
    TYPE_EMPTY_NOTIFY,
    TYPE_PS_NOTIFY,
    TYPE_PS_NOTIFY_EX,
    TYPE_PS_NOTIFY_EX2,
    TYPE_THREAD_NOTIFY
};

typedef struct _INFO_NOTIFY_CALLBACK
{
    TypeNotifyCallback  Type;
    unsigned long long  NotifyAddress;
} INFO_NOTIFY_CALLBACK, * PINFO_NOTIFY_CALLBACK;

//////////////////////////////////////////////////////////////////////////
// https://www.gaijin.at/en/infos/windows-version-numbers
//////////////////////////////////////////////////////////////////////////
typedef enum _WINDOWS_INDEX
{
	WindowsIndexUNSUPPORTED = 0,
	WindowsIndexXP = 1,
	WindowsIndex2K3 = 2,
	WindowsIndexVISTA = 3,
	WindowsIndexWIN7 = 4,
	WindowsIndexWIN8 = 5,
	WindowsIndexWIN81 = 6,
	WindowsIndexWIN10_1507 = 7,
	WindowsIndexWIN10_1511 = 8,
	WindowsIndexWIN10_1607 = 9,
	WindowsIndexWIN10_1703 = 10,
	WindowsIndexWIN10_1709 = 11,
	WindowsIndexWIN10_1803 = 12,
	WindowsIndexWIN10_1809 = 13,
	WindowsIndexWIN10_1903 = 14,
	WindowsIndexWIN10_1909 = 15,
	WindowsIndexWIN10_2004 = 16,
} WINDOWS_INDEX, * PWINDOWS_INDEX;

#pragma warning(disable:4201)

typedef union
{
	struct
    {
		UINT64 protection_enable : 1;
		UINT64 monitor_coprocessor : 1;
		UINT64 emulate_fpu : 1;
		UINT64 task_switched : 1;
		UINT64 extension_type : 1;
		UINT64 numeric_error : 1;
		UINT64 reserved_1 : 10;
		UINT64 write_protect : 1;
		UINT64 reserved_2 : 1;
		UINT64 alignment_mask : 1;
		UINT64 reserved_3 : 10;
		UINT64 not_write_through : 1;
		UINT64 cache_disable : 1;
		UINT64 paging_enable : 1;
	};

	UINT64 flags;
} cr0;

