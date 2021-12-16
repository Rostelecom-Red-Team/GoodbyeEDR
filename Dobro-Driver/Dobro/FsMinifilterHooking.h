#pragma once

#include <fltKernel.h>
#include "PrivateStructs.h"
#include "RAIIUtils.h"

typedef FLT_PREOP_CALLBACK_STATUS(*PreCallbackProt)(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

typedef FLT_POSTOP_CALLBACK_STATUS(*PostCallbackProt)(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

// Array that contain all instances that hooked and their original CallbackNodes
ArrayGuard<FltInstanceGuard*, true>* originalInstances = nullptr;

FLT_PREOP_CALLBACK_STATUS DummyCreatePreOperation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext);

CONST FLT_OPERATION_REGISTRATION Callbacks[] = 
{
    { IRP_MJ_CREATE, 0, DummyCreatePreOperation, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = 
{
    sizeof(FLT_REGISTRATION),           //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    NULL,                               //  Context Registration.
    Callbacks,                          //  Operation callbacks
    NULL,                               //  FilterUnload
    NULL,                               //  InstanceSetup
    NULL,                               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  NormalizeNameComponent
    NULL,                               //  NormalizeContextCleanup
};

// Get CallbackNodes from global instances array by specific instance in parameter
PCALLBACK_NODE GetCachedCallbackNodesByInstance(PFLT_INSTANCE instance);

