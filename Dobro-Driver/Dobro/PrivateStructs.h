#pragma once

#include <fltKernel.h>

typedef struct _CALLBACK_NODE
{
    LIST_ENTRY CallbackLinks;
    PFLT_INSTANCE Instance;
    PVOID PreOperation;
    PVOID PostOperation;
    LONG Flags;
} CALLBACK_NODE, * PCALLBACK_NODE;
