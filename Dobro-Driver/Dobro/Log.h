#pragma once

#define DRIVER_PREFIX   "[D0BR0]"

#if DBG
    #define LOG(format, ...) \
        DbgPrint(   DRIVER_PREFIX "[" __FUNCTION__ "][irql:%Iu,pid:%Iu,tid:%Iu]" format "\n",  \
                    KeGetCurrentIrql(),       \
                    PsGetCurrentProcessId(),  \
                    PsGetCurrentThreadId(),   \
                    __VA_ARGS__)
#else
    #define LOG(format, ...)
#endif