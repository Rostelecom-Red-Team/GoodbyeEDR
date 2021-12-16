#pragma once

#include <fltKernel.h>
#include "PrivateStructs.h"
#include "Log.h"

constexpr ULONG TAG = 'FSH0';

template <class T, bool shouldDeleteObj = false>
class ArrayGuard
{
public:
    ArrayGuard() : _array(nullptr), _isValid(false), _size(0) {}

    void allocate(POOL_TYPE poolType, size_t objectsCount)
    {
        if (_array != nullptr)
        {
            ExFreePoolWithTag(_array, TAG);
            _isValid = false;
        }

        _array = static_cast<T*>(ExAllocatePoolWithTag(poolType, objectsCount * sizeof(T),TAG));
        if (_array == nullptr)
        {
            _isValid = false;
            _size = 0;

            LOG("[-] Allocate memory for array failed");
            return;
        }
        
        _isValid = true;
        _size = objectsCount;
    }

    ~ArrayGuard()
    {
        if ((_array != nullptr) && (isValid()))
        {
            if constexpr (shouldDeleteObj)
            {
                for (size_t i = 0; i < _size; i++)
                {
                    delete _array[i];
                }
            }

            ExFreePoolWithTag(_array, TAG);
        }

        _isValid = false;
    }

    void* operator new(size_t size)
    {
        return ExAllocatePoolWithTag(NonPagedPool, size, TAG);
    }

    void operator delete(void* p)
    {
        ExFreePoolWithTag(p, TAG);
    }

    T operator [](size_t idx) const { return _array[idx]; }
    T& operator [](size_t idx) { return _array[idx]; }
    T* get() { return _array; }
    bool isValid() const { return _isValid; }
    size_t getSize() { return _size; }

private:
    T* _array;
    bool _isValid;
    size_t _size;
};

/**
 *  guard a FLT_OBJECT
 *  release FLT_OBJECT when exiting the current context.
 */
template <class T>
class FltObjectGuard
{
public:
    class FltObjectGuard(
        T fltObject,
        bool shouldReference = true,
        bool shouldDereference = true,
        bool isValid = false) :
        _object(fltObject), _isValid(isValid), _shouldDereference(shouldDereference)
    {
        if (shouldReference)
        {
            if (NT_SUCCESS(FltObjectReference(_object)))
            {
                _isValid = true;
            }
        }
    }

    ~FltObjectGuard()
    {
        if ((_object != nullptr) && (isValid()) && (_shouldDereference))
        {
            FltObjectDereference(_object);
        }

        _isValid = false;
    }

    void* operator new(size_t size)
    {
        return ExAllocatePoolWithTag(NonPagedPool, size, TAG);
    }

    void operator delete(void* p)
    {
        ExFreePoolWithTag(p, TAG);
    }

    T& get() { return _object; }
    bool isValid() const { return _isValid; }

protected:
    T _object;
    bool _isValid;

    bool shouldDereference() { return _shouldDereference; }

private:
    bool _shouldDereference;
};

/**
 *  reference a FLT_INSTANCE
 *  release FLT_INSTANCE when exiting the current context.
 */
class FltInstanceGuard : public FltObjectGuard<PFLT_INSTANCE>
{
public:

    static constexpr unsigned short INVALID_OFFSET = 0xffff;

    FltInstanceGuard(
        PFLT_INSTANCE fltInstance,
        bool shouldReference = false,
        bool shouldDereference = true,
        bool isValid = true) :
        FltObjectGuard(fltInstance, shouldReference, shouldDereference, isValid) {}

    /**
     *  return pointer to field of CallbackNodes in FLT_INSTANCE
     */
    PCALLBACK_NODE* getPointerToCallbackNodesField()
    {
        if (_offsetCallbackNodesField == INVALID_OFFSET)
        {
            LOG("[-] Offset of CallbackNodes field not set");
            return nullptr;
        }

        return reinterpret_cast<PCALLBACK_NODE*>(
            reinterpret_cast<ULONG_PTR>(get()) + _offsetCallbackNodesField);
    }

    /**
     *  insert CALLBACK_NODE into cachedCallbackNodes
     */
    void cachingCallbackNodes()
    {
        PCALLBACK_NODE* callbackNodes = getPointerToCallbackNodesField();

        for (size_t index = 0; index < 50; index++)
        {
            if (MmIsAddressValid(callbackNodes[index]))
            {
                _cachedCallbackNodes[index] = *callbackNodes[index];
            }
        }
    }

    PCALLBACK_NODE getCachedCallbackNodes() { return _cachedCallbackNodes; }

    inline static void setOffsetCallbackNodes(unsigned short offsetCallbackNodes)
    {
        _offsetCallbackNodesField = offsetCallbackNodes;
    }

private:
    CALLBACK_NODE _cachedCallbackNodes[50] = { 0 };
    inline static unsigned short _offsetCallbackNodesField = INVALID_OFFSET;
};


/**
 *  guard a PFLT_FILTER
 *  release PFLT_FILTER when exiting the current context.
 */
class FltFilterGuard : public FltObjectGuard<PFLT_FILTER>
{
public:
    FltFilterGuard(
        PFLT_FILTER fltFilter,
        bool shouldReference = false,
        bool shouldDereference = true,
        bool isValid = false) :
        FltObjectGuard(fltFilter, shouldReference, shouldDereference, isValid) {}

    FltFilterGuard(PCUNICODE_STRING name) : FltObjectGuard(nullptr, false, true, false)
    {
        if (NT_SUCCESS(FltGetFilterFromName(name, &_object)))
        {
            _isValid = true;
        }
    }

    FltFilterGuard(
        PDRIVER_OBJECT DriverObject,
        const FLT_REGISTRATION& registersion) : FltObjectGuard(nullptr, false, false, false)
    {
        if (!NT_SUCCESS(FltRegisterFilter(DriverObject, &registersion, &_object)))
        {
            LOG("[-] FltRegisterFilter failed");
            return;
        }

        _isValid = true;
        _isRegistered = true;
    }

    ~FltFilterGuard()
    {
        if ((_object != nullptr) && (isValid()) && (shouldDereference()))
        {
            FltObjectDereference(_object);
        }

        if (isRegistered())
        {
            FltUnregisterFilter(get());
            _isRegistered = false;
        }

        _isValid = false;
    }

    NTSTATUS startFiltering()
    {
        NTSTATUS status = STATUS_UNSUCCESSFUL;

        if (isRegistered() && isValid())
        {
            status = FltStartFiltering(get());
        }

        if(!NT_SUCCESS(status))
        {
            LOG("[-] Failed to start filter");
        }

        return status;
    }

    unsigned long getInstances(ArrayGuard<FltInstanceGuard*, true>& instancesGuardArray)
    {
        NTSTATUS status = STATUS_SUCCESS;

        ArrayGuard<PFLT_INSTANCE> fltInstancesArray;
        ULONG fltInstancesNumber = 0;

        do
        {
            if (fltInstancesNumber != 0)
            {
                fltInstancesArray.allocate(NonPagedPool, fltInstancesNumber);
            }

            status = FltEnumerateInstances(
                NULL,
                get(),
                fltInstancesArray.get(),
                sizeof(PFLT_INSTANCE) * fltInstancesNumber,
                &fltInstancesNumber);

        } while ((status == STATUS_BUFFER_TOO_SMALL) && (fltInstancesNumber != 0));

        if (!NT_SUCCESS(status))
        {
            LOG("[-] Enumeration of instances by filter failed", NT_SUCCESS(status));
            return 0;
        }

        if (fltInstancesNumber == 0)
        {
            return 0;
        }

        instancesGuardArray.allocate(NonPagedPool, fltInstancesNumber);

        for (size_t i = 0; i < fltInstancesNumber; i++)
        {
            instancesGuardArray[i] = new FltInstanceGuard(fltInstancesArray[i], false, true, true);
        }

        return fltInstancesNumber;
    }

    bool isRegistered() { return _isRegistered; }

private:
    bool _isRegistered = false;
};

class FltVolumeGuard : public FltObjectGuard<PFLT_VOLUME>
{
public:
    FltVolumeGuard(FltInstanceGuard& instance) :
        FltObjectGuard(nullptr, false, true, false) {

        if (NT_SUCCESS(FltGetVolumeFromInstance(instance.get(), &_object)))
        {
            _isValid = true;
        }
    }
};