#include <ntddk.h>

#include "main.h"
#include "HookLib.h"

static UNICODE_STRING StringNtCreateUserProcess = RTL_CONSTANT_STRING(L"NtCreateUserProcess");
static NtCreateUserProcess_t OriginalNtCreateProcess = NULL;

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
    OriginalNtCreateProcess = (NtCreateUserProcess_t)MmGetSystemRoutineAddress(&StringNtCreateUserProcess);
    if (!OriginalNtCreateProcess) {
        KdPrint(("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtCreateUserProcess));
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }

    OriginalNtCreateProcess = (NtCreateUserProcess_t)hook(OriginalNtCreateProcess, DetourNtCreateUserProcess);

    DriverObject->DriverUnload = [](PDRIVER_OBJECT DriverObject) {
        UNREFERENCED_PARAMETER(DriverObject);
        if (OriginalNtCreateProcess) {
            unhook(OriginalNtCreateProcess);
        }
    };

    return STATUS_SUCCESS;
}

NTSTATUS DetourNtCreateUserProcess
(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags,
    _In_ ULONG ThreadFlags,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_ PPS_ATTRIBUTE_LIST AttributeList
) {
    ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes;
    ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList;

    KdPrint(("----CreateUserProcess hook-------\n"));
    OriginalNtCreateProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

    return STATUS_SUCCESS;
}