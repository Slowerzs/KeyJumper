#ifndef LAUNCHER_KEXECDD_H
#define LAUNCHER_KEXECDD_H

#include "utils/vec.h"
#include <Windows.h>

#define DD_KSEC_DEVICE_NAME_U L"\\Device\\KsecDD"
#define IOCTL_KSEC_CONNECT_LSA CTL_CODE(FILE_DEVICE_KSEC, 0, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSEC_IPC_SET_FUNCTION_RETURN                                                         \
    CTL_CODE(FILE_DEVICE_KSEC, 27, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _KsecReturnStruct
{
    size_t function;
    size_t arg1;
    DWORD arg2;
} KsecReturnStruct;

typedef struct
{
    HANDLE child_handle;
    HANDLE ksec_handle;
    KsecReturnStruct *return_struct;
} KsecJopArgs;

bool kexec_get_driver_handle(HANDLE *ksec_handle, HANDLE write_handle);
bool kexec_connect(HANDLE ksec_handle, HANDLE write_handle);
bool kexec_start_jop(HANDLE ksec_handle, HANDLE write_handle, KsecReturnStruct *return_struct);
bool kexec_start_jop_and_key_log(
    Vec *pipes, HANDLE ksec_handle, HANDLE write_handle, KsecReturnStruct *return_struct
);

#endif