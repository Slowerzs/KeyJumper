#ifndef LAUNCHER_PRIVILEGES_H
#define LAUNCHER_PRIVILEGES_H

#include <Windows.h>
#include <stdbool.h>
#include <stddef.h>


bool privs_enable_privilege(LPCSTR privilege_name);
bool privs_steal_winlogon_token();
bool privs_revert_impersonation();

#endif
