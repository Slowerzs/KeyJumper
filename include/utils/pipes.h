#ifndef UTILS_PIPES_H
#define UTILS_PIPES_H

#include "utils/vec.h"
#include <Windows.h>
#include <stdbool.h>
#include <stddef.h>

#define PIPE_BUFFER_SIZE 0x11000
#define PIPE_HEADER_SIZE 0x30

bool pipes_create(Vec **pipes);
bool pipes_map_buffer_in_nonpaged_pool(
    Vec *vec_pipes,
    size_t pipe_index,
    void *buffer,
    size_t buffer_len,
    HANDLE child_pipe,
    size_t *ret_address
);
#endif
