#ifndef UTILS_ALLOC_H
#define UTILS_ALLOC_H

#include <stddef.h>
#include <Windows.h>
#include <winnt.h>

typedef struct _NonPageBuffer
{
    HANDLE write_pipe;
    HANDLE read_pipe;
    size_t kernel_address;
} NonPagedBuffer;

void *jalloc(size_t size);
void jfree(void *ptr);
void *jrealloc(void* ptr, size_t new_size);
void *jalloc_locked(size_t size, HANDLE write_pipe);

#endif
