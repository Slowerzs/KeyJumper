#include "utils/alloc.h"
#include <Windows.h>

void *jalloc(size_t size)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

void jfree(void *ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

void *jrealloc(void *ptr, size_t new_size)
{
    if (ptr == nullptr)
    {
        return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, new_size);
    }

    return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, new_size);
}
