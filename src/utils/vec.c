#include "utils/vec.h"
#include "utils/alloc.h"

Vec *vec_new()
{
    Vec *vec = nullptr;

    vec = jalloc(sizeof(Vec));
    if (vec == nullptr)
        return nullptr;

    vec->capacity = 0x10;
    vec->buffer = jalloc(sizeof(void *) * vec->capacity);
    if (vec->buffer == nullptr)
    {
        jfree(vec);
        return nullptr;
    }

    return vec;
}

void vec_add(Vec *vec, void *item)
{
    if (vec->length + 1 > vec->capacity)
    {
        vec->capacity *= 2;
        vec->buffer = jrealloc(vec->buffer, vec->capacity);
    }
    vec->buffer[vec->length] = item;
    vec->length++;

    return;
}