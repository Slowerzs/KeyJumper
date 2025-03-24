#ifndef UTILS_VEC_H
#define UTILS_VEC_H

#include <stddef.h>
typedef struct _Vec
{
    size_t length;
    size_t capacity;
    void **buffer;
} Vec;

void vec_add(Vec *vec, void *item);
Vec *vec_new();

#endif