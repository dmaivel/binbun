// The source of globals-x86_64.elf, built by scripts/build-fixtures.sh:
// a 24-byte global, `record`, that `fill` fills field by field (a 4-byte
// field at 0 and at 4, an 8-byte field at 8 and at 16) and other
// functions read, one of them with a 16-byte load spanning the fields at
// 8 and 16. Keep them in sync with crates/binbun/tests/globals.rs.

    .intel_syntax noprefix
    .text
    .globl _start
    .type _start, @function
_start:
    call    fill
    call    second
    call    last
    lea     rdi, [rip + copy]
    call    pair
1:  jmp     1b
    .size _start, . - _start

// Every field written.
    .globl fill
    .type fill, @function
fill:
    mov     dword ptr [rip + record], 1
    mov     dword ptr [rip + record + 4], 2
    mov     qword ptr [rip + record + 8], 3
    mov     qword ptr [rip + record + 16], 4
    ret
    .size fill, . - fill

// The field at 4, read directly.
    .globl second
    .type second, @function
second:
    mov     eax, dword ptr [rip + record + 4]
    ret
    .size second, . - second

// The field at 16, read directly, twice.
    .globl last
    .type last, @function
last:
    mov     rax, qword ptr [rip + record + 16]
    add     rax, qword ptr [rip + record + 16]
    ret
    .size last, . - last

// The fields at 8 and 16 in one 16-byte load, stored at rdi.
    .globl pair
    .type pair, @function
pair:
    movups  xmm0, xmmword ptr [rip + record + 8]
    movups  xmmword ptr [rdi], xmm0
    ret
    .size pair, . - pair

    .bss
    .p2align 4
    .globl record
    .type record, @object
    .size record, 24
record:
    .zero   24
    .globl copy
    .type copy, @object
    .size copy, 16
copy:
    .zero   16
