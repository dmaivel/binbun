# A shared library whose functions are exported in every way that does
# and does not interpose a name (with exports-x86_64.map):
# `malloc@@V2` and `memcpy@@V2` (default versions), `memcpy@V1` (an
# older version), `calloc` (protected: still bound by other modules),
# `free` (hidden) and `read` (local) not exported at all.
    .text

    .globl malloc
    .type malloc, @function
malloc:
    mov %rdi, %rax
    ret
    .size malloc, . - malloc

    .globl memcpy_v1
    .type memcpy_v1, @function
memcpy_v1:
    xor %eax, %eax
    ret
    .size memcpy_v1, . - memcpy_v1
    .symver memcpy_v1, memcpy@V1

    .globl memcpy_v2
    .type memcpy_v2, @function
memcpy_v2:
    mov %rdi, %rax
    ret
    .size memcpy_v2, . - memcpy_v2
    .symver memcpy_v2, memcpy@@V2

    .globl calloc
    .protected calloc
    .type calloc, @function
calloc:
    xor %eax, %eax
    ret
    .size calloc, . - calloc

    .globl free
    .hidden free
    .type free, @function
free:
    ret
    .size free, . - free

    .type read, @function
read:
    xor %eax, %eax
    ret
    .size read, . - read

    .globl _start
    .type _start, @function
_start:
    call read
    call free
    ret
    .size _start, . - _start
