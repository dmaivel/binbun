// The source of opaque-x86_64.elf, built by scripts/build-fixtures.sh:
// functions that pass a pointer into their own frame through instructions
// without semantics (AVX-512: a vector register L0 declares, a mask
// register it does not), store through the copy and load the slot again.
// L1 must not take the load as reading the earlier store. Keep them in
// sync with crates/binbun/tests/opaque.rs. Then first_difference, the
// pattern of glibc's __memcmp_evex_movbe: a branch on what instructions
// without semantics leave in a register.

    .intel_syntax noprefix
    .text
    .globl _start
    .type _start, @function
_start:
    call    through_vector
    call    through_mask
    call    first_difference
1:  jmp     1b
    .size _start, . - _start

// rdi stored at [rsp + 8]; a copy of its address made through zmm0
// (vpbroadcastq) overwrites the slot with rsi; the load gives rsi.
    .globl through_vector
    .type through_vector, @function
through_vector:
    sub     rsp, 24
    mov     [rsp + 8], rdi
    lea     rax, [rsp + 8]
    vpbroadcastq zmm0, rax
    vmovq   rcx, xmm0
    mov     [rcx], rsi
    mov     rax, [rsp + 8]
    add     rsp, 24
    ret
    .size through_vector, . - through_vector

// The same through k1, a mask register L0 does not declare.
    .globl through_mask
    .type through_mask, @function
through_mask:
    sub     rsp, 24
    mov     [rsp + 8], rdi
    lea     rax, [rsp + 8]
    kmovq   k1, rax
    kmovq   rcx, k1
    mov     [rcx], rsi
    mov     rax, [rsp + 8]
    add     rsp, 24
    ret
    .size through_mask, . - through_mask

// The first 32 bytes at rdi and rsi compared as __memcmp_evex_movbe
// compares them: vpcmpnequb sets a bit of k1 for each byte that differs,
// kmovd copies the bits to eax, and the branch tests eax. 0 if they are
// equal, else the difference of the first bytes that differ.
    .globl first_difference
    .type first_difference, @function
first_difference:
    vmovdqu64 ymm17, [rsi]
    vpcmpnequb k1, ymm17, [rdi]
    kmovd   eax, k1
    test    eax, eax
    jne     2f
    ret
2:  tzcnt   eax, eax
    movzx   ecx, byte ptr [rsi + rax]
    movzx   eax, byte ptr [rdi + rax]
    sub     eax, ecx
    ret
    .size first_difference, . - first_difference
