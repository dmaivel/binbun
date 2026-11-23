/* The twin of lie.s: imul by zero leaves ZF undefined (the architecture
   defines only CF and OF after a multiply), and processors choose
   differently. An i9-14900F's P-cores (Raptor Cove) clear it, its E-cores
   (Gracemont) set it as the product is zero, so this prints 0xdead on one
   and 0xbeef on the other. Run it pinned to each: run.sh. */
    .intel_syntax noprefix
    .section .rodata
fmt:
    .asciz "%#llx\n"
    .text
    .globl main
    .type main, @function
main:
    sub rsp, 8
    xor ecx, ecx
    mov rax, 0xDEAD
    mov rdx, 0xBEEF
    mov r8, 0xDEAD
    imul r8, rcx
    cmovz rax, rdx
    mov rsi, rax
    lea rdi, [rip + fmt]
    xor eax, eax
    call printf@PLT
    xor eax, eax
    add rsp, 8
    ret
    .size main, .-main
    .section .note.GNU-stack,"",@progbits
