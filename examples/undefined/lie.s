/* The 'lie to decompilers': imul r8, r8 on 0xDEADBEEFDEAD overflows, which
   sets OF (defined after a multiply, unlike ZF), so cmovo picks 0xBEEF and
   this always prints 0xbeef. A decompiler that takes every flag a multiply
   leaves as undefined, or folds OF to 0, shows 0xDEAD. */
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
    mov r8, 0xDEADBEEFDEAD
    imul r8, r8
    cmovo rax, rdx
    mov rsi, rax
    lea rdi, [rip + fmt]
    xor eax, eax
    call printf@PLT
    xor eax, eax
    add rsp, 8
    ret
    .size main, .-main
    .section .note.GNU-stack,"",@progbits
