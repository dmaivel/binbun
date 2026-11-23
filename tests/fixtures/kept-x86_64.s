// The source of kept-x86_64.elf, built by scripts/build-fixtures.sh:
// callee-saved registers whose entry value is read. Keep it in sync with
// crates/binbun/tests/decompile.rs.

    .text
    .globl _start
    .type _start, %function
_start:
    call    caller
    call    thunk
1:  jmp     1b
    .size _start, . - _start

// r15 is set only where the flag in edi is, and stored to `sink` only
// where `gate` says, as GCC leaves a variable unassigned where its use is
// guarded by the same condition as its assignment: on the path with
// neither, the store is of the caller's r15. The function saves and
// restores r15.
    .globl root
    .type root, %function
root:
    push    %r15
    test    %edi, %edi
    je      2f
    mov     $42, %r15d
2:  mov     gate(%rip), %eax
    test    %eax, %eax
    je      3f
    mov     %r15, sink(%rip)
3:  pop     %r15
    ret
    .size root, . - root

// Calls root with its own r15 as it found it.
    .globl caller
    .type caller, %function
caller:
    push    %rbx
    mov     $1, %edi
    call    root
    pop     %rbx
    ret
    .size caller, . - caller

// Takes a value in r15 and does not save it, as a retpoline thunk does.
    .globl thunk
    .type thunk, %function
thunk:
    mov     %r15, sink(%rip)
    ret
    .size thunk, . - thunk

    .data
gate:
    .long   1
    .p2align 3
sink:
    .quad   0
