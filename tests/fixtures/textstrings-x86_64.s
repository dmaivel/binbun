// The source of textstrings-x86_64.elf, built by scripts/build-fixtures.sh:
// strings in .text after the code, as MSVC places a driver's, their
// addresses taken by `lea` only (no symbol names them): a narrow one and
// a wide (UTF-16LE) one, passed to `show`; and `callback`, code whose
// address is taken by `lea` only too, which stays a function. Keep them
// in sync with crates/binbun/tests/textstrings.rs.

    .intel_syntax noprefix
    .text
    .globl _start
    .type _start, @function
_start:
    lea     rdi, [rip + .Lnarrow]
    lea     rsi, [rip + .Lwide]
    lea     rdx, [rip + .Lcallback]
    call    show
1:  jmp     1b
    .size _start, . - _start

// Calls its third argument with its first two.
    .globl show
    .type show, @function
show:
    jmp     rdx
    .size show, . - show

    .p2align 4
.Lcallback:
    push    rbx
    mov     rbx, rdi
    mov     eax, dword ptr [rsi]
    add     eax, dword ptr [rbx]
    pop     rbx
    ret

.Lnarrow:
    .asciz  "narrow text in .text"
    .p2align 1
.Lwide:
    .short  'w', 'i', 'd', 'e', ' ', 't', 'e', 'x', 't', 0
