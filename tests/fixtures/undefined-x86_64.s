// The source of undefined-x86_64.elf, built by scripts/build-fixtures.sh:
// functions that read flags SHRD leaves undefined (OF and AF for a count
// other than 1: AMD, Intel's P-cores and its E-cores set them
// differently), by a branch, SETO and LAHF; _start sums what they return
// and exits with it. Their C must never show a constant there, nor drop
// the branch. Last, two functions _start doesn't call (so the others keep
// their addresses): a count of 1, whose OF is defined, and the owner's
// example on a known input. Keep them in sync with
// crates/binbun-cli/tests/undefined.rs.

    .intel_syntax noprefix
    .text
    .globl _start
    .type _start, @function
_start:
    mov     rbx, rdi
    mov     r12, rsi
    mov     rdi, rbx
    call    shrd_jo
    mov     r13d, eax
    mov     rdi, rbx
    mov     rsi, r12
    call    shrd_seto
    add     r13d, eax
    mov     rdi, rbx
    mov     rsi, r12
    call    shrd_lahf
    add     r13d, eax
    mov     rdi, rbx
    mov     rsi, r12
    call    two_shrds
    add     r13d, eax
    mov     edi, r13d
    mov     eax, 60
    syscall
    ud2
    .size _start, . - _start

// The owner's example: SHRD RDX, RDX, 0x1D, then a branch on OF.
    .globl shrd_jo
    .type shrd_jo, @function
shrd_jo:
    mov     rdx, rdi
    shrd    rdx, rdx, 0x1d
    jo      1f
    mov     eax, 2
    ret
1:  mov     eax, 1
    ret
    .size shrd_jo, . - shrd_jo

// OF by SETO.
    .globl shrd_seto
    .type shrd_seto, @function
shrd_seto:
    mov     rax, rdi
    shrd    rax, rsi, 3
    seto    al
    movzx   eax, al
    ret
    .size shrd_seto, . - shrd_seto

// AF by LAHF (bit 4 of AH).
    .globl shrd_lahf
    .type shrd_lahf, @function
shrd_lahf:
    mov     rax, rdi
    shrd    rax, rsi, 5
    lahf
    movzx   eax, ah
    ret
    .size shrd_lahf, . - shrd_lahf

// Two SHRDs each leaving OF undefined: two names.
    .globl two_shrds
    .type two_shrds, @function
two_shrds:
    shrd    rdi, rsi, 3
    seto    al
    shrd    rdi, rsi, 5
    seto    cl
    add     al, cl
    movzx   eax, al
    ret
    .size two_shrds, . - two_shrds

// The "lie to decompilers": OF is defined for a count of 1 (the sign
// changed: 0xDEAD rotated right by 1 sets bit 63), so CMOVO picks 0xBEEF
// (a decompiler that treats OF as undefined shows 0xDEAD).
    .globl shrd_by_one
    .type shrd_by_one, @function
shrd_by_one:
    mov     rax, 0xDEAD
    mov     rdx, 0xBEEF
    mov     r8, 0xDEAD
    shrd    r8, r8, 1
    cmovo   rax, rdx
    ret
    .size shrd_by_one, . - shrd_by_one

// The owner's example on its input, 0x8F: a count of 29, so OF stays
// undefined however well the input is known.
    .globl shrd_jo_known
    .type shrd_jo_known, @function
shrd_jo_known:
    mov     rdx, 0x8f
    shrd    rdx, rdx, 0x1d
    jo      1f
    mov     eax, 2
    ret
1:  mov     eax, 1
    ret
    .size shrd_jo_known, . - shrd_jo_known
