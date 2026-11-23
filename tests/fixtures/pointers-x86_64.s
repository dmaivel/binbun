// The source of pointers-x86_64.elf, built by scripts/build-fixtures.sh:
// globals holding the address of an array, read through an index.
// `names` points to an array of pointers to bytes (`names[i][0]`);
// `pairs` to 16-byte elements whose first 8 bytes point to bytes
// (`pairs + 16 * i`: no array of pointers); `counts` to an array whose
// elements are read as pointers to bytes and written as integers (no
// array of pointers either); `stack` to an array of pointers to bytes
// read at an offset computed apart, a multiple of 8 (`n * 8 - 8`, then
// added scaled by 1, as `lea` does), and 8 bytes below it; `odd` to one
// read 4 bytes past such an offset, and `skewed` to one read at an index
// and 4 bytes past it (no array of pointers either). Keep them in sync
// with crates/binbun/tests/globals.rs.

    .intel_syntax noprefix
    .text
    .globl _start
    .type _start, @function
_start:
    xor     edi, edi
    call    first_letter
    xor     edi, edi
    call    pair_letter
    xor     edi, edi
    mov     esi, 1
    call    count_letter
    mov     edi, 2
    call    top_letters
    mov     edi, 2
    call    odd_letter
    xor     edi, edi
    call    skewed_letters
1:  jmp     1b
    .size _start, . - _start

// names[i][0].
    .globl first_letter
    .type first_letter, @function
first_letter:
    mov     rax, qword ptr [rip + names]
    mov     rax, qword ptr [rax + rdi*8]
    movzx   eax, byte ptr [rax]
    ret
    .size first_letter, . - first_letter

// The byte the first 8 bytes of the 16-byte element i point to, read
// twice through the element's address (a value of its own).
    .globl pair_letter
    .type pair_letter, @function
pair_letter:
    mov     rax, qword ptr [rip + pairs]
    shl     rdi, 4
    add     rax, rdi
    mov     rcx, qword ptr [rax]
    movzx   ecx, byte ptr [rcx]
    mov     rax, qword ptr [rax]
    movzx   eax, byte ptr [rax]
    add     eax, ecx
    ret
    .size pair_letter, . - pair_letter

// The byte element i points to, then element i holds the integer j.
    .globl count_letter
    .type count_letter, @function
count_letter:
    mov     rcx, qword ptr [rip + counts]
    mov     rax, qword ptr [rcx + rdi*8]
    movzx   eax, byte ptr [rax]
    movsxd  rsi, esi
    mov     qword ptr [rcx + rdi*8], rsi
    ret
    .size count_letter, . - count_letter

// stack[n - 1][0] + stack[n - 2][0], the offset of stack[n - 1] computed
// apart: (n * 8 - 8) * 1.
    .globl top_letters
    .type top_letters, @function
top_letters:
    mov     rsi, qword ptr [rip + stack]
    lea     rdx, [rdi*8 - 8]
    lea     rcx, [rsi + rdx*1]
    mov     rax, qword ptr [rcx]
    movzx   eax, byte ptr [rax]
    mov     rcx, qword ptr [rcx - 8]
    movzx   ecx, byte ptr [rcx]
    add     eax, ecx
    ret
    .size top_letters, . - top_letters

// The byte 8 bytes read at (n * 8 - 4) * 1 point to: no element's.
    .globl odd_letter
    .type odd_letter, @function
odd_letter:
    mov     rsi, qword ptr [rip + odd]
    lea     rdx, [rdi*8 - 4]
    mov     rax, qword ptr [rsi + rdx*1]
    movzx   eax, byte ptr [rax]
    ret
    .size odd_letter, . - odd_letter

// The bytes 8 bytes read at element i and 4 bytes past it point to.
    .globl skewed_letters
    .type skewed_letters, @function
skewed_letters:
    mov     rsi, qword ptr [rip + skewed]
    mov     rax, qword ptr [rsi + rdi*8]
    movzx   eax, byte ptr [rax]
    mov     rcx, qword ptr [rsi + rdi*8 + 4]
    movzx   ecx, byte ptr [rcx]
    add     eax, ecx
    ret
    .size skewed_letters, . - skewed_letters

    .bss
    .p2align 3
    .globl names
    .type names, @object
    .size names, 8
names:
    .zero   8
    .globl pairs
    .type pairs, @object
    .size pairs, 8
pairs:
    .zero   8
    .globl counts
    .type counts, @object
    .size counts, 8
counts:
    .zero   8
    .globl stack
    .type stack, @object
    .size stack, 8
stack:
    .zero   8
    .globl odd
    .type odd, @object
    .size odd, 8
odd:
    .zero   8
    .globl skewed
    .type skewed, @object
    .size skewed, 8
skewed:
    .zero   8
