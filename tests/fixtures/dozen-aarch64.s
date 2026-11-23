// The source of dozen-aarch64.elf, built by scripts/build-fixtures.sh:
// AArch64 functions written only with the dozen instructions lifted first
// (ADD and ORR shifted register, SUBS immediate, LDR/STR immediate, STP
// pre-index, LDP post-index, ADRP, B, BL, B.cond, CBZ, RET), shaped as a
// compiler writes them. Keep them in sync with crates/binbun-cli/tests.

    .text
    .globl _start
    .type _start, %function
_start:
    bl      saved_sum
    bl      loop_sum
    bl      table_entry
1:  b       1b
    .size _start, . - _start

// x0 + x1.
    .globl leaf_sum
    .type leaf_sum, %function
leaf_sum:
    add     x0, x0, x1
    ret
    .size leaf_sum, . - leaf_sum

// leaf_sum(x0, x1) + x0, keeping x0 in a callee-saved register saved in
// the frame.
    .globl saved_sum
    .type saved_sum, %function
saved_sum:
    stp     x29, x30, [sp, #-32]!
    str     x19, [sp, #16]
    mov     x19, x0
    bl      leaf_sum
    add     x0, x0, x19
    ldr     x19, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret
    .size saved_sum, . - saved_sum

// x0 + (x0 - 1) + ... + 1.
    .globl loop_sum
    .type loop_sum, %function
loop_sum:
    mov     x1, xzr
    cbz     x0, 2f
1:  add     x1, x1, x0
    subs    x0, x0, #1
    b.ne    1b
2:  mov     x0, x1
    ret
    .size loop_sum, . - loop_sum

// The second entry of a read-only table, shifted left by 2 (a constant).
    .globl table_entry
    .type table_entry, %function
table_entry:
    adrp    x8, table
    ldr     x0, [x8, :lo12:table + 8]
    add     x0, xzr, x0, lsl #2
    ret
    .size table_entry, . - table_entry

// A tail call.
    .globl tail_sum
    .type tail_sum, %function
tail_sum:
    orr     x1, x1, x1, lsl #1
    b       leaf_sum
    .size tail_sum, . - tail_sum

    .section .rodata
    .balign 8
table:
    .quad   0x1111
    .quad   0x2a
