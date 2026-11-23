// The source of opaque-aarch64.elf, built by scripts/build-fixtures.sh:
// functions that pass a pointer into their own frame through a
// floating-point register (fmov, lifted) or through instructions without
// semantics (a system register L0 does not declare), store through the
// copy and load the slot again. L1 must not take the load as reading the
// earlier store. Keep them in sync with crates/binbun/tests/opaque.rs and
// crates/binbun/tests/eval.rs.

    .text
    .globl _start
    .type _start, %function
_start:
    bl      through_fp
    bl      through_sysreg
1:  b       1b
    .size _start, . - _start

// x1 stored at [sp, #16]; a copy of sp made through d0 (fmov) overwrites
// the slot with x2; the load gives x2.
    .globl through_fp
    .type through_fp, %function
through_fp:
    stp     x29, x30, [sp, #-32]!
    str     x1, [sp, #16]
    mov     x9, sp
    fmov    d0, x9
    fmov    x10, d0
    str     x2, [x10, #16]
    ldr     x0, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret
    .size through_fp, . - through_fp

// The same through FPMR (s3_3_c4_c4_2), a system register L0 does not
// declare.
    .globl through_sysreg
    .type through_sysreg, %function
through_sysreg:
    stp     x29, x30, [sp, #-32]!
    str     x1, [sp, #16]
    mov     x9, sp
    msr     s3_3_c4_c4_2, x9
    mrs     x10, s3_3_c4_c4_2
    str     x2, [x10, #16]
    ldr     x0, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret
    .size through_sysreg, . - through_sysreg
