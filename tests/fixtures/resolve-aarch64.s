// The source of resolve-aarch64.elf, built by scripts/build-fixtures.sh and
// linked against resolve-aarch64-lib.s (a stand-in for libc): calls and a
// tail call through the PLT and a call through the GOT to imports, two of
// which never return, and switches compiled to tables as GCC and Clang
// compile them. Keep it in sync with crates/binbun-cli/tests/resolve.rs.

    .text
    .globl _start
    .type _start, %function
_start:
    .cfi_startproc
    mov     w0, #2
    bl      guarded
    bl      halves
    bl      words
    mov     x0, sp
    bl      width
    cbnz    w0, 1f
    bl      got_abort
1:  cbnz    w0, 2f
    bl      tail_exit
2:  mov     w0, #0
    bl      exit
    // Not code: exit never returns.
    udf     #0
    .cfi_endproc
    .size _start, . - _start

// GCC: a byte table of offsets from a code base, the index bounded by
// `cmp` and `b.hi` to the default.
    .globl guarded
    .type guarded, %function
guarded:
    .cfi_startproc
    cmp     w0, #3
    b.hi    .Lg_default
    adrp    x1, .Lg_table
    add     x1, x1, :lo12:.Lg_table
    ldrb    w2, [x1, w0, uxtw]
    adr     x3, .Lg_base
    add     x2, x3, w2, sxtb #2
    br      x2
.Lg_base:
.Lg0:
    mov     w0, #10
    ret
.Lg1:
    mov     w0, #11
    ret
.Lg2:
    mov     w0, #12
    ret
.Lg3:
    mov     w0, #13
    ret
.Lg_default:
    bl      puts
    mov     w0, #0
    ret
    .cfi_endproc
    .size guarded, . - guarded

// Clang: a halfword table of offsets from a code base, the jump on the
// `b.ls` side of the guard.
    .globl halves
    .type halves, %function
halves:
    .cfi_startproc
    cmp     w0, #4
    b.ls    1f
    mov     w0, #0
    ret
1:  adrp    x8, .Lh_table
    add     x8, x8, :lo12:.Lh_table
    adr     x9, .Lh_base
    ldrh    w10, [x8, w0, uxtw #1]
    add     x9, x9, x10, lsl #2
    br      x9
.Lh_base:
.Lh0:
    ret
.Lh1:
    mov     w0, #31
    ret
.Lh2:
    mov     w0, #32
    ret
.Lh3:
    mov     w0, #33
    ret
.Lh4:
    mov     w0, #34
    ret
    .cfi_endproc
    .size halves, . - halves

// A word table of offsets from the table itself, bounded by `b.hs` to
// the default.
    .globl words
    .type words, %function
words:
    .cfi_startproc
    cmp     w0, #3
    b.hs    .Lwd_default
    adrp    x1, .Lwd_table
    add     x1, x1, :lo12:.Lwd_table
    ldrsw   x2, [x1, w0, uxtw #2]
    add     x1, x1, x2
    br      x1
.Lwd0:
    mov     w0, #40
    ret
.Lwd1:
    mov     w0, #41
    ret
.Lwd2:
    mov     w0, #42
    ret
.Lwd_default:
    mov     w0, #0
    ret
    .cfi_endproc
    .size words, . - words

// An enum's byte, loaded and used as the index with no guard (the
// compiler knew its range): only its width bounds the table, which ends
// where the halfword table, which `halves` addresses, begins.
    .globl width
    .type width, %function
width:
    .cfi_startproc
    ldrb    w0, [x0]
    adrp    x1, .Lw_table
    add     x1, x1, :lo12:.Lw_table
    ldrb    w2, [x1, w0, uxtw]
    adr     x3, .Lw_base
    add     x2, x3, w2, sxtb #2
    br      x2
.Lw_base:
.Lw0:
    mov     w0, #20
    ret
.Lw1:
    mov     w0, #21
    ret
.Lw2:
    mov     w0, #22
    ret
    .cfi_endproc
    .size width, . - width

// abort through its GOT entry (`-fno-plt`): the call never returns.
    .globl got_abort
    .type got_abort, %function
got_abort:
    .cfi_startproc
    adrp    x16, :got:abort
    ldr     x16, [x16, :got_lo12:abort]
    blr     x16
    ret
    .cfi_endproc
    .size got_abort, . - got_abort

// A tail call to exit through its PLT stub.
    .globl tail_exit
    .type tail_exit, %function
tail_exit:
    .cfi_startproc
    mov     w0, #1
    b       exit
    .cfi_endproc
    .size tail_exit, . - tail_exit

    .section .rodata
    .p2align 2
.Lg_table:
    .byte   (.Lg0 - .Lg_base) / 4, (.Lg2 - .Lg_base) / 4
    .byte   (.Lg1 - .Lg_base) / 4, (.Lg3 - .Lg_base) / 4
// Four entries (the last case twice), so that the next table is aligned.
.Lw_table:
    .byte   (.Lw0 - .Lw_base) / 4, (.Lw1 - .Lw_base) / 4
    .byte   (.Lw2 - .Lw_base) / 4, (.Lw1 - .Lw_base) / 4
// Read on from .Lw_table, its first entry (1) would be the `ret` of
// width's first case.
.Lh_table:
    .hword  (.Lh1 - .Lh_base) / 4, (.Lh0 - .Lh_base) / 4
    .hword  (.Lh2 - .Lh_base) / 4, (.Lh3 - .Lh_base) / 4
    .hword  (.Lh4 - .Lh_base) / 4
    .p2align 2
.Lwd_table:
    .word   .Lwd0 - .Lwd_table, .Lwd1 - .Lwd_table, .Lwd2 - .Lwd_table
