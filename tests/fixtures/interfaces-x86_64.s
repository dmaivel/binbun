// The source of interfaces-x86_64.elf, built by scripts/build-fixtures.sh:
// functions whose parameters lowering finds from what their code reads.
// `_start` calls none of them, so each keeps the interface its body gives
// (callers that drop a result would drop what computes it). Keep them in
// sync with crates/binbun/tests/decompile.rs.

    .intel_syntax noprefix
    .text
    .globl _start
    .type _start, @function
_start:
1:  jmp     1b
    .size _start, . - _start

// `(a == 7) & (a == b)`. `sete dl` keeps bits 8 to 63 of `rdx`, and
// `and eax, edx` reads `edx` where `eax` is 0 or 1: nothing of the entry
// value of `rdx` is read. Two parameters.
    .globl both
    .type both, @function
both:
    cmp     rdi, rsi
    sete    dl
    xor     eax, eax
    cmp     rdi, 7
    sete    al
    and     eax, edx
    ret
    .size both, . - both

// The same write of `dl`, then all of `edx` returned: bits 8 to 31 of the
// entry value of `rdx` are read. Three parameters.
    .globl kept
    .type kept, @function
kept:
    cmp     rdi, rsi
    sete    dl
    mov     eax, edx
    ret
    .size kept, . - kept

// Sets both of `both`'s arguments and jumps to it: no parameter, as `rdx`
// is none of `both`'s.
    .globl forwards
    .type forwards, @function
forwards:
    mov     edi, 3
    mov     esi, 3
    jmp     both
    .size forwards, . - forwards

// Returns its tenth argument, at `[rsp + 0x20]`, and reads none of the
// seventh to ninth before it.
    .globl tenth
    .type tenth, @function
tenth:
    mov     rax, qword ptr [rsp + 0x20]
    ret
    .size tenth, . - tenth

// `10 * seventh + tenth`: the eighth and ninth are not read.
    .globl weighted
    .type weighted, @function
weighted:
    mov     rax, qword ptr [rsp + 8]
    lea     rax, [rax + rax * 4]
    add     rax, rax
    add     rax, qword ptr [rsp + 0x20]
    ret
    .size weighted, . - weighted

// Reads its seventh argument, at `[rsp + 8]`, then stores the first
// there and reads that: the slot is the function's own variable, which
// holds the argument at entry.
    .globl reused
    .type reused, @function
reused:
    mov     rax, qword ptr [rsp + 8]
    mov     qword ptr [rsp + 8], rdi
    add     rax, qword ptr [rsp + 8]
    ret
    .size reused, . - reused

// Passes the address of a local to `marks`, so its frame is memory, and
// returns its seventh argument.
    .globl escaped
    .type escaped, @function
escaped:
    sub     rsp, 24
    lea     rdi, [rsp]
    call    marks
    mov     rax, qword ptr [rsp + 32]
    add     rsp, 24
    ret
    .size escaped, . - escaped

    .globl marks
    .type marks, @function
marks:
    mov     byte ptr [rdi], 1
    ret
    .size marks, . - marks

// The bits of its argument as a `double`: `xmm0` is written and nothing
// else uses the value, so it is the result.
    .globl as_double
    .type as_double, @function
as_double:
    movq    xmm0, rdi
    ret
    .size as_double, . - as_double

// Reads the bits `as_double` returns in `xmm0`.
    .globl read_bits
    .type read_bits, @function
read_bits:
    sub     rsp, 8
    call    as_double
    movq    rax, xmm0
    xor     rax, 1
    add     rsp, 8
    ret
    .size read_bits, . - read_bits

// Copies eight bytes through `xmm0`: the value is stored, so what is left
// in the register is no result.
    .globl through
    .type through, @function
through:
    movq    xmm0, qword ptr [rsi]
    movq    qword ptr [rdi], xmm0
    ret
    .size through, . - through

// Returns its second vector argument: the first is a parameter only for
// its position.
    .globl second
    .type second, @function
second:
    movaps  xmm0, xmm1
    ret
    .size second, . - second

// Sets `named` unless its argument points to a byte that is neither 0
// nor a `-` followed by 0: three tests, with a load between them, jump
// over one store to one label (whose code is too long to copy).
    .globl guarded
    .type guarded, @function
guarded:
    test    rdi, rdi
    je      1f
    movzx   eax, byte ptr [rdi]
    test    al, al
    je      1f
    cmp     al, 45
    jne     2f
    cmp     byte ptr [rdi + 1], 0
    jne     2f
1:  mov     dword ptr [rip + named], 1
2:  mov     dword ptr [rip + named + 4], 2
    mov     dword ptr [rip + named + 8], 3
    mov     dword ptr [rip + named + 12], 4
    mov     dword ptr [rip + named + 16], 5
    mov     eax, dword ptr [rip + named]
    ret
    .size guarded, . - guarded

// `flag != 0 ? *p : 41` as the machine has it: `cmovne` reads `[rdi]`
// whichever value it keeps, so the read (and its fault) is there for
// either flag.
    .globl chosen
    .type chosen, @function
chosen:
    mov     eax, 41
    test    esi, esi
    cmovne  eax, dword ptr [rdi]
    ret
    .size chosen, . - chosen

    .bss
    .globl named
    .type named, @object
named:
    .zero 20
    .size named, 20
