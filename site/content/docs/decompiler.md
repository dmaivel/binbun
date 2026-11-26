+++
title = "The decompiler"
weight = 40
+++

binbun reconstructs a typed, structured representation from the instructions and prints it as C. It does not recover the original source. Names, types and control structures have different kinds of evidence, and incomplete knowledge stays visible.

## Follow the evidence

The C's lines and tokens carry the addresses of the instructions folded into them. In the GUI, hover a token or select a line to inspect that mapping in the listing. A calculation folded into an argument may account for many instructions. Register saves, stack adjustments and padding can have no C line at all. A highlighted range is evidence for the selected expression, not a claim that the surrounding function is correct.

**Analysis → Why…** explains inferred names and types. The command line exposes the same kind of evidence.

```sh
binbun why tests/fixtures/program-x86_64.elf classify
```

The fixture's output includes:

```text
function classify at 0x1190: name from the binary's symbol
a1 (Parameter(0)): int64_t: default (width only) [Default]; name from the printer
    upper uint32_t strength 3: unsigned comparison of v113 at 119F at 0x119f
```

A width-based type is not a recovered source declaration. User declarations, debug information, library prototypes and inference can each contribute; Why shows which did. [Value origin](@/docs/command-line.md) follows dataflow rather than explaining a type.

## Exact C and Reading View

The command line defaults to exact C. The GUI offers **Exact C** and **Reading View** beside the C. The reading view is restructured under explicit assumptions, not merely a different colour scheme.

It assumes that addresses used by loads, stores, calls and jumps are canonical. On AArch64 it also assumes that the stack pointer is aligned at entry as the ABI requires and that a signed return address authenticates. Checks settled by these assumptions, and their traps, are hidden. Integer wrapping and unknown values are not discarded.

It also assumes that no code steps back from an address of a function's stack frame that the function passes to a call or stores, as `container_of` does. The locals below every such address are then variables of their own; in exact C, any of them could be reached through the address, so they stay fields of the function's frame struct.

```sh
binbun decompile tests/fixtures/program-x86_64.elf classify --view reading
```

Reading output begins with a comment naming these assumptions. Use exact C when investigating a fault they exclude. Exact output still rests on binbun's instruction semantics, recovered function boundaries and calling-convention model; “exact” is not a whole-program correctness guarantee.

## Undefined is not zero

Some values are not defined by the architecture. Others are unknown because a call can clobber a register, or because an entry register has no known parameter. The reading view names these values, such as `_ZF_undefined`, `_RDX_clobbered` and `_RCX_entry`, with comments describing their origin.

This example uses the zero flag that `imul` leaves undefined, in the repository's `examples/undefined/twin.s`: it multiplies by zero and picks `0xbeef` or `0xdead` by that flag.

```sh
cc -o twin examples/undefined/twin.s
binbun decompile twin main --view reading
```

The function printed in that run was:

```c
int32_t main_2(void)
{
    bool _ZF_undefined = binbun_undefined_bool(); /* imul r8, rcx at 0x1154 leaves ZF undefined: processors differ */

    printf("%#llx\n", _ZF_undefined ? 0xbeef : 0xdeadL);
    return 0;
}
```

Exact C calls the unknown-value helper at the use instead of introducing that reading-view name: `binbun_undefined_bool() ? 0xbeef : 0xdeadL`. Neither view replaces the choice with a result without evidence, and `--stats` counts it as `processor-dependent 1`. A [processor profile](@/docs/profiles.md) can give the interpreter a measured rule; it does not rewrite the C.

Instructions without supported semantics remain explicit escapes. Reading C uses `__asm { }` blocks; exact C uses helper calls. Some functions cannot be lifted or printed at all and report why. Such output is not an executable replacement for the original binary.

## What the checks mean

[Verify](@/docs/verify.md) checks the structured representation against the lifted one and runs both from matching sample states. It does not invoke the native binary or prove every input. Reading-view verification uses the representation with the reading assumptions applied, so agreement cannot validate the assumptions themselves.

Generated C uses `binbun_defs.h` for operations ordinary C does not express faithfully. Its header comment specifies `-fwrapv -fno-strict-aliasing`; vector output uses GCC/Clang extensions. Successful compilation is a separate check from semantic agreement.
