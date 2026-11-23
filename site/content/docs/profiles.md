+++
title = "Profiles and runs"
weight = 70
+++

A processor profile records how a particular microarchitecture chooses values the instruction-set architecture leaves undefined. It affects interpretation and verification. It never changes the printed C or records the same choice for every processor.

## Choose a processor

**Analysis → Processor** offers **Architecture**, **Intel Raptor Cove**, **Intel Gracemont** and **Profile File…** when they fit the binary. The two shipped profiles describe x86-64 processors: Raptor Cove P-cores and Gracemont E-cores measured on an i9-14900F. There is no shipped AArch64 processor profile; an AArch64 image offers the architecture alone.

The choice is private to the project, not shared or exported. Changing it reruns the displayed runs without reanalysing the program. A profile with an unknown or varying rule leaves that site unknown. It is not a complete processor emulator or a performance model.

## Run from Here

Put the cursor on a function and choose **Analysis → Run from Here…**. binbun opens its C and asks for the arguments of an example state. A function with no parameters runs immediately. The C shows values and branch decisions beside its statements. Loops can have several recorded occurrences.

Execution is interpreted. A call that needs a stub stops the run and shows its arguments; the interpreter does not call the host system's library to pick an answer. Example states can define memory regions, registers and explicit call stubs. A stub is your assumption about that call, not recovered behaviour.

For a command-line run, save this as `classify.toml`:

```toml
format = 1
name = "classify two"
function = "classify"
arguments = ["2"]
```

```sh
binbun run tests/fixtures/program-x86_64.elf classify --state classify.toml
```

The return statement was annotated `// 32`. The report said the run returned 32 and that the machine-code run agreed. Arguments are strings interpreted according to the recovered prototype. Missing values remain undefined, rather than becoming zero.

## Compare processors

**Analysis → Compare Processors** shows a table of differences, the deciding instruction and each processor's rule. In the command line, on `twin` built from the repository's `examples/undefined/twin.s` (see [Decompiler](@/docs/decompiler.md)):

```sh
binbun verify twin main --compare intel-raptor-cove,intel-gracemont
```

That program passed `0xdead:64` to `printf` under Raptor Cove and `0xbeef:64` under Gracemont in all 16 sampled states. The deciding site was `imul2.zf` at `0x1154`: Raptor Cove gave 0 and Gracemont 1. The output recorded these rules:

```text
intel-raptor-cove: 0
intel-gracemont: (defined.dst == 0)
```

The comparison prints an example for each way the states differ and counts further states with the same difference. `--states-full` includes each retained state's registers and memory; `--save` writes the differing states for replay. “Same” means the sampled runs agreed, not that the processors are equivalent for every input.

To run it under one profile, save this as `twin.toml`:

```toml
format = 1
name = "twin"
function = "main"
```

```sh
binbun run twin main --state twin.toml --profile intel-raptor-cove
```

The run stopped at `printf`, which needs a stub, and showed its arguments: `(8196, 57005)`, the second `0xdead`. With `--profile intel-gracemont` it was 48879, `0xbeef`; with no profile, `?`. The C still contained its undefined-value helper. See [Verify](@/docs/verify.md) for how profiles affect skipped states.
