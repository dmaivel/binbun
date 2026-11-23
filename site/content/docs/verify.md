+++
title = "Verify"
weight = 50
+++

Verification checks whether a function's structured representation agrees with its lifted machine code. It compares control-flow structure, then interprets both from the same states. It is not a proof, native execution or a security audit.

## Check a function

```sh
binbun verify tests/fixtures/program-x86_64.elf classify
```

The verdict from the checked-in fixture was:

```text
classify at 0x1190, exact view: agreed on 16 of 16 sampled states
```

A separate line reports time spent lowering and checking. Omitting the function checks the recovered functions in the file. In the GUI, use **Analysis → Verify Function** for the current function and view. The **C** settings group also offers **Verify automatically** when the cursor rests.

The default is 16 random states and up to 8 states shaped by the function's types. Shaped states supply objects, terminated strings and small counts where a parameter's type makes those useful; functions without such parameters need not produce extra states. The seed defaults to the function's entry address.

```sh
binbun verify tests/fixtures/program-x86_64.elf classify --view reading --states 64 --shaped 8 --seed 1 --fuel 10000
```

That run reported `agreed on 64 of 64 sampled states`. `--fuel` bounds the number of lifted blocks entered per state. It is not a wall-clock timeout. Raising the sample count or fuel can explore more executions but cannot turn testing into proof.

## Read all three outcomes

**Agreed** means the structural check passed and the compared executions agreed. Read the agreed and skipped counts. Some sampled executions may have been skipped.

**Differs** means a structural mismatch or a state on which the runs diverged. A dynamic difference includes the seed, state and divergence details, with instruction addresses where available. Keep the binary, options and full output when reporting it.

**Not checkable** means there was no conclusive comparison, not that the function passed. Undefined inputs, unsupported semantics and exhausted fuel can prevent a useful check. A function that branches on a value the architecture leaves undefined, for example, reports `not checkable: every state skipped` and names the undefined bits its lifted form depends on.

Where such a value only decides what the function computes, [profiles](@/docs/profiles.md) can specify what each processor gives. On `twin`, built from the repository's `examples/undefined/twin.s`:

```sh
binbun verify twin main --compare intel-raptor-cove,intel-gracemont
```

```text
main at 0x1139 on intel-raptor-cove r2, intel-gracemont r2: differs: 16 states, 0 same, 0 skipped, 16 reached a site (imul2.af 16, imul2.pf 16, imul2.sf 16, imul2.zf 16, xor.af 16)
  state 0 of seed 0x1139: the call's arguments differs
    intel-raptor-cove r2: calls 0x1030(0x2004:64, 0xdead:64)
    intel-gracemont r2: calls 0x1030(0x2004:64, 0xbeef:64)
    decided by imul2.zf at 0x1154: intel-raptor-cove 0x0 by `0`; intel-gracemont 0x1 by `(defined.dst == 0)`
    15 more states differ the same way
```

The command exits with status 1 for that report: the processors differ.

## Use the exit status in scripts

`binbun verify` exits in the spirit of `diff`, for one function, every function of the file, or `--compare`:

| Status | Meaning |
| --- | --- |
| 0 | Every function checked agreed (with `--compare`: the same on each processor). Some functions of a whole file may still be not checkable, as long as at least one was checked. |
| 1 | A function differs: from its lifted form, or with `--compare` between the processors. |
| 2 | The command failed: a file it cannot read, a function it cannot find, or wrong arguments. |
| 3 | Nothing could be checked: the function, or every function of the file, is not checkable. |

Status 0 still means sampled agreement, not proof; read the report for the agreed and skipped counts.

## Know the boundary

The comparison is between binbun's lifted and structured representations, not compiled C executing on a physical processor. A mistake shared by both models can escape it. Calls and memory are modelled; this is not a complete process with its operating system and external libraries.

Exact and reading views have different inputs to the structural check. The reading view is checked against lifted code with its [stated assumptions](@/docs/decompiler.md) applied. A reading-view pass does not establish that the original program cannot take one of the hidden faults.

`--project` loads recovery corrections from a project directory. Without it, a command-line check need not use the GUI's corrected function boundaries. `--profile` supplies a processor's rules for otherwise undefined values; a profile cannot supply rules it does not define. See [Profiles](@/docs/profiles.md) for comparisons between processors and replayable example states.
