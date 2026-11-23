+++
title = "Command line"
weight = 110
+++

The desktop executable and the CLI-only executable accept the same analysis subcommands. Without a subcommand, the desktop build opens a window. The CLI-only build reports that it has no GUI.

```sh
binbun --help
binbun --version
```

The [CLI reference](@/docs/reference/cli.md) lists the syntax and options. The examples below use the source repository's checked-in fixtures; run them from its root. `/usr/bin/bash` is a Linux example and depends on the file installed on your machine.

## Find functions and read C

```sh
binbun functions tests/fixtures/program-x86_64.elf
binbun decompile tests/fixtures/program-x86_64.elf classify
binbun decompile /usr/bin/bash main
```

`functions` prints addresses, recovered block counts and names. It found `classify` at `0x1190` with one block in the fixture. Functions may be selected by name or address. The decompile command also accepts several function names in order; with none, it processes the whole program.

C goes to standard output. Diagnostics can go to standard error. A function that cannot be decompiled says why; whole-program output can contain failure comments among the functions that succeeded. Do not silently discard those comments when processing a report.

The command line defaults to [exact C](@/docs/decompiler.md). `--view reading` requests the reading assumptions. `--debug` supplies a separate debug file; `--debug none` suppresses automatic debug information. For PE images, the CLI also looks for a matching PDB at the recorded path or beside the executable and checks its GUID and age.

The CLI does not fetch symbols unless asked. `--symbols` permits fetching from symbol servers and caching the result. A symbol request tells the server which binary you are analysing. Local DWARF, PDB and dSYM files avoid that network request.

## Read instructions and references

```sh
binbun cfg tests/fixtures/program-x86_64.elf classify
binbun strings tests/fixtures/program-x86_64.elf --referenced
binbun xrefs tests/fixtures/program-x86_64.elf --from checked
```

`cfg` prints basic blocks and their instructions, followed by control-flow exits. The fixture's block ends in `ret` and `-> return`. Strings distinguish referenced strings from those found by scanning alone. The reference report for `checked` was:

```text
# 4 references from checked
0x11d6 jump     0x11e4
0x11d8 call     classify
0x11e4 address  0x2004 "negative"
0x11eb call     fail
```

Use the target form of `xrefs` to ask who refers to an address or name, rather than what a function refers to. The `graph` command lays out a function's graph and can write SVG; `cfg --dot` gives a graph in DOT form.

## Explain an inference

```sh
binbun why tests/fixtures/program-x86_64.elf classify
binbun origin tests/fixtures/program-x86_64.elf classify a1
binbun stages tests/fixtures/program-x86_64.elf classify
```

`why` explains names and types. `origin` follows a named C variable's dataflow. For this fixture it began with parameter 0 in `rdi` at `0x1190`, then followed its caller `checked`. `stages` lists the transformations from instructions to C and the passes that ran. It can also print a selected stage or its diff from the preceding one.

These are different questions. A provenance address says which instructions contributed to an expression; an origin query follows values; a type explanation describes the evidence behind a declaration.

## Check, run and identify libraries

Use [Verify](@/docs/verify.md) for structural and sampled execution checks, [Profiles and runs](@/docs/profiles.md) for explicit input states and processor differences, and [Signatures](@/docs/signatures.md) for creating and applying pack reports. Their examples include the commands and output.

`verify` [exits like `diff`](@/docs/verify.md#use-the-exit-status-in-scripts): 0 when everything it checked agrees, 1 when a function differs, 2 when the command fails and 3 when nothing could be checked.

The ordinary listing and decompilation commands are not connected to an open GUI. Options such as `--project` on `verify` and `why` explicitly load saved project information; use the [Python connection API](@/docs/python.md) when a script must work against the live window.

## Choose a universal slice

```sh
binbun functions tests/fixtures/program-universal.macho --arch arm64
```

The fixture reported its `arm64` slice and listed the other available slices, `x86_64` and `arm64e`. Without `--arch`, binbun chooses this machine's architecture when available, otherwise the first slice. It reports the choice on standard error.

## Locate application files

```sh
binbun paths
binbun paths cache
binbun paths --json
```

The first command lists resolved directories and their sizes; the second prints only the requested path; the third is machine-readable. See [Platforms and files](@/docs/platforms-and-files.md) before moving or deleting a directory.
