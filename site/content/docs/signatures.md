+++
title = "Signatures"
weight = 60
+++

Signature packs identify library functions in a binary. Making and matching packs currently supports x86-64 code only. A pack contains normalised identities and recorded behaviour. The shipped packs do not contain the library's machine code.

## Installed packs

Release downloads carry these families of packs. They are matched only against compatible architectures and systems.

| Library | Builds |
| --- | --- |
| musl 1.2.5 | GCC `-O2`, GCC `-Os`, Clang `-O2` |
| Static glibc | Debian 13, Ubuntu 26.04 LTS, Fedora 45 and Arch Linux |
| Rust std | 1.100.0, 1.99.0 and 1.98.1 |
| Microsoft static C/C++ runtime | MSVC 14.51.36231 and Universal CRT from SDK 10.0.26100.0 |
| Windows kernel support libraries | WDK 10.0.28000.0 |

These are not packs for every version of those libraries. Different builds can have different identities or behaviour. In particular, a Rust pack from another toolchain does not supply behaviour-based names as though it were the binary's own build.

binbun reads the directory named by `BINBUN_SIGNATURES`, its data directory's `signatures` folder, and the installed packs. Installed packs live in `share/binbun/signatures` on Linux, `Contents/Resources/signatures` in the macOS app, or `signatures` beside `binbun.exe` in the Windows zip, which the app and the command in `bin` both read. [Files and folders](@/docs/platforms-and-files.md) explains how to find the data directory.

## Names, evidence and undo

When a session opens a binary with packs available, exact matching names functions first. Behaviour matching continues in the background. Each applied run is one undoable change attributed to `sig:<pack>`. It records the library prototype and match evidence, and does not overwrite a name or prototype from another source.

Hover the function's name or use **Analysis → Why…** to inspect the pack, library and kind of match. The map groups identified library functions under their library and object. **Analysis → Reject Signature**, also available in the function's context menu, rejects a match and prevents it being applied again. Undo removes a run's changes; rejection is the choice when a particular match must stay rejected.

Under **File → Settings… → Signatures**, **Name library functions** turns automatic naming on or off. **Search unreached code** also searches executable bytes not covered by recovered functions and creates the functions the pack identifies there. It is off by default and adds work.

A list of candidates is not a name. Identical definitions can be aliases; functions that behave alike cannot always be distinguished. binbun withholds names when the evidence does not select one answer. A prototype from a pack is still evidence to inspect, not proof of a source-level identity.

## Make and inspect a pack

The following example uses the source repository's checked-in static library. Run it from a directory where the fixture path is available and the output is writable.

```sh
binbun sig make --library example --version 1 --licence MIT tests/fixtures/sigs-gcc.a -o example.jsonl.zst
binbun sig check example.jsonl.zst
binbun sig show example.jsonl.zst sig_hash
binbun sig match tests/fixtures/sigs-gcc-lo.elf --pack example.jsonl.zst --behaviour
```

The make run produced 16 records, 15 with behaviour recordings and none with code. Checking it noted one identity shared by multiple functions. The match run included:

```text
0x401000 stpcpy exact
0x4010b0 strcpy behaviour: 48 states agreed, 0 ruled out
0x4010c0 memcpy exact
```

It named 11 of 14 functions and left three as candidate lists. Those withheld names are intentional.

Inputs can be static archives (`.a`, `.rlib`, `.lib`), relocatable objects or linked ELF files with symbols. A Microsoft import library is not a static implementation and is refused. Supply the library's real version and licence when distributing a pack. `--plain` writes reviewable JSON Lines instead of compressed output; `--code` includes code and should not be used for a third-party pack without checking its licence. The [command reference](@/docs/reference/cli.md) lists the metadata and comparison options.

Copy your finished pack into the user signature directory to make it available to new sessions. The explicit matching command prints a report; it is not a request to rename the open GUI's project.
