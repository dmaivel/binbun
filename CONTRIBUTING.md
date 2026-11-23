# Contributing to binbun

## Working with the repository

[docs/](docs/) has the build commands, the checks every change must pass, the extra checks each kind of change needs, the oracles, the benchmarks and the project's rules.

## Before opening a pull request

Try your change on real binaries, not only on the test fixtures. `/usr/bin/bash` and your system's libc are good choices, a Windows executable, etc.

If the change shouldn't affect the decompiled C, check that `binbun decompile FILE --stats` prints exactly the same thing before and after. If it should, put the before and after numbers in the pull request (functions decompiled, compile errors and warnings, casts, gotos) and run `binbun verify FILE` to confirm it still finds no differences.

For changes to a decoder, also run its oracle tests and the fuzz targets described in `fuzz/README.md`. For changes to the GUI, run the app, try the change by hand, and attach a screenshot of anything visible.

Then read through your own diff. The analyses work from file formats, calling conventions and C's semantics, never from the name of a function or from a particular binary. `unsafe` is only used in `crates/binbun-capi/src/ffi.rs`, with a `// SAFETY:` comment on each block. Tests should check behaviour, such as results, edge cases and errors, rather than how the code is written.

If users will notice the change, add a line for it under `## Unreleased` in [CHANGELOG.md](CHANGELOG.md), saying what they can now do or will see rather than how it was done; the comment at the top of that file has the rules.

## Licence

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in binbun, as defined in the Apache-2.0 license, is dual licensed as binbun is, under MIT or Apache-2.0, without any additional terms or conditions.
