# Developing binbun

How to work on binbun's code. binbun is two Cargo workspaces: the engine, CLI, Python extension and C library at the root, the GUI in `gui/`. The user documentation is the site's, in [`site/content/docs/`](../site/content/docs/).

- [Layout](layout.md): what each crate, tool and directory is for
- [Building](building.md)
- [Testing](testing.md): the checks every change passes, and the extra ones each kind of change needs
- [Oracles](oracles.md): the differential tests against XED, LLVM, exarmo and the processor
- [Benchmarks](benchmarks.md)

## Rules

- binbun never prints a confident wrong value: what the code leaves undefined or the analysis cannot establish stays visibly unknown.
- Analyses work from file formats, calling conventions and C's semantics, never from a function's name or a particular binary.
- Generated files are regenerated, never edited: `cargo xtask codegen` (decoder tables, lifter semantics), `cargo xtask header` (the C API's generated header) and `scripts/release/third-party-licenses.sh` (the downloads' third-party licences, in `third_party/licenses/`).
- `unsafe` only in `crates/binbun-capi/src/ffi.rs`, with a `// SAFETY:` comment on each block.
- Tests check behaviour (results, edge cases, errors), not how the code is written.
- Wording, in code, output and docs: British spelling; nothing that gives binbun a mind (knows, thinks, guesses, remembers); nothing that claims more than was checked (truth, proof, verified). Markdown: one line per paragraph and per list item.
- A change users will notice gets a line under `## Unreleased` in `CHANGELOG.md` (the rules are at the top of that file).
