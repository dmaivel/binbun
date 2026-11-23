# Layout

## The pipeline

A binary goes through these crates in order; L0, L1 and L2 are binbun's three intermediate representations.

| Step | Crate |
|---|---|
| Load the file | `binbun-loader` |
| Decode instructions | `binbun-x86`, `binbun-aarch64` (`binbun-disasm`: one API over both) |
| Lift each instruction to L0 | `binbun-x86-lift`, `binbun-aarch64-lift`, over `binbun-semantics` (L0 itself) |
| Build each function's L1 (SSA) | `binbun-ssa` |
| Lower L1 to L2 and simplify, structure and type it | `binbun-decompile`, `binbun-typeinfer` |
| L2, the structured AST | `binbun-ast` |
| Print C | `binbun-print` |

`binbun` is the engine that joins them over one loaded binary; `binbun-session` runs it for an interactive front end.

## Crates

| Crate | What |
|---|---|
| `binbun` | The engine: a binary as a program database; recovery, cross-references, decompilation on demand |
| `binbun-session` | One opened binary for a front end: the engine on worker threads, edits, events |
| `binbun-cli` | The `binbun` command |
| `binbun-py` | The Python extension (`binbun._native`) |
| `binbun-protocol` | The client protocol of the Python package and the GUI's server |
| `binbun-collab` | Shared projects: the edit log synced between peers, end-to-end encrypted |
| `binbun-sync` | The sync protocol of shared projects as a state machine without I/O: signed heads, tips and pulls, fork evidence |
| `binbun-bounded` | Bounded decoding of what another party wrote: lists and strings with declared maxima, encoding within a limit, pages |
| `binbun-loader` | ELF, PE and Mach-O files as an address space with symbols, imports and unwind tables |
| `binbun-debuginfo` | DWARF and PDB, and debug files from symbol servers |
| `binbun-typedb` | The C type databases of library functions and types |
| `binbun-demangle` | Itanium C++ manglings as parse trees |
| `binbun-sigpack` | Library signatures: making and matching packs |
| `binbun-isa` | The instruction vocabulary every decoder implements |
| `binbun-x86`, `binbun-aarch64` | The decoders |
| `binbun-disasm` | One decoding API over both architectures |
| `binbun-capi` | binbun's C API, `libbinbun`: so far the decoders (the only `unsafe` code) |
| `binbun-semantics` | L0, and `core`: the shared ids, arenas and memory types |
| `binbun-x86-lift`, `binbun-aarch64-lift` | Instructions to L0, from checked hand-written semantics |
| `binbun-ssa` | L1 |
| `binbun-typeinfer` | Type inference by algebraic subtyping |
| `binbun-decompile` | L1 to L2 and the passes on L2 |
| `binbun-ast` | L2 |
| `binbun-print` | L2 as source code: C, with `binbun_defs.h`; the layout engine |
| `binbun-paths` | Where binbun keeps its files on each platform |
| `binbun-macros` | Derive macros used through `binbun_semantics::core` |
| `binbun-xed` | Reader of XED's datafiles, for the x86 decoder generator (build time only) |

Each crate's own documentation (its `lib.rs`) has the detail.

## Directories

| Path | What |
|---|---|
| `gui/` | The app, its own workspace: `view` (framework-free view models) and `app` (GPUI) |
| `python/` | The Python package around the extension, and its tests |
| `examples/` | Small tasks in Python, Rust, C and C++, run by the tests |
| `xtask/` | `cargo xtask codegen` and `cargo xtask header`: the generated sources |
| `third_party/` | XED's datafiles and Arm's AARCHMRS, the decoders' inputs; `licenses/`, the licences of the crates each download is built from (`scripts/release/third-party-licenses.sh`, run after `Cargo.lock` or `gui/Cargo.lock` changes; a release refuses them stale); `themes/`, the licence texts of the repositories the bundled themes come from (`gui/THEMES`) |
| `tools/` | The oracles (`xed-oracle`, `llvm-oracle`, `exarmo-oracle`, `cpu-oracle`, `cpu-oracle-aarch64`, `isla-check`) and `typegen` (the type databases' generator) |
| `tests/fixtures/` | Small test binaries built from `program.c` by `scripts/build-fixtures.sh` |
| `fuzz/`, `bench/` | Fuzzing and benchmarks, separate workspaces |
| `scripts/` | Builds of fixtures, oracles and type databases; `release/` packages a release |
| `site/` | binbun.org: the user documentation, built with Zola |
| `docs/` | These development notes |
