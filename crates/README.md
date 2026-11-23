# binbun's crates

These crates are the parts of [binbun](https://binbun.org), an open-source interactive disassembler and decompiler. Most are published for the crates that depend on them; their APIs serve binbun and can change between releases while binbun is 0.x.

To use binbun from Rust, start from one of these:

- [`binbun`](https://crates.io/crates/binbun): the engine. Load a binary, recover its functions, decompile them to C.
- [`binbun-session`](https://crates.io/crates/binbun-session): the engine as the app and the Python package use it, with background analysis, projects and undoable edits.
- [`binbun-disasm`](https://crates.io/crates/binbun-disasm): the x86 and AArch64 disassemblers through one API; [`binbun-x86`](https://crates.io/crates/binbun-x86) and [`binbun-aarch64`](https://crates.io/crates/binbun-aarch64) for one architecture in full detail.

The app, the `binbun` command and the Python package are on [binbun.org](https://binbun.org), the documentation at [binbun.org/docs](https://binbun.org/docs/), and the source on [GitHub](https://github.com/dmaivel/binbun).

Licensed under either of [Apache License, Version 2.0](https://github.com/dmaivel/binbun/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/dmaivel/binbun/blob/main/LICENSE-MIT) at your option. The code generated from Intel XED (in `binbun-x86-lift`) is under XED's Apache License, Version 2.0 (`LICENSE-XED`), and the code generated from Arm's A-profile Machine Readable Specification (in `binbun-aarch64-lift`) under Arm's BSD 3-Clause licence (`NOTICE-AARCHMRS.html`).
