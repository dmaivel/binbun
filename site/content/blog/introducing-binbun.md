+++
title = "Introducing binbun"
date = 2026-11-23
authors = ["dmaivel"]
description = "The first preview of binbun, an open-source interactive disassembler and decompiler."
aliases = ["releases/0.1.0/"]
+++

I'm happy to share binbun 0.1, the first preview of my interactive disassembler and decompiler.

<!-- more -->

It's written in Rust, works on x86, x86-64 and AArch64 executables in ELF, PE and Mach-O files, and is open source under the MIT or Apache-2.0 licence. It comes as a desktop app, the `binbun` command and a Python package with the whole engine, and its disassemblers are also available as libraries for Rust, C and C++.

The app has listing, graph, decompiled C and hex views with the keys reverse engineers already use. Projects can be shared and worked on together, end-to-end encrypted, and scripts and agents can drive the same engine from Python. Every line of the C leads back to the instructions it came from, so you can check what the decompiler made of the code.

While binbun is 0.x, its APIs, commands and output can change between releases. The [changelog](https://github.com/dmaivel/binbun/blob/main/CHANGELOG.md) lists what each release after 0.1 changes.

Where binbun is heading is tracked in the [roadmap issues](https://github.com/dmaivel/binbun/issues?q=label%3Aroadmap), without dates.

## Installing

You can get the app for your platform from the [download page](@/download.md). If you're on Linux or macOS and prefer the terminal, run:

```sh
curl -fsSL https://binbun.org/install.sh | sh
```

The script checks the download against the release's checksums and installs it in your home directory without root privileges. If you're using binbun as a library, choose the package you need:

```sh
pip install binbun          # Python: the whole engine
cargo add binbun            # Rust: the engine
cargo add binbun-disasm     # Rust: the disassemblers, x86 and AArch64
```

The [getting started guide](@/docs/getting-started.md) walks you through opening a binary and saving a project.

## Reporting problems

If you find a bug, please open a [GitHub issue](https://github.com/dmaivel/binbun/issues) with the binbun version, the architecture, the options you used and, if you can share it, the binary. Cases where the decompiled C behaves differently from the original even though `binbun verify` reported agreement are especially useful.

Questions and ideas are welcome in [Discussions](https://github.com/dmaivel/binbun/discussions). For security problems, please use the private reporting process in the [security policy](https://github.com/dmaivel/binbun/security/policy).
