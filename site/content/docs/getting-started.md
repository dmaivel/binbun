+++
title = "Getting started"
weight = 10
+++

## Install

Choose the desktop download for your platform on the [download page](/download/). The desktop build includes both the window and the command line. The Linux CLI-only download does not open a window and does not need desktop libraries.

The installer offered there installs into your home directory, checks the archive against an embedded SHA-256 before unpacking, and does not need root. On Linux it puts the command in `~/.local/bin`; make sure that directory is on your shell's search path. It chooses the CLI-only build on musl or when the desktop libraries are missing. On macOS it installs the app in `~/Applications`. Windows uses the release zip: the app is `binbun.exe`, the command `bin\binbun.exe`; add that `bin` folder to `PATH` to type `binbun` in a shell. See [Platforms and files](@/docs/platforms-and-files.md) for platform requirements and unsigned-app warnings.

## Open a binary

Use **File → Open…** (`Ctrl+O`), or start the desktop build with a file.

```sh
binbun /usr/bin/bash
```

binbun reads the file; it does not execute it. Function recovery and cross-references appear before the remaining analysis finishes. Opening a universal Mach-O asks which architecture to use. Each architecture has its own project.

For a small example, open `tests/fixtures/program-x86_64.elf` from the [source repository](https://github.com/dmaivel/binbun). The checked-in binary needs no compiler. Press `G`, enter `classify`, and follow the result. This fixture's function starts at `0x1190`.

## Read the listing and the C

The listing shows instructions and data. Press `F5` for the current function's C, `Tab` to switch between listing and C, and `Space` to switch the listing between text and graph. Follow a name with `Enter`; return with `Escape`. `X` shows its cross-references.

The same function can be read without opening a window.

```sh
binbun decompile tests/fixtures/program-x86_64.elf classify
```

Its function body is:

```c
int32_t classify(int64_t a1)
{
    return (uint32_t)a1 >= 7 ? -1 : (a1 + 10 + a1 * 10);
}
```

This is recovered C, not the original source. Here the parameter remains width-based, despite the comparison using 32 bits. **Analysis → Why…** explains the evidence. Hover or select the C to find the instructions behind it. The **Reading View** and **Exact C** controls choose how much machine-level detail to show; read [The decompiler](@/docs/decompiler.md) before treating either as source code.

## Make and save an edit

Put the cursor on the function name and press `N` to rename it. Use `;` for a comment and `Y` for a type. `Ctrl+Z` undoes an edit; `Ctrl+Shift+Z` redoes it.

Use **File → Save Project** (`Ctrl+S`). A project contains your edits and window layout, not a modified executable. binbun keeps projects in its data directory, keyed by the binary's contents. Moving or renaming a binary does not lose its project. Changing its bytes starts another project.

**File → Export Project…** makes a portable `.binbun` file. It does not include the binary; send the binary separately, or use [collaboration](@/docs/collaboration.md) with file transfer enabled. **File → Import Project…** reads an export. An imported project starts unshared, and private bookmarks are not exported.

Continue with [The GUI](@/docs/gui.md), or use the [command-line tour](@/docs/command-line.md) for headless work.
