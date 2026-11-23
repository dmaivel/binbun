+++
title = "Switching from other tools"
weight = 20
+++

Most everyday keys carry over. The important difference is what a tab represents: a place you are working, not a separate tab for every view of it.

| In IDA | In binbun |
| --- | --- |
| Disassembly and graph | The listing; `Space` changes its view in place. |
| Pseudocode | C; `F5` opens it and `Tab` switches between listing and C. |
| Jump to address or name | `G`, **Go Anywhere…**. |
| Follow and return | `Enter` and `Escape`; `Alt+Left` also goes back. |
| Cross-references | `X`; `Shift+X` follows a value's origin instead. |
| Rename, type, comment | `N` or `F2`, `Y`, and `;`. |
| Code, undefine, data, string | `C`, `U`, `D`, `A`. |
| Make array or function | `*` and `P`. |
| Edit function | `Alt+P`. |
| Strings | `Shift+F12`. |
| Bookmark and bookmark list | `Alt+M` and `Ctrl+M`. |
| Scripts | The Python console and the `binbun` Python package, not IDAPython. |

These are the default bindings in code panes. **File → Key Map** shows them; **File → Open Settings File** lets you override them.

## Names and types

Rename functions, globals, locals and struct members from their uses. **Set Type…** accepts C declarations. A type is an edit with a source, not an invisible replacement for the analysis. **Analysis → Why…** shows what came from you, debug information, a library declaration, a signature or inference. **Window → History** and undo cover these changes.

Struct members can be edited in their printed definition or at a use. Layout-changing edits that would overlap another member are refused. The struct editor remains useful for definitions not printed in the current C.

## What differs

The C has [exact and reading views](@/docs/decompiler.md). Neither silently chooses a processor's value for architecturally undefined flags. **Verify Function** compares the recovered representation with lifted machine code on sample states; it is not a proof of the original program.

A project lives outside the binary, found by its contents. Export and import use binbun's `.binbun` format, not an IDB. Python scripts need to be ported to the [binbun API](@/docs/python.md). There is no IDAPython compatibility layer or live debugger in 0.1.
