+++
title = "Python"
weight = 90
+++

The `binbun` package exposes the decoders, an in-process analysis session and a connection to a running GUI. It requires CPython 3.11 or later. Install the release's wheel in the interpreter you use for scripts; the GUI does not bundle or embed a Python interpreter.

The [Python reference](@/docs/reference/python.md) describes the public objects and arguments. This page covers the working model.

## Open and edit a binary

This example uses the source repository's checked-in fixture. `project=False` keeps its changes out of the saved project.

```python
import binbun

with binbun.open("tests/fixtures/program-x86_64.elf", project=False) as db:
    f = db.functions.get_by_name("classify")
    print(hex(f.entry), f.name)
    print(f.decompile().text)
    with db.transaction("Name classify"):
        db.functions.set_name(f, "classify_input")
    print(f.name)                        # a Function reads the database now
    db.undo()
    print(f.name)
    for x in db.xrefs.to_ea(f):          # anything at an address is one
        print(f"{x.from_ea:#x} in {x.function.name}")
```

The first line printed `0x1190 classify`. After the C, the two names printed were `classify_input` and `classify`, and the one call to `classify`, `0x11d8 in checked`. A transaction groups edits into one undo step. Without `project=False`, opening a binary normally uses its saved project. Close a database when finished; a context manager does that.

Wherever an argument is an address, any binbun object at one address can stand in for it: a `Function` (its entry), a string, an instruction, a block, a section, a listing line, a name or comment record. `binbun.AddressLike` is that type, for annotations. An object with two addresses, such as an `Xref`, raises `TypeError` naming the attribute to give (`x.from_ea` or `x.to_ea`).

Use `db.functions` for functions and their blocks, callers and callees. `db.listing`, strings and cross-references expose the binary's other views. A decompiled document has text and provenance, not just a string; `db.set_style(braces="allman")` (or `"kr"`, `"llvm"`, `"linux"`) chooses how its C is laid out. `Function.verify()`, `Function.why()`, `Function.origins()` and `Function.run()` answer the same kinds of questions as the GUI. Their results are structured objects described in the reference.

Names, comments, prototypes, types, bookmarks and recovery corrections are editable. They are not writes into the executable. `Function` objects read the database as it is now; `CDocument`s and other results are snapshots.

### Suggest instead of writing

Edits can be offered for someone to accept rather than made. The writes inside a `db.suggestion` block are recorded, not applied, and become one suggestion when the block ends:

```python
with db.suggestion("Name classify", rationale="a switch on the input's kind",
                   evidence=[db.xrefs.to_ea(f)]) as s:
    db.functions.set_name(f, "classify_input")
s.suggestion.accept()
```

Each write is checked as it is made, so one that would be refused raises at its line. An exception leaving the block makes no suggestion, and a transaction or undo inside it raises `TransactionError`. `s.suggestion` is the `Suggestion` made; `accept()` applies it as one undo step and `dismiss(reason)` declines it. [Agents](@/docs/agents.md#talking-to-people) shows suggestions with their threads.

## Work in the GUI

Open **View → Console** with `Ctrl+Backtick`. Under **File → Settings… → Python**, choose an interpreter with the `binbun` package installed. The console reports an unavailable interpreter or package instead of loading Python into the GUI process.

The default, `python3`, usually has no `binbun`, and a system Python refuses packages installed into it. When the Python the setting names can't run binbun, opening the console (or starting an agent in a terminal) shows a banner: **Set Up Python** makes binbun a venv of your Python 3.11 or newer in its data folder (`python`), installs `binbun` of the app's version into it from PyPI, and names it in the setting. On Debian and Ubuntu the venv needs the `python3-venv` package. Agents' `binbun mcp` runs the same Python.

The console is a tab of the [bottom dock](@/docs/gui.md#bottom-dock). Drag its tab like any other to put it beside the code or in another pane. There is one console per window: closing its tab, hiding the dock or switching to another window tab only hides it, and its variables and history stay. `Ctrl+Backtick` shows the dock with the console, and hides the dock when it shows the console; dragged into a pane of the code, the console is shown and hidden there instead. Once you have used a [terminal](@/docs/gui.md#terminals) since the console, `Ctrl+Backtick` acts on that terminal instead; right-click the console button in the status bar to choose.

The console supplies `db`, `here`, `current_function` and `selection`. Before each cell, the last three reflect the GUI's cursor, containing function and selected address range. Use ordinary Python against `db`; it is connected to this window.

A cell's writes are one undo step. If a cell raises after making edits, those completed edits stay and can be undone together. A rolled-back transaction rolls the cell's writes back with it. `Ctrl+C` interrupts a running cell, subject to the interpreter being able to interrupt the operation it is in.

The console runs `startup.py` from the configuration directory once at startup. It is executable code with your user's permissions, not a sandbox. Find its directory with:

```sh
binbun paths config
```

## Connect a script

`binbun.connect()` attaches to an open GUI or to a session served by a script. If several binaries are open and none is named, it attaches to the one whose window had the focus last; name another by its path or file name (`binbun.connect("libc.so.6")`), or choose a socket explicitly. A name that matches several (two slices of one file) raises `AmbiguousError`; `slice="arm64"` chooses one, as it chooses a universal Mach-O file's slice for `binbun.open`. Another user's server is refused.

The default remote mode asks the serving process for results and puts edits into its history. `mode="local"` opens a local analysis of the same binary and follows the server's changes while sending writes back. The remote and local objects do not expose identical surfaces; consult their entries in the reference instead of assuming every local method is an RPC.

A connected database has the window's cursor: `db.cursor` is its address, and setting it (to an address or anything at one) moves the window there. `db.selection` is the selected address range, or `None`. A database opened in process has no window, and both raise `CapabilityError`.

Give the connection a `label` to identify a script run in history. Script writes are grouped for undo. This is ordinary Python with filesystem and network access, so review a script before running it against a valuable project.

## Agents

An AI agent should work on a binary through this package: it is ordinary Python, which agents already write well, and it reaches the whole engine. After `pip install binbun`, an agent can open a binary, list its functions, read each function's C with its provenance, verify it and make edits. In an open window it connects as itself, `binbun.connect(agent="Codex")`, and becomes a participant whose edits are its own undo steps. A host that only calls tools gets the same API through `binbun mcp`. [Agents](@/docs/agents.md) covers both, with each harness's setup, presence, attribution and talking to people in address threads.

## Decode without a project

The decoders need no database or GUI.

```python
from binbun import x86

code = bytes.fromhex("554889e531c05dc3")
for insn in x86.Decoder(code, address=0x401000):
    print(f"{insn.address:#x}  {insn}")
```

```text
0x401000  push rbp
0x401001  mov rbp, rsp
0x401004  xor eax, eax
0x401006  pop rbp
0x401007  ret
```

`binbun.aarch64` provides the A64 decoder. Both expose structured operands and control-flow information as well as formatted text. The package's API version is separate from the application version; check the reference when porting scripts between releases.

### One decoder for both architectures

`binbun.disassemble` (or `binbun.Decoder`) takes the architecture as an argument and yields `binbun.Instruction`s with what both decoders share: `address`, `length`, `bytes`, `mnemonic` (the word the text writes, `movsb` for `rep movsb`), `branch`, `text()`, and `registers_read`/`registers_written` (the registers the decoder says the instruction may read and write, by the architecture's names, flags left out). `.x86` or `.aarch64` is the native instruction, for operands and flags.

```python
import binbun

code = bytes.fromhex("fd7bbfa9c0035fd6")
for insn in binbun.disassemble(code, arch=binbun.Arch.AARCH64, address=0x1000):
    print(f"{insn.address:#x}  {insn.mnemonic:<4} reads {insn.registers_read} writes {insn.registers_written}")
```

```text
0x1000  stp  reads ('x29', 'x30', 'sp') writes ('sp',)
0x1004  ret  reads ('x30',) writes ()
```

x86 is 64-bit unless `mode=binbun.x86.Mode.BITS32` (or another mode) says otherwise. Bytes that are no instruction come as `binbun.Invalid`, one byte on x86 and four on AArch64, as the native decoders step.
