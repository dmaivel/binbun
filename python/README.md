# binbun

Python bindings to [binbun](https://binbun.org), an open-source interactive disassembler and decompiler for x86, x86-64 and AArch64 executables in ELF, PE and Mach-O files. The whole engine is in the package: open a binary, list its functions and cross-references, decompile them to C with each line's provenance, check the C against the machine code, and edit names, types and comments in transactions you can undo. Its disassemblers also work on raw bytes.

```sh
pip install binbun
```

```python
import binbun

with binbun.open("/usr/bin/bash", project=False) as db:
    c = db.functions.get_by_name("main").decompile()
    print(c.text)
    # Each line of C with the instructions it came from.
    for line in c.lines:
        if line.addresses:
            print(line.number + 1, [hex(a) for a in line.addresses])
```

```python
import binbun

code = bytes.fromhex("554889e531c05dc3")
for insn in binbun.disassemble(code, arch=binbun.Arch.X86, address=0x401000):
    print(f"{insn.address:#x}  {insn.text()}")
```

The same package works against the binary open in the binbun app with `binbun.connect()`. Python 3.11 or later; the [Python documentation](https://binbun.org/docs/python/) covers the API, and the app is on [binbun.org](https://binbun.org/download/). The API can change between releases while binbun is 0.x.

Licensed under either of [Apache License, Version 2.0](https://github.com/dmaivel/binbun/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/dmaivel/binbun/blob/main/LICENSE-MIT) at your option. The decoders' code generated from Intel XED is under XED's Apache License, Version 2.0, and that generated from Arm's A-profile Machine Readable Specification under Arm's BSD 3-Clause licence; both texts are in the package's licence files.
