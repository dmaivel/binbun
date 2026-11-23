"""Quick start: decode a few bytes of x86-64 machine code and print each
instruction at its address. No file, no database: the decoder alone,
through ``binbun.disassemble``, the same call for AArch64
(``arch=binbun.Arch.AARCH64``).

    python quick_start.py
"""

import binbun

code = bytes.fromhex("554889e531c05dc3")

for insn in binbun.disassemble(code, arch=binbun.Arch.X86, address=0x401000):
    print(f"{insn.address:#x}  {insn.text()}")
