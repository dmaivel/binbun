"""Disassemble a buffer of machine code (hexadecimal on the command line)
for x86 (64, 32 or 16-bit) or AArch64 through one decoder
(``binbun.disassemble``): each instruction's address, bytes, text,
mnemonic, and the registers it reads and writes. Bytes that are no
instruction are shown as such and skipped (one byte on x86, four on
AArch64). What one architecture alone has (operands, flags) is the native
instruction's, ``insn.x86`` or ``insn.aarch64``.

With no bytes given it disassembles a small function of its own (a
prologue, a call, an epilogue) for the architecture.

    python decode_any.py
    python decode_any.py --arch aarch64
    python decode_any.py --arch x86-32 --address 0x400000 55 89e5 c3
"""

from __future__ import annotations

import argparse

import binbun
from binbun import x86

ARCHS = {
    "x86-64": (binbun.Arch.X86, x86.Mode.BITS64),
    "x86-32": (binbun.Arch.X86, x86.Mode.BITS32),
    "x86-16": (binbun.Arch.X86, x86.Mode.BITS16),
    "aarch64": (binbun.Arch.AARCH64, None),
}
# What is disassembled when no bytes are given: push the frame pointer, set
# it, call the next instruction, pop it, return.
EXAMPLES = {
    "x86-64": "554889e5e8000000005dc3",
    "x86-32": "5589e5e8000000005dc3",
    "x86-16": "5589e5e800005dc3",
    "aarch64": "fd7bbfa9fd03009101000094fd7bc1a8c0035fd6",
}


def names(registers: tuple[str, ...]) -> str:
    return " ".join(registers) or "-"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("hex", nargs="*", help="the bytes, in hexadecimal (default: a small function)")
    parser.add_argument("--arch", choices=ARCHS, default="x86-64")
    parser.add_argument("--address", type=lambda s: int(s, 0), default=0x1000,
                        help="the address of the first byte (default 0x1000)")
    args = parser.parse_args()
    try:
        code = bytes.fromhex("".join(args.hex or [EXAMPLES[args.arch]]))
    except ValueError:
        parser.error("the bytes must be hexadecimal digits, two per byte")
    if not code:
        parser.error("no bytes to disassemble")

    arch, mode = ARCHS[args.arch]
    width = (4 if arch is binbun.Arch.AARCH64 else 8) * 3
    for item in binbun.disassemble(code, arch=arch, address=args.address, mode=mode):
        shown = item.bytes.hex(" ")
        if isinstance(item, binbun.Invalid):
            print(f"{item.address:016x}  {shown:<{width}} (bad: {item.status.name.lower()})")
            continue
        text = item.text().replace("\t", " ")
        print(
            f"{item.address:016x}  {shown:<{width}} {text:<28} {item.mnemonic:<6} "
            f"reads {names(item.registers_read)}; writes {names(item.registers_written)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
