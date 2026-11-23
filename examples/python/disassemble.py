"""Disassemble a buffer of machine code (hexadecimal on the command line, or
a raw file): each instruction's address, bytes and text, x86 (64, 32 or
16-bit) or AArch64. Bytes that are no instruction are shown as such and
skipped (one byte on x86, four on AArch64), as a linear sweep does.

With no bytes given it disassembles a small function of its own (a
prologue, a call, an epilogue) for the architecture.

    python disassemble.py
    python disassemble.py 55 4889e5 e800000000 c3
    python disassemble.py --arch aarch64 --address 0x1000 fd7bbfa9 fd030091 c0035fd6
    python disassemble.py --arch x86-32 --file code.bin
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable

import binbun
from binbun import aarch64, x86

MODES = {"x86-64": x86.Mode.BITS64, "x86-32": x86.Mode.BITS32, "x86-16": x86.Mode.BITS16}
# What is disassembled when no bytes are given: push the frame pointer, set
# it, call the next instruction, pop it, return.
EXAMPLES = {
    "x86-64": "55 4889e5 e800000000 5d c3",
    "x86-32": "55 89e5 e800000000 5d c3",
    "x86-16": "55 89e5 e80000 5d c3",
    "aarch64": "fd7bbfa9 fd030091 01000094 fd7bc1a8 c0035fd6",
}


def disassemble(code: bytes, address: int, arch: str) -> Iterable[x86.Instruction | aarch64.Instruction | binbun.Invalid]:
    """Every instruction (or bytes that are none) of `code` at `address`."""
    if arch == "aarch64":
        return aarch64.Decoder(code, address)
    return x86.Decoder(code, address, MODES[arch])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("hex", nargs="*", help="the bytes, in hexadecimal (default: a small function)")
    parser.add_argument("--file", help="read the bytes from this file instead")
    parser.add_argument("--arch", choices=[*MODES, "aarch64"], default="x86-64")
    parser.add_argument("--address", type=lambda s: int(s, 0), default=0x1000,
                        help="the address of the first byte (default 0x1000)")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, "rb") as f:
                code = f.read()
        except OSError as error:
            parser.error(f"cannot read {args.file}: {error.strerror}")
    else:
        try:
            code = bytes.fromhex("".join(args.hex or [EXAMPLES[args.arch]]))
        except ValueError:
            parser.error("the bytes must be hexadecimal digits, two per byte")
    if not code:
        parser.error("no bytes to disassemble")

    items = list(disassemble(code, args.address, args.arch))
    width = max(len(item.bytes) for item in items) * 3
    for item in items:
        shown = item.bytes.hex(" ")
        if isinstance(item, binbun.Invalid):
            text = f"(bad: {item.status.name.lower()})"
        else:
            text = item.text().replace("\t", " ")
        print(f"{item.address:016x}  {shown:<{width}} {text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
