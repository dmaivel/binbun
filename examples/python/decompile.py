"""Decompile a function and show where each line of C comes from: after
each line, the machine instructions it was made from (provenance), decoded
from the function's blocks.

With no arguments it decompiles main in the checked-in test program
(tests/fixtures/program-x86_64.elf); give a path, and a function (default
main), to run on your own binary.

    python decompile.py
    python decompile.py /usr/bin/true main
    python decompile.py program.elf checked --c-only
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from functools import partial
from pathlib import Path

import binbun
from binbun import aarch64, x86

# The binary run on when no file is given.
FIXTURE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "program-x86_64.elf"


def decoder(db: binbun.Database) -> Callable[[bytes, int], x86.Instruction | aarch64.Instruction]:
    """A function decoding the instruction at the start of some bytes at an
    address, for `db`'s machine."""
    if db.machine is binbun.Machine.AARCH64:
        return aarch64.decode
    mode = x86.Mode.BITS64 if db.machine is binbun.Machine.X86_64 else x86.Mode.BITS32
    return partial(x86.decode, mode=mode)


def find(db: binbun.Database, wanted: str) -> binbun.Function | None:
    """The function named `wanted`, or starting at it (``0x...``)."""
    function = db.functions.get_by_name(wanted)
    if function is None and wanted.startswith("0x"):
        entry = int(wanted, 16)
        function = db.functions[entry] if entry in db.functions else None
    return function


def instructions(db: binbun.Database, function: binbun.Function) -> dict[int, str]:
    """The text of each instruction of `function`, by address."""
    decode = decoder(db)
    texts = {}
    for block in function.blocks:
        code = db.bytes.get_bytes_at(block.start, block.end - block.start) or b""
        offset = 0
        while offset < len(code):
            instruction = decode(code[offset:], block.start + offset)
            texts[instruction.address] = instruction.text().replace("\t", " ")
            offset += instruction.length
    return texts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file", nargs="?", default=str(FIXTURE),
                        help="an ELF or PE executable (default: the test program)")
    parser.add_argument("function", nargs="?", default="main",
                        help="the function's name, or its entry (0x...); default main")
    parser.add_argument("--c-only", action="store_true", help="the C alone, without instructions")
    args = parser.parse_args()

    try:
        db = binbun.open(args.file, project=False)
    except binbun.OpenError as error:
        print(error, file=sys.stderr)
        return 1
    with db:
        function = find(db, args.function)
        if function is None:
            print(f"{args.file}: no function {args.function}", file=sys.stderr)
            return 1
        try:
            document = function.decompile(timeout=300)
        except binbun.DecompileError as error:
            print(f"{function.name}: {error}", file=sys.stderr)
            return 1
        texts = {} if args.c_only else instructions(db, function)
        for line in document.lines:
            print(line.text)
            for address in [] if args.c_only else line.addresses:
                print(f"    // {address:#x}  {texts.get(address, '?')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
