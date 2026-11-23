"""Find the functions that call a function with a constant argument: for
each call to it, the instructions before the call in its block are decoded
backwards to what last set the argument's register (``mov`` of an
immediate, ``xor`` of itself, an address computed by ``lea``/``adr``).
Pointers to strings are shown as the string. Reads only: nothing is
written. x86-64 (System V) and AArch64 calling conventions.

With no arguments it finds the calls to exit in the checked-in test program
(tests/fixtures/program-x86_64.elf); give a path, and a function (default
exit), to run on your own binary.

    python calls_with_constant.py
    python calls_with_constant.py /usr/bin/bash exit
    python calls_with_constant.py program.elf fail --argument 1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import binbun
from binbun import aarch64, x86

# The binary run on when no file is given.
FIXTURE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "program-x86_64.elf"

# The System V x86-64 argument registers, by every name they are written to.
X86_64_ARGUMENTS = [
    {"rdi", "edi", "di", "dil"},
    {"rsi", "esi", "si", "sil"},
    {"rdx", "edx", "dx", "dl"},
    {"rcx", "ecx", "cx", "cl"},
    {"r8", "r8d", "r8w", "r8b"},
    {"r9", "r9d", "r9w", "r9b"},
]


def x86_constant(before: list[x86.Instruction], names: set[str]) -> int | None:
    """The constant the last of `before` writing a register of `names`
    puts there, or None if it is none (or none writes one)."""
    for instruction in reversed(before):
        operands = instruction.operands
        written = [
            op for op in operands
            if op.register in names and op.access & binbun.Access.WRITE
        ]
        if not written:
            continue
        source = operands[1] if len(operands) > 1 else None
        if instruction.mnemonic == "mov" and source and source.kind is x86.OperandKind.IMMEDIATE:
            return source.value
        if instruction.mnemonic == "xor" and source and source.register == operands[0].register:
            return 0
        if instruction.mnemonic == "lea" and instruction.computed_address is not None:
            return instruction.computed_address
        return None
    return None


def aarch64_constant(before: list[aarch64.Instruction], n: int) -> int | None:
    """As `x86_constant`, for argument register x`n`."""
    names = {f"x{n}", f"w{n}"}
    for instruction in reversed(before):
        operands = instruction.operands
        first = operands[0].value if operands else None
        if not (
            isinstance(first, aarch64.Register)
            and str(first) in names
            and operands[0].access & binbun.Access.WRITE
        ):
            continue
        source = operands[1].value if len(operands) > 1 else None
        if instruction.mnemonic == "mov" and isinstance(source, aarch64.Immediate):
            return int(source)
        if instruction.mnemonic == "adr":
            return instruction.computed_address
        return None
    return None


def shown(db: binbun.Database, value: int) -> str:
    """`value`, as the string it points to if it does."""
    string = db.strings.get_at(value)
    return repr(string.text) if string is not None else f"{value:#x}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file", nargs="?", default=str(FIXTURE),
                        help="an ELF or PE executable, x86-64 or AArch64 (default: the test program)")
    parser.add_argument("callee", nargs="?", default="exit", help="the function called (default exit)")
    parser.add_argument("--argument", type=int, default=1, help="which argument, from 1 (default 1)")
    args = parser.parse_args()
    if not 1 <= args.argument <= 6:
        parser.error("--argument must be 1 to 6")

    try:
        db = binbun.open(args.file, project=False)
    except binbun.OpenError as error:
        print(error, file=sys.stderr)
        return 1
    with db:
        if db.machine not in (binbun.Machine.X86_64, binbun.Machine.AARCH64):
            print(f"{args.file}: {db.machine.value}: not x86-64 or AArch64", file=sys.stderr)
            return 1
        callee = db.functions.get_by_name(args.callee)
        if callee is None:
            print(f"{args.file}: no function {args.callee}", file=sys.stderr)
            return 1
        calls = db.xrefs.to_ea(callee, kinds={binbun.XrefKind.CALL})
        found = 0
        for call in calls:
            if call.function is None:
                continue
            block = next(b for b in call.function.blocks if b.start <= call.from_ea < b.end)
            code = db.bytes.get_bytes_at(block.start, call.from_ea - block.start) or b""
            if db.machine is binbun.Machine.AARCH64:
                before = [i for i in aarch64.Decoder(code, block.start) if isinstance(i, aarch64.Instruction)]
                value = aarch64_constant(before, args.argument - 1)
            else:
                decoded = x86.Decoder(code, block.start, x86.Mode.BITS64)
                value = x86_constant(
                    [i for i in decoded if isinstance(i, x86.Instruction)],
                    X86_64_ARGUMENTS[args.argument - 1],
                )
            if value is not None:
                found += 1
                print(f"{call.from_ea:#010x}  {call.function.name:<24} {callee.name}(#{args.argument} = {shown(db, value)})")
        print(f"{found} of {len(calls)} calls to {callee.name} pass a constant argument {args.argument}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
