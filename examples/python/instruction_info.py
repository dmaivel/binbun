"""Show what one instruction does: its operands and whether it reads or
writes each, the registers it uses without naming them, the flags it reads
and writes, the memory it accesses and where it branches. x86 or AArch64.

With no bytes given it shows an add of a register to memory (on x86-64,
`add qword ptr [rbx+0x10], rax`) or, on AArch64, `stp x29, x30, [sp, #-0x10]!`.

    python instruction_info.py
    python instruction_info.py 48014310                  # add qword ptr [rbx+0x10], rax
    python instruction_info.py 55                        # push rbp: rsp, implicitly
    python instruction_info.py --arch aarch64 fd7bbfa9   # stp x29, x30, [sp, #-0x10]!
"""

from __future__ import annotations

import argparse

import binbun
from binbun import aarch64, x86

MODES = {"x86-64": x86.Mode.BITS64, "x86-32": x86.Mode.BITS32, "x86-16": x86.Mode.BITS16}
ACCESS = {0: "-", 1: "read", 2: "write", 3: "read/write"}
# What is shown when no bytes are given.
EXAMPLES = {"x86-64": "48014310", "x86-32": "014310", "x86-16": "014710", "aarch64": "fd7bbfa9"}


def flag_names(flags: int, every: type[x86.Flag] | type[aarch64.Flag]) -> str:
    return " ".join(f.name or "" for f in every if f & flags and f.value.bit_count() == 1) or "-"


def branch(b: binbun.Branch) -> str:
    if b.kind is binbun.BranchKind.NONE:
        return "none (falls through)"
    where = b.target_kind.name.lower()
    if b.target is not None:
        where += f" {b.target:#x}"
    condition = "conditional " if b.conditional else ""
    return f"{condition}{b.kind.name.lower()} to {where}"


def x86_info(i: x86.Instruction) -> list[str]:
    lines = [
        f"{i.address:#x}: {i.text()}",
        f"  mnemonic {i.mnemonic}, form {i.form}, {i.category}, {i.extension}, {i.length} bytes",
        "  operands:",
    ]
    implicit = []
    for n, op in enumerate(i.operands):
        if op.kind is x86.OperandKind.REGISTER:
            value = op.register or "-"
        elif op.kind is x86.OperandKind.MEMORY:
            parts = [p for p in (op.base, f"{op.index}*{op.scale}" if op.index else None) if p]
            value = f"[{'+'.join(parts)}{op.displacement:+#x}] ({op.memory_size} bytes)"
        elif op.kind is x86.OperandKind.RELATIVE:
            value = f"{op.displacement:+#x} from the next instruction"
        else:
            value = f"{op.value:#x}"
        line = f"    {n}  {op.kind.name.lower():<9} {ACCESS[op.access]:<10} {op.bits:>3} bits  {value}"
        lines.append(line)
        if op.visibility is x86.Visibility.SUPPRESSED:
            implicit.append(f"{value} ({ACCESS[op.access]})")
    lines.append(f"  implicit: {', '.join(implicit) or '-'}")
    f = i.flags
    lines.append(f"  flags read: {flag_names(f.read, x86.Flag)}; written: {flag_names(f.written, x86.Flag)}"
                 f"; undefined: {flag_names(f.undefined, x86.Flag)}")
    lines.append(f"  branch: {branch(i.branch)}")
    return lines


def aarch64_info(i: aarch64.Instruction) -> list[str]:
    lines = [
        f"{i.address:#x}: {i.text().replace(chr(9), ' ')}",
        f"  mnemonic {i.mnemonic}, encoding {i.encoding}",
        "  operands:",
    ]
    for n, op in enumerate(i.operands):
        lines.append(f"    {n}  {op.kind.name.lower():<9} {ACCESS[op.access]:<10} {op.value}")
    reads = ", ".join(str(r) for r in i.implicit_reads) or "-"
    writes = ", ".join(str(r) for r in i.implicit_writes) or "-"
    lines.append(f"  implicit: reads {reads}; writes {writes}")
    if i.memory is not None:
        lines.append(f"  memory: {i.memory.kind.name.lower()} of {i.memory.size} bytes")
    lines.append(f"  flags read: {flag_names(i.flags.read, aarch64.Flag)}; "
                 f"written: {flag_names(i.flags.written, aarch64.Flag)}")
    lines.append(f"  branch: {branch(i.branch)}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("hex", nargs="*", help="the instruction's bytes, in hexadecimal (default: an example)")
    parser.add_argument("--arch", choices=[*MODES, "aarch64"], default="x86-64")
    parser.add_argument("--address", type=lambda s: int(s, 0), default=0x1000)
    args = parser.parse_args()
    try:
        code = bytes.fromhex("".join(args.hex or [EXAMPLES[args.arch]]))
    except ValueError:
        parser.error("the bytes must be hexadecimal digits, two per byte")

    try:
        if args.arch == "aarch64":
            lines = aarch64_info(aarch64.decode(code, args.address))
        else:
            lines = x86_info(x86.decode(code, args.address, MODES[args.arch]))
    except binbun.DecodeError as error:
        parser.exit(1, f"{code.hex(' ')}: {error.status.name.lower()}: no instruction\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
