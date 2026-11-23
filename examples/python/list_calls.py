"""List the calls in an executable's code section: each call's address, its
text, and where it goes (a function's name, an import through its slot, or
"indirect"). The section is swept in one go (``sweep()``: columns, no object
per instruction); only the calls are decoded again for their text.
x86-64, x86-32 and AArch64; ELF or PE.

With no file given it runs on the checked-in test program
(tests/fixtures/program-x86_64.elf); give a path to run on your own binary.

    python list_calls.py
    python list_calls.py /usr/bin/true
    python list_calls.py program.exe --section .text
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


def list_calls(db: binbun.Database, section: binbun.Section) -> list[str]:
    """One line per call in `section` of `db`."""
    data = db.bytes.get_bytes_at(section.start, section.end - section.start) or b""
    decode: Callable[[bytes, int], x86.Instruction | aarch64.Instruction]
    if db.machine is binbun.Machine.AARCH64:
        sweep = aarch64.sweep(data, section.start)
        decode = aarch64.decode
    elif db.machine in (binbun.Machine.X86_64, binbun.Machine.X86):
        mode = x86.Mode.BITS64 if db.machine is binbun.Machine.X86_64 else x86.Mode.BITS32
        sweep = x86.sweep(data, section.start, mode)
        decode = partial(x86.decode, mode=mode)
    else:
        raise SystemExit(f"{db.path}: {db.architecture} code is neither x86 nor AArch64")

    imports = {i.address: i.name for i in db.imports}
    lines = []
    for n, kind in enumerate(sweep.branch_kinds):
        if kind != binbun.BranchKind.CALL:
            continue
        address, length, target = sweep.addresses[n], sweep.lengths[n], sweep.targets[n]
        offset = address - section.start
        text = decode(data[offset : offset + length], address).text().replace("\t", " ")
        target_kind = sweep.target_kinds[n]
        if target_kind == binbun.TargetKind.ADDRESS and target is not None:
            where = db.names.get_display_at(target) or f"{target:#x}"
        elif target_kind == binbun.TargetKind.POINTER and target is not None:
            where = f"*{imports.get(target, hex(target))}"
        else:
            where = "indirect"
        lines.append(f"{address:#010x}  {text:<40}  {where}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file", nargs="?", default=str(FIXTURE),
                        help="an ELF or PE executable (default: the test program)")
    parser.add_argument("--section", default=".text", help="the code section (default .text)")
    args = parser.parse_args()

    try:
        db = binbun.open(args.file, project=False, debug="none", wait=binbun.Stage.IMAGE)
    except binbun.OpenError as error:
        print(error, file=sys.stderr)
        return 1
    with db:
        section = db.sections.get_by_name(args.section)
        if section is None or not section.is_code:
            code = ", ".join(s.name for s in db.sections if s.is_code)
            print(f"{args.file}: no code section {args.section} (code: {code})", file=sys.stderr)
            return 1
        lines = list_calls(db, section)
        print(f"{len(lines)} calls in {args.section} of {db.name}")
        for line in lines:
            print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
