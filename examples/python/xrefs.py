"""Cross-references of a function or an address: who refers to it (calls,
jumps, reads, writes, pointers), from where and in which function; and,
for a function, what it refers to.

With no arguments it shows main's in the checked-in test program
(tests/fixtures/program-x86_64.elf); give a path, and a function or an
address (default main), to run on your own binary.

    python xrefs.py
    python xrefs.py /usr/bin/true main
    python xrefs.py program.elf 0x1190
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import binbun

# The binary run on when no file is given.
FIXTURE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "program-x86_64.elf"


def describe(db: binbun.Database, address: int) -> str:
    """`address` with the name of what is there, if it has one."""
    name = db.names.get_display_at(address)
    return f"{address:#x} {name}" if name else f"{address:#x}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file", nargs="?", default=str(FIXTURE),
                        help="an ELF or PE executable (default: the test program)")
    parser.add_argument("target", nargs="?", default="main",
                        help="a function's name, or an address (0x...); default main")
    args = parser.parse_args()

    try:
        db = binbun.open(args.file, project=False)
    except binbun.OpenError as error:
        print(error, file=sys.stderr)
        return 1
    with db:
        db.wait(binbun.Stage.REFERENCED)
        function = db.functions.get_by_name(args.target)
        if function is not None:
            address = function.entry
        else:
            try:
                address = int(args.target, 0)
            except ValueError:
                print(f"{args.file}: no function named {args.target}", file=sys.stderr)
                return 1
            function = db.functions[address] if address in db.functions else None

        to = db.xrefs.to_ea(address)
        print(f"{len(to)} references to {describe(db, address)}")
        for xref in to:
            made_in = xref.function.name if xref.function else "(data)"
            print(f"  {xref.from_ea:#010x}  {xref.kind.value:<8}  in {made_in}")
        if function is not None:
            made = function.xrefs_from()
            print(f"{len(made)} references from {function.name}")
            for xref in made:
                print(f"  {xref.from_ea:#010x}  {xref.kind.value:<8}  to {describe(db, xref.to_ea)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
