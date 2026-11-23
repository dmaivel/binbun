"""Open an executable and list its functions: entry, size in bytes, blocks,
callers and name, in address order. The first thing to try on a binary.

With no file given it runs on the checked-in test program
(tests/fixtures/program-x86_64.elf); give a path to run on your own binary.

    python list_functions.py
    python list_functions.py /usr/bin/true
    python list_functions.py program.elf --match sum
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import binbun

# The binary run on when no file is given.
FIXTURE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "program-x86_64.elf"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file", nargs="?", default=str(FIXTURE),
                        help="an ELF or PE executable (default: the test program)")
    parser.add_argument("--match", default="", help="only the functions whose name contains this")
    args = parser.parse_args()

    try:
        db = binbun.open(args.file, project=False)
    except binbun.OpenError as error:
        print(error, file=sys.stderr)
        return 1
    with db:
        print(f"{db.name}: {db.format.value} {db.machine.value}, {len(db.functions)} functions")
        print(f"{'entry':>10}  {'bytes':>6}  {'blocks':>6}  {'callers':>7}  name")
        for function in db.functions:
            if args.match not in function.name:
                continue
            size = sum(end - start for start, end in function.ranges)
            print(
                f"{function.entry:#010x}  {size:>6}  {len(function.blocks):>6}"
                f"  {len(function.callers()):>7}  {function.name}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
