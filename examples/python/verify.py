"""Check that the C binbun prints does what the machine code does
(differential interpretation from random and shaped states), for some
functions or all: one line per function that differs, then the verdicts
counted.

With no arguments it checks every function of the checked-in test program
(tests/fixtures/program-x86_64.elf); give a path (and function names) to
run on your own binary.

    python verify.py
    python verify.py /usr/bin/true
    python verify.py program.elf checked classify
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

import binbun

# The binary run on when no file is given.
FIXTURE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "program-x86_64.elf"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file", nargs="?", default=str(FIXTURE),
                        help="an ELF or PE executable (default: the test program)")
    parser.add_argument("functions", nargs="*", help="names to check (default: every function)")
    parser.add_argument("--limit", type=int, default=None, help="check at most this many")
    args = parser.parse_args()

    try:
        db = binbun.open(args.file, project=False)
    except binbun.OpenError as error:
        print(error, file=sys.stderr)
        return 1
    with db:
        if args.functions:
            functions = []
            for name in args.functions:
                function = db.functions.get_by_name(name)
                if function is None:
                    print(f"{args.file}: no function {name}", file=sys.stderr)
                    return 1
                functions.append(function)
        else:
            functions = list(db.functions)
        verdicts: Counter[str] = Counter()
        for function in functions[: args.limit]:
            verification = function.verify(timeout=300)
            verdicts[verification.verdict] += 1
            if verification.verdict == "differs":
                print(f"{function.entry:#010x} {function.name}: {verification.message}")
        for verdict, count in sorted(verdicts.items()):
            print(f"{verdict}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
