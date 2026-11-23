"""Decompile every function of an executable, on all cores, into one C
file; list the functions that do not decompile, and why.

With no arguments it decompiles the checked-in test program
(tests/fixtures/program-x86_64.elf) and prints the C; give a path (and a C
file to write) to run on your own binary.

    python decompile_all.py
    python decompile_all.py /usr/bin/bash bash.c
    python decompile_all.py program.elf program.c --workers 2
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path
from typing import TextIO

import binbun

# The binary run on when no file is given.
FIXTURE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "program-x86_64.elf"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file", nargs="?", default=str(FIXTURE),
                        help="an ELF or PE executable (default: the test program)")
    parser.add_argument("out", nargs="?", help="the C file to write (default: print the C)")
    parser.add_argument("--workers", type=int, default=None, help="threads decompiling (default: every core)")
    args = parser.parse_args()

    try:
        db = binbun.open(args.file, project=False)
    except binbun.OpenError as error:
        print(error, file=sys.stderr)
        return 1
    done = failed = 0
    out: contextlib.AbstractContextManager[TextIO] = contextlib.nullcontext(sys.stdout)
    if args.out:
        try:
            out = open(args.out, "w")
        except OSError as error:
            print(f"{args.out}: {error.strerror}", file=sys.stderr)
            return 1
    with db, out as c:
        for function, document in db.decompile_all(workers=args.workers):
            if isinstance(document, binbun.DecompileError):
                failed += 1
                print(f"{function.entry:#010x} {function.name}: {document}", file=sys.stderr)
                continue
            c.write(document.text + "\n")
            done += 1
    # The count goes with the C's file, or apart from the C printed.
    print(f"{done} functions decompiled into {args.out or 'stdout'}, {failed} not",
          file=sys.stdout if args.out else sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
