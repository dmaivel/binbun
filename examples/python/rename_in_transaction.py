"""Rename a function and its first parameter and comment its entry in one
transaction (one undo step), print its C before and after, then undo the
whole transaction and check the C is back as it was.

With no arguments it works on loop_sum in the checked-in test program
(tests/fixtures/program-x86_64.elf); give a path, and a function (default
loop_sum), to run on your own binary. Nothing is saved: the database is
opened without a project.

    python rename_in_transaction.py
    python rename_in_transaction.py /usr/bin/true main
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
    parser.add_argument("function", nargs="?", default="loop_sum",
                        help="the function's name; default loop_sum")
    args = parser.parse_args()

    try:
        db = binbun.open(args.file, project=False)
    except binbun.OpenError as error:
        print(error, file=sys.stderr)
        return 1
    with db:
        function = db.functions.get_by_name(args.function)
        if function is None:
            print(f"{args.file}: no function {args.function}", file=sys.stderr)
            return 1
        before = function.decompile(timeout=300)
        print(f"// before\n{before.text}")

        parameters = [v for v in before.variables if v.kind == "parameter"]
        with db.transaction(f"Name {function.name}") as tx:
            db.functions.set_name(function, f"{function.name}_renamed")
            if parameters:
                parameters[0].rename("limit")
            db.comments.set_at(function.entry, "Renamed by rename_in_transaction.py")
        after = function.decompile(timeout=300)
        print(f"// after: {tx.entry.label!r} by {tx.entry.author.via}, {tx.entry.edits} edits, one undo step")
        print(after.text)

        undone = db.undo()
        again = function.decompile(timeout=300)
        print(f"// {undone.label}: the C is {'as before' if again.text == before.text else 'NOT as before'}")
        return 0 if again.text == before.text else 1


if __name__ == "__main__":
    raise SystemExit(main())
