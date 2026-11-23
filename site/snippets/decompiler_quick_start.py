from pathlib import Path

import binbun

root = Path(__file__).parents[2]
program = root / "tests/fixtures/program-x86_64.elf"

with binbun.open(program, project=False) as db:
    c = db.functions.get_by_name("classify").decompile()
    print(c.text, end="")

    for line in c.lines:
        if "return" in line.text:
            addresses = " ".join(f"{a:#x}" for a in line.addresses)
            print(f"line {line.number + 1} came from {addresses}")
