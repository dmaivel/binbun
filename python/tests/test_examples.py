"""Every Python and Rust example (``examples/python``, ``examples/rust``), run
as a user runs it, with no arguments and against the checked-in fixtures,
its output checked for what it is meant to show: examples that aren't run
rot. The Rust examples are the binaries ``scripts/python-tests.sh`` builds
(``BINBUN_RUST_EXAMPLES``, the directory holding them)."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import binbun
from conftest import ROOT

EXAMPLES = ROOT / "examples" / "python"
FIXTURE = ROOT / "tests" / "fixtures" / "program-x86_64.elf"
AARCH64 = ROOT / "tests" / "fixtures" / "dozen-aarch64.elf"

QUICK_START = [
    "0x401000  push rbp",
    "0x401001  mov rbp, rsp",
    "0x401004  xor eax, eax",
    "0x401006  pop rbp",
]

# Every example, the arguments its header says it defaults to, and the start
# of a line it then prints.
DEFAULTS: dict[str, tuple[list[str], str]] = {
    "quick_start.py": ([], "0x401000  push rbp"),
    "disassemble.py": (["554889e5e8000000005dc3"], "0000000000001004  e8 00 00 00 00  call 0x1009"),
    "decode_any.py": (["554889e5e8000000005dc3"], "0000000000001004  e8 00 00 00 00           call 0x1009"),
    "instruction_info.py": (["48014310"], "0x1000: add qword ptr [rbx+0x10], rax"),
    "color_tokens.py": (["488b4310e800000000c3"], "0x00001004  \x1b[1;34mcall\x1b[0m \x1b[35m0x1009\x1b[0m"),
    "list_calls.py": ([str(FIXTURE)], "0x000011d8  call 0x1190                               classify"),
    "list_functions.py": ([str(FIXTURE)], "0x000011d0      32       4        1  checked"),
    "xrefs.py": ([str(FIXTURE), "main"], "  0x00001067  call      to 0x11f0 loop_sum"),
    "decompile.py": ([str(FIXTURE), "main"], "    // 0x1067  call 0x11f0"),
    "verify.py": ([str(FIXTURE)], "agreed: "),
    "calls_with_constant.py": ([str(FIXTURE), "exit"], "1 of 1 calls to exit pass a constant argument 1"),
    "rename_in_transaction.py": ([str(FIXTURE), "loop_sum"], "// Undo: Name loop_sum: the C is as before"),
    "decompiler_quick_start.py": ([], "line 7 came from 0x1190"),
    "quick_start": ([], "0x401000  push rbp"),
    "disassemble": (["554889e5e8000000005dc3"], "0000000000001004  e8 00 00 00 00  call 0x1009"),
    "decode_any": (["554889e5e8000000005dc3"], "0000000000001004  e8 00 00 00 00           call 0x1009"),
    "instruction_info": (["48014310"], "0x1000: add qword ptr [rbx+0x10], rax"),
    "disassemble_aarch64": (
        ["fd7bbfa9fd03009101000094fd7bc1a8c0035fd6"],
        "0000000000001008  94000001  bl 0x100c                            ; writes x30",
    ),
    "color_tokens": (["200440f900000094c0035fd6"], "0x00001008  \x1b[1;34mret\x1b[0m"),
    "list_calls": ([str(FIXTURE)], "0x000011d8  call 0x1190                               classify"),
    "list_functions": ([str(FIXTURE)], "0x000011d0       4  yes       checked"),
    "xrefs": ([str(FIXTURE), "main"], "  0x00001067  call      to 0x11f0 loop_sum"),
    "decompile": ([str(FIXTURE), "main"], "    printf(\"%d\\n\", loop_sum(a1 + 5));"),
    "provenance": ([str(FIXTURE), "main"], "    return 0;"),
    "decompiler_quick_start": ([], "line 7 came from 0x1190"),
    "verify": ([str(FIXTURE)], "agreed: "),
    "calls_with_constant": ([str(FIXTURE), "exit"], "1 of 1 calls to exit pass a constant first argument"),
}


def run(example: str, *args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
    """`example` run with `args`; it must succeed (or fail, if not `ok`)."""
    if example.endswith(".py"):
        command = [sys.executable, str(EXAMPLES / example)]
    else:
        built = os.environ.get("BINBUN_RUST_EXAMPLES")
        if not built:
            pytest.skip("no Rust examples built (BINBUN_RUST_EXAMPLES)")
        command = [str(Path(built) / example)]
    done = subprocess.run(
        [*command, *args], capture_output=True, text=True, timeout=600, cwd=ROOT
    )
    assert (done.returncode == 0) == ok, done.stdout + done.stderr
    return done


def out(example: str, *args: str) -> list[str]:
    return run(example, *args).stdout.splitlines()


def test_every_example_has_its_defaults_checked() -> None:
    python = {path.name for path in EXAMPLES.glob("*.py")} - {"decompile_all.py"}
    rust = {path.stem for path in (ROOT / "examples" / "rust").glob("*.rs")}
    assert set(DEFAULTS) == python | rust


@pytest.mark.parametrize("example", DEFAULTS)
def test_every_example_runs_with_no_arguments(example: str) -> None:
    defaults, line = DEFAULTS[example]
    bare = out(example)
    assert any(l.startswith(line) for l in bare), bare
    # The fixture as the example names it (the Rust ones from their crate).
    named = re.compile(r"\S*program-x86_64\.elf")
    assert [named.sub("FIXTURE", l) for l in bare] == [named.sub("FIXTURE", l) for l in out(example, *defaults)]


def test_decompile_all_prints_the_c_with_no_arguments(fixture_db: binbun.Database, tmp_path: Path) -> None:
    bare = run("decompile_all.py")
    c = tmp_path / "program.c"
    count = len(fixture_db.functions)
    assert out("decompile_all.py", str(FIXTURE), str(c)) == [f"{count} functions decompiled into {c}, 0 not"]
    assert bare.stdout == c.read_text()
    assert bare.stderr == f"{count} functions decompiled into stdout, 0 not\n"


@pytest.mark.parametrize("example", ["quick_start.py", "quick_start"])
def test_quick_start_prints_each_instruction(example: str) -> None:
    lines = out(example)
    assert lines[:-1] == QUICK_START
    assert lines[-1].startswith("0x401007  ret")


def test_python_disassemble_shows_bytes_and_bad_bytes() -> None:
    lines = out("disassemble.py", "55", "4889e5", "e800000000", "06", "c3")
    assert lines[0].startswith("0000000000001000  55 ") and lines[0].endswith("push rbp")
    assert "e8 00 00 00 00" in lines[2] and lines[2].endswith("call 0x1009")
    assert lines[3].startswith("0000000000001009  06") and lines[3].endswith("(bad: invalid)")
    a64 = out("disassemble.py", "--arch", "aarch64", "--address", "0x2000", "fd7bbfa9", "c0035fd6", "ff")
    assert a64[0] == "0000000000002000  fd 7b bf a9  stp x29, x30, [sp, #-0x10]!"
    assert a64[2].endswith("(bad: truncated)")
    assert "hexadecimal" in run("disassemble.py", "zz", ok=False).stderr


def test_rust_disassemblers_show_bytes_and_bad_bytes() -> None:
    lines = out("disassemble", "55", "4889e5", "06", "c3")
    assert lines[1].startswith("0000000000001001  48 89 e5") and lines[1].endswith("mov rbp, rsp")
    assert lines[2].endswith("(bad: invalid instruction)")
    a64 = out("disassemble_aarch64", "fd7bbfa9", "00000094", "c0035fd6", "ffffffff")
    assert a64[0].startswith("0000000000001000  a9bf7bfd  stp x29, x30, [sp, #-0x10]!")
    assert a64[1].endswith("; writes x30") and a64[2].endswith("; reads x30")
    assert a64[3].endswith("(unallocated encoding)")
    assert "usage" in run("disassemble_aarch64", "zz", ok=False).stderr


def test_decode_any_is_one_api_in_python_and_rust() -> None:
    stp = out("decode_any.py", "--arch", "aarch64")[0]
    assert stp.startswith("0000000000001000  fd 7b bf a9  stp x29, x30, [sp, #-0x10]!")
    assert stp.endswith("stp    reads x29 x30 sp; writes sp")
    x86 = out("decode_any.py", "--arch", "x86-32", "55", "06", "c3")
    assert x86[0].endswith("push   reads ebp ss esp; writes esp")
    assert x86[1].endswith("push   reads es ss esp; writes esp")
    bad = out("decode_any.py", "06", "c3")
    assert bad[0].endswith("(bad: invalid)") and "ret" in bad[1]
    # The Rust crate prints the same lines.
    for args in ([], ["--arch", "aarch64"], ["--arch", "x86-16"], ["--arch", "x86-32", "55", "06", "c3"]):
        assert out("decode_any.py", *args) == out("decode_any", *args)


@pytest.mark.parametrize("example", ["list_calls.py", "list_calls"])
def test_list_calls_names_the_fixtures_calls(example: str) -> None:
    x86 = out(example, str(FIXTURE))
    calls = {line.split()[0]: line for line in x86[1:]}
    assert x86[0].startswith("10 calls in .text of")
    assert calls["0x000011d8"].split()[1:] == ["call", "0x1190", "classify"]
    assert calls["0x000011be"].endswith("exit")
    assert calls["0x000010af"].split()[-1].startswith("*__libc_start_main")
    a64 = out(example, str(AARCH64))
    assert a64[0].startswith("4 calls")
    assert a64[-1].split() == ["0x00210154", "bl", "0x210140", "leaf_sum"]
    assert "no code section .nope" in run(example, str(FIXTURE), *(["--section", ".nope"] if example.endswith(".py") else [".nope"]), ok=False).stderr


def test_instruction_info_shows_access_flags_and_implicit_operands() -> None:
    add = out("instruction_info.py", "48014310")
    assert add[0] == "0x1000: add qword ptr [rbx+0x10], rax"
    assert add[3].split() == ["0", "memory", "read/write", "64", "bits", "[rbx+0x10]", "(8", "bytes)"]
    assert add[4].split() == ["1", "register", "read", "64", "bits", "rax"]
    assert "  implicit: rflags (write)" in add
    assert "  flags read: -; written: CF PF AF ZF SF OF; undefined: -" in add
    stp = out("instruction_info.py", "--arch", "aarch64", "fd7bbfa9")
    assert "  memory: store of 16 bytes" in stp
    assert stp[5].split()[:3] == ["2", "memory", "write"]
    ret = out("instruction_info.py", "--arch", "aarch64", "c0035fd6")
    assert "  implicit: reads x30; writes -" in ret and "  branch: return to none" in ret
    assert "truncated" in run("instruction_info.py", "0f", ok=False).stderr
    rust = out("instruction_info", "55")
    assert rust[0] == "0x1000: push rbp"
    assert "  implicit: stackpush (read/write), [rsp+0x0] (8 bytes) (write), rsp (read/write)" in rust
    assert out("instruction_info", "48014310")[-2] == "  flags: of-mod sf-mod zf-mod af-mod pf-mod cf-mod"


def test_color_tokens_colour_each_kind() -> None:
    assert out("color_tokens.py", "488b4310") == [
        "0x00001000  \x1b[1;34mmov\x1b[0m \x1b[32mrax\x1b[0m, \x1b[36mqword\x1b[0m \x1b[36mptr\x1b[0m "
        "[\x1b[32mrbx\x1b[0m+\x1b[33m0x10\x1b[0m]"
    ]
    page = out("color_tokens.py", "--html", "--arch", "aarch64", "00000094")
    assert page[1] == (
        '0x00001000  <span class="mnemonic">bl</span><span class="whitespace"> </span>'
        '<span class="address">0x1000</span>'
    )
    rust = out("color_tokens", "200440f9")
    assert rust == [
        "0x00001000  \x1b[1;34mldr\x1b[0m \x1b[32mx0\x1b[0m, [\x1b[32mx1\x1b[0m, \x1b[33m#0x8\x1b[0m]"
    ]


def test_list_functions(fixture_db: binbun.Database) -> None:
    lines = out("list_functions.py", str(FIXTURE))
    assert lines[0] == f"program-x86_64.elf: elf x86_64, {len(fixture_db.functions)} functions"
    rows = {line.split()[-1]: line.split() for line in lines[2:]}
    assert rows["checked"] == ["0x000011d0", "32", "4", "1", "checked"]
    assert set(rows) == {f.name for f in fixture_db.functions}
    rust = out("list_functions", str(FIXTURE))
    assert rust[0].endswith(f"{len(fixture_db.functions)} functions")
    assert rust[2:] == [
        f"{f.entry:#010x}  {len(f.blocks):>6}  {'yes' if f.returns else 'no':<8}  {f.name}"
        for f in fixture_db.functions
    ]
    # The OS's code, not its words (which differ by system): ENOENT, and
    # Windows' ERROR_FILE_NOT_FOUND, are both 2.
    assert "(os error 2)" in run("list_functions.py", "no-such-file", ok=False).stderr
    assert "(os error 2)" in run("list_functions", "no-such-file", ok=False).stderr


@pytest.mark.parametrize("example", ["xrefs.py", "xrefs"])
def test_xrefs(example: str) -> None:
    to_exit = out(example, str(FIXTURE), "exit")
    assert to_exit[0] == "1 references to 0x1050 exit"
    assert to_exit[1].split() == ["0x000011be", "call", "in", "fail"]
    to_string = out(example, str(FIXTURE), "0x2004")
    assert to_string[1].split() == ["0x000011e4", "address", "in", "checked"]
    assert "no function" in run(example, str(FIXTURE), "nope", ok=False).stderr


def test_decompile_shows_each_lines_instructions(fixture_db: binbun.Database) -> None:
    printed = out("decompile.py", str(FIXTURE), "fail")
    document = fixture_db.functions.get_by_name("fail").decompile()
    assert [line for line in printed if not line.startswith("    // ")] == [
        line.text for line in document.lines
    ]
    after = printed[printed.index("    puts(s);") + 1]
    assert after == "    // 0x11b4  call 0x1030"
    assert out("decompile.py", str(FIXTURE), "fail", "--c-only") == [l.text for l in document.lines]
    assert "no function nope" in run("decompile.py", str(FIXTURE), "nope", ok=False).stderr
    rust = out("provenance", str(FIXTURE), "fail")
    assert any(line.startswith("    puts(s);") and line.endswith("// 0x11b4") for line in rust)
    assert out("decompile", str(FIXTURE), "fail") == [l.text for l in document.lines]


@pytest.mark.parametrize("example", ["decompiler_quick_start.py", "decompiler_quick_start"])
def test_decompiler_quick_start_prints_the_c_and_a_lines_instructions(
    example: str, fixture_db: binbun.Database
) -> None:
    document = fixture_db.functions.get_by_name("classify").decompile()
    (line,) = [line for line in document.lines if "return" in line.text]
    assert line.addresses
    assert out(example) == [
        *document.text.splitlines(),
        f"line {line.number + 1} came from " + " ".join(f"{a:#x}" for a in line.addresses),
    ]


def test_decompile_all_writes_every_functions_c(
    fixture_db: binbun.Database, tmp_path: Path
) -> None:
    c = tmp_path / "program.c"
    printed = out("decompile_all.py", str(FIXTURE), str(c), "--workers", "2")
    texts = [d.text for _, d in fixture_db.decompile_all() if isinstance(d, binbun.CDocument)]
    assert printed == [f"{len(texts)} functions decompiled into {c}, 0 not"]
    assert c.read_text() == "".join(text + "\n" for text in texts)


@pytest.mark.parametrize("example", ["verify.py", "verify"])
def test_verify_counts_the_verdicts(example: str, fixture_db: binbun.Database) -> None:
    expected: dict[str, int] = {}
    for f in fixture_db.functions:
        verdict = f.verify().verdict
        expected[verdict] = expected.get(verdict, 0) + 1
    printed = dict(line.split(": ") for line in out(example, str(FIXTURE)) if not line.startswith("0x"))
    assert {k: int(v) for k, v in printed.items()} == expected
    if example.endswith(".py"):
        assert out(example, str(FIXTURE), "checked", "classify") == ["agreed: 2"]


@pytest.mark.parametrize("example", ["calls_with_constant.py", "calls_with_constant"])
def test_calls_with_constant_find_the_constant_arguments(example: str) -> None:
    to_fail = out(example, str(FIXTURE), "fail")
    assert to_fail[0].split()[:2] == ["0x000011eb", "checked"]
    assert to_fail[0].rstrip(")").endswith(("'negative'", '"negative"'))
    assert to_fail[1].startswith("1 of 1 calls to fail pass a constant")
    to_exit = out(example, str(FIXTURE), "exit")
    assert to_exit[0].split()[:2] == ["0x000011be", "fail"] and "0x2" in to_exit[0]
    assert out(example, str(FIXTURE), "classify") == [
        "0 of 1 calls to classify pass a constant " + ("argument 1" if example.endswith(".py") else "first argument")
    ]
    assert "no function nope" in run(example, str(FIXTURE), "nope", ok=False).stderr
