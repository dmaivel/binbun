"""bash, read through the API and compared with the CLI: the functions,
every function's C (whole program, and a sample asked for by name: several
a run, and a few alone), the cross-references and strings, verification;
the provenance of every document; two Python threads at once; Ctrl-C
during a long verification. Skipped where /usr/bin/bash is absent."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import binbun
from conftest import cli

SAMPLE = 300
# How many of the sample the CLI is asked for alone, a run each; it is asked
# for the whole sample in one run (`binbun decompile FILE F1 F2 ...`, each
# printed as alone): bash is analysed once a run, which takes far longer
# than a function's C.
ALONE = 5

# How many CLI runs at once: as many as this process has cores. Each run
# analyses bash anew.
CORES = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 8


def sample(items: list, count: int) -> list:
    """`count` of `items`, evenly spread, deterministically."""
    step = max(1, len(items) // count)
    return items[::step][:count]


@pytest.fixture(scope="module")
def documents(bash_db: binbun.Database) -> dict[int, binbun.CDocument | binbun.DecompileError]:
    """Every function's C (or why not) by entry, through decompile_all."""
    return {f.entry: doc for f, doc in bash_db.decompile_all(workers=8)}


def as_the_cli_prints(db: binbun.Database, documents: dict) -> str:
    """The whole-program output of `binbun decompile FILE`, from the API."""
    out = []
    for entry, doc in documents.items():
        if isinstance(doc, binbun.CDocument):
            out.append(doc.text if doc.text.endswith("\n") else doc.text + "\n")
        else:
            name = db.functions[entry].symbol or ""
            message = str(doc).replace("*/", "* /")
            out.append(f"/* {entry:#x} {name}: not decompiled: {message} */\n")
        out.append("\n")
    return "".join(out)


def test_the_functions_are_the_clis(bash_db: binbun.Database, bash_path: Path) -> None:
    listed = cli("functions", str(bash_path)).splitlines()
    entries = [int(line.split()[0], 16) for line in listed]
    assert len(bash_db.functions) == len(listed)
    assert bash_db.functions.entries() == sorted(entries)


def test_every_functions_c_is_the_clis_whole_program(
    bash_db: binbun.Database, bash_path: Path, documents: dict
) -> None:
    assert list(documents) == bash_db.functions.entries()
    expected = cli("decompile", str(bash_path))
    assert as_the_cli_prints(bash_db, documents) == expected


def test_a_sample_asked_alone_is_the_clis(
    bash_db: binbun.Database, bash_path: Path, documents: dict
) -> None:
    decompiled = [e for e, d in documents.items() if isinstance(d, binbun.CDocument)]
    chosen = sample(decompiled, SAMPLE)
    assert len(chosen) >= SAMPLE
    runs = [chosen] + [[entry] for entry in sample(chosen, ALONE)]

    def printed(entries: list[int]) -> str:
        return cli("decompile", str(bash_path), *(f"{entry:#x}" for entry in entries))

    with ThreadPoolExecutor(max_workers=len(runs)) as pool:
        outputs = list(pool.map(printed, runs))
    differing = []
    for entries, output in zip(runs, outputs):
        # Each function's C in turn; after the first that differs, where
        # the next starts is unknown.
        at = 0
        for entry in entries:
            text = bash_db.decompile(entry).text
            expected = (text if text.endswith("\n") else text + "\n") + "\n"
            if not output.startswith(expected, at):
                differing.append(hex(entry))
                break
            at += len(expected)
        else:
            if at != len(output):
                differing.append(f"more after {entries[-1]:#x}")
    assert differing == []


def test_every_line_is_made_from_its_functions_instructions(
    bash_db: binbun.Database, documents: dict
) -> None:
    checked = 0
    for entry, doc in documents.items():
        if not isinstance(doc, binbun.CDocument):
            continue
        ranges = bash_db.functions[entry].ranges
        for line in doc.lines:
            for address in line.addresses:
                assert any(s <= address < e for s, e in ranges), (hex(entry), line)
                assert line in doc.lines_of(address)
                checked += 1
    assert checked > 10_000


def xref_kind(x: binbun.Xref) -> str:
    """How the CLI names `x`'s kind."""
    if x.kind is binbun.XrefKind.POINTER:
        return f"pointer({x.relocation or x.pointer_origin})"
    return x.kind.value


def test_xrefs_are_the_clis(bash_db: binbun.Database, bash_path: Path) -> None:
    called = [f for f in bash_db.functions if bash_db.xrefs.calls_to_ea(f.entry)]
    strings = [s for s in bash_db.strings.get_all() if s.referenced]
    targets = [f.entry for f in sample(called, 16)] + [s.address for s in sample(strings, 8)]

    def listed(target: int) -> tuple[int, str]:
        return target, cli("xrefs", str(bash_path), f"{target:#x}")

    with ThreadPoolExecutor(max_workers=CORES) as pool:
        printed = dict(pool.map(listed, targets))
    compared = 0
    for target in targets:
        lines = printed[target].splitlines()
        if "an object of" in lines[0]:
            continue  # the CLI lists a whole object's
        expected = sorted(
            (int(line.split()[0], 16), line.split()[1])
            for line in lines
            if line.startswith("0x")
        )
        got = sorted((x.from_ea, xref_kind(x)) for x in bash_db.xrefs.to_ea(target))
        assert got == expected, hex(target)
        compared += 1
    assert compared >= 16


PLAIN = re.compile(r'[ !#-\[\]-~]*')  # printable ASCII but `"`, `\` (and `?` below)


def test_strings_are_the_clis(bash_db: binbun.Database, bash_path: Path) -> None:
    rows = [
        line.split(" ", 5)
        for line in cli("strings", str(bash_path)).splitlines()
        if not line.startswith("#")
    ]
    strings = bash_db.strings.get_all(min_length=4)
    assert len(strings) == len(rows)
    for s, (address, section, encoding, length, references, literal) in zip(strings, rows):
        assert (s.address, s.section or "-", s.encoding, s.length, s.references) == (
            int(address, 16),
            section,
            encoding,
            int(length),
            int(references),
        )
        if s.encoding == "utf8" and PLAIN.fullmatch(s.text) and "?" not in s.text:
            assert literal == f'"{s.text}"'


AGREED = re.compile(r"agreed on (\d+) of (\d+) sampled states")
# `binbun verify`'s exit status for a function of each verdict.
VERIFY_STATUS = {"agreed": 0, "differs": 1, "not_checkable": 3}


def test_verification_is_the_clis(bash_db: binbun.Database, bash_path: Path) -> None:
    middling = [f for f in bash_db.functions if 3 <= len(f.blocks) <= 12]
    chosen = sample(middling, 8)
    verdicts = [f.verify(timeout=600) for f in chosen]

    def verified(f: binbun.Function, v: binbun.Verification) -> str:
        return cli(
            "verify", str(bash_path), f"{f.entry:#x}", "--fuel", str(v.fuel), status=VERIFY_STATUS[v.verdict]
        )

    with ThreadPoolExecutor(max_workers=CORES) as pool:
        printed_all = list(pool.map(verified, chosen, verdicts))
    for v, printed in zip(verdicts, printed_all):
        if v.verdict == "agreed":
            found = AGREED.search(printed)
            assert found, printed
            assert (int(found[1]), int(found[2])) == (v.agreed, v.states)
        elif v.verdict == "not_checkable":
            assert f"not checkable: {v.message}" in printed
        else:
            assert "differs:" in printed and v.message in printed


def share_of_time_python_ran(call: Callable[[], object]) -> float:
    """The share of the time `call` took during which a pure-Python counter
    on another thread could run, from the counter's rate while this thread
    only sleeps, before and after the call (their mean, so load that comes
    and goes is not taken for the call's). A call that holds the GIL leaves
    the counter no Python to run (a share of about 0); one that releases it
    leaves the counter running, slowed only by what else the machine runs
    (the call's own threads included): well above 0, and near 1 on an idle
    machine."""
    steps = 0
    running = threading.Event()
    done = threading.Event()

    def count() -> None:
        nonlocal steps
        running.set()
        while not done.is_set():
            steps += 1

    counter = threading.Thread(target=count)
    counter.start()
    running.wait()
    try:
        before, started = steps, time.monotonic()
        time.sleep(0.3)
        rate_before = (steps - before) / (time.monotonic() - started)
        before, started = steps, time.monotonic()
        call()
        after, took = steps, time.monotonic() - started
        mark, settled = steps, time.monotonic()
        time.sleep(0.3)
        rate_after = (steps - mark) / (time.monotonic() - settled)
    finally:
        done.set()
        counter.join()
    rate = (rate_before + rate_after) / 2
    return (after - before) / (rate * took)


def test_heavy_calls_let_other_python_threads_run(bash_path: Path) -> None:
    # A fresh database, so nothing is decompiled or verified yet.
    with binbun.open(bash_path, project=False, debug="none", wait=None) as db:
        waiting = share_of_time_python_ran(lambda: db.wait(binbun.Stage.CALLERS))
        yyparse = db.functions.get_by_name("yyparse")
        assert yyparse is not None
        decompiling = share_of_time_python_ran(lambda: db.decompile(yyparse))
        verifying = share_of_time_python_ran(lambda: yyparse.verify())
    shares = (waiting, decompiling, verifying)
    # Holding the GIL gives about 0; a loaded machine has given 0.08 to a
    # call that releases it.
    assert all(share > 0.02 for share in shares), shares


# No single function of bash takes a second to verify (yyparse, the
# slowest, about 0.6 s), so the long verification interrupted is the
# whole program's, biggest functions first (about 15 s): Ctrl-C lands in
# one function's `verify` (the frame it is raised in says so), which
# cancels that question; asked again it is answered, as is the next.
INTERRUPTED = """
import json, signal, sys, time, traceback
# Python keeps SIGINT ignored when it starts with it ignored, as every
# process a non-interactive shell runs in the background does (`tests &`):
# Ctrl-C is then lost before binbun sees it. A user's Python at a terminal
# has Python's own handler; so has this one.
signal.signal(signal.SIGINT, signal.default_int_handler)
import binbun
db = binbun.open(sys.argv[1], project=False, debug="none")
db.wait(binbun.Stage.CALLERS)
functions = sorted(db.functions, key=lambda f: len(f.blocks), reverse=True)
print("verifying", flush=True)
outcome = {"interrupted": False}
for i, f in enumerate(functions):
    try:
        f.verify()
    except KeyboardInterrupt as interrupt:
        at = time.time()
        raised_in = traceback.extract_tb(interrupt.__traceback__)[-1].lineno
        outcome = {"interrupted": True, "at": at, "in": raised_in, "index": i}
        outcome["again"] = f.verify(timeout=300).verdict
        outcome["next"] = functions[i + 1].verify(timeout=300).verdict
        break
print(json.dumps(outcome), flush=True)
db.close()
"""


def test_ctrl_c_stops_a_long_verification_and_the_next_answers(bash_path: Path) -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", INTERRUPTED, str(bash_path)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert child.stdout is not None
    assert child.stdout.readline().strip() == "verifying"
    time.sleep(1.0)
    sent = time.time()
    child.send_signal(signal.SIGINT)
    outcome = json.loads(child.stdout.readline())
    assert child.wait(timeout=300) == 0
    assert outcome["interrupted"], "the verification ended before Ctrl-C"
    verify_line = INTERRUPTED.splitlines().index("        f.verify()") + 1
    assert outcome["in"] == verify_line, outcome
    assert outcome["at"] - sent < 1.0, outcome["at"] - sent
    verdicts = {"agreed", "differs", "not_checkable"}
    assert outcome["again"] in verdicts and outcome["next"] in verdicts, outcome
