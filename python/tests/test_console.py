"""``python -m binbun.console``, the GUI's console, spoken to as the GUI
speaks to it (lines of JSON on its stdin and stdout) against a database
served with a window's cursor (``db.serve(ui=True)``): cells run, their
output, values and tracebacks; incomplete cells; one undo step a cell,
kept when it raises; the magic variables following the cursor;
completions and signatures with jedi and without; Ctrl+C; startup.py; a
console that cannot connect."""

from __future__ import annotations

import importlib.util
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import binbun
from conftest import FIXTURE

HAS_JEDI = importlib.util.find_spec("jedi") is not None


class Console:
    """A console process and what it said."""

    def __init__(
        self,
        server: binbun.Server,
        db: binbun.Database,
        config: Path,
        *args: str,
        preexec_fn: Callable[[], object] | None = None,
    ) -> None:
        env = dict(os.environ, XDG_CONFIG_HOME=str(config))
        self.process = subprocess.Popen(
            [sys.executable, "-m", "binbun.console", "--socket", server.socket, "--database", db.path, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=env,
            preexec_fn=preexec_fn,
        )
        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.next = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.events.put(json.loads(line))

    def send(self, request: dict[str, Any]) -> int:
        self.next += 1
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps({"id": self.next, **request}) + "\n")
        self.process.stdin.flush()
        return self.next

    def expect(self, wanted: Callable[[dict[str, Any]], bool], timeout: float = 60.0) -> list[dict[str, Any]]:
        """The events up to the first ``wanted`` one, it included."""
        seen = []
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            assert left > 0, f"never came; saw {seen}"
            event = self.events.get(timeout=left)
            seen.append(event)
            if wanted(event):
                return seen

    def run(self, code: str) -> dict[str, Any]:
        """Runs ``code``: its output joined, its result, error and done
        event."""
        cell = self.send({"op": "run", "code": code})
        events = self.expect(lambda e: e["event"] == "done" and e["id"] == cell)
        out = "".join(e["text"] for e in events if e["event"] == "output" and e["stream"] == "stdout")
        err = "".join(e["text"] for e in events if e["event"] == "output" and e["stream"] == "stderr")
        result = next((e["text"] for e in events if e["event"] == "result"), None)
        error = next((e["text"] for e in events if e["event"] == "error"), None)
        return {"out": out, "err": err, "result": result, "error": error, "done": events[-1]}

    def close(self) -> None:
        if self.process.poll() is None:
            assert self.process.stdin is not None
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


@pytest.fixture()
def window(tmp_path: Path) -> Iterator[tuple[binbun.Database, binbun.Server]]:
    """The fixture with a project of its own, served with a window's
    cursor and selection."""
    with binbun.open(FIXTURE, project=tmp_path / "project", debug="none") as db:
        db.wait(binbun.Stage.CALLERS)
        with db.serve(ui=True) as server:
            yield db, server


def start(
    window: tuple[binbun.Database, binbun.Server],
    config: Path,
    *args: str,
    preexec_fn: Callable[[], object] | None = None,
) -> Console:
    db, server = window
    console = Console(server, db, config, *args, preexec_fn=preexec_fn)
    ready = console.expect(lambda e: e["event"] in ("ready", "failed"))[-1]
    assert ready["event"] == "ready", ready
    assert ready["protocol"] == 1 and ready["path"] == db.path
    return console


@pytest.fixture()
def console(window: tuple[binbun.Database, binbun.Server], tmp_path: Path) -> Iterator[Console]:
    started = start(window, tmp_path / "config")
    yield started
    started.close()


def test_a_cell_runs_its_output_streams_and_its_value_shows(console: Console) -> None:
    done = console.run("import os\nprint('hi')\nos.write(1, b'fd\\n')\nprint('e', file=__import__('sys').stderr)\n6 * 7")
    assert done["out"] == "hi\nfd\n"
    assert done["err"] == "e\n"
    assert done["result"] == "42"
    # The value is `_`; a statement shows nothing; stdin is empty.
    assert console.run("_ + 1")["result"] == "43"
    assert console.run("x = 1")["result"] is None
    assert "EOFError" in console.run("input()")["error"]


def test_enter_runs_only_a_complete_cell(console: Console) -> None:
    for code in ["if True:", "for i in range(2):\n    print(i)", "x = (1,"]:
        cell = console.send({"op": "run", "code": code})
        assert console.expect(lambda e: e.get("id") == cell)[-1]["event"] == "incomplete"
    done = console.run("for i in range(2):\n    print(i)\n")
    assert done["out"] == "0\n1\n"
    # A syntax error is complete: it runs, and says so.
    assert "SyntaxError" in console.run("def f(:")["error"]


def test_a_traceback_shows_the_cells_frames_not_the_consoles(console: Console) -> None:
    error = console.run("def f():\n    raise ValueError('boom')\n\nf()\n")["error"]
    assert error.startswith("Traceback")
    assert "ValueError: boom" in error
    assert 'File "<console#' in error and "raise ValueError('boom')" in error
    assert "console.py" not in error


def test_a_cell_is_one_undo_step(window: tuple[binbun.Database, binbun.Server], console: Console) -> None:
    db, _ = window
    before = len(db.history)
    done = console.run("db.functions.set_name(0x1190, 'one')\ndb.functions.set_name(0x11b0, 'two')")
    assert done["error"] is None
    assert done["done"]["step"] == "Console: db.functions.set_name(0x1190, 'one')"
    assert len(db.history) == before + 1
    entry = db.history[0]
    assert (entry.label, entry.author.via, entry.edits) == (done["done"]["step"], "script:console", 2)
    assert (db.functions[0x1190].name, db.functions[0x11B0].name) == ("one", "two")
    # A transaction in a cell joins it: still one step, the cell's label.
    console.run("with db.transaction('mine'):\n    db.functions.set_name(0x1190, 'three')\ndb.functions.set_name(0x11b0, 'four')")
    assert len(db.history) == before + 2
    assert db.history[0].label.startswith("Console: with db.transaction") and db.history[0].edits == 2
    # A cell that writes nothing makes no step.
    assert console.run("len(db.functions)")["done"]["step"] is None
    assert len(db.history) == before + 2


def test_a_raising_cell_keeps_what_it_wrote_as_one_step(window: tuple[binbun.Database, binbun.Server], console: Console) -> None:
    db, _ = window
    before = len(db.history)
    done = console.run("db.functions.set_name(0x1190, 'kept')\nraise RuntimeError('after')\ndb.functions.set_name(0x11b0, 'never')")
    assert "RuntimeError: after" in done["error"]
    assert done["done"]["step"] == "Console: db.functions.set_name(0x1190, 'kept')"
    assert len(db.history) == before + 1 and db.history[0].edits == 1
    assert db.functions[0x1190].name == "kept" and db.functions[0x11B0].name == "fail"


def test_a_transaction_rolled_back_in_a_cell_takes_the_cells_writes_with_it(
    window: tuple[binbun.Database, binbun.Server], console: Console
) -> None:
    """As nested transactions do (the outer one is the cell's)."""
    db, _ = window
    before = len(db.history)
    done = console.run(
        "db.functions.set_name(0x1190, 'x')\nwith db.transaction('t'):\n    db.functions.set_name(0x11b0, 'y')\n    raise ValueError('no')\n"
    )
    assert "ValueError: no" in done["error"]
    assert done["done"]["step"] is None and "not kept" in done["done"]["note"]
    assert len(db.history) == before
    assert (db.functions[0x1190].name, db.functions[0x11B0].name) == ("classify", "fail")
    # The next cell writes as usual.
    assert console.run("db.functions.set_name(0x1190, 'later')")["done"]["step"] is not None


def test_the_magic_variables_follow_the_cursor(window: tuple[binbun.Database, binbun.Server], console: Console) -> None:
    db, server = window
    assert console.run("(here, current_function, selection)")["result"] == "(None, None, None)"
    server.cursor = 0x1200  # inside loop_sum
    server.selection = (0x1200, 0x1210)
    assert console.run("(hex(here), hex(current_function.entry), current_function.name, selection)")["result"] == (
        "('0x1200', '0x11f0', 'loop_sum', (4608, 4624))"
    )
    server.cursor = 0x1060
    server.selection = None
    assert console.run("(hex(here), current_function.name, selection)")["result"] == "('0x1060', 'main', None)"
    # current_function is the database's: renaming it renames it there.
    assert console.run("db.functions.set_name(current_function, 'entry_point')")["error"] is None
    assert db.functions[0x1060].name == "entry_point"
    # Setting db.cursor from the console moves the window's cursor.
    assert console.run("db.cursor = db.functions.get_by_name('loop_sum')")["error"] is None
    assert server.cursor == 0x11F0


@pytest.mark.parametrize("jedi", [pytest.param(True, id="jedi"), pytest.param(False, id="rlcompleter")])
def test_completions_and_signatures(window: tuple[binbun.Database, binbun.Server], tmp_path: Path, jedi: bool) -> None:
    if jedi and not HAS_JEDI:
        pytest.skip("jedi is not installed")
    console = start(window, tmp_path, *([] if jedi else ["--no-jedi"]))
    try:
        code = "db.functions.get_"
        asked = console.send({"op": "complete", "code": code, "cursor": len(code)})
        answer = console.expect(lambda e: e.get("id") == asked)[-1]
        names = [item["text"] for item in answer["items"]]
        assert answer["start"] == len("db.functions.")
        assert {"get_at", "get_by_name", "get_containing"} <= set(names), names
        assert all(name.startswith("get_") for name in names)
        # The namespace's own names complete too.
        console.run("my_variable = 1")
        asked = console.send({"op": "complete", "code": "my_v", "cursor": 4})
        assert [i["text"] for i in console.expect(lambda e: e.get("id") == asked)[-1]["items"]] == ["my_variable"]
        code = "db.functions.get_at("
        asked = console.send({"op": "signature", "code": code, "cursor": len(code)})
        sig = console.expect(lambda e: e.get("id") == asked)[-1]
        assert sig["label"].startswith("get_at(") and "ea" in sig["label"], sig
        first, end = sig["active"]
        assert sig["label"][first:end].startswith("ea")
        assert "holding" in sig["doc"]
        asked = console.send({"op": "signature", "code": "1 + 2", "cursor": 5})
        assert console.expect(lambda e: e.get("id") == asked)[-1]["label"] is None
    finally:
        console.close()


def interrupt(console: Console, how: str) -> None:
    """Ctrl+C as the GUI sends it: SIGINT (on Unix) or ``interrupt``."""
    if how == "signal":
        console.process.send_signal(signal.SIGINT)
    else:
        console.send({"op": "interrupt"})


# Windows sends another process no SIGINT (only CTRL_C_EVENT to a console
# process group): the GUI asks with ``interrupt`` there.
NO_SIGINT = pytest.mark.skipif(sys.platform == "win32", reason="no SIGINT to another process on Windows")


@pytest.mark.parametrize("how", [pytest.param("signal", marks=NO_SIGINT), "request"])
def test_ctrl_c_interrupts_the_cell_and_the_console_goes_on(console: Console, how: str) -> None:
    for code in ["while True: pass", "import time\ntime.sleep(60)"]:
        cell = console.send({"op": "run", "code": code})
        console.expect(lambda e: e["event"] == "started" and e["id"] == cell)
        time.sleep(0.2)
        began = time.monotonic()
        interrupt(console, how)
        events = console.expect(lambda e: e["event"] == "done" and e["id"] == cell, timeout=10)
        assert time.monotonic() - began < 5
        error = next(e["text"] for e in events if e["event"] == "error")
        assert error.rstrip().endswith("KeyboardInterrupt")
        assert "console.py" not in error
    # Idle, Ctrl+C is ignored.
    interrupt(console, how)
    assert console.run("1 + 1")["result"] == "2"


# A disposition inherited through exec (and `preexec_fn`) is POSIX's.
@NO_SIGINT
def test_ctrl_c_interrupts_a_console_started_with_sigint_ignored(
    window: tuple[binbun.Database, binbun.Server], tmp_path: Path
) -> None:
    """A GUI started in the background of a shell (`binbun bash &`)
    starts its children with SIGINT ignored, and Python keeps an ignored
    SIGINT ignored: the console takes SIGINT itself whatever it inherits."""
    console = start(window, tmp_path, preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
    try:
        # The console's own handler replaced the inherited SIG_IGN.
        assert console.run("import signal; signal.getsignal(signal.SIGINT) is signal.SIG_IGN")["result"] == "False"
        cell = console.send({"op": "run", "code": "while True: pass"})
        console.expect(lambda e: e["event"] == "started" and e["id"] == cell)
        time.sleep(0.2)
        console.process.send_signal(signal.SIGINT)
        events = console.expect(lambda e: e["event"] == "done" and e["id"] == cell, timeout=10)
        error = next(e["text"] for e in events if e["event"] == "error")
        assert error.rstrip().endswith("KeyboardInterrupt")
    finally:
        console.close()


def test_startup_runs_once_and_its_errors_are_shown(window: tuple[binbun.Database, binbun.Server], tmp_path: Path) -> None:
    startup = tmp_path / "config" / "binbun" / "startup.py"
    startup.parent.mkdir(parents=True)
    startup.write_text("GREETING = 'hello'\nprint('from startup')\n1 / 0\n")
    console = start(window, tmp_path / "config")
    try:
        events = console.expect(lambda e: e["event"] == "done" and e["id"] is None)
        assert any(e["event"] == "note" and str(startup) in e["text"] for e in events)
        assert any(e["event"] == "output" and e["text"] == "from startup\n" for e in events)
        error = next(e["text"] for e in events if e["event"] == "error")
        assert "ZeroDivisionError" in error and str(startup) in error
        assert console.run("GREETING")["result"] == "'hello'"
    finally:
        console.close()


def test_a_console_that_cannot_connect_says_why(window: tuple[binbun.Database, binbun.Server], tmp_path: Path) -> None:
    db, _ = window
    process = subprocess.run(
        [sys.executable, "-m", "binbun.console", "--socket", str(tmp_path / "none.sock"), "--database", db.path],
        input="",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert process.returncode == 1
    failed = json.loads(process.stdout.splitlines()[-1])
    assert failed["event"] == "failed" and failed["message"]
