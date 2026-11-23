"""``python -m binbun.console``: the GUI's console, a Python REPL in the
user's own interpreter, connected to the GUI's database
(``binbun.connect(socket=..., label="console")``).

The GUI starts it with the interpreter of its ``python.interpreter``
setting and talks to it in lines of JSON: requests on its standard input,
replies and events on its standard output. What the user's code prints
(``print``, ``sys.stderr``, and what C code and child processes write to
file descriptors 1 and 2) comes back as ``output`` events; the user's code
never sees the channel, and reads an empty standard input.

Requests (``id`` an integer chosen by the GUI)::

    {"op": "run", "id": 1, "code": "db.functions.get_at(here)"}
    {"op": "complete", "id": 2, "code": "db.fun", "cursor": 6}
    {"op": "signature", "id": 3, "code": "db.functions.get_at(", "cursor": 20}
    {"op": "interrupt"}

``cursor`` and every offset sent back count code points of ``code``.
Events::

    {"event": "ready", "protocol": 1, "python": "3.14.0", "completer": "jedi",
     "database": "bash", "path": "/usr/bin/bash"}
    {"event": "failed", "message": "..."}          (then the console exits)
    {"event": "incomplete", "id": 1}               (the cell needs more lines)
    {"event": "accepted", "id": 1}                 (it runs once the cells before it ran)
    {"event": "started", "id": 1}
    {"event": "output", "stream": "stdout", "text": "..."}
    {"event": "result", "id": 1, "text": "<repr>"}
    {"event": "error", "id": 1, "text": "Traceback ..."}
    {"event": "done", "id": 1, "step": "Console: ...", "note": null}
    {"event": "note", "text": "..."}
    {"event": "completions", "id": 2, "start": 3, "items": [{"text": "functions", "kind": "instance"}]}
    {"event": "signature", "id": 3, "label": "get_at(ea: int)", "active": [7, 14], "doc": "..."}

A cell is one undo step in the GUI, labelled ``Console: <its first
line>``: its writes (and the transactions it begins, which join it) are
committed when it ends, also when it raises, so that what ran before the
exception stays, and one Ctrl+Z removes it. A transaction rolled back
inside a cell rolls the cell's writes back with it (nested transactions
do). Before each cell ``here`` (the GUI's cursor), ``current_function``
(the function holding it) and ``selection`` (``(start, end)``) are read
from the GUI; ``db`` is the database. ``startup.py`` in binbun's config
folder (``binbun paths config``) runs once at start, in the same
namespace.

``interrupt`` (or SIGINT to the process) raises ``KeyboardInterrupt`` in
the cell running; a console waiting for its next cell ignores it.

``--agent`` is the interpreter of ``binbun mcp``'s ``python`` and ``api``
tools. It opens the GUI's binary in this process following the GUI
(``binbun.connect(mode="local")``, so every read of ``binbun.Database``
works; writes are made in the GUI), or, with ``--open FILE`` and no GUI,
``binbun.open(FILE)``. ``startup.py`` is not run. It connects as the
agent ``--agent-name`` (``Codex``; ``--agent-version``): a participant
with its own identity, shown in the window while connected, its writes
applied and attributed to it, its cursor where its code works (the
address the cell last named or worked on, told every
:data:`PRESENCE_SECONDS` while a cell runs). ``binbun.connect(...)`` in a
cell connects as the same agent, the binary opened here, and makes the
database connected ``db``. Its requests::

    {"op": "run", "id": 1, "code": "...", "intent": "Name the parser", "max_chars": 20000}
    {"op": "doc", "id": 2, "query": "Function.decompile", "detail": "signatures"}
    {"op": "interrupt"}

A cell's output is not sent as it is printed: ``progress`` events say its
last line (at most one a second), and ``done`` carries the whole cell::

    {"event": "progress", "id": 1, "line": "..."}
    {"event": "done", "id": 1, "cell": 7, "ok": true, "output": "...",
     "truncated": false, "chars": 120, "result": "<repr>", "error": null,
     "step": "Codex: Name the parser", "edits": 1, "note": null,
     "database": "bash"}
    {"event": "doc", "id": 2, "text": "..."}

Past ``max_chars`` the output keeps its first 60% and last 40% around a
marker naming ``Out[7]``, which keeps the whole output (a ``str``; its
``.result`` the value of the cell's last expression). Tracebacks show the
cell's frames as ``<cell 7>``. A cell's undo step is labelled with the
agent's name and its intent (else its first line): ``Codex: Name the
parser``.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import codecs
import codeop
import functools
import importlib
import inspect
import io
import json
import linecache
import os
import queue
import re
import rlcompleter
import signal
import sys
import threading
import time
import traceback
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

PROTOCOL = 1
"""The version of the console's protocol with the GUI."""

LABEL_WIDTH = 48
"""The most characters of a cell's first line in its undo step's label."""

RESULT_LIMIT = 200_000
"""The most characters of a result's ``repr`` sent."""

COMPLETIONS_LIMIT = 200
"""The most completions sent."""

OUTPUT_CHARS = 20_000
"""``--agent``: the most characters of a cell's output sent, unless the
request asks otherwise."""

ERROR_CHARS = 10_000
"""``--agent``: the most characters of a traceback sent."""

KEPT_CHARS = 64_000_000
"""``--agent``: the most characters of a cell's output kept in ``Out``
from its start; past it, its last :data:`TAIL_CHARS` are kept too."""

TAIL_CHARS = 1_000_000

AGENT = "Agent"
"""``--agent``: the agent's name when ``--agent-name`` gives none."""

PRESENCE_SECONDS = 0.25
"""``--agent``: how often where the agent's code works is told to the GUI
while a cell runs (its cursor there)."""

_FLUSH_SECONDS = 0.03
_FLUSH_BYTES = 1 << 16


def label(code: str) -> str:
    """The undo step's label of cell ``code``: ``Console:`` and its first
    line that is not empty, cut to :data:`LABEL_WIDTH` characters."""
    first = next((line.strip() for line in code.splitlines() if line.strip()), "")
    if len(first) > LABEL_WIDTH:
        first = first[: LABEL_WIDTH - 1] + "\u2026"
    return f"Console: {first}"


def agent_label(code: str, intent: str | None, agent: str = AGENT) -> str:
    """``--agent``'s undo step label of cell ``code``: the agent's name
    (``Codex:``) and ``intent``, else the cell's first line that is not
    empty, cut to :data:`LABEL_WIDTH` characters."""
    text = " ".join((intent or "").split())
    if not text:
        text = next((line.strip() for line in code.splitlines() if line.strip()), "")
    if len(text) > LABEL_WIDTH:
        text = text[: LABEL_WIDTH - 1] + "\u2026"
    return f"{agent}: {text}"


def cut(text: str, limit: int, whole: str) -> tuple[str, bool]:
    """``text`` within ``limit`` characters: its first 60% and last 40%
    around a marker saying how much was cut and that ``whole`` has it
    all; whether it was cut."""
    if len(text) <= limit:
        return text, False
    head = limit * 3 // 5
    tail = limit - head
    gone = len(text) - head - tail
    return f"{text[:head]}\n[\u2026 {gone:,} characters cut; {whole} \u2026]\n{text[len(text) - tail :]}", True


class CellOutput(str):
    """``Out[n]``: what cell ``n`` printed, whole; ``.result``: the value
    of its last expression (``None`` if it had none)."""

    result: Any

    def __new__(cls, text: str, result: Any = None) -> CellOutput:
        made = super().__new__(cls, text)
        made.result = result
        return made


def is_complete(code: str) -> bool:
    """Whether Enter runs ``code`` (else it breaks the line): it compiles
    (or is wrong beyond more lines fixing it), and a block it ends in is
    closed by an empty last line."""
    try:
        compiled = codeop.compile_command(code, "<console>", "exec")
    except (SyntaxError, ValueError, OverflowError):
        return True
    if compiled is None:
        return False
    lines = code.split("\n")
    last = lines[-1]
    if not last.strip():
        return True
    return len(lines) == 1 or not last[:1].isspace()


def startup_path() -> Path | None:
    """``startup.py`` in binbun's config folder (``binbun paths config``),
    if it has one."""
    from binbun import _native

    path = _native._startup_path()
    return None if path is None else Path(path)


class Channel:
    """The GUI's side: events written as lines of JSON, output gathered
    and sent in order before the next event."""

    def __init__(self, fd: int) -> None:
        self._file = os.fdopen(fd, "w", encoding="utf-8", newline="\n", closefd=True)
        self._lock = threading.Lock()
        self._pending: list[tuple[str, str]] = []
        self._size = 0

    def output(self, stream: str, text: str) -> None:
        """Gathers ``text`` written to ``stream`` (``stdout``,
        ``stderr``)."""
        if not text:
            return
        with self._lock:
            if self._pending and self._pending[-1][0] == stream:
                self._pending[-1] = (stream, self._pending[-1][1] + text)
            else:
                self._pending.append((stream, text))
            self._size += len(text)
            if self._size >= _FLUSH_BYTES:
                self._flush()

    def send(self, event: dict[str, Any]) -> None:
        """Sends ``event``, the output gathered before it first."""
        with self._lock:
            self._flush()
            self._write(event)

    def flush(self) -> None:
        """Sends the output gathered."""
        with self._lock:
            self._flush()

    def _flush(self) -> None:
        pending, self._pending, self._size = self._pending, [], 0
        for stream, text in pending:
            self._write({"event": "output", "stream": stream, "text": text})

    def _write(self, event: dict[str, Any]) -> None:
        try:
            self._file.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._file.flush()
        except (OSError, ValueError):
            pass  # The GUI is gone; the reader sees its end.


class AgentChannel(Channel):
    """``--agent``'s channel: a cell's output kept for its ``done``
    (:meth:`take`), its last line sent in a ``progress`` event at most
    once a second while it runs."""

    def __init__(self, fd: int) -> None:
        super().__init__(fd)
        self._parts: list[str] = []
        self._kept = 0
        self._tail = ""
        self._dropped = 0
        self._cell: Any = None
        self._said = 0.0
        # The line being written, and the last one written whole.
        self._partial = ""
        self._line = ""

    def output(self, stream: str, text: str) -> None:
        if not text:
            return
        with self._lock:
            if self._kept < KEPT_CHARS:
                self._parts.append(text)
                self._kept += len(text)
            else:
                self._tail += text
                if len(self._tail) > 2 * TAIL_CHARS:
                    self._dropped += len(self._tail) - TAIL_CHARS
                    self._tail = self._tail[-TAIL_CHARS:]
            *whole, partial = (self._partial + text).split("\n")
            self._partial = partial[-200:]
            self._line = next((line for line in reversed(whole) if line.strip()), self._line)[:200]
            now = time.monotonic()
            if self._cell is not None and self._line and now - self._said >= 1.0:
                self._said = now
                self._write({"event": "progress", "id": self._cell, "line": self._line})

    def begin(self, cell: Any) -> None:
        """Cell ``cell`` starts: its output gathered from now on."""
        with self._lock:
            self._parts, self._kept, self._tail, self._dropped = [], 0, "", 0
            self._partial, self._line = "", ""
            self._cell = cell
            self._said = time.monotonic()

    def take(self) -> str:
        """The output gathered since :meth:`begin`, whole (past
        :data:`KEPT_CHARS`, its start and its end with what was not kept
        said between them)."""
        with self._lock:
            text = "".join(self._parts)
            if self._tail:
                dropped = self._dropped + max(0, len(self._tail) - TAIL_CHARS)
                tail = self._tail[-TAIL_CHARS:]
                text += f"\n[\u2026 {dropped:,} characters not kept \u2026]\n{tail}" if dropped else tail
            self._parts, self._kept, self._tail, self._dropped = [], 0, "", 0
            self._cell = None
            return text


class Stream(io.TextIOBase):
    """``sys.stdout`` or ``sys.stderr``: what is written goes to the GUI."""

    encoding = "utf-8"

    def __init__(self, channel: Channel, name: str, fd: int) -> None:
        super().__init__()
        self._channel = channel
        self._name = name
        self._fd = fd

    def writable(self) -> bool:
        return True

    def isatty(self) -> bool:
        return False

    def fileno(self) -> int:
        return self._fd

    def write(self, text: str) -> int:
        self._channel.output(self._name, str(text))
        return len(text)

    def flush(self) -> None:
        self._channel.flush()


def _quiet_thread(target: Callable[[], None], name: str) -> threading.Thread:
    """A daemon thread running ``target`` with SIGINT blocked, so that the
    signal reaches the main thread (where the cell runs). Windows has no
    signal masks: there, Python runs the handler in the main thread only."""

    def run() -> None:
        if sys.platform != "win32":
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        target()

    thread = threading.Thread(target=run, name=name, daemon=True)
    thread.start()
    return thread


class Pipe:
    """What is written to file descriptor ``fd`` (1 or 2) of this process,
    sent to the GUI as ``stream``'s output; :meth:`sync` waits until what
    was written before it is sent, so that it comes before a cell's
    end."""

    _MARK = b"\x00binbun-console-sync\x00"

    def __init__(self, fd: int, channel: Channel, stream: str) -> None:
        self._fd = fd
        read, write = os.pipe()
        os.dup2(write, fd)
        os.close(write)
        self._read = read
        self._channel = channel
        self._stream = stream
        self._marks = threading.Condition()
        self._asked = 0
        self._seen = 0
        _quiet_thread(self._forward, f"binbun-console-{stream}")

    def sync(self, timeout: float = 1.0) -> None:
        """Returns once what was written so far is sent (or after
        ``timeout`` seconds)."""
        with self._marks:
            self._asked += 1
            asked = self._asked
        try:
            os.write(self._fd, self._MARK)
        except OSError:
            return
        with self._marks:
            self._marks.wait_for(lambda: self._seen >= asked, timeout)

    def _forward(self) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        held = b""
        while True:
            try:
                data = os.read(self._read, 1 << 16)
            except OSError:
                data = b""
            if not data:
                self._channel.output(self._stream, decoder.decode(held, final=True))
                return
            held += data
            while (found := held.find(self._MARK)) >= 0:
                self._channel.output(self._stream, decoder.decode(held[:found]))
                held = held[found + len(self._MARK) :]
                with self._marks:
                    self._seen += 1
                    self._marks.notify_all()
            # A mark's start may end the read: kept for the next.
            keep = next(
                (n for n in range(len(self._MARK) - 1, 0, -1) if held.endswith(self._MARK[:n])),
                0,
            )
            self._channel.output(self._stream, decoder.decode(held[: len(held) - keep]))
            held = held[len(held) - keep :]


def _trimmed(error: BaseException) -> str:
    """``error``'s traceback without the console's own frames (the cell's
    caller above, the Ctrl+C handler below)."""
    shown = traceback.TracebackException.from_exception(error)
    shown.stack = traceback.StackSummary.from_list(
        [frame for frame in shown.stack if frame.filename != __file__]
    )
    return "".join(shown.format())


def _position(code: str, cursor: int) -> tuple[int, int]:
    """Code point ``cursor`` of ``code`` as jedi's line (from 1) and
    column."""
    before = code[:cursor]
    line = before.count("\n") + 1
    return line, len(before) - (before.rfind("\n") + 1)


class Console:
    """The namespace cells run in, and the answers about its code."""

    def __init__(
        self,
        db: Any,
        channel: Channel,
        *,
        use_jedi: bool = True,
        connection: Any = None,
    ) -> None:
        self.db = db
        self.channel = channel
        # The GUI's connection, if any: cells' undo steps, the cursor.
        self.connection = connection if connection is not None else getattr(db, "_connection", None)
        self.namespace: dict[str, Any] = {
            "__name__": "__console__",
            "__builtins__": builtins,
            "binbun": importlib.import_module("binbun"),
            "db": db,
            "here": None,
            "current_function": None,
            "selection": None,
        }
        self.jedi: Any = None
        if use_jedi:
            try:
                self.jedi = importlib.import_module("jedi")
            except ImportError:
                self.jedi = None
            else:
                # Completing never runs the user's properties (a socket
                # round trip each, or worse).
                self.jedi.settings.allow_unsafe_interpreter_executions = False
        self.running = False
        self._cells = 0
        self._agent_cells = 0
        # `--agent`: the agent's name (its undo steps' labels).
        self.agent_name = AGENT
        # `--agent`: cells run as sent (never "incomplete"), `run_agent`.
        self.agent = isinstance(channel, AgentChannel)
        self.pipes: list[Pipe] = []

    @property
    def completer(self) -> str:
        """``jedi`` or ``rlcompleter``."""
        return "rlcompleter" if self.jedi is None else "jedi"

    # ---- cells ----

    def refresh(self) -> None:
        """``here``, ``current_function`` and ``selection`` read from the
        GUI (``None`` where it shows nothing)."""
        ns = self.namespace
        connection = self.connection
        if connection is None:
            return
        here = _ask(lambda: _address(connection.call("ui.cursor", {})["address"]))
        ns["here"] = here
        ns["current_function"] = None if here is None else _ask(lambda: self.db.functions.get_at(here))
        ns["selection"] = _ask(lambda: _span(connection.call("ui.selection")))

    def run(self, code: str, cell: int | None, *, filename: str | None = None) -> None:
        """Runs ``code`` as cell ``cell`` (one undo step), its result's
        ``repr`` and its error sent; then ``done``."""
        self._cells += 1
        if filename is None:
            filename = f"<console#{self._cells}>"
            linecache.cache[filename] = (len(code), None, code.splitlines(True), filename)
        step_label = label(code) if cell is not None else "Console: startup.py"
        connection = self.connection
        if connection is not None:
            connection.cell(step_label)
        self.refresh()
        value: Any = None
        failed: BaseException | None = None
        self.running = True
        self.channel.send({"event": "started", "id": cell})
        try:
            body, last = _split(code, filename)
            if body is not None:
                exec(body, self.namespace)
            if last is not None:
                value = eval(last, self.namespace)
        except BaseException as error:  # noqa: BLE001 - shown, the console goes on
            failed = error
        finally:
            self.running = False
        for pipe in self.pipes:
            pipe.sync()
        if failed is not None:
            self.channel.send({"event": "error", "id": cell, "text": _trimmed(failed)})
        elif value is not None:
            self.namespace["_"] = value
            self.channel.send({"event": "result", "id": cell, "text": _repr(value)})
        entry, note = self._commit(connection, interrupted=isinstance(failed, KeyboardInterrupt))
        step = None if entry is None else str(entry.label)
        self.channel.send({"event": "done", "id": cell, "step": step, "note": note})

    def run_agent(self, request: dict[str, Any]) -> None:
        """``--agent``: runs ``request``'s code as the next cell, its
        output kept whole in ``Out[n]`` and sent cut to its ``max_chars``
        with its result and error in ``done``."""
        code = str(request.get("code", ""))
        cell_id = request.get("id")
        try:
            limit = max(1, int(request.get("max_chars") or OUTPUT_CHARS))
        except (TypeError, ValueError):
            limit = OUTPUT_CHARS
        self._agent_cells += 1
        n = self._agent_cells
        filename = f"<cell {n}>"
        linecache.cache[filename] = (len(code), None, code.splitlines(True), filename)
        connection = self.connection
        if connection is not None:
            connection.cell(agent_label(code, request.get("intent"), self.agent_name))
        before = None if connection is not None else _ask(lambda: self.db.revision.edits)
        self.refresh()
        channel = self.channel
        assert isinstance(channel, AgentChannel)
        channel.begin(cell_id)
        value: Any = None
        failed: BaseException | None = None
        self.running = True
        channel.send({"event": "started", "id": cell_id})
        try:
            body, last = _split(code, filename)
            if body is not None:
                exec(body, self.namespace)
            if last is not None:
                value = eval(last, self.namespace)
        except BaseException as error:  # noqa: BLE001 - said, the interpreter goes on
            failed = error
        finally:
            self.running = False
        for pipe in self.pipes:
            pipe.sync()
        output = channel.take()
        out = self.namespace.setdefault("Out", {})
        if isinstance(out, dict):
            out[n] = CellOutput(output, value)
        if value is not None:
            self.namespace["_"] = value
        # A `binbun.connect(...)` in the cell made another database `db`.
        connection = self.connection
        self.tell_presence()
        entry, note = self._commit(connection, interrupted=isinstance(failed, KeyboardInterrupt))
        if connection is not None:
            edits = 0 if entry is None else int(entry.edits)
        else:
            after = _ask(lambda: self.db.revision.edits)
            edits = after - before if isinstance(before, int) and isinstance(after, int) else 0
        shown, truncated = cut(output, limit, f"the whole output is Out[{n}]")
        result = None
        if failed is None and value is not None:
            result, _ = cut(_repr(value), limit, f"the whole value is Out[{n}].result")
        traceback_text = None if failed is None else cut(_trimmed(failed), ERROR_CHARS, "the traceback's middle")[0]
        channel.send(
            {
                "event": "done",
                "id": cell_id,
                "cell": n,
                "ok": failed is None,
                "output": shown,
                "truncated": truncated,
                "chars": len(output),
                "result": result,
                "error": traceback_text,
                "interrupted": isinstance(failed, KeyboardInterrupt),
                "step": None if entry is None else str(entry.label),
                "edits": edits,
                "note": note,
                "database": getattr(self.db, "name", ""),
            }
        )

    def adopt(self, connection: Any, db: Any) -> None:
        """``--agent``: ``db`` (connected by ``binbun.connect()`` in a cell)
        is ``db`` from now on: the cell's writes go on its connection, the
        one before committed and closed."""
        old = self.connection
        if old is connection:
            return
        label = None if old is None else old.label
        if old is not None:
            self._commit(old, interrupted=False)
        previous = self.db
        self.db = db
        self.connection = connection
        self.namespace["db"] = db
        if label is not None:
            connection.cell(label)
        if previous is not db:
            for close in (getattr(previous, "close", None), getattr(old, "close", None)):
                if close is not None:
                    try:
                        close()
                    except Exception:  # noqa: BLE001 - the GUI may be gone
                        pass
        self.refresh()

    def tell_presence(self) -> None:
        """``--agent``: tells the GUI where the agent's code worked last
        (an address it named or a function it used), if anywhere since
        last told: its cursor there."""
        connection = self.connection
        presence = getattr(connection, "presence", None)
        if presence is None:
            return
        from binbun import _native

        address = _native._touched()
        if address is None:
            return
        try:
            presence(address)
        except Exception:  # noqa: BLE001 - presence is best effort
            pass

    def doc(self, request: dict[str, Any]) -> None:
        """``--agent``: answers ``request`` (the ``api`` tool) from the
        installed package."""
        from binbun import _digest

        try:
            text = _digest.describe(
                str(request.get("query") or ""), str(request.get("detail") or "signatures"), self.namespace
            )
        except Exception as error:  # noqa: BLE001 - said, not raised
            text = f"The API could not be described: {type(error).__name__}: {error}"
        self.channel.send({"event": "doc", "id": request.get("id"), "text": text})

    def _commit(self, connection: Any, *, interrupted: bool) -> tuple[Any, str | None]:
        """The cell's writes committed: the change made (a
        ``HistoryEntry``), or why there is none."""
        if connection is None:
            return None, None
        try:
            entry = connection.finish()
        except Exception as error:  # noqa: BLE001 - said, not raised
            return None, f"The cell's writes were not kept: {error}"
        if entry is None and interrupted:
            # Ctrl+C may have stopped the wait for a group's opening the
            # server had already made: it is committed, if so.
            try:
                entry, _ = connection.commit()
            except Exception:  # noqa: BLE001 - none was open
                entry = None
        return entry, None

    def startup(self, path: Path | None) -> None:
        """Runs ``path`` (``startup.py``) once, if it is there: its errors
        shown, never fatal."""
        if path is None or not path.is_file():
            return
        try:
            code = path.read_text(encoding="utf-8")
        except OSError as error:
            self.channel.send({"event": "note", "text": f"{path}: {error}"})
            return
        self.channel.send({"event": "note", "text": f"Running {path}"})
        self.run(code, None, filename=str(path))

    # ---- completions and signatures ----

    def complete(self, code: str, cursor: int) -> tuple[int, list[dict[str, str]]]:
        """The completions of the name before code point ``cursor``: where
        the text they replace starts, and each one's text and kind."""
        if self.jedi is not None:
            return self._jedi_complete(code, cursor)
        return self._rl_complete(code, cursor)

    def _jedi_complete(self, code: str, cursor: int) -> tuple[int, list[dict[str, str]]]:
        line, column = _position(code, cursor)
        completions = self.jedi.Interpreter(code, [self.namespace]).complete(line, column)
        if not completions:
            return cursor, []
        typed = completions[0].get_completion_prefix_length()
        prefix = code[cursor - typed : cursor]
        items = [
            {"text": str(c.name_with_symbols), "kind": str(c.type)}
            for c in completions
            if prefix.startswith("_") or not str(c.name).startswith("_")
        ]
        return cursor - typed, items[:COMPLETIONS_LIMIT]

    def _rl_complete(self, code: str, cursor: int) -> tuple[int, list[dict[str, str]]]:
        found = re.search(r"[A-Za-z_][\w.]*$|\.$", code[:cursor])
        if found is None:
            return cursor, []
        word = found.group()
        completer = rlcompleter.Completer(self.namespace)
        typed = len(word) - (word.rfind(".") + 1)
        prefix = word[len(word) - typed :]
        items: list[dict[str, str]] = []
        seen: set[str] = set()
        for match in _matches(completer, word):
            callable_ = match.endswith("(")
            name = match.rstrip("(").rsplit(".", 1)[-1]
            if name in seen or (name.startswith("_") and not prefix.startswith("_")):
                continue
            seen.add(name)
            items.append({"text": name, "kind": "function" if callable_ else "instance"})
            if len(items) >= COMPLETIONS_LIMIT:
                break
        return cursor - typed, items

    def signature(self, code: str, cursor: int) -> dict[str, Any] | None:
        """The signature of the call the cursor is in: its text, the
        active parameter's range in it, the first line of its docstring."""
        if self.jedi is not None:
            line, column = _position(code, cursor)
            signatures = self.jedi.Interpreter(code, [self.namespace]).get_signatures(line, column)
            if not signatures:
                return None
            sig = signatures[0]
            text = str(sig.to_string())
            params = [str(p.to_string()) for p in sig.params]
            doc = str(sig.docstring(raw=True)).strip().split("\n\n")[0].replace("\n", " ")
            return {"label": text, "active": _active(text, params, sig.index), "doc": doc}
        return self._inspect_signature(code, cursor)

    def _inspect_signature(self, code: str, cursor: int) -> dict[str, Any] | None:
        call = _open_call(code[:cursor])
        if call is None:
            return None
        name, index = call
        target: Any = self.namespace.get(name.split(".")[0], getattr(builtins, name.split(".")[0], None))
        try:
            for part in name.split(".")[1:]:
                target = inspect.getattr_static(target, part)
                if isinstance(target, (staticmethod, classmethod)):
                    target = target.__func__
            sig = inspect.signature(target)
        except (AttributeError, TypeError, ValueError):
            return None
        parameters = [p for p in sig.parameters.values() if p.name != "self"]
        text = f"{name.rsplit('.', 1)[-1]}({', '.join(str(p) for p in parameters)})"
        doc = (inspect.getdoc(target) or "").split("\n\n")[0].replace("\n", " ")
        return {"label": text, "active": _active(text, [str(p) for p in parameters], index), "doc": doc}


def _ask(read: Callable[[], Any]) -> Any:
    """``read()``, or ``None`` if the GUI cannot say (no window, no
    cursor)."""
    try:
        return read()
    except Exception:  # noqa: BLE001 - nothing to show
        return None


def _address(text: str | None) -> int | None:
    """An address as the protocol sends it (``"0x…"``)."""
    return None if text is None else int(text, 16)


def _span(span: dict[str, str] | None) -> tuple[int, int] | None:
    """A selection as the protocol sends it."""
    return None if span is None else (int(span["start"], 16), int(span["end"], 16))


def _matches(completer: rlcompleter.Completer, word: str) -> Iterator[str]:
    state = 0
    while True:
        try:
            match = completer.complete(word, state)
        except Exception:  # noqa: BLE001 - an attribute that raises
            return
        if match is None:
            return
        yield match
        state += 1


def _split(code: str, filename: str) -> tuple[types.CodeType | None, types.CodeType | None]:
    """``code`` compiled: its statements, and its last if it is an
    expression (whose value is shown) apart."""
    tree = ast.parse(code, filename, "exec")
    last: types.CodeType | None = None
    if tree.body and isinstance(final := tree.body[-1], ast.Expr):
        tree.body.pop()
        last = compile(ast.Expression(final.value), filename, "eval")
    body = compile(tree, filename, "exec") if tree.body else None
    return body, last


def _repr(value: Any) -> str:
    """``repr(value)``, cut to :data:`RESULT_LIMIT` characters."""
    text = repr(value)
    if len(text) > RESULT_LIMIT:
        text = text[:RESULT_LIMIT] + f"\u2026 ({len(text) - RESULT_LIMIT:,} more characters)"
    return text


def _active(text: str, params: list[str], index: int | None) -> list[int] | None:
    """The range of parameter ``index`` (of ``params``, as written in
    ``text``) in ``text``."""
    if index is None or not 0 <= index < len(params):
        return None
    at = text.find("(") + 1
    for i, param in enumerate(params):
        found = text.find(param, at)
        if found < 0:
            return None
        if i == index:
            return [found, found + len(param)]
        at = found + len(param)
    return None


def _open_call(before: str) -> tuple[str, int] | None:
    """The dotted name called by the innermost call left open in
    ``before``, and how many of its arguments come before the cursor."""
    depth = 0
    commas = 0
    quote: str | None = None
    position = len(before)
    while position > 0:
        position -= 1
        ch = before[position]
        if quote is not None:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                if ch != "(":
                    return None
                name = re.search(r"[A-Za-z_][\w.]*$", before[:position])
                return None if name is None else (name.group(), commas)
            depth -= 1
        elif ch == "," and depth == 0:
            commas += 1
    return None


def _serve(
    console: Console,
    requests: Iterator[dict[str, Any]],
    cells: queue.Queue[dict[str, Any] | None],
    assists: queue.Queue[dict[str, Any] | None],
) -> None:
    """Takes the GUI's requests: cells to run queued for the main thread,
    completions and signatures queued for :func:`_assist`'s thread, the
    latest of each kind only."""
    main = threading.main_thread().ident
    for request in requests:
        op = request.get("op")
        if op == "run":
            code = str(request.get("code", ""))
            if not console.agent and not is_complete(code):
                console.channel.send({"event": "incomplete", "id": request.get("id")})
            else:
                console.channel.send({"event": "accepted", "id": request.get("id")})
                cells.put(request)
        elif op in ("complete", "signature"):
            assists.put(request)
        elif op == "doc":
            _quiet_thread(functools.partial(console.doc, request), "binbun-console-doc")
        elif op == "interrupt":
            _interrupt(console, main)
    assists.put(None)
    cells.put(None)
    _interrupt(console, main)


def _interrupt(console: Console, main: int | None) -> None:
    """SIGINT to the main thread (``KeyboardInterrupt`` in the cell
    running). Windows has no ``pthread_kill``: SIGINT is raised in this
    thread, its C handler wakes the main thread from the waits Python
    makes interruptible (``time.sleep``...), and Python runs the handler
    there."""
    if not console.running:
        return
    if sys.platform == "win32":
        signal.raise_signal(signal.SIGINT)
    elif main is not None:
        signal.pthread_kill(main, signal.SIGINT)
    else:
        import _thread

        _thread.interrupt_main()


def _assist(console: Console, assists: queue.Queue[dict[str, Any] | None]) -> None:
    """Answers completion and signature requests, skipping one when a
    newer of its kind waits."""
    if console.jedi is not None:
        try:  # The first answer loads jedi's caches: before it is asked.
            console.jedi.Interpreter("", [{}]).complete(1, 0)
        except Exception:  # noqa: BLE001 - warming only
            pass
    while True:
        request = assists.get()
        if request is None:
            return
        waiting = [request]
        while True:
            try:
                more = assists.get_nowait()
            except queue.Empty:
                break
            if more is None:
                return
            waiting.append(more)
        latest = {str(r.get("op")): r for r in waiting}
        for op, wanted in latest.items():
            _answer(console, op, wanted)


def _answer(console: Console, op: str, request: dict[str, Any]) -> None:
    code = str(request.get("code", ""))
    cursor = max(0, min(int(request.get("cursor", len(code))), len(code)))
    try:
        if op == "complete":
            start, items = console.complete(code, cursor)
            event: dict[str, Any] = {"event": "completions", "id": request.get("id"), "start": start, "items": items}
        else:
            event = {"event": "signature", "id": request.get("id"), **(console.signature(code, cursor) or {"label": None})}
    except Exception:  # noqa: BLE001 - the namespace changing under jedi, say
        event = (
            {"event": "completions", "id": request.get("id"), "start": cursor, "items": []}
            if op == "complete"
            else {"event": "signature", "id": request.get("id"), "label": None}
        )
    console.channel.send(event)


def _requests(fd: int) -> Iterator[dict[str, Any]]:
    with os.fdopen(fd, "r", encoding="utf-8", closefd=True) as lines:
        for line in lines:
            try:
                request = json.loads(line)
            except ValueError:
                continue
            if isinstance(request, dict):
                yield request


def _sigint(_signal: int, _frame: types.FrameType | None, console: Console) -> None:
    if console.running:
        raise KeyboardInterrupt


def _present(console: Console) -> None:
    """``--agent``: tells the GUI where the agent's code works while a cell
    runs, every :data:`PRESENCE_SECONDS`."""
    while True:
        time.sleep(PRESENCE_SECONDS)
        if console.running:
            console.tell_presence()


def main(argv: list[str] | None = None) -> int:
    """Runs the console until the GUI closes its standard input."""
    parser = argparse.ArgumentParser(
        prog="python -m binbun.console",
        description="binbun's console, run by the GUI: lines of JSON on stdin and stdout.",
    )
    parser.add_argument("--socket", help="the GUI's socket")
    parser.add_argument("--database", help="the path of the GUI's database")
    parser.add_argument("--no-jedi", action="store_true", help="complete with rlcompleter even if jedi is there")
    parser.add_argument("--no-startup", action="store_true", help="do not run startup.py")
    parser.add_argument(
        "--agent",
        action="store_true",
        help="binbun mcp's interpreter: the binary opened here following the GUI, cells' output cut and kept in Out",
    )
    parser.add_argument("--open", metavar="FILE", help="with --agent: FILE opened here, without a GUI")
    parser.add_argument("--agent-name", metavar="NAME", help=f"with --agent: the agent's name (default {AGENT})")
    parser.add_argument("--agent-version", metavar="VERSION", help="with --agent: the agent's version")
    args = parser.parse_args(argv)
    if args.open is not None and not args.agent:
        parser.error("--open needs --agent")
    agent_name = " ".join((args.agent_name or "").split()) or AGENT

    # The channel keeps the process's own stdin and stdout; the user's
    # code reads an empty stdin, and what it writes to fds 1 and 2 is
    # forwarded as output.
    channel = AgentChannel(os.dup(1)) if args.agent else Channel(os.dup(1))
    requests_fd = os.dup(0)
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    if sys.platform != "win32":
        # Threads started from here (the forwarders, the connection's)
        # never take SIGINT: it lands in the main thread, in the cell.
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    pipes = [Pipe(1, channel, "stdout"), Pipe(2, channel, "stderr")]
    sys.stdin = open(os.devnull, encoding="utf-8")  # noqa: SIM115 - for the process's life
    sys.stdout = Stream(channel, "stdout", 1)
    sys.stderr = Stream(channel, "stderr", 2)

    import binbun

    connection: Any = None
    db: Any
    try:
        if args.open is not None:
            db = binbun.open(args.open, wait=binbun.Stage.ANALYSED)
        elif args.agent:
            from binbun._remote import _follower

            connection = binbun.Connection(
                args.database,
                socket=args.socket,
                label=agent_name,
                agent=agent_name,
                agent_version=args.agent_version,
            )
            db = _follower(connection)
        else:
            db = binbun.connect(args.database, socket=args.socket, label="console", author="script:console")
    except Exception as error:  # noqa: BLE001 - said to the GUI
        channel.send({"event": "failed", "message": f"{type(error).__name__}: {error}"})
        return 1
    finally:
        if sys.platform != "win32":
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    console = Console(db, channel, use_jedi=not args.no_jedi and not args.agent, connection=connection)
    console.pipes = pipes
    console.agent_name = agent_name
    if args.agent:
        console.namespace["Out"] = {}
    if connection is not None and args.agent:
        from binbun import _remote

        # `binbun.connect(...)` in a cell: as this agent, the binary opened
        # here, the database it connects becoming `db`.
        _remote._agent_defaults = _remote._AgentDefaults(
            agent=agent_name, version=args.agent_version, adopt=console.adopt
        )
        _quiet_thread(lambda: _present(console), "binbun-console-presence")
    # Installed whatever SIGINT was on entry: a GUI started in a shell's
    # background (`binbun bash &`) starts this process with SIGINT
    # ignored, which Python would otherwise keep (Ctrl+C would do nothing).
    signal.signal(signal.SIGINT, lambda number, frame: _sigint(number, frame, console))
    channel.send(
        {
            "event": "ready",
            "protocol": PROTOCOL,
            "python": ".".join(map(str, sys.version_info[:3])),
            "completer": console.completer,
            "database": getattr(db, "name", ""),
            "path": getattr(db, "path", ""),
            **({"mode": "file" if args.open is not None else "gui"} if args.agent else {}),
        }
    )
    cells: queue.Queue[dict[str, Any] | None] = queue.Queue()
    assists: queue.Queue[dict[str, Any] | None] = queue.Queue()
    assist = _quiet_thread(lambda: _assist(console, assists), "binbun-console-assist")
    _quiet_thread(lambda: _serve(console, _requests(requests_fd), cells, assists), "binbun-console-requests")
    if not args.no_startup and not args.agent:
        console.startup(startup_path())
    while True:
        try:
            request = cells.get()
        except KeyboardInterrupt:
            continue
        if request is None:
            break
        if args.agent:
            console.run_agent(request)
        else:
            console.run(str(request.get("code", "")), request.get("id"))
    channel.flush()
    # jedi's first answer writes its parse caches (a pickle a file, written
    # in place): a daemon thread ended in the middle of one leaves it cut
    # short, and every console after fails to complete until the file's
    # source changes. The assist thread ends once what it was doing is done.
    assist.join()
    # The database the agent switched to last, if it did.
    db, connection = console.db, console.connection if connection is not None else None
    try:
        db.close()
    except Exception:  # noqa: BLE001 - the GUI is gone
        pass
    if connection is not None:
        try:
            connection.close()
        except Exception:  # noqa: BLE001 - the GUI is gone
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
