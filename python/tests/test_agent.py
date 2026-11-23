"""``binbun mcp``'s interpreter and tools: ``python -m binbun.console
--agent`` (cells' output cut with a marker and kept whole in ``Out``, a
cell's writes one undo step labelled with the agent and its intent and
signed by the agent's own key, its cursor where its code works, Ctrl+C,
the ``doc`` request, ``--open FILE`` without a window); an agent connected
with ``binbun.connect(agent=...)`` among ``db.session.members``; the
binary chosen by its file name, or none named among several; the ``api``
tool's digest
(every name it mentions exists, every collection of ``db`` appears) and
its lookups; and ``binbun mcp`` itself spoken to as an MCP host does (a
probe before ``initialize`` refused, two tools, a cell run, a stuck cell
killed and the interpreter restarted on cancel)."""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import binbun
from binbun import _digest
from conftest import FIXTURE, cli_path


class Process:
    """A process spoken to in lines of JSON, and what it said."""

    def __init__(self, command: list[str], env: dict[str, str] | None = None) -> None:
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            env=env,
        )
        self.lines: queue.Queue[dict[str, Any]] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.lines.put(json.loads(line))

    def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def expect(self, wanted: Callable[[dict[str, Any]], bool], timeout: float = 120.0) -> list[dict[str, Any]]:
        """What it said up to the first ``wanted``, it included."""
        seen = []
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            assert left > 0, f"never came; saw {seen}"
            line = self.lines.get(timeout=left)
            seen.append(line)
            if wanted(line):
                return seen

    def close(self) -> None:
        if self.process.poll() is None:
            assert self.process.stdin is not None
            self.process.stdin.close()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


class Agent(Process):
    """``python -m binbun.console --agent``."""

    def __init__(self, *args: str) -> None:
        super().__init__([sys.executable, "-m", "binbun.console", "--agent", *args])
        self.next = 0
        ready = self.expect(lambda e: e["event"] in ("ready", "failed"))[-1]
        assert ready["event"] == "ready", ready

    def request(self, op: str, **fields: Any) -> int:
        self.next += 1
        self.send({"op": op, "id": self.next, **fields})
        return self.next

    def run(self, code: str, **fields: Any) -> dict[str, Any]:
        cell = self.request("run", code=code, **fields)
        return self.expect(lambda e: e["event"] == "done" and e["id"] == cell)[-1]


@pytest.fixture()
def window(tmp_path: Path) -> Iterator[tuple[binbun.Database, binbun.Server]]:
    """The fixture with a project of its own, served as a window."""
    with binbun.open(FIXTURE, project=tmp_path / "project", debug="none") as db:
        db.wait(binbun.Stage.CALLERS)
        with db.serve(ui=True) as server:
            yield db, server


@pytest.fixture()
def agent(window: tuple[binbun.Database, binbun.Server]) -> Iterator[Agent]:
    db, server = window
    started = Agent("--socket", server.socket, "--database", db.path, "--agent-name", "Codex")
    yield started
    started.close()


def test_a_cell_reads_the_whole_database_and_its_value_shows(agent: Agent) -> None:
    done = agent.run("f = db.functions.get_by_name('classify')\nprint(f.callers())\nf.decompile().text")
    assert done["ok"] and done["cell"] == 1 and not done["truncated"]
    assert "classify" in done["result"]
    # A block's last line indented: run as sent, never "incomplete".
    assert agent.run("for i in range(2):\n    print(i)")["output"] == "0\n1\n"


def test_long_output_is_cut_with_a_marker_and_kept_whole_in_out(agent: Agent) -> None:
    done = agent.run("print('x' * 10_000_000)", max_chars=1000)
    assert done["truncated"] and done["chars"] == 10_000_001
    assert "[\u2026 9,999,001 characters cut; the whole output is Out[1] \u2026]" in done["output"]
    assert len(done["output"]) < 1100
    assert agent.run("len(Out[1]), Out[1].result")["result"] == "(10000001, None)"


def test_a_cells_writes_are_one_undo_step_of_the_agents_labelled_with_its_intent(
    window: tuple[binbun.Database, binbun.Server], agent: Agent
) -> None:
    db, server = window
    done = agent.run(
        "f = db.functions.get_by_name('classify')\ndb.functions.set_name(f, 'kind_of')\n"
        "db.comments.set_at(f.entry, 'sorts its argument')",
        intent="Name classify",
    )
    assert done["ok"], done
    assert done["step"] == "Codex: Name classify" and done["edits"] == 2
    assert done["database"] == db.name
    assert db.functions.get_by_name("kind_of") is not None
    # Signed by the agent's own key, which the window shows while it is
    # connected, and which the session's members name.
    entry = db.history[0]
    assert entry.label == "Codex: Name classify" and entry.author.via == "agent"
    (shown,) = server.agents
    assert shown["name"] == "Codex" and entry.author.key == shown["key"] != db.identity
    with binbun.connect(socket=server.socket) as remote:
        members = remote.session.members
    codex = members["Codex"]
    assert (codex.kind, codex.key, codex.online, codex.you) == ("agent", entry.author.key, True, False)
    assert members[entry.author.key] == codex
    me = members[0]
    assert (me.kind, me.key, me.you) == ("person", db.identity, True)
    # One undo removes the whole cell.
    undone = db.undo()
    assert undone is not None and undone.label == "Undo: Codex: Name classify"
    assert db.functions.get_by_name("classify") is not None and db.comments.get_at(shown_entry(db)) is None


def shown_entry(db: binbun.Database) -> int:
    function = db.functions.get_by_name("classify")
    assert function is not None
    return function.entry


def test_the_agents_cursor_is_where_its_code_works(window: tuple[binbun.Database, binbun.Server], agent: Agent) -> None:
    db, server = window
    entry = shown_entry(db)
    assert agent.run("db.functions.get_by_name('classify').decompile().text")["ok"]
    deadline = time.monotonic() + 10
    while server.agents[0]["address"] != entry:
        assert time.monotonic() < deadline, server.agents
        time.sleep(0.05)
    assert agent.run(f"db.comments.get_at({entry + 1:#x})")["ok"]
    deadline = time.monotonic() + 10
    while server.agents[0]["address"] != entry + 1:
        assert time.monotonic() < deadline, server.agents
        time.sleep(0.05)


def test_an_agent_connected_from_python_is_a_member_its_writes_its_own(
    window: tuple[binbun.Database, binbun.Server],
) -> None:
    db, server = window
    with binbun.connect(socket=server.socket, agent="Helper Bot") as remote:
        remote.functions.set_name(shown_entry(db), "sign_of")
        remote.commit()
        helper = next(m for m in remote.session.members if m.kind == "agent")
        assert (helper.name, helper.online) == ("Helper Bot", True)
        assert server.agents[0]["key"] == helper.key
    assert db.history[0].author == binbun.Author(helper.key, "agent")
    # The server learns of the disconnection from its own reader thread.
    deadline = time.monotonic() + 10
    while server.agents:
        assert time.monotonic() < deadline, server.agents
        time.sleep(0.05)
    gone = next(m for m in db.session.members if m.key == helper.key)
    assert not gone.online
    # The same agent is the same participant again.
    with binbun.connect(socket=server.socket, agent="Helper Bot") as again:
        assert again._connection.agent == helper.key


def test_a_binary_is_named_by_its_file_name_and_none_named_is_never_ambiguous(
    window: tuple[binbun.Database, binbun.Server], tmp_path: Path
) -> None:
    db, server = window
    other = tmp_path / "other.elf"
    other.write_bytes(FIXTURE.read_bytes() + b"\0")
    with binbun.open(other, project=tmp_path / "other", debug="none") as second, second.serve(ui=True) as served:
        with binbun.connect(FIXTURE.name) as named:
            assert named.path == db.path
        with binbun.connect("other.elf") as named:
            assert named.path == second.path
        with binbun.connect() as chosen:
            assert chosen.path in (db.path, second.path)
        assert served.socket != server.socket


def test_a_traceback_shows_the_cells_frames(agent: Agent) -> None:
    done = agent.run("def g():\n    1 / 0\nprint('before')\ng()")
    assert not done["ok"] and done["output"] == "before\n"
    assert 'File "<cell 1>", line 2, in g' in done["error"]
    assert "ZeroDivisionError" in done["error"] and "console.py" not in done["error"]


def test_interrupt_stops_a_busy_cell_and_the_interpreter_goes_on(agent: Agent) -> None:
    cell = agent.request("run", code="while True: pass")
    agent.expect(lambda e: e["event"] == "started" and e["id"] == cell)
    time.sleep(0.3)
    agent.send({"op": "interrupt"})
    done = agent.expect(lambda e: e["event"] == "done" and e["id"] == cell)[-1]
    assert done["interrupted"] and "KeyboardInterrupt" in done["error"]
    assert agent.run("6 * 7")["result"] == "42"


def test_progress_says_the_last_line(agent: Agent) -> None:
    cell = agent.request("run", code="import time\nfor i in range(30):\n    print('step', i)\n    time.sleep(0.1)")
    events = agent.expect(lambda e: e["event"] == "done" and e["id"] == cell)
    progress = [e for e in events if e["event"] == "progress"]
    assert progress and all(re.fullmatch(r"step \d+", e["line"]) for e in progress)


def test_doc_answers_from_the_installed_package(agent: Agent) -> None:
    doc = agent.request("doc", query="db.functions.get_at")
    answer = agent.expect(lambda e: e["event"] == "doc" and e["id"] == doc)[-1]
    assert answer["text"].startswith("Functions.get_at(ea: AddressLike) -> Function | None")


def test_open_works_on_a_file_without_a_window() -> None:
    agent = Agent("--open", str(FIXTURE))
    try:
        done = agent.run("db.functions.get_by_name('classify').decompile().text")
        assert done["ok"] and "classify(" in done["result"]
    finally:
        agent.close()


def test_every_name_the_digest_mentions_exists() -> None:
    for name in _digest.NAMES:
        assert _digest._resolve(name, None) is not None, name
    # Out[n].result is the python tool's own (binbun.console.CellOutput).
    known = {part for name in _digest.NAMES for part in name.split(".")} | {"result"}
    # String literals ("Name.member", ".text") aside.
    code = re.sub(r'"[^"\n]*"', '""', _digest.DIGEST)
    for attribute in re.findall(r"\.([A-Za-z_]\w*)", code):
        assert attribute in known, attribute
    for name in re.findall(r"\bbinbun\.([A-Za-z_]\w*)", _digest.DIGEST):
        assert hasattr(binbun, name), name
    assert len(_digest.DIGEST) <= 10_000  # About 2,500 tokens.


def test_every_collection_of_db_appears_in_the_digest() -> None:
    """Every property of ``Database`` typed with a class of its own name
    (``db.functions: Functions``), but enums and ``db.revision``."""
    collections = []
    for member in _digest._stubs()["Database"]:
        found = _digest._resolve(f"db.{member}", None)
        assert found is not None, member
        _, returns = _digest._signature("Database", member, found[2])
        cls = _digest._returns(returns)
        if isinstance(found[2], property) or returns is None or cls is None:
            continue
        kind = getattr(binbun, cls)
        if member != cls.lower() or kind.__module__ == "binbun._enums" or member == "revision":
            continue
        collections.append(member)
    assert len(collections) >= 15, collections
    for member in collections:
        assert f"db.{member}" in _digest.DIGEST, member


def test_api_lookups() -> None:
    assert _digest.describe("") == _digest.DIGEST
    assert "Function.callers() -> list[Function]" in _digest.describe("Function")
    full = _digest.describe("db.suggestion", "full")
    assert full.startswith("Database.suggestion(label: str | None=..., *, rationale: str | None=...")
    assert "supersedes" in full
    words = _digest.describe("rename variable")
    assert "CVariable.rename(name: str | None) -> None" in words
    assert _digest.describe("Fuction.nme").startswith("Nothing matches 'Fuction.nme'. Closest names: Function.name")
    names = _digest.describe("", "names")
    assert "Function.decompile" in names.splitlines() and "\n    " not in names
    assert len(_digest.describe("a", "full")) <= _digest.LIMIT + 100


# ---- binbun mcp, as an MCP host speaks to it ----


class Mcp(Process):
    """``binbun mcp ARGS`` over JSON-RPC, initialized."""

    def __init__(self, *args: str) -> None:
        cli = cli_path()
        if cli is None:
            pytest.skip("no binbun CLI (BINBUN_CLI)")
        super().__init__([cli, "mcp", *args, "--python", sys.executable], env=dict(os.environ))
        self.next = 0
        info = self.call("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})
        assert info["result"]["serverInfo"]["name"] == "binbun", info
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def request(self, method: str, params: dict[str, Any]) -> int:
        self.next += 1
        self.send({"jsonrpc": "2.0", "id": self.next, "method": method, "params": params})
        return self.next

    def call(self, method: str, params: dict[str, Any], timeout: float = 120.0) -> dict[str, Any]:
        sent = self.request(method, params)
        return self.expect(lambda m: m.get("id") == sent, timeout)[-1]

    def tool(self, name: str, arguments: dict[str, Any], timeout: float = 120.0) -> dict[str, Any]:
        return self.call("tools/call", {"name": name, "arguments": arguments}, timeout)["result"]


@pytest.fixture()
def mcp() -> Iterator[Mcp]:
    server = Mcp(str(FIXTURE))
    yield server
    server.close()


def test_mcp_refuses_requests_before_initialize_then_initializes() -> None:
    """A 2026 client probes with ``server/discover`` first, as
    Antigravity does (its ``_meta`` below) and fx; binbun speaks the
    ``initialize`` lifecycle only (which names the agent): "method not
    found", a notification before ``initialize`` dropped, then a normal
    handshake."""
    cli = cli_path()
    if cli is None:
        pytest.skip("no binbun CLI (BINBUN_CLI)")
    server = Process([cli, "mcp", str(FIXTURE), "--python", sys.executable], env=dict(os.environ))
    try:
        meta = {
            "io.modelcontextprotocol/clientCapabilities": {"roots": {"listChanged": True}},
            "io.modelcontextprotocol/clientInfo": {"name": "antigravity-client", "version": "v1.0.0"},
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        }
        server.send({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta}})
        server.send({"jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": {}})
        server.send({"jsonrpc": "2.0", "method": "notifications/roots/list_changed", "params": {}})
        server.send({"jsonrpc": "2.0", "id": 3, "method": "ping"})
        initialize = {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "antigravity-client", "version": "v1.0.0"}}
        server.send({"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": initialize})
        said = {m["id"]: m for m in server.expect(lambda m: m.get("id") == 4)}
        for refused in (1, 2):
            assert said[refused]["error"]["code"] == -32601, said
        assert said[3]["result"] == {}, said
        assert said[4]["result"]["serverInfo"]["name"] == "binbun", said
        server.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        server.send({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}})
        tools = server.expect(lambda m: m.get("id") == 5)[-1]["result"]["tools"]
        assert [t["name"] for t in tools] == ["python", "api"]
    finally:
        server.close()


def test_mcp_lists_exactly_two_tools(mcp: Mcp) -> None:
    tools = mcp.call("tools/list", {})["result"]["tools"]
    assert [t["name"] for t in tools] == ["python", "api"]
    python = tools[0]
    assert python["inputSchema"]["required"] == ["code"]
    assert python["outputSchema"]["required"] == ["ok", "cell", "output", "truncated", "interpreter"]
    assert python["_meta"] == {"anthropic/maxResultSizeChars": 100000}


def test_mcp_runs_cells_in_one_interpreter(mcp: Mcp) -> None:
    first = mcp.tool("python", {"code": "f = db.functions.get_by_name('classify')\nf.decompile().text"})
    assert not first["isError"] and first["structuredContent"]["interpreter"] == "fresh"
    assert "classify(" in first["structuredContent"]["result"]
    second = mcp.tool("python", {"code": "f.entry"})
    assert second["structuredContent"]["interpreter"] == "kept"
    assert mcp.tool("api", {"query": "Function.callers"})["content"][0]["text"].startswith("Function.callers()")
    bad = mcp.call("tools/call", {"name": "python", "arguments": {"code": "1", "timeout": 0}})
    assert bad["error"]["code"] == -32602


def test_mcp_kills_a_stuck_cell_on_cancel_and_restarts(mcp: Mcp) -> None:
    mcp.tool("python", {"code": "x = 1"})
    # Not a one-line `while True: pass`: Python 3.11 and 3.12 raise its
    # KeyboardInterrupt outside the `try`, which ends the cell.
    stuck = "import time\nwhile True:\n    try:\n        while True:\n            time.sleep(0.01)\n    except KeyboardInterrupt:\n        pass"
    sent = mcp.request("tools/call", {"name": "python", "arguments": {"code": stuck}})
    time.sleep(1)
    mcp.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": sent}})
    time.sleep(5)  # Interrupted, still busy 3 s later: killed.
    after = mcp.tool("python", {"code": "'x' in dir()"})
    assert after["structuredContent"]["interpreter"] == "restarted"
    assert after["structuredContent"]["result"] == "False"
    assert all(line.get("id") != sent for line in list(mcp.lines.queue))


def test_mcp_interrupts_a_cell_past_its_timeout(mcp: Mcp) -> None:
    timed = mcp.tool("python", {"code": "print('going')\nwhile True: pass", "timeout": 1})
    assert timed["isError"] and timed["structuredContent"]["error"].startswith("interrupted after 1 s\n")
    assert timed["structuredContent"]["output"] == "going\n"
    assert mcp.tool("python", {"code": "1 + 1"})["structuredContent"]["interpreter"] == "kept"
