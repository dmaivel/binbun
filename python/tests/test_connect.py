"""``binbun.connect()``: a database served over the user's socket
(``db.serve()``, the server the GUI runs) read and written by a client in
``mode="remote"`` (over the socket) and ``mode="local"`` (the binary in
process, following the server's change log); the run group as one undo
step; a client killed mid-transaction rolled back; versions and
capabilities refused; the socket private to its user; reads over the
socket fast enough."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import binbun
from conftest import FIXTURE


def wait_until(condition, timeout: float = 30.0) -> None:  # noqa: ANN001 - a callable
    """Waits until ``condition()`` holds."""
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "the condition never held"
        time.sleep(0.05)


def run_script(path: Path, source: str, *args: str) -> subprocess.Popen[str]:
    """A Python process running ``source``, written to ``path`` (connected,
    as a script is)."""
    path.write_text(textwrap.dedent(source))
    return subprocess.Popen(
        [sys.executable, str(path), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def c_of(decompile: Callable[[], binbun.CDocument | binbun.RemoteDocument]) -> str:
    """A function's C, or why it has none (as ``DecompileError`` says)."""
    try:
        return decompile().text
    except binbun.DecompileError as error:
        return f"DecompileError: {error}"


@pytest.fixture()
def served(tmp_path: Path) -> Iterator[binbun.Database]:
    """The fixture with a project of its own, served."""
    with binbun.open(FIXTURE, project=tmp_path / "project", debug="none") as db:
        db.wait(binbun.Stage.CALLERS)
        with db.serve():
            yield db


@pytest.fixture(scope="module")
def bash_served(bash_db: binbun.Database) -> Iterator[binbun.Database]:
    """bash (as the CLI reads it), every function's C made (on several
    threads, as test_bash's tests have it made), served: the reads compare
    C made, not wait for it a function at a time."""
    for _ in bash_db.decompile_all(workers=8):
        pass
    with bash_db.serve():
        yield bash_db


def test_reads_through_the_socket_and_in_process_agree(bash_served: binbun.Database) -> None:
    """The reads (functions, names, C) give the same through
    ``connect()`` as in the served process."""
    db = bash_served
    functions = list(db.functions)
    with binbun.connect(db.path) as remote:
        assert remote.path == db.path and remote.sha256 == db.sha256
        assert remote.functions.entries() == [f.entry for f in functions]
        assert len(remote.functions) == len(db.functions)
        for f in functions:
            there = remote.functions[f.entry]
            assert (there.name, there.name_source) == (f.name, f.name_source), hex(f.entry)
        # bash's names: its exports' symbols, binbun's own for the rest.
        assert {f.name_source for f in functions} == {"symbol", None}
        for f in functions:
            there = c_of(lambda f=f: remote.decompile(f.entry, timeout=120))
            assert there == c_of(lambda f=f: db.decompile(f)), hex(f.entry)
        assert remote.comments.get_all() == db.comments.get_all()
        assert all(isinstance(note, binbun.Comment) for note in remote.comments.get_all())
    # Local mode: the same binary in this process, its reads native.
    local = binbun.connect(db.path, mode="local")
    try:
        assert isinstance(local, binbun.Database) and local.connected
        assert local.functions.entries() == [f.entry for f in functions]
        assert [repr(s) for s in local.strings.get_all()] == [repr(s) for s in db.strings.get_all()]
        main = db.functions.get_by_name("main")
        assert main is not None
        assert [repr(x) for x in local.xrefs.to_ea(main.entry)] == [repr(x) for x in db.xrefs.to_ea(main.entry)]
        for f in functions[::20]:
            here = c_of(lambda f=f: local.decompile(f.entry))
            assert here == c_of(lambda f=f: db.decompile(f)), hex(f.entry)
    finally:
        local.close()


def test_a_scripts_run_group_is_one_undo_step_with_its_label_and_author(
    served: binbun.Database, tmp_path: Path
) -> None:
    """A connected script's writes outside a transaction
    are one undo step labelled by it; the server's C and listing show
    them; undone in the server (the GUI's Ctrl-Z), they are gone."""
    db = served
    loop_sum = db.functions.get_by_name("loop_sum")
    assert loop_sum is not None
    history = len(db.history)
    script = run_script(
        tmp_path / "name_loop.py",
        """
        import sys, binbun
        db = binbun.connect(sys.argv[2], label="Name the loop")
        db.functions.set_name(int(sys.argv[1], 16), "summed")
        db.comments.set_at(int(sys.argv[1], 16), "sums checked(i % 7)")
        """,
        hex(loop_sum.entry),
        db.path,
    )
    _, err = script.communicate(timeout=60)
    assert script.returncode == 0, err
    entry = db.history[0]
    assert len(db.history) == history + 1
    assert (entry.label, entry.author, entry.edits) == (
        "Name the loop",
        binbun.Author(db.identity, "script:name_loop.py"),
        2,
    )
    assert entry.suggested_by is None
    assert "summed(" in db.functions.get_by_name("main").decompile().text
    # Its proc line and first instruction (with the comment).
    first = db.listing.line_of(loop_sum.entry)
    listing = "\n".join(line.text for line in db.listing.lines(first - 1, 2))
    assert "summed" in listing and "sums checked" in listing, listing
    with binbun.connect(db.path) as remote:
        assert remote.history[0].id == entry.id
    # The server's undo (the GUI's Ctrl-Z) undoes the whole group.
    undone = db.undo()
    assert undone is not None and undone.label == "Undo: Name the loop"
    assert loop_sum.name == "loop_sum" and db.comments.get_at(loop_sum.entry) is None


def test_a_client_killed_mid_transaction_leaves_nothing(served: binbun.Database, tmp_path: Path) -> None:
    """The server rolls back the group a killed client
    left open; nothing shows, nothing enters the history."""
    db = served
    main = db.functions.get_by_name("main")
    assert main is not None
    history = [e.id for e in db.history]
    script = run_script(
        tmp_path / "killed.py",
        """
        import sys, time, binbun
        db = binbun.connect(sys.argv[2])
        tx = db.transaction("Never committed")
        tx.__enter__()
        db.functions.set_name(int(sys.argv[1], 16), "half_done")
        print("written", flush=True)
        time.sleep(600)
        """,
        hex(main.entry),
        db.path,
    )
    assert script.stdout is not None
    assert script.stdout.readline().strip() == "written"
    # Inside: the server shows the client's write (read your writes).
    assert main.name == "half_done"
    script.kill()
    script.wait(timeout=30)
    wait_until(lambda: main.name == "main")
    assert [e.id for e in db.history] == history
    # The server takes writes again.
    db.comments.set_at(main.entry, "after")
    assert db.history[0].label == "Comment"


def test_versions_and_capabilities_are_checked(served: binbun.Database) -> None:
    """No common protocol version raises ``VersionError``;
    a call needing a capability the server lacks raises
    ``CapabilityError`` without sending: the GUI's cursor of a server
    with no window, events a server never sends."""
    with pytest.raises(binbun.VersionError):
        binbun.connect(served.path, protocol=(2, 2))
    with binbun.connect(served.path) as remote:
        connection = remote._connection
        assert "ir.unstable" not in connection.capabilities
        assert "ui.cursor" not in connection.capabilities
        sent = connection.requests
        with pytest.raises(binbun.CapabilityError):
            connection.call("ir.text", {"entry": "0x11f0"})
        with pytest.raises(binbun.CapabilityError):
            _ = remote.cursor
        with pytest.raises(binbun.CapabilityError):
            remote.cursor = 0x11F0
        with pytest.raises(binbun.CapabilityError):
            _ = remote.selection
        for never in (binbun.Progress, binbun.Failed, binbun.Unresolved):
            with pytest.raises(binbun.CapabilityError):
                remote.events.subscribe(never)
        assert connection.requests == sent
        # What it has works.
        assert remote.names.get_at(0x11F0) == "loop_sum"
    # In process there is no GUI's cursor at all.
    with pytest.raises(binbun.CapabilityError):
        _ = served.cursor
    with pytest.raises(binbun.CapabilityError):
        _ = served.selection


def test_functions_are_found_by_entry_or_by_an_address_they_hold_the_same_over_the_socket(
    served: binbun.Database,
) -> None:
    """``functions[f]`` by a function or its entry, ``NoFunctionError`` (a
    ``KeyError``) where none starts; ``get_at`` the function holding an
    address, ``None`` where none does or nothing is mapped; the C of a
    function over the socket names it: in process and over the socket
    alike."""
    db = served
    loop_sum = db.functions.get_by_name("loop_sum")
    assert loop_sum is not None
    inside = loop_sum.entry + 0x10
    assert db.functions.get_at(inside) == loop_sum and db.functions[loop_sum] == loop_sum
    unmapped = 0x7FFF_0000_0000
    assert db.functions.get_at(unmapped) is None and db.functions.get_containing(unmapped) == []
    with pytest.raises(KeyError):
        db.functions[inside]
    with pytest.raises(binbun.NoFunctionError):
        db.functions[inside]
    assert inside not in db.functions and loop_sum in db.functions
    with binbun.connect(db.path) as remote:
        there = remote.functions[loop_sum.entry]
        assert remote.functions[there] == there and there.entry == loop_sum.entry
        assert remote.functions.get_at(inside) == there and remote.functions.get_at(loop_sum) == there
        assert remote.functions.get_at(unmapped) is None and remote.functions.get_containing(unmapped) == []
        with pytest.raises(KeyError):
            remote.functions[inside]
        with pytest.raises(binbun.NoFunctionError):
            remote.functions[inside]
        assert inside not in remote.functions and there in remote.functions
        document = remote.decompile(there, view="exact", timeout=60)
        assert isinstance(document, binbun.RemoteDocument) and document.function == there
        assert document == there.decompile(timeout=60)
        assert all(line.function == there for line in document.lines)
        assert document.text == db.decompile(loop_sum).text


# Windows' socket is a named pipe, its owner's alone by its DACL, not by
# modes: crates/binbun-protocol/tests/pipe.rs reads the DACL and has
# another user refused.
@pytest.mark.skipif(sys.platform == "win32", reason="a named pipe's DACL: binbun-protocol's tests/pipe.rs")
def test_the_socket_is_its_users_alone(served: binbun.Database, tmp_path: Path) -> None:
    """The socket and discovery file are 0600 in a 0700
    directory; another user's ``connect()`` raises ``PermissionError``."""
    directory = Path(os.environ["XDG_RUNTIME_DIR"]) / "binbun"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    files = sorted(directory.iterdir())
    names = {path.suffix for path in files}
    assert names == {".json", ".sock"}, files
    for path in files:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
    unshare, setpriv = shutil.which("unshare"), shutil.which("setpriv")
    if unshare is None or setpriv is None:
        pytest.skip("no unshare/setpriv for a second user")
    # Another user (a uid of this user's subordinate range, in a user
    # namespace) runs binbun copied where it can read it.
    shared = Path(tempfile.mkdtemp(prefix="binbun-other-user-"))
    try:
        shutil.copytree(Path(binbun.__file__).parent, shared / "binbun")
        for path in [shared, *shared.rglob("*")]:
            path.chmod(0o755)
        socket = next(path for path in files if path.suffix == ".sock")
        done = subprocess.run(
            [
                unshare, "--user", "--map-auto", "--map-root-user",
                setpriv, "--reuid=1000", "--regid=1000", "--clear-groups",
                sys.executable, "-I", "-c",
                textwrap.dedent(
                    """
                    import sys
                    sys.path.insert(0, sys.argv[1])
                    import binbun
                    for target in [dict(), dict(socket=sys.argv[2])]:
                        try:
                            binbun.connect(**target)
                        except PermissionError as error:
                            print("refused", type(error).__name__)
                    """
                ),
                str(shared),
                str(socket),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ},
        )
    finally:
        shutil.rmtree(shared, ignore_errors=True)
    if "Operation not permitted" in done.stderr or "unshare failed" in done.stderr:
        pytest.skip(f"no user namespaces here: {done.stderr.strip()}")
    assert done.stdout.split("\n")[:2] == ["refused PermissionError"] * 2, done.stdout + done.stderr


def test_iterating_the_functions_over_the_socket_is_within_three_times_in_process(
    bash_served: binbun.Database,
) -> None:
    """``for f in db.functions`` over the socket, on bash,
    within 3x of in process.

    Its intent: iterating is one request, never paging over the socket. So
    the requests an iteration sends are counted (exactly one), and the
    time is compared as work, not as the scheduler's mood: in process,
    over the socket, and one bare round trip (``names.get``) are measured
    interleaved, the best of 15 each, and the iteration over the socket
    must cost within 3x of in process plus that one round trip (a loaded
    machine delays the hand-offs between threads, not the work). On CI's
    shared runners the timings are printed, not compared: a few vCPUs
    shared with other jobs move them by more than the margin."""
    db = bash_served
    total = len(db.functions)

    def timed(work: Callable[[], object]) -> float:
        start = time.perf_counter()
        work()
        return time.perf_counter() - start

    with binbun.connect(db.path) as remote:
        connection = remote._connection
        sent = connection.requests
        assert sum(1 for _ in remote.functions) == total
        assert connection.requests - sent == 1, "iterating pages over the socket"
        here, there, trip = [], [], []
        for _ in range(15):
            here.append(timed(lambda: sum(1 for _ in db.functions)))
            there.append(timed(lambda: sum(1 for _ in remote.functions)))
            trip.append(timed(lambda: remote.names.get_at(0)))
    numbers = (
        f"in process {min(here) * 1e3:.3f} ms, over the socket {min(there) * 1e3:.3f} ms, "
        f"one round trip {min(trip) * 1e3:.3f} ms"
    )
    print(numbers)
    if not os.environ.get("CI"):
        assert min(there) <= 3 * min(here) + min(trip), numbers


def test_a_rename_in_the_server_reaches_a_local_client_and_its_writes_reach_the_server(
    served: binbun.Database,
) -> None:
    """``mode="local"``: a rename made in the server (the GUI's user) shows
    in the local client's C; the client's own writes are made in the
    server, in its history."""
    db = served
    local = binbun.connect(db.path, mode="local", label="Local client")
    try:
        assert isinstance(local, binbun.Database)
        queue = local.events.subscribe(binbun.HistoryChanged)
        db.functions.set_name(db.functions.get_by_name("loop_sum"), "added_up")
        assert isinstance(queue.get(timeout=30.0), binbun.HistoryChanged)
        assert "added_up(" in local.decompile(local.functions.get_by_name("main")).text
        # A local client has no GUI's cursor either: the server has no window.
        with pytest.raises(binbun.CapabilityError):
            _ = local.cursor
        # Its own writes: read at once here, made in the server.
        classify = local.functions.get_by_name("classify")
        assert classify is not None
        local.functions.set_name(classify, "sorted_into")
        assert classify.name == "sorted_into"
        assert db.functions[classify.entry].name == "sorted_into"
        entry = local.commit()
        assert entry is not None and entry.label == "Local client"
        assert db.history[0].id == entry.id
        assert local.history[0].id == entry.id
        assert classify.name == "sorted_into"
        # Undone from the client: in the server, and taken back here.
        local.undo()
        assert db.functions[classify.entry].name == "classify"
        assert classify.name == "classify"
    finally:
        local.close()
