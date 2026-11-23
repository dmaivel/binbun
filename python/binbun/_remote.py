"""``binbun.connect()``: a script talking to a running binbun GUI (or to a
script's ``db.serve()``) over the user's own Unix socket (on Windows a
named pipe).

Two modes:

- ``mode="remote"`` (the default): a :class:`RemoteDatabase`, whose reads
  and writes all cross the socket. It reads what is cheap to send: the
  functions (entries, names, address ranges), names, comments, bookmarks,
  a function's C as text, the GUI's cursor and selection. Where it cannot
  do what :class:`binbun.Database` does, the name is absent.
- ``mode="local"``: the same binary opened in this process (a
  :class:`binbun.Database`, nothing saved), following the GUI's change log
  (each change the GUI makes is taken here as it is made), its writes
  still made in the GUI, so that they land in the GUI's history. Every
  read of :class:`binbun.Database` works, at in-process speed.

Writes made outside a transaction form the **run group**: one undo step
in the GUI, labelled ``label`` (the script's name unless given), committed
by ``db.commit()``, ``db.close()``, leaving ``with binbun.connect() as
db:``, or the interpreter's exit. A ``db.transaction()`` begun meanwhile
commits the run group first and is an undo step of its own. A script
killed mid-group leaves nothing: the GUI rolls its group back.
"""

from __future__ import annotations

import atexit
import dataclasses
import os
import threading
import weakref
from collections.abc import Callable, Iterable, Iterator
from typing import Any, Literal, TypeAlias, Union, cast

from binbun._enums import Stage, View
from binbun._errors import CapabilityError, InvalidAddressError, NoFunctionError, TransactionError
from binbun._native import (
    Changed,
    Connection,
    Database,
    HistoryChanged,
    HistoryEntry,
    Mentioned,
    Reanalysed,
    Server,
    StageReached,
    ThreadChanged,
    _event,
)
from binbun._native import open as _open
from binbun._results import Comment, Named
from binbun._talk import (
    Session,
    Suggestion,
    SuggestionDraft,
    Suggestions,
    Thread,
    Threads,
    _Citable,
    _ea,
    _entry,
)

_Path = str | os.PathLike[str]

_Event: TypeAlias = Union[StageReached, Changed, HistoryChanged, Reanalysed, ThreadChanged, Mentioned]


def _hex(address: int) -> str:
    return f"{address:#x}"


def _view(view: View | str | None) -> str:
    if view is None:
        return View.EXACT.value
    return View(view).value


_NOTIFICATIONS: dict[type, str] = {
    StageReached: "event.stage",
    Changed: "event.changed",
    HistoryChanged: "event.history",
    Reanalysed: "event.reanalysed",
    ThreadChanged: "event.thread",
    Mentioned: "event.mentioned",
}
"""The notification a server sends each event as."""


class RemoteEventQueue:
    """The server's notifications as they come (``db.events.subscribe()``),
    as the events a database in process gives: ``Changed.functions`` are
    ``RemoteFunction``\\ s, and what a server does not send (``Changed.revision``,
    ``Reanalysed.kept``) is ``None``."""

    def __init__(self, db: RemoteDatabase, kinds: tuple[type, ...]) -> None:
        self._db = db
        self._kinds = kinds
        self._closed = False

    def get(self, timeout: float | None = None) -> _Event | None:
        """The next event, waiting up to ``timeout`` seconds (``None``:
        until one comes); ``None`` if none came, or the queue is closed."""
        connection = self._db._connection
        while not self._closed and not connection.closed:
            note = connection.notification(0.5 if timeout is None else timeout)
            if note is None:
                if timeout is None:
                    continue
                return None
            method, params = note
            functions = (
                [RemoteFunction(self._db, int(entry, 16)) for entry in params.get("functions", [])]
                if method == "event.changed"
                else []
            )
            event = _event(method, params, functions)
            if event is not None and (not self._kinds or isinstance(event, self._kinds)):
                # A server sends only these kinds.
                return cast(_Event, event)
            if timeout is not None:
                return None
        return None

    def close(self) -> None:
        """Stops the queue: no more events."""
        self._closed = True

    def __iter__(self) -> Iterator[_Event]:
        while (event := self.get()) is not None:
            yield event


class RemoteEvents:
    """``db.events``: the server's notifications."""

    def __init__(self, db: RemoteDatabase) -> None:
        self._db = db
        self._queue: RemoteEventQueue | None = None

    def subscribe(self, *kinds: type) -> RemoteEventQueue:
        """A queue of the events of ``kinds`` (event classes:
        ``binbun.StageReached``, ``Changed``, ``HistoryChanged``,
        ``Reanalysed``, ``ThreadChanged``, ``Mentioned``; all of them if
        none) from now on; one queue per connection. A server sends no
        ``Progress``, ``Failed`` or ``Unresolved``: ``CapabilityError``."""
        for kind in kinds:
            if kind not in _NOTIFICATIONS:
                name = getattr(kind, "__name__", repr(kind))
                raise CapabilityError(f"a server sends no {name} events")
        if self._queue is None:
            self._db._connection.call("events.subscribe", {"kinds": [_NOTIFICATIONS[kind] for kind in kinds]})
            self._queue = RemoteEventQueue(self._db, kinds)
        return self._queue


@dataclasses.dataclass(frozen=True)
class RemoteDocument:
    """A function's C as the server prints it."""

    function: RemoteFunction
    view: View
    text: str

    @property
    def lines(self) -> list[RemoteCLine]:
        """Its lines, from 0."""
        return [RemoteCLine(self.function, self.view, n, text) for n, text in enumerate(self.text.split("\n"))]


@dataclasses.dataclass(frozen=True)
class RemoteCLine:
    """A line of a function's C as the server prints it: its ``function``,
    the ``view``, its ``number`` (from 0) and ``text``. As evidence
    (``evidence=[...]``, alone or in a list of one document's lines):
    these lines of its function's C in its view."""

    function: RemoteFunction
    view: View
    number: int
    text: str

    def _cite(self) -> dict[str, Any]:
        return {
            "kind": "lines",
            "function": _hex(self.function.entry),
            "view": self.view.value,
            "lines": [self.number],
        }


class RemoteFunction:
    """A function of the server's database, by entry; read on each use."""

    __slots__ = ("_db", "entry")

    def __init__(self, db: RemoteDatabase, entry: int) -> None:
        self._db = db
        self.entry = entry

    def _info(self) -> dict[str, Any]:
        info = self._db._connection.call("functions.info", {"address": _hex(self.entry)})
        if info is None:
            from binbun._errors import FunctionGoneError

            raise FunctionGoneError(f"no function starts at {self.entry:#x} now")
        return info

    @property
    def name(self) -> str:
        """Its name: the user's, else the image's, else ``sub_XXXX``."""
        return str(self._info()["name"])

    @property
    def user_name(self) -> str | None:
        """The user's name, if given."""
        name = self._info().get("user_name")
        return None if name is None else str(name)

    @property
    def name_source(self) -> str | None:
        """Where its name comes from: ``"user"`` (or ``"script"``,
        ``"plugin"``, ``"agent"``: an edit by one), ``"signature"`` (a
        library signature), ``"symbol"``, ``"debug"``; ``None`` for
        binbun's own (``sub_…``), as ``Function.name_source``."""
        source = self._info().get("name_source")
        return None if source is None else str(source)

    @property
    def ranges(self) -> list[tuple[int, int]]:
        """Its blocks' address ranges, merged: ``(start, end)`` pairs."""
        return [(int(r["start"], 16), int(r["end"], 16)) for r in self._info()["ranges"]]

    def decompile(self, *, view: View | str | None = None, timeout: float | None = None) -> RemoteDocument:
        """Its C as text."""
        return self._db.decompile(self, view=view, timeout=timeout)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, RemoteFunction) and other._db is self._db and other.entry == self.entry

    def __hash__(self) -> int:
        return hash((id(self._db), self.entry))

    def __repr__(self) -> str:
        return f"<binbun.RemoteFunction {self.entry:#x}>"


def _held(ea: int, functions: list[RemoteFunction]) -> RemoteFunction | None:
    """Of the functions holding ``ea`` (by entry), the one starting there,
    else the nearest starting before it, else the first: the one holding
    ``ea``, as ``Functions.get_at`` says."""
    before = [f for f in functions if f.entry <= ea]
    if before:
        return max(before, key=lambda f: f.entry)
    return functions[0] if functions else None


class RemoteFunctions:
    """``db.functions`` over the socket."""

    _PAGE = 4096

    def __init__(self, db: RemoteDatabase) -> None:
        self._db = db

    def _pages(self) -> Iterator[list[dict[str, Any]]]:
        after: str | None = None
        while True:
            page = self._db._connection.call("functions.list", {"after": after, "limit": self._PAGE})
            yield page["items"]
            after = page.get("next")
            if after is None:
                return

    def _starting(self, entry: int) -> RemoteFunction | None:
        info = self._db._connection.call("functions.info", {"address": _hex(entry)})
        return None if info is None else RemoteFunction(self._db, int(info["entry"], 16))

    def __iter__(self) -> Iterator[RemoteFunction]:
        db = self._db
        return iter([RemoteFunction(db, entry) for entry in db._connection.function_entries()])

    def __len__(self) -> int:
        return len(self._db._connection.function_entries())

    def entries(self) -> list[int]:
        """Every function's entry, in order."""
        return self._db._connection.function_entries()

    def __contains__(self, function: object) -> bool:
        return self._starting(_entry(function)) is not None

    def __getitem__(self, function: object) -> RemoteFunction:
        entry = _entry(function)
        found = self._starting(entry)
        if found is None:
            raise NoFunctionError(f"no function starts at {entry:#x}")
        return found

    def get_at(self, ea: object) -> RemoteFunction | None:
        """The function holding ``ea``: the one starting there, else of
        those whose blocks hold it the one with the greatest entry below
        it; ``None`` if none does."""
        address = _ea(ea)
        return _held(address, self.get_containing(address))

    def get_containing(self, ea: object) -> list[RemoteFunction]:
        """Every function whose blocks hold ``ea`` (blocks can be
        shared), by entry."""
        try:
            infos = self._db._connection.call("functions.containing", {"address": _hex(_ea(ea))})
        except InvalidAddressError:
            return []
        return [RemoteFunction(self._db, int(info["entry"], 16)) for info in infos]

    def get_by_name(self, name: str) -> RemoteFunction | None:
        """The function named ``name``, if one is."""
        for items in self._pages():
            for item in items:
                if item["name"] == name:
                    return RemoteFunction(self._db, int(item["entry"], 16))
        return None

    def set_name(self, function: object, name: str | None) -> None:
        """Names ``function`` (a ``RemoteFunction`` or its entry; ``None``:
        its own name again)."""
        self._db._write({"write": "function_name", "entry": _hex(_entry(function)), "name": name})

    def set_prototype(self, function: object, c: str | None) -> None:
        """Gives ``function`` the prototype C ``c`` (``None``: inferred)."""
        self._db._write({"write": "prototype", "entry": _hex(_entry(function)), "c": c})


class RemoteNames:
    """``db.names`` over the socket."""

    def __init__(self, db: RemoteDatabase) -> None:
        self._db = db

    def get_at(self, ea: object) -> str | None:
        """The name of ``ea``: the user's, else the image's."""
        name = self._db._connection.call("names.get", {"address": _hex(_ea(ea))})
        return None if name is None else str(name)

    def set_name(self, ea: object, name: str | None) -> None:
        """Names ``ea``: the function starting there, else the global."""
        self._db._write({"write": "name", "address": _hex(_ea(ea)), "name": name})


class RemoteComments:
    """``db.comments`` over the socket."""

    def __init__(self, db: RemoteDatabase) -> None:
        self._db = db

    def get_all(self) -> list[Comment]:
        """Every comment, by address."""
        return [Comment(int(note["address"], 16), str(note["text"])) for note in self._db._connection.call("comments.all")]

    def get_at(self, ea: object) -> str | None:
        """The comment at ``ea``, if there is one."""
        address = _ea(ea)
        return next((note.text for note in self.get_all() if note.address == address), None)

    def set_at(self, ea: object, text: str | None) -> None:
        """Comments ``ea`` with ``text`` (``None`` or empty: none)."""
        self._db._write({"write": "comment", "address": _hex(_ea(ea)), "text": text})


class RemoteBookmarks:
    """``db.bookmarks`` over the socket."""

    def __init__(self, db: RemoteDatabase) -> None:
        self._db = db

    def get_all(self) -> list[Named]:
        """Every bookmark, by address."""
        return [Named(int(note["address"], 16), str(note["text"])) for note in self._db._connection.call("bookmarks.all")]

    def get_at(self, ea: object) -> str | None:
        """The bookmark at ``ea``, if there is one."""
        address = _ea(ea)
        return next((note.name for note in self.get_all() if note.address == address), None)

    def set_at(self, ea: object, name: str | None) -> None:
        """Bookmarks ``ea`` as ``name`` (``None`` or empty: none)."""
        self._db._write({"write": "bookmark", "address": _hex(_ea(ea)), "name": name})


class RemoteTypes:
    """``db.types``' writes over the socket."""

    def __init__(self, db: RemoteDatabase) -> None:
        self._db = db

    def define(self, c: str) -> str:
        """Defines the struct, union, enumeration or typedef C ``c``: its
        key (``struct pair``). Not inside a suggestion: the server says
        the key only once it writes the definition (``CapabilityError``)."""
        if self._db._recording():
            raise CapabilityError(
                "define inside a suggestion over the socket: the server gives the key only once it writes it"
            )
        return str(self._db._write({"write": "define", "c": c})["key"])

    def undefine(self, key: str) -> None:
        """Drops the user's definition of ``key``."""
        self._db._write({"write": "undefine", "key": key})

    def set_global_type(self, ea: object, c: str | None) -> None:
        """Types the global at ``ea``."""
        self._db._write({"write": "global_type", "address": _hex(_ea(ea)), "c": c})


def _drafting(what: str) -> TransactionError:
    return TransactionError(f"{what} inside a suggestion: its block records writes, accepted as one change")


class RemoteTransaction:
    """``with db.transaction(label):`` over the socket: one undo step in the
    server, rolled back if an exception leaves it."""

    def __init__(self, db: RemoteDatabase, label: str, author: str | None, wait: bool) -> None:
        self._db = db
        self.label = label
        self.author = author or db._connection.author
        self._wait = wait
        self.entry: HistoryEntry | None = None

    def __enter__(self) -> RemoteTransaction:
        if self._db._recording():
            raise _drafting("a transaction")
        self._db._connection.begin(self.label, self.author)
        return self

    def __exit__(
        self, exc_type: object, _exc: object = None, _traceback: object = None
    ) -> Literal[False]:
        if exc_type is not None:
            self._db._connection.rollback()
            return False
        self.entry, reanalysing = self._db._connection.commit()
        if reanalysing and self._wait:
            self._db._connection.settle()
        return False


class RemoteDatabase:
    """A database open in a binbun GUI (or a script's ``db.serve()``),
    read and written over the socket (``binbun.connect()``)."""

    connected = True
    mode: Literal["remote"] = "remote"

    def __init__(self, connection: Connection) -> None:
        self._connection = connection
        self._drafts = threading.local()
        database = connection.database
        self.path: str = database["path"]
        self.name: str = database["name"]
        self.sha256: str | None = database.get("sha256")
        self.slice: str | None = database.get("arch")
        self.functions = RemoteFunctions(self)
        self.names = RemoteNames(self)
        self.comments = RemoteComments(self)
        self.bookmarks = RemoteBookmarks(self)
        self.types = RemoteTypes(self)
        self.events = RemoteEvents(self)
        self.threads = Threads(connection.call)
        self.suggestions = Suggestions(connection.call)
        self.session = Session(connection.call)

    @property
    def identity(self) -> str | None:
        """The server's identity key (hexadecimal): whom a mention of its
        scripts names."""
        return self._connection.identity

    def _recording(self) -> bool:
        return getattr(self._drafts, "writes", None) is not None

    def _write(self, write: dict[str, Any]) -> dict[str, Any]:
        """Makes ``write`` in the server; recorded instead while this
        thread drafts a suggestion."""
        writes: list[dict[str, Any]] | None = getattr(self._drafts, "writes", None)
        if writes is None:
            return self._connection.write(write)
        writes.append(write)
        return {"corrected": False}

    def _record(self) -> None:
        if self._recording():
            raise _drafting("a suggestion")
        self._drafts.writes = []

    def _recorded(self) -> list[dict[str, Any]]:
        writes: list[dict[str, Any]] = getattr(self._drafts, "writes", None) or []
        self._drafts.writes = None
        return writes

    def suggestion(
        self,
        label: str | None = None,
        *,
        rationale: str | None = None,
        evidence: Iterable[_Citable] | None = None,
        thread: Thread | str | None = None,
        supersedes: Suggestion | str | None = None,
    ) -> SuggestionDraft:
        """A suggestion: ``with db.suggestion(label, rationale=...,
        evidence=[...]) as s:`` records the writes made in it on this
        thread instead of making them and makes them a suggestion when it
        ends (``s.suggestion``), as ``binbun.Database.suggestion``. The
        server checks the writes then (``CDeclarationError``...)."""
        return SuggestionDraft(
            self,
            self._connection.call,
            label,
            rationale=rationale,
            evidence=evidence,
            thread=thread,
            supersedes=supersedes,
        )

    def decompile(
        self, function: object, *, view: View | str | None = None, timeout: float | None = None
    ) -> RemoteDocument:
        """The C of ``function`` (a ``RemoteFunction`` or its entry) as the
        server prints it; ``TimeoutError`` after ``timeout`` seconds (the
        server goes on)."""
        entry = _entry(function)
        text = self._connection.call("c.text", {"entry": _hex(entry), "view": _view(view)}, timeout=timeout)
        return RemoteDocument(RemoteFunction(self, entry), View(_view(view)), str(text))

    def transaction(self, label: str, *, author: str | None = None, wait: bool = True) -> RemoteTransaction:
        """A transaction: one undo step labelled ``label``."""
        return RemoteTransaction(self, label, author, wait)

    def commit(self) -> HistoryEntry | None:
        """Commits the run group (the writes made outside a transaction so
        far): one undo step; the change it made."""
        return self._connection.finish()

    def undo(self, *, wait: bool = True) -> HistoryEntry | None:
        """Undoes this install's last change in the server; with ``wait``,
        an undone correction's new analysis is waited for."""
        if self._recording():
            raise _drafting("an undo")
        done = self._connection.undo()
        if wait:
            self._connection.settle()
        return done

    def redo(self, *, wait: bool = True) -> HistoryEntry | None:
        """Makes the last change undone again; as ``undo``."""
        if self._recording():
            raise _drafting("a redo")
        done = self._connection.redo()
        if wait:
            self._connection.settle()
        return done

    @property
    def history(self) -> list[HistoryEntry]:
        """The server's history, newest first."""
        return self._connection.history()

    @property
    def cursor(self) -> int | None:
        """The GUI's cursor, ``None`` if it has none; set, the GUI goes
        there (``CapabilityError`` if the server has no window)."""
        address = self._connection.call("ui.cursor", {})["address"]
        return None if address is None else int(address, 16)

    @cursor.setter
    def cursor(self, ea: object) -> None:
        self._connection.call("ui.cursor", {"address": _hex(_ea(ea))})

    @property
    def selection(self) -> tuple[int, int] | None:
        """The GUI's selection: ``(start, end)``, if one is made."""
        span = self._connection.call("ui.selection")
        return None if span is None else (int(span["start"], 16), int(span["end"], 16))

    def close(self) -> None:
        """Commits the run group and ends the connection."""
        self._connection.close()

    def __enter__(self) -> RemoteDatabase:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<binbun.RemoteDatabase {self.path} on {self._connection.server}>"


_open_connections: weakref.WeakSet[Connection] = weakref.WeakSet()


@atexit.register
def _commit_at_exit() -> None:
    for connection in list(_open_connections):
        if not connection.closed:
            connection.close()


def connect(
    target: _Path | None = None,
    *,
    slice: str | None = None,  # noqa: A002 - the API's name, as Database.slice
    sha256: str | None = None,
    socket: _Path | None = None,
    mode: Literal["remote", "local"] | None = None,
    label: str | None = None,
    author: str | None = None,
    agent: str | None = None,
    protocol: tuple[int, int] = (1, 1),
) -> RemoteDatabase | Database:
    """Connects to a running binbun GUI (or a script's ``db.serve()``): the
    database at ``target`` (a path, or a file name: ``"libc.so.6"``;
    ``slice``: its slice, of a universal Mach-O file, as ``Database.slice``
    names it) or with SHA-256 ``sha256``, else the one whose window had the
    focus last; ``socket`` names a server directly. ``AmbiguousError`` if
    those named match several, ``PermissionError`` if the server is
    another user's, ``VersionError`` without a common protocol version.

    ``mode="remote"`` (the default): a :class:`RemoteDatabase`. ``mode="local"``: the
    binary opened in this process (nothing saved; the slice the server
    opened, with the debug file its analysis read) following the GUI's
    changes, its writes made in the GUI. ``label`` names the run group
    (the script's name unless given); ``author`` makes its writes
    (``script:<name>`` unless given).

    ``agent``: the connection is that agent's (``"Codex"``): a
    participant of the session with an identity of its own (held by the
    GUI's binbun), shown among the window's participants while connected,
    its writes applied and attributed to it (history, Why…), its cursor
    where its code works. In ``binbun mcp``'s interpreter, ``agent`` and
    ``mode`` default to the agent's and ``"local"``, and the database
    connected becomes ``db``."""
    defaults = _agent_defaults
    if defaults is not None:
        agent = agent if agent is not None else defaults.agent
        if mode is None and defaults.local:
            mode = "local"
    if mode is None:
        mode = "remote"
    connection = Connection(
        None if target is None else os.fspath(target),
        slice=slice,
        sha256=sha256,
        socket=None if socket is None else os.fspath(socket),
        label=label,
        author=author,
        agent=agent,
        agent_version=None if defaults is None else defaults.version,
        protocol=protocol,
    )
    _open_connections.add(connection)
    if mode == "remote":
        remote = RemoteDatabase(connection)
        if defaults is not None and defaults.adopt is not None:
            defaults.adopt(connection, remote)
        return remote
    if mode != "local":
        connection.close(commit=False)
        raise ValueError(f"mode={mode!r}: 'remote' or 'local'")
    db = _follower(connection)
    if defaults is not None and defaults.adopt is not None:
        defaults.adopt(connection, db)
    return db


@dataclasses.dataclass
class _AgentDefaults:
    """What ``connect()`` takes in an agent's interpreter (``binbun mcp``):
    the agent's name and version, local mode, and who adopts the
    database connected (the console: it becomes ``db``)."""

    agent: str | None
    version: str | None = None
    local: bool = True
    adopt: Callable[[Connection, Any], None] | None = None


_agent_defaults: _AgentDefaults | None = None


def _follower(connection: Connection) -> Database:
    """The binary of ``connection``'s database opened in this process,
    following the server (``mode="local"``); the connection closed if
    that fails."""
    database = connection.database
    try:
        # As the server read it: with its debug file, or none.
        db = _open(
            database["path"],
            project=False,
            debug=database.get("debug") or "none",
            wait=Stage.ANALYSED,
            slice=database.get("arch"),
        )
        db._follow(connection)
    except BaseException:
        connection.close(commit=False)
        raise
    return db


__all__ = [
    "RemoteBookmarks",
    "RemoteCLine",
    "RemoteComments",
    "RemoteDatabase",
    "RemoteDocument",
    "RemoteEventQueue",
    "RemoteEvents",
    "RemoteFunction",
    "RemoteFunctions",
    "RemoteNames",
    "RemoteTransaction",
    "RemoteTypes",
    "Server",
    "connect",
]
