"""Threads, suggestions and who is in the session:
``db.threads``, ``db.suggestions``, ``db.suggestion()`` and
``db.session.members`` of a database open
in process (``binbun.open``), connected (``binbun.connect()``, either
mode: they are the server's) or remote.

- A **thread** is discussion about something in the binary
  (``db.threads.create(about, text)``: a ``binbun.Function``, a
  ``binbun.CLine`` by the first instruction it was made from, a
  ``binbun.CVariable``, a :class:`Suggestion`, a ``binbun.StringItem``,
  an address: the instruction or data item there; a type by
  ``Anchor.type(key)``): it follows them across re-analysis, never
  printed into the C. Read back, what it is about is its :class:`Anchor`.
- A **post** is edited by its author only and deleted by its author or the
  project's owner (shown "removed by the owner"); ``mentions`` name whom it
  is for (:class:`Member`\\ s of ``db.session.members``), told to them as
  ``binbun.Mentioned``.
- A **suggestion** proposes writes with what they rest on: ``with
  db.suggestion("Name parse_args", rationale=..., evidence=[...]):``
  records the ordinary write calls made in its block (``db.functions.set_name``,
  ``CVariable.rename``...) instead of making them. Nothing is written
  until a person accepts it, in whole or in part (one undo step of
  theirs, the suggestion's author named in the history); its author may
  supersede it with a new version (``db.suggestion(supersedes=s)``); its
  evidence can be asked again (stale items marked).
- **Evidence** (``evidence=``, of a suggestion or a post) is the query
  results it rests on, as they were got: C lines (a ``binbun.CLine``, or
  a list of one document's; a ``binbun.RemoteCLine`` likewise),
  ``db.xrefs.to_ea(ea)`` (a ``binbun.XrefsTo``: what refers to ``ea``), a
  call's ``binbun.Xref`` (the call at its site), ``f.verify()`` (its
  verdict), an item of ``f.why().items`` (why its variable has its type
  and name), ``db.strings.get_at(ea)`` (the string there), a ``str`` (its
  author's own words), or an :class:`Evidence` read back. Each is recorded
  as what it points at and quoted by the database when the post or
  suggestion is made; read back, it is an :class:`Evidence`.
- A **member** is someone in the session (:class:`Member`): a person or an
  agent (an agent connected with ``binbun.connect(agent=...)`` or through
  ``binbun mcp`` has an identity of its own). Talk to people in threads,
  mentioning them (``mentions=[member]``); there is no chat from Python.

Ids are strings (``"<chain>:<seq>:<n>"``), keys hexadecimal, times seconds
since the Unix epoch.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeAlias, Union, overload

if TYPE_CHECKING:
    from binbun._native import CLine, ExplanationItem, HistoryEntry, StringItem, Verification, Xref
    from binbun._remote import RemoteCLine
    from binbun._results import XrefsTo

Caller = Callable[[str, Any], Any]
"""Calls a ``threads.*`` or ``suggestions.*`` method: its result."""

# A Union of forward references: its classes are imported only for typing
# (binbun._remote imports this module).
_Citable: TypeAlias = Union[
    str,
    "CLine",
    "Sequence[CLine]",
    "RemoteCLine",
    "Sequence[RemoteCLine]",
    "XrefsTo",
    "Xref",
    "Verification",
    "ExplanationItem",
    "StringItem",
    "Evidence",
]
"""What ``evidence=`` takes: a query result as it was got (see the module)."""


class _Recorder(Protocol):
    """A database whose writes a :class:`SuggestionDraft` records."""

    def _record(self) -> None: ...
    def _recorded(self) -> list[dict[str, Any]]: ...


def _hex(address: int) -> str:
    return f"{address:#x}"


def _ea(value: object) -> int:
    """The one address ``value`` is at, as every ``ea`` parameter takes it
    (an ``int``, or a binbun object at one address)."""
    from binbun._remote import RemoteFunction

    if isinstance(value, RemoteFunction):
        return value.entry
    from binbun._native import _address

    return _address(value)


def _entry(function: object) -> int:
    """The entry of ``function``: a ``binbun.Function``, a
    ``binbun.RemoteFunction``, or an entry (an ``int``)."""
    from binbun._native import Function
    from binbun._remote import RemoteFunction

    if isinstance(function, (Function, RemoteFunction)):
        return function.entry
    if isinstance(function, int):
        return _ea(function)
    raise TypeError(f"a function is a Function or its entry (an int), not {type(function).__name__}")


def _time(millis: int | None) -> float | None:
    return None if millis is None else millis / 1000.0


@dataclasses.dataclass(frozen=True)
class Author:
    """Who did something: an identity ``key`` (hexadecimal) and as whom
    (``via``: ``user``, ``script:<name>``, ``agent``...)."""

    key: str
    via: str

    @staticmethod
    def _of(data: dict[str, Any]) -> Author:
        return Author(str(data["key"]), str(data["author"]))


@dataclasses.dataclass(frozen=True)
class Mention:
    """Whom a post mentions, read back: an identity (``key``; the server's,
    or this database's, if ``None``), and one of its scripts or agents
    (``agent``: ``"script:helper"``; ``None``: the identity itself)."""

    agent: str | None = None
    key: str | None = None

    @staticmethod
    def _of(data: dict[str, Any]) -> Mention:
        return Mention(agent=data.get("agent"), key=data.get("key"))


@dataclasses.dataclass(frozen=True)
class Anchor:
    """What a thread is about, as the protocol states it (``data``):
    ``thread.anchor``. ``Anchor.type(key)`` makes one for a type, which
    no object stands for."""

    data: dict[str, Any]

    @property
    def kind(self) -> str:
        """``function``, ``instruction``, ``data``, ``line``, ``variable``,
        ``type`` or ``suggestion``."""
        return str(self.data["kind"])

    @property
    def address(self) -> int | None:
        """Its address, if it has one (a line's first instruction)."""
        if "address" in self.data:
            return int(self.data["address"], 16)
        if self.kind == "variable":
            return int(self.data["variable"]["function"], 16)
        return None

    @staticmethod
    def type(key: str) -> Anchor:
        """A type, by the key its definition defines (``struct pair``)."""
        return Anchor({"kind": "type", "key": key})


def _anchor(about: object) -> dict[str, Any]:
    """What a thread about ``about`` is anchored to, as the protocol
    states it."""
    from binbun import _native
    from binbun._enums import View
    from binbun._remote import RemoteCLine, RemoteFunction

    if isinstance(about, Anchor):
        return dict(about.data)
    if isinstance(about, (_native.Function, RemoteFunction)):
        return {"kind": "function", "address": _hex(about.entry)}
    if isinstance(about, _native.CLine):
        if not about.addresses:
            raise ValueError(f"line {about.number} was made from no instruction: anchor at an address")
        return {
            "kind": "line",
            "function": _hex(about.function.entry),
            "view": View(about.view).value,
            "address": _hex(about.addresses[0]),
        }
    if isinstance(about, RemoteCLine):
        raise TypeError("a RemoteCLine has no instructions to anchor to: give the function or an address")
    if isinstance(about, _native.CVariable):
        return {
            "kind": "variable",
            "variable": {
                "function": _hex(about.function.entry),
                "origins": list(about.origins),
                "ordinal": about.ordinal,
            },
        }
    if isinstance(about, Suggestion):
        return {"kind": "suggestion", "id": about.id}
    if isinstance(about, _native.StringItem):
        return {"kind": "data", "address": _hex(about.address)}
    try:
        address = _ea(about)
    except TypeError:
        raise TypeError(
            "a thread is about a Function, a CLine, a CVariable, a Suggestion, a StringItem, an address"
            f" or Anchor.type(key), not {type(about).__name__}"
        ) from None
    return {"kind": "address", "address": _hex(address)}


@dataclasses.dataclass(frozen=True)
class Evidence:
    """An item of evidence of a post or suggestion, read back: what it
    points at (``data``: what asks it again) and what it said when quoted
    (``quote``; ``None`` if it could not be answered then). Given as
    evidence again, it is quoted anew."""

    data: dict[str, Any]
    quote: str | None = None

    @property
    def kind(self) -> str:
        """``why``, ``lines``, ``verification``, ``xrefs_to``, ``string``,
        ``call`` or ``text``."""
        return str(self.data["kind"])

    @staticmethod
    def _of(data: dict[str, Any]) -> Evidence:
        return Evidence(data["reference"], data.get("quote"))


def _id(item: Thread | Post | Suggestion | str) -> str:
    return item if isinstance(item, str) else item.id


def _mentions(mentions: Iterable[Member]) -> list[dict[str, Any]]:
    if isinstance(mentions, (str, Member)):
        raise TypeError("mentions is a list: mentions=[member]")
    out = []
    for mention in mentions:
        if not isinstance(mention, Member):
            raise TypeError(
                'a mention is a binbun.Member (db.session.members["alice"]),'
                f" not {type(mention).__name__}"
            )
        out.append({"key": mention.key, "agent": None})
    return out


def _not_cited(why: str) -> TypeError:
    return TypeError(
        f"{why}: evidence is query results as they were got: C lines (a CLine or"
        " RemoteCLine, or a list of one document's), db.xrefs.to_ea(ea), a call's"
        " Xref, f.verify(), an item of f.why().items, db.strings.get_at(ea), a str"
        " (your own words), or an Evidence read back"
    )


def _reference(item: object) -> dict[str, Any]:
    """What ``item`` is cited as: the record of what it points at."""
    if isinstance(item, str):
        return {"kind": "text", "text": item}
    if isinstance(item, Evidence):
        return dict(item.data)
    cite = getattr(type(item), "_cite", None)
    if cite is not None:
        return dict(cite(item))
    if isinstance(item, (list, tuple)) and item:
        lines = [_reference(line) for line in item]
        if all(line["kind"] == "lines" for line in lines) and (
            len({(line["function"], line["view"]) for line in lines}) == 1
        ):
            return {**lines[0], "lines": [n for line in lines for n in line["lines"]]}
        raise _not_cited("a list as one item is C lines of one document")
    raise _not_cited(f"a {type(item).__name__} is not cited")


def _evidence(evidence: Iterable[_Citable]) -> list[dict[str, Any]]:
    if isinstance(evidence, str) or getattr(type(evidence), "_cite", None) is not None:
        raise TypeError("evidence is a list of items: evidence=[...]")
    return [{"reference": _reference(item)} for item in evidence]


@dataclasses.dataclass(frozen=True)
class Post:
    """A post as it is now: ``body`` is empty once deleted, ``deleted_by``
    who deleted it (``removed_by_owner``: an owner, not its author)."""

    id: str
    thread: str
    reply_to: str | None
    author: Author
    time: float
    body: str
    edited: float | None
    deleted_by: Author | None
    removed_by_owner: bool
    mentions: tuple[Mention, ...]
    evidence: tuple[Evidence, ...]
    _call: Caller = dataclasses.field(repr=False, compare=False)

    @staticmethod
    def _of(call: Caller, data: dict[str, Any]) -> Post:
        deleted = data.get("deleted")
        return Post(
            id=data["id"],
            thread=data["thread"],
            reply_to=data.get("reply_to"),
            author=Author._of(data["author"]),
            time=data["millis"] / 1000.0,
            body=data["body"],
            edited=_time(data.get("edited")),
            deleted_by=None if deleted is None else Author._of(deleted),
            removed_by_owner=bool(deleted and deleted["by_owner"]),
            mentions=tuple(Mention._of(m) for m in data.get("mentions", [])),
            evidence=tuple(Evidence._of(item) for item in data.get("evidence", [])),
            _call=call,
        )

    @property
    def deleted(self) -> bool:
        """Whether it is deleted."""
        return self.deleted_by is not None

    def edit(self, text: str) -> Post:
        """Edits it to say ``text`` (its author only): it as it is now."""
        return Post._of(self._call, self._call("threads.edit", {"id": self.id, "body": text}))

    def delete(self) -> Post:
        """Deletes it (its author, or an owner): it as it is now."""
        return Post._of(self._call, self._call("threads.delete", {"id": self.id}))


@dataclasses.dataclass(frozen=True)
class Thread:
    """A thread as it was read: what it is about (``anchor``), its posts
    and the suggestions answering it."""

    id: str
    anchor: Anchor
    quote: str
    opened_by: Author
    time: float
    resolved: bool
    posts: tuple[Post, ...]
    suggestions: tuple[str, ...]
    _call: Caller = dataclasses.field(repr=False, compare=False)

    @staticmethod
    def _of(call: Caller, data: dict[str, Any]) -> Thread:
        return Thread(
            id=data["id"],
            anchor=Anchor(data["anchor"]),
            quote=data["quote"],
            opened_by=Author._of(data["opened_by"]),
            time=data["millis"] / 1000.0,
            resolved=bool(data["resolved"]),
            posts=tuple(Post._of(call, post) for post in data["posts"]),
            suggestions=tuple(data["suggestions"]),
            _call=call,
        )

    def reply(
        self,
        text: str,
        *,
        reply_to: Post | str | None = None,
        mentions: Iterable[Member] = (),
        evidence: Iterable[_Citable] = (),
    ) -> Post:
        """Posts ``text`` in it (``mentions``: :class:`Member`\\ s;
        ``evidence``: query results, see the module)."""
        return Threads(self._call).post(self, text, reply_to=reply_to, mentions=mentions, evidence=evidence)

    def resolve(self, resolved: bool = True) -> Thread:
        """Resolves it (or opens it again): it as it is now."""
        return Threads(self._call).resolve(self, resolved)

    def refresh(self) -> Thread:
        """It as it is now."""
        found = Threads(self._call).get(self.id)
        if found is None:
            from binbun._errors import ConversationError

            raise ConversationError(f"no thread {self.id}")
        return found


class Threads:
    """``db.threads``: every thread (iterating), those at an address or
    in a function, and the writes."""

    def __init__(self, call: Caller) -> None:
        self._call = call

    def _list(self, method: str, params: dict[str, Any] | None = None) -> list[Thread]:
        return [Thread._of(self._call, data) for data in self._call(method, params)]

    def __iter__(self) -> Iterator[Thread]:
        return iter(self._list("threads.list"))

    def __len__(self) -> int:
        return len(self._list("threads.list"))

    def at(self, ea: object) -> list[Thread]:
        """The threads anchored at ``ea`` (a function's entry, an
        instruction, a data item, a C line's first instruction)."""
        return self._list("threads.at", {"address": _hex(_ea(ea))})

    def in_function(self, function: object) -> list[Thread]:
        """The threads in ``function`` (a ``Function`` or its entry):
        about it, a line or variable of it, an instruction it holds."""
        return self._list("threads.of", {"entry": _hex(_entry(function))})

    def get(self, id: str) -> Thread | None:
        """Thread ``id``, if made."""
        data = self._call("threads.get", {"id": id})
        return None if data is None else Thread._of(self._call, data)

    def create(
        self,
        about: object,
        text: str = "",
        *,
        quote: str = "",
        mentions: Iterable[Member] = (),
        evidence: Iterable[_Citable] = (),
    ) -> Thread:
        """Opens a thread about ``about`` (a ``Function``, a ``CLine``, a
        ``CVariable``, a :class:`Suggestion`, a ``StringItem``, an address:
        the instruction or data item there; ``Anchor.type(key)``), quoting
        its text now (``quote``), its first post ``text`` if not empty
        (``mentions``: :class:`Member`\\ s; ``evidence``: query results):
        one change."""
        data = self._call(
            "threads.create",
            {
                "anchor": _anchor(about),
                "quote": quote,
                "body": text,
                "mentions": _mentions(mentions),
                "evidence": _evidence(evidence),
            },
        )
        return Thread._of(self._call, data)

    def post(
        self,
        thread: Thread | str,
        text: str,
        *,
        reply_to: Post | str | None = None,
        mentions: Iterable[Member] = (),
        evidence: Iterable[_Citable] = (),
    ) -> Post:
        """Posts ``text`` in ``thread``."""
        data = self._call(
            "threads.post",
            {
                "thread": _id(thread),
                "body": text,
                "reply_to": None if reply_to is None else _id(reply_to),
                "mentions": _mentions(mentions),
                "evidence": _evidence(evidence),
            },
        )
        return Post._of(self._call, data)

    def edit(self, post: Post | str, text: str) -> Post:
        """Edits ``post`` to say ``text`` (its author only)."""
        return Post._of(self._call, self._call("threads.edit", {"id": _id(post), "body": text}))

    def delete(self, post: Post | str) -> Post:
        """Deletes ``post`` (its author, or an owner)."""
        return Post._of(self._call, self._call("threads.delete", {"id": _id(post)}))

    def resolve(self, thread: Thread | str, resolved: bool = True) -> Thread:
        """Resolves ``thread`` (or opens it again)."""
        data = self._call("threads.resolve", {"id": _id(thread), "resolved": resolved})
        return Thread._of(self._call, data)


@dataclasses.dataclass(frozen=True)
class Proposal:
    """An edit a suggestion proposes, against its key now: ``kind``
    (``function_name``, ``comment``...), its ``address``, the ``value``
    proposed, the value shown ``now``, whether the key ``moved`` since."""

    kind: str
    address: int | None
    key: str
    value: str | None
    now: str | None
    moved: bool

    @staticmethod
    def _of(data: dict[str, Any]) -> Proposal:
        address = data.get("address")
        return Proposal(
            kind=data["kind"],
            address=None if address is None else int(address, 16),
            key=data["key"],
            value=data.get("value"),
            now=data.get("now"),
            moved=bool(data["moved"]),
        )


@dataclasses.dataclass(frozen=True)
class Rechecked:
    """An item of evidence asked again: the ``item`` as quoted, what it
    says ``now`` (or the ``error`` asking it), whether it is ``stale``."""

    item: Evidence
    now: str | None
    error: str | None
    stale: bool


@dataclasses.dataclass(frozen=True)
class Suggestion:
    """A suggestion as it was read: ``state`` is ``pending``, ``accepted``,
    ``dismissed`` or ``superseded``."""

    id: str
    author: Author
    time: float
    label: str
    edits: tuple[Proposal, ...]
    rationale: str
    evidence: tuple[Evidence, ...]
    thread: str | None
    supersedes: str | None
    state: Literal["pending", "accepted", "dismissed", "superseded"]
    accepted: tuple[int, ...]
    reason: str | None
    superseded_by: str | None
    decided_by: Author | None
    _call: Caller = dataclasses.field(repr=False, compare=False)

    @staticmethod
    def _of(call: Caller, data: dict[str, Any]) -> Suggestion:
        decided = data.get("decided_by")
        return Suggestion(
            id=data["id"],
            author=Author._of(data["author"]),
            time=data["millis"] / 1000.0,
            label=data["label"],
            edits=tuple(Proposal._of(edit) for edit in data["edits"]),
            rationale=data["rationale"],
            evidence=tuple(Evidence._of(item) for item in data["evidence"]),
            thread=data.get("thread"),
            supersedes=data.get("supersedes"),
            state=data["state"],
            accepted=tuple(data.get("accepted", [])),
            reason=data.get("reason"),
            superseded_by=data.get("superseded_by"),
            decided_by=None if decided is None else Author._of(decided),
            _call=call,
        )

    def accept(self, edits: Iterable[int] | None = None) -> HistoryEntry | None:
        """Accepts it: the edits numbered ``edits`` (all if ``None``), one
        undo step of this identity's naming who suggested it. The change
        made (``None`` if it changed nothing)."""
        done = self._call("suggestions.accept", {"id": self.id, "edits": list(edits or [])})
        entry = done.get("entry") if done else None
        if entry is None:
            return None
        from binbun._native import _history_entry

        return _history_entry(entry)

    def dismiss(self, reason: str = "") -> Suggestion:
        """Dismisses it, saying why: it as it is now."""
        return Suggestion._of(self._call, self._call("suggestions.dismiss", {"id": self.id, "reason": reason}))

    def recheck(self) -> list[Rechecked]:
        """Its evidence asked again against the analysis now, stale items
        marked."""
        return [
            Rechecked(Evidence._of(item["item"]), item.get("now"), item.get("error"), bool(item["stale"]))
            for item in self._call("suggestions.recheck", {"id": self.id})
        ]

    def refresh(self) -> Suggestion:
        """It as it is now."""
        found = Suggestions(self._call).get(self.id)
        if found is None:
            from binbun._errors import ConversationError

            raise ConversationError(f"no suggestion {self.id}")
        return found


class Suggestions:
    """``db.suggestions``: every suggestion (iterating), by state, by id.
    Suggestions are made with ``db.suggestion(...)``."""

    def __init__(self, call: Caller) -> None:
        self._call = call

    def _list(self, state: str | None = None) -> list[Suggestion]:
        return [Suggestion._of(self._call, data) for data in self._call("suggestions.list", {"state": state})]

    def __iter__(self) -> Iterator[Suggestion]:
        return iter(self._list())

    def __len__(self) -> int:
        return len(self._list())

    def pending(self) -> list[Suggestion]:
        """Those waiting for review."""
        return self._list("pending")

    def accepted(self) -> list[Suggestion]:
        """Those accepted."""
        return self._list("accepted")

    def get(self, id: str) -> Suggestion | None:
        """Suggestion ``id``, if made."""
        data = self._call("suggestions.get", {"id": id})
        return None if data is None else Suggestion._of(self._call, data)


class SuggestionDraft:
    """``with db.suggestion(label, rationale=..., evidence=[...],
    thread=...) as s:``: the writes made in the block on this thread
    (``db.functions.set_name(f, ...)``, ``CVariable.rename``...) are
    recorded instead of made (each checked as it is made, after those
    before it), and become a suggestion when the block ends: ``s.suggestion``
    (``None`` until then). An exception leaving the block makes none. A
    transaction, an undo or another suggestion inside the block is a
    ``TransactionError``; threads and posts are written as usual.

    ``supersedes``: a suggestion of this identity's (or its id) the new
    one is the next version of; its label, rationale, evidence and thread
    are kept unless given."""

    def __init__(
        self,
        db: _Recorder,
        call: Caller,
        label: str | None = None,
        *,
        rationale: str | None = None,
        evidence: Iterable[_Citable] | None = None,
        thread: Thread | str | None = None,
        supersedes: Suggestion | str | None = None,
    ) -> None:
        old: Suggestion | None = None
        if supersedes is not None:
            old = supersedes if isinstance(supersedes, Suggestion) else Suggestions(call).get(supersedes)
            if old is None:
                from binbun._errors import ConversationError

                raise ConversationError(f"no suggestion {supersedes}")
        if label is None:
            if old is None:
                raise TypeError('a suggestion has a label: db.suggestion("Name parse_args", ...)')
            label = old.label
        if evidence is None:
            evidence = () if old is None else old.evidence
        if thread is None and old is not None:
            thread = old.thread
        self._db = db
        self._call = call
        self.label: str = label
        """What it does, for people."""
        self.rationale: str = rationale if rationale is not None else ("" if old is None else old.rationale)
        """Why."""
        self._evidence = _evidence(evidence)
        self._thread = None if thread is None else _id(thread)
        self._supersedes = None if old is None else old.id
        self.suggestion: Suggestion | None = None
        """The suggestion made, once the block ended."""

    def __enter__(self) -> SuggestionDraft:
        self._db._record()
        return self

    def __exit__(self, exc_type: object, _exc: object = None, _traceback: object = None) -> Literal[False]:
        edits = self._db._recorded()
        if exc_type is not None:
            return False
        if not edits:
            raise ValueError(f"the block of suggestion {self.label!r} made no write: nothing to suggest")
        params = {
            "label": self.label,
            "edits": edits,
            "rationale": self.rationale,
            "evidence": self._evidence,
            "thread": self._thread,
        }
        if self._supersedes is None:
            data = self._call("suggestions.make", params)
        else:
            data = self._call("suggestions.supersede", {"id": self._supersedes, **params})
        self.suggestion = Suggestion._of(self._call, data)
        return False

    def __repr__(self) -> str:
        return f"<binbun.SuggestionDraft {self.label!r}>"


@dataclasses.dataclass(frozen=True)
class Member:
    """Someone in the session: a person or an agent (``kind``), their
    ``name``, their ``role`` in the shared project (``owner``, ``editor``,
    ``viewer``, ``agent``; ``None`` unless it is shared), whether they are
    ``online``, whether it is ``you`` (the binbun's own user), and
    ``key``, their identity (hexadecimal). A post mentions them by it
    (``mentions=[member]``)."""

    key: str
    name: str
    kind: Literal["person", "agent"]
    role: str | None
    online: bool
    you: bool = False

    @staticmethod
    def _of(data: dict[str, Any]) -> Member:
        kind: Literal["person", "agent"] = "agent" if data.get("kind") == "agent" else "person"
        return Member(
            key=str(data["key"]),
            name=str(data["name"]),
            kind=kind,
            role=data.get("role"),
            online=bool(data.get("online")),
            you=bool(data.get("you")),
        )


class Members(Sequence[Member]):
    """``db.session.members``: who is in the session, a sequence (this
    binbun's user first), also looked up by name or by key
    (``members["alice"]``): ``KeyError`` if none is, ``AmbiguousError``
    (naming their keys) if a name is several members'."""

    def __init__(self, members: Iterable[Member]) -> None:
        self._members = tuple(members)

    @overload
    def __getitem__(self, index: int) -> Member: ...
    @overload
    def __getitem__(self, index: slice) -> tuple[Member, ...]: ...
    @overload
    def __getitem__(self, index: str) -> Member: ...
    def __getitem__(self, index: int | slice | str) -> Member | tuple[Member, ...]:
        if not isinstance(index, str):
            return self._members[index]
        by_key = [m for m in self._members if m.key == index]
        found = by_key or [m for m in self._members if m.name == index]
        if len(found) == 1:
            return found[0]
        if not found:
            raise KeyError(f"no member is named {index!r} or has that key")
        from binbun._errors import AmbiguousError

        keys = ", ".join(m.key for m in found)
        raise AmbiguousError(f"{len(found)} members are named {index!r}: keys {keys}")

    def __len__(self) -> int:
        return len(self._members)

    def __iter__(self) -> Iterator[Member]:
        return iter(self._members)

    def __repr__(self) -> str:
        return f"Members({list(self._members)!r})"


class Session:
    """``db.session``: the session the database is in."""

    def __init__(self, call: Caller) -> None:
        self._call = call

    @property
    def members(self) -> Members:
        """Who is in the session, people and agents, this binbun's user
        first: in a shared project its members, else the user and the
        agents that worked here; ``members["alice"]`` by name or key."""
        return Members(Member._of(data) for data in self._call("session.members", None))


__all__ = [
    "Anchor",
    "Author",
    "Caller",
    "Evidence",
    "Member",
    "Members",
    "Mention",
    "Post",
    "Proposal",
    "Rechecked",
    "Session",
    "Suggestion",
    "SuggestionDraft",
    "Suggestions",
    "Thread",
    "Threads",
]
