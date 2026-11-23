"""Query results the extension returns as Python values: the references
to an address (:class:`XrefsTo`), and records of a few fields
(``NamedTuple``\\ s, which still unpack as tuples). A record with an
``address`` is accepted wherever an address is."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from binbun._native import Function, SignatureMatch, Xref


class XrefsTo(list["Xref"]):
    """The references to an address (``db.xrefs.to_ea(ea)``,
    ``f.xrefs_to()``): a list of ``binbun.Xref`` that keeps the address,
    ``to_ea``, even when empty. As evidence (``evidence=[...]``): what
    refers to ``to_ea``, every kind (a ``kinds`` filter is not recorded)."""

    to_ea: int

    def __init__(self, to_ea: int, xrefs: Iterable[Xref] = ()) -> None:
        super().__init__(xrefs)
        self.to_ea = int(to_ea)

    def __repr__(self) -> str:
        return f"XrefsTo({self.to_ea:#x}, {list.__repr__(self)})"

    def _cite(self) -> dict[str, Any]:
        return {"kind": "xrefs_to", "to": f"{self.to_ea:#x}"}


class Named(NamedTuple):
    """A name at an address (``db.names.get_all()``,
    ``db.bookmarks.get_all()``)."""

    address: int
    name: str


class Comment(NamedTuple):
    """A comment at an address (``db.comments.get_all()``)."""

    address: int
    text: str


class CComment(NamedTuple):
    """A user's comment as the C prints it (``CDocument.comments``): its
    line's number, the address it is at, one line of its text."""

    line: int
    address: int
    text: str


class Use(NamedTuple):
    """Where a value goes (``Origins.uses``): the instruction, and how it
    is used there, in words."""

    address: int
    how: str


class Successor(NamedTuple):
    """Where control goes from a block (``Block.successors``): how
    (``next``, ``jump``, ``taken``, ``not_taken``, ``call_return``,
    ``table``, ``unwind``) and the address."""

    kind: str
    address: int


class CorrectedItem(NamedTuple):
    """An item the user made (``db.corrections.items()``): where, its kind
    (``code``, ``undefined`` or a unit's name: ``dword``, ``string``) and
    its size in bytes."""

    address: int
    kind: str
    size: int


class CorrectedFunction(NamedTuple):
    """A function the user made or ended (``db.corrections.functions()``):
    its entry and the address after it (``None``: where recovery ends
    it)."""

    start: int
    end: int | None


class FunctionMatch(NamedTuple):
    """A function a library signature matched (``db.signatures.matches()``)
    and what the signature says."""

    function: Function
    match: SignatureMatch


class Definition(NamedTuple):
    """A type the user defined (``db.types.definitions()``): the key it
    defines (``struct pair``) and its C."""

    key: str
    c: str


__all__ = [
    "CComment",
    "Comment",
    "CorrectedFunction",
    "CorrectedItem",
    "Definition",
    "FunctionMatch",
    "Named",
    "Successor",
    "Use",
    "XrefsTo",
]
