"""The exceptions binbun raises.

Each derives from :class:`BinbunError` and, where one fits, from the
built-in it refines, so ``except LookupError`` catches an
:class:`InvalidAddressError`.
"""

from __future__ import annotations

import builtins

from binbun._enums import Status


class BinbunError(Exception):
    """The root of binbun's exceptions."""


class OpenError(BinbunError, OSError):
    """The file cannot be read, or is no image binbun reads."""


class ProjectError(BinbunError):
    """The project cannot be read or written."""


class NotAnalysedError(BinbunError, RuntimeError):
    """A read needs a stage the analysis did not reach (it stopped)."""


class InvalidAddressError(BinbunError, LookupError):
    """An address in no segment."""


class NoFunctionError(BinbunError, KeyError):
    """No function starts at the address (``db.functions[ea]``: a
    ``KeyError``, as indexing raises)."""


class NoVariableError(BinbunError, LookupError):
    """The document has no such variable."""


class StaleError(BinbunError):
    """The analysis changed under an iterator or a handle."""


class FunctionGoneError(StaleError):
    """A function handle's entry is no longer a function."""


class DecompileError(BinbunError):
    """The function does not decompile (as ``binbun decompile`` says)."""


class TimeoutError(BinbunError, builtins.TimeoutError):  # noqa: A001 - the API's name
    """A ``timeout=`` elapsed; the work goes on and its result is kept."""


class CancelledError(BinbunError):
    """Ctrl-C or ``db.cancel()`` stopped it."""


class CDeclarationError(BinbunError, ValueError):
    """C refused (a prototype, a type, a definition): ``message`` says
    why, ``span`` is the ``(start, end)`` bytes of ``c`` at fault."""

    message: str
    span: tuple[int, int]
    c: str

    def __init__(self, message: str, span: tuple[int, int] = (0, 0), c: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.span = (int(span[0]), int(span[1]))
        self.c = c


class CorrectionError(BinbunError, ValueError):
    """A correction of recovery cannot apply there (the reason)."""


class TransactionError(BinbunError):
    """A transaction misused: none open, rolled back by an inner one, or
    another thread's open while this one writes."""


class ConversationError(BinbunError):
    """A thread, post or suggestion cannot be written: none such, another's
    (only its author edits a post; only its author or an owner deletes
    it), or a suggestion no longer pending."""


class ReadOnlyError(BinbunError):
    """Writes are refused here."""


class CapabilityError(BinbunError):
    """The server connected to lacks what the call needs (raised before
    anything is sent)."""


class AmbiguousError(BinbunError, LookupError):
    """A lookup that names none or several: no database, or several open
    and none named; a name several members of the session have. The
    message lists them."""


class ProtocolError(BinbunError):
    """A malformed or unexpected message on the connection."""


class VersionError(BinbunError):
    """The client and the server speak no protocol version in common."""


class ConnectionError(BinbunError, builtins.ConnectionError):  # noqa: A001 - the API's name
    """The connection to the server failed or was lost."""


class PermissionError(BinbunError, builtins.PermissionError):  # noqa: A001 - the API's name
    """The server's directory or socket is another user's."""


class DecodeError(BinbunError, ValueError):
    """Bytes that are no instruction (``binbun.x86``, ``binbun.aarch64``):
    ``status`` says why, ``address`` where."""

    status: Status
    address: int

    def __init__(self, message: str, status: Status, address: int) -> None:
        super().__init__(message)
        self.status = status
        self.address = address
