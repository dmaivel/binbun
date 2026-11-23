"""The enums of binbun's Python API (the extension builds its values from these)."""

from __future__ import annotations

import enum


class Stage(enum.IntEnum):
    """How far the analysis of an opened binary is (``binbun_session::Stage``)."""

    OPENING = 0
    IMAGE = 1
    ANALYSED = 2
    REFERENCED = 3
    SIGNATURES = 4
    CALLERS = 5
    WARMED = 6


class View(enum.Enum):
    """Which C: the exact C, or the reading view (checks assumed away)."""

    EXACT = "exact"
    READING = "reading"


class Format(enum.Enum):
    """The file's format."""

    ELF = "elf"
    PE = "pe"
    MACHO = "macho"


class Machine(enum.Enum):
    """The instruction set the file says its code is for."""

    X86 = "x86"
    X86_64 = "x86_64"
    AARCH64 = "aarch64"
    ARM = "arm"
    OTHER = "other"


class Arch(enum.Enum):
    """The architecture ``binbun.Decoder`` decodes for (x86 in a
    ``binbun.x86.Mode``)."""

    X86 = "x86"
    AARCH64 = "aarch64"


class XrefKind(enum.Enum):
    """How a cross-reference refers (``binbun::references::Kind``)."""

    CALL = "call"
    JUMP = "jump"
    READ = "read"
    WRITE = "write"
    ADDRESS = "address"
    POINTER = "pointer"


class NumberForm(enum.Enum):
    """How a number is written in the listing and the C (the ``H`` and
    ``R`` keys; ``binbun_session::NumberForm``)."""

    HEX = "hex"
    DECIMAL = "decimal"
    CHAR = "char"


class Unit(enum.Enum):
    """The units of a data item made by a correction (``binbun::corrections::Unit``)."""

    BYTE = "byte"
    WORD = "word"
    DWORD = "dword"
    QWORD = "qword"
    STRING = "string"
    UTF16 = "utf16"


# The decoders' vocabulary (``binbun.x86``, ``binbun.aarch64``): the C
# API's names and numbers (``binbun/disasm.h``), so ``int(Status.INVALID)``
# is ``BINBUN_STATUS_INVALID``.


class Status(enum.IntEnum):
    """What a decode came to (``binbun_status``); from ``INVALID`` to 63,
    why the bytes are no instruction."""

    OK = 0
    END = 1
    TRUNCATED = 2
    NULL_POINTER = 3
    BAD_ARGUMENT = 4
    FAILED = 5
    INVALID = 16
    X86_TOO_LONG = 17
    X86_INVALID_MODE = 18
    X86_BAD_REGISTER = 19
    X86_BAD_LOCK_PREFIX = 20
    X86_BAD_LEGACY_PREFIX = 21
    X86_BAD_REX_PREFIX = 22
    X86_BAD_MAP = 23
    X86_BAD_EVEX_V_PRIME = 24
    X86_BAD_EVEX_ZEROING = 25
    X86_BAD_EVEX_LENGTH = 26
    X86_GATHER_REGISTERS = 27
    X86_BAD_REGISTER_MATCH = 28
    AARCH64_UNALLOCATED = 32
    AARCH64_UNDEFINED = 33
    AARCH64_UNPREDICTABLE = 34

    @property
    def is_invalid(self) -> bool:
        """Whether the bytes are no instruction (``BINBUN_STATUS_IS_INVALID``)."""
        return Status.INVALID <= self <= 63


class Access(enum.IntFlag):
    """How an instruction may access an operand (``BINBUN_ACCESS_*``)."""

    READ = 1
    WRITE = 2


class BranchKind(enum.IntEnum):
    """How an instruction transfers control (``binbun_branch_kind``)."""

    NONE = 0
    JUMP = 1
    CALL = 2
    RETURN = 3
    TRAP = 4
    SYSTEM_CALL = 5
    EXCEPTION_RETURN = 6
    HALT = 7


class TargetKind(enum.IntEnum):
    """Where a jump or call goes, as far as the instruction tells
    (``binbun_target_kind``)."""

    NONE = 0
    ADDRESS = 1
    POINTER = 2
    INDIRECT = 3
    FAR = 4


class TextOptions(enum.IntFlag):
    """How to write an instruction's text (``BINBUN_TEXT_*``)."""

    DEFAULT = 0
    RELATIVE_LABELS = 1
    """AArch64 only: labels as offsets (``b #0x40``), as LLVM's C API
    writes them, instead of the addresses they name (``b 0x1040``)."""


class TokenKind(enum.IntEnum):
    """What a token of an instruction's text is (``binbun_token_kind``)."""

    MNEMONIC = 0
    PREFIX = 1
    REGISTER = 2
    IMMEDIATE = 3
    INTEGER = 4
    FLOAT = 5
    ADDRESS = 6
    DISPLACEMENT = 7
    SYMBOL = 8
    PUNCTUATION = 9
    SEPARATOR = 10
    WHITESPACE = 11
