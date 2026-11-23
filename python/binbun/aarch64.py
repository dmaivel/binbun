"""binbun's AArch64 decoder (A64: every encoding of the 2026-09 release of
Arm's A-profile specification, LLVM-exact text), without a database.

>>> import binbun
>>> from binbun import aarch64
>>> aarch64.decode_word(0x8B020020).text()
'add\\tx0, x1, x2'
>>> b = aarch64.decode_word(0x14000010, address=0x1000)
>>> b.text(), b.text(binbun.TextOptions.RELATIVE_LABELS), hex(b.branch.target)
('b\\t0x1040', 'b\\t#0x40', '0x1040')

The vocabulary is the C API's (``binbun/disasm.h``): every enum below has
the names and numbers of its ``BINBUN_AARCH64_*`` constants, and
``binbun.Status``, ``binbun.Branch`` and ``binbun.Token`` are shared with
``binbun.x86``.
"""

from __future__ import annotations

import enum

from binbun import _native

_aarch64 = _native.aarch64

LENGTH: int = _aarch64.LENGTH
"""Every instruction's length in bytes (4)."""

decode_word = _aarch64.decode_word
decode = _aarch64.decode
sweep = _aarch64.sweep
Decoder = _aarch64.Decoder
Instruction = _aarch64.Instruction
Operand = _aarch64.Operand
Register = _aarch64.Register
RegisterList = _aarch64.RegisterList
Immediate = _aarch64.Immediate
Float = _aarch64.Float
Shift = _aarch64.Shift
Extend = _aarch64.Extend
Memory = _aarch64.Memory
Label = _aarch64.Label
SystemRegister = _aarch64.SystemRegister
Named = _aarch64.Named
Za = _aarch64.Za
ZaList = _aarch64.ZaList
IndexedRegister = _aarch64.IndexedRegister
Condition = _aarch64.Condition
Flags = _aarch64.Flags
MemoryAccess = _aarch64.MemoryAccess


class Cond(enum.IntEnum):
    """A condition field (``binbun_aarch64_cond``): ``EQ`` 0 to ``NV`` 15."""

    EQ = 0
    NE = 1
    HS = 2
    LO = 3
    MI = 4
    PL = 5
    VS = 6
    VC = 7
    HI = 8
    LS = 9
    GE = 10
    LT = 11
    GT = 12
    LE = 13
    AL = 14
    NV = 15


class RegisterClass(enum.IntEnum):
    """The letter and width a register is written with
    (``binbun_aarch64_register_class``)."""

    W = 1
    X = 2
    WSP = 3
    XSP = 4
    B = 5
    H = 6
    S = 7
    D = 8
    Q = 9
    V = 10
    Z = 11
    P = 12
    PN = 13
    ZT = 14
    C = 15
    FFR = 16


class Element(enum.IntEnum):
    """An element size (``binbun_aarch64_element``)."""

    NONE = 0
    B = 1
    H = 2
    S = 3
    D = 4
    Q = 5


class Predication(enum.IntEnum):
    """A predicate qualifier (``binbun_aarch64_predication``)."""

    NONE = 0
    ZEROING = 1
    MERGING = 2


class ConditionKind(enum.IntEnum):
    """What a condition tests (``binbun_aarch64_condition_kind``)."""

    FLAGS = 1
    ZERO = 2
    BIT = 3
    COMPARE = 4


class CompareKind(enum.IntEnum):
    """What a compare-and-branch compares with (``binbun_aarch64_compare_kind``)."""

    REGISTER = 1
    IMMEDIATE = 2


class Flag(enum.IntFlag):
    """The condition flags, as they sit in NZCV (``BINBUN_AARCH64_FLAG_*``)."""

    V = 1 << 0
    C = 1 << 1
    Z = 1 << 2
    N = 1 << 3


class MemoryKind(enum.IntEnum):
    """What kind of memory access (``binbun_aarch64_memory_kind``)."""

    LOAD = 1
    STORE = 2
    ATOMIC = 3
    LOAD_EXCLUSIVE = 4
    STORE_EXCLUSIVE = 5
    PREFETCH = 6
    COPY = 7
    LOAD_TAG = 8
    STORE_TAG = 9


class OperandKind(enum.IntEnum):
    """What an operand is (``binbun_aarch64_operand_kind``), and so what its
    ``value`` is."""

    REGISTER = 1
    LIST = 2
    IMMEDIATE = 3
    FLOAT = 4
    SHIFT = 5
    EXTEND = 6
    MEMORY = 7
    WRITEBACK = 8
    LABEL = 9
    CONDITION = 10
    SYSTEM_REGISTER = 11
    NAMED = 12
    ZA = 13
    ZA_LIST = 14
    TABLE_SLICE = 15
    INDEXED_REGISTER = 16


class Radix(enum.IntEnum):
    """How a number is written (``binbun_aarch64_radix``)."""

    HEX = 1
    DECIMAL = 2
    PADDED_HEX = 3


class ListStyle(enum.IntEnum):
    """How a register list is written (``binbun_aarch64_list_style``)."""

    COMMAS = 1
    RANGE = 2


class ShiftKind(enum.IntEnum):
    """A shift (``binbun_aarch64_shift_kind``)."""

    LSL = 1
    LSR = 2
    ASR = 3
    ROR = 4
    MSL = 5
    MUL = 6


class ExtendKind(enum.IntEnum):
    """An extend (``binbun_aarch64_extend_kind``)."""

    UXTB = 1
    UXTH = 2
    UXTW = 3
    UXTX = 4
    SXTB = 5
    SXTH = 6
    SXTW = 7
    SXTX = 8


class OffsetKind(enum.IntEnum):
    """What a memory operand adds to its base (``binbun_aarch64_offset_kind``)."""

    NONE = 0
    IMMEDIATE = 1
    REGISTER = 2
    VECTOR_LENGTH = 3


class Writeback(enum.IntEnum):
    """Whether and when a memory operand's base is written back
    (``binbun_aarch64_writeback``)."""

    NONE = 0
    PRE = 1
    POST = 2


class Modifier(enum.IntEnum):
    """How a memory operand's index register is modified
    (``binbun_aarch64_modifier``)."""

    NONE = 0
    SHIFT = 1
    EXTEND = 2


class LabelBase(enum.IntEnum):
    """What a PC-relative address is relative to (``binbun_aarch64_label_base``)."""

    INSTRUCTION = 1
    PAGE = 2


class NameKind(enum.IntEnum):
    """What a named operand names (``binbun_aarch64_name_kind``)."""

    PREFETCH = 1
    BARRIER = 2
    BRANCH_TARGET = 3
    PSTATE_FIELD = 4
    PATTERN = 5
    SYSTEM_OPERATION = 6
    KEYWORD = 7


class SliceDirection(enum.IntEnum):
    """A ZA tile slice's direction (``binbun_aarch64_slice_direction``)."""

    NONE = 0
    HORIZONTAL = 1
    VERTICAL = 2


class ZaListKind(enum.IntEnum):
    """What a ZA list holds (``binbun_aarch64_za_list_kind``)."""

    SLICE = 1
    TILES = 2


__all__ = [
    "LENGTH",
    "CompareKind",
    "Cond",
    "Condition",
    "ConditionKind",
    "Decoder",
    "Element",
    "Extend",
    "ExtendKind",
    "Flag",
    "Flags",
    "Float",
    "Immediate",
    "IndexedRegister",
    "Instruction",
    "Label",
    "LabelBase",
    "ListStyle",
    "Memory",
    "MemoryAccess",
    "MemoryKind",
    "Modifier",
    "Named",
    "NameKind",
    "OffsetKind",
    "Operand",
    "OperandKind",
    "Predication",
    "Radix",
    "Register",
    "RegisterClass",
    "RegisterList",
    "Shift",
    "ShiftKind",
    "SliceDirection",
    "SystemRegister",
    "Writeback",
    "Za",
    "ZaList",
    "ZaListKind",
    "decode",
    "decode_word",
    "sweep",
]
