"""binbun's x86 decoder (16, 32 and 64-bit, XED-exact), without a database.

>>> from binbun import x86
>>> insn = x86.decode(b"\\x48\\x89\\xc7", address=0x1000)
>>> insn.text(), insn.length, insn.mnemonic
('mov rdi, rax', 3, 'mov')
>>> [str(i) for i in x86.Decoder(b"\\x55\\xc3", address=0x401000)]
['push rbp', 'ret']

The vocabulary is the C API's (``binbun/disasm.h``): every enum below has
the names and numbers of its ``BINBUN_X86_*`` constants, and
``binbun.Status``, ``binbun.Branch`` and ``binbun.Token`` are shared with
``binbun.aarch64``.
"""

from __future__ import annotations

import enum

from binbun import _native

_x86 = _native.x86

MAX_LENGTH: int = _x86.MAX_LENGTH
"""The longest instruction, in bytes (15)."""

decode = _x86.decode
decode_length = _x86.decode_length
sweep = _x86.sweep
Decoder = _x86.Decoder
Instruction = _x86.Instruction
Operand = _x86.Operand
Flags = _x86.Flags


class Mode(enum.IntEnum):
    """The processor mode (``binbun_x86_mode``)."""

    REAL16 = 1
    REAL32 = 2
    BITS16 = 3
    BITS32 = 4
    BITS64 = 5


class Encoding(enum.IntEnum):
    """How an instruction is encoded (``binbun_x86_encoding``)."""

    LEGACY = 1
    VEX = 2
    EVEX = 3
    XOP = 4


class Condition(enum.IntEnum):
    """The condition an instruction tests (``binbun_x86_condition``)."""

    NONE = 0
    O = 1  # noqa: E741 - the condition's name
    NO = 2
    B = 3
    NB = 4
    Z = 5
    NZ = 6
    BE = 7
    NBE = 8
    S = 9
    NS = 10
    P = 11
    NP = 12
    L = 13
    NL = 14
    LE = 15
    NLE = 16
    FALSE = 17
    TRUE = 18
    COUNT_ZERO = 19
    LOOP = 20
    LOOP_ZERO = 21
    LOOP_NOT_ZERO = 22
    TRANSACTION_ABORT = 23


class Flag(enum.IntFlag):
    """The flags (``BINBUN_X86_FLAG_*``): RFLAGS bit positions, and the x87
    condition codes C0-C3 in bits 28-31."""

    CF = 1 << 0
    PF = 1 << 2
    AF = 1 << 4
    ZF = 1 << 6
    SF = 1 << 7
    TF = 1 << 8
    IF = 1 << 9
    DF = 1 << 10
    OF = 1 << 11
    IOPL = 3 << 12
    NT = 1 << 14
    RF = 1 << 16
    VM = 1 << 17
    AC = 1 << 18
    VIF = 1 << 19
    VIP = 1 << 20
    ID = 1 << 21
    FC0 = 1 << 28
    FC1 = 1 << 29
    FC2 = 1 << 30
    FC3 = 1 << 31


class OperandKind(enum.IntEnum):
    """What an operand's value is (``binbun_x86_operand_kind``)."""

    REGISTER = 1
    MEMORY = 2
    IMMEDIATE = 3
    SECOND_IMMEDIATE = 4
    RELATIVE = 5
    FIELD = 6


class OperandField(enum.IntEnum):
    """Which decoder field holds an operand (``binbun_x86_operand_field``,
    XED's operand names)."""

    REG0 = 1
    REG1 = 2
    REG2 = 3
    REG3 = 4
    REG4 = 5
    REG5 = 6
    REG6 = 7
    REG7 = 8
    REG8 = 9
    REG9 = 10
    BASE0 = 11
    BASE1 = 12
    MEM0 = 13
    MEM1 = 14
    AGEN = 15
    IMM0 = 16
    IMM1 = 17
    RELBR = 18
    ABSBR = 19
    PTR = 20


class Visibility(enum.IntEnum):
    """Whether the text shows an operand (``binbun_x86_visibility``)."""

    EXPLICIT = 1
    IMPLICIT = 2
    SUPPRESSED = 3


class Action(enum.IntEnum):
    """How an instruction accesses an operand (``binbun_x86_action``)."""

    READ = 1
    WRITE = 2
    READ_WRITE = 3
    CONDITIONAL_READ = 4
    CONDITIONAL_WRITE = 5
    CONDITIONAL_READ_WRITE = 6
    READ_CONDITIONAL_WRITE = 7


__all__ = [
    "MAX_LENGTH",
    "Action",
    "Condition",
    "Decoder",
    "Encoding",
    "Flag",
    "Flags",
    "Instruction",
    "Mode",
    "Operand",
    "OperandField",
    "OperandKind",
    "Visibility",
    "decode",
    "decode_length",
    "sweep",
]
