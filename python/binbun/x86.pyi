import enum
from collections.abc import Iterator
from typing import final

from binbun._enums import Access, TextOptions
from binbun._native import Branch, Invalid, Sweep, Token

_Data = bytes | bytearray | memoryview

MAX_LENGTH: int

class Mode(enum.IntEnum):
    REAL16 = 1
    REAL32 = 2
    BITS16 = 3
    BITS32 = 4
    BITS64 = 5

class Encoding(enum.IntEnum):
    LEGACY = 1
    VEX = 2
    EVEX = 3
    XOP = 4

class Condition(enum.IntEnum):
    NONE = 0
    O = 1  # noqa: E741
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
    CF = 1
    PF = 4
    AF = 16
    ZF = 64
    SF = 128
    TF = 256
    IF = 512
    DF = 1024
    OF = 2048
    IOPL = 12288
    NT = 16384
    RF = 65536
    VM = 131072
    AC = 262144
    VIF = 524288
    VIP = 1048576
    ID = 2097152
    FC0 = 268435456
    FC1 = 536870912
    FC2 = 1073741824
    FC3 = 2147483648

class OperandKind(enum.IntEnum):
    REGISTER = 1
    MEMORY = 2
    IMMEDIATE = 3
    SECOND_IMMEDIATE = 4
    RELATIVE = 5
    FIELD = 6

class OperandField(enum.IntEnum):
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
    EXPLICIT = 1
    IMPLICIT = 2
    SUPPRESSED = 3

class Action(enum.IntEnum):
    READ = 1
    WRITE = 2
    READ_WRITE = 3
    CONDITIONAL_READ = 4
    CONDITIONAL_WRITE = 5
    CONDITIONAL_READ_WRITE = 6
    READ_CONDITIONAL_WRITE = 7

def decode(data: _Data, address: int = ..., mode: Mode | int = ...) -> Instruction: ...
def decode_length(data: _Data, mode: Mode | int = ...) -> int: ...
def sweep(data: _Data, address: int = ..., mode: Mode | int = ...) -> Sweep: ...
@final
class Decoder:
    def __new__(cls, data: _Data, address: int = ..., mode: Mode | int = ...) -> Decoder: ...
    @property
    def offset(self) -> int: ...
    @offset.setter
    def offset(self, value: int) -> None: ...
    @property
    def address(self) -> int: ...
    def __iter__(self) -> Iterator[Instruction | Invalid]: ...
    def __next__(self) -> Instruction | Invalid: ...

@final
class Instruction:
    @property
    def address(self) -> int: ...
    @property
    def length(self) -> int: ...
    def __len__(self) -> int: ...
    @property
    def bytes(self) -> bytes: ...
    @property
    def mode(self) -> Mode: ...
    @property
    def mnemonic(self) -> str: ...
    @property
    def form(self) -> str: ...
    @property
    def category(self) -> str: ...
    @property
    def extension(self) -> str: ...
    @property
    def isa_set(self) -> str: ...
    @property
    def encoding(self) -> Encoding: ...
    @property
    def condition(self) -> Condition: ...
    @property
    def operand_width(self) -> int: ...
    @property
    def address_width(self) -> int: ...
    @property
    def stack_address_width(self) -> int: ...
    @property
    def branch(self) -> Branch: ...
    @property
    def computed_address(self) -> int | None: ...
    @property
    def flags(self) -> Flags: ...
    @property
    def operands(self) -> tuple[Operand, ...]: ...
    def text(self, options: TextOptions | int = 0) -> str: ...
    def tokens(self, options: TextOptions | int = 0) -> list[Token]: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Operand:
    @property
    def kind(self) -> OperandKind: ...
    @property
    def field(self) -> OperandField: ...
    @property
    def visibility(self) -> Visibility: ...
    @property
    def action(self) -> Action: ...
    @property
    def access(self) -> Access: ...
    @property
    def bits(self) -> int: ...
    @property
    def register(self) -> str | None: ...
    @property
    def segment(self) -> str | None: ...
    @property
    def base(self) -> str | None: ...
    @property
    def index(self) -> str | None: ...
    @property
    def scale(self) -> int: ...
    @property
    def displacement(self) -> int: ...
    @property
    def memory_size(self) -> int: ...
    @property
    def value(self) -> int: ...
    @property
    def signed_immediate(self) -> bool: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Flags:
    @property
    def read(self) -> Flag: ...
    @property
    def written(self) -> Flag: ...
    @property
    def undefined(self) -> Flag: ...
    @property
    def may_write(self) -> bool: ...
    @property
    def must_write(self) -> bool: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

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
