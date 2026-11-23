import enum
from collections.abc import Iterator
from typing import final

from binbun._enums import Access, TextOptions
from binbun._native import Branch, Invalid, Sweep, Token

_Data = bytes | bytearray | memoryview

LENGTH: int

class Cond(enum.IntEnum):
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
    NONE = 0
    B = 1
    H = 2
    S = 3
    D = 4
    Q = 5

class Predication(enum.IntEnum):
    NONE = 0
    ZEROING = 1
    MERGING = 2

class ConditionKind(enum.IntEnum):
    FLAGS = 1
    ZERO = 2
    BIT = 3
    COMPARE = 4

class CompareKind(enum.IntEnum):
    REGISTER = 1
    IMMEDIATE = 2

class Flag(enum.IntFlag):
    V = 1
    C = 2
    Z = 4
    N = 8

class MemoryKind(enum.IntEnum):
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
    HEX = 1
    DECIMAL = 2
    PADDED_HEX = 3

class ListStyle(enum.IntEnum):
    COMMAS = 1
    RANGE = 2

class ShiftKind(enum.IntEnum):
    LSL = 1
    LSR = 2
    ASR = 3
    ROR = 4
    MSL = 5
    MUL = 6

class ExtendKind(enum.IntEnum):
    UXTB = 1
    UXTH = 2
    UXTW = 3
    UXTX = 4
    SXTB = 5
    SXTH = 6
    SXTW = 7
    SXTX = 8

class OffsetKind(enum.IntEnum):
    NONE = 0
    IMMEDIATE = 1
    REGISTER = 2
    VECTOR_LENGTH = 3

class Writeback(enum.IntEnum):
    NONE = 0
    PRE = 1
    POST = 2

class Modifier(enum.IntEnum):
    NONE = 0
    SHIFT = 1
    EXTEND = 2

class LabelBase(enum.IntEnum):
    INSTRUCTION = 1
    PAGE = 2

class NameKind(enum.IntEnum):
    PREFETCH = 1
    BARRIER = 2
    BRANCH_TARGET = 3
    PSTATE_FIELD = 4
    PATTERN = 5
    SYSTEM_OPERATION = 6
    KEYWORD = 7

class SliceDirection(enum.IntEnum):
    NONE = 0
    HORIZONTAL = 1
    VERTICAL = 2

class ZaListKind(enum.IntEnum):
    SLICE = 1
    TILES = 2

def decode_word(word: int, address: int = ...) -> Instruction: ...
def decode(data: _Data, address: int = ...) -> Instruction: ...
def sweep(data: _Data, address: int = ...) -> Sweep: ...
@final
class Decoder:
    def __new__(cls, data: _Data, address: int = ...) -> Decoder: ...
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
    def word(self) -> int: ...
    @property
    def length(self) -> int: ...
    def __len__(self) -> int: ...
    @property
    def bytes(self) -> bytes: ...
    @property
    def encoding(self) -> str: ...
    @property
    def encoding_mnemonic(self) -> str: ...
    @property
    def features(self) -> list[str]: ...
    @property
    def mnemonic(self) -> str: ...
    @property
    def branch(self) -> Branch: ...
    @property
    def computed_address(self) -> int | None: ...
    @property
    def condition(self) -> Condition | None: ...
    @property
    def flags(self) -> Flags: ...
    @property
    def memory(self) -> MemoryAccess | None: ...
    @property
    def implicit_reads(self) -> list[Register]: ...
    @property
    def implicit_writes(self) -> list[Register]: ...
    @property
    def operands(self) -> tuple[Operand, ...]: ...
    def text(self, options: TextOptions | int = 0) -> str: ...
    def tokens(self, options: TextOptions | int = 0) -> list[Token]: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

_Value = (
    Register
    | RegisterList
    | Immediate
    | Float
    | Shift
    | Extend
    | Memory
    | Label
    | Cond
    | SystemRegister
    | Named
    | Za
    | ZaList
    | int
    | IndexedRegister
)

@final
class Operand:
    @property
    def kind(self) -> OperandKind: ...
    @property
    def access(self) -> Access: ...
    @property
    def value(self) -> _Value: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class Register:
    @property
    def register_class(self) -> RegisterClass: ...
    @property
    def number(self) -> int: ...
    @property
    def lanes(self) -> int: ...
    @property
    def element(self) -> Element: ...
    @property
    def index(self) -> int | None: ...
    @property
    def predication(self) -> Predication: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class RegisterList:
    @property
    def first(self) -> Register: ...
    @property
    def count(self) -> int: ...
    @property
    def stride(self) -> int: ...
    @property
    def style(self) -> ListStyle: ...
    @property
    def registers(self) -> list[Register]: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Immediate:
    @property
    def value(self) -> int: ...
    @property
    def signed(self) -> bool: ...
    @property
    def radix(self) -> Radix: ...
    def __int__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Float:
    @property
    def value(self) -> float: ...
    @property
    def exact(self) -> bool: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class Shift:
    @property
    def kind(self) -> ShiftKind: ...
    @property
    def amount(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Extend:
    @property
    def kind(self) -> ExtendKind: ...
    @property
    def amount(self) -> int | None: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Memory:
    @property
    def base(self) -> Register: ...
    @property
    def offset_kind(self) -> OffsetKind: ...
    @property
    def offset(self) -> int: ...
    @property
    def offset_signed(self) -> bool: ...
    @property
    def offset_radix(self) -> Radix | None: ...
    @property
    def index(self) -> Register | None: ...
    @property
    def modifier(self) -> Modifier: ...
    @property
    def modifier_kind(self) -> ShiftKind | ExtendKind | None: ...
    @property
    def modifier_amount(self) -> int | None: ...
    @property
    def writeback(self) -> Writeback: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Label:
    @property
    def offset(self) -> int: ...
    @property
    def base(self) -> LabelBase: ...
    @property
    def radix(self) -> Radix: ...
    @property
    def target(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class SystemRegister:
    @property
    def name(self) -> str | None: ...
    @property
    def encoding(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Named:
    @property
    def kind(self) -> NameKind: ...
    @property
    def name(self) -> str: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Za:
    @property
    def tile(self) -> int | None: ...
    @property
    def element(self) -> Element: ...
    @property
    def direction(self) -> SliceDirection: ...
    @property
    def slice_index(self) -> int | None: ...
    @property
    def slice_offset(self) -> int: ...
    @property
    def slice_last(self) -> int | None: ...
    @property
    def group(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class ZaList:
    @property
    def kind(self) -> ZaListKind: ...
    @property
    def tiles(self) -> int: ...
    @property
    def za(self) -> Za | None: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class IndexedRegister:
    @property
    def register(self) -> Register: ...
    @property
    def index(self) -> Register: ...
    @property
    def offset(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Condition:
    @property
    def kind(self) -> ConditionKind: ...
    @property
    def cond(self) -> Cond | None: ...
    @property
    def sense(self) -> bool: ...
    @property
    def bit(self) -> int: ...
    @property
    def register(self) -> Register | None: ...
    @property
    def right_kind(self) -> CompareKind | None: ...
    @property
    def right_register(self) -> Register | None: ...
    @property
    def right_immediate(self) -> int | None: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Flags:
    @property
    def read(self) -> Flag: ...
    @property
    def written(self) -> Flag: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class MemoryAccess:
    @property
    def kind(self) -> MemoryKind: ...
    @property
    def size(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

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
