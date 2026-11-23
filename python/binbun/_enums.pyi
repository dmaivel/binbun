import enum

class Stage(enum.IntEnum):
    OPENING = 0
    IMAGE = 1
    ANALYSED = 2
    REFERENCED = 3
    SIGNATURES = 4
    CALLERS = 5
    WARMED = 6

class View(enum.Enum):
    EXACT = "exact"
    READING = "reading"

class Format(enum.Enum):
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"

class Machine(enum.Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    AARCH64 = "aarch64"
    ARM = "arm"
    OTHER = "other"

class Arch(enum.Enum):
    X86 = "x86"
    AARCH64 = "aarch64"

class XrefKind(enum.Enum):
    CALL = "call"
    JUMP = "jump"
    READ = "read"
    WRITE = "write"
    ADDRESS = "address"
    POINTER = "pointer"

class NumberForm(enum.Enum):
    HEX = "hex"
    DECIMAL = "decimal"
    CHAR = "char"

class Unit(enum.Enum):
    BYTE = "byte"
    WORD = "word"
    DWORD = "dword"
    QWORD = "qword"
    STRING = "string"
    UTF16 = "utf16"

class Status(enum.IntEnum):
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
    def is_invalid(self) -> bool: ...

class Access(enum.IntFlag):
    READ = 1
    WRITE = 2

class BranchKind(enum.IntEnum):
    NONE = 0
    JUMP = 1
    CALL = 2
    RETURN = 3
    TRAP = 4
    SYSTEM_CALL = 5
    EXCEPTION_RETURN = 6
    HALT = 7

class TargetKind(enum.IntEnum):
    NONE = 0
    ADDRESS = 1
    POINTER = 2
    INDIRECT = 3
    FAR = 4

class TextOptions(enum.IntFlag):
    DEFAULT = 0
    RELATIVE_LABELS = 1

class TokenKind(enum.IntEnum):
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
