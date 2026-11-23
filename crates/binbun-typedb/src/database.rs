//! A type database as generated from one source (C headers, Windows
//! metadata, syzkaller descriptions): the functions and types it declares,
//! with types referring to each other by key. The file format is
//! [`jsonl`](crate::jsonl)'s; [`TypeLibrary::add`](crate::TypeLibrary::add)
//! loads a database.

use serde::{Deserialize, Serialize};

use crate::types::{Enum, FloatFormat, Opaque, Record, Signature, Typedef};
use crate::{Origin, is_false};

/// A type database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Database {
    /// What it was generated from and for.
    pub header: Header,
    /// The functions it declares.
    pub functions: Vec<Function>,
    /// The named types it defines, each under a key unique in the
    /// database.
    pub types: Vec<Definition<TypeRef>>,
}

/// What a database was generated from and for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The schema version, [`SCHEMA_VERSION`].
    pub binbun_typedb: u32,
    /// The kind of source every declaration in it comes from.
    pub source: Source,
    /// The target the declarations are for.
    pub target: Target,
    /// The generator and the version of the library it parsed with (e.g.
    /// `binbun-typegen 0.0.0, libclang 22.1.8`).
    pub generator: String,
    /// The inputs, as the generating script names them (package versions,
    /// a commit).
    pub inputs: Vec<String>,
}

/// The schema version databases are written in. A file of another version
/// is refused: a fact must not be misread or silently dropped.
/// Version 2 added [`Function::number`].
pub const SCHEMA_VERSION: u32 = 2;

/// The kind of source a database's declarations come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// C headers, parsed by libclang.
    Header,
    /// Windows metadata (`.winmd`).
    Winmd,
    /// syzkaller's syscall descriptions (syzlang). Its functions are
    /// system calls, not library functions.
    Syzlang,
}

impl Source {
    /// The origin of the facts from this source.
    pub fn origin(self) -> Origin {
        match self {
            Self::Header => Origin::Header,
            Self::Winmd => Origin::Winmd,
            Self::Syzlang => Origin::Syzlang,
        }
    }
}

/// The target a database's declarations are for. Free strings, matched as
/// they are.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    /// The architecture (`x86_64`, `aarch64`).
    pub arch: String,
    /// The operating system (`linux`, `windows`).
    pub os: String,
    /// The environment (`gnu`, `msvc`).
    pub env: String,
    /// The size of a pointer in bytes.
    pub pointer_size: u8,
}

/// A function a database declares.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Function {
    /// Its name as linked: what an import or symbol says (a header's
    /// `__asm__` label, not the C name it redirects).
    pub name: String,
    /// The library it is imported from, if the source says (Windows
    /// metadata names the DLL; headers name none, so an ELF import, which
    /// may name its symbol version's library, matches the entry for any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    /// Its prototype.
    pub signature: Signature<TypeRef>,
    /// Whether the source declares that it never returns (`_Noreturn`,
    /// `__attribute__((noreturn))`, `[DoesNotReturn]`). `false` says
    /// nothing: a declaration without the attribute is no evidence that a
    /// function returns.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_return: bool,
    /// Whether the source declares that it never throws an exception
    /// (C++ `throw()` or `noexcept`, `__attribute__((nothrow))`,
    /// `__declspec(nothrow)`). `false` says nothing, as for `no_return`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_throw: bool,
    /// The format string the declaration says it takes
    /// (`__attribute__((format(printf, 1, 2)))`), if it states one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<Format>,
    /// The parameters whose format string its result is, translated
    /// (`__attribute__((format_arg(n)))`, counted from 1; `ngettext` has
    /// two): GCC checks a call whose format is such a result against
    /// these arguments' strings, on GNU gettext's documented contract that
    /// a translation keeps its message's conversions. Empty where the
    /// declaration states none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub format_arg: Vec<u32>,
    /// The parameters whose value is the size in bytes of the object it
    /// returns, counted from 1: one (`__attribute__((alloc_size(1)))`, as
    /// `malloc`'s), or two whose product it is (`alloc_size(1, 2)`, as
    /// `calloc`'s); `None` where the declaration states none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alloc_size: Option<Vec<u32>>,
    /// A system call's number on the database's target (the kernel's
    /// `__NR_` constant), in a system call database ([`Source::Syzlang`])
    /// for a call the target's table has; `None` otherwise. A call
    /// reads exactly its [`Signature::params`]' arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
}

/// A declared format string parameter: GCC's and Clang's
/// `__attribute__((format(archetype, string, first)))`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Format {
    /// The style of its conversion specifications as the attribute names
    /// it, without the underscores it may be spelled with (`printf`,
    /// `scanf`, `strftime`, `strfmon`, `gnu_printf`, `NSString`).
    pub archetype: String,
    /// The format string's parameter, counted from 1.
    pub string: u32,
    /// The first argument it describes, counted from 1; 0 where the
    /// arguments are not passed to it (a `va_list`, as `vprintf` takes).
    pub first: u32,
}

/// A reference to a type in a database: built from primitives, or naming a
/// type the same database defines.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeRef {
    /// `void`.
    Void,
    /// `_Bool`.
    Bool,
    /// Plain `char`, whose signedness the target decides.
    Char {
        /// Whether `char` is signed on the target.
        signed: bool,
    },
    /// An integer.
    Int {
        /// Whether it is signed.
        signed: bool,
        /// Its size in bytes.
        size: u8,
    },
    /// A floating-point number.
    Float(FloatFormat),
    /// A pointer.
    Pointer(Box<TypeRef>),
    /// An array.
    Array {
        /// The element type.
        element: Box<TypeRef>,
        /// The number of elements (`None`: unbounded, `T[]`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
    },
    /// A function type (a pointer to one is a [`Pointer`](Self::Pointer)
    /// to it).
    Function(Box<Signature<TypeRef>>),
    /// The type the database defines under this key: for C, as a reference
    /// spells it (`struct stat`, `union sigval`, `enum idtype_t`,
    /// `size_t`). Keys of anonymous types say where they appear, in
    /// parentheses no C name contains: `struct (__sigset_t)` is the
    /// structure typedef `__sigset_t` names, `union (struct
    /// sigaction).__sigaction_handler` the type of that field, `(…).#2` an
    /// unnamed member by index.
    Named(String),
}

/// A type a database defines under a key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Definition<R> {
    /// A structure or union.
    Record(Record<R>),
    /// An enumeration or flag set.
    Enum(Enum),
    /// A typedef.
    Typedef(Typedef<R>),
    /// A type named but not described.
    Opaque(Opaque),
}

impl<R> Definition<R> {
    /// Its key.
    pub fn key(&self) -> &str {
        match self {
            Self::Record(record) => &record.key,
            Self::Enum(definition) => &definition.key,
            Self::Typedef(typedef) => &typedef.key,
            Self::Opaque(opaque) => &opaque.key,
        }
    }
}
