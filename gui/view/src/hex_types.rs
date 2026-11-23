//! C as the hex view's template language: struct,
//! union, enumeration and typedef declarations read by the engine's C
//! parser ([`binbun_typedb::c`]), laid out as a C compiler for the
//! image's data model lays them out, as a tree of [`Node`]s: records with
//! their members, arrays with one element's layout (so a 10,000-entry
//! table costs one element), bit-fields with their bit ranges, scalars
//! with their enumeration's or flags' names, `char` arrays as text.
//!
//! The tree's leaves ([`Layout::leaves_in`]) are what the hex view tints:
//! each scalar, each array of scalars and each run of bit-fields, numbered
//! in offset order so neighbours differ.
//!
//! [`TypeSet::builtin`] holds the ELF and PE header structures (from
//! `<elf.h>` and `<winnt.h>`, with their names and their fields'
//! enumerations and flags), so headers are read and shown through the same
//! layouts as a struct the user writes.
//!
//! ```
//! use binbun_gui_view::hex_types::{DataModel, TypeSet};
//!
//! let mut types = TypeSet::builtin(DataModel::LP64);
//! let layout = types
//!     .apply("struct pair { uint16_t tag; char *name; }")
//!     .unwrap();
//! assert_eq!(layout.size, 16);
//! assert_eq!(layout.field("name").map(|(at, _)| at), Some(8));
//! assert_eq!(types.layout("Elf64_Ehdr").unwrap().size, 64);
//! ```

use std::collections::HashMap;
use std::fmt::Write as _;
use std::ops::Range;
use std::sync::Arc;

use binbun_ast::types::{Enumeration, Type as AstType, TypeId as AstId};
use binbun_debuginfo::info::DebugModel;
use binbun_debuginfo::info::model::{
    CompositeKind, Encoding, Type as DebugType, TypeId as DebugTypeId,
};
use binbun_session::GlobalTable;
use binbun_typedb::c::Scope;
use binbun_typedb::{Type, TypeId};

pub use binbun_typedb::c::{CError, DataModel};

/// What a scalar's bytes mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scalar {
    /// An integer, signed or not.
    Int {
        /// Whether it is signed.
        signed: bool,
    },
    /// A character.
    Char,
    /// A boolean.
    Bool,
    /// A binary floating-point number.
    Float,
    /// A pointer.
    Pointer,
}

/// The names of an enumeration's constants, or of a set of flags' bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names {
    /// Whether the constants are flags, combined with `|`.
    pub flags: bool,
    /// Each constant's name and value (two's complement in 64 bits), in
    /// declaration order.
    pub values: Vec<(String, u64)>,
}

impl Names {
    /// `value` by name: the enumeration's constant (`None` if it has
    /// none), or the flags set in it as `A|B` in declaration order, the
    /// bits no flag names after them in hex (`PF_R|0x100`).
    pub fn format(&self, value: u64) -> Option<String> {
        if !self.flags {
            return self
                .values
                .iter()
                .find(|(_, v)| *v == value)
                .map(|(name, _)| name.clone());
        }
        if value == 0 {
            return self
                .values
                .iter()
                .find(|(_, v)| *v == 0)
                .map(|(name, _)| name.clone());
        }
        let mut rest = value;
        let mut out = String::new();
        for (name, v) in &self.values {
            if *v != 0 && value & v == *v && rest & v != 0 {
                if !out.is_empty() {
                    out.push('|');
                }
                out.push_str(name);
                rest &= !v;
            }
        }
        if out.is_empty() {
            return None;
        }
        if rest != 0 {
            let _ = write!(out, "|0x{rest:X}");
        }
        Some(out)
    }
}

/// A bit-field of a run of them ([`Shape::Bits`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitField {
    /// Its name.
    pub name: String,
    /// Its declared type as C writes it.
    pub ty: String,
    /// Its first bit from the run's first byte (System V's numbering: from
    /// the least significant bit on a little-endian target, the most
    /// significant on a big-endian one).
    pub bit: u64,
    /// Its width in bits.
    pub width: u32,
    /// Whether it is signed.
    pub signed: bool,
    /// Its enumeration's names, if its type is one.
    pub names: Option<Arc<Names>>,
}

impl BitField {
    /// Its value in `bytes` (the run's, from its first byte), unsigned.
    pub fn read(&self, bytes: &[u8], little: bool) -> Option<u64> {
        if self.width == 0 || self.width > 64 {
            return None;
        }
        let mut v = 0u64;
        for k in 0..u64::from(self.width) {
            let p = self.bit + k;
            let byte = *bytes.get(usize::try_from(p / 8).ok()?)?;
            let bit = if little {
                (byte >> (p % 8)) & 1
            } else {
                (byte >> (7 - p % 8)) & 1
            };
            if little {
                v |= u64::from(bit) << k;
            } else {
                v = (v << 1) | u64::from(bit);
            }
        }
        Some(v)
    }

    /// Its value in `bytes` as C writes it: its constant's name, signed or
    /// unsigned.
    pub fn value(&self, bytes: &[u8], little: bool) -> String {
        let Some(v) = self.read(bytes, little) else {
            return String::new();
        };
        if let Some(name) = self.names.as_ref().and_then(|n| n.format(v)) {
            return name;
        }
        if self.signed && self.width < 64 && (v >> (self.width - 1)) & 1 == 1 {
            let shift = 64 - self.width;
            let signed = i64::from_ne_bytes((v << shift).to_ne_bytes()) >> shift;
            return signed.to_string();
        }
        v.to_string()
    }
}

/// What a [`Node`] is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shape {
    /// One scalar of the node's size.
    Scalar {
        /// What its bytes mean.
        scalar: Scalar,
        /// Its enumeration's names, if its type is one.
        names: Option<Arc<Names>>,
    },
    /// A `char` array: text.
    Text,
    /// An array: `count` of `element`, each its size apart.
    Array {
        /// One element, at offset 0.
        element: Arc<Node>,
        /// How many there are.
        count: u64,
    },
    /// A struct or union.
    Record {
        /// Whether it is a union (its members overlap).
        union: bool,
        /// Its members, in declaration order.
        members: Vec<Node>,
    },
    /// A run of bit-fields sharing bytes.
    Bits(Vec<BitField>),
}

/// A laid-out type, or a member of one: a node of a [`Layout`]'s tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Its name: the member's (`e_ident`); empty for a type laid out
    /// whole, an array's element and an anonymous member.
    pub name: String,
    /// Its type as C writes it (`Elf64_Half`, `unsigned char[16]`).
    pub ty: String,
    /// Its offset from its parent's start, in bytes.
    pub offset: u64,
    /// Its size in bytes.
    pub size: u64,
    /// What it is.
    pub shape: Shape,
    /// How many leaves it has.
    leaves: u64,
}

impl Node {
    /// A node of `shape`, its leaves counted.
    pub fn new(name: String, ty: String, offset: u64, size: u64, shape: Shape) -> Self {
        let leaves = match &shape {
            Shape::Record { union, members } => {
                let members = if *union {
                    members.get(..1).unwrap_or_default()
                } else {
                    members
                };
                members.iter().map(|m| m.leaves).sum::<u64>().max(1)
            }
            Shape::Array { element, count } if !element.is_scalar() => {
                element.leaves.saturating_mul(*count)
            }
            Shape::Scalar { .. } | Shape::Text | Shape::Array { .. } | Shape::Bits(_) => 1,
        };
        Self {
            name,
            ty,
            offset,
            size,
            shape,
            leaves,
        }
    }

    /// Whether it is one scalar.
    pub fn is_scalar(&self) -> bool {
        matches!(self.shape, Shape::Scalar { .. })
    }

    /// The node as a member `name` at `offset`.
    #[must_use]
    pub fn member(&self, name: &str, offset: u64) -> Self {
        Self {
            name: name.to_owned(),
            offset,
            ..self.clone()
        }
    }

    /// An array of `count` of the node, as a member `name` at `offset`.
    #[must_use]
    pub fn array(&self, count: u64, name: &str, offset: u64) -> Self {
        let element = Self {
            name: String::new(),
            offset: 0,
            ..self.clone()
        };
        Self::new(
            name.to_owned(),
            format!("{}[{count}]", self.ty),
            offset,
            self.size.saturating_mul(count),
            Shape::Array {
                element: Arc::new(element),
                count,
            },
        )
    }

    /// Whether the hex view tints it as one: a scalar, text, an array of
    /// scalars, a run of bit-fields, a record without members.
    pub fn is_leaf(&self) -> bool {
        match &self.shape {
            Shape::Scalar { .. } | Shape::Text | Shape::Bits(_) => true,
            Shape::Array { element, .. } => element.is_scalar(),
            Shape::Record { members, .. } => members.is_empty(),
        }
    }

    /// How many leaves it has.
    pub fn leaves(&self) -> u64 {
        self.leaves
    }

    /// Its value in `bytes` (its own) as C writes it, if it is a scalar,
    /// text or an array of scalars (empty otherwise); `little` is the byte
    /// order, `name` names a pointer's target.
    pub fn value(
        &self,
        bytes: &[u8],
        little: bool,
        name: &dyn Fn(u64) -> Option<String>,
    ) -> String {
        match &self.shape {
            Shape::Scalar { scalar, names } => {
                let named =
                    read_uint(bytes, little).and_then(|v| names.as_ref().and_then(|n| n.format(v)));
                named.unwrap_or_else(|| scalar_value(*scalar, bytes, little, name))
            }
            Shape::Text => {
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                let text: String = bytes
                    .get(..end)
                    .unwrap_or_default()
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7f).contains(&b) {
                            char::from(b)
                        } else {
                            '.'
                        }
                    })
                    .collect();
                format!("\"{text}\"")
            }
            Shape::Array { element, .. } if element.is_scalar() => {
                let stride = usize::try_from(element.size.max(1)).unwrap_or(1);
                // Bytes as hex digits (`7F 45 4C 46`), wider elements as
                // a C initialiser.
                if stride == 1 && !matches!(element.shape, Shape::Scalar { names: Some(_), .. }) {
                    let mut out = String::new();
                    for (i, b) in bytes.iter().take(16).enumerate() {
                        if i > 0 {
                            out.push(' ');
                        }
                        let _ = write!(out, "{b:02X}");
                    }
                    if bytes.len() > 16 {
                        out.push_str(" …");
                    }
                    return out;
                }
                let items: Vec<String> = bytes
                    .chunks(stride)
                    .take(8)
                    .map(|b| element.value(b, little, name))
                    .collect();
                let more = if bytes.len() / stride > 8 {
                    ", …"
                } else {
                    ""
                };
                format!("{{{}{more}}}", items.join(", "))
            }
            Shape::Array { .. } | Shape::Record { .. } | Shape::Bits(_) => String::new(),
        }
    }

    /// The leaves of the node at `at` overlapping `range` (both relative
    /// to the same start), numbered from `ordinal`, their paths under
    /// `path`, into `out`.
    fn collect<'a>(
        &'a self,
        at: u64,
        ordinal: u64,
        path: &str,
        range: &Range<u64>,
        out: &mut Vec<Leaf<'a>>,
    ) {
        if self.size == 0 || at >= range.end || at + self.size <= range.start {
            return;
        }
        if self.is_leaf() {
            out.push(Leaf {
                start: at,
                end: at + self.size,
                ordinal,
                path: path.to_owned(),
                node: self,
            });
            return;
        }
        match &self.shape {
            Shape::Record { union, members } => {
                let members = if *union {
                    members.get(..1).unwrap_or_default()
                } else {
                    members
                };
                let mut ordinal = ordinal;
                for member in members {
                    member.collect(
                        at + member.offset,
                        ordinal,
                        &join(path, &member.name),
                        range,
                        out,
                    );
                    ordinal += member.leaves;
                }
            }
            Shape::Array { element, count } => {
                let stride = element.size;
                if stride == 0 {
                    return;
                }
                let first = range.start.saturating_sub(at) / stride;
                let last = range.end.saturating_sub(at).div_ceil(stride).min(*count);
                for i in first..last {
                    element.collect(
                        at + i * stride,
                        ordinal + i * element.leaves,
                        &format!("{path}[{i}]"),
                        range,
                        out,
                    );
                }
            }
            Shape::Scalar { .. } | Shape::Text | Shape::Bits(_) => {}
        }
    }
}

/// `name` under `path` (`a.b`), or either alone.
fn join(path: &str, name: &str) -> String {
    match (path.is_empty(), name.is_empty()) {
        (_, true) => path.to_owned(),
        (true, false) => name.to_owned(),
        (false, false) => format!("{path}.{name}"),
    }
}

/// A scalar's value in `bytes` as C writes it: signed integers and small
/// unsigned ones in decimal, the rest in `h`-suffixed hex (`1F0h`), a pointer
/// with the name it points to.
fn scalar_value(
    scalar: Scalar,
    bytes: &[u8],
    little: bool,
    name: &dyn Fn(u64) -> Option<String>,
) -> String {
    let Some(v) = read_uint(bytes, little) else {
        return String::new();
    };
    let n = bytes.len();
    match scalar {
        Scalar::Int { signed: true } => {
            let shift = 64 - 8 * u32::try_from(n).unwrap_or(8);
            (i64::from_ne_bytes((v << shift).to_ne_bytes()) >> shift).to_string()
        }
        Scalar::Int { signed: false } | Scalar::Char if v < 10 => v.to_string(),
        Scalar::Bool => (v != 0).to_string(),
        Scalar::Float if n == 4 => f32::from_bits(u32::try_from(v).unwrap_or(0)).to_string(),
        Scalar::Float if n == 8 => f64::from_bits(v).to_string(),
        Scalar::Int { signed: false } | Scalar::Char | Scalar::Float => format!("{v:X}h"),
        Scalar::Pointer => match name(v) {
            Some(name) => format!("{v:X}h {name}"),
            None => format!("{v:X}h"),
        },
    }
}

/// A leaf of a layout over a range: where it is, its number, its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf<'a> {
    /// Its first byte, from the layout's start.
    pub start: u64,
    /// Past its last.
    pub end: u64,
    /// Its number in offset order (its tint).
    pub ordinal: u64,
    /// Its path from the type (`e_ident`, `phdr[2].p_flags`); empty for a
    /// scalar type laid out alone.
    pub path: String,
    /// The node.
    pub node: &'a Node,
}

/// A type laid over bytes: its size and its tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The type as C names it (`Elf64_Ehdr`, `struct pair`, `uint32_t[4]`);
    /// empty for a file's headers and tables gathered as one.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// Whether only its members' bytes are its own (a file's headers and
    /// tables, far apart), not every byte to its size.
    pub sparse: bool,
    /// The tree.
    pub root: Node,
}

impl Layout {
    /// The layout of `root`, its size.
    pub fn new(name: String, root: Node) -> Self {
        Self {
            name,
            size: root.size,
            sparse: false,
            root,
        }
    }

    /// The node at `path` (`e_phoff`, `OptionalHeader.DataDirectory[1].Size`)
    /// and its offset from the start.
    pub fn field(&self, path: &str) -> Option<(u64, &Node)> {
        let mut node = &self.root;
        let mut at = 0;
        for part in path.split('.') {
            let (name, indices) = part
                .split_once('[')
                .map_or((part, ""), |(n, rest)| (n, rest));
            if !name.is_empty() {
                let Shape::Record { members, .. } = &node.shape else {
                    return None;
                };
                node = members.iter().find(|m| m.name == name)?;
                at += node.offset;
            }
            for index in indices.split('[').filter(|s| !s.is_empty()) {
                let i: u64 = index.trim_end_matches(']').parse().ok()?;
                let Shape::Array { element, count } = &node.shape else {
                    return None;
                };
                if i >= *count {
                    return None;
                }
                at += i * element.size;
                node = element;
            }
        }
        Some((at, node))
    }

    /// Field `path` of the instance in `bytes` (from its start) as an
    /// unsigned integer of its size, little-endian if `little`.
    pub fn read(&self, bytes: &[u8], path: &str, little: bool) -> Option<u64> {
        let (at, node) = self.field(path)?;
        let start = usize::try_from(at).ok()?;
        let size = usize::try_from(node.size).ok()?;
        read_uint(bytes.get(start..start.checked_add(size)?)?, little)
    }

    /// Whether byte `at` (from the start) is the layout's own.
    pub fn holds(&self, at: u64) -> bool {
        if at >= self.size {
            return false;
        }
        match &self.root.shape {
            Shape::Record { members, .. } if self.sparse => members
                .iter()
                .any(|m| (m.offset..m.offset + m.size).contains(&at)),
            Shape::Scalar { .. }
            | Shape::Text
            | Shape::Array { .. }
            | Shape::Record { .. }
            | Shape::Bits(_) => true,
        }
    }

    /// Its leaves overlapping `range` (from the start), by offset.
    pub fn leaves_in(&self, range: Range<u64>) -> Vec<Leaf<'_>> {
        let mut out = Vec::new();
        self.root.collect(0, 0, "", &range, &mut out);
        out
    }
}

/// `bytes` (at most 8) as an unsigned integer, little-endian if `little`.
pub fn read_uint(bytes: &[u8], little: bool) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let fold = |v: u64, &b: &u8| (v << 8) | u64::from(b);
    Some(if little {
        bytes.iter().rev().fold(0, fold)
    } else {
        bytes.iter().fold(0, fold)
    })
}

/// Structs, unions and typedefs: the built-in headers and what the user
/// defined, in the engine's C scope.
#[derive(Clone, Debug)]
pub struct TypeSet {
    scope: Scope<'static>,
    /// Layouts made, by name.
    cache: HashMap<String, Arc<Layout>>,
}

/// The ELF headers (`<elf.h>`), their fields' enumerations and flags from
/// the System V gABI (Object Files, chapters 4 and 5) as glibc's `elf.h`
/// names them (`ET_*`, `EM_*`, `PT_*`, `PF_*`, `SHT_*`, `SHF_*`).
const ELF_H: &str = r"
typedef uint16_t Elf32_Half; typedef uint32_t Elf32_Word; typedef int32_t Elf32_Sword;
typedef uint32_t Elf32_Addr; typedef uint32_t Elf32_Off;
typedef uint16_t Elf64_Half; typedef uint32_t Elf64_Word; typedef int32_t Elf64_Sword;
typedef uint64_t Elf64_Xword; typedef int64_t Elf64_Sxword;
typedef uint64_t Elf64_Addr; typedef uint64_t Elf64_Off;
enum elf_type : uint16_t { ET_NONE, ET_REL, ET_EXEC, ET_DYN, ET_CORE };
enum elf_machine : uint16_t {
    EM_NONE = 0, EM_M32 = 1, EM_SPARC = 2, EM_386 = 3, EM_68K = 4, EM_88K = 5, EM_IAMCU = 6,
    EM_860 = 7, EM_MIPS = 8, EM_S370 = 9, EM_MIPS_RS3_LE = 10, EM_PARISC = 15, EM_PPC = 20,
    EM_PPC64 = 21, EM_S390 = 22, EM_ARM = 40, EM_SH = 42, EM_SPARCV9 = 43, EM_IA_64 = 50,
    EM_X86_64 = 62, EM_AVR = 83, EM_XTENSA = 94, EM_MSP430 = 105, EM_AARCH64 = 183,
    EM_CUDA = 190, EM_AMDGPU = 224, EM_RISCV = 243, EM_BPF = 247, EM_LOONGARCH = 258
};
enum elf_segment_type : uint32_t {
    PT_NULL = 0, PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3, PT_NOTE = 4, PT_SHLIB = 5,
    PT_PHDR = 6, PT_TLS = 7, PT_GNU_EH_FRAME = 0x6474e550, PT_GNU_STACK = 0x6474e551,
    PT_GNU_RELRO = 0x6474e552, PT_GNU_PROPERTY = 0x6474e553, PT_GNU_SFRAME = 0x6474e554
};
enum __attribute__((flag_enum)) elf_segment_flags : uint32_t { PF_R = 4, PF_W = 2, PF_X = 1 };
enum elf_section_type : uint32_t {
    SHT_NULL = 0, SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4,
    SHT_HASH = 5, SHT_DYNAMIC = 6, SHT_NOTE = 7, SHT_NOBITS = 8, SHT_REL = 9, SHT_SHLIB = 10,
    SHT_DYNSYM = 11, SHT_INIT_ARRAY = 14, SHT_FINI_ARRAY = 15, SHT_PREINIT_ARRAY = 16,
    SHT_GROUP = 17, SHT_SYMTAB_SHNDX = 18, SHT_RELR = 19,
    SHT_GNU_ATTRIBUTES = 0x6ffffff5, SHT_GNU_HASH = 0x6ffffff6, SHT_GNU_LIBLIST = 0x6ffffff7,
    SHT_CHECKSUM = 0x6ffffff8, SHT_GNU_verdef = 0x6ffffffd, SHT_GNU_verneed = 0x6ffffffe,
    SHT_GNU_versym = 0x6fffffff
};
enum __attribute__((flag_enum)) elf32_section_flags : uint32_t {
    SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4, SHF_MERGE = 0x10,
    SHF_STRINGS = 0x20, SHF_INFO_LINK = 0x40, SHF_LINK_ORDER = 0x80,
    SHF_OS_NONCONFORMING = 0x100, SHF_GROUP = 0x200, SHF_TLS = 0x400, SHF_COMPRESSED = 0x800,
    SHF_GNU_RETAIN = 0x200000, SHF_EXCLUDE = 0x80000000
};
enum __attribute__((flag_enum)) elf64_section_flags : uint64_t {
    SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4, SHF_MERGE = 0x10,
    SHF_STRINGS = 0x20, SHF_INFO_LINK = 0x40, SHF_LINK_ORDER = 0x80,
    SHF_OS_NONCONFORMING = 0x100, SHF_GROUP = 0x200, SHF_TLS = 0x400, SHF_COMPRESSED = 0x800,
    SHF_GNU_RETAIN = 0x200000, SHF_EXCLUDE = 0x80000000
};
typedef struct {
    unsigned char e_ident[16]; enum elf_type e_type; enum elf_machine e_machine;
    Elf32_Word e_version; Elf32_Addr e_entry; Elf32_Off e_phoff; Elf32_Off e_shoff;
    Elf32_Word e_flags; Elf32_Half e_ehsize; Elf32_Half e_phentsize; Elf32_Half e_phnum;
    Elf32_Half e_shentsize; Elf32_Half e_shnum; Elf32_Half e_shstrndx;
} Elf32_Ehdr;
typedef struct {
    unsigned char e_ident[16]; enum elf_type e_type; enum elf_machine e_machine;
    Elf64_Word e_version; Elf64_Addr e_entry; Elf64_Off e_phoff; Elf64_Off e_shoff;
    Elf64_Word e_flags; Elf64_Half e_ehsize; Elf64_Half e_phentsize; Elf64_Half e_phnum;
    Elf64_Half e_shentsize; Elf64_Half e_shnum; Elf64_Half e_shstrndx;
} Elf64_Ehdr;
typedef struct {
    enum elf_segment_type p_type; Elf32_Off p_offset; Elf32_Addr p_vaddr; Elf32_Addr p_paddr;
    Elf32_Word p_filesz; Elf32_Word p_memsz; enum elf_segment_flags p_flags;
    Elf32_Word p_align;
} Elf32_Phdr;
typedef struct {
    enum elf_segment_type p_type; enum elf_segment_flags p_flags; Elf64_Off p_offset;
    Elf64_Addr p_vaddr; Elf64_Addr p_paddr; Elf64_Xword p_filesz; Elf64_Xword p_memsz;
    Elf64_Xword p_align;
} Elf64_Phdr;
typedef struct {
    Elf32_Word sh_name; enum elf_section_type sh_type; enum elf32_section_flags sh_flags;
    Elf32_Addr sh_addr; Elf32_Off sh_offset; Elf32_Word sh_size; Elf32_Word sh_link;
    Elf32_Word sh_info; Elf32_Word sh_addralign; Elf32_Word sh_entsize;
} Elf32_Shdr;
typedef struct {
    Elf64_Word sh_name; enum elf_section_type sh_type; enum elf64_section_flags sh_flags;
    Elf64_Addr sh_addr; Elf64_Off sh_offset; Elf64_Xword sh_size; Elf64_Word sh_link;
    Elf64_Word sh_info; Elf64_Xword sh_addralign; Elf64_Xword sh_entsize;
} Elf64_Shdr;
typedef struct {
    Elf32_Word st_name; Elf32_Addr st_value; Elf32_Word st_size;
    unsigned char st_info; unsigned char st_other; Elf32_Half st_shndx;
} Elf32_Sym;
typedef struct {
    Elf64_Word st_name; unsigned char st_info; unsigned char st_other;
    Elf64_Half st_shndx; Elf64_Addr st_value; Elf64_Xword st_size;
} Elf64_Sym;
typedef struct { Elf32_Addr r_offset; Elf32_Word r_info; Elf32_Sword r_addend; } Elf32_Rela;
typedef struct { Elf64_Addr r_offset; Elf64_Xword r_info; Elf64_Sxword r_addend; } Elf64_Rela;
typedef struct { Elf32_Sword d_tag; Elf32_Word d_val; } Elf32_Dyn;
typedef struct { Elf64_Sxword d_tag; Elf64_Xword d_val; } Elf64_Dyn;
";

/// The PE headers (`<winnt.h>`), their fields' enumerations and flags from
/// Microsoft's PE Format specification (Machine Types, Characteristics,
/// Windows Subsystem, DLL Characteristics, Section Flags; the section
/// flags' 4-bit alignment field, `IMAGE_SCN_ALIGN_*`, is no flag and is
/// left as a hex remainder).
const WINNT_H: &str = r"
typedef uint8_t BYTE; typedef uint16_t WORD; typedef uint32_t DWORD; typedef int32_t LONG;
typedef uint64_t ULONGLONG;
enum image_file_machine : WORD {
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0, IMAGE_FILE_MACHINE_I386 = 0x14c,
    IMAGE_FILE_MACHINE_R4000 = 0x166, IMAGE_FILE_MACHINE_ARM = 0x1c0,
    IMAGE_FILE_MACHINE_THUMB = 0x1c2, IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0, IMAGE_FILE_MACHINE_IA64 = 0x200,
    IMAGE_FILE_MACHINE_EBC = 0xebc, IMAGE_FILE_MACHINE_RISCV32 = 0x5032,
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064, IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264,
    IMAGE_FILE_MACHINE_AMD64 = 0x8664, IMAGE_FILE_MACHINE_ARM64 = 0xaa64
};
enum __attribute__((flag_enum)) image_file_characteristics : WORD {
    IMAGE_FILE_RELOCS_STRIPPED = 0x1, IMAGE_FILE_EXECUTABLE_IMAGE = 0x2,
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x4, IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x8,
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x10, IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x20,
    IMAGE_FILE_BYTES_REVERSED_LO = 0x80, IMAGE_FILE_32BIT_MACHINE = 0x100,
    IMAGE_FILE_DEBUG_STRIPPED = 0x200, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x400,
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x800, IMAGE_FILE_SYSTEM = 0x1000, IMAGE_FILE_DLL = 0x2000,
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000, IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
};
enum image_subsystem : WORD {
    IMAGE_SUBSYSTEM_UNKNOWN = 0, IMAGE_SUBSYSTEM_NATIVE = 1, IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3, IMAGE_SUBSYSTEM_OS2_CUI = 5, IMAGE_SUBSYSTEM_POSIX_CUI = 7,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8, IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10, IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12, IMAGE_SUBSYSTEM_EFI_ROM = 13,
    IMAGE_SUBSYSTEM_XBOX = 14, IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
};
enum __attribute__((flag_enum)) image_dll_characteristics : WORD {
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x20, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40,
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x80, IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x200, IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x400,
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x800, IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000, IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
};
enum __attribute__((flag_enum)) image_scn_characteristics : DWORD {
    IMAGE_SCN_TYPE_NO_PAD = 0x8, IMAGE_SCN_CNT_CODE = 0x20,
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40, IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80,
    IMAGE_SCN_LNK_OTHER = 0x100, IMAGE_SCN_LNK_INFO = 0x200, IMAGE_SCN_LNK_REMOVE = 0x800,
    IMAGE_SCN_LNK_COMDAT = 0x1000, IMAGE_SCN_GPREL = 0x8000,
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x1000000, IMAGE_SCN_MEM_DISCARDABLE = 0x2000000,
    IMAGE_SCN_MEM_NOT_CACHED = 0x4000000, IMAGE_SCN_MEM_NOT_PAGED = 0x8000000,
    IMAGE_SCN_MEM_SHARED = 0x10000000, IMAGE_SCN_MEM_EXECUTE = 0x20000000,
    IMAGE_SCN_MEM_READ = 0x40000000, IMAGE_SCN_MEM_WRITE = 0x80000000
};
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic; WORD e_cblp; WORD e_cp; WORD e_crlc; WORD e_cparhdr; WORD e_minalloc;
    WORD e_maxalloc; WORD e_ss; WORD e_sp; WORD e_csum; WORD e_ip; WORD e_cs;
    WORD e_lfarlc; WORD e_ovno; WORD e_res[4]; WORD e_oemid; WORD e_oeminfo;
    WORD e_res2[10]; LONG e_lfanew;
} IMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER {
    enum image_file_machine Machine; WORD NumberOfSections; DWORD TimeDateStamp;
    DWORD PointerToSymbolTable; DWORD NumberOfSymbols; WORD SizeOfOptionalHeader;
    enum image_file_characteristics Characteristics;
} IMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD Magic; BYTE MajorLinkerVersion; BYTE MinorLinkerVersion; DWORD SizeOfCode;
    DWORD SizeOfInitializedData; DWORD SizeOfUninitializedData; DWORD AddressOfEntryPoint;
    DWORD BaseOfCode; DWORD BaseOfData; DWORD ImageBase; DWORD SectionAlignment;
    DWORD FileAlignment; WORD MajorOperatingSystemVersion; WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion; WORD MinorImageVersion; WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion; DWORD Win32VersionValue; DWORD SizeOfImage;
    DWORD SizeOfHeaders; DWORD CheckSum; enum image_subsystem Subsystem;
    enum image_dll_characteristics DllCharacteristics;
    DWORD SizeOfStackReserve; DWORD SizeOfStackCommit; DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit; DWORD LoaderFlags; DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD Magic; BYTE MajorLinkerVersion; BYTE MinorLinkerVersion; DWORD SizeOfCode;
    DWORD SizeOfInitializedData; DWORD SizeOfUninitializedData; DWORD AddressOfEntryPoint;
    DWORD BaseOfCode; ULONGLONG ImageBase; DWORD SectionAlignment; DWORD FileAlignment;
    WORD MajorOperatingSystemVersion; WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion; WORD MinorImageVersion; WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion; DWORD Win32VersionValue; DWORD SizeOfImage;
    DWORD SizeOfHeaders; DWORD CheckSum; enum image_subsystem Subsystem;
    enum image_dll_characteristics DllCharacteristics;
    ULONGLONG SizeOfStackReserve; ULONGLONG SizeOfStackCommit; ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit; DWORD LoaderFlags; DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;
typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union { DWORD PhysicalAddress; DWORD VirtualSize; } Misc;
    DWORD VirtualAddress; DWORD SizeOfRawData; DWORD PointerToRawData;
    DWORD PointerToRelocations; DWORD PointerToLinenumbers; WORD NumberOfRelocations;
    WORD NumberOfLinenumbers; enum image_scn_characteristics Characteristics;
} IMAGE_SECTION_HEADER;
";

/// The 64-bit Mach-O headers (`<mach-o/loader.h>`): the header, load
/// commands, segments and sections, with their fields' enumerations and
/// flags (a section's flags hold its type in the low byte, which is no
/// flag and is left as a hex remainder).
const MACH_O_H: &str = r"
enum mach_cpu_type : int32_t {
    CPU_TYPE_X86 = 7, CPU_TYPE_X86_64 = 0x1000007, CPU_TYPE_ARM = 12,
    CPU_TYPE_ARM64 = 0x100000c, CPU_TYPE_ARM64_32 = 0x200000c, CPU_TYPE_POWERPC = 18,
    CPU_TYPE_POWERPC64 = 0x1000012
};
enum mach_file_type : uint32_t {
    MH_OBJECT = 0x1, MH_EXECUTE = 0x2, MH_FVMLIB = 0x3, MH_CORE = 0x4, MH_PRELOAD = 0x5,
    MH_DYLIB = 0x6, MH_DYLINKER = 0x7, MH_BUNDLE = 0x8, MH_DYLIB_STUB = 0x9, MH_DSYM = 0xa,
    MH_KEXT_BUNDLE = 0xb, MH_FILESET = 0xc, MH_GPU_EXECUTE = 0xd, MH_GPU_DYLIB = 0xe
};
enum __attribute__((flag_enum)) mach_header_flags : uint32_t {
    MH_NOUNDEFS = 0x1, MH_INCRLINK = 0x2, MH_DYLDLINK = 0x4, MH_BINDATLOAD = 0x8,
    MH_PREBOUND = 0x10, MH_SPLIT_SEGS = 0x20, MH_LAZY_INIT = 0x40, MH_TWOLEVEL = 0x80,
    MH_FORCE_FLAT = 0x100, MH_NOMULTIDEFS = 0x200, MH_NOFIXPREBINDING = 0x400,
    MH_PREBINDABLE = 0x800, MH_ALLMODSBOUND = 0x1000, MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000,
    MH_CANONICAL = 0x4000, MH_WEAK_DEFINES = 0x8000, MH_BINDS_TO_WEAK = 0x10000,
    MH_ALLOW_STACK_EXECUTION = 0x20000, MH_ROOT_SAFE = 0x40000, MH_SETUID_SAFE = 0x80000,
    MH_NO_REEXPORTED_DYLIBS = 0x100000, MH_PIE = 0x200000, MH_DEAD_STRIPPABLE_DYLIB = 0x400000,
    MH_HAS_TLV_DESCRIPTORS = 0x800000, MH_NO_HEAP_EXECUTION = 0x1000000,
    MH_APP_EXTENSION_SAFE = 0x2000000, MH_NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x4000000,
    MH_SIM_SUPPORT = 0x8000000, MH_IMPLICIT_PAGEZERO = 0x10000000,
    MH_DYLIB_IN_CACHE = 0x80000000
};
enum load_command_type : uint32_t {
    LC_SEGMENT = 0x1, LC_SYMTAB = 0x2, LC_SYMSEG = 0x3, LC_THREAD = 0x4, LC_UNIXTHREAD = 0x5,
    LC_LOADFVMLIB = 0x6, LC_IDFVMLIB = 0x7, LC_IDENT = 0x8, LC_FVMFILE = 0x9, LC_PREPAGE = 0xa,
    LC_DYSYMTAB = 0xb, LC_LOAD_DYLIB = 0xc, LC_ID_DYLIB = 0xd, LC_LOAD_DYLINKER = 0xe,
    LC_ID_DYLINKER = 0xf, LC_PREBOUND_DYLIB = 0x10, LC_ROUTINES = 0x11,
    LC_SUB_FRAMEWORK = 0x12, LC_SUB_UMBRELLA = 0x13, LC_SUB_CLIENT = 0x14,
    LC_SUB_LIBRARY = 0x15, LC_TWOLEVEL_HINTS = 0x16, LC_PREBIND_CKSUM = 0x17,
    LC_LOAD_WEAK_DYLIB = 0x80000018, LC_SEGMENT_64 = 0x19, LC_ROUTINES_64 = 0x1a,
    LC_UUID = 0x1b, LC_RPATH = 0x8000001c, LC_CODE_SIGNATURE = 0x1d,
    LC_SEGMENT_SPLIT_INFO = 0x1e, LC_REEXPORT_DYLIB = 0x8000001f, LC_LAZY_LOAD_DYLIB = 0x20,
    LC_ENCRYPTION_INFO = 0x21, LC_DYLD_INFO = 0x22, LC_DYLD_INFO_ONLY = 0x80000022,
    LC_LOAD_UPWARD_DYLIB = 0x80000023, LC_VERSION_MIN_MACOSX = 0x24,
    LC_VERSION_MIN_IPHONEOS = 0x25, LC_FUNCTION_STARTS = 0x26, LC_DYLD_ENVIRONMENT = 0x27,
    LC_MAIN = 0x80000028, LC_DATA_IN_CODE = 0x29, LC_SOURCE_VERSION = 0x2a,
    LC_DYLIB_CODE_SIGN_DRS = 0x2b, LC_ENCRYPTION_INFO_64 = 0x2c, LC_LINKER_OPTION = 0x2d,
    LC_LINKER_OPTIMIZATION_HINT = 0x2e, LC_VERSION_MIN_TVOS = 0x2f,
    LC_VERSION_MIN_WATCHOS = 0x30, LC_NOTE = 0x31, LC_BUILD_VERSION = 0x32,
    LC_DYLD_EXPORTS_TRIE = 0x80000033, LC_DYLD_CHAINED_FIXUPS = 0x80000034,
    LC_FILESET_ENTRY = 0x80000035, LC_ATOM_INFO = 0x36, LC_FUNCTION_VARIANTS = 0x37,
    LC_FUNCTION_VARIANT_FIXUPS = 0x38, LC_TARGET_TRIPLE = 0x39
};
enum __attribute__((flag_enum)) vm_prot : int32_t {
    VM_PROT_READ = 0x1, VM_PROT_WRITE = 0x2, VM_PROT_EXECUTE = 0x4
};
enum __attribute__((flag_enum)) segment_flags : uint32_t {
    SG_HIGHVM = 0x1, SG_FVMLIB = 0x2, SG_NORELOC = 0x4, SG_PROTECTED_VERSION_1 = 0x8,
    SG_READ_ONLY = 0x10
};
enum __attribute__((flag_enum)) section_attributes : uint32_t {
    S_ATTR_PURE_INSTRUCTIONS = 0x80000000, S_ATTR_NO_TOC = 0x40000000,
    S_ATTR_STRIP_STATIC_SYMS = 0x20000000, S_ATTR_NO_DEAD_STRIP = 0x10000000,
    S_ATTR_LIVE_SUPPORT = 0x8000000, S_ATTR_SELF_MODIFYING_CODE = 0x4000000,
    S_ATTR_DEBUG = 0x2000000, S_ATTR_SOME_INSTRUCTIONS = 0x400, S_ATTR_EXT_RELOC = 0x200,
    S_ATTR_LOC_RELOC = 0x100
};
struct mach_header_64 {
    uint32_t magic; enum mach_cpu_type cputype; int32_t cpusubtype;
    enum mach_file_type filetype; uint32_t ncmds; uint32_t sizeofcmds;
    enum mach_header_flags flags; uint32_t reserved;
};
struct load_command { enum load_command_type cmd; uint32_t cmdsize; };
struct segment_command_64 {
    enum load_command_type cmd; uint32_t cmdsize; char segname[16]; uint64_t vmaddr;
    uint64_t vmsize; uint64_t fileoff; uint64_t filesize; enum vm_prot maxprot;
    enum vm_prot initprot; uint32_t nsects; enum segment_flags flags;
};
struct section_64 {
    char sectname[16]; char segname[16]; uint64_t addr; uint64_t size; uint32_t offset;
    uint32_t align; uint32_t reloff; uint32_t nreloc; enum section_attributes flags;
    uint32_t reserved1; uint32_t reserved2; uint32_t reserved3;
};
";

impl TypeSet {
    /// C's own types under `model`, nothing defined.
    pub fn new(model: DataModel) -> Self {
        Self {
            scope: Scope::new(model, None),
            cache: HashMap::new(),
        }
    }

    /// C's types and the ELF, PE and Mach-O headers under `model`.
    pub fn builtin(model: DataModel) -> Self {
        let mut types = Self::new(model);
        for header in [ELF_H, WINNT_H, MACH_O_H] {
            // The headers are this file's own text: they parse (a test
            // checks).
            let _ = types.define(header);
        }
        types
    }

    /// The data model.
    pub fn model(&self) -> DataModel {
        self.scope.model()
    }

    /// Defines the structs, unions, enumerations and typedefs of `c`; the
    /// names it defined (`struct pair`, `pair_t`), in order. Nothing is
    /// defined if any of it is refused.
    ///
    /// # Errors
    ///
    /// The C does not parse, or names a type not defined.
    pub fn define(&mut self, c: &str) -> Result<Vec<String>, CError> {
        let defined = self.scope.define(c)?;
        self.cache.clear();
        Ok(defined)
    }

    /// The layout of the type `name` names: a typedef, `struct tag`,
    /// `union tag`, a scalar, with `*` and `[N]` after it.
    ///
    /// # Errors
    ///
    /// `name` is not a type, or one without a size (`void`).
    pub fn layout(&mut self, name: &str) -> Result<Arc<Layout>, CError> {
        let name = name.trim();
        if let Some(layout) = self.cache.get(name) {
            return Ok(Arc::clone(layout));
        }
        let ty = self.scope.type_name(name)?;
        let layout = Arc::new(
            self.node(String::new(), ty, 0, 0)
                .map(|root| Layout::new(name.to_owned(), root))
                .ok_or_else(|| CError {
                    message: format!("{name} has no size"),
                    span: 0..name.len(),
                })?,
        );
        self.cache.insert(name.to_owned(), Arc::clone(&layout));
        Ok(layout)
    }

    /// The layout `text` asks for: a type's name, or C defining structs,
    /// unions and typedefs (then the last one defined), which stay
    /// defined.
    ///
    /// # Errors
    ///
    /// The C is refused, defines nothing, or the type has no size.
    pub fn apply(&mut self, text: &str) -> Result<Arc<Layout>, CError> {
        let text = text.trim();
        if !text.contains('{') && !text.starts_with("typedef") {
            return self.layout(text);
        }
        let mut c = text.to_owned();
        if !c.ends_with(';') {
            c.push(';');
        }
        let defined = self.define(&c)?;
        let last = defined.last().ok_or_else(|| CError {
            message: "nothing is defined".to_owned(),
            span: 0..text.len(),
        })?;
        self.layout(&last.clone())
    }

    /// What `ty`'s bytes are, if it is a scalar, and its enumeration's
    /// names.
    fn scalar(&self, ty: TypeId) -> Option<(Scalar, Option<Arc<Names>>)> {
        Some(match self.scope.types().ty(self.scope.resolve(ty))? {
            &Type::Int { signed, .. } => (Scalar::Int { signed }, None),
            Type::Enum(definition) => {
                let values: Vec<(String, u64)> = definition
                    .variants
                    .iter()
                    .filter_map(|v| {
                        let value = v.value?;
                        Some((
                            v.name.clone(),
                            u64::try_from(value & i128::from(u64::MAX)).ok()?,
                        ))
                    })
                    .collect();
                let signed = definition
                    .variants
                    .iter()
                    .any(|v| v.value.is_some_and(|v| v < 0));
                (
                    Scalar::Int { signed },
                    Some(Arc::new(Names {
                        flags: definition.flags,
                        values,
                    })),
                )
            }
            Type::Char { .. } => (Scalar::Char, None),
            Type::Bool => (Scalar::Bool, None),
            Type::Float(_) => (Scalar::Float, None),
            Type::Pointer(_) => (Scalar::Pointer, None),
            Type::Void
            | Type::Array { .. }
            | Type::Function(_)
            | Type::Record(_)
            | Type::Typedef(_)
            | Type::Opaque(_) => return None,
        })
    }

    /// `ty` laid out as a node named `name` at `offset`; `None` for a type
    /// without a size.
    fn node(&self, name: String, ty: TypeId, offset: u64, depth: u32) -> Option<Node> {
        if depth > 16 {
            return None;
        }
        let size = self.scope.size_of(ty)?;
        let spelled = self.scope.spell(ty, "");
        if let Some((scalar, names)) = self.scalar(ty) {
            return Some(Node::new(
                name,
                spelled,
                offset,
                size,
                Shape::Scalar { scalar, names },
            ));
        }
        let shape = match self.scope.types().ty(self.scope.resolve(ty)) {
            Some(&Type::Array { element, count }) => {
                let element = self.node(String::new(), element, 0, depth + 1)?;
                // `char`s, and a section header's `BYTE Name[8]`.
                let text = matches!(
                    element.shape,
                    Shape::Scalar {
                        scalar: Scalar::Char,
                        ..
                    }
                ) || (name == "Name"
                    && element.size == 1
                    && matches!(
                        element.shape,
                        Shape::Scalar {
                            scalar: Scalar::Int { .. },
                            names: None
                        }
                    ));
                if text {
                    Shape::Text
                } else {
                    Shape::Array {
                        element: Arc::new(element),
                        count: count.unwrap_or(0),
                    }
                }
            }
            Some(Type::Record(record)) => {
                let fields = record.fields.as_deref().unwrap_or_default();
                let mut members = Vec::new();
                let mut bits: Vec<(u64, BitField, u64)> = Vec::new();
                let flush = |bits: &mut Vec<(u64, BitField, u64)>, members: &mut Vec<Node>| {
                    members.extend(bit_run(std::mem::take(bits)));
                };
                for field in fields {
                    let at = field.bit_offset.unwrap_or(0);
                    if let Some(width) = field.bit_width {
                        if width == 0 {
                            flush(&mut bits, &mut members);
                            continue;
                        }
                        let (scalar, names) = self
                            .scalar(field.ty)
                            .unwrap_or((Scalar::Int { signed: false }, None));
                        bits.push((
                            at,
                            BitField {
                                name: field.name.clone().unwrap_or_default(),
                                ty: self.scope.spell(field.ty, ""),
                                bit: 0,
                                width,
                                signed: scalar == Scalar::Int { signed: true },
                                names,
                            },
                            u64::from(width),
                        ));
                        continue;
                    }
                    flush(&mut bits, &mut members);
                    let member_name = field.name.clone().unwrap_or_default();
                    if let Some(node) = self.node(member_name, field.ty, at / 8, depth + 1) {
                        members.push(node);
                    }
                }
                flush(&mut bits, &mut members);
                Shape::Record {
                    union: record.union,
                    members,
                }
            }
            _ => Shape::Record {
                union: false,
                members: Vec::new(),
            },
        };
        Some(Node::new(name, spelled, offset, size, shape))
    }
}

/// A run of bit-fields (each its first bit from the record's start, the
/// field, its width) as one node over the bytes they share.
fn bit_run(run: Vec<(u64, BitField, u64)>) -> Option<Node> {
    let first = run.iter().map(|(at, _, _)| *at).min()?;
    let end = run.iter().map(|(at, _, w)| at + w).max()?;
    let start = first / 8;
    let size = end.div_ceil(8) - start;
    let ty = run
        .iter()
        .map(|(_, f, _)| f.ty.as_str())
        .next()
        .unwrap_or_default()
        .to_owned();
    let fields = run
        .into_iter()
        .map(|(at, field, _)| BitField {
            bit: at - start * 8,
            ..field
        })
        .collect();
    Some(Node::new(
        String::new(),
        ty,
        start,
        size,
        Shape::Bits(fields),
    ))
}

/// The layout of debug information's type `ty` (a global's), named as C
/// writes the type; `None` for a type without a size.
pub fn from_debug(debug: &DebugModel, ty: DebugTypeId) -> Option<Layout> {
    debug.size(ty).filter(|&size| size > 0)?;
    let root = debug_node(debug, ty, String::new(), 0, 0)?;
    Some(Layout::new(debug.display(ty), root))
}

/// What a debug type's scalar is, if it is one.
fn debug_scalar(debug: &DebugModel, ty: DebugTypeId) -> Option<Scalar> {
    match debug.ty(debug.resolve(ty)) {
        DebugType::Base { encoding, .. } => Some(match encoding {
            Encoding::Signed => Scalar::Int { signed: true },
            Encoding::Unsigned | Encoding::Other => Scalar::Int { signed: false },
            Encoding::Char { .. } => Scalar::Char,
            Encoding::Bool => Scalar::Bool,
            Encoding::Float => Scalar::Float,
        }),
        DebugType::Pointer { .. } => Some(Scalar::Pointer),
        DebugType::Enum { signed, .. } => Some(Scalar::Int { signed: *signed }),
        DebugType::Void
        | DebugType::Array { .. }
        | DebugType::Composite(_)
        | DebugType::Typedef { .. }
        | DebugType::Function { .. }
        | DebugType::Unknown => None,
    }
}

/// Debug type `ty` as a node named `name` at `offset`.
fn debug_node(
    debug: &DebugModel,
    ty: DebugTypeId,
    name: String,
    offset: u64,
    depth: u32,
) -> Option<Node> {
    if depth > 16 {
        return None;
    }
    let size = debug.size(ty)?;
    let spelled = debug.display(ty);
    if let Some(scalar) = debug_scalar(debug, ty) {
        return Some(Node::new(
            name,
            spelled,
            offset,
            size,
            Shape::Scalar {
                scalar,
                names: None,
            },
        ));
    }
    let shape = match debug.ty(debug.resolve(ty)) {
        DebugType::Array { element, count } => {
            let element = debug_node(debug, *element, String::new(), 0, depth + 1)?;
            if matches!(
                element.shape,
                Shape::Scalar {
                    scalar: Scalar::Char,
                    ..
                }
            ) {
                Shape::Text
            } else {
                Shape::Array {
                    element: Arc::new(element),
                    count: count.unwrap_or(0),
                }
            }
        }
        DebugType::Composite(composite) => {
            let mut members = Vec::new();
            let mut bits: Vec<(u64, BitField, u64)> = Vec::new();
            for field in &composite.fields {
                let field_name = field.name.clone().unwrap_or_default();
                if let Some((bit, width)) = field.bits {
                    let scalar = debug_scalar(debug, field.ty);
                    bits.push((
                        field.offset * 8 + bit,
                        BitField {
                            name: field_name,
                            ty: debug.display(field.ty),
                            bit: 0,
                            width: u32::try_from(width).unwrap_or(0),
                            signed: scalar == Some(Scalar::Int { signed: true }),
                            names: None,
                        },
                        width,
                    ));
                    continue;
                }
                members.extend(bit_run(std::mem::take(&mut bits)));
                if let Some(node) = debug_node(debug, field.ty, field_name, field.offset, depth + 1)
                {
                    members.push(node);
                }
            }
            members.extend(bit_run(bits));
            Shape::Record {
                union: composite.kind == CompositeKind::Union,
                members,
            }
        }
        DebugType::Void
        | DebugType::Base { .. }
        | DebugType::Pointer { .. }
        | DebugType::Enum { .. }
        | DebugType::Typedef { .. }
        | DebugType::Function { .. }
        | DebugType::Unknown => Shape::Record {
            union: false,
            members: Vec::new(),
        },
    };
    Some(Node::new(name, spelled, offset, size, shape))
}

/// The layout of a global's type over the whole program (its table, each
/// type named as the C names it: [`GlobalTable`]), named as the C names
/// the type; `None` for a type without a size.
pub fn from_table(table: &GlobalTable) -> Option<Layout> {
    let root = table_node(table, table.ty, String::new(), 0, 0)?;
    Some(Layout::new(root.ty.clone(), root))
}

/// What a table's scalar is, if `ty` is one: as the C declares it
/// (untyped bits of 32 and 64 are signed, `int32_t`; a bit is a `bool`).
fn table_scalar(ty: &AstType) -> Option<Scalar> {
    Some(match *ty {
        AstType::Int(_) => Scalar::Int { signed: true },
        AstType::Bits(1) | AstType::UInt(1) | AstType::Bool(_) => Scalar::Bool,
        AstType::Bits(width) => Scalar::Int {
            signed: matches!(width, 32 | 64),
        },
        AstType::UInt(_) => Scalar::Int { signed: false },
        AstType::Enum(Enumeration { signed, .. }) => Scalar::Int { signed },
        AstType::Char { .. } => Scalar::Char,
        AstType::Float(_) => Scalar::Float,
        AstType::Pointer(_) | AstType::Code(_) => Scalar::Pointer,
        AstType::Struct(_) | AstType::Union(_) | AstType::Array { .. } | AstType::Vector { .. } => {
            return None;
        }
    })
}

/// Type `ty` of `table` as a node named `name` at `offset`.
fn table_node(
    table: &GlobalTable,
    ty: AstId,
    name: String,
    offset: u64,
    depth: u32,
) -> Option<Node> {
    if depth > 16 {
        return None;
    }
    let types = &table.types;
    let size = types.width(ty)? / 8;
    if size == 0 {
        return None;
    }
    let spelled = table
        .names
        .get(usize::try_from(ty.0).ok()?)
        .cloned()
        .flatten()
        .unwrap_or_default();
    let found = types.get(ty)?;
    if let Some(scalar) = table_scalar(found) {
        let shape = Shape::Scalar {
            scalar,
            names: None,
        };
        return Some(Node::new(name, spelled, offset, size, shape));
    }
    let shape = match found {
        &(AstType::Array { element, .. } | AstType::Vector { element, .. }) => {
            let element = table_node(table, element, String::new(), 0, depth + 1)?;
            let count = size / element.size;
            if matches!(
                element.shape,
                Shape::Scalar {
                    scalar: Scalar::Char,
                    ..
                }
            ) {
                Shape::Text
            } else {
                Shape::Array {
                    element: Arc::new(element),
                    count,
                }
            }
        }
        AstType::Struct(aggregate) | AstType::Union(aggregate) => Shape::Record {
            union: matches!(found, AstType::Union(_)),
            members: aggregate
                .fields
                .iter()
                .filter_map(|field| {
                    let named = field
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("field_{:x}", field.offset));
                    table_node(table, field.ty, named, field.offset, depth + 1)
                })
                .collect(),
        },
        AstType::Bits(_)
        | AstType::Int(_)
        | AstType::UInt(_)
        | AstType::Char { .. }
        | AstType::Bool(_)
        | AstType::Float(_)
        | AstType::Pointer(_)
        | AstType::Code(_)
        | AstType::Enum(_) => return None,
    };
    Some(Node::new(name, spelled, offset, size, shape))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests fail loudly"
    )]

    use super::*;

    #[test]
    fn the_elf_pe_and_mach_o_headers_have_their_sizes_and_offsets() {
        let mut types = TypeSet::new(DataModel::LP64);
        types.define(ELF_H).unwrap();
        types.define(WINNT_H).unwrap();
        types.define(MACH_O_H).unwrap();
        let size = |types: &mut TypeSet, name: &str| types.layout(name).unwrap().size;
        assert_eq!(size(&mut types, "Elf64_Ehdr"), 64);
        assert_eq!(size(&mut types, "Elf32_Ehdr"), 52);
        assert_eq!(size(&mut types, "Elf64_Phdr"), 56);
        assert_eq!(size(&mut types, "Elf32_Phdr"), 32);
        assert_eq!(size(&mut types, "Elf64_Shdr"), 64);
        assert_eq!(size(&mut types, "Elf32_Shdr"), 40);
        assert_eq!(size(&mut types, "Elf64_Sym"), 24);
        assert_eq!(size(&mut types, "IMAGE_DOS_HEADER"), 64);
        assert_eq!(size(&mut types, "IMAGE_FILE_HEADER"), 20);
        assert_eq!(size(&mut types, "IMAGE_OPTIONAL_HEADER32"), 224);
        assert_eq!(size(&mut types, "IMAGE_OPTIONAL_HEADER64"), 240);
        assert_eq!(size(&mut types, "IMAGE_NT_HEADERS64"), 264);
        assert_eq!(size(&mut types, "IMAGE_SECTION_HEADER"), 40);
        let ehdr = types.layout("Elf64_Ehdr").unwrap();
        let at = |name: &str| ehdr.field(name).map(|(at, f)| (at, f.size));
        assert_eq!(at("e_type"), Some((0x10, 2)));
        assert_eq!(at("e_phoff"), Some((0x20, 8)));
        assert_eq!(at("e_shstrndx"), Some((0x3e, 2)));
        assert_eq!(at("e_ident[5]"), Some((5, 1)));
        assert_eq!(at("e_ident[16]"), None);
        let nt = types.layout("IMAGE_NT_HEADERS64").unwrap();
        let at = |name: &str| nt.field(name).map(|(at, _)| at);
        assert_eq!(at("OptionalHeader.ImageBase"), Some(48));
        assert_eq!(at("OptionalHeader.DataDirectory[15].Size"), Some(260));
        let section = types.layout("IMAGE_SECTION_HEADER").unwrap();
        assert_eq!(section.field("Name").unwrap().1.shape, Shape::Text);
        let at = |name: &str| section.field(name).map(|(at, _)| at);
        assert_eq!(at("Misc.PhysicalAddress"), Some(8));
        assert_eq!(at("Misc.VirtualSize"), Some(8));
        assert_eq!(at("VirtualAddress"), Some(12));
        assert_eq!(size(&mut types, "struct mach_header_64"), 32);
        assert_eq!(size(&mut types, "struct load_command"), 8);
        assert_eq!(size(&mut types, "struct segment_command_64"), 72);
        assert_eq!(size(&mut types, "struct section_64"), 80);
        let segment = types.layout("struct segment_command_64").unwrap();
        assert_eq!(segment.field("segname").unwrap().1.shape, Shape::Text);
        let at = |name: &str| segment.field(name).map(|(at, f)| (at, f.size));
        assert_eq!(at("fileoff"), Some((40, 8)));
        assert_eq!(at("nsects"), Some((64, 4)));
        let section = types.layout("struct section_64").unwrap();
        let at = |name: &str| section.field(name).map(|(at, f)| (at, f.size));
        assert_eq!(at("offset"), Some((48, 4)));
        assert_eq!(at("flags"), Some((64, 4)));
    }

    #[test]
    fn header_fields_read_as_their_enumerations_and_flags() {
        let mut types = TypeSet::builtin(DataModel::LP64);
        let value = |layout: &Layout, path: &str, bytes: &[u8]| {
            layout.field(path).unwrap().1.value(bytes, true, &|_| None)
        };
        let ehdr = types.layout("Elf64_Ehdr").unwrap();
        assert_eq!(value(&ehdr, "e_type", &[3, 0]), "ET_DYN");
        assert_eq!(value(&ehdr, "e_machine", &[62, 0]), "EM_X86_64");
        // A machine `elf.h` lists but not here: the number.
        assert_eq!(value(&ehdr, "e_machine", &[0x34, 0x12]), "1234h");
        assert_eq!(
            value(&ehdr, "e_ident", b"\x7fELF\x02\x01"),
            "7F 45 4C 46 02 01"
        );
        let phdr = types.layout("Elf64_Phdr").unwrap();
        assert_eq!(
            value(&phdr, "p_type", &0x6474_e551u32.to_le_bytes()),
            "PT_GNU_STACK"
        );
        assert_eq!(value(&phdr, "p_flags", &5u32.to_le_bytes()), "PF_R|PF_X");
        assert_eq!(
            value(&phdr, "p_flags", &0x106u32.to_le_bytes()),
            "PF_R|PF_W|0x100"
        );
        let shdr = types.layout("Elf64_Shdr").unwrap();
        assert_eq!(shdr.field("sh_flags").unwrap().1.size, 8);
        assert_eq!(
            value(&shdr, "sh_flags", &0x42u64.to_le_bytes()),
            "SHF_ALLOC|SHF_INFO_LINK"
        );
        assert_eq!(
            value(&shdr, "sh_type", &0x6fff_fff6u32.to_le_bytes()),
            "SHT_GNU_HASH"
        );
        let file = types.layout("IMAGE_FILE_HEADER").unwrap();
        assert_eq!(
            value(&file, "Machine", &0x8664u16.to_le_bytes()),
            "IMAGE_FILE_MACHINE_AMD64"
        );
        assert_eq!(
            value(&file, "Characteristics", &0x22u16.to_le_bytes()),
            "IMAGE_FILE_EXECUTABLE_IMAGE|IMAGE_FILE_LARGE_ADDRESS_AWARE"
        );
        let section = types.layout("IMAGE_SECTION_HEADER").unwrap();
        // The alignment field is no flag: a hex remainder.
        assert_eq!(
            value(&section, "Characteristics", &0x6050_0020u32.to_le_bytes()),
            "IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ|0x500000"
        );
    }

    #[test]
    fn a_type_is_a_tree_of_records_arrays_and_bit_fields() {
        let mut types = TypeSet::new(DataModel::LP64);
        types
            .define(
                "struct a { char c; int i; short s; };
                 union u { char c[5]; int i; };
                 struct n { struct a inner[2]; long l; int (*f)(int, char **);
                            unsigned lo : 3; int mid : 6; unsigned hi : 7;
                            union u un; char name[4]; double d[2]; };",
            )
            .unwrap();
        let n = types.layout("struct n").unwrap();
        let Shape::Record { members, union } = &n.root.shape else {
            panic!("not a record");
        };
        assert!(!union);
        let names: Vec<(&str, u64, u64)> = members
            .iter()
            .map(|m| (m.name.as_str(), m.offset, m.size))
            .collect();
        assert_eq!(
            names,
            [
                ("inner", 0, 24),
                ("l", 24, 8),
                ("f", 32, 8),
                // The bit-fields' run: bits 0–15 of offset 40.
                ("", 40, 2),
                ("un", 44, 8),
                ("name", 52, 4),
                ("d", 56, 16),
            ]
        );
        let Shape::Bits(bits) = &members[3].shape else {
            panic!("not bit-fields");
        };
        let ranges: Vec<(&str, u64, u32)> = bits
            .iter()
            .map(|b| (b.name.as_str(), b.bit, b.width))
            .collect();
        assert_eq!(ranges, [("lo", 0, 3), ("mid", 3, 6), ("hi", 9, 7)]);
        // lo = 5, mid = -2 (0b111110), hi = 0x41, little-endian.
        let word: u16 = 5 | (0b11_1110 << 3) | (0x41 << 9);
        let bytes = word.to_le_bytes();
        let values: Vec<String> = bits.iter().map(|b| b.value(&bytes, true)).collect();
        assert_eq!(values, ["5", "-2", "65"]);
        // Big-endian: the first field from the most significant bit.
        let word: u16 = (5 << 13) | (0b11_1110 << 7) | 0x41;
        let values: Vec<String> = bits
            .iter()
            .map(|b| b.value(&word.to_be_bytes(), false))
            .collect();
        assert_eq!(values, ["5", "-2", "65"]);
        // An array of records keeps one element; text and arrays of
        // scalars are leaves.
        let (_, inner) = n.field("inner").unwrap();
        assert!(matches!(&inner.shape, Shape::Array { count: 2, element } if element.size == 12));
        assert_eq!(n.field("inner[1].s").map(|(at, _)| at), Some(20));
        assert_eq!(n.field("name").unwrap().1.shape, Shape::Text);
        assert_eq!(n.field("un.c").unwrap().1.shape, Shape::Text);
        assert!(n.field("d").unwrap().1.is_leaf());
        assert_eq!(types.layout("struct a *[3]").unwrap().size, 24);
        assert_eq!(types.layout("long").unwrap().size, 8, "LP64's long");
        assert_eq!(
            TypeSet::new(DataModel::LLP64).layout("long").unwrap().size,
            4
        );
        assert!(types.layout("void").is_err());
    }

    #[test]
    fn leaves_are_numbered_in_offset_order_and_found_by_range() {
        let mut types = TypeSet::new(DataModel::LP64);
        types
            .define("struct e { uint32_t key; uint16_t tag; uint8_t pad[2]; };")
            .unwrap();
        let table = types.layout("struct e[10000]").unwrap();
        // Three leaves an element: element 9000's are 27000–27002.
        let leaves = table.leaves_in(9000 * 8..9000 * 8 + 6);
        let found: Vec<(u64, u64, u64, &str)> = leaves
            .iter()
            .map(|l| (l.start, l.end, l.ordinal, l.path.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                (72000, 72004, 27000, "[9000].key"),
                (72004, 72006, 27001, "[9000].tag"),
            ]
        );
        assert_eq!(table.root.leaves(), 30000);
        // A union is tinted by its first member.
        let u = types
            .apply("union v { uint8_t b[8]; uint64_t q; }")
            .unwrap();
        let leaves = u.leaves_in(0..8);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].path, "b");
    }

    #[test]
    fn applied_c_stays_defined_and_refused_c_defines_nothing() {
        let mut types = TypeSet::new(DataModel::LP64);
        assert!(types.apply("struct bad { mystery_t x; }").is_err());
        assert!(types.layout("struct bad").is_err());
        let p = types.apply("struct p { char *s; int n; }").unwrap();
        assert_eq!((p.name.as_str(), p.size), ("struct p", 16));
        assert_eq!(types.layout("struct p").unwrap().size, 16);
    }

    #[test]
    fn integers_read_in_either_byte_order() {
        assert_eq!(read_uint(&[0x34, 0x12], true), Some(0x1234));
        assert_eq!(read_uint(&[0x34, 0x12], false), Some(0x3412));
        assert_eq!(read_uint(&[], true), None);
        assert_eq!(read_uint(&[0; 9], true), None);
    }
}
