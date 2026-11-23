//! What one debug-information format states, in one model for
//! both: functions by entry address, their parameters, return types and
//! local variables with their locations and the compilation units they
//! come from, global variables by address, and the types they reference.

use std::collections::BTreeMap;
use std::ops::Range;

/// An index into [`DebugModel::types`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(pub u32);

/// An index into [`DebugModel::units`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitId(pub u32);

/// What debug information states about an image.
#[derive(Clone, Debug, Default)]
pub struct DebugModel {
    /// The functions with code, by entry address.
    pub functions: BTreeMap<u64, Function>,
    /// The variables with static storage at a fixed address (file-scope
    /// and static ones), by address.
    pub globals: BTreeMap<u64, Global>,
    /// The names public symbols give code, by address (PDB `S_PUB32` with
    /// the code or function flag): linkage names (decorated for C++),
    /// stated without a type, so a name only, never a prototype. A public
    /// (stripped) PDB, as Microsoft's symbol server serves, states only
    /// these.
    pub publics: BTreeMap<u64, String>,
    /// Every type a function refers to (and what they refer to).
    pub types: Vec<Type>,
    /// The compilation units [`Function::unit`] names (only those), in
    /// the order their first function is read.
    pub units: Vec<Unit>,
    /// The damaged parts, skipped.
    pub damage: Vec<Damage>,
}

/// A compilation unit: one source file compiled (with what it includes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    /// The primary source file as the compiler was given it (relative to
    /// [`Self::directory`] unless absolute): DWARF's `DW_AT_name` of the
    /// `DW_TAG_compile_unit`; PDB's source file of the module's build
    /// information (`S_BUILDINFO`), else the module's (object file's) name.
    pub name: String,
    /// The directory the compiler ran in: DWARF's `DW_AT_comp_dir`; PDB's
    /// current directory of the module's build information.
    pub directory: Option<String>,
    /// The language it is written in: DWARF's `DW_AT_language`; PDB's
    /// compile flags (`S_COMPILE2`, `S_COMPILE3`).
    pub language: Language,
}

/// A unit's source language, as far as how its functions pass their
/// arguments goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Language {
    /// C: a struct or union by value is passed and returned as the
    /// platform's C convention says.
    C,
    /// Another, or none stated. C++ passes a class with a constructor, a
    /// destructor or a base by reference whatever its size, and other
    /// languages have conventions of their own.
    #[default]
    Other,
}

impl Unit {
    /// The source file's path: [`Self::name`] if absolute (`/`, `\\`, a
    /// drive letter), else in [`Self::directory`], joined with the
    /// directory's separator, `.` and `..` resolved lexically
    /// (`D:\a\PCbuild` and `..\Modules\getpath.c`:
    /// `D:\a\Modules\getpath.c`).
    pub fn path(&self) -> String {
        let name = self.name.as_str();
        let bytes = name.as_bytes();
        let absolute = name.starts_with(['/', '\\'])
            || matches!(bytes, [drive, b':', ..] if drive.is_ascii_alphabetic());
        match &self.directory {
            Some(directory) if !absolute && !directory.is_empty() => {
                let separator = if directory.contains('/') { '/' } else { '\\' };
                let mut parts: Vec<&str> = directory.split(separator).collect();
                if parts.last() == Some(&"") {
                    parts.pop();
                }
                // The directory's own parts are kept as stated; the name's
                // `.` and `..` resolved against them (never past the root).
                let root = usize::from(
                    parts
                        .first()
                        .is_some_and(|first| first.is_empty() || first.ends_with(':')),
                );
                for part in name.split(['/', '\\']) {
                    match part {
                        ".." if parts.len() > root => {
                            parts.pop();
                        }
                        "." | "" | ".." => {}
                        part => parts.push(part),
                    }
                }
                parts.join(&separator.to_string())
            }
            Some(_) | None => name.to_owned(),
        }
    }
}

/// A damaged part of the debug information, skipped (wholly or from where the
/// damage starts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Damage {
    /// Where, in the format's own terms (a `.debug_info` offset, a PDB
    /// stream and record index).
    pub at: String,
    /// What is wrong.
    pub message: String,
}

/// A function with code.
#[derive(Clone, Debug)]
pub struct Function {
    /// The entry address.
    pub entry: u64,
    /// The source (or linkage) name.
    pub name: Option<String>,
    /// The parameters, in source order.
    pub parameters: Vec<Variable>,
    /// The return type ([`Type::Void`] if it returns nothing).
    pub returns: TypeId,
    /// Whether it takes more arguments than its parameters (C's `...`).
    pub variadic: bool,
    /// How many parameters its type states, where the format states the
    /// type apart from the parameters' variables (PDB's procedure type,
    /// whose parameters without a symbol are missing from
    /// [`Self::parameters`]); `None` where each parameter is stated as a
    /// variable (DWARF).
    pub arity: Option<usize>,
    /// The local variables of the function's own body (inlined callees'
    /// variables are not included), with their locations.
    pub locals: Vec<Variable>,
    /// The compilation unit it is defined in, if the format states one.
    pub unit: Option<UnitId>,
}

/// A variable with static storage at a fixed address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Global {
    /// The source name.
    pub name: String,
    /// The declared type.
    pub ty: TypeId,
}

/// A parameter or local variable.
#[derive(Clone, Debug)]
pub struct Variable {
    /// The source name.
    pub name: Option<String>,
    /// The declared type.
    pub ty: TypeId,
    /// Where it lives, by address range (empty: optimised out or unknown).
    pub location: Vec<Span>,
}

impl Variable {
    /// Where the variable lives at `pc`.
    pub fn place_at(&self, pc: u64) -> Option<&Place> {
        self.location
            .iter()
            .find(|span| span.range.contains(&pc))
            .map(|span| &span.place)
    }

    /// The stack slot (canonical frame address relative) the variable lives
    /// in, if it lives in one for all of its stated ranges.
    pub fn stack_slot(&self) -> Option<i64> {
        let mut slots = self.location.iter().map(|span| match span.place {
            Place::Stack(offset) => Some(offset),
            Place::Register(_) | Place::Relative { .. } | Place::Other => None,
        });
        let first = slots.next()??;
        slots.all(|slot| slot == Some(first)).then_some(first)
    }
}

/// Where a variable lives over a range of addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    /// The addresses (the whole function for a single location).
    pub range: Range<u64>,
    /// The place.
    pub place: Place,
}

/// A variable's place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    /// In a register (by its lower-case assembler name: `rdi`, `xmm0`,
    /// `x0`).
    Register(&'static str),
    /// In memory at this byte offset from the canonical frame address (the
    /// stack pointer's value before the call instruction: on x86-64 the
    /// entry stack pointer + 8, on AArch64 the entry stack pointer).
    Stack(i64),
    /// In memory at a register plus an offset, where the register's distance
    /// from the canonical frame address is not stated here (Clang's frame
    /// base `rsp` or `rbp`; PDB's frame-pointer-relative offsets).
    Relative {
        /// The register.
        register: &'static str,
        /// The byte offset.
        offset: i64,
    },
    /// Anything else: split into pieces, a computed value, an entry value.
    Other,
}

/// A type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    /// `void`.
    Void,
    /// A base type.
    Base {
        /// The source name (`unsigned int`).
        name: String,
        /// The width in bytes.
        bytes: u64,
        /// What its bits mean.
        encoding: Encoding,
    },
    /// A pointer or C++ reference (to [`Type::Void`] for `void *`).
    Pointer {
        /// What it points to.
        target: TypeId,
        /// The width in bytes.
        bytes: u64,
    },
    /// An array.
    Array {
        /// The element type.
        element: TypeId,
        /// The number of elements, if stated (flexible arrays have none).
        count: Option<u64>,
    },
    /// A struct, class or union.
    Composite(Composite),
    /// An enumeration.
    Enum {
        /// The tag name.
        name: Option<String>,
        /// The width in bytes.
        bytes: u64,
        /// Whether the underlying type is signed.
        signed: bool,
    },
    /// A typedef, kept as its name over its target.
    Typedef {
        /// The name.
        name: String,
        /// The type it names.
        target: TypeId,
    },
    /// A function type (what a function pointer points to).
    Function {
        /// The return type.
        returns: TypeId,
        /// The parameter types.
        parameters: Vec<TypeId>,
        /// Whether it takes more arguments (`...`).
        variadic: bool,
    },
    /// A type the reader could not read (damaged, or a kind the model does
    /// not have: pointers to members, unspecified types).
    Unknown,
}

/// What a base type's bits mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// A signed integer.
    Signed,
    /// An unsigned integer.
    Unsigned,
    /// A character type (`char`, `signed char`, `unsigned char`,
    /// `wchar_t`...), with its signedness.
    Char {
        /// Whether it is signed.
        signed: bool,
    },
    /// A boolean.
    Bool,
    /// A binary floating-point number.
    Float,
    /// Anything else (complex, decimal float, fixed point).
    Other,
}

/// What kind of composite type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositeKind {
    /// `struct`.
    Struct,
    /// `class`.
    Class,
    /// `union`.
    Union,
}

/// A struct, class or union.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Composite {
    /// The kind.
    pub kind: CompositeKind,
    /// The tag name (none for anonymous ones).
    pub name: Option<String>,
    /// The size in bytes (none for a declaration without its definition).
    pub size: Option<u64>,
    /// The data members, in declaration order (base classes as members at
    /// their offsets).
    pub fields: Vec<Field>,
}

/// A data member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The name (none for anonymous members and base classes).
    pub name: Option<String>,
    /// The byte offset from the start of the composite (of the storage unit,
    /// for a bit-field).
    pub offset: u64,
    /// The type.
    pub ty: TypeId,
    /// For a bit-field: its bit offset from `offset` and its width in bits.
    pub bits: Option<(u64, u64)>,
}

impl DebugModel {
    /// The compilation unit `id` refers to.
    pub fn unit(&self, id: UnitId) -> Option<&Unit> {
        self.units.get(usize::try_from(id.0).ok()?)
    }

    /// The compilation unit of the function at `entry`.
    pub fn unit_of(&self, entry: u64) -> Option<&Unit> {
        self.unit(self.functions.get(&entry)?.unit?)
    }

    /// Adds `unit`; its id.
    pub fn push_unit(&mut self, unit: Unit) -> UnitId {
        let id = UnitId(u32::try_from(self.units.len()).unwrap_or(u32::MAX));
        self.units.push(unit);
        id
    }

    /// The type `id` refers to ([`Type::Unknown`] for an index out of
    /// range).
    pub fn ty(&self, id: TypeId) -> &Type {
        usize::try_from(id.0)
            .ok()
            .and_then(|index| self.types.get(index))
            .unwrap_or(&Type::Unknown)
    }

    /// `id` with typedefs looked through (at most 64 deep, so a cycle in
    /// damaged information ends).
    pub fn resolve(&self, mut id: TypeId) -> TypeId {
        for _ in 0..64 {
            match self.ty(id) {
                Type::Typedef { target, .. } => id = *target,
                Type::Void
                | Type::Base { .. }
                | Type::Pointer { .. }
                | Type::Array { .. }
                | Type::Composite(_)
                | Type::Enum { .. }
                | Type::Function { .. }
                | Type::Unknown => return id,
            }
        }
        id
    }

    /// The width of `id` in bytes, if it has one.
    pub fn size(&self, id: TypeId) -> Option<u64> {
        self.size_within(id, 64)
    }

    fn size_within(&self, id: TypeId, depth: u32) -> Option<u64> {
        let depth = depth.checked_sub(1)?;
        match self.ty(id) {
            Type::Base { bytes, .. } | Type::Pointer { bytes, .. } | Type::Enum { bytes, .. } => {
                Some(*bytes)
            }
            Type::Array { element, count } => {
                self.size_within(*element, depth)?.checked_mul((*count)?)
            }
            Type::Composite(composite) => composite.size,
            Type::Typedef { target, .. } => self.size_within(*target, depth),
            Type::Void | Type::Function { .. } | Type::Unknown => None,
        }
    }

    /// `id` as C, for reports (`struct node *`, `int[4]`).
    pub fn display(&self, id: TypeId) -> String {
        self.display_within(id, 8)
    }

    fn display_within(&self, id: TypeId, depth: u32) -> String {
        let Some(depth) = depth.checked_sub(1) else {
            return "...".to_owned();
        };
        match self.ty(id) {
            Type::Void => "void".to_owned(),
            Type::Base { name, .. } | Type::Typedef { name, .. } => name.clone(),
            Type::Pointer { target, .. } => {
                let target = self.display_within(*target, depth);
                if target.ends_with('*') {
                    format!("{target}*")
                } else {
                    format!("{target} *")
                }
            }
            Type::Array { element, count } => match count {
                Some(count) => format!("{}[{count}]", self.display_within(*element, depth)),
                None => format!("{}[]", self.display_within(*element, depth)),
            },
            Type::Composite(composite) => {
                let kind = match composite.kind {
                    CompositeKind::Struct => "struct",
                    CompositeKind::Class => "class",
                    CompositeKind::Union => "union",
                };
                format!(
                    "{kind} {}",
                    composite.name.as_deref().unwrap_or("<anonymous>")
                )
            }
            Type::Enum { name, .. } => format!("enum {}", name.as_deref().unwrap_or("<anonymous>")),
            Type::Function { returns, .. } => {
                format!("{} (...)", self.display_within(*returns, depth))
            }
            Type::Unknown => "?".to_owned(),
        }
    }
}
