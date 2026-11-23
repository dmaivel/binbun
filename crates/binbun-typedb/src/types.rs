//! The definitions types and prototypes are made of, shared by the database
//! files and the library: generic over how they refer to another type
//! (`R`: a [`TypeRef`](crate::database::TypeRef) in a file, a
//! [`TypeId`](crate::TypeId) in a [`TypeLibrary`](crate::TypeLibrary)).

use serde::{Deserialize, Serialize};

use crate::is_false;

/// A floating-point format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FloatFormat {
    /// IEEE 754 binary16 (`_Float16`).
    Half,
    /// IEEE 754 binary32 (`float`).
    Single,
    /// IEEE 754 binary64 (`double`; `long double` on Windows and Apple
    /// AArch64).
    Double,
    /// The x87 80-bit extended format (`long double` on x86), stored in
    /// 16 bytes on x86-64 and 12 on 32-bit x86.
    X87,
    /// IEEE 754 binary128 (`__float128`; `long double` on AArch64 Linux).
    Quad,
}

/// A calling convention a declaration states, when it is not the target's
/// default C convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Convention {
    /// `__stdcall` (32-bit x86; Win32's `WINAPI` there).
    Stdcall,
    /// `__fastcall`.
    Fastcall,
    /// `__thiscall`.
    Thiscall,
    /// `__vectorcall`.
    Vectorcall,
    /// `__regcall`.
    Regcall,
    /// The Windows x64 convention on a target whose default differs
    /// (`__attribute__((ms_abi))`).
    Win64,
    /// The System V AMD64 convention on a target whose default differs
    /// (`__attribute__((sysv_abi))`).
    SysV64,
    /// AAPCS, base variant (`__attribute__((pcs("aapcs")))`).
    Aapcs,
    /// AAPCS, VFP variant (`__attribute__((pcs("aapcs-vfp")))`).
    AapcsVfp,
    /// Clang's `preserve_most`.
    PreserveMost,
    /// Clang's `preserve_all`.
    PreserveAll,
    /// Swift.
    Swift,
}

/// A function's prototype.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signature<R> {
    /// The return type.
    #[serde(rename = "return")]
    pub ret: R,
    /// The declared parameters, in order.
    pub params: Vec<Param<R>>,
    /// Whether arguments beyond `params` may be passed: an explicit `...`,
    /// or a declaration without a prototype (`int f();` before C23). The
    /// variadic tail is never part of `params`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub variadic: bool,
    /// The calling convention, if the declaration states one other than
    /// the target's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub convention: Option<Convention>,
}

/// A parameter.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Param<R> {
    /// Its name, as declared (`None`: unnamed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its type.
    #[serde(rename = "type")]
    pub ty: R,
}

/// A structure or union.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Record<R> {
    /// The key it is referred to by in its database: `struct stat`,
    /// `union sigval`; an anonymous one by where it appears (see
    /// [`TypeRef::Named`](crate::database::TypeRef::Named)).
    pub key: String,
    /// Its tag (`None`: anonymous).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether it is a union.
    #[serde(default, skip_serializing_if = "is_false")]
    pub union: bool,
    /// Its size in bytes, if the source states or computes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Its alignment in bytes, if the source states or computes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub align: Option<u64>,
    /// Its fields in declaration order (`None`: declared but not defined,
    /// like `struct __dirstream`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<Field<R>>>,
}

/// A field of a [`Record`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Field<R> {
    /// Its name (`None`: an anonymous member structure or union, whose
    /// fields belong to the enclosing record in C).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its type; a bit-field's declared type (`unsigned int` for
    /// `unsigned int flag : 1`).
    #[serde(rename = "type")]
    pub ty: R,
    /// Its offset from the start of the record, in bits, if the source
    /// states or computes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_offset: Option<u64>,
    /// A bit-field's width in bits (`None`: not a bit-field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_width: Option<u32>,
}

/// An enumeration or a set of flags.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Enum {
    /// The key it is referred to by in its database (`enum idtype_t`,
    /// `flags mmap_prot`).
    pub key: String,
    /// Its tag (`None`: anonymous).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The size in bytes of its underlying integer, if the source states
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u8>,
    /// Whether the source declares its values flags to be combined with
    /// `|` (syzlang `flags`, Win32 `[Flags]`, clang's `flag_enum`); never
    /// guessed from the values.
    #[serde(default, skip_serializing_if = "is_false")]
    pub flags: bool,
    /// Its constants, in declaration order.
    pub variants: Vec<Variant>,
}

/// A constant of an [`Enum`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Variant {
    /// Its name.
    pub name: String,
    /// Its value, if known (syzlang constants are resolved only by
    /// compiling a probe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i128>,
}

/// A name for another type: a typedef, a Windows handle, a syzlang
/// resource. It stays a named atom over its target; it is not replaced by
/// it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Typedef<R> {
    /// The key it is referred to by in its database.
    pub key: String,
    /// Its name.
    pub name: String,
    /// The type it names.
    pub target: R,
}

/// A type the source names but does not describe: a COM interface, a
/// syzlang type the generator does not model.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Opaque {
    /// The key it is referred to by in its database.
    pub key: String,
    /// Its name.
    pub name: String,
}
