//! C declarations read into a type library's [`Type`]s: what a user types
//! where binbun asks for a type (a variable's, a function's prototype, a
//! structure laid over bytes), parsed against a [`Scope`] of the types it
//! may name (C's own, the user's definitions, a [`TypeLibrary`]'s named
//! types) and laid out as a C compiler for the target lays them out.
//!
//! What is read: type specifiers (C's words, `struct`, `union` and `enum`
//! with or without a body, a typedef's name), declarators (`*`, `[N]`,
//! parameter lists, parentheses: `int (*)(int, char **)`, `char *argv[]`),
//! `typedef`s, bit-fields, `__attribute__((packed))`, C23's fixed
//! underlying types of enumerations (`enum e_type : uint16_t { ... }`),
//! clang's `__attribute__((flag_enum))` (the enumeration's values are
//! flags, [`Enum::flags`]), qualifiers (ignored) and integer constant
//! expressions (array lengths, enumerators, bit-field widths). Layout
//! follows the target's C ABI ([`DataModel`]): natural alignment, System
//! V's bit-field rules; bit-fields are refused on targets whose compilers
//! lay them out by Microsoft's rules. Errors give the text's byte range at
//! fault ([`CError::span`]).
//!
//! ```
//! use binbun_typedb::c::{DataModel, Scope};
//!
//! let mut scope = Scope::new(DataModel::LP64, None);
//! scope
//!     .define("struct pair { uint16_t tag; char *name; unsigned flags : 3; };")
//!     .unwrap();
//! let pair = scope.lookup("struct pair").unwrap();
//! assert_eq!((scope.size_of(pair), scope.align_of(pair)), (Some(24), Some(8)));
//! let main = scope.declaration("int main(int argc, char *argv[])").unwrap();
//! assert_eq!(main.name.as_deref(), Some("main"));
//! assert_eq!(scope.spell(main.ty, "main"), "int main(int argc, char **argv)");
//! let error = scope.type_name("struct pair *[2").unwrap_err();
//! assert_eq!(error.message, "expected ']'");
//! ```

use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Write as _};
use std::ops::Range;

use crate::types::{Enum, Field, FloatFormat, Param, Record, Signature, Typedef, Variant};
use crate::{Type, TypeId, TypeLibrary};

/// The widths and layout rules C's types follow on a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DataModel {
    /// A pointer's size in bytes.
    pub pointer: u8,
    /// `long`'s size in bytes.
    pub long: u8,
    /// Whether plain `char` is signed.
    pub char_signed: bool,
    /// `long double`'s format.
    pub long_double: FloatFormat,
    /// The alignment of an 8-byte scalar: 4 on 32-bit System V x86
    /// (`double` and `long long` in a structure), else 8.
    pub wide_align: u8,
    /// Whether bit-fields are laid out by the System V psABI's rules
    /// (GCC, Clang on Unix); Microsoft's rules (Windows) are not
    /// modelled, so bit-fields are refused there.
    pub system_v: bool,
}

impl DataModel {
    /// x86-64 System V (Linux, BSD): `long` and pointers 8 bytes.
    pub const LP64: Self = Self {
        pointer: 8,
        long: 8,
        char_signed: true,
        long_double: FloatFormat::X87,
        wide_align: 8,
        system_v: true,
    };
    /// x86-64 Windows: `long` 4 bytes, pointers 8.
    pub const LLP64: Self = Self {
        pointer: 8,
        long: 4,
        char_signed: true,
        long_double: FloatFormat::Double,
        wide_align: 8,
        system_v: false,
    };
    /// 32-bit x86 System V: `long` and pointers 4 bytes, 8-byte scalars
    /// aligned to 4.
    pub const ILP32: Self = Self {
        pointer: 4,
        long: 4,
        char_signed: true,
        long_double: FloatFormat::X87,
        wide_align: 4,
        system_v: true,
    };

    /// The data model of architecture `arch` (`x86_64`, `x86`, `aarch64`,
    /// `arm`) under operating system `os` (`linux`, `windows`, `macos`),
    /// as the type databases name them.
    pub fn of(arch: &str, os: &str) -> Self {
        let windows = os == "windows";
        let apple = matches!(os, "macos" | "ios" | "darwin");
        let x86 = matches!(arch, "x86" | "i386" | "i686");
        let arm = matches!(arch, "arm" | "armv7");
        let aarch64 = matches!(arch, "aarch64" | "arm64");
        let pointer = if x86 || arm { 4 } else { 8 };
        Self {
            pointer,
            long: if windows { 4 } else { pointer },
            char_signed: !(arm || aarch64) || windows || apple,
            long_double: if windows || apple || arm {
                FloatFormat::Double
            } else if aarch64 {
                FloatFormat::Quad
            } else {
                FloatFormat::X87
            },
            wide_align: if x86 && !windows { 4 } else { 8 },
            system_v: !windows,
        }
    }

    /// The alignment of an integer or pointer of `size` bytes.
    fn scalar_align(self, size: u64) -> u64 {
        if size == 8 {
            u64::from(self.wide_align)
        } else {
            size.max(1)
        }
    }

    /// The size and alignment of a floating-point number of `format`.
    fn float_layout(self, format: FloatFormat) -> (u64, u64) {
        match format {
            FloatFormat::Half => (2, 2),
            FloatFormat::Single => (4, 4),
            FloatFormat::Double => (8, self.scalar_align(8)),
            FloatFormat::X87 if self.pointer == 4 => (12, 4),
            FloatFormat::X87 | FloatFormat::Quad => (16, 16),
        }
    }
}

/// Why C was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CError {
    /// What is wrong.
    pub message: String,
    /// The bytes of the text at fault (empty at the text's end).
    pub span: Range<usize>,
}

impl fmt::Display for CError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at {})", self.message, self.span.start)
    }
}

impl std::error::Error for CError {}

/// A declaration read by [`Scope::declaration`]: `char *name`,
/// `int main(int argc, char **argv)`, or a type alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declared {
    /// The name declared, if any.
    pub name: Option<String>,
    /// Its type in the scope's table ([`Scope::types`]): a function's is
    /// a [`Type::Function`] whose parameters keep their names.
    pub ty: TypeId,
}

/// The types C text may name, and those it defined: a table of its own
/// (C's types, the definitions read, the library types they refer to,
/// copied in) over an optional [`TypeLibrary`] whose named types it may
/// name (`struct stat`, `size_t`).
#[derive(Clone, Debug)]
pub struct Scope<'b> {
    model: DataModel,
    base: Option<&'b TypeLibrary>,
    types: TypeLibrary,
    /// The types defined here by key (`struct tag`, `union tag`,
    /// `enum tag`, a typedef's name).
    names: HashMap<String, TypeId>,
    /// The enumerators defined here.
    constants: HashMap<String, i128>,
    /// The base library's types copied into the table.
    imported: HashMap<TypeId, TypeId>,
    /// How many anonymous records and enumerations were read.
    anonymous: usize,
}

/// C's base type words, in a type specifier in any order.
const BASE_WORDS: &[&str] = &[
    "unsigned", "signed", "char", "short", "int", "long", "float", "double", "void", "_Bool",
    "bool", "__int128",
];

/// Words skipped where a type is read.
const QUALIFIERS: &[&str] = &[
    "const",
    "volatile",
    "restrict",
    "__restrict",
    "__restrict__",
    "static",
    "extern",
    "register",
    "inline",
    "__inline",
    "_Noreturn",
    "__extension__",
];

/// The names of types C's headers define, which a scope knows without
/// them (`<stdint.h>`, `<stddef.h>`, `<uchar.h>`).
const BUILTIN_NAMES: &[&str] = &[
    "int8_t",
    "uint8_t",
    "int16_t",
    "uint16_t",
    "int32_t",
    "uint32_t",
    "int64_t",
    "uint64_t",
    "size_t",
    "ssize_t",
    "uintptr_t",
    "intptr_t",
    "ptrdiff_t",
    "wchar_t",
    "char16_t",
    "char32_t",
];

/// How deep a type's layout is followed (a malformed table may cycle).
const MAX_DEPTH: u32 = 64;

impl<'b> Scope<'b> {
    /// C's own types under `model`, naming `base`'s named types too, if
    /// given.
    pub fn new(model: DataModel, base: Option<&'b TypeLibrary>) -> Self {
        Self {
            model,
            base,
            types: TypeLibrary::new(),
            names: HashMap::new(),
            constants: HashMap::new(),
            imported: HashMap::new(),
            anonymous: 0,
        }
    }

    /// The data model.
    pub fn model(&self) -> DataModel {
        self.model
    }

    /// The table the scope's types are in (every [`TypeId`] it gives).
    pub fn types(&self) -> &TypeLibrary {
        &self.types
    }

    /// The table the scope's types are in, taken (its [`TypeId`]s stay
    /// valid in it).
    pub fn into_types(self) -> TypeLibrary {
        self.types
    }

    /// Defines the structs, unions, enumerations and typedefs of `c`; the
    /// keys it defined (`struct pair`, `pair_t`), in order. Nothing is
    /// defined if any of it is refused.
    ///
    /// # Errors
    ///
    /// The C does not parse, names a type not defined, declares anything
    /// but a type, or lays out a type it cannot.
    pub fn define(&mut self, c: &str) -> Result<Vec<String>, CError> {
        let ((), defined) = self.read(c, |parser| {
            while !parser.done() {
                parser.definition()?;
            }
            Ok(())
        })?;
        Ok(defined)
    }

    /// The declaration `c`: a type and a declarator, named or not
    /// (`char *argv[]`, `int main(int argc, char **argv)`, `int (*)(int)`),
    /// an optional `;` after it. A struct, union or enumeration it defines
    /// stays defined.
    ///
    /// # Errors
    ///
    /// The C does not parse or names a type not defined.
    pub fn declaration(&mut self, c: &str) -> Result<Declared, CError> {
        let (declared, _) = self.read(c, |parser| {
            let declared = parser.declaration()?;
            Ok(declared.0)
        })?;
        Ok(declared)
    }

    /// The type `c` names: a declaration without a name (`struct pair *`,
    /// `int (*)(int, char **)`).
    ///
    /// # Errors
    ///
    /// The C does not parse, names a type not defined, or declares a name.
    pub fn type_name(&mut self, c: &str) -> Result<TypeId, CError> {
        let (ty, _) = self.read(c, |parser| {
            let (declared, span) = parser.declaration()?;
            match (declared.name, span) {
                (Some(name), Some(span)) => Err(CError {
                    message: format!("unexpected name {name}"),
                    span,
                }),
                _ => Ok(declared.ty),
            }
        })?;
        Ok(ty)
    }

    /// Runs `read` over `c`'s tokens on a copy of the scope, taken only if
    /// it succeeds; what it gave and the keys it defined.
    fn read<T>(
        &mut self,
        c: &str,
        read: impl FnOnce(&mut Parser<'_, '_, 'b>) -> Result<T, CError>,
    ) -> Result<(T, Vec<String>), CError> {
        let tokens = lex(c)?;
        let mut scratch = self.clone();
        let mut parser = Parser {
            tokens: &tokens,
            at: 0,
            end: c.len(),
            scope: &mut scratch,
            defined: Vec::new(),
        };
        let value = read(&mut parser)?;
        let defined = std::mem::take(&mut parser.defined);
        *self = scratch;
        Ok((value, defined))
    }

    /// The type named `name`: a typedef's or a type of C's headers'
    /// name, or `struct tag`, `union tag`, `enum tag`; the scope's own
    /// definitions first, then the library's (copied into the table).
    pub fn lookup(&mut self, name: &str) -> Option<TypeId> {
        if let Some(&id) = self.names.get(name) {
            return Some(id);
        }
        if let Some(ty) = self.builtin(name) {
            return Some(self.types.intern(ty));
        }
        let found = self.base?.named(name)?;
        Some(self.import(found))
    }

    /// Whether `name` names a type ([`lookup`](Self::lookup) would find
    /// it).
    fn is_type_name(&self, name: &str) -> bool {
        self.names.contains_key(name)
            || BUILTIN_NAMES.contains(&name)
            || self.base.is_some_and(|base| base.named(name).is_some())
    }

    /// The names a type may be written with, sorted: C's words and
    /// headers' types, the scope's definitions and the library's named
    /// types (anonymous ones left out).
    pub fn names(&self) -> Vec<String> {
        let mut names: BTreeSet<&str> = BASE_WORDS.iter().chain(BUILTIN_NAMES).copied().collect();
        names.extend(self.names.keys().map(String::as_str));
        if let Some(base) = self.base {
            names.extend(base.keys());
        }
        names
            .into_iter()
            .filter(|name| !name.contains(['<', ' ']) || is_tagged(name))
            .map(str::to_owned)
            .collect()
    }

    /// The size in bytes of type `id`: `None` for `void`, functions,
    /// incomplete and opaque types.
    pub fn size_of(&self, id: TypeId) -> Option<u64> {
        self.size_align(id, 0).map(|(size, _)| size)
    }

    /// The alignment in bytes of type `id`, where it has a size.
    pub fn align_of(&self, id: TypeId) -> Option<u64> {
        self.size_align(id, 0).map(|(_, align)| align)
    }

    /// Type `id` through its typedefs.
    pub fn resolve(&self, id: TypeId) -> TypeId {
        let mut id = id;
        for _ in 0..MAX_DEPTH {
            let Some(Type::Typedef(typedef)) = self.types.ty(id) else {
                break;
            };
            id = typedef.target;
        }
        id
    }

    /// `id` declared as `name` in C (`char *argv[2]`, `int (*f)(int)`);
    /// an empty `name` spells the type alone (`char *[2]`).
    pub fn spell(&self, id: TypeId, name: &str) -> String {
        let mut declarator = name.to_owned();
        let mut id = id;
        let mut base = None;
        for _ in 0..MAX_DEPTH {
            match self.types.ty(id) {
                Some(&Type::Pointer(target)) => {
                    declarator.insert(0, '*');
                    id = target;
                }
                Some(&Type::Array { element, count }) => {
                    if declarator.starts_with('*') {
                        declarator = format!("({declarator})");
                    }
                    let count = count.map(|n| n.to_string()).unwrap_or_default();
                    declarator = format!("{declarator}[{count}]");
                    id = element;
                }
                Some(Type::Function(signature)) => {
                    if declarator.starts_with('*') {
                        declarator = format!("({declarator})");
                    }
                    let mut parameters: Vec<String> = signature
                        .params
                        .iter()
                        .map(|param| self.spell(param.ty, param.name.as_deref().unwrap_or("")))
                        .collect();
                    if signature.variadic {
                        parameters.push("...".to_owned());
                    } else if parameters.is_empty() {
                        parameters.push("void".to_owned());
                    }
                    declarator = format!("{declarator}({})", parameters.join(", "));
                    id = signature.ret;
                }
                Some(other) => {
                    base = Some(self.specifier_name(other));
                    break;
                }
                None => break,
            }
        }
        let base = base.unwrap_or_else(|| "void".to_owned());
        if declarator.is_empty() {
            base
        } else {
            format!("{base} {declarator}")
        }
    }

    /// The definition of struct or union `id` as C (`struct pair {` …
    /// `};`, a member a line, bit-fields with their widths), if it is one
    /// with members; of enumeration `id` (`enum __attribute__((flag_enum))
    /// perm : uint32_t {` …, a constant a line with its value, those of
    /// unknown value left out), one without a tag as the typedef `id` is
    /// (`typedef enum : int32_t {` … `} kind_t;`).
    pub fn definition(&self, id: TypeId) -> Option<String> {
        let mut out = String::new();
        match self.types.ty(self.resolve(id))? {
            Type::Record(record) => self.write_record(record, 0, &mut out)?,
            Type::Enum(definition) if !definition.key.contains('<') => {
                write_enum(definition, definition.name.as_deref(), &mut out);
            }
            Type::Enum(definition) => {
                // Anonymous: named by its typedef (as the typedef names it).
                let Some(Type::Typedef(typedef)) = self.types.ty(id) else {
                    return None;
                };
                out.push_str("typedef ");
                write_enum(definition, None, &mut out);
                out.push(' ');
                out.push_str(&typedef.name);
            }
            Type::Void
            | Type::Bool
            | Type::Char { .. }
            | Type::Int { .. }
            | Type::Float(_)
            | Type::Pointer(_)
            | Type::Array { .. }
            | Type::Function(_)
            | Type::Typedef(_)
            | Type::Opaque(_) => return None,
        }
        out.push(';');
        Some(out)
    }

    /// `record`'s definition into `out`, its members indented one more
    /// than `indent` levels (no `;` after it).
    fn write_record(&self, record: &Record<TypeId>, indent: usize, out: &mut String) -> Option<()> {
        let fields = record.fields.as_ref()?;
        let head = if record.key.contains('<') {
            (if record.union { "union" } else { "struct" }).to_owned()
        } else {
            self.specifier_name(&Type::Record(record.clone()))
        };
        let pad = "    ".repeat(indent + 1);
        out.push_str(&head);
        out.push_str(" {\n");
        for field in fields {
            out.push_str(&pad);
            match (&field.name, self.types.ty(field.ty)) {
                (None, Some(Type::Record(inner))) => self.write_record(inner, indent + 1, out)?,
                (name, _) => out.push_str(&self.spell(field.ty, name.as_deref().unwrap_or(""))),
            }
            if let Some(width) = field.bit_width {
                out.push_str(" : ");
                out.push_str(&width.to_string());
            }
            out.push_str(";\n");
        }
        out.push_str(&"    ".repeat(indent));
        out.push('}');
        Some(())
    }

    /// The type specifier naming `ty` (not a pointer, array or function).
    fn specifier_name(&self, ty: &Type) -> String {
        match ty {
            Type::Void => "void".to_owned(),
            Type::Bool => "_Bool".to_owned(),
            Type::Char { .. } => "char".to_owned(),
            &Type::Int { signed, size } => {
                let name = match size {
                    1 => "char",
                    2 => "short",
                    4 => "int",
                    8 if self.model.long == 8 => "long",
                    8 => "long long",
                    _ => "__int128",
                };
                match (signed, size) {
                    (true, 1) => "signed char".to_owned(),
                    (true, _) => name.to_owned(),
                    (false, _) => format!("unsigned {name}"),
                }
            }
            Type::Float(format) => match format {
                FloatFormat::Half => "_Float16",
                FloatFormat::Single => "float",
                FloatFormat::Double => "double",
                FloatFormat::X87 | FloatFormat::Quad => "long double",
            }
            .to_owned(),
            Type::Record(record) => record
                .name
                .as_ref()
                .filter(|_| !record.key.contains('<'))
                .map_or_else(
                    || record.key.clone(),
                    |name| format!("{} {name}", if record.union { "union" } else { "struct" }),
                ),
            Type::Enum(definition) => definition.key.clone(),
            Type::Typedef(typedef) => typedef.name.clone(),
            Type::Opaque(opaque) => opaque.name.clone(),
            Type::Pointer(_) | Type::Array { .. } | Type::Function(_) => String::new(),
        }
    }

    /// A type of C's headers named `name`.
    fn builtin(&self, name: &str) -> Option<Type> {
        let int = |signed: bool, size: u8| Some(Type::Int { signed, size });
        match name {
            "int8_t" => int(true, 1),
            "uint8_t" => int(false, 1),
            "int16_t" => int(true, 2),
            "uint16_t" | "char16_t" => int(false, 2),
            "int32_t" => int(true, 4),
            "uint32_t" | "char32_t" => int(false, 4),
            "int64_t" => int(true, 8),
            "uint64_t" => int(false, 8),
            // GCC's and Clang's predefined names for `__int128`.
            "__int128_t" => int(true, 16),
            "__uint128_t" => int(false, 16),
            "size_t" | "uintptr_t" => int(false, self.model.pointer),
            "ssize_t" | "intptr_t" | "ptrdiff_t" => int(true, self.model.pointer),
            // Unix's is a signed 32-bit integer, Windows' an unsigned
            // 16-bit one.
            "wchar_t" => int(self.model.system_v, if self.model.system_v { 4 } else { 2 }),
            _ => None,
        }
    }

    /// The scalar C's base type `words` name (`unsigned long`, `char`).
    fn scalar(&self, words: &[&str]) -> Option<Type> {
        let count = |w: &str| words.iter().filter(|&&word| word == w).count();
        let (unsigned, signed) = (count("unsigned"), count("signed"));
        let longs = count("long");
        let distinct = words.iter().collect::<BTreeSet<_>>().len();
        if unsigned + signed > 1 || words.len() != distinct + longs.saturating_sub(1) {
            return None;
        }
        let only = |allowed: &[&str]| words.iter().all(|w| allowed.contains(w));
        let int = |size: u8| {
            Some(Type::Int {
                signed: unsigned == 0,
                size,
            })
        };
        if count("void") == 1 {
            return (words.len() == 1).then_some(Type::Void);
        }
        if count("_Bool") + count("bool") == 1 {
            return (words.len() == 1).then_some(Type::Bool);
        }
        if count("float") == 1 {
            return (words.len() == 1).then_some(Type::Float(FloatFormat::Single));
        }
        if count("double") == 1 {
            return match (words.len(), longs) {
                (1, 0) => Some(Type::Float(FloatFormat::Double)),
                (2, 1) => Some(Type::Float(self.model.long_double)),
                _ => None,
            };
        }
        if count("char") == 1 {
            if !only(&["char", "signed", "unsigned"]) {
                return None;
            }
            return Some(if unsigned + signed == 0 {
                Type::Char {
                    signed: self.model.char_signed,
                }
            } else {
                Type::Int {
                    signed: unsigned == 0,
                    size: 1,
                }
            });
        }
        // GCC's extension, which the printer spells for 16-byte integers.
        if count("__int128") == 1 {
            return if only(&["__int128", "signed", "unsigned"]) {
                int(16)
            } else {
                None
            };
        }
        if !only(&["short", "int", "long", "signed", "unsigned"]) {
            return None;
        }
        match (count("short"), longs) {
            (1, 0) => int(2),
            (0, 0) => int(4),
            (0, 1) => int(self.model.long),
            (0, 2) => int(8),
            _ => None,
        }
    }

    /// Copies type `id` of the base library into the table (once). A
    /// record or typedef whose key the scope defines is the scope's
    /// definition: the library's types refer to the user's version of it.
    fn import(&mut self, id: TypeId) -> TypeId {
        if let Some(&own) = self.imported.get(&id) {
            return own;
        }
        let Some(ty) = self.base.and_then(|base| base.ty(id)).cloned() else {
            return self.types.intern(Type::Void);
        };
        let key = match &ty {
            Type::Record(record) => Some(&record.key),
            Type::Typedef(typedef) => Some(&typedef.key),
            Type::Void
            | Type::Bool
            | Type::Char { .. }
            | Type::Int { .. }
            | Type::Float(_)
            | Type::Pointer(_)
            | Type::Array { .. }
            | Type::Function(_)
            | Type::Enum(_)
            | Type::Opaque(_) => None,
        };
        if let Some(&own) = key.and_then(|key| self.names.get(key)) {
            self.imported.insert(id, own);
            return own;
        }
        let own = match ty {
            Type::Record(mut record) => {
                // Reserved first: a record may point to itself.
                let own = self.types.push(Type::Void);
                self.imported.insert(id, own);
                for field in record.fields.iter_mut().flatten() {
                    field.ty = self.import(field.ty);
                }
                self.types.set(own, Type::Record(record));
                own
            }
            Type::Typedef(mut typedef) => {
                let own = self.types.push(Type::Void);
                self.imported.insert(id, own);
                typedef.target = self.import(typedef.target);
                self.types.set(own, Type::Typedef(typedef));
                own
            }
            Type::Enum(_) | Type::Opaque(_) => self.types.push(ty),
            Type::Pointer(target) => {
                let target = self.import(target);
                self.types.intern(Type::Pointer(target))
            }
            Type::Array { element, count } => {
                let element = self.import(element);
                self.types.intern(Type::Array { element, count })
            }
            Type::Function(mut signature) => {
                signature.ret = self.import(signature.ret);
                for param in &mut signature.params {
                    param.ty = self.import(param.ty);
                }
                self.types.intern(Type::Function(signature))
            }
            Type::Void | Type::Bool | Type::Char { .. } | Type::Int { .. } | Type::Float(_) => {
                self.types.intern(ty)
            }
        };
        self.imported.insert(id, own);
        own
    }

    /// The size and alignment of type `id`.
    fn size_align(&self, id: TypeId, depth: u32) -> Option<(u64, u64)> {
        if depth > MAX_DEPTH {
            return None;
        }
        let model = self.model;
        Some(match self.types.ty(id)? {
            Type::Void | Type::Function(_) | Type::Opaque(_) => return None,
            Type::Bool | Type::Char { .. } => (1, 1),
            &Type::Int { size, .. } => (u64::from(size), model.scalar_align(u64::from(size))),
            &Type::Float(format) => model.float_layout(format),
            Type::Pointer(_) => {
                let size = u64::from(model.pointer);
                (size, model.scalar_align(size))
            }
            &Type::Array { element, count } => {
                let (size, align) = self.size_align(element, depth + 1)?;
                (size.checked_mul(count?)?, align)
            }
            Type::Record(record) => (record.size?, record.align?),
            Type::Enum(definition) => {
                let size = u64::from(definition.size.unwrap_or(4));
                (size, model.scalar_align(size))
            }
            Type::Typedef(typedef) => self.size_align(typedef.target, depth + 1)?,
        })
    }

    /// Whether `id` is an integer type (what a bit-field may be).
    fn is_integer(&self, id: TypeId) -> bool {
        matches!(
            self.types.ty(self.resolve(id)),
            Some(Type::Bool | Type::Char { .. } | Type::Int { .. } | Type::Enum(_))
        )
    }

    /// Lays out a record's `members` in order, as the target's C compiler
    /// does: its fields, size and alignment.
    fn lay_out(
        &self,
        members: Vec<Member>,
        union: bool,
        packed: bool,
    ) -> Result<(Vec<Field<TypeId>>, u64, u64), CError> {
        let mut fields: Vec<Field<TypeId>> = Vec::with_capacity(members.len());
        // The next free bit (a struct), the widest member (a union).
        let (mut bit, mut widest, mut align) = (0u64, 0u64, 1u64);
        let count = members.len();
        for (index, member) in members.into_iter().enumerate() {
            if let Some(name) = &member.name
                && fields.iter().any(|f| f.name.as_ref() == Some(name))
            {
                return Err(refuse(format!("{name} is declared twice"), &member));
            }
            let flexible = index + 1 == count && !union && member.bits.is_none();
            let (size, natural) = self.member_layout(&member, flexible)?;
            let unit_align = if packed { 1 } else { natural };
            let Some(width) = member.bits else {
                let offset = if union {
                    0
                } else {
                    bit.div_ceil(8).next_multiple_of(unit_align) * 8
                };
                align = align.max(unit_align);
                fields.push(Field {
                    name: member.name,
                    ty: member.ty,
                    bit_offset: Some(offset),
                    bit_width: None,
                });
                bit = offset + size * 8;
                widest = widest.max(size * 8);
                continue;
            };
            let width = self.bit_width(&member, width, size)?;
            if width == 0 {
                // An unnamed zero-width bit-field starts the next unit.
                bit = bit.next_multiple_of(natural * 8);
                continue;
            }
            let start = if union {
                0
            } else if packed {
                bit
            } else {
                // A bit-field never straddles a unit of its type at the
                // type's alignment.
                let unit = bit - bit % (natural * 8);
                if bit + width > unit + size * 8 {
                    bit.next_multiple_of(natural * 8)
                } else {
                    bit
                }
            };
            // An unnamed bit-field's type does not align the record.
            if member.name.is_some() {
                align = align.max(unit_align);
            }
            fields.push(Field {
                name: member.name,
                ty: member.ty,
                bit_offset: Some(start),
                bit_width: u32::try_from(width).ok(),
            });
            bit = start + width;
            widest = widest.max(width);
        }
        let used = if union { widest } else { bit };
        Ok((fields, used.div_ceil(8).next_multiple_of(align), align))
    }

    /// The size and alignment of `member`; a flexible array member's (if
    /// it may be one: last in a struct) is 0 and its element's.
    fn member_layout(&self, member: &Member, flexible: bool) -> Result<(u64, u64), CError> {
        if let Some(layout) = self.size_align(member.ty, 0) {
            return Ok(layout);
        }
        let element = if let Some(&Type::Array {
            element,
            count: None,
        }) = self.types.ty(self.resolve(member.ty))
            && flexible
        {
            self.align_of(element)
        } else {
            None
        };
        let align =
            element.ok_or_else(|| refuse(format!("{} has no size", member.label()), member))?;
        Ok((0, align))
    }

    /// The width of bit-field `member` (`width` bits of a type of `size`
    /// bytes), if it may be one.
    fn bit_width(&self, member: &Member, width: u32, size: u64) -> Result<u64, CError> {
        let label = member.label();
        if !self.model.system_v {
            return Err(refuse(
                "bit-fields are laid out only for System V targets".to_owned(),
                member,
            ));
        }
        if !self.is_integer(member.ty) {
            return Err(refuse(
                format!("{label} is a bit-field of a type not an integer"),
                member,
            ));
        }
        let width = u64::from(width);
        if width > size * 8 {
            return Err(refuse(format!("{label} is wider than its type"), member));
        }
        if width == 0 && member.name.is_some() {
            return Err(refuse(format!("{label} is a bit-field of width 0"), member));
        }
        Ok(width)
    }

    /// Gives an anonymous record or enumeration the name of the typedef
    /// that names it (`typedef struct { ... } Elf64_Ehdr`).
    fn name_anonymous(&mut self, id: TypeId, name: &str) {
        let name = Some(name.to_owned());
        let renamed = if let Some(Type::Record(record)) = self.types.ty(id)
            && record.name.is_none()
        {
            Type::Record(Record {
                name,
                ..record.clone()
            })
        } else if let Some(Type::Enum(definition)) = self.types.ty(id)
            && definition.name.is_none()
        {
            Type::Enum(Enum {
                name,
                ..definition.clone()
            })
        } else {
            return;
        };
        self.types.set(id, renamed);
    }
}

/// Whether `key` is a tagged type's (`struct stat`), not an anonymous one.
fn is_tagged(key: &str) -> bool {
    ["struct ", "union ", "enum "].iter().any(|prefix| {
        key.strip_prefix(prefix)
            .is_some_and(|tag| !tag.contains(['<', ' ']))
    })
}

/// Enumeration `definition` as C with `tag` (no `;` after it): `flags` as
/// clang's `flag_enum`, its underlying integer where its size is one (signed
/// unless no constant is negative and one needs the top bit, as
/// `binbun::prototypes::enumeration` reads it), each constant whose value
/// is known on a line with its value (hexadecimal for flags).
fn write_enum(definition: &Enum, tag: Option<&str>, out: &mut String) {
    out.push_str("enum ");
    if definition.flags {
        out.push_str("__attribute__((flag_enum)) ");
    }
    if let Some(tag) = tag {
        out.push_str(tag);
        out.push(' ');
    }
    let values = || definition.variants.iter().filter_map(|v| v.value);
    if let Some(size @ (1 | 2 | 4 | 8)) = definition.size {
        let top = 1i128 << (u32::from(size) * 8 - 1);
        let signed = values().any(|v| v < 0) || values().all(|v| v < top);
        let sign = if signed { "" } else { "u" };
        let _ = write!(out, ": {sign}int{}_t ", u32::from(size) * 8);
    }
    out.push_str("{\n");
    for variant in &definition.variants {
        let Some(value) = variant.value else {
            continue;
        };
        let _ = if definition.flags && value >= 0 {
            writeln!(out, "    {} = {value:#x},", variant.name)
        } else {
            writeln!(out, "    {} = {value},", variant.name)
        };
    }
    out.push('}');
}

/// A member of a record as read, before layout.
struct Member {
    name: Option<String>,
    ty: TypeId,
    /// A bit-field's width.
    bits: Option<u32>,
    span: Range<usize>,
}

impl Member {
    /// Its name in a message.
    fn label(&self) -> &str {
        self.name.as_deref().unwrap_or("the member")
    }
}

/// `message` about `member`.
fn refuse(message: String, member: &Member) -> CError {
    CError {
        message,
        span: member.span.clone(),
    }
}

/// A declarator as read: what it makes of the type before it.
struct Declarator {
    name: Option<(String, Range<usize>)>,
    /// Its `*`s, applied first.
    pointers: usize,
    /// Its `[N]`s and parameter lists, in order (the rightmost applies
    /// first).
    suffixes: Vec<Suffix>,
    /// A parenthesised declarator inside it, applied last.
    inner: Option<Box<Declarator>>,
    span: Range<usize>,
}

impl Declarator {
    /// The name declared, inside any parentheses.
    fn name(&self) -> Option<&(String, Range<usize>)> {
        self.name
            .as_ref()
            .or_else(|| self.inner.as_ref().and_then(|inner| inner.name()))
    }
}

enum Suffix {
    /// `[N]`, `[]`.
    Array(Option<u64>),
    /// `(parameters)`, and whether `...` (or no prototype) ends them.
    Function(Vec<Param<TypeId>>, bool),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Number(u64),
    Punct(char),
    /// `...`, `<<`, `>>`.
    Op(&'static str),
}

/// `c` as tokens with their spans; comments and preprocessor lines
/// skipped.
fn lex(c: &str) -> Result<Vec<(Tok, Range<usize>)>, CError> {
    let bytes = c.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let at = |i: usize| bytes.get(i).copied();
    while let Some(b) = at(i) {
        let start = i;
        if b.is_ascii_whitespace() {
            i += 1;
        } else if (b == b'/' && at(i + 1) == Some(b'/')) || b == b'#' {
            while at(i).is_some_and(|b| b != b'\n') {
                i += 1;
            }
        } else if b == b'/' && at(i + 1) == Some(b'*') {
            i += 2;
            while at(i).is_some() && !(at(i) == Some(b'*') && at(i + 1) == Some(b'/')) {
                i += 1;
            }
            i += 2;
        } else if b.is_ascii_alphabetic() || b == b'_' {
            while at(i).is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_') {
                i += 1;
            }
            let word = c.get(start..i).unwrap_or_default().to_owned();
            out.push((Tok::Ident(word), start..i));
        } else if b.is_ascii_digit() {
            while at(i).is_some_and(|b| b.is_ascii_alphanumeric()) {
                i += 1;
            }
            let text = c.get(start..i).unwrap_or_default();
            let digits = text.trim_end_matches(['u', 'U', 'l', 'L']);
            let value = if let Some(hex) = digits
                .strip_prefix("0x")
                .or_else(|| digits.strip_prefix("0X"))
            {
                u64::from_str_radix(hex, 16)
            } else if digits.len() > 1 && digits.starts_with('0') {
                u64::from_str_radix(digits, 8)
            } else {
                digits.parse()
            }
            .map_err(|_| CError {
                message: format!("{text} is not a number"),
                span: start..i,
            })?;
            out.push((Tok::Number(value), start..i));
        } else if let Some(op) = ["...", "<<", ">>"]
            .into_iter()
            .find(|op| c.get(i..).is_some_and(|rest| rest.starts_with(op)))
        {
            i += op.len();
            out.push((Tok::Op(op), start..i));
        } else if b"{}[]();,*:=-+~|&^/%".contains(&b) {
            i += 1;
            out.push((Tok::Punct(char::from(b)), start..i));
        } else {
            let ch = c
                .get(i..)
                .and_then(|rest| rest.chars().next())
                .unwrap_or('?');
            return Err(CError {
                message: format!("unexpected {ch:?}"),
                span: i..i + ch.len_utf8(),
            });
        }
    }
    Ok(out)
}

/// A reader of one text's tokens into a scope.
struct Parser<'t, 's, 'b> {
    tokens: &'t [(Tok, Range<usize>)],
    at: usize,
    end: usize,
    scope: &'s mut Scope<'b>,
    /// The keys defined, in order.
    defined: Vec<String>,
}

impl<'t> Parser<'t, '_, '_> {
    fn done(&self) -> bool {
        self.at >= self.tokens.len()
    }

    fn peek(&self) -> Option<&'t Tok> {
        self.tokens.get(self.at).map(|(t, _)| t)
    }

    fn peek_at(&self, ahead: usize) -> Option<&'t Tok> {
        self.tokens.get(self.at + ahead).map(|(t, _)| t)
    }

    fn peek_ident(&self) -> Option<&'t str> {
        match self.peek() {
            Some(Tok::Ident(name)) => Some(name),
            Some(Tok::Number(_) | Tok::Punct(_) | Tok::Op(_)) | None => None,
        }
    }

    /// The span of the next token (empty at the end).
    fn span(&self) -> Range<usize> {
        self.tokens
            .get(self.at)
            .map_or(self.end..self.end, |(_, span)| span.clone())
    }

    /// Where the last token read ends.
    fn last_end(&self) -> usize {
        self.at
            .checked_sub(1)
            .and_then(|last| self.tokens.get(last))
            .map_or(0, |(_, span)| span.end)
    }

    fn error(&self, message: &str) -> CError {
        CError {
            message: message.to_owned(),
            span: self.span(),
        }
    }

    fn eat(&mut self, punct: char) -> bool {
        if self.peek() == Some(&Tok::Punct(punct)) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn eat_op(&mut self, op: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Op(o)) if *o == op) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, punct: char) -> Result<(), CError> {
        if self.eat(punct) {
            Ok(())
        } else {
            Err(self.error(&format!("expected {punct:?}")))
        }
    }

    fn ident(&mut self) -> Option<(String, Range<usize>)> {
        let name = self.peek_ident()?.to_owned();
        let span = self.span();
        self.at += 1;
        Some((name, span))
    }

    /// Skips qualifiers and `__attribute__((...))`; whether `packed` was
    /// among the attributes.
    fn skip_qualifiers(&mut self) -> Result<bool, CError> {
        self.skip_attributes("packed")
    }

    /// Skips qualifiers and `__attribute__((...))`; whether an attribute
    /// named `word` (or `__word__`) was among them.
    fn skip_attributes(&mut self, word: &str) -> Result<bool, CError> {
        let mut seen = false;
        loop {
            match self.peek_ident() {
                Some(q) if QUALIFIERS.contains(&q) => self.at += 1,
                Some("__attribute__" | "__attribute") => {
                    self.at += 1;
                    let start = self.at;
                    self.skip_parens()?;
                    seen |= self.tokens.get(start..self.at).is_some_and(|tokens| {
                        tokens
                            .iter()
                            .any(|(t, _)| matches!(t, Tok::Ident(n) if n.contains(word)))
                    });
                }
                Some(_) | None => return Ok(seen),
            }
        }
    }

    /// Skips a balanced `( ... )`.
    fn skip_parens(&mut self) -> Result<(), CError> {
        self.expect('(')?;
        let mut depth = 1;
        while depth > 0 {
            match self.peek() {
                Some(Tok::Punct('(')) => depth += 1,
                Some(Tok::Punct(')')) => depth -= 1,
                Some(_) => {}
                None => return Err(self.error("unbalanced parentheses")),
            }
            self.at += 1;
        }
        Ok(())
    }

    /// A type specifier: base words, a typedef's name, or a struct, union
    /// or enumeration (defined here or named).
    fn specifier(&mut self) -> Result<TypeId, CError> {
        let packed = self.skip_qualifiers()?;
        match self.peek_ident() {
            Some(kind @ ("struct" | "union")) => {
                self.at += 1;
                let packed = self.skip_qualifiers()? || packed;
                let id = self.record(kind == "union", packed)?;
                self.skip_qualifiers()?;
                Ok(id)
            }
            Some("enum") => {
                self.at += 1;
                let flags = self.skip_attributes("flag_enum")?;
                let id = self.enumeration(flags)?;
                self.skip_qualifiers()?;
                Ok(id)
            }
            Some(word) if BASE_WORDS.contains(&word) => {
                let start = self.span().start;
                let mut words = Vec::new();
                while let Some(word) = self.peek_ident().filter(|w| BASE_WORDS.contains(w)) {
                    words.push(word);
                    self.at += 1;
                    self.skip_qualifiers()?;
                }
                let ty = self.scope.scalar(&words).ok_or_else(|| CError {
                    message: format!("{} is not a type", words.join(" ")),
                    span: start..self.last_end(),
                })?;
                Ok(self.scope.types.intern(ty))
            }
            Some(name) => {
                let id = self
                    .scope
                    .lookup(name)
                    .ok_or_else(|| self.error(&format!("{name} is not a type")))?;
                self.at += 1;
                self.skip_qualifiers()?;
                Ok(id)
            }
            None => Err(self.error("expected a type")),
        }
    }

    /// `struct`/`union` after its keyword: `tag`, `tag { ... }`, `{ ... }`.
    fn record(&mut self, union: bool, packed: bool) -> Result<TypeId, CError> {
        let word = if union { "union" } else { "struct" };
        let tag = self.ident();
        let start = self.span().start;
        if !self.eat('{') {
            let Some((tag, _)) = tag else {
                return Err(self.error("expected '{'"));
            };
            let key = format!("{word} {tag}");
            if let Some(id) = self.scope.lookup(&key) {
                return Ok(id);
            }
            // Incomplete: a pointer to it is still a type.
            let id = self.scope.types.push(Type::Record(Record {
                key: key.clone(),
                name: Some(tag),
                union,
                size: None,
                align: None,
                fields: None,
            }));
            self.scope.names.insert(key, id);
            return Ok(id);
        }
        let key = if let Some((tag, _)) = &tag {
            format!("{word} {tag}")
        } else {
            self.scope.anonymous += 1;
            format!("{word} <anonymous {}>", self.scope.anonymous)
        };
        let shell = Record {
            key: key.clone(),
            name: tag.as_ref().map(|(tag, _)| tag.clone()),
            union,
            size: None,
            align: None,
            fields: None,
        };
        // An incomplete declaration earlier is completed; a complete one
        // is replaced (what refers to it keeps the old one).
        let id = match self.scope.names.get(&key).copied() {
            Some(id) if matches!(self.scope.types.ty(id), Some(Type::Record(r)) if r.fields.is_none()) => {
                id
            }
            _ => self.scope.types.push(Type::Record(shell.clone())),
        };
        if tag.is_some() {
            self.scope.names.insert(key.clone(), id);
        }
        let members = self.members()?;
        let packed = self.skip_qualifiers()? || packed;
        let (fields, size, align) = self.scope.lay_out(members, union, packed).map_err(|e| {
            if e.span.is_empty() {
                CError {
                    span: start..self.last_end(),
                    ..e
                }
            } else {
                e
            }
        })?;
        self.scope.types.set(
            id,
            Type::Record(Record {
                size: Some(size),
                align: Some(align),
                fields: Some(fields),
                ..shell
            }),
        );
        if tag.is_some() {
            self.defined.push(key);
        }
        Ok(id)
    }

    /// A record's members after its `{`, through its `}`.
    fn members(&mut self) -> Result<Vec<Member>, CError> {
        let mut members = Vec::new();
        while !self.eat('}') {
            if self.done() {
                return Err(self.error("expected '}'"));
            }
            let first = self.span().start;
            let base = self.specifier()?;
            if self.eat(';') {
                // An anonymous struct or union member: its members are the
                // record's.
                let span = first..self.last_end();
                if !matches!(self.scope.types.ty(base), Some(Type::Record(_))) {
                    return Err(CError {
                        message: "expected a member's name".to_owned(),
                        span,
                    });
                }
                members.push(Member {
                    name: None,
                    ty: base,
                    bits: None,
                    span,
                });
                continue;
            }
            loop {
                let declarator = self.declarator()?;
                let name = declarator.name().map(|(name, _)| name.clone());
                let mut span = declarator.span.clone();
                let ty = self.apply(base, declarator)?;
                let bits = if self.eat(':') {
                    let value = self.constant()?;
                    span.end = self.last_end();
                    Some(u32::try_from(value).map_err(|_| CError {
                        message: format!("{value} is not a bit-field's width"),
                        span: span.clone(),
                    })?)
                } else {
                    None
                };
                if name.is_none() && bits.is_none() {
                    return Err(CError {
                        message: "expected a member's name".to_owned(),
                        span,
                    });
                }
                members.push(Member {
                    name,
                    ty,
                    bits,
                    span,
                });
                if !self.eat(',') {
                    break;
                }
            }
            self.expect(';')?;
        }
        Ok(members)
    }

    /// `enum` after its keyword (and its attributes: `flags` if they
    /// include `flag_enum`): `tag`, `tag { ... }`, `{ ... }`, each with
    /// C23's `: type` after the tag.
    fn enumeration(&mut self, flags: bool) -> Result<TypeId, CError> {
        let tag = self.ident();
        let key = if let Some((tag, _)) = &tag {
            format!("enum {tag}")
        } else {
            self.scope.anonymous += 1;
            format!("enum <anonymous {}>", self.scope.anonymous)
        };
        let name = tag.map(|(tag, _)| tag);
        // `enum tag : 3` is an unnamed bit-field, not an underlying type.
        let underlying = if self.peek() == Some(&Tok::Punct(':'))
            && matches!(self.peek_at(1), Some(Tok::Ident(_)))
        {
            self.at += 1;
            let start = self.span().start;
            let ty = self.specifier()?;
            let size = self
                .scope
                .size_of(ty)
                .filter(|_| self.scope.is_integer(ty))
                .and_then(|size| u8::try_from(size).ok())
                .ok_or_else(|| CError {
                    message: "an enumeration's underlying type is an integer type".to_owned(),
                    span: start..self.last_end(),
                })?;
            Some(size)
        } else {
            None
        };
        let body = self.eat('{');
        if !body {
            if name.is_none() {
                return Err(self.error("expected '{'"));
            }
            if let Some(id) = self.scope.lookup(&key) {
                return Ok(id);
            }
        }
        let mut variants = Vec::new();
        let mut next = 0i128;
        while body && !self.eat('}') {
            let (enumerator, span) = self
                .ident()
                .ok_or_else(|| self.error("expected an enumerator"))?;
            if self.eat('=') {
                next = self.constant()?;
            }
            if variants.iter().any(|v: &Variant| v.name == enumerator) {
                return Err(CError {
                    message: format!("{enumerator} is declared twice"),
                    span,
                });
            }
            self.scope.constants.insert(enumerator.clone(), next);
            variants.push(Variant {
                name: enumerator,
                value: Some(next),
            });
            next = next
                .checked_add(1)
                .ok_or_else(|| self.error("the constant overflows"))?;
            if !self.eat(',') {
                self.expect('}')?;
                break;
            }
        }
        let fits = |v: &Variant| {
            v.value
                .is_none_or(|v| i128::from(i32::MIN) <= v && v <= i128::from(u32::MAX))
        };
        let definition = Enum {
            key: key.clone(),
            name: name.clone(),
            size: Some(underlying.unwrap_or(if variants.iter().all(fits) { 4 } else { 8 })),
            flags,
            variants,
        };
        let id = self.scope.types.push(Type::Enum(definition));
        if name.is_some() {
            self.scope.names.insert(key.clone(), id);
            if body {
                self.defined.push(key);
            }
        }
        Ok(id)
    }

    /// Whether a `(` here opens a parenthesised declarator rather than a
    /// parameter list.
    fn nested_follows(&self) -> bool {
        if self.peek() != Some(&Tok::Punct('(')) {
            return false;
        }
        match self.peek_at(1) {
            Some(Tok::Punct('*' | '(' | '[')) => true,
            Some(Tok::Ident(name)) => {
                !(BASE_WORDS.contains(&name.as_str())
                    || QUALIFIERS.contains(&name.as_str())
                    || matches!(name.as_str(), "struct" | "union" | "enum")
                    || self.scope.is_type_name(name))
            }
            Some(Tok::Punct(_) | Tok::Number(_) | Tok::Op(_)) | None => false,
        }
    }

    /// A declarator: `*`s, then a name, a parenthesised declarator or
    /// nothing (abstract), then `[N]`s and parameter lists.
    fn declarator(&mut self) -> Result<Declarator, CError> {
        let start = self.span().start;
        let mut pointers = 0;
        while self.eat('*') {
            self.skip_qualifiers()?;
            pointers += 1;
        }
        let mut inner = None;
        let mut name = None;
        if self.nested_follows() {
            self.at += 1;
            inner = Some(Box::new(self.declarator()?));
            self.expect(')')?;
        } else if self
            .peek_ident()
            .is_some_and(|word| !QUALIFIERS.contains(&word) && !word.starts_with("__attribute"))
        {
            name = self.ident();
        }
        let mut suffixes = Vec::new();
        loop {
            if self.eat('[') {
                if self.eat(']') {
                    suffixes.push(Suffix::Array(None));
                    continue;
                }
                let at = self.span();
                let count = self.constant()?;
                let count = u64::try_from(count).map_err(|_| CError {
                    message: format!("{count} is not an array's length"),
                    span: at.start..self.last_end(),
                })?;
                self.expect(']')?;
                suffixes.push(Suffix::Array(Some(count)));
            } else if self.eat('(') {
                let (params, variadic) = self.parameters()?;
                suffixes.push(Suffix::Function(params, variadic));
            } else {
                break;
            }
        }
        self.skip_qualifiers()?;
        Ok(Declarator {
            name,
            pointers,
            suffixes,
            inner,
            span: start..self.last_end().max(start),
        })
    }

    /// A parameter list after its `(`: the parameters (arrays and
    /// functions adjusted to pointers, as C does) and whether more may
    /// follow (`...`, or `()`: no prototype).
    fn parameters(&mut self) -> Result<(Vec<Param<TypeId>>, bool), CError> {
        if self.eat(')') {
            return Ok((Vec::new(), true));
        }
        if self.peek_ident() == Some("void") && self.peek_at(1) == Some(&Tok::Punct(')')) {
            self.at += 2;
            return Ok((Vec::new(), false));
        }
        let mut params = Vec::new();
        loop {
            if self.eat_op("...") {
                self.expect(')')?;
                return Ok((params, true));
            }
            let start = self.span().start;
            let base = self.specifier()?;
            let declarator = self.declarator()?;
            let name = declarator.name().map(|(name, _)| name.clone());
            let ty = self.apply(base, declarator)?;
            let resolved = self.scope.resolve(ty);
            let kind = self.scope.types.ty(resolved);
            let ty = if let Some(&Type::Array { element, .. }) = kind {
                self.scope.types.intern(Type::Pointer(element))
            } else if matches!(kind, Some(Type::Function(_))) {
                self.scope.types.intern(Type::Pointer(ty))
            } else if matches!(kind, Some(Type::Void)) {
                return Err(CError {
                    message: "a parameter cannot be void".to_owned(),
                    span: start..self.last_end(),
                });
            } else {
                ty
            };
            params.push(Param { name, ty });
            if !self.eat(',') {
                self.expect(')')?;
                return Ok((params, false));
            }
        }
    }

    /// `base` as `declarator` makes it.
    fn apply(&mut self, base: TypeId, declarator: Declarator) -> Result<TypeId, CError> {
        let mut ty = base;
        for _ in 0..declarator.pointers {
            ty = self.scope.types.intern(Type::Pointer(ty));
        }
        for suffix in declarator.suffixes.into_iter().rev() {
            let kind = self.scope.types.ty(self.scope.resolve(ty));
            ty = match suffix {
                Suffix::Array(count) => {
                    if matches!(kind, Some(Type::Function(_) | Type::Void)) {
                        return Err(CError {
                            message: "an array's elements cannot be functions or void".to_owned(),
                            span: declarator.span,
                        });
                    }
                    self.scope.types.intern(Type::Array { element: ty, count })
                }
                Suffix::Function(params, variadic) => {
                    if matches!(kind, Some(Type::Function(_) | Type::Array { .. })) {
                        return Err(CError {
                            message: "a function cannot return a function or an array".to_owned(),
                            span: declarator.span,
                        });
                    }
                    self.scope.types.intern(Type::Function(Signature {
                        ret: ty,
                        params,
                        variadic,
                        convention: None,
                    }))
                }
            };
        }
        match declarator.inner {
            Some(inner) => self.apply(ty, *inner),
            None => Ok(ty),
        }
    }

    /// `typedef T name, ...;`, `struct tag { ... };`, `union tag { ... };`,
    /// `enum tag { ... };`.
    fn definition(&mut self) -> Result<(), CError> {
        if self.eat(';') {
            return Ok(());
        }
        let typedef = self.peek_ident() == Some("typedef");
        if typedef {
            self.at += 1;
        }
        let base = self.specifier()?;
        if self.eat(';') || self.done() {
            if typedef {
                return Err(self.error("expected the typedef's name"));
            }
            return Ok(());
        }
        if !typedef {
            return Err(self.error("expected ';' (only types are defined here)"));
        }
        loop {
            let declarator = self.declarator()?;
            let Some((name, _)) = declarator.name().cloned() else {
                return Err(CError {
                    message: "expected the typedef's name".to_owned(),
                    span: declarator.span,
                });
            };
            let ty = self.apply(base, declarator)?;
            self.scope.name_anonymous(ty, &name);
            let id = self.scope.types.push(Type::Typedef(Typedef {
                key: name.clone(),
                name: name.clone(),
                target: ty,
            }));
            self.scope.names.insert(name.clone(), id);
            self.defined.push(name);
            if !self.eat(',') {
                break;
            }
        }
        if !self.eat(';') && !self.done() {
            return Err(self.error("expected ';'"));
        }
        Ok(())
    }

    /// A whole declaration (`;` optional), and its name's span.
    fn declaration(&mut self) -> Result<(Declared, Option<Range<usize>>), CError> {
        let base = self.specifier()?;
        let declarator = self.declarator()?;
        let name = declarator.name().cloned();
        let ty = self.apply(base, declarator)?;
        self.eat(';');
        if !self.done() {
            return Err(self.error("expected the end of the declaration"));
        }
        let (name, span) = name.map_or((None, None), |(name, span)| (Some(name), Some(span)));
        Ok((Declared { name, ty }, span))
    }

    /// An integer constant expression.
    fn constant(&mut self) -> Result<i128, CError> {
        self.binary(0)
    }

    /// Binary operators of at least precedence `min`.
    fn binary(&mut self, min: u8) -> Result<i128, CError> {
        let mut left = self.unary()?;
        while let Some(op) = self.peek().cloned() {
            let precedence = match &op {
                Tok::Punct(c) => match c {
                    '|' => 1,
                    '^' => 2,
                    '&' => 3,
                    '+' | '-' => 5,
                    '*' | '/' | '%' => 6,
                    _ => return Ok(left),
                },
                Tok::Op("<<" | ">>") => 4,
                Tok::Op(_) | Tok::Ident(_) | Tok::Number(_) => return Ok(left),
            };
            if precedence < min {
                return Ok(left);
            }
            let span = self.span();
            self.at += 1;
            let right = self.binary(precedence + 1)?;
            let overflow = || CError {
                message: "the constant overflows".to_owned(),
                span: span.clone(),
            };
            left = match op {
                Tok::Punct('|') => left | right,
                Tok::Punct('^') => left ^ right,
                Tok::Punct('&') => left & right,
                Tok::Op("<<") => u32::try_from(right)
                    .ok()
                    .filter(|&s| s < 64)
                    .and_then(|s| left.checked_shl(s))
                    .ok_or_else(overflow)?,
                Tok::Op(">>") => u32::try_from(right)
                    .ok()
                    .and_then(|s| left.checked_shr(s))
                    .ok_or_else(overflow)?,
                Tok::Punct('+') => left.checked_add(right).ok_or_else(overflow)?,
                Tok::Punct('-') => left.checked_sub(right).ok_or_else(overflow)?,
                Tok::Punct('*') => left.checked_mul(right).ok_or_else(overflow)?,
                Tok::Punct('/') => left.checked_div(right).ok_or_else(overflow)?,
                Tok::Punct('%') => left.checked_rem(right).ok_or_else(overflow)?,
                Tok::Punct(_) | Tok::Op(_) | Tok::Ident(_) | Tok::Number(_) => left,
            };
        }
        Ok(left)
    }

    /// A number, an enumerator, `sizeof(type)`, a parenthesised
    /// expression, or `-`, `~`, `+` of one.
    fn unary(&mut self) -> Result<i128, CError> {
        let span = self.span();
        match self.peek() {
            Some(&Tok::Number(n)) => {
                self.at += 1;
                Ok(i128::from(n))
            }
            Some(Tok::Punct('-')) => {
                self.at += 1;
                self.unary()?.checked_neg().ok_or_else(|| CError {
                    message: "the constant overflows".to_owned(),
                    span,
                })
            }
            Some(Tok::Punct('+')) => {
                self.at += 1;
                self.unary()
            }
            Some(Tok::Punct('~')) => {
                self.at += 1;
                Ok(!self.unary()?)
            }
            Some(Tok::Punct('(')) => {
                self.at += 1;
                let value = self.binary(0)?;
                self.expect(')')?;
                Ok(value)
            }
            Some(Tok::Ident(word)) if word == "sizeof" => {
                self.at += 1;
                self.expect('(')?;
                let base = self.specifier()?;
                let declarator = self.declarator()?;
                let ty = self.apply(base, declarator)?;
                self.expect(')')?;
                self.scope
                    .size_of(ty)
                    .map(i128::from)
                    .ok_or_else(|| CError {
                        message: format!("{} has no size", self.scope.spell(ty, "")),
                        span: span.start..self.last_end(),
                    })
            }
            Some(Tok::Ident(word)) => {
                let value = self
                    .scope
                    .constants
                    .get(word)
                    .copied()
                    .ok_or_else(|| self.error(&format!("{word} is not a constant")))?;
                self.at += 1;
                Ok(value)
            }
            Some(Tok::Punct(_) | Tok::Op(_)) | None => Err(self.error("expected a constant")),
        }
    }
}

#[cfg(test)]
mod tests;
