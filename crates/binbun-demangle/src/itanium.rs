//! The Itanium C++ ABI's manglings (§5.1): `_Z <encoding>`, as a tree.
//!
//! A [`Symbol`] holds its nodes in tables, referred to by index:
//! [`Prefix`] nodes (a name is a chain of them, each naming its parent,
//! so `std::vector<int>::push_back` is four nodes, `std`, `vector`,
//! `<int>`, `push_back`, the last one the name) and [`Type`]s. The
//! substitution table ([`Symbol::substitutions`]) refers to both, in the
//! order the grammar numbers them (`S_`, `S0_`, …).

mod parse;
mod render;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use parse::parse;

/// A parsed mangling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// What it mangles.
    pub encoding: Encoding,
    /// The vendor suffix after a `.` (`cold`, `isra.0`, `constprop.0`):
    /// a part or a clone the compiler made of the function, with its own
    /// interface.
    pub suffix: Option<String>,
    /// The name nodes, indexed by [`PrefixId`].
    pub prefixes: Vec<Prefix>,
    /// The types, indexed by [`TypeId`].
    pub types: Vec<Type>,
    /// The substitution candidates, in the order `S_`, `S0_`, `S1_`, …
    /// number them.
    pub substitutions: Vec<Substitutable>,
}

/// `<encoding> ::= <name> <bare-function-type> | <name> |
/// <special-name>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// A function: its name and type.
    Function(Name, FunctionType),
    /// A data object.
    Data(Name),
    /// One of the `<special-name>`s parsed.
    Special(Special),
}

/// The `<special-name>`s parsed: those naming a class's run-time type
/// information (the others, thunks and guard variables among them, are
/// refused).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Special {
    /// `TV <type>`: the virtual table of a class.
    VirtualTable(TypeId),
    /// `TT <type>`: the VTT of a class.
    Vtt(TypeId),
    /// `TI <type>`: the `type_info` object of a type.
    TypeInfo(TypeId),
    /// `TS <type>`: the name string of a type's `type_info`.
    TypeInfoName(TypeId),
}

/// `<bare-function-type>`: the types of a function's parameters, and its
/// return type where the mangling states one (a template's, other than a
/// constructor's, destructor's or conversion operator's; a function
/// type's).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionType {
    /// The return type, if stated.
    pub returns: Option<TypeId>,
    /// The parameter types; empty for `(void)`. A last
    /// [`Builtin::Ellipsis`] makes it variadic.
    pub parameters: Vec<TypeId>,
}

/// `<name>`: an unscoped name (`<unscoped-name>`, possibly a template's
/// with its arguments) or a `<nested-name>` (`N … E`) with the
/// qualifiers of the member function it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Name {
    /// The last node of its chain.
    pub path: PrefixId,
    /// Whether it is a `<nested-name>`.
    pub nested: bool,
    /// The cv-qualifiers of the member function it names (`NK…E`: a
    /// `const` member function).
    pub cv: CvQualifiers,
    /// The ref-qualifier of the member function it names.
    pub reference: Option<RefQualifier>,
}

/// One node of a name: its parent (the scope or the template it is in)
/// and what it adds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    /// The node it follows, if any.
    pub parent: Option<PrefixId>,
    /// What it adds.
    pub component: Component,
}

/// What a [`Prefix`] node adds to its parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Component {
    /// `St`: namespace `std`.
    Std,
    /// One of the standard abbreviations (`Sa`, `Sb`, `Ss`, `Si`, `So`,
    /// `Sd`).
    Abbreviation(Abbreviation),
    /// `<unqualified-name>`.
    Name(UnqualifiedName),
    /// `<template-args>`: the parent is the template.
    Arguments(Vec<TemplateArg>),
}

/// The standard substitution abbreviations (§5.1.8) that name a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abbreviation {
    /// `Sa`: `std::allocator`.
    Allocator,
    /// `Sb`: `std::basic_string`.
    BasicString,
    /// `Ss`: `std::basic_string<char, std::char_traits<char>,
    /// std::allocator<char> >`.
    String,
    /// `Si`: `std::basic_istream<char, std::char_traits<char> >`.
    Istream,
    /// `So`: `std::basic_ostream<char, std::char_traits<char> >`.
    Ostream,
    /// `Sd`: `std::basic_iostream<char, std::char_traits<char> >`.
    Iostream,
}

/// `<unqualified-name>`, with its ABI tags (`B <source-name>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnqualifiedName {
    /// The name.
    pub kind: NameKind,
    /// Its ABI tags (`[abi:cxx11]`).
    pub abi_tags: Vec<String>,
}

/// The kinds of `<unqualified-name>` parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameKind {
    /// `<source-name>`: an identifier (`L` before it, internal linkage,
    /// is dropped).
    Source(String),
    /// `<operator-name>`: its C++ spelling after `operator`.
    Operator(&'static str),
    /// `C1`…`C5`: a constructor of the parent class.
    Constructor(u8),
    /// `D0`…`D5`: a destructor of the parent class (`D0` deletes).
    Destructor(u8),
}

/// A type in [`Symbol::types`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(pub u32);

/// A name node in [`Symbol::prefixes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixId(pub u32);

/// `<type>`, as far as parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    /// `<builtin-type>`.
    Builtin(Builtin),
    /// `<CV-qualifiers> <type>`.
    Qualified(CvQualifiers, TypeId),
    /// `P <type>`.
    Pointer(TypeId),
    /// `R <type>`.
    LvalueReference(TypeId),
    /// `O <type>`.
    RvalueReference(TypeId),
    /// `<class-enum-type>`: a class, union or enumeration (the mangling
    /// does not say which), named by its last node.
    Named {
        /// The last node of its name.
        path: PrefixId,
        /// Whether the name is a `<nested-name>` (`N … E`).
        nested: bool,
    },
    /// `<function-type>`: `F <bare-function-type> E`.
    Function(FunctionType),
    /// `<template-param>`: `T_` is 0, `T0_` is 1: the function
    /// template's argument of that index.
    TemplateParam(u32),
}

/// `<builtin-type>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Builtin {
    /// `v`.
    Void,
    /// `w`.
    Wchar,
    /// `b`.
    Bool,
    /// `c`: plain `char`.
    Char,
    /// `a`.
    SignedChar,
    /// `h`.
    UnsignedChar,
    /// `s`.
    Short,
    /// `t`.
    UnsignedShort,
    /// `i`.
    Int,
    /// `j`.
    UnsignedInt,
    /// `l`.
    Long,
    /// `m`.
    UnsignedLong,
    /// `x`.
    LongLong,
    /// `y`.
    UnsignedLongLong,
    /// `n`.
    Int128,
    /// `o`.
    UnsignedInt128,
    /// `f`.
    Float,
    /// `d`.
    Double,
    /// `e`.
    LongDouble,
    /// `g`.
    Float128,
    /// `z`: `...`.
    Ellipsis,
    /// `Di`.
    Char32,
    /// `Ds`.
    Char16,
    /// `Du`.
    Char8,
    /// `Dn`: `decltype(nullptr)`.
    Nullptr,
}

/// `<CV-qualifiers> ::= [r] [V] [K]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CvQualifiers {
    /// `r`: `restrict`.
    pub restrict: bool,
    /// `V`.
    pub volatile: bool,
    /// `K`.
    pub constant: bool,
}

impl CvQualifiers {
    /// Whether it has no qualifier.
    pub fn is_empty(self) -> bool {
        !(self.restrict || self.volatile || self.constant)
    }
}

/// `<ref-qualifier>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefQualifier {
    /// `R`: `&`.
    Lvalue,
    /// `O`: `&&`.
    Rvalue,
}

/// `<template-arg>`, as far as parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateArg {
    /// A type.
    Type(TypeId),
    /// `L <type> <value number> E`: an integer or `bool` literal of a
    /// builtin type.
    Literal {
        /// Its type.
        ty: Builtin,
        /// Its value as mangled: decimal digits, `n` for a minus sign.
        value: String,
    },
    /// `J <template-arg>* E`: an argument pack.
    Pack(Vec<TemplateArg>),
}

/// An entry of the substitution table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Substitutable {
    /// A name prefix (a scope, a template's name, a template with its
    /// arguments).
    Prefix(PrefixId),
    /// A type.
    Type(TypeId),
}

/// Why a mangling is refused: the production not (yet) parsed, or that
/// the input does not follow, and where.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Error {
    /// The production, as the ABI names it (`<local-name>`,
    /// `<special-name>`), or what was expected.
    pub production: &'static str,
    /// The byte offset in the mangling.
    pub offset: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.production, self.offset)
    }
}

impl Symbol {
    /// The name of the function or data object it mangles.
    pub fn name(&self) -> Option<&Name> {
        match &self.encoding {
            Encoding::Function(name, _) | Encoding::Data(name) => Some(name),
            Encoding::Special(_) => None,
        }
    }

    /// The type of the function it mangles, if it mangles one.
    pub fn function(&self) -> Option<&FunctionType> {
        match &self.encoding {
            Encoding::Function(_, function) => Some(function),
            Encoding::Data(_) | Encoding::Special(_) => None,
        }
    }

    /// Type `id`.
    pub fn ty(&self, id: TypeId) -> Option<&Type> {
        self.types.get(id.0 as usize)
    }

    /// Name node `id`.
    pub fn prefix(&self, id: PrefixId) -> Option<&Prefix> {
        self.prefixes.get(id.0 as usize)
    }

    /// The template arguments of the function template it names (the
    /// last node of its name, if that is [`Component::Arguments`]).
    pub fn template_args(&self) -> Option<&[TemplateArg]> {
        match &self.prefix(self.name()?.path)?.component {
            Component::Arguments(arguments) => Some(arguments),
            Component::Std | Component::Abbreviation(_) | Component::Name(_) => None,
        }
    }

    /// The unqualified name it ends in: the template's for a template.
    pub fn last_name(&self) -> Option<&UnqualifiedName> {
        let mut node = self.prefix(self.name()?.path)?;
        loop {
            match &node.component {
                Component::Name(name) => return Some(name),
                Component::Arguments(_) => node = self.prefix(node.parent?)?,
                Component::Std | Component::Abbreviation(_) => return None,
            }
        }
    }

    /// Type `id` with template parameters replaced by the function
    /// template's arguments they stand for (through any number of them),
    /// if every one stands for a type.
    pub fn resolve(&self, id: TypeId) -> Option<TypeId> {
        let mut id = id;
        for _ in 0..=self.types.len() {
            let Type::TemplateParam(index) = self.ty(id)? else {
                return Some(id);
            };
            match self.template_args()?.get(*index as usize)? {
                TemplateArg::Type(ty) => id = *ty,
                TemplateArg::Literal { .. } | TemplateArg::Pack(_) => return None,
            }
        }
        None
    }
}
