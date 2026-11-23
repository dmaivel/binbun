//! Mangled C++ names as parse trees.
//!
//! [`itanium`] parses the Itanium C++ ABI's manglings (§5.1, `_Z…`: GCC
//! and Clang on every target but Windows) into a public tree shaped like
//! the grammar: an [`Encoding`](itanium::Encoding), its
//! [`Name`](itanium::Name) as a chain of [`Prefix`](itanium::Prefix)
//! nodes, its parameter [`Type`](itanium::Type)s, template arguments as
//! parsed nodes, and the substitution table they were numbered in.
//!
//! It is not yet a full demangler: it covers what a function's parameter
//! list needs (builtin types, pointers, references, cv-qualifiers, named
//! types, substitutions, template arguments) and refuses everything else
//! with an [`Error`](itanium::Error) naming the production, never
//! guessing. Extending it means adding productions to the tree and the
//! parser. [`itanium::Symbol::parameters_text`] renders a parameter list
//! as C++ text, as demanglers print it.
//! [`demangle`] reads a mangling as C++ text in one call (what the GUI's
//! map and the Python API show).
//!
//! The crate is `no_std` (with `alloc`) and has no dependencies.

#![no_std]

extern crate alloc;

pub mod itanium;

use alloc::string::String;

/// An Itanium C++ mangling (`_Z…`) as C++ text: the qualified name, and a
/// function's parameters and qualifiers (`std::locale::name() const`);
/// a class's run-time type information as c++filt words it (`typeinfo
/// for Error`); a symbol version after `@` kept as it is. `None` if `name`
/// is no mangling the demangler reads.
///
/// ```
/// use binbun_demangle::demangle;
///
/// assert_eq!(demangle("_ZTI5Error").as_deref(), Some("typeinfo for Error"));
/// assert_eq!(
///     demangle("_ZTSSt13runtime_error").as_deref(),
///     Some("typeinfo name for std::runtime_error")
/// );
/// assert_eq!(
///     demangle("_ZTIi@CXXABI_1.3").as_deref(),
///     Some("typeinfo for int@CXXABI_1.3")
/// );
/// assert_eq!(demangle("main"), None);
/// ```
pub fn demangle(name: &str) -> Option<String> {
    let (mangled, version) = match name.split_once('@') {
        Some((mangled, version)) => (mangled, Some(version)),
        None => (name, None),
    };
    if !mangled.starts_with("_Z") {
        return None;
    }
    let symbol = itanium::parse(mangled).ok()?;
    let mut text = if let itanium::Encoding::Special(special) = symbol.encoding {
        let (words, ty) = match special {
            itanium::Special::VirtualTable(ty) => ("vtable for ", ty),
            itanium::Special::Vtt(ty) => ("VTT for ", ty),
            itanium::Special::TypeInfo(ty) => ("typeinfo for ", ty),
            itanium::Special::TypeInfoName(ty) => ("typeinfo name for ", ty),
        };
        let mut text = String::from(words);
        text.push_str(&symbol.type_text(ty)?);
        text
    } else {
        let path = symbol.name()?.path;
        let mut text = symbol.prefix_text(path)?;
        if symbol.function().is_some() {
            let parameters = symbol.parameters_text()?;
            text.push('(');
            text.push_str(&parameters);
            text.push(')');
            text.push_str(&symbol.qualifiers_text());
        }
        text
    };
    if let Some(version) = version {
        text.push('@');
        text.push_str(version);
    }
    Some(text)
}
