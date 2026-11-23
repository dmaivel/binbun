//! Hand-written facts that no database binbun embeds states for every
//! target (`data/overrides.toml`), each with the reason it holds: the
//! standard, documentation or source that says so. They have
//! [`Origin::Override`](crate::Origin::Override), below every database.

use std::sync::LazyLock;

use serde::Deserialize;

use crate::database::{Format, TypeRef};
use crate::types::Signature;

/// The overrides file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Overrides {
    #[serde(default)]
    function: Vec<Override>,
}

/// A fact about one function.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// The function's name, as imported (C++ names mangled).
    pub name: String,
    /// The library it is matched in (`None`: any).
    pub library: Option<String>,
    /// Whether it never returns (`false`: says nothing).
    #[serde(default)]
    pub no_return: bool,
    /// The format string it takes.
    pub format: Option<Format>,
    /// Its prototype, for a function no header declares (one the compiler
    /// calls, as `__stack_chk_fail`), in a database's form; built of
    /// primitives only: an override has no types of its own to name.
    pub signature: Option<Signature<TypeRef>>,
    /// Why: the standard, documentation or source that says so.
    pub reason: String,
}

static EMBEDDED: LazyLock<Vec<Override>> = LazyLock::new(|| {
    let overrides: Overrides = toml::from_str(include_str!("../data/overrides.toml"))
        .unwrap_or_else(|error| panic!("data/overrides.toml: {error}"));
    overrides.function
});

/// The embedded overrides, parsed on first use.
///
/// # Panics
///
/// If `data/overrides.toml` does not parse (a test checks it does).
pub fn embedded() -> &'static [Override] {
    &EMBEDDED
}

/// The override for function `name` of `library` (`None`: of any), as
/// [`TypeLibrary::function`](crate::TypeLibrary::function) matches them:
/// one for that library (case-insensitively) first, else one for any.
pub fn find(library: Option<&str>, name: &str) -> Option<&'static Override> {
    let overrides = embedded();
    library
        .and_then(|library| {
            overrides.iter().find(|entry| {
                entry.name == name
                    && entry
                        .library
                        .as_deref()
                        .is_some_and(|own| own.eq_ignore_ascii_case(library))
            })
        })
        .or_else(|| {
            overrides
                .iter()
                .find(|entry| entry.name == name && entry.library.is_none())
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::database::TypeRef;
    use crate::{Origin, Type, TypeLibrary};

    #[test]
    fn parse_with_reasons_and_without_duplicates() {
        let mut seen = BTreeSet::new();
        for entry in super::embedded() {
            assert!(
                entry.reason.len() > 20,
                "{}: the reason must cite where the fact comes from",
                entry.name
            );
            assert!(
                seen.insert((entry.library.clone(), entry.name.clone())),
                "{} is overridden twice",
                entry.name
            );
        }
    }

    /// The stack protector's failure handler, which no header declares,
    /// is `noreturn void (void)` for every target and library.
    #[test]
    fn a_signature_is_the_prototype_of_any_library() {
        let entry = super::find(None, "__stack_chk_fail").unwrap();
        let signature = entry.signature.as_ref().unwrap();
        assert_eq!(signature.ret, TypeRef::Void);
        assert!(signature.params.is_empty() && !signature.variadic);
        let library = TypeLibrary::builtin();
        for module in [None, Some("libc.so.6"), Some("msvcrt.dll")] {
            let declaration = library.function(module, "__stack_chk_fail").unwrap();
            let prototype = declaration.prototype.as_ref().unwrap();
            assert_eq!(prototype.origin, Origin::Override);
            assert_eq!(library.ty(prototype.value.ret), Some(&Type::Void));
            assert!(prototype.value.params.is_empty() && !prototype.value.variadic);
            assert!(declaration.no_return.is_some_and(|fact| fact.value));
        }
    }
}
