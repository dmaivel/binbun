//! Turning specification names into Rust identifiers.

use std::collections::HashMap;

use proc_macro2::{Ident, Span};

use crate::Result;

/// `REP_MOVSB` → `RepMovsb`, `VFMADD132PS` → `Vfmadd132ps`, `x87` → `X87`.
pub fn camel_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for word in name.split('_').filter(|word| !word.is_empty()) {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars.map(|c| c.to_ascii_lowercase()));
        }
    }
    out
}

/// An identifier, rejecting text that is not one.
pub fn ident(name: &str) -> Result<Ident> {
    let valid = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(format!("`{name}` is not a Rust identifier").into());
    }
    Ok(Ident::new(name, Span::call_site()))
}

/// Identifiers for `names`, failing if two names map to the same identifier.
pub fn unique_idents<'a>(
    names: impl IntoIterator<Item = &'a str>,
    to_ident: impl Fn(&str) -> String,
) -> Result<Vec<Ident>> {
    let mut seen: HashMap<String, &str> = HashMap::new();
    names
        .into_iter()
        .map(|name| {
            let converted = to_ident(name);
            if let Some(other) = seen.insert(converted.clone(), name) {
                return Err(format!("`{other}` and `{name}` both become `{converted}`").into());
            }
            ident(&converted)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{camel_case, ident, unique_idents};

    #[test]
    fn camel_case_lowers_word_tails() {
        assert_eq!(camel_case("REP_MOVSB"), "RepMovsb");
        assert_eq!(camel_case("VFMADD132PS"), "Vfmadd132ps");
        assert_eq!(camel_case("pseudox87"), "Pseudox87");
        assert_eq!(camel_case("A__B_"), "AB");
    }

    #[test]
    fn rejects_collisions_and_non_identifiers() {
        assert!(unique_idents(["AB_C", "ab_c"], camel_case).is_err());
        assert!(unique_idents(["A_B", "AB"], camel_case).is_ok());
        assert!(ident("3DNOW").is_err());
        assert!(ident("A-B").is_err());
    }
}
