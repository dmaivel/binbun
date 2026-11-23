//! The usual names for what has no symbol: dummy names by kind and
//! address, string names from the text.

use crate::listing::{Listing, Name, NameKind};

/// The longest name made from a string's text, `a` included
/// (`aSOptionRequire`).
const STRING_NAME: usize = 15;

/// The name for a string with `text`: `a` and the text's words, each
/// capitalised, alphanumerics only, cut at 15 characters
/// (`"%s: option requires an argument"` → `aSOptionRequire`); `None` if
/// it has no letter or digit (`asc_` then).
pub(crate) fn string_name(text: &str) -> Option<String> {
    let mut name = String::from("a");
    let mut word_start = true;
    for c in text.chars() {
        if name.len() >= STRING_NAME {
            break;
        }
        if c.is_ascii_alphanumeric() {
            name.push(if word_start {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            });
            word_start = false;
        } else {
            word_start = true;
        }
    }
    (name.len() > 1).then_some(name)
}

/// A dummy name: `prefix_` and the address in upper-case hexadecimal.
pub(crate) fn dummy(prefix: &str, address: u64) -> String {
    format!("{prefix}_{address:X}")
}

impl Listing {
    /// Names `address` `text` unless it has a name; whether it did. The
    /// first name for an address stays, and a name already taken gets
    /// `_0`, `_1`…; `automatic` if binbun made it (a dummy name, a
    /// string's), not a symbol or debug information.
    pub(super) fn give(
        &mut self,
        address: u64,
        text: String,
        kind: NameKind,
        automatic: bool,
    ) -> bool {
        if self.names.contains_key(&address) {
            return false;
        }
        let text = if self.by_name.contains_key(&text) {
            (0..=u32::MAX)
                .map(|n| format!("{text}_{n}"))
                .find(|candidate| !self.by_name.contains_key(candidate))
                .unwrap_or(text)
        } else {
            text
        };
        self.by_name.insert(text.clone(), address);
        self.names.insert(
            address,
            Name {
                text,
                kind,
                automatic,
            },
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::string_name;

    #[test]
    fn string_names_take_the_text_s_words() {
        assert_eq!(
            string_name("%s: option requires an argument").as_deref(),
            Some("aSOptionRequire")
        );
        assert_eq!(
            string_name("Read lines from a file into an array variable.\n").as_deref(),
            Some("aReadLinesFromA")
        );
        assert_eq!(string_name("-c").as_deref(), Some("aC"));
        assert_eq!(string_name("BASH_ENV").as_deref(), Some("aBashEnv"));
        assert_eq!(string_name(" \t\n\r=;&|()<>"), None);
    }
}
