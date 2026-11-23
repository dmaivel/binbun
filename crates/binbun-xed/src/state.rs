//! State macros (`all-state.txt`, XED's `read_state_spec`).
//!
//! Each line is `name word…`. In a pattern, a word equal to a macro name is
//! replaced by the macro's words before the pattern is interpreted, so
//! `mode64` becomes `MODE=2`. Expansion is not recursive. A later
//! definition of the same name replaces an earlier one, as in XED.

use std::collections::HashMap;

use crate::{Datafile, Error, ErrorKind};

/// The state macros of a datafile.
#[derive(Debug, Clone, Default)]
pub struct StateMacros<'a> {
    macros: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> StateMacros<'a> {
    /// Parses `all-state.txt`.
    ///
    /// # Errors
    ///
    /// A line with a name but no words.
    pub fn parse(file: &'a Datafile<'_>) -> Result<Self, Error> {
        let mut macros = HashMap::with_capacity(file.lines().len());
        for line in file.lines() {
            let mut words = line.text().split_whitespace();
            let (Some(name), expansion) = (words.next(), words.collect::<Vec<_>>()) else {
                continue;
            };
            if expansion.is_empty() {
                let what = format!("state macro `{name}` has no expansion");
                return Err(Error::new(line.number, ErrorKind::Malformed(what)));
            }
            macros.insert(name, expansion);
        }
        Ok(Self { macros })
    }

    /// The words `name` expands to, if it is a macro.
    pub fn get(&self, name: &str) -> Option<&[&'a str]> {
        self.macros.get(name).map(Vec::as_slice)
    }

    /// Number of macros.
    pub fn len(&self) -> usize {
        self.macros.len()
    }

    /// Whether there are no macros.
    pub fn is_empty(&self) -> bool {
        self.macros.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::StateMacros;
    use crate::Datafile;

    #[test]
    fn later_definitions_replace_earlier_ones() {
        let file =
            Datafile::new("mode64 MODE=2\nreset_rex REX=0 REXW=0\nmode64 MODE=3 # redefined\n");
        let macros = StateMacros::parse(&file).unwrap();
        assert_eq!(macros.get("mode64"), Some(["MODE=3"].as_slice()));
        assert_eq!(
            macros.get("reset_rex"),
            Some(["REX=0", "REXW=0"].as_slice())
        );
        assert_eq!(macros.get("MODE=2"), None);
    }

    #[test]
    fn a_name_without_words_is_an_error() {
        assert!(StateMacros::parse(&Datafile::new("lonely\n")).is_err());
    }
}
