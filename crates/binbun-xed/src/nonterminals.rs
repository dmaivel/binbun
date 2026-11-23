//! Nonterminal tables: sections of `all-dec-patterns.txt` and
//! `all-dec-spine.txt` whose name does not contain `INSTRUCTIONS` (XED's
//! `read_flat_input`).
//!
//! Each line is a rule `PATTERN | BINDINGS`. The pattern is matched against the
//! input (see [`pattern`](crate::pattern)); the bindings set fields or name the
//! value a lookup nonterminal returns, e.g. `EOSZ=1 | OUTREG=XED_REG_AX`.
//! Sections with the same name form one nonterminal, rules in file order.

use crate::pattern::{self, Pattern};
use crate::state::StateMacros;
use crate::{Datafile, Error, ErrorKind};

/// A nonterminal and its rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonterminal<'a> {
    /// Name without `()`, e.g. `MODRM` or `rFLAGS`.
    pub name: &'a str,
    /// What a lookup nonterminal returns, e.g. `xed_reg_enum_t`.
    pub return_type: Option<&'a str>,
    /// Line of its first header.
    pub line: u32,
    /// Rules in file order.
    pub rules: Vec<Rule<'a>>,
}

/// One `PATTERN | BINDINGS` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule<'a> {
    /// Line number.
    pub line: u32,
    /// What the rule matches.
    pub pattern: Pattern<'a>,
    /// Field bindings and outputs, unparsed. May be empty.
    pub bindings: &'a str,
}

/// Parses the nonterminal sections of `file`, merging sections with the same
/// name, in order of their first header. Instruction sections are skipped.
///
/// # Errors
///
/// A rule without exactly one `|`, a malformed pattern, or headers of the
/// same nonterminal that disagree on the return type.
pub fn parse<'a>(
    file: &'a Datafile<'_>,
    macros: &StateMacros<'a>,
) -> Result<Vec<Nonterminal<'a>>, Error> {
    let mut nonterminals: Vec<Nonterminal<'a>> = Vec::new();
    for section in file.sections()? {
        let header = section.header;
        if header.name.contains("INSTRUCTIONS") {
            continue;
        }
        let existing = nonterminals.iter().position(|nt| nt.name == header.name);
        if let Some(index) = existing
            && nonterminals
                .get(index)
                .is_some_and(|nt| nt.return_type != header.return_type)
        {
            let what = format!(
                "return type of `{}` differs between its sections",
                header.name
            );
            return Err(Error::new(header.line, ErrorKind::Malformed(what)));
        }
        let index = existing.unwrap_or_else(|| {
            nonterminals.push(Nonterminal {
                name: header.name,
                return_type: header.return_type,
                line: header.line,
                rules: Vec::new(),
            });
            nonterminals.len() - 1
        });
        let Some(nonterminal) = nonterminals.get_mut(index) else {
            continue;
        };
        for line in section.body {
            let mut sides = line.text().split('|');
            let (Some(left), Some(right), None) = (sides.next(), sides.next(), sides.next()) else {
                let what = "rule; expected `PATTERN | BINDINGS`".to_owned();
                return Err(Error::new(line.number, ErrorKind::Malformed(what)));
            };
            nonterminal.rules.push(Rule {
                line: line.number,
                pattern: pattern::parse(line.number, left, macros)?,
                bindings: right.trim(),
            });
        }
    }
    Ok(nonterminals)
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::pattern::{Constraint, Pattern, Test, Token};
    use crate::{Datafile, StateMacros};

    #[test]
    fn merges_sections_and_splits_rules() {
        let state = Datafile::new("mode64 MODE=2\n");
        let macros = StateMacros::parse(&state).unwrap();
        let file = Datafile::new(
            "xed_reg_enum_t rFLAGS()::\nmode64 | OUTREG=XED_REG_RFLAGS\n\
             PREFIXES()::\notherwise |\nxed_reg_enum_t rFLAGS()::\nMODE=1 | OUTREG=XED_REG_EFLAGS\n",
        );
        let nonterminals = parse(&file, &macros).unwrap();
        let summary: Vec<_> = nonterminals
            .iter()
            .map(|nt| (nt.name, nt.return_type, nt.rules.len()))
            .collect();
        assert_eq!(
            summary,
            [("rFLAGS", Some("xed_reg_enum_t"), 2), ("PREFIXES", None, 1)]
        );

        let rflags = &nonterminals[0].rules;
        assert_eq!(
            rflags[0].pattern,
            Pattern::Tokens(vec![Token::Constraint(Constraint {
                field: "MODE",
                test: Test::Eq,
                value: 2
            })])
        );
        assert_eq!(
            (rflags[1].line, rflags[1].bindings),
            (6, "OUTREG=XED_REG_EFLAGS")
        );
        assert_eq!(
            (
                &nonterminals[1].rules[0].pattern,
                nonterminals[1].rules[0].bindings
            ),
            (&Pattern::Otherwise, "")
        );
    }

    #[test]
    fn rejects_rules_without_exactly_one_bar() {
        let empty = StateMacros::default();
        for body in ["MODE=1", "MODE=1 | A | B"] {
            let source = format!("NT()::\n{body}\n");
            assert!(parse(&Datafile::new(&source), &empty).is_err(), "{body}");
        }
    }

    #[test]
    fn rejects_conflicting_return_types() {
        let empty = StateMacros::default();
        let file = Datafile::new("a_t NT()::\nMODE=1 |\nb_t NT()::\nMODE=2 |\n");
        assert!(parse(&file, &empty).is_err());
    }
}
