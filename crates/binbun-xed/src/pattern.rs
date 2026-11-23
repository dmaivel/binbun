//! Decode patterns: the `PATTERN` of an instruction record and the left side
//! of a nonterminal rule (XED's `parse_opcode_spec`).
//!
//! A pattern is a sequence of whitespace-separated words. State macros are
//! expanded first (see [`StateMacros`]); then each word is, in XED's order:
//!
//! | Word | Meaning |
//! |---|---|
//! | `otherwise` | the rule that applies when no other rule of the nonterminal does |
//! | `0x0F` | literal bits, padded on the left to a multiple of 8 |
//! | `MOD[mm]`, `REG[0b100]` | bits captured into a field, letters are variable bits |
//! | `MODRM()` | a nonterminal |
//! | `MODE=2`, `REP!=0` | a constraint on a field's value |
//! | `0b0100` | literal bits, exactly as wide as written |
//! | `wrxb`, `1101_1rrr` | bits: `0`/`1` literal, letters variable, `_` ignored |
//!
//! `x/N` stands for `N` copies of the variable bit `x` (`UIMM0[i/16]`), as in
//! XED's slash expansion. Identical constraints in one pattern are kept once.
//!
//! An instruction pattern may contain one `REG[lo-hi]`; XED turns such a form
//! into one form per value (`genutil.expand_reg_range`). Find the range with
//! [`reg_range`] and parse each instance with [`parse_with_reg`].

use std::ops::RangeInclusive;

use binbun_semantics::core::Keyword;

use crate::state::StateMacros;
use crate::{Error, ErrorKind, value};

/// One bit of a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bit {
    /// A literal 0.
    Zero,
    /// A literal 1.
    One,
    /// A variable bit; bits with the same letter in one capture form one value.
    Var(u8),
}

/// A decode pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern<'a> {
    /// The fallback rule of a nonterminal.
    Otherwise,
    /// Tokens to match, in order.
    Tokens(Vec<Token<'a>>),
}

/// One element of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token<'a> {
    /// Bits to match.
    Bits(Vec<Bit>),
    /// Bits to match and store into `field`.
    Capture {
        /// Field that receives the bits.
        field: &'a str,
        /// The bits.
        bits: Vec<Bit>,
    },
    /// A nonterminal to match, by name without `()`.
    Nonterminal(&'a str),
    /// A required field value.
    Constraint(Constraint<'a>),
}

/// `FIELD=value` or `FIELD!=value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Constraint<'a> {
    /// The constrained field.
    pub field: &'a str,
    /// Equal or not equal.
    pub test: Test,
    /// The value.
    pub value: u64,
}

/// How a [`Constraint`] compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
pub enum Test {
    /// `=`
    #[keyword("=")]
    Eq,
    /// `!=`
    #[keyword("!=")]
    Ne,
}

/// Parses the pattern `text` from line `line`, expanding `macros`.
///
/// # Errors
///
/// [`ErrorKind::Malformed`] for a word that is none of the forms above, or
/// for `otherwise` combined with other words.
pub fn parse<'a>(line: u32, text: &'a str, macros: &StateMacros<'a>) -> Result<Pattern<'a>, Error> {
    parse_with_reg(line, text, macros, None)
}

/// Like [`parse`], but a `REG[lo-hi]` word becomes the 3-bit capture
/// `REG[reg]`. Without `reg`, such a word is an error.
///
/// # Errors
///
/// As [`parse`].
pub fn parse_with_reg<'a>(
    line: u32,
    text: &'a str,
    macros: &StateMacros<'a>,
    reg: Option<u8>,
) -> Result<Pattern<'a>, Error> {
    let mut tokens: Vec<Token<'a>> = Vec::new();
    for word in text.split_whitespace() {
        if word == "otherwise" {
            return if text.split_whitespace().count() == 1 {
                Ok(Pattern::Otherwise)
            } else {
                Err(Error::new(
                    line,
                    ErrorKind::Malformed("`otherwise` with other words".to_owned()),
                ))
            };
        }
        if let (Some(reg), Some(_)) = (reg, range_word(word)) {
            let bits = (0..3)
                .rev()
                .map(|i| {
                    if (reg >> i) & 1 == 1 {
                        Bit::One
                    } else {
                        Bit::Zero
                    }
                })
                .collect();
            tokens.push(Token::Capture { field: "REG", bits });
            continue;
        }
        match macros.get(word) {
            Some(expansion) => {
                for &word in expansion {
                    push_word(line, word, &mut tokens)?;
                }
            }
            None => push_word(line, word, &mut tokens)?,
        }
    }
    Ok(Pattern::Tokens(tokens))
}

/// The values of the `REG[lo-hi]` word in `text`, if there is one.
///
/// # Errors
///
/// [`ErrorKind::Malformed`] for more than one such word, `lo > hi`, or
/// `hi > 7` (`REG` is three bits).
pub fn reg_range(line: u32, text: &str) -> Result<Option<RangeInclusive<u8>>, Error> {
    let mut ranges = text.split_whitespace().filter_map(range_word);
    let range = ranges.next();
    let valid = range
        .as_ref()
        .is_none_or(|range| range.start() <= range.end() && *range.end() <= 7);
    if ranges.next().is_some() || !valid {
        return Err(Error::new(
            line,
            ErrorKind::Malformed("`REG[lo-hi]` range".to_owned()),
        ));
    }
    Ok(range)
}

/// `REG[lo-hi]` with decimal bounds.
fn range_word(word: &str) -> Option<RangeInclusive<u8>> {
    let (lo, hi) = word
        .strip_prefix("REG[")?
        .strip_suffix(']')?
        .split_once('-')?;
    Some(lo.parse().ok()?..=hi.parse().ok()?)
}

fn push_word<'a>(line: u32, word: &'a str, tokens: &mut Vec<Token<'a>>) -> Result<(), Error> {
    let bad = || Error::new(line, ErrorKind::Malformed(format!("pattern word `{word}`")));
    let token = if word.starts_with("0x") || word.starts_with("0X") {
        Token::Bits(hex_bits(word).ok_or_else(bad)?)
    } else if let Some((field, bits)) = capture(word) {
        Token::Capture {
            field,
            bits: bits_of(bits).ok_or_else(bad)?,
        }
    } else if let Some(name) = nonterminal(word) {
        Token::Nonterminal(name)
    } else if let Some((field, test, value)) = constraint(word) {
        let value = value::number(value).ok_or_else(bad)?;
        let token = Token::Constraint(Constraint { field, test, value });
        if tokens.contains(&token) {
            return Ok(());
        }
        token
    } else {
        Token::Bits(bits_of(word).ok_or_else(bad)?)
    };
    tokens.push(token);
    Ok(())
}

/// `Name()`, where a name starts with an uppercase letter.
pub fn nonterminal(word: &str) -> Option<&str> {
    let name = word.strip_suffix("()")?;
    let mut chars = name.chars();
    let starts_upper = chars.next().is_some_and(|c| c.is_ascii_uppercase());
    (starts_upper && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')).then_some(name)
}

/// `FIELD[bits]`, returning the field and the text between the brackets.
fn capture(word: &str) -> Option<(&str, &str)> {
    let (field, rest) = word.split_once('[')?;
    let bits = rest.strip_suffix(']')?;
    is_field_name(field).then_some((field, bits))
}

/// `FIELD=value` or `FIELD!=value`, with the value still unparsed.
fn constraint(word: &str) -> Option<(&str, Test, &str)> {
    let (field, test, value) = if let Some((field, value)) = word.split_once("!=") {
        (field, Test::Ne, value)
    } else {
        let (field, value) = word.split_once('=')?;
        (field, Test::Eq, value)
    };
    is_field_name(field).then_some((field, test, value))
}

fn is_field_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Bits of a hex literal: its value in binary, padded on the left to a
/// multiple of 8 bits (`genutil.hex_to_binary` + `pad_to_multiple_of_8bits`).
fn hex_bits(word: &str) -> Option<Vec<Bit>> {
    let value = value::number(word)?;
    let significant = value.bit_width().max(1);
    let width = significant.div_ceil(8) * 8;
    Some(
        (0..width)
            .rev()
            .map(|i| {
                if (value >> i) & 1 == 1 {
                    Bit::One
                } else {
                    Bit::Zero
                }
            })
            .collect(),
    )
}

/// Bits of a `0b…` literal or of a bit/letter word, with `_` ignored and
/// `x/N` expanded to `N` copies of `x`.
fn bits_of(text: &str) -> Option<Vec<Bit>> {
    let text = text.strip_prefix("0b").unwrap_or(text);
    let bytes = text.as_bytes();
    let mut bits = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        let bit = match byte {
            b'0' => Bit::Zero,
            b'1' => Bit::One,
            b'_' => {
                i += 1;
                continue;
            }
            b'a'..=b'z' => Bit::Var(byte),
            _ => return None,
        };
        i += 1;
        if bytes.get(i) == Some(&b'/') {
            let digits: &[u8] = bytes.get(i + 1..)?;
            let len = digits
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count()
                .min(2);
            let count: usize = std::str::from_utf8(digits.get(..len)?).ok()?.parse().ok()?;
            if !matches!(bit, Bit::Var(_)) {
                return None;
            }
            bits.extend(std::iter::repeat_n(bit, count));
            i += 1 + len;
        } else {
            bits.push(bit);
        }
    }
    (!bits.is_empty()).then_some(bits)
}

#[cfg(test)]
mod tests {
    use super::{Bit, Constraint, Pattern, Test, Token, parse, parse_with_reg, reg_range};
    use crate::{Datafile, state::StateMacros};

    fn bits(text: &str) -> Vec<Bit> {
        text.bytes()
            .map(|b| match b {
                b'0' => Bit::Zero,
                b'1' => Bit::One,
                _ => Bit::Var(b),
            })
            .collect()
    }

    fn tokens(text: &str) -> Vec<Token<'_>> {
        let empty = StateMacros::default();
        match parse(1, text, &empty).unwrap() {
            Pattern::Tokens(tokens) => tokens,
            Pattern::Otherwise => panic!("unexpected otherwise"),
        }
    }

    #[test]
    fn classifies_every_word_form() {
        assert_eq!(
            tokens("0x0F MOD[mm] MODRM() REP!=0 0b0100 1101_1rrr UIMM0[i/16]"),
            [
                Token::Bits(bits("00001111")),
                Token::Capture {
                    field: "MOD",
                    bits: bits("mm")
                },
                Token::Nonterminal("MODRM"),
                Token::Constraint(Constraint {
                    field: "REP",
                    test: Test::Ne,
                    value: 0
                }),
                Token::Bits(bits("0100")),
                Token::Bits(bits("11011rrr")),
                Token::Capture {
                    field: "UIMM0",
                    bits: bits(&"i".repeat(16))
                },
            ]
        );
    }

    #[test]
    fn hex_literals_are_padded_to_whole_bytes() {
        assert_eq!(tokens("0x0"), [Token::Bits(bits("00000000"))]);
        assert_eq!(tokens("0x1FF"), [Token::Bits(bits("0000000111111111"))]);
    }

    #[test]
    fn expands_state_macros_and_drops_duplicate_constraints() {
        let state = Datafile::new("mode64 MODE=2\nnot64 MODE!=2\n");
        let macros = StateMacros::parse(&state).unwrap();
        let Pattern::Tokens(tokens) = parse(1, "mode64 MODE=2 not64", &macros).unwrap() else {
            panic!("expected tokens")
        };
        assert_eq!(
            tokens,
            [
                Token::Constraint(Constraint {
                    field: "MODE",
                    test: Test::Eq,
                    value: 2
                }),
                Token::Constraint(Constraint {
                    field: "MODE",
                    test: Test::Ne,
                    value: 2
                }),
            ]
        );
    }

    #[test]
    fn otherwise_must_stand_alone() {
        let empty = StateMacros::default();
        assert_eq!(parse(1, "otherwise", &empty).unwrap(), Pattern::Otherwise);
        assert!(parse(1, "MODE=1 otherwise", &empty).is_err());
    }

    #[test]
    fn rejects_unknown_words() {
        let empty = StateMacros::default();
        for text in [
            "0xZZ",
            "MOD[m-1]",
            "MODE=XED_REG_AX",
            "ab$",
            "Foo(x)",
            "REG[1-7]",
            "1/3",
        ] {
            assert!(parse(1, text, &empty).is_err(), "{text}");
        }
    }

    #[test]
    fn reg_ranges_expand_to_three_bit_captures() {
        let empty = StateMacros::default();
        let text = "0x0F MOD[mm] REG[1-7] RM[nnn]";
        assert_eq!(reg_range(1, text).unwrap(), Some(1..=7));
        let Pattern::Tokens(tokens) = parse_with_reg(1, text, &empty, Some(5)).unwrap() else {
            panic!("expected tokens")
        };
        assert_eq!(
            tokens.get(2),
            Some(&Token::Capture {
                field: "REG",
                bits: bits("101")
            })
        );
        assert!(reg_range(1, "REG[3-2]").is_err());
        assert!(reg_range(1, "REG[0-8]").is_err());
        assert!(reg_range(1, "REG[0-1] REG[2-3]").is_err());
    }
}
