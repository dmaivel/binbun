//! Operand specifiers: the words of an instruction's `OPERANDS` and of a
//! nonterminal rule's bindings (XED's `opnds.parse_one_operand`).
//!
//! A word is `BODY[:ACTION[:EXTRA…]]`.
//!
//! - `BODY` is `NAME=VALUE`, `NAME!=VALUE`, a bare operand name such as
//!   `MEM0` or `RELBR`, `XED_RESET`, or a state macro such as `reset_rex`,
//!   which is expanded and its words parsed in turn.
//! - `ACTION` is how the operand is accessed (`r`, `w`, `rw`, `cr`, `cw`,
//!   `crw`, `rcw`); it defaults to `r`.
//! - Each `EXTRA` is a visibility (`EXPL`, `IMPL`, `SUPP`, `ECOND`) in the
//!   second or third position, `MULTISOURCE4`-style register counts,
//!   `TXT=NAME` print conversions, the width code (the first lowercase word,
//!   e.g. `v` or `mem32real`), and then the element type (e.g. `f32`, `2f16`).
//!
//! Operands with visibility `ECOND` exist only for the encoder and are dropped,
//! as in XED's decoder.

use binbun_semantics::core::Keyword;

use crate::pattern::{Bit, Test};
use crate::state::StateMacros;
use crate::{Error, ErrorKind, value};

/// One parsed word of an operand list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Word<'a> {
    /// An operand or field binding.
    Operand(Operand<'a>),
    /// `XED_RESET`: restart the enclosing nonterminal after a prefix.
    Reset,
}

/// An operand or a field binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operand<'a> {
    /// Operand or field name, e.g. `REG0`, `MEM0`, `OUTREG`, `REXW`.
    pub name: &'a str,
    /// `=` or `!=`. Bare operands such as `MEM0` use `=`.
    pub test: Test,
    /// The bound value.
    pub value: Value<'a>,
    /// How the operand is accessed.
    pub action: Action,
    /// Visibility in assembly; `None` uses the field's default.
    pub visibility: Option<Visibility>,
    /// Width code, e.g. `v`, `q`, `mem32real`.
    pub width: Option<&'a str>,
    /// Element type, e.g. `f32`, `2f16`.
    pub element_type: Option<&'a str>,
    /// `MULTISOURCE4` and similar: an operand naming several consecutive registers.
    pub multireg: Option<(MultiReg, u8)>,
    /// `TXT=NAME` print conversions, in order.
    pub conversions: Vec<&'a str>,
}

/// The value bound to an operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    /// A bare operand name (`MEM0`, `IMM0`, `AGEN`, `RELBR`, `ABSBR`, `PTR`):
    /// the operand is present.
    Present,
    /// `XED_REG_…`, the full enumerator name.
    Register(&'a str),
    /// `XED_ERROR_…`, the full enumerator name.
    Error(&'a str),
    /// Another `XED_…` enumerator name.
    Enumerator(&'a str),
    /// A number.
    Number(u64),
    /// Bits captured from the pattern by letter, e.g. `w` in `REXW=w`.
    Bits(Vec<Bit>),
    /// The value a lookup nonterminal returns, by name without `()`.
    Lookup(&'a str),
}

/// How an operand is accessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
pub enum Action {
    /// `r`
    #[keyword("r")]
    Read,
    /// `w`
    #[keyword("w")]
    Write,
    /// `rw`
    #[keyword("rw")]
    ReadWrite,
    /// `cr`: conditionally read.
    #[keyword("cr")]
    ConditionalRead,
    /// `cw`: conditionally written.
    #[keyword("cw")]
    ConditionalWrite,
    /// `crw`: conditionally read, always written.
    #[keyword("crw")]
    ConditionalReadWrite,
    /// `rcw`: read, conditionally written.
    #[keyword("rcw")]
    ReadConditionalWrite,
}

/// Whether an operand appears in assembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
pub enum Visibility {
    /// `EXPL`: written in assembly.
    #[keyword("EXPL")]
    Explicit,
    /// `IMPL`: implied by the mnemonic but shown.
    #[keyword("IMPL")]
    Implicit,
    /// `SUPP`: not shown.
    #[keyword("SUPP")]
    Suppressed,
    /// `ECOND`: an encoder-only condition.
    #[keyword("ECOND")]
    EncoderCondition,
}

/// Which way a multi-register operand goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "UPPERCASE")]
pub enum MultiReg {
    /// `MULTISOURCEn`
    Source,
    /// `MULTIDESTn`
    Dest,
    /// `MULTISOURCEDESTn`
    SourceDest,
}

/// Parses an operand list, expanding state macros, and drops encoder-only
/// (`ECOND`) operands.
///
/// # Errors
///
/// [`ErrorKind::Malformed`] for a word that does not follow the grammar above
/// or a bare word that is not a state macro.
pub fn parse<'a>(
    line: u32,
    text: &'a str,
    macros: &StateMacros<'a>,
) -> Result<Vec<Word<'a>>, Error> {
    let mut words = Vec::new();
    for word in text.split_whitespace() {
        let bare = !word.contains(['=', ':']) && !is_bare_operand(word) && word != "XED_RESET";
        if bare {
            let expansion = macros
                .get(word)
                .ok_or_else(|| malformed(line, "operand", word))?;
            for &word in expansion {
                push_word(line, word, &mut words)?;
            }
        } else {
            push_word(line, word, &mut words)?;
        }
    }
    Ok(words)
}

fn push_word<'a>(line: u32, word: &'a str, words: &mut Vec<Word<'a>>) -> Result<(), Error> {
    let mut chunks = word.split(':');
    let body = chunks.next().unwrap_or_default();
    if body == "XED_RESET" {
        words.push(Word::Reset);
        return Ok(());
    }
    let action = match chunks.next() {
        None | Some("") => Action::Read,
        Some(action) => action
            .parse()
            .map_err(|_| malformed(line, "operand action", word))?,
    };
    let mut operand = body_operand(body).ok_or_else(|| malformed(line, "operand", word))?;
    operand.action = action;
    for (position, chunk) in (2..).zip(chunks) {
        let visibility = (position <= 3)
            .then(|| chunk.parse::<Visibility>().ok())
            .flatten();
        if let Some(visibility) = visibility {
            operand.visibility = Some(visibility);
        } else if let Some(multireg) = multireg(chunk) {
            operand.multireg = Some(multireg);
        } else if let Some(conversion) = chunk.strip_prefix("TXT=") {
            operand.conversions.push(conversion);
        } else if operand.width.is_none() && chunk.starts_with(|c: char| c.is_ascii_lowercase()) {
            operand.width =
                Some(lower_identifier(chunk).ok_or_else(|| malformed(line, "width code", word))?);
        } else if operand.width.is_some() && operand.element_type.is_none() {
            operand.element_type =
                Some(lower_identifier(chunk).ok_or_else(|| malformed(line, "element type", word))?);
        } else {
            return Err(malformed(line, "operand modifier", word));
        }
    }
    if operand.visibility != Some(Visibility::EncoderCondition) {
        words.push(Word::Operand(operand));
    }
    Ok(())
}

fn malformed(line: u32, what: &str, word: &str) -> Error {
    Error::new(line, ErrorKind::Malformed(format!("{what} `{word}`")))
}

/// The operand described by a word's body, with default modifiers.
fn body_operand(body: &str) -> Option<Operand<'_>> {
    if body.contains('/') {
        return None;
    }
    let (name, test, value) = if let Some((name, value)) = body.split_once("!=") {
        let value = match value {
            register if register.starts_with("XED_REG_") => Value::Register(register),
            number => Value::Number(value::number(number)?),
        };
        (name, Test::Ne, value)
    } else if let Some((name, value)) = body.split_once('=') {
        (name, Test::Eq, binding_value(value)?)
    } else if is_bare_operand(body) {
        (body, Test::Eq, Value::Present)
    } else {
        return None;
    };
    let valid_name = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    valid_name.then_some(Operand {
        name,
        test,
        value,
        action: Action::Read,
        visibility: None,
        width: None,
        element_type: None,
        multireg: None,
        conversions: Vec::new(),
    })
}

/// The right side of `NAME=VALUE`, classified as XED does.
fn binding_value(value: &str) -> Option<Value<'_>> {
    // Lookup nonterminals may start in lowercase here (`rIP()`, `rFLAGS()`).
    if let Some(nonterminal) = value.strip_suffix("()") {
        let identifier = !nonterminal.is_empty()
            && nonterminal
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        return identifier.then_some(Value::Lookup(nonterminal));
    }
    if value.starts_with("XED_REG_") {
        return Some(Value::Register(value));
    }
    if value.starts_with("XED_ERROR_") {
        return Some(Value::Error(value));
    }
    if value.starts_with("XED_") {
        return Some(Value::Enumerator(value));
    }
    if let Some(number) = value::number(value) {
        return Some(Value::Number(number));
    }
    let letters = !value.is_empty() && value.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    letters.then(|| Value::Bits(value.bytes().filter(|&b| b != b'_').map(Bit::Var).collect()))
}

/// Operand names XED binds to 1 when written bare.
fn is_bare_operand(body: &str) -> bool {
    matches!(
        body,
        "MEM0" | "MEM1" | "IMM0" | "IMM1" | "IMM2" | "IMM3" | "AGEN" | "RELBR" | "ABSBR" | "PTR"
    )
}

/// `MULTISOURCEn`, `MULTIDESTn` or `MULTISOURCEDESTn`.
fn multireg(chunk: &str) -> Option<(MultiReg, u8)> {
    let rest = chunk.strip_prefix("MULTI")?;
    let digits = rest.find(|c: char| c.is_ascii_digit())?;
    let (kind, count) = rest.split_at(digits);
    Some((kind.parse().ok()?, count.parse().ok()?))
}

/// A lowercase-or-digit identifier such as `mem32real` or `2f16`.
fn lower_identifier(chunk: &str) -> Option<&str> {
    let valid = !chunk.is_empty()
        && chunk
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    valid.then_some(chunk)
}

#[cfg(test)]
mod tests {
    use super::{Action, MultiReg, Operand, Value, Visibility, Word, parse};
    use crate::pattern::{Bit, Test};
    use crate::{Datafile, StateMacros};

    fn operand<'a>(name: &'a str, value: Value<'a>) -> Operand<'a> {
        Operand {
            name,
            test: Test::Eq,
            value,
            action: Action::Read,
            visibility: None,
            width: None,
            element_type: None,
            multireg: None,
            conversions: Vec::new(),
        }
    }

    fn words(text: &str) -> Vec<Word<'_>> {
        parse(1, text, &StateMacros::default()).unwrap()
    }

    fn single(text: &str) -> Operand<'_> {
        let mut words = words(text);
        match (words.pop(), words.is_empty()) {
            (Some(Word::Operand(op)), true) => op,
            other => panic!("expected one operand, got {other:?}"),
        }
    }

    #[test]
    fn reads_modifiers_in_any_order_after_the_action() {
        let op = single("REG0=XED_REG_ST0:rw:SUPP:f80");
        assert_eq!(
            (op.value, op.action, op.visibility, op.width),
            (
                Value::Register("XED_REG_ST0"),
                Action::ReadWrite,
                Some(Visibility::Suppressed),
                Some("f80")
            )
        );

        let op = single("REG0=ZMM_R3():w:zf32:TXT=ZEROSTR:MULTIDEST2");
        assert_eq!(op.value, Value::Lookup("ZMM_R3"));
        assert_eq!((op.width, op.element_type), (Some("zf32"), None));
        assert_eq!(op.conversions, ["ZEROSTR"]);
        assert_eq!(op.multireg, Some((MultiReg::Dest, 2)));
    }

    #[test]
    fn classifies_binding_values() {
        assert_eq!(
            words(
                "MEM0 REXW=w IMM_WIDTH=16 ERROR=XED_ERROR_BAD OUTREG=XED_REG_AX BCAST!=0 XED_RESET"
            ),
            [
                Word::Operand(operand("MEM0", Value::Present)),
                Word::Operand(operand("REXW", Value::Bits(vec![Bit::Var(b'w')]))),
                Word::Operand(operand("IMM_WIDTH", Value::Number(16))),
                Word::Operand(operand("ERROR", Value::Error("XED_ERROR_BAD"))),
                Word::Operand(operand("OUTREG", Value::Register("XED_REG_AX"))),
                Word::Operand(Operand {
                    test: Test::Ne,
                    ..operand("BCAST", Value::Number(0))
                }),
                Word::Reset,
            ]
        );
    }

    #[test]
    fn element_type_follows_the_width_and_encoder_conditions_are_dropped() {
        let op = single("MEM0:r:dq:2f16 BASE0=SrSP():rw:SUPP:ECOND");
        assert_eq!((op.width, op.element_type), (Some("dq"), Some("2f16")));
        assert!(parse(1, "MEM0:r:2f16", &StateMacros::default()).is_err());
    }

    #[test]
    fn expands_state_macros_and_rejects_unknown_bare_words() {
        let state = Datafile::new("reset_rex REX=0 REXW=0\n");
        let macros = StateMacros::parse(&state).unwrap();
        let expanded = parse(1, "XED_RESET reset_rex", &macros).unwrap();
        assert_eq!(expanded.len(), 3);
        assert!(parse(1, "not_a_macro", &macros).is_err());
    }

    #[test]
    fn rejects_malformed_words() {
        for text in [
            "REG0=XED_REG_AX:rx",
            "A=b/2",
            "lower=1",
            "A=Bad",
            "MEM0:r:q:f32:u8",
            "A!=x",
        ] {
            assert!(parse(1, text, &StateMacros::default()).is_err(), "{text}");
        }
    }
}
