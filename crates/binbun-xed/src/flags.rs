//! The `FLAGS` field of an instruction record (XED's `flag_gen.flags_info_t`).
//!
//! A specification is one or more comma-separated records
//! `[QUALIFIER] STRENGTH [ flag-action … ]`, for example
//! `IMM1 MUST [ of-mod cf-mod ], IMMx MUST [ of-u cf-mod ]`: with an
//! immediate count of 1, `OF` and `CF` are written; otherwise `OF` is
//! undefined. Flag actions are case-insensitive; the single action
//! `nothing` means the record touches no flag.

use binbun_semantics::core::Keyword;

use crate::{Error, ErrorKind};

/// One flags record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagRecord {
    /// When the record applies; `None` means always.
    pub qualifier: Option<Qualifier>,
    /// Whether the effects always happen.
    pub strength: Strength,
    /// Effects, in order. Empty for `nothing`.
    pub actions: Vec<FlagEffect>,
}

/// One `flag-action` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlagEffect {
    /// The flag.
    pub flag: Flag,
    /// What happens to it.
    pub action: FlagAction,
}

/// The condition a qualified record applies under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
pub enum Qualifier {
    /// A `REP` prefix is present.
    #[keyword("REP")]
    Rep,
    /// No `REP` prefix.
    #[keyword("NOREP")]
    NoRep,
    /// The immediate is 0.
    #[keyword("IMM0")]
    ImmZero,
    /// The immediate is 1.
    #[keyword("IMM1")]
    ImmOne,
    /// Any other immediate.
    #[keyword("IMMx")]
    ImmOther,
}

/// How certain a record's effects are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "UPPERCASE")]
pub enum Strength {
    /// The effects may happen (e.g. depend on a count of zero).
    May,
    /// The effects always happen.
    Must,
    /// Flags are only read.
    Readonly,
}

/// An x86 or x87 flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "lowercase")]
pub enum Flag {
    /// Overflow.
    Of,
    /// Sign.
    Sf,
    /// Zero.
    Zf,
    /// Auxiliary carry.
    Af,
    /// Parity.
    Pf,
    /// Carry.
    Cf,
    /// Direction.
    Df,
    /// Virtual interrupt.
    Vif,
    /// I/O privilege level.
    Iopl,
    /// Interrupt enable.
    If,
    /// Alignment check.
    Ac,
    /// Virtual-8086 mode.
    Vm,
    /// Resume.
    Rf,
    /// Nested task.
    Nt,
    /// Trap.
    Tf,
    /// CPUID available.
    Id,
    /// Virtual interrupt pending.
    Vip,
    /// x87 condition code 0.
    Fc0,
    /// x87 condition code 1.
    Fc1,
    /// x87 condition code 2.
    Fc2,
    /// x87 condition code 3.
    Fc3,
}

/// What an instruction does to a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
pub enum FlagAction {
    /// Modified according to the result.
    #[keyword("mod")]
    Modify,
    /// Read.
    #[keyword("tst")]
    Test,
    /// Left architecturally undefined.
    #[keyword("u")]
    Undefined,
    /// Cleared.
    #[keyword("0")]
    Clear,
    /// Set.
    #[keyword("1")]
    Set,
    /// Loaded from `AH` (`SAHF`).
    #[keyword("ah")]
    FromAh,
    /// Loaded from the stack (`POPF`).
    #[keyword("pop")]
    Pop,
}

impl FlagAction {
    /// Whether the action reads the flag.
    pub const fn reads(self) -> bool {
        matches!(self, Self::Test)
    }

    /// Whether the action writes the flag (every action but a test does).
    pub const fn writes(self) -> bool {
        !self.reads()
    }
}

/// Parses a `FLAGS` value found on line `line`.
///
/// # Errors
///
/// [`ErrorKind::Malformed`] for a record without `[ … ]`, an unknown
/// qualifier, strength, flag or action, or a `nothing` mixed with actions.
pub fn parse(line: u32, text: &str) -> Result<Vec<FlagRecord>, Error> {
    text.split(',')
        .map(|record| parse_record(line, record))
        .collect()
}

fn parse_record(line: u32, record: &str) -> Result<FlagRecord, Error> {
    let bad = |what: &str| {
        Error::new(
            line,
            ErrorKind::Malformed(format!("flags {what} in `{record}`")),
        )
    };
    let (head, rest) = record
        .split_once('[')
        .ok_or_else(|| bad("record without `[`"))?;
    let body = rest
        .trim_end()
        .strip_suffix(']')
        .ok_or_else(|| bad("record without `]`"))?;

    let mut head = head.split_whitespace();
    let first = head.next().ok_or_else(|| bad("record without strength"))?;
    let (qualifier, strength) = match first.parse::<Qualifier>() {
        Ok(qualifier) => (
            Some(qualifier),
            head.next().ok_or_else(|| bad("record without strength"))?,
        ),
        Err(_) => (None, first),
    };
    let strength = strength.parse().map_err(|_| bad("strength"))?;
    if head.next().is_some() {
        return Err(bad("extra words before `[`"));
    }

    let words: Vec<&str> = body.split_whitespace().collect();
    let actions = if words.as_slice() == ["nothing"] {
        Vec::new()
    } else {
        words
            .iter()
            .map(|word| {
                let (flag, action) = word.split_once('-').ok_or_else(|| bad("flag action"))?;
                Ok(FlagEffect {
                    flag: Flag::from_keyword_ignore_ascii_case(flag).ok_or_else(|| bad("flag"))?,
                    action: FlagAction::from_keyword_ignore_ascii_case(action)
                        .ok_or_else(|| bad("action"))?,
                })
            })
            .collect::<Result<_, Error>>()?
    };
    Ok(FlagRecord {
        qualifier,
        strength,
        actions,
    })
}

#[cfg(test)]
mod tests {
    use super::{Flag, FlagAction, FlagEffect, FlagRecord, Qualifier, Strength, parse};

    fn effect(flag: Flag, action: FlagAction) -> FlagEffect {
        FlagEffect { flag, action }
    }

    #[test]
    fn reads_qualified_records_and_upper_case_actions() {
        assert_eq!(
            parse(1, "IMM1 MUST [ of-mod cf-mod ], IMMx MUST [ OF-U  cf-tst ]").unwrap(),
            [
                FlagRecord {
                    qualifier: Some(Qualifier::ImmOne),
                    strength: Strength::Must,
                    actions: vec![
                        effect(Flag::Of, FlagAction::Modify),
                        effect(Flag::Cf, FlagAction::Modify)
                    ],
                },
                FlagRecord {
                    qualifier: Some(Qualifier::ImmOther),
                    strength: Strength::Must,
                    actions: vec![
                        effect(Flag::Of, FlagAction::Undefined),
                        effect(Flag::Cf, FlagAction::Test)
                    ],
                },
            ]
        );
    }

    #[test]
    fn nothing_means_no_effects() {
        let records = parse(1, "REP MAY [ nothing ]").unwrap();
        assert_eq!(records[0].actions, []);
        assert_eq!(records[0].qualifier, Some(Qualifier::Rep));
    }

    #[test]
    fn rejects_malformed_records() {
        for text in [
            "MUST of-mod",
            "SOMETIMES [ of-mod ]",
            "MUST [ xf-mod ]",
            "MUST [ of-zap ]",
            "IMM1 [ of-mod ]",
            "MUST [ nothing of-mod ]",
        ] {
            assert!(parse(1, text).is_err(), "{text}");
        }
    }
}
