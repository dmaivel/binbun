//! Numbers as the listing and the C write them, read back ([`parse`]) and
//! written again in the form the user chose ([`NumberForm::spell`]): the
//! listing's conversions (`H` hexadecimal, decimal, `R` character, `M` an
//! enumeration's constants: [`by_name`]), presentation only.

use binbun_ast::types::Enumeration;

use crate::edits::NumberForm;

/// A number as written: its bits and whether it was written negative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    /// Its bits (a negative number's two's complement).
    pub bits: u64,
    /// Whether it was written with a minus sign.
    pub negative: bool,
}

impl Written {
    /// The number with a minus sign before it: C writes `-1` as the
    /// operator `-` and the literal `1`, one number.
    ///
    /// ```
    /// use binbun_session::number::parse;
    ///
    /// assert_eq!(parse("0x1").map(|n| n.negated()), parse("-1"));
    /// ```
    #[must_use]
    pub const fn negated(self) -> Self {
        Self {
            bits: self.bits.wrapping_neg(),
            negative: !self.negative,
        }
    }
}

/// How hexadecimal numbers are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Radix {
    /// MASM's `88h` (a leading `0` before a letter: `0FFh`).
    Masm,
    /// C's `0x88`.
    C,
}

/// The number `text` writes: decimal, C's or MASM's hexadecimal (`0x88`,
/// `88h`), a character constant (`'A'`, MASM's `'ab'`), a minus sign
/// before any of them, C's integer suffixes (`u`, `l`, `ll` in any case)
/// after them. `None` if it is no number.
///
/// ```
/// use binbun_session::number::{Written, parse};
///
/// assert_eq!(parse("0FFh"), Some(Written { bits: 0xff, negative: false }));
/// assert_eq!(parse("-0x8"), Some(Written { bits: 0u64.wrapping_sub(8), negative: true }));
/// assert_eq!(parse("'A'"), Some(Written { bits: 0x41, negative: false }));
/// assert_eq!(parse("rax"), None);
/// ```
pub fn parse(text: &str) -> Option<Written> {
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let magnitude = if let Some(chars) = body.strip_prefix('\'') {
        character(chars.strip_suffix('\'')?)?
    } else {
        let body = body.trim_end_matches(['u', 'U', 'l', 'L']);
        if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()?
        } else if let Some(hex) = body.strip_suffix(['h', 'H']) {
            if !hex.starts_with(|c: char| c.is_ascii_digit()) {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()?
        } else {
            if !body.starts_with(|c: char| c.is_ascii_digit()) {
                return None;
            }
            body.parse().ok()?
        }
    };
    Some(Written {
        bits: if negative {
            magnitude.wrapping_neg()
        } else {
            magnitude
        },
        negative,
    })
}

/// Whether `a` and `b` (numbers' bits) are one number written at two
/// widths: equal, or one is a negative number of 8, 16 or 32 bits and the
/// other its 64 bits (an operand `0FFFFFFFFh` of a 32-bit instruction is
/// the C's `-1`).
///
/// ```
/// use binbun_session::number::same;
///
/// assert!(same(0xffff_ffff, u64::MAX));
/// assert!(same(u64::MAX - 0xf, 0xf0));
/// assert!(!same(0xffff_ffff, 0xffff));
/// assert!(!same(0x10, 0x20));
/// ```
pub fn same(a: u64, b: u64) -> bool {
    // `narrow`, of `bits` bits, sign-extended to 64 is `wide`.
    let widens = |narrow: u64, wide: u64, bits: u32| {
        let shift = 64 - bits;
        narrow >> bits == 0 && ((narrow << shift).cast_signed() >> shift).cast_unsigned() == wide
    };
    a == b
        || [8, 16, 32]
            .into_iter()
            .any(|bits| widens(a, b, bits) || widens(b, a, bits))
}

/// The one number `value` (a number's bits) is at every width: sign
/// extended to 64 bits from the narrowest of 8, 16 or 32 bits that holds
/// it, if its top bit there is set; else `value` itself. Numbers that are
/// [`same`] have one canonical value, and so have `0xff`, `0xffff` and
/// `0xffff_ffff`: the key a number's form is stated by (one form per
/// number on one instruction).
///
/// ```
/// use binbun_session::number::canonical;
///
/// assert_eq!(canonical(0xff), u64::MAX);
/// assert_eq!(canonical(0xffff_ffff), u64::MAX);
/// assert_eq!(canonical(0x80), u64::MAX - 0x7f);
/// assert_eq!(canonical(0x7f), 0x7f);
/// assert_eq!(canonical(0x1ff), 0x1ff);
/// assert_eq!(canonical(0x1_0000_0000), 0x1_0000_0000);
/// ```
pub fn canonical(value: u64) -> u64 {
    for bits in [8, 16, 32] {
        if value >> bits == 0 {
            let shift = 64 - bits;
            return ((value << shift).cast_signed() >> shift).cast_unsigned();
        }
    }
    value
}

/// The bytes of a character constant's text (escapes `\\`, `\'`, `\n`,
/// `\t`, `\r`, `\0`), first byte highest (C's and MASM's multi-character
/// order), as a number; `None` past 8 bytes or with another escape.
fn character(text: &str) -> Option<u64> {
    let mut value: u64 = 0;
    let mut count = 0;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        let byte = match c {
            '\\' => match chars.next()? {
                '\\' => b'\\',
                '\'' => b'\'',
                'n' => b'\n',
                't' => b'\t',
                'r' => b'\r',
                '0' => 0,
                _ => return None,
            },
            c if c.is_ascii() => u8::try_from(c).ok()?,
            _ => return None,
        };
        count += 1;
        if count > 8 {
            return None;
        }
        value = (value << 8) | u64::from(byte);
    }
    (count > 0).then_some(value)
}

impl NumberForm {
    /// `written` in this form, hexadecimal in `radix`; `None` where the
    /// form cannot write it (a character constant of bytes that are not
    /// printable ASCII, or of more than one byte in C), and for an
    /// enumeration's form, which its constants spell ([`by_name`]).
    ///
    /// ```
    /// use binbun_session::NumberForm;
    /// use binbun_session::number::{Radix, parse};
    ///
    /// let n = parse("65").unwrap();
    /// assert_eq!(NumberForm::Hex.spell(n, Radix::Masm).as_deref(), Some("41h"));
    /// assert_eq!(NumberForm::Char.spell(n, Radix::C).as_deref(), Some("'A'"));
    /// ```
    pub fn spell(&self, written: Written, radix: Radix) -> Option<String> {
        let magnitude = if written.negative {
            written.bits.wrapping_neg()
        } else {
            written.bits
        };
        let sign = if written.negative { "-" } else { "" };
        match self {
            Self::Enum(_) => None,
            Self::Decimal => Some(format!("{sign}{magnitude}")),
            Self::Hex => Some(match radix {
                Radix::C => format!("{sign}0x{magnitude:x}"),
                Radix::Masm => {
                    let digits = format!("{magnitude:X}");
                    let zero = if digits.starts_with(|c: char| c.is_ascii_alphabetic()) {
                        "0"
                    } else {
                        ""
                    };
                    format!("{sign}{zero}{digits}h")
                }
            }),
            Self::Char => {
                if written.negative {
                    return None;
                }
                let bytes: Vec<u8> = magnitude
                    .to_be_bytes()
                    .into_iter()
                    .skip_while(|&b| b == 0)
                    .collect();
                let fits = match radix {
                    Radix::C => bytes.len() == 1,
                    Radix::Masm => !bytes.is_empty(),
                };
                if !fits {
                    return None;
                }
                let mut out = String::from("'");
                for byte in bytes {
                    match byte {
                        b'\\' => out.push_str("\\\\"),
                        b'\'' => out.push_str("\\'"),
                        0x20..=0x7e => out.push(char::from(byte)),
                        b'\n' => out.push_str("\\n"),
                        b'\t' => out.push_str("\\t"),
                        b'\r' => out.push_str("\\r"),
                        _ => return None,
                    }
                }
                out.push('\'');
                Some(out)
            }
        }
    }
}

/// `written` by the names of `enumeration`'s constants
/// ([`Enumeration::named`]): the constant equal to it, or the flags it
/// holds, bits no flag names after them in hexadecimal in `radix`
/// (`GENERIC_READ | GENERIC_WRITE | 0x1`); `None` where no constant names
/// it, or it is no value of the enumeration's width.
pub fn by_name(enumeration: &Enumeration, written: Written, radix: Radix) -> Option<String> {
    let width = u32::from(enumeration.width.clamp(1, 64));
    let mask = u64::MAX >> (64 - width);
    let bits = written.bits;
    let sign = bits >> (width - 1) & 1 == 1;
    if bits & !mask != 0 && !(bits | mask == u64::MAX && sign) {
        return None;
    }
    let named = enumeration.named(u128::from(bits & mask))?;
    let mut parts: Vec<String> = named.names.into_iter().map(str::to_owned).collect();
    if named.rest != 0 {
        #[expect(clippy::cast_possible_truncation, reason = "within the width")]
        let rest = Written {
            bits: named.rest as u64,
            negative: false,
        };
        parts.push(NumberForm::Hex.spell(rest, radix)?);
    }
    Some(parts.join(" | "))
}

#[cfg(test)]
mod tests {
    use binbun_ast::types::Enumeration;

    use super::{Radix, Written, by_name, parse};
    use crate::edits::NumberForm;

    #[test]
    fn every_way_of_writing_a_number_reads_back() {
        let n = |bits, negative| Some(Written { bits, negative });
        assert_eq!(parse("88h"), n(0x88, false));
        assert_eq!(parse("0x88"), n(0x88, false));
        assert_eq!(parse("136"), n(136, false));
        assert_eq!(parse("0FFFFFFFFh"), n(0xffff_ffff, false));
        assert_eq!(parse("8uLL"), n(8, false));
        assert_eq!(parse("-1"), n(u64::MAX, true));
        assert_eq!(parse("'\\n'"), n(10, false));
        assert_eq!(parse("'ab'"), n(0x6162, false));
        // Names that look like numbers are not.
        assert_eq!(parse("FFh"), None);
        assert_eq!(parse("ah"), None);
        assert_eq!(parse("''"), None);
        assert_eq!(parse("'abcdefghi'"), None);
    }

    #[test]
    fn forms_round_trip_and_refuse_what_they_cannot_write() {
        for text in ["88h", "-8", "0x7f", "'A'", "'ab'", "0"] {
            let written = parse(text).unwrap();
            for form in [NumberForm::Hex, NumberForm::Decimal, NumberForm::Char] {
                for radix in [Radix::Masm, Radix::C] {
                    if let Some(spelled) = form.spell(written, radix) {
                        assert_eq!(parse(&spelled), Some(written), "{text} as {spelled}");
                    }
                }
            }
        }
        let n = |text| parse(text).unwrap();
        assert_eq!(
            NumberForm::Hex.spell(n("255"), Radix::Masm).as_deref(),
            Some("0FFh")
        );
        assert_eq!(
            NumberForm::Hex.spell(n("-8"), Radix::C).as_deref(),
            Some("-0x8")
        );
        assert_eq!(
            NumberForm::Decimal.spell(n("0FFh"), Radix::Masm).as_deref(),
            Some("255")
        );
        // Two bytes: MASM writes them, C has one-byte constants only.
        assert_eq!(
            NumberForm::Char.spell(n("6162h"), Radix::Masm).as_deref(),
            Some("'ab'")
        );
        assert_eq!(NumberForm::Char.spell(n("6162h"), Radix::C), None);
        assert_eq!(NumberForm::Char.spell(n("7"), Radix::Masm), None);
        assert_eq!(NumberForm::Char.spell(n("-65"), Radix::Masm), None);
        assert_eq!(NumberForm::Char.spell(n("0"), Radix::Masm), None);
    }

    #[test]
    fn an_enumeration_spells_values_of_its_width_by_its_constants() {
        let flags = Enumeration {
            name: Some("ACCESS_MASK".to_owned()),
            width: 32,
            signed: false,
            flags: true,
            macros: false,
            constants: vec![
                ("GENERIC_READ".to_owned(), 0x8000_0000),
                ("GENERIC_WRITE".to_owned(), 0x4000_0000),
            ],
        };
        let n = |text| parse(text).unwrap();
        assert_eq!(
            by_name(&flags, n("0C0000001h"), Radix::Masm).as_deref(),
            Some("GENERIC_READ | GENERIC_WRITE | 1h")
        );
        assert_eq!(
            by_name(&flags, n("0x40000000"), Radix::C).as_deref(),
            Some("GENERIC_WRITE")
        );
        // No flag in it; wider than the enumeration.
        assert_eq!(by_name(&flags, n("0x20000000"), Radix::C), None);
        assert_eq!(by_name(&flags, n("0x140000000"), Radix::C), None);
        let plain = Enumeration {
            name: None,
            width: 32,
            signed: true,
            flags: false,
            macros: false,
            constants: vec![("ERROR".to_owned(), 0xffff_ffff), ("ONE".to_owned(), 1)],
        };
        // The C's `-1` and the listing's `0FFFFFFFFh` alike.
        assert_eq!(by_name(&plain, n("-1"), Radix::C).as_deref(), Some("ERROR"));
        assert_eq!(
            by_name(&plain, n("0FFFFFFFFh"), Radix::Masm).as_deref(),
            Some("ERROR")
        );
        // A plain enumeration names only a value equal to a constant.
        assert_eq!(by_name(&plain, n("3"), Radix::C), None);
        assert_eq!(
            NumberForm::Enum("FILE_TYPE".to_owned()).spell(n("1"), Radix::C),
            None
        );
    }
}
