//! The data inspector: the bytes at the
//! hex view's selection read as every type at once: integers of each
//! width and signedness in both byte orders, `float` and `double`, a
//! pointer with the name it points to, a C string, a UTF-16 string,
//! LEB128 and ULEB128, and Unix times.
//!
//! ```
//! use binbun_gui_view::inspect::{Values, inspect};
//!
//! let rows = inspect(&[0xff, 0x01, 0, 0, 0, 0, 0, 0], true, 8, &|_| None);
//! let row = |label: &str| rows.iter().find(|r| r.label == label).unwrap();
//! assert_eq!(
//!     row("int16").values,
//!     Values::Two { little: "511".to_owned(), big: "-255".to_owned() }
//! );
//! assert_eq!(row("ULEB128").values, Values::One("255 (2 bytes)".to_owned()));
//! ```

use std::fmt::Write as _;

/// How many bytes a string is read to at most.
pub const STRING_LIMIT: usize = 64;

/// A row's value or values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Values {
    /// One reading (no byte order, or the image's).
    One(String),
    /// Little- and big-endian readings.
    Two {
        /// Little-endian.
        little: String,
        /// Big-endian.
        big: String,
    },
}

/// One reading of the selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The type (`uint32`, `float`, `C string`).
    pub label: &'static str,
    /// What the bytes read as.
    pub values: Values,
    /// The address a pointer holds, to follow.
    pub target: Option<u64>,
}

/// `bytes` (from the selection's first byte on) read as every type; the
/// pointer and times in the image's byte order (`little`), the pointer
/// `pointer` bytes wide and named by `name`. A type needing more bytes
/// than there are is left out.
#[expect(clippy::too_many_lines, reason = "one reading after another")]
pub fn inspect(
    bytes: &[u8],
    little: bool,
    pointer: u8,
    name: &dyn Fn(u64) -> Option<String>,
) -> Vec<Row> {
    let mut rows = Vec::new();
    let two = |little: String, big: String| Values::Two { little, big };
    let read = |n: usize, little: bool| -> Option<u64> {
        let b = bytes.get(..n)?;
        let fold = |v: u64, &x: &u8| (v << 8) | u64::from(x);
        Some(if little {
            b.iter().rev().fold(0, fold)
        } else {
            b.iter().fold(0, fold)
        })
    };
    if let Some(&b) = bytes.first() {
        rows.push(Row {
            label: "binary",
            values: Values::One(format!("{b:08b}")),
            target: None,
        });
        rows.push(Row {
            label: "char",
            values: Values::One(char_literal(b)),
            target: None,
        });
    }
    for (n, signed, unsigned) in [
        (1, "int8", "uint8"),
        (2, "int16", "uint16"),
        (4, "int32", "uint32"),
        (8, "int64", "uint64"),
    ] {
        let (Some(le), Some(be)) = (read(n, true), read(n, false)) else {
            continue;
        };
        let as_signed = |v: u64| sign_extend(v, n);
        if n == 1 {
            rows.push(Row {
                label: unsigned,
                values: Values::One(le.to_string()),
                target: None,
            });
            rows.push(Row {
                label: signed,
                values: Values::One(as_signed(le).to_string()),
                target: None,
            });
        } else {
            rows.push(Row {
                label: unsigned,
                values: two(le.to_string(), be.to_string()),
                target: None,
            });
            rows.push(Row {
                label: signed,
                values: two(as_signed(le).to_string(), as_signed(be).to_string()),
                target: None,
            });
        }
    }
    if let (Some(le), Some(be)) = (read(4, true), read(4, false)) {
        let f = |v: u64| float(f64::from(f32::from_bits(u32::try_from(v).unwrap_or(0))));
        rows.push(Row {
            label: "float",
            values: two(f(le), f(be)),
            target: None,
        });
    }
    if let (Some(le), Some(be)) = (read(8, true), read(8, false)) {
        let f = |v: u64| float(f64::from_bits(v));
        rows.push(Row {
            label: "double",
            values: two(f(le), f(be)),
            target: None,
        });
    }
    if let Some(p) = read(usize::from(pointer), little) {
        let width = usize::from(pointer) * 2;
        let text = match name(p) {
            Some(name) => format!("{p:0width$X} {name}"),
            None => format!("{p:0width$X}"),
        };
        rows.push(Row {
            label: "pointer",
            values: Values::One(text),
            target: Some(p),
        });
    }
    if let Some(text) = c_string(bytes) {
        rows.push(Row {
            label: "C string",
            values: Values::One(text),
            target: None,
        });
    }
    if let Some(text) = utf16_string(bytes, little) {
        rows.push(Row {
            label: "UTF-16",
            values: Values::One(text),
            target: None,
        });
    }
    if let Some((value, len)) = uleb128(bytes) {
        rows.push(Row {
            label: "ULEB128",
            values: Values::One(format!("{value} ({len} {})", plural(len))),
            target: None,
        });
    }
    if let Some((value, len)) = sleb128(bytes) {
        rows.push(Row {
            label: "LEB128",
            values: Values::One(format!("{value} ({len} {})", plural(len))),
            target: None,
        });
    }
    for (n, label) in [(4, "time32"), (8, "time64")] {
        if let Some(v) = read(n, little)
            && let Some(time) = unix_time(sign_extend(v, n))
        {
            rows.push(Row {
                label,
                values: Values::One(time),
                target: None,
            });
        }
    }
    rows
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "byte" } else { "bytes" }
}

/// `v`, `n` bytes wide, as a signed number.
fn sign_extend(v: u64, n: usize) -> i64 {
    let shift = 64 - 8 * u32::try_from(n.clamp(1, 8)).unwrap_or(8);
    i64::from_ne_bytes((v << shift).to_ne_bytes()) >> shift
}

/// A float as a C literal would write it: plain where short, else with an
/// exponent.
fn float(v: f64) -> String {
    let magnitude = v.abs();
    if v.is_nan() || v.is_infinite() || magnitude == 0.0 || (1e-4..1e15).contains(&magnitude) {
        format!("{v}")
    } else {
        format!("{v:e}")
    }
}

/// `b` as a C character literal.
fn char_literal(b: u8) -> String {
    match b {
        b'\'' => "'\\''".to_owned(),
        b'\\' => "'\\\\'".to_owned(),
        0x20..=0x7e => format!("'{}'", char::from(b)),
        _ => {
            let mut s = String::from("'");
            escape(&mut s, b);
            s.push('\'');
            s
        }
    }
}

/// Appends byte `b` of a C string, escaped where it is not printable.
fn escape(out: &mut String, b: u8) {
    match b {
        b'\n' => out.push_str("\\n"),
        b'\t' => out.push_str("\\t"),
        b'\r' => out.push_str("\\r"),
        0 => out.push_str("\\0"),
        b'"' => out.push_str("\\\""),
        b'\\' => out.push_str("\\\\"),
        0x20..=0x7e => out.push(char::from(b)),
        _ => {
            let _ = write!(out, "\\x{b:02X}");
        }
    }
}

/// The C string from the first byte: up to its NUL (or
/// [`STRING_LIMIT`] bytes, then `…`), quoted and escaped; `None` if the
/// first byte is the NUL.
fn c_string(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    let shown = end.min(STRING_LIMIT);
    let mut out = String::from("\"");
    for &b in bytes.get(..shown)? {
        escape(&mut out, b);
    }
    out.push('"');
    if end > shown || end == bytes.len() {
        out.push('…');
    }
    Some(out)
}

/// The UTF-16 string from the first byte, in the image's byte order:
/// up to its NUL; `None` if empty, not UTF-16, or 8-bit text (its first
/// two bytes printable ASCII: read as UTF-16 it would be noise).
fn utf16_string(bytes: &[u8], little: bool) -> Option<String> {
    if let [a, b, ..] = bytes
        && (0x20..0x7f).contains(a)
        && (0x20..0x7f).contains(b)
    {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| {
            if little {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            }
        })
        .take_while(|&u| u != 0)
        .take(STRING_LIMIT)
        .collect();
    if units.is_empty() {
        return None;
    }
    let text = String::from_utf16(&units).ok()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    Some(format!("L\"{text}\""))
}

/// ULEB128 from the first byte: its value and length (`None` past 10
/// bytes or the bytes' end).
fn uleb128(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &b) in bytes.iter().take(10).enumerate() {
        let shift = 7 * u32::try_from(i).ok()?;
        value |= u64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Signed LEB128 from the first byte: its value and length.
fn sleb128(bytes: &[u8]) -> Option<(i64, usize)> {
    let (value, len) = uleb128(bytes)?;
    let bits = 7 * u32::try_from(len).ok()?;
    if bits >= 64 {
        return Some((i64::from_ne_bytes(value.to_ne_bytes()), len));
    }
    let shift = 64 - bits;
    Some((
        i64::from_ne_bytes((value << shift).to_ne_bytes()) >> shift,
        len,
    ))
}

/// Seconds since 1970 as a UTC date and time, for years 1970–2200.
pub fn unix_time(seconds: i64) -> Option<String> {
    // 2200-01-01.
    if !(0..7_258_118_400).contains(&seconds) {
        return None;
    }
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    let (year, month, day) = civil(days);
    Some(format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    ))
}

/// The date `days` after 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail loudly")]

    use super::*;

    fn value<'r>(rows: &'r [Row], label: &str) -> &'r Values {
        &rows.iter().find(|r| r.label == label).unwrap().values
    }

    fn one(text: &str) -> Values {
        Values::One(text.to_owned())
    }

    #[test]
    fn integers_read_in_each_width_signedness_and_byte_order() {
        let bytes = [0xfe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x80];
        let rows = inspect(&bytes, true, 8, &|_| None);
        assert_eq!(value(&rows, "uint8"), &one("254"));
        assert_eq!(value(&rows, "int8"), &one("-2"));
        assert_eq!(
            value(&rows, "int32"),
            &Values::Two {
                little: "-2".to_owned(),
                big: "-16777217".to_owned()
            }
        );
        assert_eq!(
            value(&rows, "uint64"),
            &Values::Two {
                little: "9223372041149743102".to_owned(),
                big: "18374686475376656512".to_owned()
            }
        );
        // Three bytes: no 32- or 64-bit readings.
        let short = inspect(&bytes[..3], true, 8, &|_| None);
        assert!(
            short
                .iter()
                .all(|r| !matches!(r.label, "int32" | "uint32" | "int64" | "float" | "pointer"))
        );
    }

    #[test]
    fn floats_pointers_and_strings_read_as_c_writes_them() {
        let mut bytes = 1.5f32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0x40, 0, 0, 0]);
        let rows = inspect(&bytes, true, 8, &|p| {
            (p == 0x40_3FC0_0000).then(|| "main".to_owned())
        });
        assert!(matches!(value(&rows, "float"), Values::Two { little, .. } if little == "1.5"));
        let pointer = rows.iter().find(|r| r.label == "pointer").unwrap();
        assert_eq!(pointer.values, one("000000403FC00000 main"));
        assert_eq!(pointer.target, Some(0x40_3FC0_0000));
        let text = inspect(b"hi\n\"x\0rest", true, 8, &|_| None);
        assert_eq!(value(&text, "C string"), &one("\"hi\\n\\\"x\""));
        let wide = inspect(&[b'o', 0, b'k', 0, 0, 0], true, 4, &|_| None);
        assert_eq!(value(&wide, "UTF-16"), &one("L\"ok\""));
        assert!(text.iter().all(|r| r.label != "UTF-16"), "8-bit text");
        assert_eq!(float(1e-300), "1e-300");
    }

    #[test]
    fn leb128_and_times_decode() {
        // DWARF's examples: 624485 and -123456.
        assert_eq!(uleb128(&[0xe5, 0x8e, 0x26]), Some((624_485, 3)));
        assert_eq!(sleb128(&[0xc0, 0xbb, 0x78]), Some((-123_456, 3)));
        assert_eq!(sleb128(&[0x7f]), Some((-1, 1)));
        assert_eq!(uleb128(&[0x80, 0x80]), None);
        assert_eq!(unix_time(0).as_deref(), Some("1970-01-01 00:00:00 UTC"));
        assert_eq!(
            unix_time(1_709_296_496).as_deref(),
            Some("2024-03-01 12:34:56 UTC")
        );
        assert_eq!(unix_time(-1), None);
    }
}
