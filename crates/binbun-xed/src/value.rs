//! Numbers as XED writes them (`genutil.make_numeric`): `0x…` hex, `0b…`
//! binary with optional `_` separators, or decimal.

/// Parses a XED number, or `None` if `text` is not one.
pub fn number(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16)
            .ok()
            .filter(|_| !hex.starts_with('+'));
    }
    if let Some(binary) = text.strip_prefix("0b") {
        if binary.is_empty() || !binary.bytes().all(|b| matches!(b, b'0' | b'1' | b'_')) {
            return None;
        }
        return binary
            .bytes()
            .filter(|&b| b != b'_')
            .try_fold(0u64, |acc, b| {
                acc.checked_mul(2)?.checked_add(u64::from(b - b'0'))
            });
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        return text.parse().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::number;

    #[test]
    fn parses_hex_binary_and_decimal() {
        assert_eq!(number("0x1F"), Some(31));
        assert_eq!(number("0b0100_1"), Some(9));
        assert_eq!(number("42"), Some(42));
    }

    #[test]
    fn rejects_malformed_numbers() {
        for text in ["", "0x", "0x+1", "0b", "0b012", "-1", "4a", "XED_REG_AX"] {
            assert_eq!(number(text), None, "{text}");
        }
    }

    #[test]
    fn rejects_overflow() {
        assert_eq!(number("0x10000000000000000"), None);
        assert_eq!(number(&format!("0b1{}", "0".repeat(64))), None);
    }
}
