//! Numbers and columns of the listing.

use crate::listing::Numbers;

/// Where the mnemonic starts in the text area.
pub(crate) const MNEMONIC: usize = 16;
/// Where operands start: the mnemonic padded to 8.
pub(crate) const OPERANDS: usize = 24;
/// Where comments start.
pub(crate) const COMMENTS: usize = 40;
/// The longest operand of a string's data line (every wrapped line of
/// bash's strings is 67 characters, quotes and commas included).
pub(crate) const STRING_WRAP: usize = 67;
/// The longest preview of a string in a comment.
pub(crate) const PREVIEW: usize = 40;

/// `value` in `style`: `88h`, `0A8h` (a leading 0 before a letter),
/// or C's `0x88`; 0 to 9 in decimal either way.
pub(crate) fn number(value: u64, style: Numbers) -> String {
    if value <= 9 {
        return value.to_string();
    }
    match style {
        Numbers::Masm => {
            let digits = format!("{value:X}");
            if digits.starts_with(|c: char| c.is_ascii_alphabetic()) {
                format!("0{digits}h")
            } else {
                format!("{digits}h")
            }
        }
        Numbers::C => format!("{value:#x}"),
    }
}

/// A signed `value` in `style`: `-0A8h`, `-8`.
pub(crate) fn signed(value: i64, style: Numbers) -> String {
    if value < 0 {
        format!("-{}", number(value.unsigned_abs(), style))
    } else {
        number(value.unsigned_abs(), style)
    }
}

/// The C escape-free preview of a string's text, at most `limit`
/// characters, `...` after the quote if cut (a pointee preview).
pub(crate) fn preview(text: &str, limit: usize) -> String {
    let mut out = String::from("\"");
    for (count, c) in text.chars().enumerate() {
        if count == limit {
            out.push_str("\"...");
            return out;
        }
        match c {
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The general-purpose register `name`'s size in bytes.
pub(crate) fn gpr_size(name: &str) -> Option<u32> {
    const B8: [&str; 4] = ["rax", "rbx", "rcx", "rdx"];
    const B4: [&str; 4] = ["eax", "ebx", "ecx", "edx"];
    const B2: [&str; 8] = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
    const B1: [&str; 12] = [
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl",
    ];
    const B8B: [&str; 4] = ["rsi", "rdi", "rbp", "rsp"];
    const B4B: [&str; 4] = ["esi", "edi", "ebp", "esp"];
    if B8.contains(&name) || B8B.contains(&name) {
        return Some(8);
    }
    if B4.contains(&name) || B4B.contains(&name) {
        return Some(4);
    }
    if B2.contains(&name) {
        return Some(2);
    }
    if B1.contains(&name) {
        return Some(1);
    }
    // r8..r31 with their suffixes.
    let rest = name.strip_prefix('r')?;
    let digits = rest.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let number: u32 = digits.parse().ok()?;
    if !(8..=31).contains(&number) {
        return None;
    }
    match rest.get(digits.len()..)? {
        "" => Some(8),
        "d" => Some(4),
        "w" => Some(2),
        "b" => Some(1),
        _ => None,
    }
}

/// The size keyword for an access of `bytes`.
pub(crate) fn size_word(bytes: u32) -> &'static str {
    match bytes {
        2 => "word",
        4 => "dword",
        6 => "fword",
        8 => "qword",
        10 => "tbyte",
        16 => "xmmword",
        32 => "ymmword",
        64 => "zmmword",
        _ => "byte",
    }
}

/// The dummy-name prefix of data accessed at `bytes` (`byte_` …
/// `xmmword_`; `unk_` if not known).
pub(crate) fn data_prefix(bytes: u32) -> &'static str {
    match bytes {
        1 => "byte",
        2 => "word",
        4 => "dword",
        8 => "qword",
        10 => "tbyte",
        16 => "xmmword",
        32 => "ymmword",
        _ => "unk",
    }
}

#[cfg(test)]
mod tests {
    use super::{gpr_size, number, signed};
    use crate::listing::Numbers;

    #[test]
    fn numbers_are_written_in_masm_and_c_style() {
        assert_eq!(number(3, Numbers::Masm), "3");
        assert_eq!(number(10, Numbers::Masm), "0Ah");
        assert_eq!(number(0x88, Numbers::Masm), "88h");
        assert_eq!(number(0xA8, Numbers::Masm), "0A8h");
        assert_eq!(number(0xFFFF_FFFF, Numbers::Masm), "0FFFFFFFFh");
        assert_eq!(signed(-0xA8, Numbers::Masm), "-0A8h");
        assert_eq!(signed(-8, Numbers::Masm), "-8");
        assert_eq!(number(0x88, Numbers::C), "0x88");
        assert_eq!(signed(i64::MIN, Numbers::C), "-0x8000000000000000");
    }

    #[test]
    fn register_sizes_cover_the_numbered_registers() {
        assert_eq!(gpr_size("r12"), Some(8));
        assert_eq!(gpr_size("r12d"), Some(4));
        assert_eq!(gpr_size("r8w"), Some(2));
        assert_eq!(gpr_size("r15b"), Some(1));
        assert_eq!(gpr_size("sil"), Some(1));
        assert_eq!(gpr_size("xmm0"), None);
        assert_eq!(gpr_size("rip"), None);
    }
}
