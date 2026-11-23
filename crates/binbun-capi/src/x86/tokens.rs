//! x86 text as tokens.
//!
//! The Intel printer writes plain text; its grammar is small and fixed
//! (prefix words, the mnemonic, an optional `{dfv=…}`, then the operands
//! the text shows, separated by `, `), so the text is read back into tokens
//! here, and each operand's tokens are matched with the operand they show.

use std::fmt::{self, Write as _};

use binbun_x86::{
    Category, Encoding, Instruction, OperandName, Register, RegisterClass, Value, Visibility,
};

use super::{MAX_OPERANDS, MAX_TEXT, register_named};
use crate::text::{NO_OPERAND, TokenKind, TokenSink, number};

/// Room for any instruction's text.
const LINE: usize = 256;

const _: () = assert!(MAX_TEXT < LINE);

/// Words the printer writes before the mnemonic.
const PREFIXES: [&str; 14] = [
    "bnd",
    "xacquire",
    "xrelease",
    "lock",
    "rep",
    "repne",
    "hint-not-taken",
    "hint-taken",
    "notrack",
    "addr32",
    "addr16",
    "data16",
    "data32",
    "{nf}",
];

/// Words of a memory operand's size.
const SIZES: [&str; 8] = [
    "byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword", "ptr",
];

/// The segment registers, which the printer may show as an operand of their
/// own.
const SEGMENTS: [&str; 6] = ["es", "cs", "ss", "ds", "fs", "gs"];

/// The text of one instruction, on the stack.
struct Line {
    bytes: [u8; LINE],
    len: usize,
}

impl fmt::Write for Line {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len + text.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Writes the tokens of `instruction` at `address` to `out`.
///
/// # Errors
///
/// If the text is longer than any instruction's.
pub fn write(instruction: &Instruction, address: u64, out: &mut impl TokenSink) -> fmt::Result {
    let mut line = Line {
        bytes: [0; LINE],
        len: 0,
    };
    write!(line, "{}", instruction.intel(address))?;
    let text = line
        .bytes
        .get(..line.len)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or(fmt::Error)?;
    let operands = head(text, out);
    if operands.is_empty() {
        return Ok(());
    }
    let mut groups = [""; MAX_OPERANDS + 2];
    let count = split(operands, &mut groups).ok_or(fmt::Error)?;
    let groups = groups.get(..count).unwrap_or_default();
    let (map, mask) = assign(instruction, groups, true)
        .map(|map| (map, mask(instruction)))
        .or_else(|| assign(instruction, groups, false).map(|map| (map, None)))
        .unwrap_or(([NO_OPERAND; MAX_OPERANDS + 2], None));
    for (i, (group, &operand)) in groups.iter().zip(&map).enumerate() {
        if i > 0 {
            out.push(TokenKind::Separator, NO_OPERAND, ", ", 0);
        }
        let numbers = match instruction.operands().nth(usize::from(operand)) {
            Some(shown) if matches!(shown.value, Value::Relative(_) | Value::Field(_)) => {
                TokenKind::Address
            }
            Some(_) | None => TokenKind::Immediate,
        };
        let mask = if i == 0 { mask } else { None };
        lex(group, operand, numbers, mask, out);
    }
    Ok(())
}

/// Writes the tokens before the operands (prefixes, mnemonic, `{dfv=…}`
/// and the space after them) and returns the operands' text.
fn head<'t>(text: &'t str, out: &mut impl TokenSink) -> &'t str {
    let mut rest = text;
    while let Some((word, after)) = rest.split_once(' ') {
        if after.is_empty() || !PREFIXES.contains(&word) {
            break;
        }
        out.push(TokenKind::Prefix, NO_OPERAND, word, 0);
        out.push(TokenKind::Whitespace, NO_OPERAND, " ", 0);
        rest = after;
    }
    let mut end = rest.find(' ').unwrap_or(rest.len());
    let word = rest.get(..end).unwrap_or_default();
    let after = rest.get(end..).unwrap_or_default();
    if matches!(word, "call" | "jmp" | "ret")
        && after
            .strip_prefix(" far")
            .is_some_and(|tail| tail.is_empty() || tail.starts_with(' '))
    {
        end += " far".len();
    }
    let (mnemonic, mut rest) = rest.split_at_checked(end).unwrap_or((rest, ""));
    out.push(TokenKind::Mnemonic, NO_OPERAND, mnemonic, 0);
    if rest.starts_with(" {dfv=")
        && let Some(close) = rest.find('}')
    {
        out.push(TokenKind::Whitespace, NO_OPERAND, " ", 0);
        out.push(
            TokenKind::Symbol,
            NO_OPERAND,
            rest.get(1..=close).unwrap_or_default(),
            0,
        );
        rest = rest.get(close + 1..).unwrap_or_default();
    }
    match rest.strip_prefix(' ') {
        Some(operands) => {
            out.push(TokenKind::Whitespace, NO_OPERAND, " ", 0);
            operands
        }
        None => "",
    }
}

/// Splits the operands' text at the `, ` outside brackets and braces into
/// `groups`; returns how many there are, `None` if more than fit.
fn split<'t>(text: &'t str, groups: &mut [&'t str]) -> Option<usize> {
    let bytes = text.as_bytes();
    let (mut depth, mut start, mut count) = (0i32, 0, 0);
    for (i, &byte) in bytes.iter().enumerate() {
        match byte {
            b'[' | b'{' => depth += 1,
            b']' | b'}' => depth -= 1,
            b',' if depth == 0 && bytes.get(i + 1) == Some(&b' ') => {
                *groups.get_mut(count)? = text.get(start..i)?;
                count += 1;
                start = i + 2;
            }
            _ => {}
        }
    }
    *groups.get_mut(count)? = text.get(start..)?;
    Some(count + 1)
}

/// The position of an AVX-512 write mask, which the printer writes inside
/// the first operand (`zmm0{k1}`), or nothing for `k0`: the second operand
/// of an EVEX instruction, when it is a mask register.
fn mask(instruction: &Instruction) -> Option<u8> {
    let mut operands = instruction.operands();
    let first = operands.next()?;
    let second = operands.next()?;
    let is_mask =
        matches!(second.value, Value::Register(Some(r)) if r.class() == RegisterClass::Mask);
    (instruction.encoding() == Encoding::Evex
        && first.visibility != Visibility::Suppressed
        && is_mask)
        .then_some(1)
}

/// Which operand each group of the text shows, or `None` if the groups do
/// not match the operands; `skip_mask` leaves out the write mask.
///
/// The text shows the operands that are not suppressed (and a string
/// instruction's memory operands), in order; besides, the segment override
/// of a suppressed memory operand, where that operand is, and an MPX
/// instruction's index register, last, which belongs to its memory operand.
fn assign(
    instruction: &Instruction,
    groups: &[&str],
    skip_mask: bool,
) -> Option<[u8; MAX_OPERANDS + 2]> {
    let mask = if skip_mask { mask(instruction) } else { None };
    let string = instruction.category() == Category::Stringop;
    // (shown, a suppressed memory operand) for each operand.
    let mut operands = [(false, false); MAX_OPERANDS];
    let mut memory = None;
    let mut count = 0;
    for (i, operand) in instruction.operands().enumerate() {
        let memory_name = matches!(operand.name, OperandName::Mem0 | OperandName::Mem1);
        if matches!(operand.name, OperandName::Mem0 | OperandName::Agen) {
            memory = Some(i);
        }
        let shown = operand.visibility != Visibility::Suppressed || (string && memory_name);
        let skipped = mask == Some(u8::try_from(i).ok()?);
        *operands.get_mut(i)? = (shown && !skipped, memory_name && !shown);
        count = i + 1;
    }
    let operands = operands.get(..count)?;
    let mut map = [NO_OPERAND; MAX_OPERANDS + 2];
    let mut group = 0;
    for (i, &(shown, suppressed_memory)) in operands.iter().enumerate() {
        let shown_after = operands.iter().skip(i + 1).filter(|o| o.0).count();
        let segment = suppressed_memory
            && groups
                .get(group)
                .is_some_and(|text| SEGMENTS.contains(text))
            && groups.len() - group > shown_after;
        if shown || segment {
            *map.get_mut(group)? = u8::try_from(i).ok()?;
            group += 1;
        }
    }
    if group + 1 == groups.len()
        && let Some(memory) = memory
    {
        *map.get_mut(group)? = u8::try_from(memory).ok()?;
        group += 1;
    }
    (group == groups.len()).then_some(map)
}

/// The register `name` writes: a register's name, or `st` for an implicit
/// `st(0)`.
fn register(name: &str) -> Option<Register> {
    if name == "st" {
        Some(Register::ST0)
    } else {
        register_named(name)
    }
}

/// Writes the tokens of one operand's text, `operand`'s; numbers outside
/// brackets are `numbers`; `mask` is the write mask's position if the text
/// shows it here.
fn lex(text: &str, operand: u8, numbers: TokenKind, mask: Option<u8>, out: &mut impl TokenSink) {
    let bytes = text.as_bytes();
    let mut i = 0;
    let (mut in_memory, mut previous, mut after_mask) = (false, 0u8, false);
    while let (Some(&byte), Some(rest)) = (bytes.get(i), text.get(i..)) {
        let mut owner = operand;
        let (kind, length, value) = match byte {
            b'{' => {
                let length = rest.find('}').map_or(rest.len(), |close| close + 1);
                let inner = rest.get(1..length - 1).unwrap_or_default();
                if let (Some(register), Some(mask)) = (register(inner), mask) {
                    out.push(TokenKind::Punctuation, mask, "{", 0);
                    out.push(TokenKind::Register, mask, inner, u64::from(register as u16));
                    out.push(TokenKind::Punctuation, mask, "}", 0);
                    (i, previous, after_mask) = (i + length, b'}', true);
                    continue;
                }
                if after_mask && let Some(mask) = mask {
                    owner = mask;
                }
                (TokenKind::Symbol, length, 0)
            }
            b' ' => {
                let length = rest.bytes().take_while(|&b| b == b' ').count();
                (TokenKind::Whitespace, length, 0)
            }
            b'0'..=b'9' => {
                let length = if rest.starts_with("0x") {
                    2 + rest
                        .bytes()
                        .skip(2)
                        .take_while(u8::is_ascii_hexdigit)
                        .count()
                } else {
                    rest.bytes().take_while(u8::is_ascii_digit).count()
                };
                let value = number(rest.get(..length).unwrap_or_default());
                match (previous, in_memory) {
                    (b'*' | b'+', false) | (b'*', true) => (TokenKind::Integer, length, value),
                    (b'-', true) => (TokenKind::Displacement, length, value.wrapping_neg()),
                    (_, true) => (TokenKind::Displacement, length, value),
                    (_, false) => (numbers, length, value),
                }
            }
            b'a'..=b'z' => {
                let mut length = rest
                    .bytes()
                    .take_while(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    .count();
                let word = rest.get(..length).unwrap_or_default();
                if word == "st" && rest.get(2..3) == Some("(") {
                    length = rest.find(')').map_or(length, |close| close + 1);
                }
                let word = rest.get(..length).unwrap_or_default();
                match register(word) {
                    Some(register) if !SIZES.contains(&word) => {
                        (TokenKind::Register, length, u64::from(register as u16))
                    }
                    Some(_) | None => (TokenKind::Symbol, length, 0),
                }
            }
            b'[' => {
                in_memory = true;
                (TokenKind::Punctuation, 1, 0)
            }
            b']' => {
                in_memory = false;
                (TokenKind::Punctuation, 1, 0)
            }
            _ => (TokenKind::Punctuation, 1, 0),
        };
        let length = length.max(1);
        let piece = rest.get(..length).unwrap_or(rest);
        out.push(kind, owner, piece, value);
        if kind != TokenKind::Whitespace {
            previous = piece.bytes().last().unwrap_or(0);
            after_mask = after_mask && kind == TokenKind::Symbol;
        }
        i += length;
    }
}

#[cfg(test)]
mod tests {
    use binbun_x86::{Mode, OperandName, Register, decode};

    use crate::text::Collected;
    use crate::text::NO_OPERAND as NO;
    use crate::text::TokenKind::{
        self, Address, Displacement, Immediate, Integer, Mnemonic, Prefix, Punctuation,
        Register as Reg, Separator, Symbol, Whitespace,
    };

    /// The tokens of `bytes` in 64-bit mode at 0x1000 but whitespace, after
    /// checking that all of them together are the text.
    fn tokens(bytes: &[u8]) -> Vec<(TokenKind, u8, String, u64)> {
        let instruction = decode(bytes, Mode::Bits64).unwrap();
        let mut tokens = Collected::new();
        super::write(&instruction, 0x1000, &mut tokens).unwrap();
        let text: String = tokens.iter().map(|token| token.2.as_str()).collect();
        assert_eq!(text, instruction.intel(0x1000).to_string());
        tokens.retain(|token| token.0 != Whitespace);
        tokens
    }

    fn token(kind: TokenKind, operand: u8, text: &str, value: u64) -> (TokenKind, u8, String, u64) {
        (kind, operand, text.to_owned(), value)
    }

    #[test]
    fn memory_operand_parts_and_prefix() {
        // lock add dword ptr [rax+rbx*4-0x10], 0x5
        assert_eq!(
            tokens(&[0xf0, 0x83, 0x44, 0x98, 0xf0, 0x05]),
            [
                token(Prefix, NO, "lock", 0),
                token(Mnemonic, NO, "add", 0),
                token(Symbol, 0, "dword", 0),
                token(Symbol, 0, "ptr", 0),
                token(Punctuation, 0, "[", 0),
                token(Reg, 0, "rax", Register::RAX as u64),
                token(Punctuation, 0, "+", 0),
                token(Reg, 0, "rbx", Register::RBX as u64),
                token(Punctuation, 0, "*", 0),
                token(Integer, 0, "4", 4),
                token(Punctuation, 0, "-", 0),
                token(Displacement, 0, "0x10", 16u64.wrapping_neg()),
                token(Punctuation, 0, "]", 0),
                token(Separator, NO, ", ", 0),
                token(Immediate, 1, "0x5", 5),
            ]
        );
    }

    #[test]
    fn write_mask_belongs_to_the_mask_operand() {
        // vaddps zmm0{k1}{z}, zmm1, zmm2: the mask is operand 1.
        assert_eq!(
            tokens(&[0x62, 0xf1, 0x74, 0xc9, 0x58, 0xc2]),
            [
                token(Mnemonic, NO, "vaddps", 0),
                token(Reg, 0, "zmm0", Register::ZMM0 as u64),
                token(Punctuation, 1, "{", 0),
                token(Reg, 1, "k1", Register::K1 as u64),
                token(Punctuation, 1, "}", 0),
                token(Symbol, 1, "{z}", 0),
                token(Separator, NO, ", ", 0),
                token(Reg, 2, "zmm1", Register::ZMM1 as u64),
                token(Separator, NO, ", ", 0),
                token(Reg, 3, "zmm2", Register::ZMM2 as u64),
            ]
        );
    }

    #[test]
    fn mask_register_operand_is_not_a_write_mask() {
        // vpmovm2d zmm0, k1: an EVEX instruction whose second operand is a
        // mask register it reads, written as an operand of its own.
        let tokens = tokens(&[0x62, 0xf2, 0x7e, 0x48, 0x38, 0xc1]);
        assert_eq!(
            tokens.last(),
            Some(&token(Reg, 1, "k1", Register::K1 as u64))
        );
    }

    #[test]
    fn branch_target_is_an_address() {
        // call 0x1005
        assert_eq!(
            tokens(&[0xe8, 0, 0, 0, 0]),
            [
                token(Mnemonic, NO, "call", 0),
                token(Address, 0, "0x1005", 0x1005)
            ]
        );
    }

    #[test]
    fn string_instruction_shows_its_suppressed_memory_operands() {
        // rep movsb byte ptr [rdi], byte ptr [rsi]: the text shows both
        // memory operands, which XED suppresses.
        let bytes = [0xf3, 0xa4];
        let movsb = decode(&bytes, Mode::Bits64).unwrap();
        let tokens = tokens(&bytes);
        let registers: Vec<_> = tokens
            .iter()
            .filter(|token| token.0 == Reg)
            .map(|token| {
                let operand = movsb.operands().nth(usize::from(token.1)).unwrap();
                (operand.name, token.2.as_str())
            })
            .collect();
        assert_eq!(tokens.first(), Some(&token(Prefix, NO, "rep", 0)));
        assert_eq!(
            registers,
            [(OperandName::Mem0, "rdi"), (OperandName::Mem1, "rsi")]
        );
    }
}
