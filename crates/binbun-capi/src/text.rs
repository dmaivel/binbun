//! Text into the caller's buffers: plain text, and text as tokens.

use std::fmt;
use std::mem::MaybeUninit;

/// What a piece of an instruction's text is (`binbun_token_kind`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// The mnemonic (`add`, `b.eq`, `call far`).
    Mnemonic = 0,
    /// A prefix written as a word before the mnemonic (`lock`, `rep`).
    Prefix = 1,
    /// A register, with what is written on it (`v0.16b`, `p0/z`); `value`
    /// is the x86 register (`binbun_x86_register`), 0 on AArch64.
    Register = 2,
    /// An immediate (`0x10`, `#-0x8`), whose value is `value`.
    Immediate = 3,
    /// A number written bare: a scale, a lane index, a register count.
    Integer = 4,
    /// A floating-point immediate (`#1.00000000`); `value` holds the bits
    /// of the `double`.
    Float = 5,
    /// A branch target or another PC-relative address, which `value`
    /// holds (an offset with `BINBUN_TEXT_RELATIVE_LABELS`).
    Address = 6,
    /// The displacement of an x86 memory operand, which `value` holds
    /// signed (`-0x10` is −16).
    Displacement = 7,
    /// A word from a fixed set: a size (`dword`, `ptr`), a decoration
    /// (`{z}`, `{1to16}`), a shift or extend, a condition, a named operand.
    Symbol = 8,
    /// Brackets, braces and other punctuation within an operand, including
    /// a `, ` that does not separate operands.
    Punctuation = 9,
    /// The `, ` between two operands, and only there.
    Separator = 10,
    /// Spaces and tabs.
    Whitespace = 11,
}

/// What [`Token::operand`] holds for a token that is part of no operand.
pub const NO_OPERAND: u8 = 0xff;

/// One token of an instruction's text, a span of the text buffer
/// (`binbun_token`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Token {
    /// A [`TokenKind`].
    pub kind: u8,
    /// Which operand (of the architecture's operand list) the token is part
    /// of, or [`NO_OPERAND`].
    pub operand: u8,
    /// Zero.
    pub reserved0: u16,
    /// Where the token starts in the text.
    pub offset: u32,
    /// Its length in bytes.
    pub length: u32,
    /// Zero.
    pub reserved1: u32,
    /// The number an immediate, integer, float, address, displacement or
    /// x86 register token stands for; 0 for the others.
    pub value: u64,
}

// The layout the header describes, on 64-bit targets.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Token>() == 24 && align_of::<Token>() == 8);

/// How much text and how many tokens an instruction has
/// (`binbun_text_size`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TextSize {
    /// The number of tokens.
    pub tokens: usize,
    /// The length of the text without its NUL.
    pub length: usize,
}

/// Text written into the caller's buffer as far as it goes, leaving room
/// for the NUL, while counting the whole length.
#[derive(Debug)]
pub struct TextOut<'a> {
    buffer: &'a mut [MaybeUninit<u8>],
    len: usize,
}

impl<'a> TextOut<'a> {
    pub const fn new(buffer: &'a mut [MaybeUninit<u8>]) -> Self {
        Self { buffer, len: 0 }
    }

    /// The length written so far, counting what did not fit.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Appends `bytes`, or as much as fits.
    pub fn push(&mut self, bytes: &[u8]) {
        let room = self.buffer.len().saturating_sub(1);
        if let Some(free) = self.buffer.get_mut(self.len..room) {
            let n = free.len().min(bytes.len());
            if let (Some(target), Some(source)) = (free.get_mut(..n), bytes.get(..n)) {
                target.write_copy_of_slice(source);
            }
        }
        self.len = self.len.saturating_add(bytes.len());
    }

    /// Ends the text with a NUL if the buffer has room for one, and returns
    /// its whole length.
    pub fn finish(self) -> usize {
        let end = self.len.min(self.buffer.len().saturating_sub(1));
        if let Some(nul) = self.buffer.get_mut(end) {
            nul.write(0);
        }
        self.len
    }
}

impl fmt::Write for TextOut<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push(text.as_bytes());
        Ok(())
    }
}

/// Tokens written into the caller's buffers, with their text, as far as
/// they go, counting them all.
#[derive(Debug)]
pub struct TokenOut<'a> {
    text: TextOut<'a>,
    tokens: &'a mut [MaybeUninit<Token>],
    count: usize,
}

impl<'a> TokenOut<'a> {
    pub const fn new(text: TextOut<'a>, tokens: &'a mut [MaybeUninit<Token>]) -> Self {
        Self {
            text,
            tokens,
            count: 0,
        }
    }

    /// Ends the text and returns the sizes.
    pub fn finish(self) -> TextSize {
        TextSize {
            tokens: self.count,
            length: self.text.finish(),
        }
    }
}

/// Where tokens go.
pub trait TokenSink {
    /// Appends a token of `text`, part of operand `operand` (or
    /// [`NO_OPERAND`]), standing for `value`.
    fn push(&mut self, kind: TokenKind, operand: u8, text: &str, value: u64);
}

impl TokenSink for TokenOut<'_> {
    fn push(&mut self, kind: TokenKind, operand: u8, text: &str, value: u64) {
        let offset = u32::try_from(self.text.len()).unwrap_or(u32::MAX);
        self.text.push(text.as_bytes());
        if let Some(slot) = self.tokens.get_mut(self.count) {
            slot.write(Token {
                kind: kind as u8,
                operand,
                reserved0: 0,
                offset,
                length: u32::try_from(text.len()).unwrap_or(u32::MAX),
                reserved1: 0,
                value,
            });
        }
        self.count += 1;
    }
}

/// Tokens as (kind, operand, text, value), for tests.
#[cfg(test)]
pub type Collected = Vec<(TokenKind, u8, String, u64)>;

#[cfg(test)]
impl TokenSink for Collected {
    fn push(&mut self, kind: TokenKind, operand: u8, text: &str, value: u64) {
        self.push((kind, operand, text.to_owned(), value));
    }
}

/// The number a token writes: an optional `#`, an optional `-`, then `0x`
/// and hex digits or decimal digits, up to the first other character; a
/// negative number as its two's complement.
pub fn number(text: &str) -> u64 {
    let text = text.strip_prefix('#').unwrap_or(text);
    let (negative, text) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (radix, digits) = match text.strip_prefix("0x") {
        Some(rest) => (16, rest),
        None => (10, text),
    };
    let mut value = 0u64;
    for digit in digits.chars().map_while(|c| c.to_digit(radix)) {
        value = value
            .wrapping_mul(u64::from(radix))
            .wrapping_add(u64::from(digit));
    }
    if negative {
        value.wrapping_neg()
    } else {
        value
    }
}

/// The bits of the `double` a floating-point token (`#1.5`) writes; 0 if
/// it writes none.
pub fn float_bits(text: &str) -> u64 {
    text.strip_prefix('#')
        .unwrap_or(text)
        .parse::<f64>()
        .map_or(0, f64::to_bits)
}

#[cfg(test)]
mod tests {
    use super::number;

    #[test]
    fn numbers_are_read_as_written() {
        assert_eq!(number("#0x10"), 16);
        assert_eq!(number("#-0x10"), 16u64.wrapping_neg());
        assert_eq!(number("12"), 12);
        assert_eq!(number("0x4:0x7"), 4);
        assert_eq!(number("#0000000000000000"), 0);
        assert_eq!(number("0xffffffffffffffff"), u64::MAX);
    }
}
