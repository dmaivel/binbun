//! AArch64 text as tokens, from the printer's own token stream
//! ([`Sink`]): kinds as the printer gives them, and the operand each token
//! is part of from where the `, ` between operands falls.

use std::fmt;

use binbun_aarch64::operand::{Memory, Offset, Operand, Operands, Writeback};
use binbun_aarch64::{Instruction, LabelStyle, Sink, TokenKind as Kind};

use crate::text::{NO_OPERAND, TokenKind, TokenSink, float_bits, number};

/// The printer's tokens, passed on.
struct Tokens<'s, S: TokenSink> {
    out: &'s mut S,
    operands: Operands,
    /// The operand being written, once the tab after the mnemonic is.
    operand: Option<usize>,
    /// Brackets and braces open.
    depth: u32,
    /// Whether a post-indexed memory operand's `, ` (`[x0], #8`) is past.
    post_index: bool,
}

/// Writes the tokens of `instruction` at `address` to `out`.
///
/// # Errors
///
/// Never; the printer's interface can fail.
pub fn write(
    instruction: Instruction,
    address: u64,
    style: LabelStyle,
    out: &mut impl TokenSink,
) -> fmt::Result {
    let mut tokens = Tokens {
        out,
        operands: instruction.operands(),
        operand: None,
        depth: 0,
        post_index: false,
    };
    instruction.format_with(address, style, &mut tokens)
}

impl<S: TokenSink> Tokens<'_, S> {
    /// The operand being written, or [`NO_OPERAND`].
    fn owner(&self) -> u8 {
        self.operand
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or(NO_OPERAND)
    }

    /// Whether a `, ` at the top level is the one inside a post-indexed
    /// memory operand rather than between operands.
    fn inside_post_index(&self) -> bool {
        let current = self.operand.and_then(|i| self.operands.as_slice().get(i));
        !self.post_index
            && matches!(
                current,
                Some(Operand::Memory(Memory {
                    writeback: Writeback::Post,
                    offset: Offset::Immediate(_)
                        | Offset::Register { .. }
                        | Offset::VectorLength(_),
                    ..
                }))
            )
    }

    fn punctuation(&mut self, text: &str) {
        if self.depth == 0 && text == ", " && self.operand.is_some() {
            if self.inside_post_index() {
                self.post_index = true;
            } else {
                self.out.push(TokenKind::Separator, NO_OPERAND, text, 0);
                self.operand = self.operand.map(|i| i + 1);
                self.post_index = false;
                return;
            }
        }
        for byte in text.bytes() {
            match byte {
                b'[' | b'{' => self.depth += 1,
                b']' | b'}' => self.depth = self.depth.saturating_sub(1),
                _ => {}
            }
        }
        let owner = self.owner();
        self.out.push(TokenKind::Punctuation, owner, text, 0);
    }
}

impl<S: TokenSink> Sink for Tokens<'_, S> {
    fn token(&mut self, kind: Kind, text: &str) -> fmt::Result {
        let owner = self.owner();
        match kind {
            Kind::Mnemonic => self.out.push(TokenKind::Mnemonic, NO_OPERAND, text, 0),
            Kind::Whitespace if self.operand.is_none() => {
                self.out.push(TokenKind::Whitespace, NO_OPERAND, text, 0);
                self.operand = Some(0);
            }
            Kind::Whitespace => self.out.push(TokenKind::Whitespace, owner, text, 0),
            Kind::Punctuation => self.punctuation(text),
            Kind::Register => self.out.push(TokenKind::Register, owner, text, 0),
            Kind::Immediate if text.starts_with('#') && text.contains('.') => {
                self.out
                    .push(TokenKind::Float, owner, text, float_bits(text));
            }
            Kind::Immediate if text.starts_with('#') => {
                self.out
                    .push(TokenKind::Immediate, owner, text, number(text));
            }
            Kind::Immediate => self.out.push(TokenKind::Integer, owner, text, number(text)),
            Kind::Address => self.out.push(TokenKind::Address, owner, text, number(text)),
            Kind::Text => self.out.push(TokenKind::Symbol, owner, text, 0),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use binbun_aarch64::{LabelStyle, decode};

    use crate::text::Collected;
    use crate::text::NO_OPERAND as NO;
    use crate::text::TokenKind::{
        self, Address, Immediate, Mnemonic, Punctuation, Register, Separator, Symbol, Whitespace,
    };

    /// The tokens of `word` at 0x1000 but whitespace, after checking that
    /// all of them together are the text.
    fn tokens(word: u32, style: LabelStyle) -> Collected {
        let instruction = decode(word).unwrap();
        let mut tokens = Collected::new();
        super::write(instruction, 0x1000, style, &mut tokens).unwrap();
        let text: String = tokens.iter().map(|token| token.2.as_str()).collect();
        assert_eq!(text, instruction.display_with(0x1000, style).to_string());
        tokens.retain(|token| token.0 != Whitespace);
        tokens
    }

    fn token(kind: TokenKind, operand: u8, text: &str, value: u64) -> (TokenKind, u8, String, u64) {
        (kind, operand, text.to_owned(), value)
    }

    #[test]
    fn post_index_offset_stays_in_its_memory_operand() {
        // ldr x0, [x1], #0x8
        assert_eq!(
            tokens(0xf840_8420, LabelStyle::Absolute),
            [
                token(Mnemonic, NO, "ldr", 0),
                token(Register, 0, "x0", 0),
                token(Separator, NO, ", ", 0),
                token(Punctuation, 1, "[", 0),
                token(Register, 1, "x1", 0),
                token(Punctuation, 1, "]", 0),
                token(Punctuation, 1, ", ", 0),
                token(Immediate, 1, "#0x8", 8),
            ]
        );
    }

    #[test]
    fn shift_is_an_operand_of_its_own_and_list_commas_are_inside() {
        // add x0, x1, x2, lsl #3
        let add = tokens(0x8b02_0c20, LabelStyle::Absolute);
        assert_eq!(add.last(), Some(&token(Immediate, 3, "#3", 3)));
        assert!(add.contains(&token(Symbol, 3, "lsl", 0)));
        // ld1 { v0.16b, v1.16b }, [x0]
        let ld1 = tokens(0x4c40_a000, LabelStyle::Absolute);
        let separators = ld1.iter().filter(|t| t.0 == Separator).count();
        assert_eq!(separators, 1);
        assert_eq!(ld1.last(), Some(&token(Punctuation, 1, "]", 0)));
    }

    #[test]
    fn labels_carry_their_address_or_offset() {
        // b 0x1040
        assert_eq!(
            tokens(0x1400_0010, LabelStyle::Absolute),
            [
                token(Mnemonic, NO, "b", 0),
                token(Address, 0, "0x1040", 0x1040)
            ]
        );
        // b #-0x8
        assert_eq!(
            tokens(0x17ff_fffe, LabelStyle::Relative).last(),
            Some(&token(Address, 0, "#-0x8", 8u64.wrapping_neg()))
        );
    }
}
