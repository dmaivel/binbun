//! Decoding a buffer of code instruction by instruction.

use core::iter::FusedIterator;

use crate::{DecodeError, Instruction, MAX_LENGTH, Mode, decode};

/// Decodes the instructions of a buffer one after another (a linear sweep).
///
/// Each item is the instruction's address and the decode result. After an
/// instruction the decoder moves past it; after an error, by one byte, so
/// that a sweep over data or misaligned code resynchronises.
///
/// ```
/// use binbun_x86::{Decoder, Mode};
///
/// let code = [0x48, 0x89, 0xc7, 0xc3]; // mov rdi, rax; ret
/// let mut decoder = Decoder::new(&code, Mode::Bits64, 0x1000);
/// let (address, mov) = decoder.next().unwrap();
/// assert_eq!((address, mov.unwrap().intel(address).to_string()), (0x1000, "mov rdi, rax".into()));
/// let (address, ret) = decoder.next().unwrap();
/// assert_eq!((address, ret.unwrap().len()), (0x1003, 1));
/// assert!(decoder.next().is_none());
/// ```
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    mode: Mode,
    /// Address of `bytes[0]`.
    base: u64,
    /// Offset of the next instruction in `bytes`.
    offset: usize,
}

impl<'a> Decoder<'a> {
    /// A decoder of `bytes`, which are at `address`, in `mode`.
    pub const fn new(bytes: &'a [u8], mode: Mode, address: u64) -> Self {
        Self {
            bytes,
            mode,
            base: address,
            offset: 0,
        }
    }

    /// Offset in the buffer of the next instruction.
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Address of the next instruction.
    pub const fn address(&self) -> u64 {
        self.base.wrapping_add(self.offset as u64)
    }

    /// Continues at `offset` in the buffer (past the end: nothing more).
    pub const fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    /// The bytes not decoded yet.
    pub fn remaining(&self) -> &'a [u8] {
        self.bytes.get(self.offset..).unwrap_or_default()
    }
}

impl Iterator for Decoder<'_> {
    type Item = (u64, Result<Instruction, DecodeError>);

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.remaining();
        if rest.is_empty() {
            return None;
        }
        let address = self.address();
        let result = decode(rest, self.mode);
        self.offset += result.as_ref().map_or(1, Instruction::len);
        Some((address, result))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rest = self.remaining().len();
        (rest.div_ceil(MAX_LENGTH), Some(rest))
    }
}

impl FusedIterator for Decoder<'_> {}
