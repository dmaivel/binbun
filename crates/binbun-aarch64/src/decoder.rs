//! Decoding a buffer of code instruction by instruction.

use core::iter::FusedIterator;

use crate::{Error, Instruction, decode_bytes};

/// Decodes the instructions of a buffer one after another (a linear sweep).
///
/// Each item is the instruction's address and the decode result. Every A64
/// instruction is 4 bytes, so the decoder moves 4 bytes on, after an error
/// too; a last piece shorter than 4 bytes gives [`Error::TooShort`] and
/// ends the sweep.
///
/// ```
/// use binbun_aarch64::Decoder;
///
/// let code = [0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]; // mov x0, x1; ret
/// let mut decoder = Decoder::new(&code, 0x1000);
/// let (address, mov) = decoder.next().unwrap();
/// assert_eq!((address, mov.unwrap().display(address).to_string()), (0x1000, "mov\tx0, x1".into()));
/// let (address, ret) = decoder.next().unwrap();
/// assert_eq!((address, ret.unwrap().mnemonic()), (0x1004, "ret"));
/// assert!(decoder.next().is_none());
/// ```
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    /// Address of `bytes[0]`.
    base: u64,
    /// Offset of the next instruction in `bytes`.
    offset: usize,
}

impl<'a> Decoder<'a> {
    /// A decoder of `bytes`, which are at `address`.
    pub const fn new(bytes: &'a [u8], address: u64) -> Self {
        Self {
            bytes,
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
    type Item = (u64, Result<Instruction, Error>);

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.remaining();
        if rest.is_empty() {
            return None;
        }
        let address = self.address();
        let result = decode_bytes(rest);
        self.offset = self.offset.saturating_add(4);
        Some((address, result))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.remaining().len().div_ceil(4);
        (count, Some(count))
    }
}

impl ExactSizeIterator for Decoder<'_> {}

impl FusedIterator for Decoder<'_> {}
