//! A64 instruction decoder.
//!
//! The tables in `generated/` are produced by `cargo xtask codegen` from Arm's
//! machine-readable A-profile specification (AARCHMRS, the BSD package in
//! `third_party/aarchmrs`) and binbun's hand-written tables of decode-time
//! UNDEFINED checks (`xtask/src/aarch64/undefined.rs`); the code around them
//! is written by hand. The crate is `no_std`; its one dependency is
//! `binbun-isa`, the vocabulary of control flow analyses share.
//!
//! Decoding finds the word's [`Encoding`] (Arm's name for one bit pattern of
//! an instruction, e.g. `ADD_32_addsub_imm`): every A64 encoding of the
//! 2026-09 specification is decoded, whatever features it needs, including
//! those of unannounced architecture versions ([`Encoding::fat`]). Which
//! words decode agrees with LLVM 22's disassembler with every feature
//! enabled, on all 2^32 words, apart from encodings newer than LLVM and two
//! LLVM quirks documented in `tests/oracle.rs`. Where the architecture makes
//! a word CONSTRAINED UNPREDICTABLE (should-be bits not as specified,
//! overlapping registers), the word decodes if LLVM decodes it and is
//! [`Error::Unpredictable`] otherwise.
//!
//! Operands ([`Instruction::operands`], typed: [`operand`]) and text
//! ([`Instruction::display`], or [`Instruction::format`] into a token
//! [`Sink`]) are computed from the word on demand, after alias selection,
//! and the text is LLVM's (every feature, hexadecimal immediates), with
//! labels as the addresses they name, as llvm-objdump writes them;
//! [`LabelStyle::Relative`] writes them as offsets, as LLVM's C API does.
//! Text equals LLVM 22's for every word both decode, apart from a few
//! places where LLVM's text contradicts Arm's syntax (typos, an annotation,
//! an alias Arm withdrew), listed in `tests/oracle.rs`.
//!
//! For analyses: how an instruction transfers control
//! ([`Instruction::flow`]) and the condition it tests
//! ([`Instruction::condition`]); [`AArch64`] implements
//! [`binbun_isa::Architecture`]; [`Decoder`] sweeps a buffer.
//!
//! ```
//! use binbun_aarch64::{Encoding, Error, LabelStyle, decode, decode_bytes};
//!
//! let add = decode(0x8b02_0020)?; // add x0, x1, x2
//! assert_eq!(add.encoding(), Encoding::ADD_64_addsub_shift);
//! assert_eq!(add.encoding().mnemonic(), "ADD");
//! assert_eq!(decode_bytes(&[0x1f, 0x20, 0x03, 0xd5])?.encoding(), Encoding::NOP_HI_hints);
//! // add w0, w1, w2 with shift == '11', a reserved shift type
//! assert_eq!(decode(0x0bc2_0020), Err(Error::Undefined));
//!
//! // Operands and text, as LLVM writes them; aliases are resolved.
//! let mov = decode(0xaa01_03e0)?; // orr x0, xzr, x1
//! assert_eq!(mov.mnemonic(), "mov");
//! assert_eq!(mov.display(0x1000).to_string(), "mov\tx0, x1");
//!
//! // Labels: the address by default, the offset as LLVM's C API writes it.
//! let b = decode(0x1400_0010)?; // b +0x40
//! assert_eq!(b.display(0x1000).to_string(), "b\t0x1040");
//! assert_eq!(b.display_with(0x1000, LabelStyle::Relative).to_string(), "b\t#0x40");
//! # Ok::<(), Error>(())
//! ```

#![no_std]

mod access;
mod decoder;
mod error;
mod flow;
mod format;
mod generated;
mod isa;
pub mod operand;
mod pseudocode;

use core::fmt;

pub use access::{Access, Accesses, FlagSet, Flags, Implicit, MemoryAccess, MemoryKind};
pub use decoder::Decoder;
pub use error::Error;
pub use flow::{CompareOperand, Condition};
pub use format::{Display, LabelStyle, Sink, TokenKind};
pub use generated::encoding::Encoding;
pub use generated::feature::Feature;
pub use isa::{AArch64, Mode};
pub use operand::{Operand, Operands};

use generated::syntax;

/// Error of parsing a name that names nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownName;

impl fmt::Display for UnknownName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown name")
    }
}

impl core::error::Error for UnknownName {}

/// A decoded A64 instruction: the word and its encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Instruction {
    word: u32,
    encoding: Encoding,
}

impl Instruction {
    /// The instruction word.
    #[inline]
    pub const fn word(self) -> u32 {
        self.word
    }

    /// The encoding the word is an instance of.
    #[inline]
    pub const fn encoding(self) -> Encoding {
        self.encoding
    }

    /// The features the encoding needs; see [`Encoding::features`].
    #[inline]
    pub const fn features(self) -> &'static [Feature] {
        self.encoding.features()
    }

    /// The mnemonic as written, after alias selection, lower case and with
    /// any suffix (`mov` for `orr x0, xzr, x1`, `b.eq`).
    pub fn mnemonic(self) -> &'static str {
        let alias = syntax::select(self.encoding, self.word);
        syntax::mnemonic(self.encoding, alias, self.word)
    }

    /// The operands as written, after alias selection.
    pub fn operands(self) -> Operands {
        let mut operands = Operands::new();
        let alias = syntax::select(self.encoding, self.word);
        syntax::operands(self.encoding, alias, self.word, &mut operands);
        operands
    }

    /// The operands of the encoding's own syntax, whatever alias the text
    /// would use (`orr x0, xzr, x1` for `mov x0, x1`, `subs xzr, x1, #0x5`
    /// for `cmp x1, #0x5`): what Arm's pseudocode for the encoding names,
    /// for lifting. Optional parts are omitted as the text omits them
    /// (`{, <shift> #<amount>}` with `lsl #0`, `ret`'s `x30`).
    pub fn encoding_operands(self) -> Operands {
        let mut operands = Operands::new();
        syntax::operands(self.encoding, 0, self.word, &mut operands);
        operands
    }
}

/// Decodes one instruction word.
///
/// # Errors
///
/// [`Error::Unallocated`] if no encoding has the word, [`Error::Undefined`]
/// if its encoding's decode checks reject it, [`Error::Unpredictable`] if it
/// is a CONSTRAINED UNPREDICTABLE form LLVM rejects.
#[inline]
pub fn decode(word: u32) -> Result<Instruction, Error> {
    let encoding = generated::decode::decode(word)?;
    Ok(Instruction { word, encoding })
}

/// Decodes the instruction at the start of `bytes` (little-endian; A64
/// instructions are always 4 bytes).
///
/// # Errors
///
/// [`Error::TooShort`] if `bytes` has fewer than 4 bytes; otherwise as
/// [`decode`].
#[inline]
pub fn decode_bytes(bytes: &[u8]) -> Result<Instruction, Error> {
    let word = bytes.first_chunk::<4>().ok_or(Error::TooShort)?;
    decode(u32::from_le_bytes(*word))
}
