//! Architecture-independent instruction decoding and inspection for x86 and AArch64.
//!
//! [`decode`] and [`Decoder`] take an [`Arch`] chosen by the caller (nothing
//! is guessed from the bytes) and give an [`Insn`]: its address, the bytes
//! it was decoded from (borrowed from the caller's buffer), its length, its
//! mnemonic, its text, its control flow and the registers it reads and
//! writes, whichever the architecture. Everything else stays with the
//! native decoders, [`binbun_x86`] and [`binbun_aarch64`]
//! (re-exported as [`x86`] and [`aarch64`]), whose instruction
//! [`Insn::as_x86`] and [`Insn::as_aarch64`] return: operands, flags,
//! conditions, encodings, text options and tokens.
//!
//! The crate is `no_std` and allocates nothing: an [`Insn`] is the native
//! instruction behind an enum, and its facts are computed when asked.
//! Features `x86` and `aarch64` (both default) choose the architectures:
//! without one, its [`Arch`] variant, [`Insn`]'s `as_` method and its
//! decoder crate are left out. [`Flow`] and [`Target`] are re-exported, so
//! that no other crate is needed.
//!
//! - [`Insn::mnemonic`] is the mnemonic the text writes, lower case: on
//!   x86 the word after any prefix words (`movsb` of `rep movsb`, not
//!   XED's iclass `REP_MOVSB`), on AArch64 after alias selection, with its
//!   suffix (`mov`, `b.eq`).
//! - The text (`Display`) is each decoder's own default: Intel syntax as
//!   XED writes it on x86, LLVM's on AArch64 (a tab after the mnemonic);
//!   branch targets as addresses on both. Nothing is normalised.
//! - [`Insn::registers_read`] and [`Insn::registers_written`] are what
//!   the decoders report an instruction *may* read and write; see
//!   [`Registers`].
//!
//! ```
//! use binbun_disasm::{Arch, Decoder, Flow, Target, x86};
//!
//! let code = [0x55, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3]; // push rbp; call; ret
//! let mut decoder = Decoder::new(Arch::X86(x86::Mode::Bits64), &code, 0x1000);
//! let (address, push) = decoder.next().unwrap();
//! let push = push?;
//! assert_eq!((address, push.mnemonic(), push.to_string()), (0x1000, "push", "push rbp".into()));
//! assert_eq!(push.bytes(), [0x55]);
//! let names = |registers: &binbun_disasm::Registers| {
//!     registers.iter().map(ToString::to_string).collect::<Vec<_>>()
//! };
//! assert_eq!(names(&push.registers_read()), ["rbp", "rsp"]);
//! assert_eq!(names(&push.registers_written()), ["rsp"]);
//! let (_, call) = decoder.next().unwrap();
//! assert_eq!(call?.flow(), Flow::Call(Target::Address(0x1006)));
//!
//! let a64 = [0xe0, 0x03, 0x01, 0xaa]; // orr x0, xzr, x1
//! let mov = binbun_disasm::decode(Arch::AArch64, &a64, 0x2000)?;
//! assert_eq!((mov.mnemonic(), mov.to_string()), ("mov", "mov\tx0, x1".into()));
//! assert_eq!(mov.as_aarch64().unwrap().encoding().mnemonic(), "ORR");
//! # Ok::<(), binbun_disasm::DecodeError>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]

mod registers;

#[cfg(not(any(feature = "x86", feature = "aarch64")))]
compile_error!("binbun-disasm needs feature `x86` or `aarch64` (or both)");

use core::fmt;
use core::iter::FusedIterator;

#[cfg(feature = "aarch64")]
pub use binbun_aarch64 as aarch64;
pub use binbun_isa::{Flow, Target};
#[cfg(feature = "x86")]
pub use binbun_x86 as x86;
#[cfg(feature = "aarch64")]
pub use registers::AArch64Register;
pub use registers::{Register, Registers};

/// The architecture to decode for, with x86's processor mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    /// x86 in a mode: 16, 32 or 64-bit ([`x86::Mode`]).
    #[cfg(feature = "x86")]
    X86(x86::Mode),
    /// AArch64's A64 instruction set.
    #[cfg(feature = "aarch64")]
    AArch64,
}

impl Arch {
    /// The longest instruction, in bytes: 15 on x86, 4 on AArch64 (whose
    /// instructions are all 4 bytes).
    pub const fn max_length(self) -> usize {
        match self {
            #[cfg(feature = "x86")]
            Self::X86(_) => x86::MAX_LENGTH,
            #[cfg(feature = "aarch64")]
            Self::AArch64 => 4,
        }
    }

    /// How far a [`Decoder`] moves past bytes that are no instruction: one
    /// byte on x86, so that a sweep resynchronises; four on AArch64.
    pub const fn invalid_step(self) -> usize {
        match self {
            #[cfg(feature = "x86")]
            Self::X86(_) => 1,
            #[cfg(feature = "aarch64")]
            Self::AArch64 => 4,
        }
    }
}

/// Why bytes are no instruction: the native decoder's error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecodeError {
    /// The x86 decoder's.
    #[cfg(feature = "x86")]
    X86(x86::DecodeError),
    /// The AArch64 decoder's.
    #[cfg(feature = "aarch64")]
    AArch64(aarch64::Error),
}

impl DecodeError {
    /// Whether the bytes end before the instruction does.
    pub const fn is_truncated(self) -> bool {
        match self {
            #[cfg(feature = "x86")]
            Self::X86(error) => matches!(error, x86::DecodeError::TooShort),
            #[cfg(feature = "aarch64")]
            Self::AArch64(error) => matches!(error, aarch64::Error::TooShort),
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "x86")]
            Self::X86(error) => error.fmt(f),
            #[cfg(feature = "aarch64")]
            Self::AArch64(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for DecodeError {}

#[cfg(feature = "x86")]
impl From<x86::DecodeError> for DecodeError {
    fn from(error: x86::DecodeError) -> Self {
        Self::X86(error)
    }
}

#[cfg(feature = "aarch64")]
impl From<aarch64::Error> for DecodeError {
    fn from(error: aarch64::Error) -> Self {
        Self::AArch64(error)
    }
}

/// The native instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Native {
    #[cfg(feature = "x86")]
    X86(x86::Instruction, x86::Mode),
    #[cfg(feature = "aarch64")]
    AArch64(aarch64::Instruction),
}

/// A decoded instruction at its address, with the bytes it was decoded
/// from.
///
/// Its `Display` is its text, as the native decoder writes it by default
/// (see the [crate] documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insn<'a> {
    address: u64,
    bytes: &'a [u8],
    native: Native,
}

impl<'a> Insn<'a> {
    /// The x86 instruction `instruction`, which a decode in `mode` made
    /// from `bytes` at `address`, as [`decode`] would give it: for code
    /// that keeps native instructions and asks them again, without
    /// decoding twice (binbun's C API). `bytes` past the instruction's
    /// length are left out.
    #[cfg(feature = "x86")]
    pub fn from_x86(
        instruction: x86::Instruction,
        mode: x86::Mode,
        bytes: &'a [u8],
        address: u64,
    ) -> Self {
        Self {
            address,
            bytes: bytes.get(..instruction.len()).unwrap_or(bytes),
            native: Native::X86(instruction, mode),
        }
    }

    /// The AArch64 instruction `instruction`, decoded from `bytes` at
    /// `address`, as [`decode`] would give it; see [`Insn::from_x86`].
    #[cfg(feature = "aarch64")]
    pub fn from_aarch64(instruction: aarch64::Instruction, bytes: &'a [u8], address: u64) -> Self {
        Self {
            address,
            bytes: bytes.get(..4).unwrap_or(bytes),
            native: Native::AArch64(instruction),
        }
    }

    /// The architecture it was decoded for.
    pub const fn arch(&self) -> Arch {
        match self.native {
            #[cfg(feature = "x86")]
            Native::X86(_, mode) => Arch::X86(mode),
            #[cfg(feature = "aarch64")]
            Native::AArch64(_) => Arch::AArch64,
        }
    }

    /// Its address.
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Its length in bytes: 1 to 15 on x86, 4 on AArch64.
    #[allow(clippy::len_without_is_empty, reason = "an instruction is never empty")]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// The bytes it was decoded from, borrowed from the buffer decoded
    /// (AArch64's are the word, little-endian).
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The mnemonic its text writes, lower case: on x86 the word after any
    /// prefix words (`movsb` of `rep movsb`; `call far`), on AArch64 after
    /// alias selection, with its suffix (`mov`, `b.eq`). The native
    /// mnemonics, XED's iclass and Arm's encoding mnemonic, are the native
    /// instruction's.
    pub fn mnemonic(&self) -> &'static str {
        match &self.native {
            #[cfg(feature = "x86")]
            Native::X86(instruction, _) => instruction.intel_mnemonic(),
            #[cfg(feature = "aarch64")]
            Native::AArch64(instruction) => instruction.mnemonic(),
        }
    }

    /// What it does to the flow of control at its address.
    pub fn flow(&self) -> Flow {
        match &self.native {
            #[cfg(feature = "x86")]
            Native::X86(instruction, _) => binbun_isa::Instruction::flow(instruction, self.address),
            #[cfg(feature = "aarch64")]
            Native::AArch64(instruction) => instruction.flow(self.address),
        }
    }

    /// The registers it may read; see [`Registers`].
    pub fn registers_read(&self) -> Registers {
        match &self.native {
            #[cfg(feature = "x86")]
            Native::X86(instruction, _) => registers::x86(instruction, registers::Side::Read),
            #[cfg(feature = "aarch64")]
            Native::AArch64(instruction) => registers::aarch64(*instruction, registers::Side::Read),
        }
    }

    /// The registers it may write; see [`Registers`].
    pub fn registers_written(&self) -> Registers {
        match &self.native {
            #[cfg(feature = "x86")]
            Native::X86(instruction, _) => registers::x86(instruction, registers::Side::Write),
            #[cfg(feature = "aarch64")]
            Native::AArch64(instruction) => {
                registers::aarch64(*instruction, registers::Side::Write)
            }
        }
    }

    /// The x86 decoder's instruction, if it is one.
    #[cfg(feature = "x86")]
    pub const fn as_x86(&self) -> Option<&x86::Instruction> {
        match &self.native {
            Native::X86(instruction, _) => Some(instruction),
            #[cfg(feature = "aarch64")]
            Native::AArch64(_) => None,
        }
    }

    /// The AArch64 decoder's instruction, if it is one.
    #[cfg(feature = "aarch64")]
    pub const fn as_aarch64(&self) -> Option<&aarch64::Instruction> {
        match &self.native {
            #[cfg(feature = "x86")]
            Native::X86(..) => None,
            Native::AArch64(instruction) => Some(instruction),
        }
    }
}

impl fmt::Display for Insn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.native {
            #[cfg(feature = "x86")]
            Native::X86(instruction, _) => instruction.intel(self.address).fmt(f),
            #[cfg(feature = "aarch64")]
            Native::AArch64(instruction) => instruction.display(self.address).fmt(f),
        }
    }
}

/// Decodes the instruction at the start of `bytes`, which is at
/// `address`, for `arch`.
///
/// # Errors
///
/// The native decoder's: [`x86::decode`]'s or
/// [`aarch64::decode_bytes`]'s.
pub fn decode(arch: Arch, bytes: &[u8], address: u64) -> Result<Insn<'_>, DecodeError> {
    let native = match arch {
        #[cfg(feature = "x86")]
        Arch::X86(mode) => Native::X86(x86::decode(bytes, mode)?, mode),
        #[cfg(feature = "aarch64")]
        Arch::AArch64 => Native::AArch64(aarch64::decode_bytes(bytes)?),
    };
    let len = match &native {
        #[cfg(feature = "x86")]
        Native::X86(instruction, _) => instruction.len(),
        #[cfg(feature = "aarch64")]
        Native::AArch64(_) => 4,
    };
    Ok(Insn {
        address,
        bytes: bytes.get(..len).unwrap_or(bytes),
        native,
    })
}

/// Decodes the instructions of a buffer one after another (a linear
/// sweep), for an architecture.
///
/// Each item is the address and the decode result. After an instruction
/// the decoder moves past it; after bytes that are no instruction, as the
/// native decoders do ([`Arch::invalid_step`]): one byte on x86, so that a
/// sweep over data or misaligned code resynchronises, four on AArch64 (a
/// last piece shorter than 4 bytes is one truncated step).
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    arch: Arch,
    bytes: &'a [u8],
    /// Address of `bytes[0]`.
    base: u64,
    /// Offset of the next instruction in `bytes`.
    offset: usize,
}

impl<'a> Decoder<'a> {
    /// A decoder of `bytes`, which are at `address`, for `arch`.
    pub const fn new(arch: Arch, bytes: &'a [u8], address: u64) -> Self {
        Self {
            arch,
            bytes,
            base: address,
            offset: 0,
        }
    }

    /// The architecture it decodes for.
    pub const fn arch(&self) -> Arch {
        self.arch
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

impl<'a> Iterator for Decoder<'a> {
    type Item = (u64, Result<Insn<'a>, DecodeError>);

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.remaining();
        if rest.is_empty() {
            return None;
        }
        let address = self.address();
        let result = decode(self.arch, rest, address);
        let step = result.as_ref().map_or(self.arch.invalid_step(), Insn::len);
        self.offset = self.offset.saturating_add(step);
        Some((address, result))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rest = self.remaining().len();
        match self.arch {
            #[cfg(feature = "x86")]
            Arch::X86(_) => (rest.div_ceil(x86::MAX_LENGTH), Some(rest)),
            #[cfg(feature = "aarch64")]
            Arch::AArch64 => (rest.div_ceil(4), Some(rest.div_ceil(4))),
        }
    }
}

impl FusedIterator for Decoder<'_> {}
