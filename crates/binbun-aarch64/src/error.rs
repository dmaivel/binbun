//! Decoding errors.

use core::fmt;

/// Why bytes do not decode to an A64 instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// Fewer than 4 bytes.
    TooShort,
    /// No encoding has this word: the space is unallocated.
    Unallocated,
    /// The word is an instance of an encoding, but a check in its decode
    /// pseudocode makes it UNDEFINED (a reserved field value, such as
    /// `shift == '11'` for an add with shifted register).
    Undefined,
    /// The word is an instance of an encoding, but CONSTRAINED UNPREDICTABLE
    /// (should-be bits not as specified, a load pair loading one register
    /// twice, …), and rejected as LLVM's disassembler rejects it.
    Unpredictable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooShort => "instruction is truncated",
            Self::Unallocated => "unallocated encoding",
            Self::Undefined => "undefined instruction",
            Self::Unpredictable => "constrained unpredictable instruction",
        })
    }
}

impl core::error::Error for Error {}
