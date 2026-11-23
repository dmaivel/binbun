//! Decoding modes and errors.

use core::fmt;

/// The processor mode instructions are decoded for.
///
/// Compatibility mode decodes like protected mode of the same width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Real-address mode with 16-bit code segments.
    Real16,
    /// Real-address mode with a 32-bit code segment (`CS.D = 1`).
    Real32,
    /// 16-bit protected or compatibility mode.
    Bits16,
    /// 32-bit protected or compatibility mode.
    Bits32,
    /// 64-bit mode.
    Bits64,
}

impl Mode {
    /// Default operand and address size in bits: 16, 32 or 64.
    pub const fn bits(self) -> u32 {
        match self {
            Self::Real16 | Self::Bits16 => 16,
            Self::Real32 | Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }

    /// Whether this is real-address mode.
    pub const fn is_real(self) -> bool {
        matches!(self, Self::Real16 | Self::Real32)
    }
}

/// Why bytes do not decode to an instruction. The variants follow XED's
/// `xed_error_enum_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DecodeError {
    /// The bytes end before the instruction does.
    TooShort = 1,
    /// The instruction would be longer than 15 bytes.
    TooLong,
    /// No instruction has this encoding.
    Invalid,
    /// The instruction does not exist in the decoding mode.
    InvalidMode,
    /// A register field encodes no valid register.
    BadRegister,
    /// `LOCK` on an instruction that does not allow it.
    BadLockPrefix,
    /// `66`, `F2` or `F3` where none is allowed (e.g. before VEX).
    BadLegacyPrefix,
    /// `REX` where none is allowed (e.g. before VEX or REX2).
    BadRexPrefix,
    /// An opcode map that does not exist.
    BadMap,
    /// `EVEX.V'` is 0 outside 64-bit mode.
    BadEvexVPrime,
    /// `EVEX.z` is set without a mask register.
    BadEvexZeroingWithoutMask,
    /// `EVEX.L'L` is 3 without embedded rounding.
    BadEvexLength,
    /// An AVX2 gather's index, destination and mask registers are not all
    /// different.
    GatherRegisters,
    /// Registers that must differ are the same.
    BadRegisterMatch,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooShort => "instruction is truncated",
            Self::TooLong => "instruction is longer than 15 bytes",
            Self::Invalid => "invalid instruction",
            Self::InvalidMode => "instruction is invalid in this mode",
            Self::BadRegister => "invalid register encoding",
            Self::BadLockPrefix => "LOCK prefix is not allowed",
            Self::BadLegacyPrefix => "66, F2 or F3 prefix is not allowed",
            Self::BadRexPrefix => "REX prefix is not allowed",
            Self::BadMap => "invalid opcode map",
            Self::BadEvexVPrime => "EVEX.V' must be 1 outside 64-bit mode",
            Self::BadEvexZeroingWithoutMask => "EVEX.z requires a mask register",
            Self::BadEvexLength => "EVEX.L'L is 3 without embedded rounding",
            Self::GatherRegisters => "gather index, destination and mask registers must differ",
            Self::BadRegisterMatch => "registers that must differ are the same",
        })
    }
}

impl core::error::Error for DecodeError {}

impl DecodeError {
    const ALL: [Self; 14] = [
        Self::TooShort,
        Self::TooLong,
        Self::Invalid,
        Self::InvalidMode,
        Self::BadRegister,
        Self::BadLockPrefix,
        Self::BadLegacyPrefix,
        Self::BadRexPrefix,
        Self::BadMap,
        Self::BadEvexVPrime,
        Self::BadEvexZeroingWithoutMask,
        Self::BadEvexLength,
        Self::GatherRegisters,
        Self::BadRegisterMatch,
    ];

    /// The error numbered `code` (`error as u8`), `None` for 0.
    #[inline]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code).checked_sub(1)?).copied()
    }
}
