//! What instructions do to the flags (`RFLAGS` and the x87 condition
//! codes), from XED's `FLAGS` records (`xed_decoded_inst_get_rflags_info`).

use core::fmt;

use super::Instruction;
use crate::generated::flags::FLAG_RECORDS;

/// A flag of `RFLAGS`, or an x87 condition code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flag {
    /// Carry.
    Cf,
    /// Parity.
    Pf,
    /// Auxiliary carry.
    Af,
    /// Zero.
    Zf,
    /// Sign.
    Sf,
    /// Trap.
    Tf,
    /// Interrupt enable.
    If,
    /// Direction.
    Df,
    /// Overflow.
    Of,
    /// I/O privilege level (two bits).
    Iopl,
    /// Nested task.
    Nt,
    /// Resume.
    Rf,
    /// Virtual-8086 mode.
    Vm,
    /// Alignment check.
    Ac,
    /// Virtual interrupt.
    Vif,
    /// Virtual interrupt pending.
    Vip,
    /// CPUID available.
    Id,
    /// x87 condition code 0.
    Fc0,
    /// x87 condition code 1.
    Fc1,
    /// x87 condition code 2.
    Fc2,
    /// x87 condition code 3.
    Fc3,
}

impl Flag {
    /// The flag's bits in a [`FlagSet`].
    pub const fn bits(self) -> u32 {
        match self {
            Self::Cf => 1 << 0,
            Self::Pf => 1 << 2,
            Self::Af => 1 << 4,
            Self::Zf => 1 << 6,
            Self::Sf => 1 << 7,
            Self::Tf => 1 << 8,
            Self::If => 1 << 9,
            Self::Df => 1 << 10,
            Self::Of => 1 << 11,
            Self::Iopl => 3 << 12,
            Self::Nt => 1 << 14,
            Self::Rf => 1 << 16,
            Self::Vm => 1 << 17,
            Self::Ac => 1 << 18,
            Self::Vif => 1 << 19,
            Self::Vip => 1 << 20,
            Self::Id => 1 << 21,
            Self::Fc0 => 1 << 28,
            Self::Fc1 => 1 << 29,
            Self::Fc2 => 1 << 30,
            Self::Fc3 => 1 << 31,
        }
    }

    /// XED's lower-case name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cf => "cf",
            Self::Pf => "pf",
            Self::Af => "af",
            Self::Zf => "zf",
            Self::Sf => "sf",
            Self::Tf => "tf",
            Self::If => "if",
            Self::Df => "df",
            Self::Of => "of",
            Self::Iopl => "iopl",
            Self::Nt => "nt",
            Self::Rf => "rf",
            Self::Vm => "vm",
            Self::Ac => "ac",
            Self::Vif => "vif",
            Self::Vip => "vip",
            Self::Id => "id",
            Self::Fc0 => "fc0",
            Self::Fc1 => "fc1",
            Self::Fc2 => "fc2",
            Self::Fc3 => "fc3",
        }
    }
}

/// A set of flags, laid out as in `RFLAGS` (the x87 condition codes in
/// bits 28 to 31, which `RFLAGS` does not use).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct FlagSet(pub u32);

impl FlagSet {
    /// Whether `flag` is in the set.
    pub const fn contains(self, flag: Flag) -> bool {
        self.0 & flag.bits() != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// What an instruction does to a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlagAction {
    /// Set according to the result.
    Modify,
    /// Read.
    Test,
    /// Left undefined.
    Undefined,
    /// Cleared.
    Clear,
    /// Set.
    Set,
    /// Loaded from `AH` (`SAHF`).
    FromAh,
    /// Loaded from the stack (`POPF`).
    Pop,
}

impl FlagAction {
    /// XED's spelling (`mod`, `tst`, `u`, `0`, `1`, `ah`, `pop`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Modify => "mod",
            Self::Test => "tst",
            Self::Undefined => "u",
            Self::Clear => "0",
            Self::Set => "1",
            Self::FromAh => "ah",
            Self::Pop => "pop",
        }
    }
}

/// One flag and what happens to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlagEffect {
    /// The flag.
    pub flag: Flag,
    /// What happens to it.
    pub action: FlagAction,
}

impl fmt::Display for FlagEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.flag.as_str(), self.action.as_str())
    }
}

/// An instruction's effect on the flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flags {
    /// Flags read.
    pub read: FlagSet,
    /// Flags written (set, cleared, modified or left undefined).
    pub written: FlagSet,
    /// Flags left undefined.
    pub undefined: FlagSet,
    /// The writes may not happen (a `REP` with a zero count).
    pub may_write: bool,
    /// The writes always happen.
    pub must_write: bool,
    /// Each flag and what happens to it, in XED's order.
    pub effects: &'static [FlagEffect],
}

/// Which [`Flags`] record applies to an instruction (XED's simple and
/// complex flags): indices into `FLAG_RECORDS` plus one, 0 for none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlagsRule {
    /// The instruction touches no flags.
    None,
    /// One record.
    Always(u16),
    /// By the shift count (the 8-bit immediate masked to 5 bits, or 6 with
    /// a 64-bit operand size): 0, 1 or more.
    Count { zero: u16, one: u16, other: u16 },
}

impl Instruction {
    /// The instruction's effect on the flags, `None` if it has none (or,
    /// like a shift by 0, none for these operands).
    pub fn flags(&self) -> Option<&'static Flags> {
        let s = &self.fields;
        let record = match self.info().flags {
            FlagsRule::None => 0,
            FlagsRule::Always(record) => record,
            FlagsRule::Count { zero, one, other } => {
                let mask = if s.eosz == 3 { 0x3f } else { 0x1f };
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "XED reads the immediate's low byte"
                )]
                match s.uimm0 as u8 & mask {
                    0 => zero,
                    1 => one,
                    _ => other,
                }
            }
        };
        FLAG_RECORDS.get(usize::from(record).checked_sub(1)?)
    }
}
