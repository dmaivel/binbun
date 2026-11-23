//! The vocabulary analyses use to work with any instruction set: how an
//! instruction transfers control ([`Flow`], [`Target`]) and the traits every
//! binbun decoder implements ([`Architecture`], [`Instruction`]).
//! Control-flow recovery needs only [`FlowStep`]s, which
//! [`Architecture::decode_flow`] may give faster than a full decode.
//!
//! Analyses (CFG recovery, later lifting) are written against these traits
//! only. Architecture-specific detail, such as which condition a branch
//! tests, stays in the decoder crates.
//!
//! `no_std`, no dependencies.

#![no_std]

use core::fmt::Debug;

/// Where a jump or call goes, as far as the instruction alone tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// A known address.
    Address(u64),
    /// The address stored in memory (an x86 `jmp [rip+disp]`, the usual
    /// way to reach an import through its GOT or IAT slot).
    Pointer {
        /// Where the address is stored.
        address: u64,
        /// Its size in bytes.
        size: u8,
    },
    /// A register or a computed memory operand.
    Indirect,
    /// A segmented address (an x86 far pointer), which needs the segment's
    /// base to become an address.
    Far {
        /// The segment selector.
        selector: u16,
        /// The offset in the segment.
        offset: u64,
    },
}

impl Target {
    /// The address, if known.
    pub const fn address(self) -> Option<u64> {
        match self {
            Self::Address(address) => Some(address),
            Self::Pointer { .. } | Self::Indirect | Self::Far { .. } => None,
        }
    }
}

/// How an instruction transfers control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flow {
    /// Execution continues with the next instruction.
    Next,
    /// An unconditional jump.
    Jump(Target),
    /// A conditional jump: to the target, or on with the next instruction.
    Branch(Target),
    /// A call; the callee normally returns to the next instruction.
    Call(Target),
    /// A return from a call.
    Return,
    /// A software interrupt or deliberate exception (`INT3`, `UD2`, `BRK`);
    /// `conditional` ones (`INTO`) continue with the next instruction when
    /// they do not trap.
    Trap {
        /// Whether it only traps on a condition.
        conditional: bool,
    },
    /// An entry to the operating system or hypervisor (`SYSCALL`, `SVC`),
    /// which normally returns to the next instruction.
    SystemCall,
    /// A return from an interrupt, exception or system call (`IRET`,
    /// `SYSRET`, `ERET`).
    ExceptionReturn,
    /// A halt until the next interrupt (`HLT`).
    Halt,
}

impl Flow {
    /// Whether execution can continue with the next instruction.
    pub const fn falls_through(self) -> bool {
        match self {
            Self::Next | Self::Branch(_) | Self::Call(_) | Self::SystemCall => true,
            Self::Trap { conditional } => conditional,
            Self::Jump(_) | Self::Return | Self::ExceptionReturn | Self::Halt => false,
        }
    }
}

/// A decoded instruction, as analyses see it.
#[expect(clippy::len_without_is_empty, reason = "an instruction is never empty")]
pub trait Instruction {
    /// Length in bytes.
    fn len(&self) -> usize;

    /// How it transfers control, for the instruction at `address`.
    fn flow(&self, address: u64) -> Flow;

    /// An address the instruction at `address` computes as a value instead
    /// of accessing it (an x86 RIP-relative `lea`): a pointer it may pass
    /// on, such as a function's address given to a call.
    fn computed_address(&self, address: u64) -> Option<u64> {
        let _ = address;
        None
    }
}

/// What control-flow recovery needs of the instruction at an address: its
/// length, how it transfers control and the address it computes
/// ([`Instruction::len`], [`Instruction::flow`] and
/// [`Instruction::computed_address`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowStep {
    /// Length in bytes.
    pub len: usize,
    /// How it transfers control.
    pub flow: Flow,
    /// An address it computes as a value.
    pub computed_address: Option<u64>,
}

impl FlowStep {
    /// The step of `instruction` at `address`.
    pub fn of<I: Instruction + ?Sized>(instruction: &I, address: u64) -> Self {
        Self {
            len: instruction.len(),
            flow: instruction.flow(address),
            computed_address: instruction.computed_address(address),
        }
    }
}

/// An instruction set and its decoder.
pub trait Architecture {
    /// A decoded instruction.
    type Instruction: Instruction;
    /// Why bytes do not decode.
    type Error: Copy + Debug;
    /// The processor mode instructions are decoded for (x86's 16/32/64-bit
    /// modes; AArch64 has one).
    type Mode: Copy + Debug + Eq;

    /// The longest instruction, in bytes: reading this many always
    /// suffices to decode one.
    const MAX_LENGTH: usize;

    /// Decodes the instruction at the start of `bytes` in `mode`.
    ///
    /// # Errors
    ///
    /// When the bytes are no instruction, or end before one does.
    fn decode(&self, bytes: &[u8], mode: Self::Mode) -> Result<Self::Instruction, Self::Error>;

    /// The [`FlowStep`] of the instruction at the start of `bytes`, which is
    /// at `address`: as from [`Architecture::decode`], which decoders may do
    /// faster by skipping what control flow does not need.
    ///
    /// # Errors
    ///
    /// Exactly when [`Architecture::decode`] fails, with its error.
    fn decode_flow(
        &self,
        bytes: &[u8],
        mode: Self::Mode,
        address: u64,
    ) -> Result<FlowStep, Self::Error> {
        self.decode(bytes, mode)
            .map(|instruction| FlowStep::of(&instruction, address))
    }
}
