//! x86 and x86-64 instruction decoder.
//!
//! The tables in `generated/` are produced by `cargo xtask codegen` from Intel
//! XED's datafiles (`third_party/xed`); the decoding logic around them is
//! written by hand. The crate is `no_std`; its only dependency is
//! [`binbun_isa`], whose traits it implements ([`X86`]) and whose control-flow
//! vocabulary [`Instruction::flow`] returns.

#![no_std]

mod cpuid;
mod decode;
mod decoder;
mod error;
mod fast;
mod generated;
mod ild;
mod isa;

use core::fmt;

pub use cpuid::{CpuidField, CpuidRegister};
#[cfg(feature = "internal-reference")]
#[doc(hidden)]
pub use decode::decode_reference;
pub use decode::flags::{Flag, FlagAction, FlagEffect, FlagSet, Flags};
pub use decode::flow::{Condition, relative_target};
pub use decode::format::Intel;
pub use decode::operand::{Action, ElementBase, Memory, Operand, Value, Visibility};
pub use decode::{Attributes, Encoding, Instruction, decode, decode_flow};
pub use decoder::Decoder;
pub use error::{DecodeError, Mode};
pub use generated::form::{Attribute, Category, Extension, Form, IsaSet};
pub use generated::mnemonic::Mnemonic;
pub use generated::operand::{ElementType, OperandName, OperandWidth};
pub use generated::register::{Register, RegisterClass};
pub use ild::{MAX_LENGTH, decode_length};
pub use isa::X86;

/// Most operands an instruction has: the longest
/// [`Instruction::operands`].
pub const MAX_OPERANDS: usize = {
    let mut most = 0;
    let mut rest: &[decode::InstructionInfo] = &generated::form::INSTRUCTIONS;
    while let [info, tail @ ..] = rest {
        if info.operand_count as usize > most {
            most = info.operand_count as usize;
        }
        rest = tail;
    }
    most
};

/// Error of parsing a name that names nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownName;

impl fmt::Display for UnknownName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown name")
    }
}

impl core::error::Error for UnknownName {}
