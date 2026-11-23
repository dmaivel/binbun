//! AArch64 instructions to L0 ([`binbun_semantics`]).
//!
//! The semantics are written by hand in `semantics/*.rs` (a strict subset
//! of Rust syntax, never compiled as Rust), one entry per AARCHMRS operation
//! (`#[operation(ADD_addsub_shift)]` covers the 32- and 64-bit encodings),
//! and compiled by `cargo xtask codegen` into `src/generated.rs`, checked
//! against the decoder's operand access and flag metadata for words of every
//! encoding an entry covers. Everything mechanical (operands, the zero
//! register and the stack pointer, addressing and writeback, the execution
//! context) is the hand-written runtime in [`lifter`].
//!
//! The execution context is Linux's EL0: AArch64, little-endian,
//! `SCTLR_EL1.SA0` set (an SP-based access with SP not 16-byte aligned
//! faults: [`Trap::Stack`]), top-byte-ignore for branch targets (in L0)
//! and data addresses (by the machine, as part of
//! address translation: L0 accesses the virtual address, tag included), no
//! tag checking, no guarded control stack, no guarded pages
//! (`PSTATE.BTYPE` is kept, not checked).
//!
//! Instructions without semantics that continue with the next one can
//! still be given an honest over-approximation ([`lift_opaque`]).
//!
//! [`Trap::Stack`]: binbun_semantics::ir::Trap::Stack

#![no_std]

extern crate alloc;

mod generated;
pub mod lifter;
mod opaque;
pub mod registers;

use binbun_aarch64::Instruction;
use binbun_semantics::Semantics;

pub use generated::ENCODINGS;
pub use lifter::{LiftError, Lifter};
pub use opaque::{lift_opaque, opaque_outputs};
pub use registers::AARCH64;

/// The semantics of `instruction` at `address`.
///
/// # Errors
///
/// [`LiftError::Unsupported`] if its encoding has no semantics yet;
/// [`LiftError::Problem`] if it needs state L0 does not model yet.
pub fn lift(instruction: &Instruction, address: u64) -> Result<Semantics, LiftError> {
    let mut lifter = Lifter::new(instruction, address);
    if !generated::lift(&mut lifter, instruction.encoding()) {
        return Err(LiftError::Unsupported);
    }
    lifter.finish()
}
