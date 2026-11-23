//! x86 instructions to L0 ([`binbun_semantics`]).
//!
//! The semantics are written by hand in `semantics/*.rs` (a strict subset
//! of Rust syntax, never compiled as Rust) and compiled by `cargo xtask
//! codegen` into `src/generated.rs`, checked against XED's operand and
//! flag metadata for every form an entry covers. Everything mechanical
//! (operand access, x86's register write rules, flags XED fixes) is the
//! hand-written runtime in [`lifter`]. Only 64-bit mode is lifted so far.
//! Each undefined value is a [`site`]'s, listed in [`sites`] by the same
//! generator.
//! Instructions without semantics can still be given an honest
//! over-approximation ([`lift_opaque`]).
//! With the `profiles` feature, the `profiles` module reads what a
//! processor does at the sites (the shipped profiles and files like them).

#![no_std]

extern crate alloc;
#[cfg(feature = "profiles")]
extern crate std;

mod generated;
pub mod lifter;
mod opaque;
#[cfg(feature = "profiles")]
pub mod profiles;
pub mod registers;
pub mod site;
pub mod sites;

use binbun_semantics::Semantics;
use binbun_x86::{Instruction, Mode};

pub use lifter::{LiftError, Lifter};
pub use opaque::{lift_opaque, opaque_outputs};
pub use registers::X86;

/// The semantics of `instruction`, decoded in `mode` at `address`.
///
/// # Errors
///
/// If its form has no semantics yet, the mode is not 64-bit, or the
/// instruction needs state L0 does not model yet.
pub fn lift(instruction: &Instruction, mode: Mode, address: u64) -> Result<Semantics, LiftError> {
    if mode != Mode::Bits64 {
        return Err(LiftError::Mode(mode));
    }
    let mut lifter = Lifter::new(instruction, address);
    if !generated::lift(&mut lifter, instruction.form()) {
        return Err(LiftError::Unsupported);
    }
    lifter.finish()
}
