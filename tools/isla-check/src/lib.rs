//! isla-check: binbun's AArch64 L0 against sail-arm's execute pseudocode.
//!
//! For one A64 word, isla runs sail-arm v9.4 (the `armv9p4.ir` Jib
//! snapshot) symbolically from a reset state with every general-purpose
//! register, the stack pointer, NZCV and BTYPE unknown ([`model`]), under
//! binbun's execution context: EL0, AArch64, little-endian, Linux's
//! `SCTLR_EL1.SA0` = 1 and `TCR_EL1.TBI0` = `TBI1` = `TBID1` = 1, BTI
//! implemented, flat Normal memory ([`model::CONFIG`], [`model::OVERRIDES`],
//! [`context`]). Each path
//! isla finds ([`trace`]) is compared with binbun's L0 for the word, encoded
//! by `binbun_semantics::smt` over the same initial state, and z3 looks
//! for an initial state where they end differently ([`check`]): an
//! exception where binbun does not trap, or any register, the next PC,
//! BTYPE, memory or the bytes accessed differing.
//!
//! A verdict is equivalent (z3 proved every path), a counterexample (the
//! initial state, what differs, both values), or unsupported (isla failed,
//! Sail writes state binbun does not map, or the terms are floating
//! point).

pub mod check;
pub mod context;
pub mod model;
pub mod sexp;
pub mod solver;
pub mod sweep;
pub mod trace;

pub use check::{Counterexample, Verdict, check};
pub use model::{Model, with_model};
