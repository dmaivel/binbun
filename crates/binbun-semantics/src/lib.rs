//! L0, binbun's per-instruction semantics: what one instruction does,
//! exactly, for every architecture.
//!
//! - [`ir`]: the data model ([`Semantics`], expressions, statements, an
//!   architecture's [`Declarations`] of registers and intrinsics, views).
//! - [`build`]: building semantics, with hash-consed expressions and
//!   structured `if`/`loop`.
//! - [`verify`]: checking the model's rules.
//! - [`text`]: the canonical text form (`parse(print(x)) == x`).
//! - [`interpret`]: running semantics on concrete state, with undefined
//!   bits tracked (IEEE arithmetic by `rustc_apfloat`).
//! - [`expand`]: flag computations in plain operations.
//! - [`smt`]: semantics as SMT-LIB 2 terms over their initial state, for
//!   proving equivalences with a solver.
//! - [`rule`] and [`profile`]: what a processor does where the semantics
//!   leave a value undefined.
//!
//! Architectures declare their registers and intrinsics and produce
//! [`Semantics`]
//! (x86: `binbun-x86-lift`); nothing here is specific to one architecture.
//!
//! [`core`](crate::core) holds the foundation types every binbun crate shares: typed
//! ids, arenas, keyword enums, memory, passes.

#![no_std]

extern crate alloc;
// Lets the derives, which emit `::binbun_semantics::core::…` paths, be
// used inside this crate.
extern crate self as binbun_semantics;

pub mod bits;
pub mod build;
pub mod core;
pub mod expand;
mod float;
pub mod interpret;
pub mod ir;
pub mod profile;
pub mod rule;
pub mod smt;
pub mod text;
pub mod verify;

pub use bits::Bits;
pub use build::Builder;
pub use ir::{Declarations, IntrinsicId, IntrinsicInfo, RegisterId, RegisterInfo, Semantics, View};
