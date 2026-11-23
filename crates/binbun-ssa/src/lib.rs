//! L1, binbun's function-level code: one function in SSA form, built from
//! the L0 semantics of its machine instructions ([`binbun_semantics`]), for
//! every architecture.
//!
//! - [`ir`]: the data model ([`Function`], blocks with parameters,
//!   instructions, terminators, one memory variable).
//! - [`build`]: construction from a function's L0 ([`build::build`]).
//! - [`constant`]: constant propagation, and which blocks can run.
//!   Branches it proves go one way become jumps
//!   ([`FoldBranches`](constant::FoldBranches)).
//! - [`condition`]: branch conditions read as comparisons.
//! - [`float`]: the reading view's floating-point assumptions: the
//!   controls a process starts with
//!   ([`AssumeFloatControls`](float::AssumeFloatControls)), and results C
//!   does not tell apart ([`AssumeFloatResults`](float::AssumeFloatResults)).
//! - [`graph`]: predecessors and dominators.
//! - [`jump`]: the targets of computed jumps through tables.
//! - [`stack`]: stack slots, and what loads from them read; checks that a
//!   stack address is canonical made jumps
//!   ([`AssumeCanonical`](stack::AssumeCanonical)).
//! - [`pass`]: the environment ([`pass::L1Env`]) in which these analyses
//!   and passes run under [`binbun_semantics::core::pass`]'s manager.
//! - [`summary`]: a function's effect on its caller.
//! - [`verify`]: checking the model's rules.
//! - [`text`]: a readable text form.
//! - [`interpret`]: running a function on concrete state, with undefined
//!   bits tracked as in L0.

#![no_std]

extern crate alloc;

pub mod build;
pub mod condition;
pub mod constant;
pub mod float;
pub mod graph;
mod groups;
pub mod implied;
pub mod interpret;
pub mod ir;
pub mod jump;
pub mod pass;
pub mod stack;
pub mod summary;
pub mod text;
pub mod verify;

pub use build::{
    BuildError, CallEffect, Code, Environment, FuncletReturn, Instruction, Resume, Unwind, build,
};
pub use ir::{Block, BlockId, Function, Inst, InstId, Op, Terminator, Type, Value};
