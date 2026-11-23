//! Checks of a lowered and structured function against its L1.
//!
//! - [`structure`]: L2's statements lowered back to a graph of
//!   straight-line pieces and decisions ([`graph`]), each the L1 block its
//!   provenance names (`Origin::Block`), with `&&` and `||` split as C
//!   evaluates them, give L1's CFG: the same successors for every L1
//!   block, up to copies of a block, and blocks that only jump and that
//!   L2 has nothing of contracted.
//! - [`differential`]: L1's and L2's interpreters run from the same
//!   random states ([`random_states`]) on the same memory and intrinsic
//!   answers ([`Oracle`]), up to the first call, exit or escape, and must
//!   end the same way, with the same return value or call target and
//!   arguments, and the same memory, through the
//!   [`Mapping`](crate::mapping::Mapping) lowering gives.
//!   [`localize`] finds where the runs from one state part: the first
//!   assignment whose value differs from the L1 value it stands for.
//! - [`compare_processors`]: L1 run from the same states on several
//!   processors' profiles ([`OnProcessor`]): whether the function behaves
//!   differently on them, and which site decides.

mod differential;
mod flow;
pub mod graph;
mod processors;
mod states;

use alloc::string::String;
use core::fmt;

use binbun_ssa::ir::BlockId;

pub use differential::{
    Difference, Divergence, L2_FUEL, Report, Skip, differential, differential_cancellable, localize,
};
pub use flow::structure;
pub use processors::{Comparison, Decider, Differing, Output, Stored, compare_processors};
pub use states::{
    Hashed, Link, OnProcessor, Oracle, RETURN_ADDRESS, Setup, State, random_states, shaped_states,
};

/// Where L2's control flow differs from L1's ([`structure`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// The L1 block it concerns, if one.
    pub block: Option<BlockId>,
    /// What differs.
    pub message: String,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.block {
            Some(block) => write!(f, "block {}: {}", block.0, self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl core::error::Error for Mismatch {}
