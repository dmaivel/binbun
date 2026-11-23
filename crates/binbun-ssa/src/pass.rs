//! L1 under the pass manager ([`binbun_semantics::core::pass`]): the environment its
//! analyses and passes run in ([`L1Env`]), a function's size (what fuel
//! is measured in) and the verifier the manager runs after each change.
//!
//! - Analyses: [`Constants`](crate::constant::Constants) (constant
//!   propagation), [`Stack`](crate::stack::Stack) (from the constants),
//!   [`Dominators`](crate::graph::Dominators).
//! - Passes: [`AssumeCanonical`](crate::stack::AssumeCanonical) (preserves
//!   nothing: it removes edges), [`FoldBranches`](crate::constant::FoldBranches)
//!   (preserves the constants, which already took only the edge it keeps).

use alloc::string::{String, ToString};
use core::fmt;

use binbun_semantics::ir::{Declarations, RegisterId};

use crate::constant::ReadOnly;
use crate::ir::Function;
use crate::verify;

/// What L1 analyses and passes know beyond the function: its
/// architecture, the memory that never changes, the calling
/// convention's stack pointer, arguments and return address, and the
/// platform's thread pointer.
#[derive(Clone, Copy)]
pub struct L1Env<'a> {
    /// The architecture's registers and intrinsics.
    pub declarations: &'a Declarations,
    /// Memory known before the program runs (loads from it fold).
    pub memory: &'a dyn ReadOnly,
    /// The stack pointer.
    pub stack_pointer: RegisterId,
    /// The registers calls take arguments in, in order.
    pub arguments: &'a [RegisterId],
    /// Where calls leave the return address: at this offset from the
    /// entry stack pointer (x86), or `None` (in a register).
    pub return_slot: Option<i64>,
    /// The register the platform keeps the thread pointer in (x86-64:
    /// `fs_base` under System V, `gs_base` under Windows; AArch64:
    /// `tpidr_el0`), if known.
    pub thread_pointer: Option<RegisterId>,
}

impl fmt::Debug for L1Env<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L1Env")
            .field("stack_pointer", &self.stack_pointer)
            .field("arguments", &self.arguments)
            .field("return_slot", &self.return_slot)
            .field("thread_pointer", &self.thread_pointer)
            .finish_non_exhaustive()
    }
}

/// `function`'s size: its blocks and instructions (each L1 pass spends a
/// unit of fuel per block it visits).
pub fn size(function: &Function) -> u64 {
    let nodes = function.blocks.len().saturating_add(function.insts.len());
    u64::try_from(nodes).unwrap_or(u64::MAX)
}

/// L1's verifier ([`verify::verify`]) as the manager runs it.
///
/// # Errors
///
/// The first broken rule, as text.
pub fn verify(function: &Function, env: &L1Env<'_>) -> Result<(), String> {
    verify::verify(function, env.declarations).map_err(|error| error.to_string())
}

/// `function`'s blocks, as units of fuel.
pub(crate) fn blocks(function: &Function) -> u64 {
    u64::try_from(function.blocks.len()).unwrap_or(u64::MAX)
}
