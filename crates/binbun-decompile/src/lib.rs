//! From L1 ([`binbun_ssa`]) to L2 ([`binbun_ast`]), and the passes on L2.
//!
//! - [`lower`]: one L1 function to goto-only L2 (signature, variables out
//!   of SSA, expressions, conditions, calls, escapes).
//! - [`format`]: `printf` and `scanf` format strings: the arguments a
//!   call passes after one, and their C types.
//! - [`itanium`]: exception handling under the Itanium C++ ABI: what a
//!   landing pad receives, its clauses, and the structuring passes that
//!   turn its code into `Try` handlers.
//! - [`mapping`]: how a lowered function stands for its L1 function
//!   (parameters, return value, calls, blocks), lowering's second output.
//! - [`names`]: names for variables from evidence (declarations, the
//!   callees' parameters they are passed as, structural roles).
//! - [`pass`]: the environment ([`pass::L2Env`]) and verifier of the L2
//!   passes under [`binbun_semantics::core::pass`]'s manager.
//! - [`prototype`]: declared prototypes, from whatever knows them.
//! - [`range`]: the analysis of ranges: counted loops (their tests and
//!   counters' ranges) and the values that read the same signed or
//!   unsigned.
//! - [`scopes`]: where each local is declared (the innermost block
//!   holding its uses, where no value flows in), the last L2 pass.
//! - [`simplify`]: copy propagation, dead code, proved rewrite rules and
//!   idioms (division by a constant) on structured L2; operations given
//!   the signedness of their operands where both agree (`signs`).
//! - [`structure`]: the structuring pass (region tree, schemas, …).
//! - [`typing`]: decompilation's type inference: constraint solving on
//!   L1 inside lowering.
//! - [`validate`]: the checks every function passes (structure against
//!   L1's CFG, L2's interpreter against L1's).
//!
//! Every pass that changes a function is followed by [`binbun_ast`]'s
//! verifier (the manager runs it).

#![no_std]

extern crate alloc;

pub mod data;
pub mod format;
pub mod itanium;
pub mod lower;
pub mod mapping;
pub mod msvc;
pub mod names;
pub mod pass;
pub mod prototype;
pub mod range;
pub mod scopes;
pub mod simplify;
pub mod structure;
pub mod typing;
pub mod validate;
