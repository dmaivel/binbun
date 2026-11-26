//! Simplification of structured L2 (expressions, and compiler
//! optimisations undone): passes that make a function read like source
//! without changing what it does.
//!
//! - [`copies`]: [`Propagate`](copies::Propagate) (copy propagation and the
//!   substitution of a value read once into its reader),
//!   [`Narrow`](copies::Narrow) (a variable whose every read takes its low
//!   bits becomes a variable of those bits, and one assigned only
//!   extensions a variable of their sources' width) and
//!   [`Prune`](copies::Prune)
//!   (assignments nothing reads, but for the loads that may fault in them).
//! - [`rules`]: [`Rewrite`](rules::Rewrite), rewrite rules written as data
//!   (`crates/binbun-decompile/rules/*.rules`), compiled by `cargo xtask
//!   codegen` into a matcher and proved by z3 (the test `rules`), plus
//!   constant folding with L0's own operations.
//! - [`division`]: [`Divisions`](division::Divisions), multiply-high
//!   sequences back to division (and remainder) by a constant.
//! - [`sink`]: [`Sink`](sink::Sink), assignments with no effect but their
//!   write moved down to their uses, undoing a compiler's scheduling.
//! - [`coalesce`]: [`Coalesce`](coalesce::Coalesce), the two variables of
//!   a copy made one where they never hold different values while both
//!   are live (liveness and value numbering over the statements' control
//!   flow, `flow`).
//! - [`signs`]: [`LocalSigns`](signs::LocalSigns), a local's signedness
//!   the one more of its reads ask for, then [`Signs`](signs::Signs), the
//!   last pass: an operation whose operands read the same signed or
//!   unsigned ([`crate::range`]) takes the signedness of their types.
//! - [`fields`]: [`DeclaredFields`](fields::DeclaredFields), the types
//!   of what is read and written through the thread pointer, from the
//!   structure its platform declares (types only: loads and stores are
//!   retyped in place).
//!
//! All of them work on the tree as it is: expressions are appended (never
//! changed: an expression may have several users), statements are changed
//! in place or dropped from their block, labels and control statements are
//! never touched, so the function's control flow stays as structuring left
//! it.
//!
//! Where a value moves (from its assignment into the statement that reads
//! it), the move is checked structurally ([`facts::Facts::available`]):
//! the reader comes after the assignment in the same block, or inside a
//! statement that does; nothing between them can be entered from
//! elsewhere (a label a `goto` names) or writes what the value reads (a
//! variable, or memory if it loads); a value with an undefined part is not
//! moved into a loop (each evaluation would be its own); and a value that
//! may fault (a load) is moved only past assignments of values that
//! cannot, into a statement that runs right after them and evaluates no
//! other load, so the fault happens at the same point with the same state.

pub mod coalesce;
pub mod copies;
pub mod division;
pub(crate) mod expr;
mod facts;
pub mod fields;
pub(crate) mod flow;
pub mod rules;
pub mod signs;
pub mod sink;
