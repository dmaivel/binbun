//! Foundation types shared by every binbun crate (no domain logic).
//!
//! - [`Id`] and [`Arena`]: dense, typed `u32` indices instead of pointers, so
//!   graphs (CFGs, IR, type graphs) are plain data with no lifetimes or
//!   reference counting.
//! - [`Keyword`]: fieldless enums with exactly one textual spelling per
//!   variant, used for every token of every text format binbun reads or writes.
//! - [`Memory`]: an address space analyses read from (a loaded file, a dump,
//!   a live target), with fallible reads and permissions.
//! - [`pass`]: passes over a function and the analyses they share, run by
//!   a [`pass::Manager`] (cached analyses dropped on change, one budget, a
//!   verifier after every change, counts).
//!
//! [`Id`] and [`Keyword`] are normally implemented with the derives
//! re-exported here.

mod arena;
mod id;
mod keyword;
pub mod memory;
pub mod pass;

pub use arena::Arena;
pub use binbun_macros::{Id, Keyword};
pub use id::Id;
pub use keyword::{Keyword, UnknownKeyword};
pub use memory::Memory;
