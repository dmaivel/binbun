//! What the development tasks (`cargo xtask`, `src/main.rs`) share with
//! the workspace's tests.
//!
//! - [`aarchmrs`]: the reader of Arm's AARCHMRS package, the input of the
//!   AArch64 decoder generator, which the decoder's and the lifter's tests
//!   check themselves against too.

pub mod aarchmrs;
