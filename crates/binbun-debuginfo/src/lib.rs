//! A binary's debug information: what it states, and where to get it.
//!
//! - [`info`]: what DWARF and PDB state about a binary's functions,
//!   variables and types, in one model, and where an image's debug
//!   information is by the documented conventions.
//! - `symbols` (feature `symbols`): debug files from symbol servers (PDBs
//!   by `CodeView` GUID and age, ELF debug files over debuginfod by build
//!   ID), cached in symstore layout. Without the feature the crate has no
//!   network code.

pub mod info;
#[cfg(feature = "symbols")]
pub mod symbols;
