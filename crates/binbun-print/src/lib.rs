//! L2 ([`binbun_ast`]) as C.
//!
//! - [`document`]: tokens with kinds and provenance, in layout groups.
//! - [`layout`]: renders a document under a [`style::Style`].
//! - [`style`]: layout and presentation options, presets.
//! - [`c`]: an L2 function to a document, with the declarations it
//!   needs; C's rules live here and nowhere else.
//!
//! `binbun_defs.h` (the helpers the output calls) is `include/binbun_defs.h`.

#![no_std]

extern crate alloc;

pub mod c;
pub mod document;
pub mod layout;
pub mod style;
