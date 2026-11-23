//! Reader for Intel XED's aggregated datafiles.
//!
//! XED's build concatenates the datafiles of every enabled ISA extension into
//! `obj/dgen/all-*.txt`; binbun vendors those in `third_party/xed` (see
//! `scripts/update-xed.sh`). This crate parses them into structures that
//! borrow from the text, reproducing the interpretation of XED's Python
//! generator. It is an input to binbun's decoder generator and is never a
//! runtime dependency.
//!
//! ```
//! use binbun_xed::{Datafile, instructions};
//!
//! let file = Datafile::new("INSTRUCTIONS()::\n{\nICLASS: NOP\nCATEGORY: NOP\n\
//!                           EXTENSION: BASE\nPATTERN: 0x90\nOPERANDS:\n}\n");
//! let tables = instructions::parse(&file)?;
//! assert_eq!(tables[0].selected()[0].iclass, "NOP");
//! # Ok::<(), binbun_xed::Error>(())
//! ```

mod error;
pub mod fields;
pub mod flags;
pub mod instructions;
pub mod lines;
pub mod maps;
pub mod nonterminals;
pub mod operands;
pub mod pattern;
mod section;
pub mod state;
pub mod tables;
mod value;

pub use error::{Error, ErrorKind};
pub use section::{Datafile, Header, Section};
pub use state::StateMacros;
