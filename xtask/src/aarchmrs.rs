//! Reader for Arm's BSD AARCHMRS package (the A-profile machine-readable
//! specification).
//!
//! binbun vendors the package unchanged as a tarball in `third_party/aarchmrs`
//! (see `scripts/update-aarchmrs.sh`); [`Package::read`] decompresses it and
//! parses the parts binbun's AArch64 decoder generator uses into typed
//! structures:
//!
//! - the A64 instruction tree ([`instructions`]): groups, encodings and
//!   aliases with their conditions, encoding sets (fixed bits, fields,
//!   should-be bits), assembly templates and `_meta.encoded_in`;
//! - the assembly rules (tokens, rules, choices) the templates refer to;
//! - the feature model ([`features`]): parameters and their constraints;
//! - the A64 system accessors of `Registers.json` ([`registers`]), with the
//!   conditions of their register's field layouts.
//!
//! The A32 and T32 instruction sets, the register fields and the
//! documentation are skipped without being materialised. The module is an
//! input to the generator (and the decoder's and lifter's tests) and never
//! a runtime dependency.
//!
//! ```no_run
//! use xtask::aarchmrs::Package;
//!
//! let package = Package::read("third_party/aarchmrs/AARCHMRS_OPENSOURCE_A_profile_FAT-2026-09.tar.gz")?;
//! let encodings = package.a64.encodings();
//! assert_eq!(encodings.len(), 4429);
//! # Ok::<(), xtask::aarchmrs::Error>(())
//! ```

mod error;
pub mod expr;
pub mod features;
pub mod instructions;
pub mod registers;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;

pub use error::Error;
pub use expr::{BinaryOp, Expr, Pattern};
pub use features::{Features, Parameter};
pub use instructions::{
    Alias, AssemblyRule, EncodeField, Encodeset, Group, Instruction, InstructionSet, Node, Range,
    Symbol,
};
pub use registers::{AccessorEncoding, AccessorIndex, AccessorValue, SystemAccessor};

/// The release a file belongs to (`_meta.version`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Version {
    /// Architecture version covered, e.g. `vFATAp2-A`.
    pub architecture: String,
    /// Build number.
    pub build: String,
    /// Release reference, e.g. `2026-09_rel`.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Schema version, e.g. `2.9.6`.
    pub schema: String,
    /// Build time.
    pub timestamp: String,
}

/// What binbun uses of an AARCHMRS package.
#[derive(Debug, Clone)]
pub struct Package {
    /// The release (from `Instructions.json`).
    pub version: Version,
    /// The A64 instruction set.
    pub a64: InstructionSet,
    /// Assembly rules by id.
    pub assembly_rules: BTreeMap<String, AssemblyRule>,
    /// The feature model.
    pub features: Features,
    /// System accessors of AArch64 registers, in file order.
    pub accessors: Vec<SystemAccessor>,
}

const INSTRUCTIONS: &str = "Instructions.json";
const FEATURES: &str = "Features.json";
const REGISTERS: &str = "Registers.json";

impl Package {
    /// Reads the package tarball (`.tar.gz`) at `path`.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, is not a gzip-compressed tar archive,
    /// lacks a JSON file or the JSON does not follow the modelled schema.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::from_tar_gz(std::fs::File::open(path)?)
    }

    /// Reads the package from a gzip-compressed tar stream.
    ///
    /// # Errors
    ///
    /// As [`Package::read`].
    pub fn from_tar_gz(reader: impl Read) -> Result<Self, Error> {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(reader));
        let mut instructions = None;
        let mut features = None;
        let mut accessors = None;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let file = match entry.path()?.to_str() {
                Some(INSTRUCTIONS) => INSTRUCTIONS,
                Some(FEATURES) => FEATURES,
                Some(REGISTERS) => REGISTERS,
                _ => continue,
            };
            let mut json = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
            entry.read_to_end(&mut json)?;
            let context = |error| Error::Json { file, error };
            match file {
                INSTRUCTIONS => instructions = Some(instructions::parse(&json).map_err(context)?),
                FEATURES => features = Some(features::parse(&json).map_err(context)?),
                _ => accessors = Some(registers::parse(&json).map_err(context)?),
            }
        }
        let instructions = instructions
            .ok_or(Error::MissingFile(INSTRUCTIONS))?
            .ok_or(Error::MissingA64)?;
        Ok(Self {
            version: instructions.version,
            a64: instructions.a64,
            assembly_rules: instructions.assembly_rules,
            features: features.ok_or(Error::MissingFile(FEATURES))?,
            accessors: accessors.ok_or(Error::MissingFile(REGISTERS))?,
        })
    }
}
