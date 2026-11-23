//! Library signatures: which library function a piece of statically
//! linked code is.
//!
//! - [`canon`]: a function's canonical form from its own L1 and its
//!   identity, a hash of that form that register allocation, block
//!   layout, frame layout and addresses do not change; which argument
//!   registers it reads ([`canon::reads`]).
//! - [`Fingerprint`]: cheap features of the canonical form, and
//!   [`index`], the candidate index over them.
//! - [`pack`]: signature packs, JSON Lines.
//! - [`rust`]: Rust symbol names as paths without crate hashes, and the
//!   generic code an instance comes from.
//! - [`check`]: behaviour checking: a library function's behaviour
//!   recorded on states chosen when the pack is made, and an unknown
//!   function run on those states, its calls answered as recorded,
//!   compared with the recording.
//!
//! Making packs and matching a binary against them, which need the
//! loader, recovery and lifting, are the engine's
//! (`binbun::signatures`).

pub mod canon;
pub mod check;
pub mod index;
pub mod pack;
pub mod rust;

use core::fmt;
use core::fmt::Write as _;
use core::str::FromStr;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub use canon::{Abi, Canonical, Input, Reads, Referent, Surroundings, canonical, reads};

/// A function's identity: the hash of its canonical form, of identity
/// version [`canon::VERSION`], written `i2:` and 32 hexadecimal digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identity(pub u128);

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "i{}:{:032x}", canon::VERSION, self.0)
    }
}

impl FromStr for Identity {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let prefix = format!("i{}:", canon::VERSION);
        let digits = text
            .strip_prefix(&prefix)
            .ok_or_else(|| format!("{text}: not an identity of version {}", canon::VERSION))?;
        if digits.len() != 32 {
            return Err(format!("{text}: an identity has 32 hexadecimal digits"));
        }
        u128::from_str_radix(digits, 16)
            .map(Self)
            .map_err(|e| format!("{text}: {e}"))
    }
}

impl Serialize for Identity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The hash of a function's bytes with relocated fields zeroed, as
/// byte-pattern signatures match them (the baseline the identity is
/// measured against):
/// `b1:` and the first 128 bits of their BLAKE3 hash in hexadecimal.
pub fn bytes_hash(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    let mut text = String::from("b1:");
    for byte in hash.as_bytes().iter().take(16) {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The fingerprint of a canonical form.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// The argument registers read (a mask over the convention's
    /// argument registers, integer then vector).
    pub arguments: u32,
    /// The result registers written (register numbers).
    pub results: BTreeSet<u16>,
    /// Blocks of the canonical graph.
    pub blocks: u32,
    /// Edges back to an earlier block of the walk.
    pub loops: u32,
    /// Returns.
    pub returns: u32,
    /// Calls and tail calls.
    pub calls: u32,
    /// System calls.
    pub system_calls: u32,
    /// Traps.
    pub traps: u32,
    /// Operations and roots.
    pub size: u32,
    /// Distinctive constants.
    pub constants: BTreeSet<u64>,
    /// Read-only strings, by their contents' hash.
    pub strings: BTreeSet<String>,
    /// Callees known by name.
    pub callees: BTreeSet<String>,
    /// Operations by class (`add`, `load8`, `store4`, …).
    pub ops: BTreeMap<String, u32>,
}
