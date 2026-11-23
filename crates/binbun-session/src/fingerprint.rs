//! What peers compare to know they analyse alike: the analysis
//! fingerprint ([`Session::fingerprint`]).

use std::fs;
use std::path::Path;

use crate::journal::EngineVersion;
use crate::{Session, Stage};

/// A debug file an analysis read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugDigest {
    /// Its file name.
    pub name: String,
    /// Its SHA-256.
    pub sha256: [u8; 32],
}

/// What an analysis is, for comparing with a peer's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    /// BLAKE3 of the build, the binary's SHA-256, the debug file's
    /// SHA-256 (zeros without one) and every function's entry and end
    /// (the end of its last block), by entry.
    pub analysis: [u8; 32],
    /// The debug file read, if any.
    pub debug: Option<DebugDigest>,
}

/// The SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// The debug file at `path`, hashed; `None` if it cannot be read.
fn debug_digest(path: &Path) -> Option<DebugDigest> {
    let bytes = fs::read(path).ok()?;
    Some(DebugDigest {
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        sha256: sha256(&bytes),
    })
}

impl Session {
    /// The analysis fingerprint, once the
    /// functions are recovered ([`Stage::Analysed`]): equal on two
    /// machines when the same binbun build recovered the same functions
    /// from the same binary and debug file. It hashes the debug file
    /// anew on each call: call it once per analysis, off the UI thread.
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        if self.stage() < Stage::Analysed {
            return None;
        }
        let database = self.database()?;
        let binary = match self.key() {
            Some(key) => *key.sha256(),
            None => sha256(self.bytes()?),
        };
        let debug = self.debug_file().and_then(debug_digest);
        let engine = EngineVersion::this();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"binbun/v1/analysis");
        for part in [&engine.release, &engine.build] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        hasher.update(&binary);
        hasher.update(&debug.as_ref().map_or([0; 32], |debug| debug.sha256));
        let program = database.program();
        let mut functions: Vec<(u64, u64)> = database
            .functions()
            .map(|(_, function)| {
                let end = function
                    .blocks
                    .iter()
                    .filter_map(|block| program.blocks.get(*block))
                    .map(|block| block.end)
                    .max()
                    .unwrap_or(function.entry);
                (function.entry, end)
            })
            .collect();
        functions.sort_unstable();
        hasher.update(&(functions.len() as u64).to_le_bytes());
        for (entry, end) in functions {
            hasher.update(&entry.to_le_bytes());
            hasher.update(&end.to_le_bytes());
        }
        Some(Fingerprint {
            analysis: *hasher.finalize().as_bytes(),
            debug,
        })
    }
}
