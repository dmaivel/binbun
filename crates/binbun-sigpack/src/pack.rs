//! Signature packs: JSON Lines, UTF-8, one pack per library, version and
//! target. A header line, then one line per function sorted by name and
//! object, so a new revision diffs by function.
//!
//! ```text
//! {"binbun_sigpack":1,"identity":2,"revision":1,"library":"musl",...}
//! {"function":{"name":"strcpy","object":"strcpy.o","builds":{"gcc-O2":{...}},...}}
//! ```
//!
//! A function's record per build of the library: its identity, the hash
//! of its bytes with relocated fields zeroed (the usual byte-pattern
//! signature, for comparison), whether the identity is trivial, its size,
//! fingerprint, the symbols its code slots call, and what behaviour
//! checking compares it by ([`Check`]): its behaviour recorded on chosen
//! states (what shipped packs carry, so no library code is
//! redistributed), or its code (packs a user makes for themselves). A
//! build whose record equals another build's says so (`"=gcc-O2"`).
//!
//! `binbun_sigpack` is the format version and `identity` the identity
//! version; packs of other versions are refused with a message naming
//! them.
//!
//! A pack file is that text, or the text compressed with zstd
//! (`.jsonl.zst`, as packs are installed: [`compress`]); [`text`] reads
//! either.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read as _;

use ruzstd::decoding::StreamingDecoder;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};
use serde::{Deserialize, Serialize};

use crate::check::Recording;
use crate::{Fingerprint, Identity, canon};

/// The pack format version.
pub const FORMAT: u32 = 1;

/// zstd's magic number: a compressed pack's first four bytes.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// The most memory set aside for a decompressed pack before reading it,
/// whatever size its frame header gives: a larger pack grows as it is read.
const MOST_RESERVED: u64 = 1 << 28;

/// The text of a pack file of `bytes`: decompressed if they are zstd's
/// (`.jsonl.zst`), else as they are.
///
/// # Errors
///
/// The bytes are not UTF-8, or not a whole zstd frame of it.
pub fn text(bytes: Vec<u8>) -> Result<String, String> {
    if !bytes.starts_with(&ZSTD_MAGIC) {
        return String::from_utf8(bytes).map_err(|e| e.to_string());
    }
    let mut decoder = StreamingDecoder::new(bytes.as_slice()).map_err(|e| format!("zstd: {e}"))?;
    let size = decoder.decoder.content_size().min(MOST_RESERVED);
    let mut text = String::with_capacity(usize::try_from(size).unwrap_or_default());
    decoder
        .read_to_string(&mut text)
        .map_err(|e| format!("zstd: {e}"))?;
    Ok(text)
}

/// `text` compressed with zstd, as `binbun sig make` writes packs
/// (`.jsonl.zst`; `zstd -d` gives the text back). The same text gives the
/// same bytes.
pub fn compress(text: &str) -> Vec<u8> {
    compress_to_vec(text.as_bytes(), CompressionLevel::Fastest)
}

/// A pack's header line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The format version ([`FORMAT`]).
    pub binbun_sigpack: u32,
    /// The identity version ([`canon::VERSION`]).
    pub identity: u32,
    /// The pack's revision.
    pub revision: u32,
    /// The library (`musl`).
    pub library: String,
    /// Its version (`1.2.5`).
    pub version: String,
    /// What its code runs on.
    pub target: Target,
    /// The library's licence (SPDX).
    pub licence: String,
    /// The library's copyright notice, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
    /// The source the library was built from, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// The builds of the library the pack holds.
    pub builds: Vec<BuildInfo>,
    /// The type database the prototypes come from, if one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typedb: Option<String>,
    /// What made the pack.
    pub made_by: String,
}

/// A pack's target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// The architecture (`x86_64`).
    pub arch: String,
    /// The operating system (`linux`).
    pub os: String,
    /// The environment (`musl`, `gnu`).
    pub env: String,
    /// The pointer size in bytes.
    pub pointer_size: u8,
}

/// The source a library was built from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// The package (`musl-1.2.5.tar.gz`).
    pub package: String,
    /// Where it is published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Its SHA-256.
    pub sha256: String,
}

/// One build of the library in a pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInfo {
    /// Its name in the pack (`gcc16-O2`).
    pub id: String,
    /// The toolchain, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<String>,
    /// The flags, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    /// The input files' names.
    pub inputs: Vec<String>,
    /// Their SHA-256s, in order.
    pub sha256: Vec<String>,
}

/// One line of a pack after the header.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Line {
    /// A function.
    Function(Entry),
}

/// A library function.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Its name.
    pub name: String,
    /// Other names of the same function: symbols at its address, and
    /// non-trivial identical definitions in other objects (the same
    /// identity and masked bytes, the same data, and callees that are
    /// themselves identical).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// How many functions of the library it stands for: identical
    /// definitions merged into it, each at its own address (a binary
    /// holds it at no more addresses than this).
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub copies: u32,
    /// The equivalence group it is in, if any: functions no
    /// check tells apart (each one's code fits the other's recording),
    /// named by their first member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Other functions whose code fits this one's recording on every
    /// state, though this one's does not fit theirs: a function whose
    /// behaviour fits this recording is named only when each of these was
    /// checked and ruled out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub look_alikes: Vec<String>,
    /// The object it comes from.
    pub object: String,
    /// Its C prototype, where known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    /// Its record per build.
    pub builds: BTreeMap<String, Built>,
    /// States telling it from look-alikes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub separators: Vec<Separator>,
}

/// One, the default of [`Entry::copies`].
const fn one() -> u32 {
    1
}

/// Whether `copies` is the default, one.
#[expect(clippy::trivially_copy_pass_by_ref, reason = "serde's signature")]
const fn is_one(copies: &u32) -> bool {
    *copies == 1
}

/// A function's record in one build, or the name of the build whose
/// record it equals (written `"=id"`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Built {
    /// The same as another build's.
    Same(String),
    /// Its own.
    Record(Box<Build>),
}

/// A function's record in one build.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Build {
    /// Its identity.
    pub identity: Identity,
    /// The SHA-256 of its bytes with relocated fields zeroed, `b1:` and
    /// 32 hexadecimal digits (the first 128 bits).
    pub bytes: String,
    /// Whether the identity is trivial.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub trivial: bool,
    /// Its fingerprint.
    pub fingerprint: Fingerprint,
    /// The symbol each code slot calls, by slot number (empty: an address
    /// no symbol names).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callees: Vec<String>,
    /// What behaviour checking compares it by, if it is checkable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<Check>,
}

/// What behaviour checking compares a library function by.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Check {
    /// Its behaviour on chosen states, recorded when the pack was made.
    Recorded(Recording),
    /// Its machine code (relocated fields zeroed) and relocations, run
    /// beside the unknown function: only in packs a user makes for
    /// themselves.
    Code(Code),
}

/// A function's machine code in a pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Code {
    /// The bytes, hexadecimal, relocated fields zeroed.
    pub code: String,
    /// The relocations: offset, kind, symbol, addend.
    pub relocs: Vec<(u32, String, String, i64)>,
}

/// A state that tells a function from another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Separator {
    /// The function it tells this one from.
    pub from: String,
    /// The state's index in this function's recording.
    pub state: u32,
}

/// A whole pack.
#[derive(Clone, Debug, PartialEq)]
pub struct Pack {
    /// Its header.
    pub header: Header,
    /// Its functions, sorted by name and object.
    pub functions: Vec<Entry>,
}

impl Pack {
    /// The pack as text: the header, then each function, one line each.
    ///
    /// # Errors
    ///
    /// A line does not serialize (never, for these types).
    pub fn write(&self) -> Result<String, String> {
        let mut text = serde_json::to_string(&self.header).map_err(|e| e.to_string())?;
        text.push('\n');
        let mut functions: Vec<&Entry> = self.functions.iter().collect();
        functions.sort_by(|a, b| (&a.name, &a.object).cmp(&(&b.name, &b.object)));
        for entry in functions {
            let line =
                serde_json::to_string(&Line::Function(entry.clone())).map_err(|e| e.to_string())?;
            let _ = writeln!(text, "{line}");
        }
        Ok(text)
    }

    /// The pack in `text`.
    ///
    /// # Errors
    ///
    /// A line is no JSON of the format, or the pack is of another format
    /// or identity version.
    pub fn read(text: &str) -> Result<Self, String> {
        let mut lines = text
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty());
        let (_, first) = lines.next().ok_or("an empty pack")?;
        let value: serde_json::Value =
            serde_json::from_str(first).map_err(|e| format!("line 1: {e}"))?;
        let format = value
            .get("binbun_sigpack")
            .and_then(serde_json::Value::as_u64);
        if format != Some(u64::from(FORMAT)) {
            return Err(format!(
                "a pack of format {} (this binbun reads format {FORMAT})",
                format.map_or_else(|| "unknown".to_owned(), |f| f.to_string())
            ));
        }
        let header: Header = serde_json::from_value(value).map_err(|e| format!("line 1: {e}"))?;
        if header.identity != canon::VERSION {
            return Err(format!(
                "a pack of identity version {} (this binbun computes version {}; the pack must be remade)",
                header.identity,
                canon::VERSION
            ));
        }
        let mut functions = Vec::new();
        for (number, line) in lines {
            match serde_json::from_str::<Line>(line)
                .map_err(|e| format!("line {}: {e}", number + 1))?
            {
                Line::Function(entry) => functions.push(entry),
            }
        }
        Ok(Self { header, functions })
    }

    /// The record of `entry` in build `id`, following `"=other"`.
    pub fn build<'p>(&'p self, entry: &'p Entry, id: &str) -> Option<&'p Build> {
        let mut id = id;
        for _ in 0..=self.header.builds.len() {
            match entry.builds.get(id)? {
                Built::Record(build) => return Some(build),
                Built::Same(other) => id = other.strip_prefix('=').unwrap_or(other),
            }
        }
        None
    }

    /// Every (entry, build id, record) of the pack.
    pub fn records(&self) -> impl Iterator<Item = (&Entry, &str, &Build)> {
        self.functions.iter().flat_map(move |entry| {
            entry
                .builds
                .keys()
                .filter_map(move |id| Some((entry, id.as_str(), self.build(entry, id)?)))
        })
    }

    /// Adds the builds of `other` (one library, one target) to this pack,
    /// merging per function (by name and object); a function's record
    /// equal to one this pack has for another build is written as that
    /// build's name.
    ///
    /// # Errors
    ///
    /// The packs are of different libraries, versions or targets, or name
    /// a build alike.
    pub fn merge(&mut self, other: Self) -> Result<(), String> {
        let (a, b) = (&self.header, &other.header);
        if (&a.library, &a.version, &a.target) != (&b.library, &b.version, &b.target) {
            return Err(format!(
                "cannot merge {} {} into {} {} (different library, version or target)",
                b.library, b.version, a.library, a.version
            ));
        }
        for build in &other.header.builds {
            if a.builds.iter().any(|known| known.id == build.id) {
                return Err(format!("the pack already has a build {}", build.id));
            }
        }
        let mut index: BTreeMap<(String, String), usize> = self
            .functions
            .iter()
            .enumerate()
            .map(|(i, e)| ((e.name.clone(), e.object.clone()), i))
            .collect();
        for mut entry in other.functions {
            let key = (entry.name.clone(), entry.object.clone());
            if let Some(&i) = index.get(&key)
                && let Some(existing) = self.functions.get_mut(i)
            {
                let records: Vec<(String, Build)> = existing
                    .builds
                    .iter()
                    .filter_map(|(id, built)| match built {
                        Built::Record(build) => Some((id.clone(), (**build).clone())),
                        Built::Same(_) => None,
                    })
                    .collect();
                for (id, built) in core::mem::take(&mut entry.builds) {
                    let same = match &built {
                        Built::Record(build) => records
                            .iter()
                            .find(|(_, known)| known == &**build)
                            .map(|(known, _)| Built::Same(format!("={known}"))),
                        Built::Same(_) => None,
                    };
                    existing.builds.insert(id, same.unwrap_or(built));
                }
                existing.prototype = existing.prototype.take().or(entry.prototype);
                let aliases: BTreeSet<String> =
                    existing.aliases.drain(..).chain(entry.aliases).collect();
                existing.aliases = aliases.into_iter().collect();
                existing.copies = existing.copies.max(entry.copies);
                let look_alikes: BTreeSet<String> = existing
                    .look_alikes
                    .drain(..)
                    .chain(entry.look_alikes)
                    .collect();
                existing.look_alikes = look_alikes.into_iter().collect();
            } else {
                index.insert(key, self.functions.len());
                self.functions.push(entry);
            }
        }
        self.functions
            .sort_by(|a, b| (&a.name, &a.object).cmp(&(&b.name, &b.object)));
        self.header.builds.extend(other.header.builds);
        self.header.revision = self.header.revision.max(other.header.revision);
        Ok(())
    }

    /// What is wrong with the pack: lines out of order or repeated, builds
    /// referred to that the header does not list, `"="` references that
    /// do not resolve; and, as notes, identities shared by several
    /// functions of one build.
    pub fn check(&self) -> (Vec<String>, Vec<String>) {
        let mut errors = Vec::new();
        let mut notes = Vec::new();
        let builds: BTreeSet<&str> = self.header.builds.iter().map(|b| b.id.as_str()).collect();
        for pair in self.functions.windows(2) {
            if let [a, b] = pair
                && (&a.name, &a.object) >= (&b.name, &b.object)
            {
                errors.push(format!(
                    "{} ({}) is not sorted before {} ({}), or repeats",
                    a.name, a.object, b.name, b.object
                ));
            }
        }
        for entry in &self.functions {
            for id in entry.builds.keys() {
                if !builds.contains(id.as_str()) {
                    errors.push(format!("{}: build {id} is not in the header", entry.name));
                }
                if self.build(entry, id).is_none() {
                    errors.push(format!(
                        "{}: build {id}'s record does not resolve",
                        entry.name
                    ));
                }
            }
        }
        let mut shared: BTreeMap<(&str, Identity), Vec<&str>> = BTreeMap::new();
        for (entry, id, build) in self.records() {
            shared
                .entry((id, build.identity))
                .or_default()
                .push(&entry.name);
        }
        let duplicated = shared.values().filter(|names| names.len() > 1).count();
        if duplicated != 0 {
            notes.push(format!(
                "{duplicated} identities are shared by more than one function of a build (listed, never named, unless aliases)"
            ));
        }
        (errors, notes)
    }
}
