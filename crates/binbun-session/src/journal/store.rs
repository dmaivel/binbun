//! The log on disk, beside the project file it is the truth of:
//!
//! ```text
//! log/
//!   project              the log's id (hexadecimal), written once
//!   bound                what its chains are of, written once: `binary <sha256> <slice|->`
//!                        or `set` (the binding a chain begun here names)
//!   share                the share's genesis (hexadecimal): written last, and again from the
//!                        marks if it is lost
//!   local                the chains this install and its agents write, one a line: what
//!                        past its mark is pending work, not another's change to pull again
//!   projected            BLAKE3 of the project file as the journal last wrote it
//!   frozen               "binbun frozen 1", then per chain frozen: chain, from which change,
//!                        and why (`cut <record> <hash>`, `fork`, `never`)
//!   evidence             "binbun evidence 1", then per chain: `proof <hex>` (a fork proof)
//!                        or `refused <hex>` (the signed head of a change refused for good)
//!   admitted             (shared) "binbun admitted 1", the share's genesis and binding, the
//!                        prefixes its first record lists (`before`), and per chain the number
//!                        admitted up to and the hash of the change there (`mark`): there, the
//!                        log is shared (written after the freezes and evidence it needs)
//!   chains/<chain>.log   "binbun log 1\n", then per change: signed head, LEB128 length, body
//!   apart/<chain>.log    the same, of changes kept apart: refused work, chains of no share
//!   import/<name>.toml   edits to take as an import at the next opening
//! ```
//!
//! Beside it, in the project's directory, `collab/<share>/intent` while a
//! membership record is being taken ([`Intent`], sync §4.3): its freezes
//! are written to `log/frozen` before the log is read.
//!
//! A chain's file is only appended to (each change flushed to the disk
//! before the project file is written) and cut back only to move a
//! refused suffix apart or to drop what is past its mark; a change cut
//! short by a crash is dropped (and cut off at the next append), and
//! changes a failed write left past what is taken are written over. A
//! file with a change in it that does not read is never written to: read
//! as nothing in a log of no share, and keeping a share's log from
//! opening. Every other file is written whole and crash-safely (data,
//! rename, directory), and every directory an entry is made or removed
//! in is flushed before the write counts as done.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::{
    ChainId, ChangeHash, Evidence, ForkProof, FrozenBy, Of, ProjectId, PublicKey, SignedChange,
    SignedHead,
};

/// How far a write goes: whole, or (a crash injected by a test) part of
/// the way, or not at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Whole,
    Part,
    Nothing,
}

/// Crashes injected by tests at each durable write of the log (sync
/// §10.5, P10): the write numbered `at` of this thread stops part way
/// (data written and not renamed, a change cut short, a cut not made)
/// and fails, and every write after it fails without effect, as if the
/// process had stopped there.
#[cfg(test)]
pub(crate) mod crash {
    use std::cell::Cell;

    use super::Step;

    thread_local! {
        static AT: Cell<Option<usize>> = const { Cell::new(None) };
        static DONE: Cell<usize> = const { Cell::new(0) };
        static CRASHED: Cell<bool> = const { Cell::new(false) };
    }

    /// Crashes at write `at` (none: never), counting from now.
    pub(crate) fn arm(at: Option<usize>) {
        AT.set(at);
        DONE.set(0);
        CRASHED.set(false);
    }

    /// Whether the crash came.
    pub(crate) fn crashed() -> bool {
        CRASHED.get()
    }

    /// How far the next write goes.
    pub(super) fn step() -> Step {
        if CRASHED.get() {
            return Step::Nothing;
        }
        let done = DONE.get();
        DONE.set(done + 1);
        if AT.get() == Some(done) {
            CRASHED.set(true);
            Step::Part
        } else {
            Step::Whole
        }
    }
}

/// How far the next write goes: whole, outside tests.
#[cfg(not(test))]
mod crash {
    use super::Step;

    /// Whole.
    pub(super) const fn step() -> Step {
        Step::Whole
    }
}

/// Why a write a test crashed did not complete.
const CRASHED: &str = "stopped part way (a crash, in a test)";

/// Writes `text` to `path` crash-safely: data, rename, directory.
fn write_safely(path: &Path, text: &str) -> Result<(), String> {
    write_bytes(path, text.as_bytes())
}

/// What a chain's file starts with.
const MAGIC: &[u8] = b"binbun log 1\n";

/// The first line of `frozen`.
const FROZEN: &str = "binbun frozen 1";

/// The first line of `evidence`.
const EVIDENCE: &str = "binbun evidence 1";

/// The first line of `admitted`.
const ADMITTED: &str = "binbun admitted 1";

/// A chain frozen: from which change, and why.
pub(crate) type Freezes = BTreeMap<ChainId, (u64, FrozenBy)>;

/// A shared log's admitted marks, under the share and binding they are
/// of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Admitted {
    /// The share's genesis.
    pub(crate) genesis: [u8; 32],
    /// What the log's chains are of.
    pub(crate) of: Of,
    /// The prefixes of chains begun in no share that the share's first
    /// record lists: up to which number, and the hash there.
    pub(crate) before: BTreeMap<ChainId, (u64, ChangeHash)>,
    /// Per chain: the number admitted up to, and the hash of the change
    /// there.
    pub(crate) marks: BTreeMap<ChainId, (u64, ChangeHash)>,
}

/// A chain's file as read.
#[derive(Debug)]
pub(crate) enum Read {
    /// Its changes, in order (a change cut short at its end dropped).
    Changes(Vec<SignedChange>),
    /// It does not read: why.
    Unreadable(String),
}

/// The first line of an intent.
const INTENT: &str = "binbun intent 1";

/// A membership record being taken (sync §4.3), as
/// `collab/<share>/intent` keeps it in the project's directory: written
/// whole before anything else of the record, removed once all of it is.
/// The record is collaboration's (`binbun-collab` writes and reads it);
/// the freezes are the journal's too, so that a log is never read without
/// the freezes of a record being taken, with or without collaboration.
///
/// As a file: `binbun intent 1`, `share <genesis>`, `cut <number>
/// <hash>`, a line `freeze <chain> <from>` per freeze, `record <hex>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// The share's genesis: only a log of this share takes its freezes.
    pub genesis: [u8; 32],
    /// The record, signed, as collaboration encodes it.
    pub record: Vec<u8>,
    /// The record's number in the membership chain.
    pub seq: u64,
    /// The record's hash (BLAKE3 of its bytes).
    pub hash: [u8; 32],
    /// The freezes it causes: per chain, from which change.
    pub freezes: BTreeMap<ChainId, u64>,
}

impl Intent {
    /// The cause its freezes name.
    pub fn by(&self) -> FrozenBy {
        FrozenBy::Cut {
            record: self.seq,
            hash: self.hash,
        }
    }

    /// It as its file holds it.
    pub fn encode(&self) -> Vec<u8> {
        let mut text = format!(
            "{INTENT}\nshare {}\ncut {} {}\n",
            hex(&self.genesis),
            self.seq,
            hex(&self.hash)
        );
        for (chain, from) in &self.freezes {
            let _ = writeln!(text, "freeze {chain} {from}");
        }
        let _ = writeln!(text, "record {}", hex(&self.record));
        text.into_bytes()
    }

    /// The intent file `bytes` hold.
    ///
    /// # Errors
    ///
    /// They are no intent, whole.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let bad = || "not an intent".to_owned();
        let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
        let mut lines = text.lines();
        if lines.next() != Some(INTENT) {
            return Err(bad());
        }
        let genesis = lines
            .next()
            .and_then(|line| parse_hex(line.strip_prefix("share ")?))
            .ok_or_else(bad)?;
        let (seq, hash) = lines
            .next()
            .and_then(|line| {
                let mut words = line.strip_prefix("cut ")?.split(' ');
                let seq = words.next()?.parse().ok()?;
                let hash = parse_hex(words.next()?)?;
                words.next().is_none().then_some((seq, hash))
            })
            .ok_or_else(bad)?;
        let mut freezes = BTreeMap::new();
        let mut record = None;
        for line in lines {
            if record.is_some() {
                return Err(bad());
            }
            if let Some(rest) = line.strip_prefix("record ") {
                record = Some(hex_bytes(rest).ok_or_else(bad)?);
                continue;
            }
            let mut words = line.strip_prefix("freeze ").ok_or_else(bad)?.split(' ');
            let freeze = (|| {
                let chain = ChainId(parse_hex(words.next()?)?);
                let from = words
                    .next()?
                    .parse::<u64>()
                    .ok()
                    .filter(|&from| from >= 1)?;
                words.next().is_none().then_some((chain, from))
            })();
            let (chain, from) = freeze.ok_or_else(bad)?;
            freezes.insert(chain, from);
        }
        Ok(Self {
            genesis,
            record: record.ok_or_else(bad)?,
            seq,
            hash,
            freezes,
        })
    }

    /// The intents kept in project directory `dir`: each
    /// `collab/<share>/intent`.
    ///
    /// # Errors
    ///
    /// The directory or an intent cannot be read, or an intent is not one:
    /// what it freezes is not known.
    pub(crate) fn kept_in(dir: &Path) -> Result<Vec<Self>, String> {
        let collab = dir.join("collab");
        let entries = match fs::read_dir(&collab) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("{}: {error}", collab.display())),
        };
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", collab.display()))?;
            let share = entry.file_name();
            if share.to_str().and_then(parse_hex::<16>).is_some() {
                paths.push(entry.path().join("intent"));
            }
        }
        paths.sort();
        let mut intents = Vec::new();
        for path in paths {
            match fs::read(&path) {
                Ok(bytes) => intents.push(
                    Self::decode(&bytes).map_err(|why| format!("{}: {why}", path.display()))?,
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
        }
        Ok(intents)
    }
}

/// A project's log directory.
#[derive(Clone, Debug)]
pub(crate) struct Store {
    dir: PathBuf,
    /// Each chain file's length up to its last whole change, and that
    /// change's number (0: none), once known.
    whole: BTreeMap<ChainId, (u64, u64)>,
    /// The chain files that do not read: never written to.
    unreadable: BTreeSet<ChainId>,
}

impl Store {
    /// The log in directory `dir` (a project's `log/`, or a share's
    /// directory of its own).
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            whole: BTreeMap::new(),
            unreadable: BTreeSet::new(),
        }
    }

    /// Its directory.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether chain `chain`'s file does not read (it is never written).
    pub(crate) fn unreadable(&self, chain: ChainId) -> bool {
        self.unreadable.contains(&chain)
    }

    fn failed(path: &Path) -> impl Fn(io::Error) -> String + '_ {
        move |error| format!("{}: {error}", path.display())
    }

    /// The text of file `name`, if it exists.
    fn text(&self, name: &str) -> Result<Option<String>, String> {
        let path = self.dir.join(name);
        match fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Self::failed(&path)(error)),
        }
    }

    /// Why file `name` does not read: `what`.
    fn bad(&self, name: &str, what: &str) -> String {
        format!("{}: {what}", self.dir.join(name).display())
    }

    /// The log's id, if the log is made.
    ///
    /// # Errors
    ///
    /// It cannot be read, or is not an id.
    pub(crate) fn project(&self) -> Result<Option<ProjectId>, String> {
        self.text("project")?
            .map(|text| {
                parse_hex(text.trim())
                    .map(ProjectId)
                    .ok_or_else(|| self.bad("project", "not a project id"))
            })
            .transpose()
    }

    /// Makes the log of id `project`, its chains of `of` (kept if it says
    /// so already).
    ///
    /// # Errors
    ///
    /// It cannot be written, or is bound to something else already.
    pub(crate) fn create(&self, project: ProjectId, of: &Of) -> Result<(), String> {
        make_dir(&self.dir.join("chains"))?;
        match self.bound()? {
            Some(bound) if bound == *of => {}
            Some(_) => return Err(self.bad("bound", "bound to another binary")),
            None => write_safely(&self.dir.join("bound"), &format!("{}\n", of_text(of)))?,
        }
        if self.project()?.is_none() {
            write_safely(&self.dir.join("project"), &format!("{project}\n"))?;
        }
        Ok(())
    }

    /// What the log's chains are of, if it says.
    ///
    /// # Errors
    ///
    /// It cannot be read, or says nothing this build reads.
    pub(crate) fn bound(&self) -> Result<Option<Of>, String> {
        self.text("bound")?
            .map(|text| parse_of(text.trim()).ok_or_else(|| self.bad("bound", "not a binding")))
            .transpose()
    }

    /// The share's genesis, if the log is shared.
    ///
    /// # Errors
    ///
    /// It cannot be read, or is no genesis.
    pub(crate) fn share(&self) -> Result<Option<[u8; 32]>, String> {
        self.text("share")?
            .map(|text| parse_hex(text.trim()).ok_or_else(|| self.bad("share", "not a genesis")))
            .transpose()
    }

    /// The share's genesis, if the log is a share's: its `share` file's,
    /// else (that file lost) its marks' ([`Self::admitted`]), which make
    /// the log a share's (sync §4.5 rule 3).
    ///
    /// # Errors
    ///
    /// Either cannot be read, or holds what it should not.
    pub(crate) fn genesis(&self) -> Result<Option<[u8; 32]>, String> {
        match self.share()? {
            Some(genesis) => Ok(Some(genesis)),
            None => Ok(self.admitted()?.map(|admitted| admitted.genesis)),
        }
    }

    /// Makes the log shared, in share `genesis`: written last of what a
    /// share writes.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub(crate) fn set_share(&self, genesis: &[u8; 32]) -> Result<(), String> {
        write_safely(&self.dir.join("share"), &format!("{}\n", hex(genesis)))
    }

    /// The chains this install and its agents write.
    ///
    /// # Errors
    ///
    /// The list cannot be read, or holds what is no chain.
    pub(crate) fn local(&self) -> Result<BTreeSet<ChainId>, String> {
        let Some(text) = self.text("local")? else {
            return Ok(BTreeSet::new());
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                parse_hex(line.trim())
                    .map(ChainId)
                    .ok_or_else(|| self.bad("local", line))
            })
            .collect()
    }

    /// Keeps `local` as the chains this install and its agents write,
    /// crash-safely.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub(crate) fn set_local(&self, local: &BTreeSet<ChainId>) -> Result<(), String> {
        let text = local.iter().fold(String::new(), |mut text, chain| {
            let _ = writeln!(text, "{chain}");
            text
        });
        write_safely(&self.dir.join("local"), &text)
    }

    /// The grants a share last gave this install and its agents, by key
    /// (`log/grants`): what a chain begun while collaboration is not
    /// attached names. None if the file is not there.
    ///
    /// # Errors
    ///
    /// It cannot be read, or holds what is no grant.
    pub(crate) fn grants(&self) -> Result<BTreeMap<PublicKey, u64>, String> {
        let Some(text) = self.text("grants")? else {
            return Ok(BTreeMap::new());
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let mut words = line.split(' ');
                let grant = (|| {
                    let key = PublicKey(parse_hex(words.next()?)?);
                    let grant = words.next()?.parse::<u64>().ok()?;
                    words.next().is_none().then_some((key, grant))
                })();
                grant.ok_or_else(|| self.bad("grants", line))
            })
            .collect()
    }

    /// Keeps `grants` as the grants this install and its agents hold,
    /// crash-safely.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub(crate) fn set_grants(&self, grants: &BTreeMap<PublicKey, u64>) -> Result<(), String> {
        let text = grants.iter().fold(String::new(), |mut text, (key, grant)| {
            let _ = writeln!(text, "{} {grant}", hex(&key.0));
            text
        });
        write_safely(&self.dir.join("grants"), &text)
    }

    /// The chains frozen (none if the file is not there).
    ///
    /// # Errors
    ///
    /// It cannot be read, or holds what is no freeze.
    pub(crate) fn frozen(&self) -> Result<Option<Freezes>, String> {
        let Some(text) = self.text("frozen")? else {
            return Ok(None);
        };
        let mut lines = text.lines();
        if lines.next() != Some(FROZEN) {
            return Err(self.bad("frozen", "not a list of freezes"));
        }
        lines
            .filter(|line| !line.trim().is_empty())
            .map(|line| parse_freeze(line).ok_or_else(|| self.bad("frozen", line)))
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// Keeps `frozen` as the chains frozen, crash-safely.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub(crate) fn set_frozen(&self, frozen: &Freezes) -> Result<(), String> {
        let mut text = format!("{FROZEN}\n");
        for (chain, (from, by)) in frozen {
            let _ = match by {
                FrozenBy::Cut { record, hash } => {
                    writeln!(text, "{chain} {from} cut {record} {}", hex(hash))
                }
                FrozenBy::Fork => writeln!(text, "{chain} {from} fork"),
                FrozenBy::Never => writeln!(text, "{chain} {from} never"),
            };
        }
        write_safely(&self.dir.join("frozen"), &text)
    }

    /// Keeps the freezes of the intents of this log's share kept in project
    /// directory `dir` ([`Intent::kept_in`]) in `frozen`, before the log is
    /// read: each lowers a chain's freeze to its change (never into a
    /// prefix the share's first record lists). Step 3 of taking a record
    /// (sync §4.3), done again; collaboration does the rest when it
    /// attaches. A log of no share has no freezes of records; a share's
    /// without its freezes is not taken as having none (what an intent
    /// would write then omits every earlier cut).
    ///
    /// # Errors
    ///
    /// An intent, the freezes or the marks cannot be read, the freezes are
    /// not there, or they cannot be written: the log is not read.
    pub(crate) fn freeze_intents(&self, dir: &Path) -> Result<(), String> {
        let Some(genesis) = self.genesis()? else {
            return Ok(());
        };
        let mut intents = Intent::kept_in(dir)?;
        intents.retain(|intent| intent.genesis == genesis);
        if intents.iter().all(|intent| intent.freezes.is_empty()) {
            return Ok(());
        }
        let mut frozen = self.frozen()?.ok_or_else(|| {
            format!(
                "{}: a share's log without its freezes is not opened",
                self.dir.display()
            )
        })?;
        let listed = self
            .admitted()?
            .map(|admitted| admitted.before)
            .unwrap_or_default();
        let mut lowered = false;
        for intent in &intents {
            for (&chain, &from) in &intent.freezes {
                let from = from.max(listed.get(&chain).map_or(1, |(through, _)| through + 1));
                if frozen.get(&chain).is_none_or(|(known, _)| from < *known) {
                    frozen.insert(chain, (from, intent.by()));
                    lowered = true;
                }
            }
        }
        if lowered {
            self.set_frozen(&frozen)?;
        }
        Ok(())
    }

    /// The evidence kept (none if the file is not there).
    ///
    /// # Errors
    ///
    /// It cannot be read, or holds what is no evidence.
    pub(crate) fn evidence(&self) -> Result<Option<BTreeMap<ChainId, Evidence>>, String> {
        let Some(text) = self.text("evidence")? else {
            return Ok(None);
        };
        let mut lines = text.lines();
        if lines.next() != Some(EVIDENCE) {
            return Err(self.bad("evidence", "not a list of evidence"));
        }
        lines
            .filter(|line| !line.trim().is_empty())
            .map(|line| parse_evidence(line).ok_or_else(|| self.bad("evidence", line)))
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// Keeps `evidence`, crash-safely.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub(crate) fn set_evidence(
        &self,
        evidence: &BTreeMap<ChainId, Evidence>,
    ) -> Result<(), String> {
        let mut text = format!("{EVIDENCE}\n");
        for (chain, evidence) in evidence {
            let _ = match evidence {
                Evidence::Proof(proof) => writeln!(text, "{chain} proof {}", hex(&proof.bytes())),
                Evidence::Refused(head) => {
                    writeln!(text, "{chain} refused {}", hex(&head.bytes()))
                }
            };
        }
        write_safely(&self.dir.join("evidence"), &text)
    }

    /// The admitted marks (none if the file is not there).
    ///
    /// # Errors
    ///
    /// It cannot be read, or holds what is no mark.
    pub(crate) fn admitted(&self) -> Result<Option<Admitted>, String> {
        let Some(text) = self.text("admitted")? else {
            return Ok(None);
        };
        let bad = |what: &str| self.bad("admitted", what);
        let mut lines = text.lines();
        if lines.next() != Some(ADMITTED) {
            return Err(bad("not a list of marks"));
        }
        let genesis = lines
            .next()
            .and_then(|line| parse_hex(line.strip_prefix("share ")?))
            .ok_or_else(|| bad("no share"))?;
        let of = lines
            .next()
            .and_then(|line| parse_of(line.strip_prefix("of ")?))
            .ok_or_else(|| bad("no binding"))?;
        let mut admitted = Admitted {
            genesis,
            of,
            before: BTreeMap::new(),
            marks: BTreeMap::new(),
        };
        for line in lines.filter(|line| !line.trim().is_empty()) {
            let mut words = line.split(' ');
            let kind = words.next();
            let mark = (|| {
                let chain = ChainId(parse_hex(words.next()?)?);
                let seq = words.next()?.parse::<u64>().ok()?;
                let hash = ChangeHash(parse_hex(words.next()?)?);
                words.next().is_none().then_some((chain, (seq, hash)))
            })();
            match (kind, mark) {
                (Some("before"), Some((chain, mark))) => admitted.before.insert(chain, mark),
                (Some("mark"), Some((chain, mark))) => admitted.marks.insert(chain, mark),
                _ => return Err(bad(line)),
            };
        }
        Ok(Some(admitted))
    }

    /// Keeps `admitted` as the marks, crash-safely.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub(crate) fn set_admitted(&self, admitted: &Admitted) -> Result<(), String> {
        let mut text = format!(
            "{ADMITTED}\nshare {}\nof {}\n",
            hex(&admitted.genesis),
            of_text(&admitted.of)
        );
        for (kind, marks) in [("before", &admitted.before), ("mark", &admitted.marks)] {
            for (chain, (seq, hash)) in marks {
                let _ = writeln!(text, "{kind} {chain} {seq} {hash}");
            }
        }
        write_safely(&self.dir.join("admitted"), &text)
    }

    /// The hash of the project file as the journal last wrote it.
    pub(crate) fn projected(&self) -> Option<[u8; 32]> {
        let text = fs::read_to_string(self.dir.join("projected")).ok()?;
        parse_hex(text.trim())
    }

    /// Records `text` as the project file the journal wrote. Not flushed:
    /// a record lost or cut short by a crash only has the next opening
    /// compare the project file with the log (which it then matches).
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub(crate) fn set_projected(&self, text: &str) -> Result<(), String> {
        let hash = blake3::hash(text.as_bytes());
        let path = self.dir.join("projected");
        fs::write(&path, format!("{}\n", hash.to_hex())).map_err(Self::failed(&path))
    }

    /// The chain files of directory `kind` (`chains`, `apart`), by chain.
    fn files(&self, kind: &str) -> Result<Vec<(ChainId, PathBuf)>, String> {
        let dir = self.dir.join(kind);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(Self::failed(&dir)(error)),
        };
        let mut files = Vec::new();
        for entry in entries {
            let path = entry.map_err(Self::failed(&dir))?.path();
            let chain = path
                .file_name()
                .and_then(|name| name.to_str()?.strip_suffix(".log"))
                .and_then(parse_hex)
                .map(ChainId);
            if let Some(chain) = chain {
                files.push((chain, path));
            }
        }
        files.sort();
        Ok(files)
    }

    /// Every chain of `log/chains/`, each read whole up to its last whole
    /// change, or as not reading.
    ///
    /// # Errors
    ///
    /// The directory or a file cannot be read.
    pub(crate) fn read(&mut self) -> Result<Vec<(ChainId, Read)>, String> {
        let mut read = Vec::new();
        for (chain, path) in self.files("chains")? {
            let bytes = fs::read(&path).map_err(Self::failed(&path))?;
            match decode(&bytes) {
                Ok((changes, whole)) => {
                    let last = changes.last().map_or(0, |change| change.id().seq);
                    self.whole.insert(chain, (whole, last));
                    read.push((chain, Read::Changes(changes)));
                }
                Err(why) => {
                    self.unreadable.insert(chain);
                    read.push((
                        chain,
                        Read::Unreadable(format!("{}: {why}", path.display())),
                    ));
                }
            }
        }
        Ok(read)
    }

    /// Every chain kept apart, read as [`Self::read`] does.
    ///
    /// # Errors
    ///
    /// The directory or a file cannot be read.
    pub(crate) fn read_apart(&self) -> Result<Vec<(ChainId, Read)>, String> {
        let mut read = Vec::new();
        for (chain, path) in self.files("apart")? {
            let bytes = fs::read(&path).map_err(Self::failed(&path))?;
            read.push((
                chain,
                match decode(&bytes) {
                    Ok((changes, _)) => Read::Changes(changes),
                    Err(why) => Read::Unreadable(format!("{}: {why}", path.display())),
                },
            ));
        }
        Ok(read)
    }

    /// The file of chain `chain` in directory `kind`.
    fn path(&self, kind: &str, chain: ChainId) -> PathBuf {
        self.dir.join(kind).join(format!("{chain}.log"))
    }

    /// What of each chain's file an export carries (sync §14.6), by chain:
    /// of a log of no share, the file whole; of a share's, its admitted
    /// and pending changes only: a chain this install writes (`local`) up
    /// to its last whole change, another's up to its admitted mark, and a
    /// chain with neither left out. Nothing of `apart/` is ever read.
    ///
    /// # Errors
    ///
    /// A file cannot be read; a share's log has no marks, or a chain's
    /// file of it does not read.
    pub(crate) fn exported(&self) -> Result<Vec<(ChainId, Vec<u8>)>, String> {
        let shared = match self.genesis()? {
            Some(_) => Some((
                self.admitted()?
                    .ok_or_else(|| self.bad("admitted", "a share's log without its marks"))?
                    .marks,
                self.local()?,
            )),
            None => None,
        };
        let mut exported = Vec::new();
        for (chain, path) in self.files("chains")? {
            let mut bytes = fs::read(&path).map_err(Self::failed(&path))?;
            if let Some((marks, local)) = &shared {
                let failed = |why: String| format!("{}: {why}", path.display());
                let end = if local.contains(&chain) {
                    decode(&bytes).map_err(failed)?.1
                } else if let Some((seq, _)) = marks.get(&chain) {
                    let end = offset_of(&bytes, seq.saturating_add(1)).map_err(failed)?;
                    u64::try_from(end).unwrap_or(u64::MAX)
                } else {
                    continue;
                };
                bytes.truncate(usize::try_from(end).unwrap_or(usize::MAX));
                if bytes.len() <= MAGIC.len() {
                    continue;
                }
            }
            exported.push((chain, bytes));
        }
        Ok(exported)
    }

    /// Appends `changes` to chain `chain`'s file and flushes it to the
    /// disk (a change cut short there cut off first, and any the file holds
    /// from the first of `changes` on written over: written by a write
    /// that failed after them, and taken back since).
    ///
    /// # Errors
    ///
    /// It cannot be written, or does not read.
    pub(crate) fn append(
        &mut self,
        chain: ChainId,
        changes: &[&SignedChange],
    ) -> Result<(), String> {
        if changes.is_empty() {
            return Ok(());
        }
        let path = self.path("chains", chain);
        if self.unreadable.contains(&chain) {
            return Err(format!("{}: does not read; not written to", path.display()));
        }
        let failed = Self::failed(&path);
        if let Some(parent) = path.parent() {
            make_dir(parent)?;
        }
        // A file this store has not written whole or read: made now, or
        // after a write that failed; its entry is flushed with it.
        let seen = self.whole.contains_key(&chain);
        let (mut whole, last) = match self.whole.get(&chain) {
            Some(&whole) => whole,
            None => match fs::read(&path) {
                Ok(bytes) => {
                    let (held, whole) = decode(&bytes)?;
                    (whole, held.last().map_or(0, |change| change.id().seq))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => (0, 0),
                Err(error) => return Err(failed(error)),
            },
        };
        let first = changes.first().map_or(u64::MAX, |change| change.id().seq);
        if last >= first {
            let bytes = fs::read(&path).map_err(&failed)?;
            whole = u64::try_from(offset_of(&bytes, first)?).unwrap_or(u64::MAX);
        }
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(&failed)?;
        if file.metadata().map_err(&failed)?.len() != whole {
            file.set_len(whole).map_err(&failed)?;
        }
        let mut bytes = Vec::new();
        if whole == 0 {
            bytes.extend_from_slice(MAGIC);
        }
        for change in changes {
            bytes.extend_from_slice(&change.encode());
        }
        let step = crash::step();
        if step == Step::Nothing {
            return Err(CRASHED.to_owned());
        }
        if step == Step::Part {
            // Cut short: half of it reached the disk.
            bytes.truncate(bytes.len() / 2);
        }
        file.seek(SeekFrom::Start(whole)).map_err(&failed)?;
        file.write_all(&bytes).map_err(&failed)?;
        file.sync_data().map_err(&failed)?;
        if step == Step::Part {
            return Err(CRASHED.to_owned());
        }
        let last = changes.last().map_or(last, |change| change.id().seq);
        if !seen {
            sync_dir(path.parent().unwrap_or(&self.dir))?;
        }
        self.whole.insert(
            chain,
            (whole + u64::try_from(bytes.len()).unwrap_or(u64::MAX), last),
        );
        Ok(())
    }

    /// Cuts chain `chain`'s file back to its changes before number `from`
    /// (none left: the file removed), flushed.
    ///
    /// # Errors
    ///
    /// It cannot be read or written.
    pub(crate) fn cut(&mut self, chain: ChainId, from: u64) -> Result<(), String> {
        let path = self.path("chains", chain);
        let failed = Self::failed(&path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(failed(error)),
        };
        let at = offset_of(&bytes, from)?;
        if crash::step() != Step::Whole {
            return Err(CRASHED.to_owned());
        }
        if at <= MAGIC.len() {
            fs::remove_file(&path).map_err(&failed)?;
            self.whole.remove(&chain);
            return sync_dir(path.parent().unwrap_or(&self.dir));
        }
        let file = OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(&failed)?;
        let at = u64::try_from(at).unwrap_or(u64::MAX);
        file.set_len(at).map_err(&failed)?;
        file.sync_all().map_err(&failed)?;
        self.whole.insert(chain, (at, from.saturating_sub(1)));
        Ok(())
    }

    /// Moves chain `chain`'s changes from number `from` on apart: written
    /// to `apart/` (after any kept apart before) and made durable, and
    /// only then cut off its file.
    ///
    /// # Errors
    ///
    /// A file cannot be read or written.
    pub(crate) fn move_apart(
        &mut self,
        chain: ChainId,
        moved: &[&SignedChange],
        from: u64,
    ) -> Result<(), String> {
        if !moved.is_empty() {
            let path = self.path("apart", chain);
            let failed = Self::failed(&path);
            if let Some(parent) = path.parent() {
                make_dir(parent)?;
            }
            let mut bytes = match fs::read(&path) {
                Ok(bytes) => {
                    let (kept, whole) = decode(&bytes)?;
                    let mut bytes = bytes;
                    bytes.truncate(usize::try_from(whole).unwrap_or(usize::MAX));
                    // Moved again after a crash: what is apart already stays once.
                    let first = moved.first().map_or(u64::MAX, |change| change.id().seq);
                    if kept.iter().any(|change| change.id().seq >= first) {
                        bytes.truncate(offset_of(&bytes, first)?);
                    }
                    bytes
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => MAGIC.to_vec(),
                Err(error) => return Err(failed(error)),
            };
            for change in moved {
                bytes.extend_from_slice(&change.encode());
            }
            write_bytes(&path, &bytes)?;
        }
        self.cut(chain, from)
    }

    /// Writes `changes` (of one chain) apart whole, durably: a merged
    /// bundle's chain in a shared log.
    ///
    /// # Errors
    ///
    /// A file cannot be read or written.
    pub(crate) fn put_apart(
        &self,
        chain: ChainId,
        changes: &[&SignedChange],
    ) -> Result<(), String> {
        let path = self.path("apart", chain);
        if let Some(parent) = path.parent() {
            make_dir(parent)?;
        }
        let mut bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => MAGIC.to_vec(),
            Err(error) => return Err(Self::failed(&path)(error)),
        };
        let (kept, whole) = decode(&bytes)?;
        bytes.truncate(usize::try_from(whole).unwrap_or(usize::MAX));
        let next = kept.last().map_or(0, |change| change.id().seq);
        for change in changes.iter().filter(|change| change.id().seq > next) {
            bytes.extend_from_slice(&change.encode());
        }
        write_bytes(&path, &bytes)
    }

    /// Completes moves apart cut short by a crash: a chain whose file
    /// still holds the first change kept apart (the same change) past its
    /// admitted mark in `marks` is cut back before it. A move apart only
    /// ever takes what is past the mark, so a change at or below it held
    /// in both is admitted work that a merged bundle also carried (or the
    /// share admitted since), never a move to complete. The chains so
    /// completed.
    ///
    /// # Errors
    ///
    /// A file cannot be read or written.
    pub(crate) fn complete_moves(
        &mut self,
        marks: &BTreeMap<ChainId, (u64, ChangeHash)>,
    ) -> Result<Vec<ChainId>, String> {
        let mut completed = Vec::new();
        for (chain, read) in self.read_apart()? {
            let Read::Changes(apart) = read else {
                continue;
            };
            let admitted = marks.get(&chain).map_or(0, |(seq, _)| *seq);
            let path = self.path("chains", chain);
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(Self::failed(&path)(error)),
            };
            let Ok((held, _)) = decode(&bytes) else {
                continue;
            };
            let first = apart.iter().find(|change| {
                change.id().seq > admitted
                    && held
                        .iter()
                        .any(|held| held.id() == change.id() && held.hash() == change.hash())
            });
            if let Some(first) = first {
                self.cut(chain, first.id().seq)?;
                completed.push(chain);
            }
        }
        Ok(completed)
    }

    /// The edits waiting in `import/` to be taken, with their files.
    pub(crate) fn imports(&self) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(self.dir.join("import")) else {
            return Vec::new();
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|e| e == "toml"))
            .collect();
        files.sort();
        files
    }
}

/// Flushes directory `dir` (on Unix; elsewhere the rename or creation
/// itself is what the platform guarantees), so that what was named,
/// made or removed in it stays.
///
/// # Errors
///
/// The directory cannot be opened or flushed: what was done in it may
/// not stay, and the write it ends has failed.
fn sync_dir(dir: &Path) -> Result<(), String> {
    if crash::step() != Step::Whole {
        // The entry made, its directory not flushed.
        return Err(CRASHED.to_owned());
    }
    #[cfg(unix)]
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("{}: {error}", dir.display()))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Makes directory `dir` if it is not there, its entry flushed in the
/// directory above it ([`sync_dir`]).
///
/// # Errors
///
/// It cannot be made, or its entry flushed.
fn make_dir(dir: &Path) -> Result<(), String> {
    if dir.is_dir() {
        return Ok(());
    }
    let parent = dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    make_dir(parent)?;
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => {}
        Err(error) => return Err(format!("{}: {error}", dir.display())),
    }
    sync_dir(parent)
}

/// Writes `bytes` to `path` crash-safely: data, rename, directory.
fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let failed = |error: io::Error| format!("{}: {error}", path.display());
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = Path::new(&temporary);
    let step = crash::step();
    if step == Step::Nothing {
        return Err(CRASHED.to_owned());
    }
    let mut file = File::create(temporary).map_err(failed)?;
    file.write_all(bytes).map_err(failed)?;
    file.sync_all().map_err(failed)?;
    drop(file);
    if step == Step::Part {
        // The data written, never renamed into place.
        return Err(CRASHED.to_owned());
    }
    fs::rename(temporary, path).map_err(failed)?;
    sync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
}

/// Whether reading a change failed because its bytes end first: a change
/// cut short by a crash.
fn short(why: &str) -> bool {
    matches!(why, "too short" | "a body cut short" | "no body's length")
}

/// The changes of a chain file's `bytes` and the length up to its last
/// whole change; a change cut short at the end dropped.
///
/// # Errors
///
/// It is no chain's file, or a change in it does not read: the whole file
/// does not.
pub(crate) fn decode(bytes: &[u8]) -> Result<(Vec<SignedChange>, u64), String> {
    decode_most(bytes, usize::MAX).map_err(|why| match why {
        Decoded::Unreadable(why) => why,
        Decoded::TooMany => "more changes than can be read".to_owned(),
    })
}

/// Why a chain file's bytes were not read ([`decode_most`]).
#[derive(Debug)]
pub(crate) enum Decoded {
    /// They hold more changes than were to be read.
    TooMany,
    /// They are no chain's file, or a change in them does not read: why.
    Unreadable(String),
}

/// [`decode`] of bytes from elsewhere (an exported project's), reading no
/// more than `most` changes.
///
/// # Errors
///
/// As [`decode`]; or they hold more than `most` changes, the rest not
/// read.
pub(crate) fn decode_most(bytes: &[u8], most: usize) -> Result<(Vec<SignedChange>, u64), Decoded> {
    let Some(mut rest) = bytes.strip_prefix(MAGIC) else {
        return if bytes.is_empty() {
            Ok((Vec::new(), 0))
        } else {
            Err(Decoded::Unreadable("not a chain's log".to_owned()))
        };
    };
    let mut changes = Vec::new();
    let total = bytes.len();
    let mut whole = MAGIC.len();
    while !rest.is_empty() {
        if changes.len() == most {
            return Err(Decoded::TooMany);
        }
        match SignedChange::take(rest) {
            Ok((change, after)) => {
                changes.push(change);
                rest = after;
                whole = total - rest.len();
            }
            Err(why) if short(why.0) => break,
            Err(why) => {
                return Err(Decoded::Unreadable(format!(
                    "the change at byte {whole} does not read: {why}"
                )));
            }
        }
    }
    Ok((changes, u64::try_from(whole).unwrap_or(u64::MAX)))
}

/// The offset in chain file `bytes` of its change numbered `from` (or of
/// its end, if none is from there on).
fn offset_of(bytes: &[u8], from: u64) -> Result<usize, String> {
    let Some(mut rest) = bytes.strip_prefix(MAGIC) else {
        return Ok(0);
    };
    let total = bytes.len();
    while !rest.is_empty() {
        let at = total - rest.len();
        match SignedChange::take(rest) {
            Ok((change, _)) if change.id().seq >= from => return Ok(at),
            Ok((_, after)) => rest = after,
            Err(why) if short(why.0) => return Ok(at),
            Err(why) => return Err(format!("the change at byte {at} does not read: {why}")),
        }
    }
    Ok(total)
}

/// `bytes` in lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The bytes `text` spells in hexadecimal.
pub(crate) fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// The `N` bytes `text` spells in hexadecimal.
fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    <[u8; N]>::try_from(hex_bytes(text)?.as_slice()).ok()
}

/// A binding as a line says it.
fn of_text(of: &Of) -> String {
    match of {
        Of::Binary { sha256, slice } => {
            format!("binary {} {}", hex(sha256), slice.as_deref().unwrap_or("-"))
        }
        Of::Set => "set".to_owned(),
    }
}

/// The binding line `text` says.
fn parse_of(text: &str) -> Option<Of> {
    if text == "set" {
        return Some(Of::Set);
    }
    let mut words = text.split(' ');
    (words.next()? == "binary").then_some(())?;
    let sha256 = parse_hex(words.next()?)?;
    let slice = match words.next()? {
        "-" => None,
        slice => Some(slice.to_owned()),
    };
    words
        .next()
        .is_none()
        .then_some(Of::Binary { sha256, slice })
}

/// A freeze as its line says it.
fn parse_freeze(line: &str) -> Option<(ChainId, (u64, FrozenBy))> {
    let mut words = line.split(' ');
    let chain = ChainId(parse_hex(words.next()?)?);
    let from = words
        .next()?
        .parse::<u64>()
        .ok()
        .filter(|&from| from >= 1)?;
    let by = match words.next()? {
        "cut" => FrozenBy::Cut {
            record: words.next()?.parse().ok()?,
            hash: parse_hex(words.next()?)?,
        },
        "fork" => FrozenBy::Fork,
        "never" => FrozenBy::Never,
        _ => return None,
    };
    words.next().is_none().then_some((chain, (from, by)))
}

/// Evidence as its line says it (a proof checked, a head of its chain).
fn parse_evidence(line: &str) -> Option<(ChainId, Evidence)> {
    let mut words = line.split(' ');
    let chain = ChainId(parse_hex(words.next()?)?);
    let kind = words.next()?;
    let bytes = hex_bytes(words.next()?)?;
    words.next().is_none().then_some(())?;
    let evidence = match kind {
        "proof" => Evidence::Proof(Box::new(
            ForkProof::parse(&bytes)
                .ok()
                .filter(|proof| proof.verify() && proof.chain() == chain)?,
        )),
        "refused" => Evidence::Refused(Box::new(
            SignedHead::parse(&bytes)
                .ok()
                .filter(|head| head.head.chain == chain)?,
        )),
        _ => return None,
    };
    Some((chain, evidence))
}

#[cfg(test)]
mod tests {
    use super::super::{
        ChainId, ChainOrigin, ChangeHash, Head, ProjectId, PublicKey, SignedChange, SignedHead,
        Signer,
    };
    use super::{MAGIC, decode, offset_of};

    fn change(seq: u64, body: &[u8]) -> SignedChange {
        let signer = Signer::from_seed(&[1; 32]);
        let origin = ChainOrigin {
            author: signer.public(),
            project: ProjectId([2; 16]),
            salt: [3; 16],
        };
        let head = Head {
            chain: origin.chain(),
            seq,
            prev: ChangeHash::ZERO,
            body: [0; 32],
            origin: (seq == 1).then_some(origin),
        };
        SignedChange {
            head: SignedHead::sign(head, &signer),
            body: body.to_vec(),
        }
    }

    #[test]
    fn a_change_cut_short_is_not_whole_and_a_bad_one_spoils_the_file() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&change(1, b"start").encode());
        let one = bytes.len();
        bytes.extend_from_slice(&change(2, b"edit").encode());
        let (changes, whole) = decode(&bytes).unwrap();
        assert_eq!((changes.len(), whole), (2, bytes.len() as u64));
        assert_eq!(offset_of(&bytes, 2).unwrap(), one);
        // Cut short by a crash: the whole changes read.
        let torn = &bytes[..bytes.len() - 2];
        let (changes, whole) = decode(torn).unwrap();
        assert_eq!((changes.len(), whole), (1, one as u64));
        // A change that does not read (a number 0) spoils the file.
        let mut bad = bytes.clone();
        bad[one + 16..one + 24].copy_from_slice(&0u64.to_be_bytes());
        assert!(decode(&bad).is_err());
        assert!(decode(b"not a log").is_err());
        let _ = (ChainId([0; 16]), PublicKey([0; 32]));
    }
}
