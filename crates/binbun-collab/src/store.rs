//! What a peer keeps of a shared project beside the project's own files,
//! in `<project>/collab/<project id>/`:
//!
//! - `membership.log`, its membership chain: `"binbun membership 1\n"`,
//!   then per record a LEB128 length and the record's postcard, each
//!   appended and synced as it is taken.
//! - `intent`, while a record is being taken (sync §4.3): the record
//!   signed and the freezes it causes ([`Intent`]), in the journal's
//!   format ([`journal::Intent`]: the journal writes its freezes to its
//!   log before reading it, with or without collaboration), written
//!   beside its place, synced and renamed into it, the directory synced,
//!   before anything of the record is written, and removed once all of it
//!   is. One found at open is carried out again before anything else.
//!
//! Every directory an entry is made, renamed or removed in is synced
//! before the write counts as done (on Unix; elsewhere the platform's
//! rename is what is relied on).
//!
//! The epochs' keys are not kept: the chain holds them wrapped to each
//! member.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use binbun_bounded::{self as bounded, Map};
use binbun_session::journal::{self, ChainId, ProjectId};

use crate::Error;
use crate::membership::{MAX_RECORD, SignedRecord};

/// What the chain's file starts with.
const MAGIC: &[u8] = b"binbun membership 1\n";

/// The most chains an intent freezes.
const MAX_FREEZES: usize = 1 << 20;

/// The most bytes of a record's frame in the chain's file: its length,
/// its postcard.
const MAX_FRAME: usize = MAX_RECORD + 128;

/// A membership record being taken: the record signed and the freezes it
/// causes, per chain from which change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Intent {
    /// The share's genesis.
    pub(crate) genesis: [u8; 32],
    /// The record.
    pub(crate) record: SignedRecord,
    /// Its number in the chain.
    pub(crate) seq: u64,
    /// The freezes it causes.
    pub(crate) freezes: Map<ChainId, u64, MAX_FREEZES>,
}

impl Intent {
    /// `record`, number `seq` of the chain of genesis `genesis`, causing
    /// `freezes`.
    ///
    /// # Errors
    ///
    /// More than [`MAX_FREEZES`] freezes.
    pub(crate) fn new(
        genesis: [u8; 32],
        record: SignedRecord,
        seq: u64,
        freezes: BTreeMap<ChainId, u64>,
    ) -> Result<Self, Error> {
        Ok(Self {
            genesis,
            record,
            seq,
            freezes: Map::try_from(freezes)?,
        })
    }

    /// It as its file holds it.
    fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(journal::Intent {
            genesis: self.genesis,
            record: bounded::encode(&self.record, MAX_FRAME)?,
            seq: self.seq,
            hash: *blake3::hash(&self.record.bytes).as_bytes(),
            freezes: self
                .freezes
                .iter()
                .map(|(chain, from)| (*chain, *from))
                .collect(),
        }
        .encode())
    }

    /// The intent its file's `bytes` hold.
    fn decode(bytes: &[u8]) -> Option<Self> {
        let intent = journal::Intent::decode(bytes).ok()?;
        let record: SignedRecord = bounded::decode(&intent.record).ok()?;
        (*blake3::hash(&record.bytes).as_bytes() == intent.hash).then_some(())?;
        Self::new(intent.genesis, record, intent.seq, intent.freezes).ok()
    }
}

/// What is kept of a shared project: its chain, and the intent of a record
/// being taken if one is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Kept {
    /// The chain's records, in order.
    pub(crate) records: Vec<SignedRecord>,
    /// The record being taken, if any.
    pub(crate) intent: Option<Intent>,
}

/// Where a project's membership chain is kept.
#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
    file: PathBuf,
    intent: PathBuf,
}

impl Store {
    /// The chain of shared project `project` in the project directory
    /// `dir`.
    pub fn new(dir: &Path, project: ProjectId) -> Self {
        let dir = dir.join("collab").join(project.to_string());
        Self {
            file: dir.join("membership.log"),
            intent: dir.join("intent"),
            dir,
        }
    }

    /// The shares kept in the project directory `dir`: each
    /// `collab/<project id>/` with a chain or an intent in it.
    pub(crate) fn kept_in(dir: &Path) -> Vec<(ProjectId, Self)> {
        let mut found: Vec<(ProjectId, Self)> = fs::read_dir(dir.join("collab"))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let bytes = data_encoding::HEXLOWER.decode(name.as_bytes()).ok()?;
                let project = ProjectId(bytes.try_into().ok()?);
                let store = Self::new(dir, project);
                (store.file.exists() || store.intent.exists()).then_some((project, store))
            })
            .collect();
        found.sort_by_key(|(project, _)| *project);
        found
    }

    /// What is kept (nothing if there are no files). A last record of the
    /// chain written in part is left out if an intent is kept (the intent
    /// holds it; it is written again), and refused if not.
    ///
    /// # Errors
    ///
    /// A file cannot be read or is not one.
    pub(crate) fn load(&self) -> Result<Kept, Error> {
        let intent = self.intent()?;
        let bytes = match fs::read(&self.file) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(failed(&self.file, &error)),
        };
        let bad = || Error::new(format!("{}: not a membership log", self.file.display()));
        let mut records = Vec::new();
        let mut rest = match bytes.strip_prefix(MAGIC) {
            Some(rest) => rest,
            // Created, its first record not written whole.
            None if intent.is_some() && MAGIC.starts_with(&bytes) => &[],
            None if bytes.is_empty() => &[],
            None => return Err(bad()),
        };
        while !rest.is_empty() {
            let Some((record, after)) = frame(rest) else {
                if intent.is_some() {
                    break;
                }
                return Err(bad());
            };
            records.push(bounded::decode(record).map_err(|_| bad())?);
            rest = after;
        }
        Ok(Kept { records, intent })
    }

    /// The intent kept, if any.
    ///
    /// # Errors
    ///
    /// Its file cannot be read or is not one.
    pub(crate) fn intent(&self) -> Result<Option<Intent>, Error> {
        let bytes = match fs::read(&self.intent) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(failed(&self.intent, &error)),
        };
        let bad = || Error::new(format!("{}: not an intent", self.intent.display()));
        Intent::decode(&bytes).map(Some).ok_or_else(bad)
    }

    /// Keeps `intent`, synced, in place of none: written beside its place,
    /// synced, renamed into it, the directory synced.
    ///
    /// # Errors
    ///
    /// It cannot be written whole. A failure after the rename (the
    /// directory not synced) leaves it in place, perhaps not durably: the
    /// caller takes it as kept.
    pub(crate) fn write_intent(&self, intent: &Intent) -> Result<(), Error> {
        let bytes = intent.encode()?;
        make_dir(&self.dir)?;
        let temporary = self.dir.join("intent.tmp");
        let mut file = File::create(&temporary).map_err(|error| failed(&temporary, &error))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| failed(&temporary, &error))?;
        fs::rename(&temporary, &self.intent).map_err(|error| failed(&self.intent, &error))?;
        sync_dir(&self.dir)
    }

    /// Removes the intent kept, if any, the directory synced.
    ///
    /// # Errors
    ///
    /// It cannot be removed.
    pub(crate) fn remove_intent(&self) -> Result<(), Error> {
        match fs::remove_file(&self.intent) {
            Ok(()) => sync_dir(&self.dir),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(failed(&self.intent, &error)),
        }
    }

    /// Appends `record` to the chain kept, whose records before it are
    /// `before`, and syncs it: whatever the file holds past them (a record
    /// written in part, or this one already) is written over, so doing it
    /// again does the same.
    ///
    /// # Errors
    ///
    /// The file holds fewer records than `before`, or cannot be written.
    pub(crate) fn append(
        &self,
        before: &[SignedRecord],
        record: &SignedRecord,
    ) -> Result<(), Error> {
        let at_file = |error: io::Error| failed(&self.file, &error);
        let mut length = MAGIC.len() as u64;
        for kept in before {
            length += framed_len(kept)?;
        }
        let frame = framed(record)?;
        make_dir(&self.dir)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.file)
            .map_err(at_file)?;
        if before.is_empty() {
            file.set_len(0)
                .and_then(|()| file.write_all(MAGIC))
                .map_err(at_file)?;
        } else if file.metadata().map_err(at_file)?.len() < length {
            return Err(Error::new(format!(
                "{}: shorter than the chain taken",
                self.file.display()
            )));
        }
        file.set_len(length)
            .and_then(|()| file.seek(SeekFrom::Start(length)))
            .and_then(|_| file.write_all(&frame))
            .and_then(|()| file.sync_all())
            .map_err(at_file)?;
        if before.is_empty() {
            sync_dir(&self.dir)?;
        }
        Ok(())
    }
}

/// Failures of directory syncs injected by tests: while set on a thread,
/// every directory sync of it fails, after what it ends was done.
#[cfg(test)]
pub(crate) mod failing {
    use std::cell::Cell;

    thread_local! {
        static SYNCS: Cell<bool> = const { Cell::new(false) };
    }

    /// Directory syncs of this thread fail from now (`true`) or not.
    pub(crate) fn syncs(fail: bool) {
        SYNCS.set(fail);
    }

    /// Whether they fail.
    pub(super) fn now() -> bool {
        SYNCS.get()
    }
}

/// Syncs directory `dir`, so that what was named, made or removed in it
/// stays (on Unix; elsewhere the rename itself is what the platform
/// guarantees).
///
/// # Errors
///
/// It cannot be opened or synced: what was done in it may not stay.
fn sync_dir(dir: &Path) -> Result<(), Error> {
    #[cfg(test)]
    if failing::now() {
        return Err(Error::new(format!(
            "{}: not synced (failing, in a test)",
            dir.display()
        )));
    }
    #[cfg(unix)]
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| failed(dir, &error))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Makes directory `dir` if it is not there, its entry synced in the
/// directory above it, and that one's too if it is made.
///
/// # Errors
///
/// It cannot be made, or an entry synced.
fn make_dir(dir: &Path) -> Result<(), Error> {
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
        Err(error) => return Err(failed(dir, &error)),
    }
    sync_dir(parent)
}

/// An error of `path`'s.
fn failed(path: &Path, error: &io::Error) -> Error {
    Error::new(format!("{}: {error}", path.display()))
}

/// `record` as the chain's file holds it: its length, its postcard.
fn framed(record: &SignedRecord) -> Result<Vec<u8>, Error> {
    let encoded = bounded::encode(record, MAX_FRAME)?;
    let length =
        u32::try_from(encoded.len()).map_err(|_| Error::new("a membership record too large"))?;
    let mut frame = bounded::encode(&length, 8)?;
    frame.extend(encoded);
    Ok(frame)
}

/// The bytes of [`framed`]`(record)`, counted without writing them.
fn framed_len(record: &SignedRecord) -> Result<u64, Error> {
    let size = bounded::size(record, MAX_FRAME)?;
    let length = u32::try_from(size).map_err(|_| Error::new("a membership record too large"))?;
    Ok((bounded::size(&length, 8)? + size) as u64)
}

/// The record at the start of `bytes`, framed, and the bytes after it;
/// `None` if they do not start with one whole.
fn frame(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, after) = bounded::take::<u32>(bytes).ok()?;
    after.split_at_checked(usize::try_from(length).ok()?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    use binbun_bounded::Bytes;
    use binbun_session::journal::{ChainId, ProjectId};
    use ed25519_dalek::Signature;

    use super::{Intent, Store, failing, framed};
    use crate::membership::SignedRecord;

    /// Record `n`, as the store sees it (it checks no signature).
    fn record(n: u8) -> SignedRecord {
        SignedRecord {
            bytes: Bytes::try_from(vec![n; 300]).unwrap(),
            sig: Signature::from_bytes(&[n; 64]),
        }
    }

    #[test]
    fn a_record_written_in_part_is_left_to_its_intent_and_refused_without_one() {
        let dir = std::env::temp_dir().join(format!("binbun-store-torn-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::new(&dir, ProjectId([1; 16]));
        let (one, two, three) = (record(1), record(2), record(3));
        store.append(&[], &one).unwrap();
        store.append(std::slice::from_ref(&one), &two).unwrap();
        // The third written in part, as a crash leaves it.
        let frame = framed(&three).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&store.file)
            .unwrap()
            .write_all(&frame[..frame.len() / 2])
            .unwrap();
        assert!(store.load().is_err());
        let freezes = BTreeMap::from([(ChainId([4; 16]), 2)]);
        let intent = Intent::new([5; 32], three.clone(), 3, freezes).unwrap();
        store.write_intent(&intent).unwrap();
        let kept = store.load().unwrap();
        assert_eq!(kept.records, [one.clone(), two.clone()]);
        assert_eq!(kept.intent, Some(intent));
        // Written again over the part, and again: the same file.
        let before = [one, two];
        store.append(&before, &three).unwrap();
        let whole = fs::read(&store.file).unwrap();
        store.append(&before, &three).unwrap();
        assert_eq!(fs::read(&store.file).unwrap(), whole);
        store.remove_intent().unwrap();
        let kept = store.load().unwrap();
        assert_eq!(kept.records.len(), 3);
        assert_eq!(kept.intent, None);
        // Fewer records on file than taken: refused, never padded.
        assert!(
            store
                .append(&[record(1), record(2), record(3), record(4)], &record(5))
                .is_err()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_sync_that_fails_fails_the_write_it_ends() {
        let dir = std::env::temp_dir().join(format!("binbun-store-sync-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::new(&dir, ProjectId([1; 16]));
        fs::create_dir_all(&store.dir).unwrap();
        let intent = Intent::new([5; 32], record(1), 1, BTreeMap::new()).unwrap();
        failing::syncs(true);
        let written = store.write_intent(&intent);
        let appended = store.append(&[], &record(1));
        failing::syncs(false);
        assert!(written.is_err());
        assert!(appended.is_err());
        // Renamed into place before the sync failed: it may be kept.
        assert_eq!(store.intent().unwrap(), Some(intent));
        store.remove_intent().unwrap();
        failing::syncs(true);
        let _ = store.write_intent(&Intent::new([5; 32], record(2), 2, BTreeMap::new()).unwrap());
        let removed = store.remove_intent();
        failing::syncs(false);
        assert!(removed.is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
