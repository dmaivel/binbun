//! Where a binary's own files live: its project, one directory per binary
//! in binbun's data folder ([`root`]: `projects`,
//! [`binbun_paths::Place::Projects`]), named by the binary's
//! contents ([`Key`]: `<sha256 hex>-<file name>`). The same bytes find the
//! same project wherever the file is (moved, renamed, a copy: [`locate`]
//! looks a project up by the hash alone); changed bytes, a new one. A
//! [`Project`] holds the edits (`project.toml`), the hex view's overlays
//! (`overlays.toml`), the Pathfinder's question (`pathfinder.toml`), the
//! window's layout (`layout.toml`), the example states (`states/`) and
//! this install's private bookmarks (`private.toml`, local only: never
//! exported).
//!
//! A universal Mach-O file holds an image per architecture; the project
//! is the opened slice's ([`crate::Options::arch`]), keyed by the slice's
//! bytes alone (what `lipo -thin` extracts, which opens the same project),
//! so each slice has its own.
//!
//! A binary may also have a project per share it was joined in (a
//! share's journal belongs to one share, and a joiner's lives apart from
//! their private work): `<sha256 hex>-<file name>@<share>`
//! ([`Key::share_dir_name`], [`share_id`]). The owner's share is their
//! own project, shared in place. [`locate`] opens the share's when one is
//! named, else the one project there is for the bytes, else the one used
//! last, and says which ([`Located`]).
//!
//! Export and import ([`export`], [`Bundle`], [`import`]): a project as
//! one portable TOML file (`<name>.binbun`) recording the binary's SHA-256
//! and file name and holding every file of the project as text (the log's
//! as base64) but a share's (`collab/`): an imported project starts
//! unshared. Importing installs it here under its hash, never replacing a
//! project with edits unless asked to; a project replaced keeps its own
//! shares of the project imported.
//!
//! ```no_run
//! use binbun_session::project::{self, Key};
//!
//! let bytes = std::fs::read("/usr/bin/bash")?;
//! let key = Key::new(&bytes, "bash");
//! let root = project::root().expect("a home");
//! let located = project::locate(&root, &key, &project::Choice::Any)?;
//! println!("{}", located.project.edits().display());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::{self, Write as _};
use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::edits::Edits;
use crate::identity::Identity;
use crate::journal::{self, Applied, Of, SignedChange};

/// The extension of an exported project ([`export`]).
pub const EXTENSION: &str = "binbun";

/// The edits' file in a project.
const EDITS: &str = "project.toml";
/// This install's private bookmarks' file in a project: never exported.
const PRIVATE: &str = "private.toml";
/// The hex view's overlays' file in a project.
const OVERLAYS: &str = "overlays.toml";
/// The Pathfinder's question's file in a project.
const PATHFINDER: &str = "pathfinder.toml";
/// The window's layout's file in a project.
const LAYOUT: &str = "layout.toml";
/// The example states' directory in a project.
const STATES: &str = "states";

/// The version of an exported project's format, the one read and written.
const FORMAT: u32 = 1;

/// The log's directory in a project, whose files are bytes.
const LOG: &str = "log/";

/// The project's files of text an exported project carries, beside its
/// example states (`states/<name>.toml`).
const EXPORTED_TEXT: [&str; 4] = [EDITS, OVERLAYS, PATHFINDER, LAYOUT];

/// The log's files an exported project carries, beside its chains'
/// (`log/chains/<chain>.log`) and, of a log of no share, the edits waiting
/// to be taken (`log/import/<name>.toml`). Never this install's part in
/// a share (`share`, `admitted`, `local`, `grants`: a bundle carries no
/// marks, sync §4.5, and an imported project starts unshared), nor what
/// is kept apart (`apart/`, §14.6).
const EXPORTED_LOG: [&str; 5] = [
    "log/project",
    "log/bound",
    "log/projected",
    "log/frozen",
    "log/evidence",
];

/// The most bytes of an exported project's file read ([`Bundle::read`],
/// [`Bundle::parse`]): refused before it is read whole.
pub const MAX_BUNDLE: u64 = 256 << 20;

/// The most files in an exported project: a log's most chains
/// (65,536) and room for the project's other files.
const MAX_PARTS: usize = 1 << 17;

/// The most bytes of one file in an exported project, as written (its
/// text, or its base64).
const MAX_PART: usize = 64 << 20;

/// The most changes taken from an exported project's log ([`merge`]).
const MAX_MERGED: usize = 1 << 20;

/// The directory a shared project's share is kept in (`binbun-collab`:
/// per shared project `<project id>/` with its membership chain, sealed
/// blobs and offers and fetches, and the lock). It is this computer's
/// part in the share, not the project's: never exported nor imported,
/// and kept when an import replaces the project ([`import`]).
const COLLAB: &str = "collab";

/// What names a binary's project: the SHA-256 of the whole file and its
/// file name (for people; the hash alone finds the project).
/// Of a slice of a universal file, the hash is the slice's, the same in
/// every container holding those bytes; a key read from the file opened
/// also knows that file ([`Self::opened`]), which an export checks the
/// project's log against. Keys are equal by hash and name alone.
#[derive(Clone)]
pub struct Key {
    sha256: [u8; 32],
    name: String,
    /// The file the key was read from, as a log's chains name it (its
    /// whole SHA-256, the slice's architecture), if it is known.
    opened: Option<Of>,
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        (self.sha256, &self.name) == (other.sha256, &other.name)
    }
}

impl Eq for Key {}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.sha256.hash(state);
        self.name.hash(state);
    }
}

impl Key {
    /// The key of a file named `name` holding `bytes`. With the SHA
    /// extensions (x86-64's since 2016, every Apple Silicon) it takes
    /// about 0.45 ms a megabyte. What file it is of is not known
    /// ([`Self::opened`]); `bytes` may be a slice of one.
    pub fn new(bytes: &[u8], name: impl Into<String>) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
        let mut sha256 = [0; 32];
        sha256.copy_from_slice(digest.as_ref());
        Self {
            sha256,
            name: name.into(),
            opened: None,
        }
    }

    /// The same key, read from the file `opened` names (as a log's chains
    /// name a binary: the whole file's SHA-256, and the slice's
    /// architecture of a universal file).
    #[must_use]
    pub fn from_file(mut self, opened: Of) -> Self {
        self.opened = Some(opened);
        self
    }

    /// The file the key was read from, if it is known: the whole file's
    /// SHA-256, and the slice's architecture of a universal file.
    pub fn opened(&self) -> Option<&Of> {
        self.opened.as_ref()
    }

    /// The key of the file at `path`, named by its file name: of a
    /// universal Mach-O file, of the slice a session opens without
    /// [`crate::Options::arch`] ([`binbun_loader::select`]: this
    /// machine's instruction set's, else the first).
    ///
    /// # Errors
    ///
    /// It cannot be read.
    pub fn of_file(path: &Path) -> io::Result<Self> {
        Self::of_file_slice(path, None)
    }

    /// The key of the file at `path`, named by its file name: of a
    /// universal Mach-O file, of its slice of architecture `arch`
    /// ([`crate::Options::arch`]; `None`: as [`Self::of_file`]); any other
    /// file whole, whatever `arch` says.
    ///
    /// # Errors
    ///
    /// It cannot be read; it is a universal file with no slice of `arch`.
    pub fn of_file_slice(path: &Path, arch: Option<&str>) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        let (image, slice) = match binbun_loader::select(&bytes, arch) {
            Ok((image, slice)) => (image, slice.map(|slice| slice.arch)),
            Err(error) if arch.is_some() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                ));
            }
            Err(_) => (bytes.as_slice(), None),
        };
        let key = Self::new(image, file_name(path));
        let sha256 = match slice {
            None => key.sha256,
            Some(_) => Self::new(&bytes, "").sha256,
        };
        Ok(key.from_file(Of::Binary { sha256, slice }))
    }

    /// The file's SHA-256.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// The file's SHA-256 in lower-case hexadecimal.
    pub fn hex(&self) -> String {
        let mut text = String::with_capacity(64);
        for byte in self.sha256 {
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    /// The file's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The same bytes named `name` (a share's binary, by the name its
    /// offer gives rather than the one a fetch was saved under): the name
    /// is made safe as a path component where it names a directory.
    #[must_use]
    pub fn renamed(&self, name: impl Into<String>) -> Self {
        Self {
            sha256: self.sha256,
            name: name.into(),
            opened: self.opened.clone(),
        }
    }

    /// The name of its project's directory: `<sha256 hex>-<file name>`,
    /// the name made safe as one path component.
    pub fn dir_name(&self) -> String {
        format!("{}-{}", self.hex(), component(&self.name))
    }

    /// The name of the project directory of its share whose genesis (the
    /// hash of the share's first membership record) is `genesis`: a
    /// joiner's project for the share, `<sha256 hex>-<file name>@<share>`,
    /// the share named by [`share_id`].
    pub fn share_dir_name(&self, genesis: &[u8; 32]) -> String {
        format!("{}@{}", self.dir_name(), share_id(genesis))
    }
}

/// The short name of the share whose genesis is `genesis`: its first
/// [`SHARE_ID`] hexadecimal digits, as a share's project directory and
/// `--share` name it.
pub fn share_id(genesis: &[u8; 32]) -> String {
    let mut text = String::with_capacity(SHARE_ID);
    for byte in genesis.iter().take(SHARE_ID / 2) {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The hexadecimal digits of a share's short name ([`share_id`]).
pub const SHARE_ID: usize = 16;

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({})", self.dir_name())
    }
}

/// `path`'s file name, as text (the whole path if it has none).
pub fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// `name` as one path component: separators, NUL and `@` (which marks a
/// share's project) as `_`, and never empty, `.` or `..`.
fn component(name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | '\0' | '@') {
                '_'
            } else {
                c
            }
        })
        .collect();
    match safe.as_str() {
        "" | "." | ".." => format!("_{safe}"),
        _ => safe,
    }
}

/// Where the projects are kept ([`binbun_paths::Place::Projects`]); `None`
/// without binbun's data directory.
pub fn root() -> Option<PathBuf> {
    binbun_paths::Place::Projects.path()
}

/// The names of a project's own files and directories.
const OWN: [&str; 8] = [
    EDITS, PRIVATE, OVERLAYS, PATHFINDER, LAYOUT, STATES, "log", COLLAB,
];

/// Whether a file named `name` would be taken for a project's, compared
/// without regard to case (as some volumes compare names): the name of
/// one of a project's own files or directories.
pub fn reserved(name: &str) -> bool {
    OWN.contains(&name.to_lowercase().as_str())
}

/// Whether a file of format `found` is of format `this`, the one this
/// binbun reads and writes.
///
/// # Errors
///
/// It is not: a later format is reported as one.
pub(crate) fn check_format(found: i64, this: u32) -> Result<(), String> {
    match found.cmp(&i64::from(this)) {
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Greater => Err(format!(
            "format {found} is newer than this binbun's ({this})"
        )),
        std::cmp::Ordering::Less => Err(format!(
            "format {found} is not a format of binbun's ({this})"
        )),
    }
}

/// Whether `dir` is a project's directory, wherever it is: it holds a
/// project's edits' file.
pub fn is_project(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(EDITS)).is_ok()
}

/// A binary's project: the directory its own files are kept in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Project {
    dir: PathBuf,
}

impl Project {
    /// The project in directory `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Its directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The edits' file ([`Edits::load`], [`Edits::save`]).
    pub fn edits(&self) -> PathBuf {
        self.dir.join(EDITS)
    }

    /// The hex view's overlays' file.
    pub fn overlays(&self) -> PathBuf {
        self.dir.join(OVERLAYS)
    }

    /// The Pathfinder's question's file.
    pub fn pathfinder(&self) -> PathBuf {
        self.dir.join(PATHFINDER)
    }

    /// The window's layout's file.
    pub fn layout(&self) -> PathBuf {
        self.dir.join(LAYOUT)
    }

    /// The example states' directory.
    pub fn states(&self) -> PathBuf {
        self.dir.join(STATES)
    }

    /// This install's private bookmarks' file
    /// ([`crate::Session::bookmark_private`]): a project file holding
    /// bookmarks only, local (never in the log, never exported).
    pub fn private(&self) -> PathBuf {
        self.dir.join(PRIVATE)
    }

    /// Whether it holds the user's work, what an import asks before
    /// replacing: edits (a project file that is not empty, or one that
    /// cannot be read), overlays, example states, private bookmarks (or
    /// their undo steps), or a share's journal (whatever it projects). A
    /// layout and a Pathfinder question alone are not.
    pub fn has_edits(&self) -> bool {
        let edits = Edits::load(&self.edits()).map_or(true, |edits| !edits.is_empty())
            || journal::private_holds(&self.private());
        let states = fs::read_dir(self.states()).is_ok_and(|mut entries| entries.next().is_some());
        let shared = ["share", "admitted"]
            .iter()
            .any(|name| fs::symlink_metadata(self.dir.join("log").join(name)).is_ok());
        edits || self.overlays().exists() || states || shared
    }

    /// The values of its edits that `identity` may bring into a share
    /// ([`crate::Session::bring`]), read from its log alone, with no
    /// session or analysis: every edit's value shown, with who wrote it;
    /// none for a project with no log. Opening the log completes what a
    /// crash left (a change past its mark cut off), so it is read held for
    /// writing ([`Self::hold`]): never beside the session writing it. The
    /// project of a session open in this process is read through that
    /// session ([`crate::Session::bringable_from`]).
    ///
    /// # Errors
    ///
    /// The project is held for writing elsewhere (as [`Self::hold`]); the
    /// log cannot be read, or says not what its chains are of.
    pub fn bringable(&self, identity: &Identity) -> Result<Vec<journal::Bringable>, String> {
        let store = journal::store::Store::new(self.dir.join("log"));
        if store.project()?.is_none() {
            return Ok(Vec::new());
        }
        let _held = self.hold()?;
        let of = store.bound()?.ok_or_else(|| {
            format!(
                "{}: the log says not what its chains are of",
                self.dir.display()
            )
        })?;
        let (_, journal) = journal::open(self, identity, of)?;
        Ok(journal.bringable())
    }

    /// The project held for writing by this process until what is
    /// returned is dropped: its lock file (`collab/lock`) locked, so that
    /// no second process (and no second session of this one) writes its
    /// journal meanwhile. The lock is the operating system's, on the open
    /// file, not anything written in it: it goes with the process however
    /// the process ends, and a file left behind holds nothing. Reading the
    /// project's files ([`export`]) takes no lock and is not refused by
    /// one; opening its journal to read it ([`Self::bringable`]) does.
    ///
    /// Held by this process already, it is refused at once, unless the
    /// session holding it is closing ([`crate::Session::close`], its worker
    /// finishing): then it is waited for, at most ten seconds. Held by
    /// another process, it is refused at once.
    ///
    /// # Errors
    ///
    /// The project is held for writing elsewhere (or still, ten seconds
    /// on, by a session closing); the lock file cannot be made.
    pub fn hold(&self) -> Result<Held, String> {
        let elsewhere = || {
            format!(
                "the project {} is open elsewhere (another binbun, window or session): close \
                 it there first",
                self.dir.display()
            )
        };
        let here = || {
            format!(
                "the project {} is already open in this binbun (another window, script or \
                 session): close it there first",
                self.dir.display()
            )
        };
        let dir = self.dir.join(COLLAB);
        fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        let path = dir.join("lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let path =
            fs::canonicalize(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let deadline = Instant::now() + HOLD_WAIT;
        let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some(closing) = held.get(&path) {
            if !closing.load(Ordering::Relaxed) {
                return Err(here());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(here());
            }
            held = LET_GO
                .wait_timeout(held, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        match file.try_lock() {
            Ok(()) => {
                let closing = Arc::new(AtomicBool::new(false));
                held.insert(path.clone(), Arc::clone(&closing));
                Ok(Held {
                    lock: file,
                    path,
                    closing,
                })
            }
            Err(fs::TryLockError::WouldBlock) => Err(elsewhere()),
            Err(fs::TryLockError::Error(error)) => Err(format!("{}: {error}", path.display())),
        }
    }
}

/// How long [`Project::hold`] waits for a project a session of this
/// process holds while it closes.
const HOLD_WAIT: Duration = Duration::from_secs(10);

/// The lock files this process holds ([`Held`]), by path, each with
/// whether the session holding it is closing ([`Held::close`]).
static HELD: Mutex<BTreeMap<PathBuf, Arc<AtomicBool>>> = Mutex::new(BTreeMap::new());

/// Told when this process lets go of a lock file.
static LET_GO: Condvar = Condvar::new();

/// A project held for writing ([`Project::hold`]), until dropped.
#[derive(Debug)]
pub struct Held {
    /// The lock file, locked.
    lock: File,
    /// Its path, as [`HELD`] has it.
    path: PathBuf,
    /// Whether the session holding it is closing.
    closing: Arc<AtomicBool>,
}

impl Held {
    /// Marks it as let go of soon: the session holding it is closing, its
    /// worker finishing. A [`Project::hold`] of this process waits for it
    /// from now on, rather than being refused.
    pub(crate) fn close(&self) {
        self.closing.store(true, Ordering::Relaxed);
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        // Unlocked before it is let go of here: whoever waits takes it.
        let _ = self.lock.unlock();
        HELD.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.path);
        LET_GO.notify_all();
    }
}

/// Which of a binary's projects to open: a binary may have a private one
/// and one per share it is in (`<sha256>-<name>@<share>`).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Choice {
    /// The one there is, else the one used last.
    #[default]
    Any,
    /// The private one (of no share).
    Private,
    /// The one of the share whose short name starts with this
    /// ([`share_id`]).
    Share(String),
}

/// How [`locate`] chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chosen {
    /// None was there: a new one, not made yet.
    New,
    /// The only one there.
    Only,
    /// The one asked for.
    Asked,
    /// Of several, the one used last (its files changed last).
    LastUsed,
}

/// What [`locate`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located {
    /// The project.
    pub project: Project,
    /// How it was chosen.
    pub chosen: Chosen,
    /// Every project there for the same bytes, used last first.
    pub all: Vec<Project>,
}

/// The project of the binary `key` in the projects directory `root`, as
/// `choice` says: the share's when one is named (by the start of its
/// short name); the private one when asked; else the one there for its
/// SHA-256, under whatever file name it was made for (a file moved,
/// renamed or copied keeps its project), or of several the one used last
/// (its files changed last), said so ([`Chosen::LastUsed`]). With none,
/// a new private one (not made yet) named by `key`.
///
/// # Errors
///
/// The share named has no project here for these bytes, or more than one.
pub fn locate(root: &Path, key: &Key, choice: &Choice) -> Result<Located, String> {
    let found = existing(root, &key.hex());
    let mut all: Vec<(std::time::SystemTime, String)> = found
        .iter()
        .map(|name| (used(&root.join(name)), name.clone()))
        .collect();
    all.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let projects: Vec<Project> = all
        .iter()
        .map(|(_, name)| Project::new(root.join(name)))
        .collect();
    let own = key.dir_name();
    let located = |name: &str, chosen: Chosen| Located {
        project: Project::new(root.join(name)),
        chosen,
        all: projects.clone(),
    };
    match choice {
        Choice::Share(id) => {
            let id = id.to_ascii_lowercase();
            let shares: Vec<&String> = found
                .iter()
                .filter(|name| {
                    name.rsplit_once('@')
                        .is_some_and(|(_, share)| !id.is_empty() && share.starts_with(&id))
                })
                .collect();
            match shares.as_slice() {
                [name] => Ok(located(name, Chosen::Asked)),
                [] => Err(format!("no project of share {id} for this binary")),
                _ => Err(format!(
                    "share {id} names more than one project: give more of it"
                )),
            }
        }
        Choice::Private => {
            let project = private(root, &key.hex(), &key.name);
            let chosen = if project.dir().exists() {
                Chosen::Asked
            } else {
                Chosen::New
            };
            Ok(Located {
                project,
                chosen,
                all: projects,
            })
        }
        Choice::Any => Ok(match all.as_slice() {
            [] => located(&own, Chosen::New),
            [(_, name)] => located(name, Chosen::Only),
            [(_, name), ..] => located(name, Chosen::LastUsed),
        }),
    }
}

/// The private project (of no share) in `root` of the file whose SHA-256
/// is `hex` (lower-case hexadecimal) and whose name is `name`: the one
/// there under that name, else the first by name under another, else a
/// new one (not made yet) under that name.
fn private(root: &Path, hex: &str, name: &str) -> Project {
    let own = format!("{hex}-{}", component(name));
    let found: Vec<String> = existing(root, hex)
        .into_iter()
        .filter(|name| !name.contains('@'))
        .collect();
    let name = if found.contains(&own) {
        own
    } else {
        found.into_iter().next().unwrap_or(own)
    };
    Project::new(root.join(name))
}

/// When the project in `dir` was used last, as its files say: the latest
/// change of the directory, its edits, its layout or its log.
fn used(dir: &Path) -> std::time::SystemTime {
    [
        dir.to_path_buf(),
        dir.join(EDITS),
        dir.join(LAYOUT),
        dir.join("log"),
    ]
    .iter()
    .filter_map(|path| fs::metadata(path).and_then(|meta| meta.modified()).ok())
    .max()
    .unwrap_or(std::time::UNIX_EPOCH)
}

/// The project already in the projects directory `root` for the file
/// whose SHA-256 is `hex` (lower-case hexadecimal), under whatever file
/// name; the first by name of several.
pub fn find(root: &Path, hex: &str) -> Option<Project> {
    existing(root, hex)
        .into_iter()
        .next()
        .map(|name| Project::new(root.join(name)))
}

/// The names of the projects in `root` for the SHA-256 `hex`, sorted.
fn existing(root: &Path, hex: &str) -> Vec<String> {
    let prefix = format!("{hex}-");
    let mut found: Vec<String> = fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(&prefix))
        .collect();
    found.sort();
    found
}

/// A hidden directory beside `dir` for work on it (`.<name>.<what>`).
fn sibling(dir: &Path, what: &str) -> PathBuf {
    let name = dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    dir.with_file_name(format!(".{name}.{what}-{}", std::process::id()))
}

/// Writes `text` to `path` crash-safely: whole to a temporary file beside
/// it, flushed to the disk, renamed over it, and the directory's entry
/// flushed where the platform allows.
///
/// # Errors
///
/// The file cannot be written.
pub(crate) fn write_safely(path: &Path, text: &str) -> Result<(), String> {
    let failed = |error: io::Error| format!("{}: {error}", path.display());
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = Path::new(&temporary);
    let mut file = File::create(temporary).map_err(failed)?;
    file.write_all(text.as_bytes()).map_err(failed)?;
    file.sync_all().map_err(failed)?;
    drop(file);
    fs::rename(temporary, path).map_err(failed)?;
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Opening a directory to flush it works on Unix only; elsewhere the
    // rename itself is what the platform guarantees.
    #[cfg(unix)]
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

/// An exported project: the binary's SHA-256 and file name, and every
/// file of the project (its path in the project, `/`-separated, and its
/// text). As a file (`<name>.binbun`), TOML:
///
/// ```toml
/// format = 1
/// sha256 = "…"
/// name = "bash"
///
/// [[file]]
/// path = "project.toml"
/// text = '''
/// format = 1
/// …
/// '''
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    sha256: String,
    name: String,
    files: Vec<(String, String)>,
    /// The log's files (under `log/`), as bytes.
    logs: Vec<(String, Vec<u8>)>,
}

/// An exported project's file ([`Bundle`]).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    /// Its format's version ([`FORMAT`]).
    format: u32,
    /// The binary's SHA-256, lower-case hexadecimal.
    sha256: String,
    /// The binary's file name.
    name: String,
    /// The project's files.
    #[serde(default)]
    file: Vec<Part>,
}

/// One file of an exported project.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Part {
    /// Its path in the project, `/`-separated.
    path: String,
    /// Its text (a file of text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    /// Its bytes in base64 (a file of the log).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

impl Bundle {
    /// The binary's SHA-256, as bytes.
    ///
    /// # Errors
    ///
    /// It is not one.
    fn sha256_bytes(&self) -> Result<[u8; 32], String> {
        journal::store::hex_bytes(&self.sha256)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or_else(|| format!("not a SHA-256: {:?}", self.sha256))
    }

    /// The project `project` of the binary `key`, by path: the files an
    /// exported project carries and nothing else ([`exported`]); of a
    /// share's log, its admitted and pending changes only (sync §14.6).
    ///
    /// # Errors
    ///
    /// A file cannot be read, or is not text; the log is bound to a whole
    /// file other than `key`'s, or to a slice of a universal file other
    /// than the one `key` was read from, or not known to be the same
    /// ([`Key::opened`]).
    pub fn of(project: &Project, key: &Key) -> Result<Self, String> {
        let store = journal::store::Store::new(project.dir.join("log"));
        // A file of no slice is its key's bytes: its log's binding is
        // compared with them, not taken on the key's word. (A slice's key
        // is the slice's hash, the same in every container holding those
        // bytes: its binding is compared with the file the key was read
        // from, and refused if that is not known.)
        let other = || {
            format!(
                "{}: the project's log is of another binary than {}",
                project.dir.display(),
                key.name
            )
        };
        match store.bound()? {
            Some(Of::Binary {
                sha256,
                slice: None,
            }) if sha256 != key.sha256 => return Err(other()),
            Some(bound @ Of::Binary { slice: Some(_), .. }) => match &key.opened {
                Some(opened) if *opened == bound => {}
                Some(_) => return Err(other()),
                None => {
                    return Err(format!(
                        "{}: the project's log is of a slice of a universal file, and which \
                         file {} is is not known",
                        project.dir.display(),
                        key.name
                    ));
                }
            },
            Some(_) | None => {}
        }
        let (mut files, mut logs) = collect(project, &store)?;
        files.sort();
        logs.sort();
        Ok(Self {
            sha256: key.hex(),
            name: key.name.clone(),
            files,
            logs,
        })
    }

    /// The exported project in `text`.
    ///
    /// # Errors
    ///
    /// It is longer than [`MAX_BUNDLE`], not TOML, not this format (a
    /// later version, or none), its hash is not a SHA-256, a path leaves the
    /// project, it holds more than [`MAX_PARTS`] files or one of more
    /// than [`MAX_PART`] bytes, or its edits do not parse. A file it
    /// holds that an exported project does not carry ([`exported`]) is
    /// not taken.
    pub fn parse(text: &str) -> Result<Self, String> {
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_BUNDLE {
            return Err(too_long());
        }
        // Read once; its version first, as a later format's fields are not
        // this one's.
        let table: toml::Table = text
            .parse()
            .map_err(|error: toml::de::Error| error.to_string())?;
        let format = table
            .get("format")
            .ok_or("missing field `format`")?
            .as_integer()
            .ok_or("`format` is not a number")?;
        check_format(format, FORMAT)?;
        if table
            .get("file")
            .and_then(toml::Value::as_array)
            .is_some_and(|parts| parts.len() > MAX_PARTS)
        {
            return Err(format!("more than {MAX_PARTS} files"));
        }
        let file: BundleFile = table.try_into().map_err(|error| error.to_string())?;
        if file.sha256.len() != 64
            || !file
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!("not a SHA-256: {:?}", file.sha256));
        }
        // Each file's bytes, decoded, are no more than as written: what is
        // taken is no more than `text`, itself within [`MAX_BUNDLE`].
        let mut files = Vec::new();
        let mut logs = Vec::new();
        for part in file.file {
            if !inside(&part.path) {
                return Err(format!("not a path in a project: {:?}", part.path));
            }
            if part
                .text
                .as_ref()
                .or(part.data.as_ref())
                .map_or(0, String::len)
                > MAX_PART
            {
                return Err(format!("{}: more than {MAX_PART} bytes", part.path));
            }
            // Only what an export carries is taken: never a share's files,
            // marks or what is kept apart.
            if !exported(&part.path) {
                continue;
            }
            match (part.text, part.data) {
                (Some(text), None) if !part.path.starts_with(LOG) => {
                    if part.path == EDITS {
                        Edits::parse(&text).map_err(|error| format!("{EDITS}: {error}"))?;
                    }
                    files.push((part.path, text));
                }
                (None, Some(data)) if part.path.starts_with(LOG) => {
                    let bytes =
                        base64_decode(&data).ok_or_else(|| format!("{}: not base64", part.path))?;
                    logs.push((part.path, bytes));
                }
                _ => {
                    return Err(format!(
                        "{}: the log's files are data, the others text",
                        part.path
                    ));
                }
            }
        }
        Ok(Self {
            sha256: file.sha256,
            name: file.name,
            files,
            logs,
        })
    }

    /// The exported project in the file at `path`.
    ///
    /// # Errors
    ///
    /// As [`Bundle::parse`] (a file longer than [`MAX_BUNDLE`] refused
    /// before it is read), or the file cannot be read.
    pub fn read(path: &Path) -> Result<Self, String> {
        let failed = |error: io::Error| format!("{}: {error}", path.display());
        let file = File::open(path).map_err(failed)?;
        let length = file.metadata().map_err(failed)?.len();
        if length > MAX_BUNDLE {
            return Err(format!("{}: {}", path.display(), too_long()));
        }
        let mut text = String::with_capacity(usize::try_from(length).unwrap_or(0));
        // Read no further than the bound, should the file grow meanwhile.
        io::Read::read_to_string(&mut io::Read::take(file, MAX_BUNDLE + 1), &mut text)
            .map_err(failed)?;
        Self::parse(&text).map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Its text.
    ///
    /// # Errors
    ///
    /// It cannot be written as TOML.
    pub fn to_toml(&self) -> Result<String, String> {
        let texts = self.files.iter().map(|(path, text)| Part {
            path: path.clone(),
            text: Some(text.clone()),
            data: None,
        });
        let logs = self.logs.iter().map(|(path, bytes)| Part {
            path: path.clone(),
            text: None,
            data: Some(base64_encode(bytes)),
        });
        toml::to_string(&BundleFile {
            format: FORMAT,
            sha256: self.sha256.clone(),
            name: self.name.clone(),
            file: texts.chain(logs).collect(),
        })
        .map_err(|error| error.to_string())
    }

    /// The binary's SHA-256, lower-case hexadecimal.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The binary's file name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The project's files: each one's path in the project and text.
    pub fn files(&self) -> &[(String, String)] {
        &self.files
    }

    /// The log's files (`log/…`): each one's path in the project and
    /// bytes.
    pub fn logs(&self) -> &[(String, Vec<u8>)] {
        &self.logs
    }

    /// The project it is installed as in `root`: the one there for its
    /// hash of no share, else a new one ([`Choice::Private`]).
    pub fn project_in(&self, root: &Path) -> Project {
        private(root, &self.sha256, &self.name)
    }
}

/// Whether `path` names a file inside a project: relative, `/`-separated
/// plain names (no `.`, `..`, root or prefix).
fn inside(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && path.split('/').all(|part| {
            let mut components = Path::new(part).components();
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
        })
}

/// Why an exported project is not read: longer than [`MAX_BUNDLE`].
fn too_long() -> String {
    format!("longer than {} MiB: not read", MAX_BUNDLE >> 20)
}

/// Whether `path` (`/`-separated, in a project) names a file an exported
/// project carries: the project's files of text ([`EXPORTED_TEXT`]), its
/// example states (`states/<name>.toml`), the log's files
/// ([`EXPORTED_LOG`]), its chains (`log/chains/<chain>.log`) and the edits
/// waiting in it (`log/import/<name>.toml`). An allow-list: nothing else
/// of a project's directory (this install's part in a share, its private
/// bookmarks, what is kept apart, a lock, a write's leftovers) is
/// exported or imported.
fn exported(path: &str) -> bool {
    let named = |dir: &str, extension: &str| {
        path.strip_prefix(dir)
            .and_then(|name| name.strip_suffix(extension))
            .is_some_and(|stem| !stem.is_empty() && !stem.contains('/'))
    };
    let chain = path
        .strip_prefix("log/chains/")
        .and_then(|name| name.strip_suffix(".log"))
        .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    EXPORTED_TEXT.contains(&path)
        || EXPORTED_LOG.contains(&path)
        || chain
        || named("states/", ".toml")
        || named("log/import/", ".toml")
}

/// The bytes of the file at `path`, if there is one (a link followed
/// nowhere).
fn regular(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let failed = |error: io::Error| format!("{}: {error}", path.display());
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => fs::read(path).map(Some).map_err(failed),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(failed(error)),
    }
}

/// The names of the files in directory `dir` that are `exported` as
/// `prefix` + their name, sorted (none if it is not there).
fn listed(dir: &Path, prefix: &str) -> Result<Vec<String>, String> {
    let failed = |error: io::Error| format!("{}: {error}", dir.display());
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(failed(error)),
    };
    let mut names = Vec::new();
    for entry in entries {
        let name = entry.map_err(failed)?.file_name();
        if let Some(name) = name.to_str().map(|name| format!("{prefix}{name}"))
            && exported(&name)
        {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// A project's files of text (`/`-separated path, text) and its log's
/// (path, bytes), as an export carries them ([`collect`]).
type Collected = (Vec<(String, String)>, Vec<(String, Vec<u8>)>);

/// What of `project` an export carries ([`exported`]): its files of text
/// (`/`-separated path, text) and its log's (path, bytes), its chains as
/// `store` exports them (sync §14.6: of a share's log, its admitted and
/// pending changes).
///
/// # Errors
///
/// A file cannot be read, or is not text; a share's log lacks its marks.
fn collect(project: &Project, store: &journal::store::Store) -> Result<Collected, String> {
    let at = |path: &str| {
        path.split('/')
            .fold(project.dir.clone(), |dir, part| dir.join(part))
    };
    let mut texts: Vec<String> = EXPORTED_TEXT.iter().map(|&name| name.to_owned()).collect();
    texts.extend(listed(&project.states(), "states/")?);
    let mut files = Vec::new();
    for path in texts {
        if let Some(bytes) = regular(&at(&path))? {
            let text = String::from_utf8(bytes)
                .map_err(|_| format!("{}: not text", at(&path).display()))?;
            files.push((path, text));
        }
    }
    let mut paths: Vec<String> = EXPORTED_LOG.iter().map(|&name| name.to_owned()).collect();
    // Edits waiting to be taken are signed as this install's at the next
    // opening: of a share's log, they are no change of it yet.
    if store.genesis()?.is_none() {
        paths.extend(listed(&store.dir().join("import"), "log/import/")?);
    }
    let mut logs = Vec::new();
    for path in paths {
        if let Some(bytes) = regular(&at(&path))? {
            logs.push((path, bytes));
        }
    }
    for (chain, bytes) in store.exported()? {
        logs.push((format!("{LOG}chains/{chain}.log"), bytes));
    }
    Ok((files, logs))
}

/// Writes the project `project` of the binary `key` to `to` as one file
/// ([`Bundle`]), crash-safely.
///
/// # Errors
///
/// A file of the project cannot be read, or `to` cannot be written.
pub fn export(project: &Project, key: &Key, to: &Path) -> Result<(), String> {
    write_safely(to, &Bundle::of(project, key)?.to_toml()?)
}

/// What [`import`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Imported {
    /// The project was installed here.
    Installed(Project),
    /// A project with edits ([`Project::has_edits`]) is there already and
    /// replacing it was not asked for: nothing changed.
    Exists(Project),
}

/// Installs `bundle` in the projects directory `root` under its hash
/// ([`Bundle::project_in`]): written whole beside it, then renamed into
/// place. A project already there with edits is replaced only if
/// `replace`; one without is replaced. A project replaced keeps its part
/// in the shares of what `bundle`'s log takes changes of (`collab/`: the
/// lock, and each `<project id>/` of its own id or one merged), which
/// stay consistent with it since they hold no changes; the shares of
/// other projects go with the log replaced, which they shared.
///
/// # Errors
///
/// A file cannot be written, or the share's files cannot be moved into
/// the project installed (then nothing is replaced); the project there
/// is open elsewhere ([`Project::hold`]).
pub fn import(bundle: &Bundle, root: &Path, replace: bool) -> Result<Imported, String> {
    let project = bundle.project_in(root);
    if !replace && project.has_edits() {
        return Ok(Imported::Exists(project));
    }
    // Not replaced under a session writing it.
    let _held = if project.dir.exists() {
        Some(project.hold()?)
    } else {
        None
    };
    let failed = |path: &Path, error: io::Error| format!("{}: {error}", path.display());
    let partial = sibling(&project.dir, "importing");
    let _ = fs::remove_dir_all(&partial);
    fs::create_dir_all(&partial).map_err(|e| failed(&partial, e))?;
    let texts = bundle
        .files
        .iter()
        .map(|(path, text)| (path, text.as_bytes()));
    // Only what an export carries: [`Bundle::parse`] and [`Bundle::of`]
    // take nothing else.
    let logs = bundle
        .logs
        .iter()
        .map(|(path, bytes)| (path, bytes.as_slice()));
    for (path, bytes) in texts.chain(logs) {
        let to = path
            .split('/')
            .fold(partial.clone(), |dir, part| dir.join(part));
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).map_err(|e| failed(parent, e))?;
        }
        fs::write(&to, bytes).map_err(|e| failed(&to, e))?;
    }
    let old = sibling(&project.dir, "replaced");
    let replacing = project.dir.exists();
    // This computer's part in the shares kept, moved into the new
    // project before the swap (and back if the swap fails).
    let share = project.dir.join(COLLAB);
    let kept = if replacing {
        kept_shares(bundle, &share)?
    } else {
        Vec::new()
    };
    move_entries(&share, &partial.join(COLLAB), &kept)?;
    let restore = || {
        let _ = move_entries(&partial.join(COLLAB), &share, &kept);
    };
    if replacing {
        let _ = fs::remove_dir_all(&old);
        if let Err(error) = fs::rename(&project.dir, &old) {
            restore();
            return Err(failed(&project.dir, error));
        }
    }
    if let Err(error) = fs::rename(&partial, &project.dir) {
        if replacing {
            let _ = fs::rename(&old, &project.dir);
            restore();
        }
        return Err(failed(&project.dir, error));
    }
    if replacing {
        let _ = fs::remove_dir_all(&old);
    }
    Ok(Imported::Installed(project))
}

/// The entries of a project's `collab/` (`share`) an import of `bundle`
/// over it keeps: all but the shares (`<project id>/`) of logs other than
/// `bundle`'s (its id, in `log/project`).
fn kept_shares(bundle: &Bundle, share: &Path) -> Result<Vec<OsString>, String> {
    let failed = |path: &Path, error: io::Error| format!("{}: {error}", path.display());
    let entries = match fs::read_dir(share) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(failed(share, error)),
    };
    let mut taken = Vec::new();
    for (path, bytes) in &bundle.logs {
        if path == "log/project" {
            taken.extend(
                String::from_utf8_lossy(bytes)
                    .lines()
                    .map(|id| id.trim().to_owned()),
            );
        }
    }
    let mut kept = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| failed(share, e))?;
        let name = entry.file_name();
        let of_another = name.to_str().is_some_and(|name| {
            name.len() == 32
                && name.bytes().all(|b| b.is_ascii_hexdigit())
                && !taken.iter().any(|id| id.eq_ignore_ascii_case(name))
        });
        if !of_another {
            kept.push(name);
        }
    }
    Ok(kept)
}

/// Moves the entries `names` of the directory `from` into `to`, made if
/// need be: all, or (one failing) none, those moved moved back.
fn move_entries(from: &Path, to: &Path, names: &[OsString]) -> Result<(), String> {
    if names.is_empty() {
        return Ok(());
    }
    let failed = |path: &Path, error: io::Error| format!("{}: {error}", path.display());
    fs::create_dir_all(to).map_err(|e| failed(to, e))?;
    for (at, name) in names.iter().enumerate() {
        if let Err(error) = fs::rename(from.join(name), to.join(name)) {
            for name in names.iter().take(at) {
                let _ = fs::rename(to.join(name), from.join(name));
            }
            return Err(failed(&from.join(name), error));
        }
    }
    Ok(())
}

/// What [`merge`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Merged {
    /// The project merged into (or installed, if there was none).
    pub project: Project,
    /// What taking the exported project's changes came to.
    pub applied: Applied,
}

/// Merges `bundle` into the project for its binary in `root`,
/// `identity` writing what changes are made: the union of their chains
/// (every change of the exported project's log, checked, kept in this
/// one's; a key both changed a conflict, shown, nothing lost). An exported
/// project without a log has its edits taken as a change of the importer's
/// made beside this project's. Into a share's journal, the chains of the
/// exported project are kept apart, but for what it holds already (sync
/// §4.5): nothing it holds is cut or replaced. With no project there, it
/// is installed ([`import`]).
///
/// # Errors
///
/// The project or a file cannot be read or written; the exported
/// project's log holds more than [`MAX_MERGED`] changes; it has no log
/// and the project is a share's (its edits would be published as the
/// importer's: a Bring is how values enter a share); the project is open
/// elsewhere ([`Project::hold`]).
pub fn merge(bundle: &Bundle, root: &Path, identity: &Identity) -> Result<Merged, String> {
    let project = bundle.project_in(root);
    if !project.dir.exists() {
        import(bundle, root, false)?;
        return Ok(Merged {
            project,
            applied: Applied::default(),
        });
    }
    let of = Of::Binary {
        sha256: bundle.sha256_bytes()?,
        slice: None,
    };
    let _held = project.hold()?;
    let (mut edits, mut journal) = journal::open(&project, identity, of)?;
    let applied = if bundle.logs.is_empty() {
        if journal.genesis().is_some() {
            return Err(format!(
                "{}: a share's project takes an exported project's edits by a Bring, not \
                 a merge",
                project.dir.display()
            ));
        }
        let theirs = bundle
            .files
            .iter()
            .find(|(path, _)| path == EDITS)
            .map(|(_, text)| Edits::parse(text))
            .transpose()?
            .unwrap_or_default();
        journal.import(
            &theirs,
            &format!("{}.{EXTENSION}", bundle.name),
            true,
            &mut edits,
        )?;
        Applied::default()
    } else {
        let mut changes: Vec<SignedChange> = Vec::new();
        let chains = bundle
            .logs
            .iter()
            .filter(|(path, _)| path.starts_with("log/chains/"));
        for (_, bytes) in chains {
            let most = MAX_MERGED - changes.len();
            match journal::store::decode_most(bytes, most) {
                Ok((taken, _)) => changes.extend(taken),
                Err(journal::store::Decoded::TooMany) => {
                    return Err(format!(
                        "the exported project's log holds more than {MAX_MERGED} changes"
                    ));
                }
                // A chain's file that does not read is none of its chains.
                Err(journal::store::Decoded::Unreadable(_)) => {}
            }
        }
        let mut touched = BTreeSet::new();
        let applied = journal.merge_bundle(changes, &mut touched)?;
        journal.settle(applied, touched, &mut edits).0
    };
    journal.save(&edits, &project)?;
    Ok(Merged { project, applied })
}

/// The base64 alphabet (RFC 4648 §4).
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `bytes` in base64, padded.
fn base64_encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0u32, |word, (at, &byte)| {
            word | u32::from(byte) << (16 - 8 * at)
        });
        for at in 0..4 {
            if at <= chunk.len() {
                let index = (word >> (18 - 6 * at)) & 0x3f;
                text.push(char::from(
                    BASE64.get(index as usize).copied().unwrap_or(b'A'),
                ));
            } else {
                text.push('=');
            }
        }
    }
    text
}

/// The bytes base64 `text` spells (padded; whitespace ignored), read in
/// place: no more is held than the bytes it spells.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut digits = text.bytes().filter(|b| !b.is_ascii_whitespace());
    let mut bytes = Vec::with_capacity(text.len() / 4 * 3);
    let mut ended = false;
    loop {
        let mut chunk = [0u8; 4];
        let mut read = 0;
        for (slot, digit) in chunk.iter_mut().zip(digits.by_ref()) {
            *slot = digit;
            read += 1;
        }
        match read {
            0 => return Some(bytes),
            4 if !ended => {}
            _ => return None,
        }
        let padding = chunk.iter().rev().take_while(|&&b| b == b'=').count();
        if padding > 2 {
            return None;
        }
        // Padding ends the text.
        ended = padding > 0;
        let mut word = 0u32;
        for (at, &digit) in chunk.iter().enumerate() {
            let value = if at >= 4 - padding {
                0
            } else {
                u32::try_from(BASE64.iter().position(|&b| b == digit)?).ok()?
            };
            word |= value << (18 - 6 * at);
        }
        let [_, high, middle, low] = word.to_be_bytes();
        bytes.extend_from_slice([high, middle, low].get(..3 - padding).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::{Bundle, Key, base64_decode, base64_encode, component, inside};

    #[test]
    fn base64_reads_as_written_and_refuses_what_is_not() {
        for bytes in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0, 255, 128],
        ] {
            assert_eq!(base64_decode(&base64_encode(bytes)).unwrap(), bytes);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_decode("Zm9v\nYmE=").unwrap(), b"fooba");
        for bad in ["Zm9", "Zm9!", "Z==="] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }

    /// The key is the SHA-256 of the bytes and the name; its directory
    /// joins them.
    #[test]
    fn key_and_directory_name() {
        let key = Key::new(b"abc", "bash");
        assert_eq!(
            key.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            key.dir_name(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad-bash"
        );
        assert_ne!(Key::new(b"abd", "bash"), key);
        assert_eq!(component("a/b\\c"), "a_b_c");
        assert_eq!(component(".."), "_..");
    }

    /// Paths that leave the project, and hashes that are not SHA-256s, are
    /// refused.
    #[test]
    fn bundles_stay_inside() {
        for good in ["project.toml", "states/f.zero.toml"] {
            assert!(inside(good), "{good}");
        }
        for bad in ["", "/etc/passwd", "../x", "a/../b", "./a", "a//b", "a\\b"] {
            assert!(!inside(bad), "{bad}");
        }
        let hash = "0".repeat(64);
        let text = |sha: &str, path: &str| {
            format!(
                "format = 1\nsha256 = \"{sha}\"\nname = \"x\"\n[[file]]\npath = \"{path}\"\ntext = \"\"\n"
            )
        };
        assert!(Bundle::parse(&text(&hash, "layout.toml")).is_ok());
        assert!(Bundle::parse(&text(&hash, "../layout.toml")).is_err());
        assert!(Bundle::parse(&text("abc", "layout.toml")).is_err());
        assert!(Bundle::parse(&text(&"A".repeat(64), "layout.toml")).is_err());
        // Edits that are not a project file are refused before anything
        // is installed.
        assert!(Bundle::parse(&text(&hash, "project.toml")).is_err());
        // A share's file is not taken.
        let lock = Bundle::parse(&text(&hash, "collab/lock")).unwrap();
        assert_eq!(lock.files(), []);
    }

    /// A later format is reported as one, whatever its fields; this
    /// format's file still has to have its own.
    #[test]
    fn a_newer_bundle_says_so() {
        // A project of several binaries, as a later format is designed:
        // no `sha256` or `name` of its own, members this build cannot read.
        let newer = format!(
            "format = 2\n[set]\nlabel = \"tools\"\n[[member]]\nsha256 = \"{}\"\nbundle = \"\"\n",
            "0".repeat(64)
        );
        assert_eq!(
            Bundle::parse(&newer).unwrap_err(),
            "format 2 is newer than this binbun's (1)"
        );
        let error = Bundle::parse("format = 1\nname = \"x\"\n").unwrap_err();
        assert!(error.contains("missing field `sha256`"), "{error}");
        let error = Bundle::parse("format = 0\nname = \"x\"\n").unwrap_err();
        assert_eq!(error, "format 0 is not a format of binbun's (1)");
    }

    /// A project held in this process is refused a second hold at once;
    /// one whose session is closing is waited for.
    #[test]
    fn a_hold_here_is_refused_at_once_unless_it_is_closing() {
        let dir = std::env::temp_dir().join(format!("binbun-hold-{}", std::process::id()));
        let project = super::Project::new(&dir);
        let first = project.hold().unwrap();
        let asked = std::time::Instant::now();
        let refused = project.hold().unwrap_err();
        assert!(refused.contains("already open in this binbun"), "{refused}");
        assert!(asked.elapsed() < super::HOLD_WAIT / 4);
        // Closing: let go of a moment later, and taken then.
        first.close();
        let late = std::time::Duration::from_millis(300);
        let closer = std::thread::spawn(move || {
            std::thread::sleep(late);
            drop(first);
        });
        let asked = std::time::Instant::now();
        let second = project.hold().unwrap();
        assert!(asked.elapsed() >= late / 2);
        closer.join().unwrap();
        drop(second);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
