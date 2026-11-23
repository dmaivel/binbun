//! Where files fetched from peers are kept (I10):
//!
//! - **While they come**, in binbun's cache ([`Fetches`]: by default
//!   [`Place::Fetches`]), a directory per blob. The fetch of a blob holds
//!   the blob's lock file (`<blob id>.lock`: one fetch of a blob at a
//!   time), which records the blob's directory: one binbun made under a
//!   random name, and what identifies it on this machine. The directory
//!   is worked on through handles held open, never by following a link
//!   in it; a fetch cut short leaves it, recorded, for the next to go on
//!   with; it is removed (no link in it followed) once the file is whole
//!   or the blob refused. Anything else in the cache, or at the recorded
//!   name but not the directory recorded, is never used nor removed.
//! - **Once whole**, at a destination the user chose for that file, or in
//!   binbun's downloads folder ([`downloads`]) under a name binbun gives
//!   it ([`local_name`]): the name a peer offers is shown, never used as a
//!   path. No fetch puts a file where a project's would be
//!   ([`destination`]).

use std::fs::{self, File};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use binbun_paths::Place;
use binbun_session::journal::BlobId;
use binbun_session::project;
use ring::rand::{SecureRandom as _, SystemRandom};

use crate::Error;
use crate::blobs::{Kind, Offer};

/// The directory of iroh-blobs' store in a blob's directory.
const STORE: &str = "store";

/// The deepest a blob's directory is walked (iroh-blobs' store is a few
/// levels deep).
const DEPTH: usize = 16;

/// The longest record a lock file holds that is read.
const RECORD: u64 = 128;

/// `error` at `path`.
fn failed(path: &Path, error: &io::Error) -> Error {
    Error::new(format!("{}: {error}", path.display()))
}

/// The cache of fetches under way: a directory per blob ([module
/// docs](self)).
#[derive(Clone, Debug)]
pub struct Fetches {
    root: PathBuf,
}

impl Fetches {
    /// binbun's ([`Place::Fetches`]), made if it is not there.
    ///
    /// # Errors
    ///
    /// binbun has no cache folder; it cannot be made.
    pub fn new() -> Result<Self, Error> {
        let root = Place::Fetches
            .path()
            .ok_or_else(|| Error::new(Place::Fetches.missing()))?;
        let fetches = Self::at(root)?;
        // A tag for backup tools and cleaners; the cache works without.
        let _ = binbun_paths::tag_cache(&fetches.root);
        Ok(fetches)
    }

    /// One at `root`, made if it is not there.
    ///
    /// # Errors
    ///
    /// It cannot be made, or is not a directory (a link to one is not).
    pub fn at(root: impl Into<PathBuf>) -> Result<Self, Error> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|error| failed(&root, &error))?;
        let meta = fs::symlink_metadata(&root).map_err(|error| failed(&root, &error))?;
        if !meta.is_dir() {
            return Err(Error::new(format!(
                "{}: not a directory: fetches are not kept there",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    /// Where it is.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Blob `blob`'s directory, for this fetch alone: the one its lock
    /// file records, gone on with, if it is still the directory recorded;
    /// else one made under a random name and recorded (what is at the
    /// name recorded left alone).
    ///
    /// # Errors
    ///
    /// Another fetch of the blob is under way; the lock is not a file
    /// (left alone); a directory or the record cannot be made.
    pub(crate) fn stage(&self, blob: BlobId) -> Result<Staged, Error> {
        let root = held::Dir::open(&self.root).map_err(|error| failed(&self.root, &error))?;
        let lock_name = format!("{}.lock", data_encoding::HEXLOWER.encode(&blob.0));
        let lock_path = self.root.join(&lock_name);
        let mut lock = root.file(&lock_name).map_err(|error| {
            Error::new(format!(
                "{}: not a fetch's lock: left alone ({error})",
                lock_path.display()
            ))
        })?;
        lock.try_lock()
            .map_err(|_| Error::new("another fetch of this file is under way"))?;
        if let Some((name, identity)) = recorded(&mut lock)
            && let Ok(dir) = root.child(&name)
            && dir.identity().ok() == Some(identity)
        {
            return Ok(Staged {
                path: self.root.join(&name),
                name,
                root,
                dir,
                lock,
            });
        }
        let random = SystemRandom::new();
        for _ in 0..4 {
            let mut bytes = [0; 16];
            random
                .fill(&mut bytes)
                .map_err(|_| Error::new("no random numbers for a fetch's directory"))?;
            let name = data_encoding::HEXLOWER.encode(&bytes);
            let path = self.root.join(&name);
            let dir = match root.make(&name) {
                Ok(dir) => dir,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(failed(&path, &error)),
            };
            let identity = dir.identity().map_err(|error| failed(&path, &error))?;
            record(&mut lock, &name, identity).map_err(|error| failed(&lock_path, &error))?;
            return Ok(Staged {
                path,
                name,
                root,
                dir,
                lock,
            });
        }
        Err(Error::new(format!(
            "{}: no name free for a fetch's directory",
            self.root.display()
        )))
    }
}

/// What a lock file records: its blob's directory's name (32 hexadecimal
/// digits) and identity; `None` if nothing (or nothing readable) is
/// recorded.
fn recorded(lock: &mut File) -> Option<(String, held::Identity)> {
    let mut text = String::new();
    lock.seek(SeekFrom::Start(0)).ok()?;
    lock.take(RECORD).read_to_string(&mut text).ok()?;
    let mut words = text.split_whitespace();
    let name = words.next()?;
    let ours = name.len() == 32 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let identity = (words.next()?.parse().ok()?, words.next()?.parse().ok()?);
    (ours && words.next().is_none()).then(|| (name.to_owned(), identity))
}

/// Records directory `name` of identity `identity` in `lock`, in place of
/// what it recorded.
fn record(lock: &mut File, name: &str, (a, b): held::Identity) -> io::Result<()> {
    lock.set_len(0)?;
    lock.seek(SeekFrom::Start(0))?;
    lock.write_all(format!("{name} {a} {b}\n").as_bytes())?;
    lock.sync_data()
}

/// A blob's directory in [`Fetches`], held open, its lock held.
pub(crate) struct Staged {
    /// Where it is, for iroh-blobs' store, which opens by path.
    path: PathBuf,
    /// Its name in the cache.
    name: String,
    /// The cache, held.
    root: held::Dir,
    /// It, held.
    dir: held::Dir,
    /// Its blob's lock, which records it.
    lock: File,
}

impl Staged {
    /// Where iroh-blobs' store of the blob goes, made if it is not there:
    /// a directory in it, the one its path leads to now, with no link
    /// (nor anything but files and directories) in it.
    ///
    /// # Errors
    ///
    /// It cannot be made; it, or anything in it, is a link; its path does
    /// not lead to the directory held.
    pub(crate) fn store(&self) -> Result<PathBuf, Error> {
        let path = self.path.join(STORE);
        let store = match self.dir.make(STORE) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => self.dir.child(STORE),
            made => made,
        }
        .map_err(|error| failed(&path, &error))?;
        let refused = |why: &str| Error::new(format!("{}: {why}: not used", path.display()));
        if store.linked(DEPTH).map_err(|error| failed(&path, &error))? {
            return Err(refused("a link, or something not a file, is in it"));
        }
        let there = fs::metadata(&path).map_err(|error| failed(&path, &error))?;
        if Some(held::identity(&there)) != store.identity().ok() {
            return Err(refused("not the directory made for the fetch"));
        }
        Ok(path)
    }

    /// Removes the directory (the file whole, or the blob refused), if its
    /// name in the cache still names it, no link in it followed; then its
    /// record. The lock is let go after.
    pub(crate) fn remove(self) {
        let ours = self
            .root
            .child(&self.name)
            .and_then(|there| there.identity())
            .is_ok_and(|there| self.dir.identity().ok() == Some(there));
        if ours && self.dir.empty(DEPTH).is_ok() && self.root.remove_dir(&self.name).is_ok() {
            let _ = self.lock.set_len(0);
        }
    }
}

/// The cache's directories, held open: what is done in one is done by
/// handle, relative to it, never following a link
/// (`openat(O_NOFOLLOW)`).
#[cfg(unix)]
mod held {
    use std::fs::{File, Metadata};
    use std::io;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, unlinkat};
    use rustix::path::Arg;

    /// What tells one directory from another on this machine: its device
    /// and inode.
    pub(super) type Identity = (u64, u64);

    /// The identity of what `meta` describes.
    pub(super) fn identity(meta: &Metadata) -> Identity {
        (meta.dev(), meta.ino())
    }

    /// A directory, held open.
    pub(super) struct Dir(File);

    /// Opening a directory, not a link to one.
    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    impl Dir {
        /// The directory at `path`, itself not a link.
        pub(super) fn open(path: &Path) -> io::Result<Self> {
            Ok(Self(
                rustix::fs::open(path, dir_flags(), Mode::empty())?.into(),
            ))
        }

        /// Its directory `name`, not a link.
        pub(super) fn child<P: Arg>(&self, name: P) -> io::Result<Self> {
            Ok(Self(
                openat(&self.0, name, dir_flags(), Mode::empty())?.into(),
            ))
        }

        /// Directory `name`, made in it (nothing of that name there).
        pub(super) fn make(&self, name: &str) -> io::Result<Self> {
            mkdirat(&self.0, name, Mode::RWXU)?;
            self.child(name)
        }

        /// Its file `name`, made if it is not there, for reading and
        /// writing: a file, not a link.
        pub(super) fn file(&self, name: &str) -> io::Result<File> {
            let flags = OFlags::RDWR
                | OFlags::CREATE
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC;
            let file = File::from(openat(&self.0, name, flags, Mode::RUSR | Mode::WUSR)?);
            if !file.metadata()?.is_file() {
                return Err(io::Error::other("not a file"));
            }
            Ok(file)
        }

        /// Its identity.
        pub(super) fn identity(&self) -> io::Result<Identity> {
            Ok(identity(&self.0.metadata()?))
        }

        /// The names in it.
        fn names(&self) -> io::Result<Vec<std::ffi::CString>> {
            let mut names = Vec::new();
            for entry in rustix::fs::Dir::read_from(&self.0)? {
                let name = entry?.file_name().to_owned();
                if name.as_bytes() != b"." && name.as_bytes() != b".." {
                    names.push(name);
                }
            }
            Ok(names)
        }

        /// Whether anything in it, `depth` levels down, is a link or
        /// anything but a file or a directory.
        pub(super) fn linked(&self, depth: usize) -> io::Result<bool> {
            let depth = depth.checked_sub(1).ok_or_else(too_deep)?;
            for name in self.names()? {
                let linked = if let Ok(child) = self.child(name.as_c_str()) {
                    child.linked(depth)?
                } else {
                    let flags =
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
                    let file = openat(&self.0, name.as_c_str(), flags, Mode::empty());
                    let file = file.ok().map(File::from);
                    !file.is_some_and(|file| file.metadata().is_ok_and(|m| m.is_file()))
                };
                if linked {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        /// Removes everything in it, `depth` levels down: a link is
        /// removed, never what it names.
        pub(super) fn empty(&self, depth: usize) -> io::Result<()> {
            let depth = depth.checked_sub(1).ok_or_else(too_deep)?;
            for name in self.names()? {
                if let Ok(child) = self.child(name.as_c_str()) {
                    child.empty(depth)?;
                    unlinkat(&self.0, name.as_c_str(), AtFlags::REMOVEDIR)?;
                } else {
                    unlinkat(&self.0, name.as_c_str(), AtFlags::empty())?;
                }
            }
            Ok(())
        }

        /// Removes its directory `name`, empty.
        pub(super) fn remove_dir(&self, name: &str) -> io::Result<()> {
            Ok(unlinkat(&self.0, name, AtFlags::REMOVEDIR)?)
        }
    }

    /// Deeper than a fetch's directory goes.
    fn too_deep() -> io::Error {
        io::Error::other("deeper than a fetch's directory goes")
    }
}

/// The cache's directories, by path, each checked not to be a link before
/// it is used (no `openat` here); removal by [`std::fs::remove_dir_all`],
/// which follows no link.
#[cfg(not(unix))]
mod held {
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::UNIX_EPOCH;

    /// What tells one directory from another here: when it was made.
    pub(super) type Identity = (u64, u64);

    /// The identity of what `meta` describes.
    pub(super) fn identity(meta: &Metadata) -> Identity {
        meta.created()
            .ok()
            .and_then(|made| made.duration_since(UNIX_EPOCH).ok())
            .map_or((0, 0), |made| {
                (made.as_secs(), u64::from(made.subsec_nanos()))
            })
    }

    /// A directory, by path.
    pub(super) struct Dir(PathBuf);

    impl Dir {
        /// The directory at `path`, itself not a link.
        pub(super) fn open(path: &Path) -> io::Result<Self> {
            let meta = fs::symlink_metadata(path)?;
            if meta.is_symlink() || !meta.is_dir() {
                return Err(io::Error::other("not a directory"));
            }
            Ok(Self(path.to_path_buf()))
        }

        /// Its directory `name`, not a link.
        pub(super) fn child(&self, name: &str) -> io::Result<Self> {
            Self::open(&self.0.join(name))
        }

        /// Directory `name`, made in it (nothing of that name there).
        pub(super) fn make(&self, name: &str) -> io::Result<Self> {
            fs::create_dir(self.0.join(name))?;
            self.child(name)
        }

        /// Its file `name`, made if it is not there, for reading and
        /// writing: a file, not a link.
        pub(super) fn file(&self, name: &str) -> io::Result<File> {
            let path = self.0.join(name);
            if fs::symlink_metadata(&path).is_ok_and(|meta| !meta.is_file()) {
                return Err(io::Error::other("not a file"));
            }
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(path)
        }

        /// Its identity.
        pub(super) fn identity(&self) -> io::Result<Identity> {
            Ok(identity(&fs::symlink_metadata(&self.0)?))
        }

        /// Whether anything in it, `depth` levels down, is a link or
        /// anything but a file or a directory.
        pub(super) fn linked(&self, depth: usize) -> io::Result<bool> {
            let depth = depth.checked_sub(1).ok_or_else(too_deep)?;
            for entry in fs::read_dir(&self.0)? {
                let path = entry?.path();
                let meta = fs::symlink_metadata(&path)?;
                if meta.is_symlink() || !(meta.is_file() || meta.is_dir()) {
                    return Ok(true);
                }
                if meta.is_dir() && Self(path).linked(depth)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        /// Removes everything in it: a link is removed, never what it
        /// names.
        pub(super) fn empty(&self, _depth: usize) -> io::Result<()> {
            for entry in fs::read_dir(&self.0)? {
                let path = entry?.path();
                let meta = fs::symlink_metadata(&path)?;
                if meta.is_dir() && !meta.is_symlink() {
                    fs::remove_dir_all(&path)?;
                } else {
                    fs::remove_file(&path)?;
                }
            }
            Ok(())
        }

        /// Removes its directory `name`, empty.
        pub(super) fn remove_dir(&self, name: &str) -> io::Result<()> {
            fs::remove_dir(self.0.join(name))
        }
    }

    /// Deeper than a fetch's directory goes.
    fn too_deep() -> io::Error {
        io::Error::other("deeper than a fetch's directory goes")
    }
}

/// binbun's downloads folder ([`Place::Downloads`]), made if it is not
/// there.
///
/// # Errors
///
/// binbun has no data folder; it cannot be made.
pub fn downloads() -> Result<PathBuf, Error> {
    let dir = Place::Downloads
        .path()
        .ok_or_else(|| Error::new(Place::Downloads.missing()))?;
    fs::create_dir_all(&dir).map_err(|error| failed(&dir, &error))?;
    Ok(dir)
}

/// The name `offer`'s file is given on disk where the user chose none:
/// what it is and its SHA-256's first 16 hexadecimal digits
/// (`binary-0123456789abcdef`, `debug-0123456789abcdef`), never the name
/// offered.
pub fn local_name(offer: &Offer) -> String {
    let kind = match offer.kind {
        Kind::Binary => "binary",
        Kind::DebugFile => "debug",
    };
    let digest = data_encoding::HEXLOWER.encode(&offer.sha256[..8]);
    format!("{kind}-{digest}")
}

/// Refuses `to` as where a fetched file goes where it would be taken for
/// a project's (I10), its folder made canonical first: its name is one a
/// project's files have ([`project::reserved`], whatever the case); it is
/// in binbun's projects folder, `projects`; or a folder above it is a project's
/// ([`project::is_project`]), wherever it is. A folder merely named as a
/// project's are (`log`) is no reason. A projects folder that is not
/// there holds nothing; one that is unknown (`None`) or cannot be made
/// canonical refuses every destination.
///
/// # Errors
///
/// `to` is refused; its folder cannot be read.
pub(crate) fn destination(to: &Path, projects: Option<&Path>) -> Result<(), Error> {
    let refused = |why: &str| {
        Error::new(format!(
            "{}: {why}, where no file fetched goes",
            to.display()
        ))
    };
    let Some(name) = to.file_name() else {
        return Err(refused("not a file's name"));
    };
    if project::reserved(&name.to_string_lossy()) {
        return Err(refused("a name binbun keeps for a project's files"));
    }
    let parent = match to.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let folder = binbun_paths::canonical(parent).map_err(|error| failed(parent, &error))?;
    let projects = projects.ok_or_else(|| {
        Error::new(format!(
            "{}: binbun's projects folder is unknown, so no file fetched goes anywhere",
            to.display()
        ))
    })?;
    match binbun_paths::canonical(projects) {
        Ok(projects) if folder.starts_with(&projects) => {
            return Err(refused("in binbun's projects folder"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::new(format!(
                "{}: binbun's projects folder cannot be read ({error}), so no file fetched goes \
                 anywhere",
                projects.display()
            )));
        }
    }
    if folder.ancestors().any(project::is_project) {
        return Err(refused("in a project's folder"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use binbun_bounded::Text;
    use binbun_session::journal::BlobId;

    use super::{Fetches, STORE, destination, local_name};
    use crate::blob::BlobKey;
    use crate::blobs::{Kind, Offer};

    /// A scratch directory of its own.
    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("binbun-fetches-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn offer(name: &str) -> Offer {
        Offer {
            blob: BlobId([3; 32]),
            key: BlobKey::random().unwrap(),
            length: 10,
            sha256: [0xab; 32],
            kind: Kind::DebugFile,
            name: Text::truncated(name),
            arch: None,
        }
    }

    /// The directories in `root`, sorted.
    fn dirs(root: &Path) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| fs::symlink_metadata(path).unwrap().is_dir())
            .collect();
        dirs.sort();
        dirs
    }

    /// Someone else's directory, `dir`, holding a file `keep`.
    fn theirs(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("keep"), b"someone's").unwrap();
        dir.to_path_buf()
    }

    /// Whether `dir`'s file `keep` is as [`theirs`] left it.
    fn kept(dir: &Path) -> bool {
        fs::read(dir.join("keep")).is_ok_and(|bytes| bytes == b"someone's")
    }

    #[test]
    fn the_name_on_disk_is_never_the_one_offered() {
        for name in ["project.toml", "../x"] {
            assert_eq!(local_name(&offer(name)), "debug-abababababababab");
        }
    }

    #[test]
    fn a_blob_s_directory_is_made_at_random_recorded_used_once_at_a_time_and_removed() {
        let dir = scratch("stage");
        let fetches = Fetches::at(dir.join("cache")).unwrap();
        let blob = BlobId([1; 32]);
        let staged = fetches.stage(blob).unwrap();
        let store = staged.store().unwrap();
        fs::write(store.join("part"), b"resume state").unwrap();
        let made = dirs(fetches.root());
        assert_eq!(made.len(), 1);
        // Named at random, not by the blob.
        assert_eq!(made[0].file_name().unwrap().len(), 32);
        // A second fetch of it while the first works: refused.
        assert!(fetches.stage(blob).is_err());
        drop(staged);
        // Cut short: kept, and gone on with.
        let again = fetches.stage(blob).unwrap();
        assert_eq!(
            fs::read(again.store().unwrap().join("part")).unwrap(),
            b"resume state"
        );
        again.remove();
        assert_eq!(dirs(fetches.root()), Vec::<PathBuf>::new());
        // Removed, it is forgotten: the next fetch makes another.
        let next = fetches.stage(blob).unwrap();
        assert!(!next.store().unwrap().join("part").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A blob's directory swapped for a link, or another directory, at
    /// its name: not used, and what it names is never removed.
    #[cfg(unix)]
    #[test]
    fn a_directory_substituted_in_the_cache_is_neither_used_nor_removed() {
        let dir = scratch("swap");
        let fetches = Fetches::at(dir.join("cache")).unwrap();
        let blob = BlobId([4; 32]);
        let elsewhere = theirs(&dir.join("elsewhere"));

        // During a fetch: its store is not used, nothing is removed.
        let staged = fetches.stage(blob).unwrap();
        let ours = dirs(fetches.root()).remove(0);
        fs::rename(&ours, dir.join("moved")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &ours).unwrap();
        assert!(staged.store().is_err());
        assert!(!elsewhere.join(STORE).exists());
        staged.remove();
        assert!(kept(&elsewhere));
        assert!(fs::symlink_metadata(&ours).unwrap().is_symlink());

        // Between fetches: the next makes a directory of its own.
        let staged = fetches.stage(blob).unwrap();
        staged.store().unwrap();
        drop(staged);
        let ours = dirs(fetches.root()).remove(0);
        // Moved away rather than removed: its inode is not free for the
        // directory planted.
        fs::rename(&ours, dir.join("moved again")).unwrap();
        let planted = theirs(&ours);
        let staged = fetches.stage(blob).unwrap();
        assert!(!staged.store().unwrap().starts_with(&planted));
        staged.remove();
        assert!(kept(&planted));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A link put in a blob's store: the store is not used, and removing
    /// the directory removes the link, not what it names.
    #[cfg(unix)]
    #[test]
    fn a_link_in_a_blob_s_directory_is_not_followed() {
        let dir = scratch("link");
        let fetches = Fetches::at(dir.join("cache")).unwrap();
        let elsewhere = theirs(&dir.join("elsewhere"));
        let staged = fetches.stage(BlobId([5; 32])).unwrap();
        let store = staged.store().unwrap();
        fs::create_dir_all(store.join("data")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, store.join("data").join("blob")).unwrap();
        assert!(staged.store().is_err());
        staged.remove();
        assert!(kept(&elsewhere));
        assert_eq!(dirs(fetches.root()), Vec::<PathBuf>::new());

        // The store itself a link: not used.
        let staged = fetches.stage(BlobId([6; 32])).unwrap();
        let store = staged.store().unwrap();
        fs::remove_dir(&store).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &store).unwrap();
        assert!(staged.store().is_err());
        staged.remove();
        assert!(kept(&elsewhere));

        // A blob's lock a link: left alone.
        let lock = fetches.root().join(format!("{}.lock", "07".repeat(32)));
        std::os::unix::fs::symlink(elsewhere.join("keep"), &lock).unwrap();
        assert!(fetches.stage(BlobId([7; 32])).is_err());
        assert!(kept(&elsewhere));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_file_fetched_goes_where_a_project_s_would() {
        let dir = scratch("projects");
        let projects = dir.join("data").join("projects");
        let project = projects.join("abc");
        fs::create_dir_all(&project).unwrap();
        let downloads = dir.join("data").join("downloads");
        fs::create_dir_all(&downloads).unwrap();
        for to in [project.join("x"), projects.join("x")] {
            assert!(destination(&to, Some(&projects)).is_err(), "{to:?}");
        }
        // Through `..` too.
        let around = downloads.join("..").join("projects").join("abc").join("x");
        assert!(destination(&around, Some(&projects)).is_err());
        destination(&downloads.join("binary-0011"), Some(&projects)).unwrap();

        // A project's file name, whatever the case: refused anywhere.
        for name in ["Project.TOML", "layout.toml", "log"] {
            assert!(
                destination(&downloads.join(name), Some(&projects)).is_err(),
                "{name}"
            );
        }
        // Under a project's folder outside the projects folder: refused;
        // under folders merely named as a project's are: not.
        let copied = dir.join("copied");
        fs::create_dir_all(copied.join("states")).unwrap();
        fs::write(copied.join("project.toml"), b"").unwrap();
        for to in [copied.join("x"), copied.join("states").join("x")] {
            assert!(destination(&to, Some(&projects)).is_err(), "{to:?}");
        }
        for named in ["log", "collab"] {
            fs::create_dir_all(dir.join(named)).unwrap();
            destination(&dir.join(named).join("x"), Some(&projects)).unwrap();
        }

        // A projects folder not there yet holds nothing; an unknown one
        // refuses.
        destination(&downloads.join("x"), Some(&dir.join("none"))).unwrap();
        assert!(destination(&downloads.join("x"), None).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
