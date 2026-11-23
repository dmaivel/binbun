//! What the session's tests share: directories of their own.

use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process;

/// A directory of one test's own, empty when made and removed when
/// dropped. Its name holds the process's id as well as the test's: test
/// binaries run at once over one target directory (two `cargo test`s,
/// one binary run many times in parallel) share its temporary directory,
/// and with the test's name alone one run's directory was another's,
/// emptied or removed under it.
#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    /// The directory for test `name` in this process, empty.
    pub fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        Self(dir)
    }
}

impl Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
