//! binbun's own symbol cache ([`binbun_debuginfo::symbols::config::cache`]), as the
//! GUI shows and clears it: its path and clearing it (its size is
//! [`binbun_paths::size`]). Only that directory is ever removed: the
//! stores of `_NT_SYMBOL_PATH` and ntoseye's are only read. Counting and
//! clearing walk the disk: the GUI runs them off the UI thread.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// binbun's symbol cache as the environment says (where its downloads go).
pub fn path() -> PathBuf {
    binbun_debuginfo::symbols::config::cache()
}

/// Removes `dir` and everything under it (a symbolic link is removed, not
/// followed); nothing to do if it does not exist.
///
/// # Errors
///
/// Something under it cannot be removed.
pub fn clear(dir: &Path) -> io::Result<()> {
    match fs::remove_dir_all(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        done => done,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearing_removes_the_directory_alone() {
        let root = std::env::temp_dir().join(format!("binbun-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let cache = root.join("binbun").join("symbols");
        let beside = root.join("other-store");
        fs::create_dir_all(cache.join("a.pdb/0011/")).unwrap();
        fs::create_dir_all(&beside).unwrap();
        fs::write(cache.join("a.pdb/0011/a.pdb"), [0u8; 300]).unwrap();
        fs::write(cache.join("flat.pdb"), [0u8; 20]).unwrap();
        fs::write(beside.join("kept.pdb"), [0u8; 7]).unwrap();

        clear(&cache).unwrap();
        assert!(!cache.exists());
        assert!(root.join("binbun").is_dir());
        assert!(beside.join("kept.pdb").is_file());
        // Cleared again: nothing there, nothing to do.
        clear(&cache).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }
}
