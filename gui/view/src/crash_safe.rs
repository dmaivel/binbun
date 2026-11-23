//! Writing a file so a crash leaves either the old or the new file.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Writes `bytes` to `path` crash-safely: into a temporary file beside it
/// (`.<name>.<pid>.tmp`, so two processes never share one), synced through
/// the handle that wrote it, then renamed over `path`. Creates the
/// directory when missing; the temporary file is removed on failure.
/// Syncing the directory (the rename itself durable) is best-effort: the
/// file is complete either way, and Windows cannot open a directory as a
/// file.
///
/// # Errors
///
/// The directory or the file cannot be written, or `path` names no file.
pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a file path"))?;
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    if let Some(dir) = dir {
        fs::create_dir_all(dir)?;
    }
    let mut temporary = OsString::from(".");
    temporary.push(name);
    temporary.push(format!(".{}.tmp", std::process::id()));
    let temporary = path.with_file_name(temporary);
    let written = write_synced(&temporary, bytes).and_then(|()| fs::rename(&temporary, path));
    if let Err(error) = written {
        fs::remove_file(&temporary).ok();
        return Err(error);
    }
    if let Some(dir) = dir
        && let Ok(handle) = fs::File::open(dir)
    {
        handle.sync_all().ok();
    }
    Ok(())
}

/// Writes and syncs through one handle: syncing needs write access on
/// Windows (`FlushFileBuffers`), so a handle opened again to read cannot.
fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut handle = fs::File::create(path)?;
    handle.write_all(bytes)?;
    handle.sync_all()
}

#[cfg(test)]
mod tests {
    use super::write;

    #[test]
    fn a_file_is_replaced_whole_and_no_temporary_file_is_left() {
        let dir = std::env::temp_dir().join(format!("binbun-crash-safe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("file.toml");
        write(&path, b"old").unwrap();
        write(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["file.toml"]);
        assert!(write(&dir.join(".."), b"").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
