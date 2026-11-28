//! What `binbun mcp` tells the binbun windows, and reads of them, through
//! the folder their discovery files are in
//! ([`binbun_paths::Place::Servers`]).
//!
//! From the handshake on it announces itself: `agent-<pid>.json`, the
//! agent it serves (`Claude Code`), when it started (Unix milliseconds),
//! and whether its interpreter is `starting`, `ready` or `failed` (with
//! why). A window that saw a coding agent start in one of its terminals
//! knows from it that the agent's harness runs binbun's server, and if its
//! Python failed, why, before any participant joins. Beside it
//! `agent-<pid>.lock`, locked while the server runs: a server that died
//! without removing its files (a harness's SIGINT) leaves a lock anyone may
//! take, and the next server to start removes them.
//!
//! It also reads the windows' discovery files for the binary the window it
//! follows has open, named in its instructions.

use std::fs::{self, File, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// How the interpreter's start went, as announced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Start {
    Starting,
    Ready,
    Failed,
}

impl Start {
    fn name(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Failed => "failed",
        }
    }
}

/// This server's announcement; its files removed when it is dropped.
#[derive(Debug)]
pub(super) struct Announcement {
    json: PathBuf,
    lock: PathBuf,
    /// Held locked while this server runs.
    _held: File,
    agent: String,
    version: Option<String>,
    started: u64,
    /// What the file says now: written again only when that changes.
    said: Mutex<Option<(Start, Option<String>)>>,
}

impl Announcement {
    /// The agent `agent` announced as starting; `None` where there is no
    /// servers' folder (no window to tell) or it cannot be written.
    pub(super) fn new(agent: &str, version: Option<&str>) -> Option<Self> {
        let dir = binbun_paths::Place::Servers.path()?;
        if !dir.is_dir() {
            return None;
        }
        sweep(&dir);
        let pid = std::process::id();
        let lock = dir.join(format!("agent-{pid}.lock"));
        let held = File::create(&lock).ok()?;
        held.try_lock().ok()?;
        let announcement = Self {
            json: dir.join(format!("agent-{pid}.json")),
            lock,
            _held: held,
            agent: agent.to_owned(),
            version: version.map(str::to_owned),
            started: now(),
            said: Mutex::new(None),
        };
        announcement.set(Start::Starting, None);
        Some(announcement)
    }

    /// The interpreter's start now `start` (`error` why it failed): the
    /// file replaced whole.
    pub(super) fn set(&self, start: Start, error: Option<&str>) {
        let now = Some((start, error.map(str::to_owned)));
        {
            let mut said = self.said.lock().unwrap_or_else(PoisonError::into_inner);
            if *said == now {
                return;
            }
            *said = now;
        }
        let text = serde_json::json!({
            "pid": std::process::id(),
            "agent": self.agent,
            "version": self.version,
            "started": self.started,
            "state": start.name(),
            "error": error,
        })
        .to_string();
        let written = self.json.with_extension("json.part");
        if fs::write(&written, text).is_ok() {
            let _ = fs::rename(&written, &self.json);
        }
    }
}

impl Drop for Announcement {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.json);
        let _ = fs::remove_file(&self.lock);
    }
}

/// The announcements in `dir` of servers that died without removing them:
/// their locks free.
fn sweep(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
        let is_lock = path.extension().is_some_and(|e| e == "lock")
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("agent-"));
        if !is_lock {
            continue;
        }
        let Ok(file) = File::options().read(true).write(true).open(&path) else {
            continue;
        };
        match file.try_lock() {
            Ok(()) => {
                drop(file);
                let _ = fs::remove_file(path.with_extension("json"));
                let _ = fs::remove_file(&path);
            }
            Err(TryLockError::WouldBlock | TryLockError::Error(_)) => {}
        }
    }
}

/// Now, in Unix milliseconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A binary a window has open, as its discovery file says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Open {
    /// Its file name.
    pub(super) name: String,
    /// Its path.
    pub(super) path: String,
}

/// The binary the interpreter will follow: the one of the window `socket`
/// (if given) at `database` (a path or a name, if given), else the one
/// whose window had the focus last, among the windows running.
pub(super) fn followed(socket: Option<&Path>, database: Option<&str>) -> Option<Open> {
    let dir = binbun_paths::Place::Servers.path()?;
    let mut best: Option<(u64, Open)> = None;
    for entry in fs::read_dir(&dir).ok()?.filter_map(Result::ok) {
        let path = entry.path();
        let is_server = path.extension().is_some_and(|e| e == "json")
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("gui-"));
        if !is_server {
            continue;
        }
        let Some(server) = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        else {
            continue;
        };
        let Some(its) = server.get("socket").and_then(|s| s.as_str()).map(Path::new) else {
            continue;
        };
        if socket.is_some_and(|socket| socket != its) || !runs(its) {
            continue;
        }
        let databases = server.get("databases").and_then(|d| d.as_array());
        for db in databases.into_iter().flatten() {
            let field = |key| db.get(key).and_then(|v| v.as_str()).unwrap_or_default();
            let open = Open {
                name: field("name").to_owned(),
                path: field("path").to_owned(),
            };
            if database.is_some_and(|wanted| wanted != open.path && wanted != open.name) {
                continue;
            }
            let focused = db
                .get("focused")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if best.as_ref().is_none_or(|(at, _)| focused >= *at) {
                best = Some((focused, open));
            }
        }
    }
    best.map(|(_, open)| open)
}

/// Whether the window serving at `socket` runs: something answers on its
/// socket (a crashed window's file and socket stay); on Windows, its pipe
/// is among the machine's.
fn runs(socket: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(socket).is_ok()
    }
    #[cfg(windows)]
    {
        fs::read_dir(r"\\.\pipe\").map_or(true, |pipes| {
            pipes
                .filter_map(Result::ok)
                .any(|pipe| Some(pipe.file_name().as_os_str()) == socket.file_name())
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = socket;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lock taken is not swept; one free (its server gone) is, with its
    /// announcement.
    #[test]
    fn a_dead_servers_announcement_is_swept() {
        let dir = std::env::temp_dir().join(format!("binbun-announce-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let live = dir.join("agent-1.lock");
        let held = File::create(&live).unwrap();
        held.try_lock().unwrap();
        fs::write(dir.join("agent-1.json"), "{}").unwrap();
        File::create(dir.join("agent-2.lock")).unwrap();
        fs::write(dir.join("agent-2.json"), "{}").unwrap();
        sweep(&dir);
        assert!(live.exists() && dir.join("agent-1.json").exists());
        assert!(!dir.join("agent-2.lock").exists() && !dir.join("agent-2.json").exists());
        drop(held);
        fs::remove_dir_all(&dir).unwrap();
    }
}
