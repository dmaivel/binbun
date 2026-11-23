//! Where servers are found: a directory of the user's own ([`dir`]:
//! `$XDG_RUNTIME_DIR/binbun`, 0700;
//! on macOS, which has no `XDG_RUNTIME_DIR`, `$TMPDIR/binbun`; on Windows
//! `%LOCALAPPDATA%\binbun\run`), holding
//! each server's socket (0600) and its discovery file `gui-<pid>.json`
//! (0600): its process, version, socket and the databases it has open.
//! On Windows the socket is a named pipe ([`pipe`]), named in the
//! discovery file only. Never a TCP port.

#[cfg(windows)]
use std::collections::HashSet;
#[cfg(windows)]
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use rustix::process::{Pid, test_kill_process};
use serde::{Deserialize, Serialize};

use crate::fault::{Fault, FaultKind};
use crate::handshake::DatabaseInfo;

/// What a server says of itself in its discovery file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    /// Its process.
    pub pid: u32,
    /// Its version (`binbun-gui/0.4.0`).
    pub server: String,
    /// Its socket.
    pub socket: PathBuf,
    /// The databases it has open.
    pub databases: Vec<DatabaseInfo>,
}

/// The directory of the user's servers ([`binbun_paths::Place::Servers`]).
/// On Windows, `%LOCALAPPDATA%` is the user's alone (its ACL: the user,
/// SYSTEM and the Administrators, inherited by what is made in it), as
/// `XDG_RUNTIME_DIR` is; and unlike `%TEMP%`, which Storage Sense may
/// empty, it is left alone.
///
/// # Errors
///
/// There is no runtime directory (on Linux, no absolute `XDG_RUNTIME_DIR`).
pub fn dir() -> Result<PathBuf, Fault> {
    binbun_paths::Place::Servers.path().ok_or_else(|| {
        Fault::new(
            FaultKind::Binbun,
            format!(
                "{}: binbun's sockets live in the user's runtime directory",
                binbun_paths::Place::Servers.missing()
            ),
        )
    })
}

/// `error` at `path` as a fault.
fn failed(path: &Path, error: &io::Error) -> Fault {
    let kind = if error.kind() == io::ErrorKind::PermissionDenied {
        FaultKind::Permission
    } else {
        FaultKind::Binbun
    };
    Fault::new(kind, format!("{}: {error}", path.display()))
}

/// Makes `dir` (0700) if it is not; refuses one that others can enter.
/// On Windows it is made only: what it is made in gives it its ACL
/// ([`dir`]).
///
/// # Errors
///
/// It cannot be made, or others can read, write or enter it.
pub fn make_private(dir: &Path) -> Result<(), Fault> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir).map_err(|error| failed(dir, &error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir)
            .map_err(|error| failed(dir, &error))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(Fault::new(
                FaultKind::Binbun,
                format!(
                    "{} is open to others (mode {:o}): binbun's sockets need a directory of the user's own",
                    dir.display(),
                    mode & 0o777
                ),
            ));
        }
    }
    Ok(())
}

/// The name a server's socket and discovery file share: `gui-<pid>`, then
/// `-<n>` for the process's `n`th server after its first (a process may
/// run several: a script serving two databases, a test's servers), so
/// that one server never takes another's socket.
pub fn stem(pid: u32, n: u64) -> String {
    if n == 0 {
        format!("gui-{pid}")
    } else {
        format!("gui-{pid}-{n}")
    }
}

/// The discovery file of the server named `stem` in `dir`.
pub fn file(dir: &Path, stem: &str) -> PathBuf {
    dir.join(format!("{stem}.json"))
}

/// The socket of the server named `stem` in `dir`.
pub fn socket(dir: &Path, stem: &str) -> PathBuf {
    dir.join(format!("{stem}.sock"))
}

/// The named pipe of the server named `stem` on Windows:
/// `\\.\pipe\binbun-<stem>-<nonce>` (`nonce` in hexadecimal). Pipes
/// share one namespace across the machine; a random `nonce` keeps another
/// user from taking the name first, and the name is told only in the
/// discovery file.
pub fn pipe(stem: &str, nonce: u64) -> PathBuf {
    PathBuf::from(format!(r"\\.\pipe\binbun-{stem}-{nonce:016x}"))
}

/// Writes `discovery` to the file of the server named `stem` in `dir`
/// (0600), whole: written beside it, then renamed into place.
///
/// # Errors
///
/// It cannot be written.
pub fn publish(dir: &Path, stem: &str, discovery: &Discovery) -> Result<(), Fault> {
    let path = file(dir, stem);
    let temporary = dir.join(format!(".{stem}.json.tmp"));
    let text = serde_json::to_vec_pretty(discovery)
        .map_err(|error| Fault::new(FaultKind::Binbun, error.to_string()))?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut out: File = options
        .open(&temporary)
        .map_err(|error| failed(&temporary, &error))?;
    out.write_all(&text)
        .map_err(|error| failed(&temporary, &error))?;
    drop(out);
    fs::rename(&temporary, &path).map_err(|error| failed(&path, &error))
}

/// The servers whose discovery files are in `dir`, those still running
/// ([`Running`]), by process.
///
/// # Errors
///
/// `dir` is another user's ([`FaultKind::Permission`]) or cannot be read.
pub fn servers(dir: &Path) -> Result<Vec<Discovery>, Fault> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(failed(dir, &error)),
    };
    let running = Running::now();
    let mut found: Vec<Discovery> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("gui-"))
        })
        .filter_map(|path| serde_json::from_slice::<Discovery>(&fs::read(path).ok()?).ok())
        .filter(|discovery| running.runs(discovery))
        .collect();
    found.sort_by_key(|discovery| discovery.pid);
    Ok(found)
}

/// Whether a discovery file's server still runs, so that a crashed
/// server's file is not listed. On Unix: its process runs and is this
/// user's, as the server that wrote a file in this user's directory is
/// (`kill(pid, 0)`, which sends nothing; a pid taken since by another
/// user's process is not this user's server). On Windows: its pipe is
/// among the machine's (the listing of `\\.\pipe\`, which connects to
/// none), as it is from the server's start to its end, a crashed one's
/// going with its process; every file where the listing cannot be read.
struct Running {
    /// The names of the machine's pipes, if they could be listed.
    #[cfg(windows)]
    pipes: Option<HashSet<OsString>>,
}

impl Running {
    /// As things are now.
    fn now() -> Self {
        Self {
            #[cfg(windows)]
            pipes: fs::read_dir(r"\\.\pipe\").ok().map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name())
                    .collect()
            }),
        }
    }

    /// Whether the server of `discovery` runs.
    #[cfg(unix)]
    #[expect(clippy::unused_self, reason = "Windows' takes what `now` listed")]
    fn runs(&self, discovery: &Discovery) -> bool {
        i32::try_from(discovery.pid)
            .ok()
            .and_then(Pid::from_raw)
            .is_some_and(|pid| test_kill_process(pid).is_ok())
    }

    /// Whether the server of `discovery` runs.
    #[cfg(windows)]
    fn runs(&self, discovery: &Discovery) -> bool {
        self.pipes.as_ref().is_none_or(|pipes| {
            discovery
                .socket
                .file_name()
                .is_some_and(|name| pipes.contains(name))
        })
    }
}

/// Removes the socket and discovery file of the server named `stem` from
/// `dir` (on Windows the discovery file: a pipe goes with its server).
pub fn withdraw(dir: &Path, stem: &str) {
    let _ = fs::remove_file(file(dir, stem));
    #[cfg(unix)]
    let _ = fs::remove_file(socket(dir, stem));
}

/// The server and database a client means: the server whose socket is
/// `socket` if given; of the servers in `dir`, the database whose path is
/// `target` (or whose file name is `target`, a bare name: `libc.so.6`;
/// opened as its slice `arch`, of a universal Mach-O file) or whose
/// SHA-256 is `sha256`; none named, the one whose window had the focus
/// last (the only one open, if one is).
///
/// # Errors
///
/// No server, no such database ([`FaultKind::Binbun`]), or several and
/// those named do not tell them apart ([`FaultKind::Ambiguous`], listing
/// them).
pub fn choose(
    servers: &[Discovery],
    target: Option<&Path>,
    arch: Option<&str>,
    sha256: Option<&str>,
) -> Result<(PathBuf, u64), Fault> {
    let candidates: Vec<(&Discovery, &DatabaseInfo)> = servers
        .iter()
        .flat_map(|server| server.databases.iter().map(move |db| (server, db)))
        .filter(|(_, db)| {
            target.is_none_or(|target| {
                same_file(Path::new(&db.path), target)
                    || (target.components().count() == 1 && target.as_os_str() == db.name.as_str())
            }) && arch.is_none_or(|arch| db.arch.as_deref() == Some(arch))
                && sha256.is_none_or(|sha| db.sha256.as_deref() == Some(sha))
        })
        .collect();
    let named = target.is_some() || arch.is_some() || sha256.is_some();
    match candidates.as_slice() {
        [(server, db)] => Ok((server.socket.clone(), db.id)),
        [] => Err(Fault::new(
            FaultKind::Binbun,
            if servers.is_empty() {
                "no binbun GUI is running for this user".to_owned()
            } else {
                "no binbun GUI has that database open".to_owned()
            },
        )),
        several if !named => several
            .iter()
            .max_by_key(|(server, db)| (db.focused, server.pid, db.id))
            .map(|(server, db)| (server.socket.clone(), db.id))
            .ok_or_else(|| Fault::new(FaultKind::Binbun, "no binbun GUI is running")),
        several => Err(Fault::new(
            FaultKind::Ambiguous,
            format!(
                "several databases are open; name one (a path, arch= or sha256=): {}",
                several
                    .iter()
                    .map(|(server, db)| match &db.arch {
                        Some(arch) => format!("{} {arch} (gui {})", db.path, server.pid),
                        None => format!("{} (gui {})", db.path, server.pid),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

/// Whether `a` and `b` name the same file.
fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{Discovery, choose, pipe, servers, stem};
    use crate::fault::FaultKind;
    use crate::handshake::DatabaseInfo;
    #[cfg(windows)]
    use crate::socket::Listener;

    /// `path` from the root, as this host writes an absolute path.
    fn absolute(path: &str) -> PathBuf {
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        Path::new(root).join(path)
    }

    /// A server's pipe: in the pipes' namespace (`\\.\pipe\`), its stem
    /// and nonce, the nonce in sixteen hexadecimal digits.
    #[test]
    fn a_pipe_is_named_by_its_stem_and_nonce() {
        assert_eq!(
            pipe(&stem(4242, 3), 0xdead_beef).to_str(),
            Some(r"\\.\pipe\binbun-gui-4242-3-00000000deadbeef")
        );
    }

    /// A crashed server's file (its process gone) is not listed; a running
    /// one's is.
    #[cfg(unix)]
    #[test]
    fn a_gone_servers_discovery_file_is_not_listed() {
        let dir = std::env::temp_dir().join(format!("binbun-discovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let gone = child.id();
        child.wait().unwrap();
        for pid in [std::process::id(), gone] {
            let discovery = Discovery {
                pid,
                server: "binbun-gui/0.0.0".to_owned(),
                socket: dir.join(stem(pid, 0)),
                databases: Vec::new(),
            };
            let text = serde_json::to_vec(&discovery).unwrap();
            std::fs::write(dir.join(format!("{}.json", stem(pid, 0))), text).unwrap();
        }
        let found: Vec<u32> = servers(&dir).unwrap().iter().map(|d| d.pid).collect();
        assert_eq!(found, [std::process::id()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// On Windows a crashed server's file (its pipe gone) is not listed; a
    /// running one's (its pipe listened on) is.
    #[cfg(windows)]
    #[test]
    fn a_gone_servers_discovery_file_is_not_listed() {
        let dir = std::env::temp_dir().join(format!("binbun-discovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nonce = u64::from(std::process::id());
        let running = pipe(&stem(1, 0), nonce);
        let _listener = Listener::bind(&running).unwrap();
        for (pid, socket) in [(1, running), (2, pipe(&stem(2, 0), nonce))] {
            let discovery = Discovery {
                pid,
                server: "binbun-gui/0.0.0".to_owned(),
                socket,
                databases: Vec::new(),
            };
            let text = serde_json::to_vec(&discovery).unwrap();
            std::fs::write(dir.join(format!("{}.json", stem(pid, 0))), text).unwrap();
        }
        let found: Vec<u32> = servers(&dir).unwrap().iter().map(|d| d.pid).collect();
        assert_eq!(found, [1]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two slices of one universal file open: told apart by `arch`.
    #[test]
    fn the_slice_tells_two_databases_of_one_file_apart() {
        let db = |id: u64, arch: &str| DatabaseInfo {
            id,
            path: "/bin/tool".to_owned(),
            name: "tool".to_owned(),
            arch: Some(arch.to_owned()),
            ..DatabaseInfo::default()
        };
        let servers = [Discovery {
            pid: 7,
            server: "binbun-gui/0.0.0".to_owned(),
            socket: absolute("run/gui-7.sock"),
            databases: vec![db(1, "x86_64"), db(2, "arm64e")],
        }];
        let target = Some(Path::new("/bin/tool"));
        let fault = choose(&servers, target, None, None).unwrap_err();
        assert_eq!(fault.kind, FaultKind::Ambiguous);
        assert_eq!(choose(&servers, target, Some("arm64e"), None).unwrap().1, 2);
        assert_eq!(choose(&servers, None, Some("x86_64"), None).unwrap().1, 1);
        let fault = choose(&servers, target, Some("i386"), None).unwrap_err();
        assert_eq!(fault.kind, FaultKind::Binbun);
    }

    /// Several binaries open in two windows and none named: the one
    /// focused last; a bare file name names one.
    #[test]
    fn none_named_is_the_one_focused_last_and_a_file_name_names_one() {
        let db = |id: u64, name: &str, focused: Option<u64>| DatabaseInfo {
            id,
            path: format!("/lib/{name}"),
            name: name.to_owned(),
            focused,
            ..DatabaseInfo::default()
        };
        let server = |pid: u32, databases| Discovery {
            pid,
            server: "binbun-gui/0.0.0".to_owned(),
            socket: absolute(&format!("run/gui-{pid}.sock")),
            databases,
        };
        let servers = [
            server(7, vec![db(1, "bash", Some(500)), db(2, "ls", None)]),
            server(8, vec![db(1, "libc.so.6", Some(900))]),
        ];
        let (socket, id) = choose(&servers, None, None, None).unwrap();
        assert_eq!((socket, id), (absolute("run/gui-8.sock"), 1));
        let (socket, id) = choose(&servers, Some(Path::new("bash")), None, None).unwrap();
        assert_eq!((socket, id), (absolute("run/gui-7.sock"), 1));
        let fault = choose(&servers, Some(Path::new("zsh")), None, None).unwrap_err();
        assert_eq!(fault.kind, FaultKind::Binbun);
    }
}
