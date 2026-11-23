//! Fetching debug information from symbol servers ([`Config::fetch`]):
//! HTTP(S) with timeouts, cancellable between reads, a compressed PDB
//! (`.pd_`, a cabinet) expanded, the file verified before it is stored
//! and stored atomically (written beside its place, then renamed), so a
//! store never holds a partial or mismatched file.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ureq::Agent;

use crate::symbols::config::{Config, Server};
use crate::symbols::identity::{Identity, Mismatch};

/// Stops a fetch from another thread: it ends with
/// [`Failure::Cancelled`] at its next read.
#[derive(Clone, Debug, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// Stops the fetch.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Whether the fetch is to stop.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl From<Arc<AtomicBool>> for Cancel {
    /// Cancelled when `flag` is set (a caller's own stop flag).
    fn from(flag: Arc<AtomicBool>) -> Self {
        Self(flag)
    }
}

/// A fetch that brought the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// Where it is stored now.
    pub path: PathBuf,
    /// The server it came from.
    pub server: Server,
    /// Whether it came compressed (a PDB's `_` form).
    pub compressed: bool,
}

/// Why a fetch brought nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// No server is set for the kind of file.
    NoServer,
    /// No server has it.
    NotFound {
        /// The servers asked (hosts).
        servers: Vec<String>,
    },
    /// A server has a file there that is another build's.
    Mismatch {
        /// The server (host).
        server: String,
        /// How it differs.
        why: Mismatch,
    },
    /// A server could not be reached, or answered with an error.
    Network {
        /// The server (host).
        server: String,
        /// What went wrong.
        message: String,
    },
    /// The file could not be written to the cache, or expanded.
    Store(String),
    /// The fetch was cancelled ([`Cancel`]).
    Cancelled,
}

impl Failure {
    /// Which failure is reported when every server failed: the most
    /// telling (a mismatch, then the network, then the cache, then
    /// absence).
    fn rank(&self) -> u8 {
        match self {
            Self::Mismatch { .. } => 4,
            Self::Network { .. } => 3,
            Self::Store(_) => 2,
            Self::NotFound { .. } => 1,
            Self::NoServer | Self::Cancelled => 0,
        }
    }
}

impl fmt::Display for Failure {
    /// One line, as a user reads it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoServer => f.write_str("no symbol server is set"),
            Self::NotFound { servers } => write!(f, "not found on {}", servers.join(", ")),
            Self::Mismatch { server, why } => write!(f, "{server}: {why}"),
            Self::Network { server, message } => write!(f, "{server}: {message}"),
            Self::Store(message) => write!(f, "cannot store it: {message}"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for Failure {}

/// Why storing one download failed.
enum Stored {
    /// The fetch was cancelled.
    Cancelled,
    /// Reading the body failed.
    Network(String),
    /// Writing or expanding failed.
    Store(String),
    /// The file is another build's.
    Mismatch(Mismatch),
}

impl Config {
    /// Fetches `identity` from its servers ([`Config::servers`]), in
    /// order, into the first server's cache that has it; a PDB's plain
    /// file first, its compressed form where the plain one is absent.
    /// Only a file that is `identity` ([`Identity::verify`]) is stored.
    /// This sends `identity` to the servers: callers decide whether that
    /// may happen ([`Config::locate`] first sends nothing).
    ///
    /// # Errors
    ///
    /// Why nothing was fetched ([`Failure`]): with several servers, the
    /// most telling of their failures.
    pub fn fetch(&self, identity: &Identity, cancel: &Cancel) -> Result<Fetched, Failure> {
        let servers = self.servers(identity);
        if servers.is_empty() {
            return Err(Failure::NoServer);
        }
        let agent: Agent = Agent::config_builder()
            .timeout_connect(Some(self.timeout))
            .timeout_recv_response(Some(self.timeout))
            .timeout_per_read(Some(self.timeout))
            .http_status_as_error(false)
            .user_agent(concat!("binbun/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let mut failed: Option<Failure> = None;
        let mut fail = |failure: Failure| {
            if failed
                .as_ref()
                .is_none_or(|worst| failure.rank() > worst.rank())
            {
                failed = Some(failure);
            }
        };
        for server in servers {
            let host = server.host().to_owned();
            for (url, compressed) in identity.urls(&server.url) {
                if cancel.is_cancelled() {
                    return Err(Failure::Cancelled);
                }
                let response = match agent.get(&url).call() {
                    Ok(response) => response,
                    Err(error) => {
                        fail(Failure::Network {
                            server: host.clone(),
                            message: error.to_string(),
                        });
                        break;
                    }
                };
                let status = response.status().as_u16();
                if status == 404 || status == 410 {
                    continue;
                }
                if status != 200 {
                    fail(Failure::Network {
                        server: host.clone(),
                        message: format!("HTTP {status}"),
                    });
                    break;
                }
                let destination = server.cache.join(identity.store_path());
                let body = response.into_body().into_reader();
                match store(body, &destination, compressed, identity, cancel) {
                    Ok(()) => {
                        return Ok(Fetched {
                            path: destination,
                            server: server.clone(),
                            compressed,
                        });
                    }
                    Err(Stored::Cancelled) => return Err(Failure::Cancelled),
                    Err(Stored::Network(message)) => fail(Failure::Network {
                        server: host.clone(),
                        message,
                    }),
                    Err(Stored::Store(message)) => fail(Failure::Store(message)),
                    Err(Stored::Mismatch(why)) => fail(Failure::Mismatch {
                        server: host.clone(),
                        why,
                    }),
                }
                break;
            }
        }
        Err(failed.unwrap_or_else(|| Failure::NotFound {
            servers: servers
                .iter()
                .map(|server| server.host().to_owned())
                .collect(),
        }))
    }
}

/// Writes `body` to `destination`: to a file beside it first, expanded
/// if `compressed`, verified to be `identity`, then renamed into place.
fn store(
    mut body: impl Read,
    destination: &Path,
    compressed: bool,
    identity: &Identity,
    cancel: &Cancel,
) -> Result<(), Stored> {
    let failed = |error: io::Error| Stored::Store(error.to_string());
    let directory = destination
        .parent()
        .ok_or_else(|| Stored::Store("no directory".to_owned()))?;
    fs::create_dir_all(directory).map_err(failed)?;
    // binbun's own cache, made here first, is tagged as one.
    binbun_paths::tag_cache(directory).map_err(failed)?;
    let download = Partial::beside(destination);
    {
        let mut file = File::create(&download.0).map_err(failed)?;
        let mut buffer = vec![0; 1 << 16];
        loop {
            if cancel.is_cancelled() {
                return Err(Stored::Cancelled);
            }
            let read = body
                .read(&mut buffer)
                .map_err(|error| Stored::Network(error.to_string()))?;
            let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
                break;
            };
            file.write_all(chunk).map_err(failed)?;
        }
        file.sync_all().map_err(failed)?;
    }
    let file = if compressed {
        let expanded = Partial::beside(destination);
        expand(&download.0, &expanded.0).map_err(|error| {
            Stored::Store(format!("cannot expand the compressed file: {error}"))
        })?;
        expanded
    } else {
        download
    };
    identity.verify(&file.0).map_err(Stored::Mismatch)?;
    fs::rename(&file.0, destination).map_err(failed)
}

/// Expands the cabinet at `cabinet` (a compressed PDB: one file) to
/// `out`.
///
/// # Errors
///
/// If it is no cabinet, holds no file, or cannot be read or written.
pub fn expand(cabinet: &Path, out: &Path) -> io::Result<()> {
    let mut cabinet = cab::Cabinet::new(File::open(cabinet)?)?;
    let name = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries())
        .map(|file| file.name().to_owned())
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the cabinet is empty"))?;
    let mut reader = cabinet.read_file(&name)?;
    let mut file = File::create(out)?;
    io::copy(&mut reader, &mut file)?;
    file.sync_all()
}

/// A file being written beside its place, removed unless renamed.
struct Partial(PathBuf);

impl Partial {
    /// A name of its own beside `destination` (hidden, with the process
    /// and a counter, so concurrent fetches never share one).
    fn beside(destination: &Path) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = destination
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(destination.with_file_name(format!(".{name}.{}.{n}.partial", process::id())))
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        // Gone already once renamed into place.
        let _ = fs::remove_file(&self.0);
    }
}
