//! Debug information from symbol servers in a session
//! ([`Options::symbols`](crate::Options::symbols)): found in a local store
//! without asking anyone, else offered ([`Download::Ask`]) or fetched at
//! once ([`Download::Always`]) on a thread of its own while the analysis
//! goes on, never under [`Download::Never`]. What becomes of it is told as
//! [`Event::Symbols`]; a fetched file is taken by a session opened with it
//! ([`Session::with_debug`](crate::Session::with_debug)), as the binary's
//! debug information is read before its functions are recovered.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use binbun_debuginfo::symbols::{Cancel, Config, Failure, Identity};

use crate::Event;
use crate::worker::Shared;

/// Whether a session may fetch debug information from a symbol server: a
/// request tells the server which binary is analysed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Download {
    /// Offer it ([`SymbolState::Available`]); fetch when the front end
    /// says so ([`Session::fetch_symbols`](crate::Session::fetch_symbols)).
    Ask,
    /// Fetch it as soon as the image is parsed.
    Always,
    /// Never fetch (local stores are still read).
    #[default]
    Never,
}

/// Debug information from symbol servers: whether it may be fetched, and
/// where it is looked for and fetched from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbols {
    /// Whether it may be fetched.
    pub download: Download,
    /// The local stores and the servers.
    pub config: Config,
}

impl Default for Symbols {
    /// Never fetched; the stores and servers the environment says
    /// ([`Config::from_environment`]).
    fn default() -> Self {
        Self {
            download: Download::Never,
            config: Config::from_environment(),
        }
    }
}

/// What became of the binary's debug information on a symbol server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymbolState {
    /// No local store has it; `server` is where it would be fetched from
    /// (nothing is sent until [`Session::fetch_symbols`](crate::Session::fetch_symbols)).
    Available {
        /// The binary's file name.
        binary: String,
        /// The server (its host).
        server: String,
    },
    /// Being fetched from `server`.
    Fetching {
        /// The binary's file name.
        binary: String,
        /// The server (its host).
        server: String,
    },
    /// Fetched, verified and stored at `path`.
    Fetched {
        /// The binary's file name.
        binary: String,
        /// Where it is stored.
        path: PathBuf,
        /// The server it came from (its host).
        server: String,
    },
    /// Not fetched: why, in one line.
    Failed {
        /// The binary's file name.
        binary: String,
        /// Why ([`Failure`]'s text).
        reason: String,
    },
}

/// The binary's debug information as the session knows it on servers.
#[derive(Debug, Default)]
pub(crate) struct Slot {
    /// What the binary needs, once no local store had it and fetching is
    /// allowed.
    identity: Option<Identity>,
    /// What became of it (as told, [`Event::Symbols`], once the slot's
    /// lock is let go).
    state: Option<SymbolState>,
}

/// The file `identity` names from a local store, if one has it (nothing
/// sent).
pub(crate) fn local(shared: &Shared, identity: &Identity) -> Option<PathBuf> {
    shared.symbols.config.locate(identity)
}

/// Offers `identity`, which no local store has, as the session's
/// [`Download`] says: nothing under [`Download::Never`] or without a
/// server; [`SymbolState::Available`] under [`Download::Ask`]; a fetch
/// under [`Download::Always`].
pub(crate) fn offer(shared: &Arc<Shared>, identity: Identity) {
    if shared.symbols.download == Download::Never {
        return;
    }
    let Some(server) = shared.symbols.config.servers(&identity).first() else {
        return;
    };
    let state = SymbolState::Available {
        binary: binary(shared),
        server: server.host().to_owned(),
    };
    {
        let mut slot = shared.symbol_slot();
        slot.identity = Some(identity);
        slot.state = Some(state.clone());
    }
    shared.emit(&Event::Symbols(state));
    if shared.symbols.download == Download::Always {
        fetch(shared);
    }
}

/// The state last told, if the session has one.
pub(crate) fn state(shared: &Shared) -> Option<SymbolState> {
    shared.symbol_state()
}

/// Starts fetching the debug information offered, on a thread of its
/// own (again after a failure); whether it started (not if nothing is
/// offered or a fetch is running or done).
pub(crate) fn fetch(shared: &Arc<Shared>) -> bool {
    let (identity, fetching) = {
        let mut slot = shared.symbol_slot();
        let Some(identity) = slot.identity.clone() else {
            return false;
        };
        let server = match &slot.state {
            Some(SymbolState::Available { server, .. }) => server.clone(),
            Some(SymbolState::Failed { .. }) => shared
                .symbols
                .config
                .servers(&identity)
                .first()
                .map(|server| server.host().to_owned())
                .unwrap_or_default(),
            Some(SymbolState::Fetching { .. } | SymbolState::Fetched { .. }) | None => {
                return false;
            }
        };
        let state = SymbolState::Fetching {
            binary: binary(shared),
            server,
        };
        slot.state = Some(state.clone());
        (identity, state)
    };
    shared.emit(&Event::Symbols(fetching));
    let kept = Arc::clone(shared);
    let started = thread::Builder::new()
        .name("binbun-symbols".to_owned())
        .spawn(move || {
            let shared = kept;
            let cancel = Cancel::from(Arc::clone(&shared.cancelled));
            let result = shared.symbols.config.fetch(&identity, &cancel);
            let binary = binary(&shared);
            let state = match result {
                Ok(fetched) => SymbolState::Fetched {
                    binary,
                    path: fetched.path,
                    server: fetched.server.host().to_owned(),
                },
                Err(Failure::Cancelled) => return,
                Err(failure) => SymbolState::Failed {
                    binary,
                    reason: failure.to_string(),
                },
            };
            shared.symbol_slot().state = Some(state.clone());
            shared.emit(&Event::Symbols(state));
        });
    if let Err(error) = started {
        let state = SymbolState::Failed {
            binary: binary(shared),
            reason: format!("cannot start a thread: {error}"),
        };
        shared.symbol_slot().state = Some(state.clone());
        shared.emit(&Event::Symbols(state));
    }
    true
}

/// The binary's file name.
fn binary(shared: &Shared) -> String {
    shared.path.file_name().map_or_else(
        || shared.path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}
