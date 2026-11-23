//! The handshake (`initialize`): the client sends the protocol versions
//! it speaks, who it is and which of the server's databases it means;
//! the server answers with the highest
//! version both speak, its capabilities and the databases it has open, or
//! refuses ([`FaultKind::Version`]: Python's `VersionError`).

use serde::{Deserialize, Serialize};

use crate::fault::{Fault, FaultKind};
use crate::types::RevisionData;

/// The protocol's version (an integer major: within one, servers only add
/// capabilities).
pub const PROTOCOL_VERSION: u32 = 1;

/// The capabilities, by name: each gates methods, and a client checks the
/// one a call needs before sending it.
pub mod capability {
    /// Writes and transactions: `edits.begin`, `edits.commit`,
    /// `edits.rollback`, `edits.apply`, `edits.settle`.
    pub const WRITES: &str = "writes";
    /// Undo, redo and the history: `edits.undo`, `edits.redo`,
    /// `edits.history`.
    pub const UNDO: &str = "undo";
    /// Notifications: `events.subscribe`.
    pub const EVENTS: &str = "events";
    /// The cheap reads: `functions.list`, `functions.info`,
    /// `functions.containing`, `names.get`, `comments.all`,
    /// `bookmarks.all`.
    pub const READS: &str = "reads";
    /// A function's C as text: `c.text`.
    pub const C_TEXT: &str = "c.text";
    /// The change log: `sync.changes_since`.
    pub const SYNC: &str = "sync";
    /// The GUI's cursor and selection: `ui.cursor`, `ui.selection` (a GUI
    /// only).
    pub const UI: &str = "ui.cursor";
    /// The unstable IR (no server of this crate has it).
    pub const IR: &str = "ir.unstable";
    /// Threads anchored to addresses and their posts: `threads.*`, and
    /// the notifications `event.thread`, `event.mentioned`.
    pub const THREADS: &str = "threads";
    /// Suggestions, made, superseded, accepted, dismissed, their evidence
    /// asked again: `suggestions.*`.
    pub const SUGGESTIONS: &str = "suggestions";
    /// Who is in the session: `session.members`; and an agent's place:
    /// `presence.set`.
    pub const MEMBERS: &str = "session.members";

    /// What every server of this crate has; a GUI adds [`UI`].
    pub const SERVED: [&str; 9] = [
        WRITES,
        UNDO,
        EVENTS,
        READS,
        C_TEXT,
        SYNC,
        THREADS,
        SUGGESTIONS,
        MEMBERS,
    ];
}

/// A database a server has open.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// Its number on this server.
    pub id: u64,
    /// The binary's path.
    pub path: String,
    /// Its file name.
    pub name: String,
    /// Its SHA-256 (hexadecimal), once read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The debug information file its analysis read, if one (a client
    /// opening the binary in process reads the same).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<String>,
    /// The slice open of a universal Mach-O file (`x86_64`, `arm64e`), if
    /// the binary is one (a client opening it in process opens the same).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// The stage its analysis reached (`binbun.Stage`'s value).
    pub stage: u8,
    /// Its revision.
    pub revision: RevisionData,
    /// When its window last had the focus (milliseconds since the Unix
    /// epoch), if a GUI shows it: a client naming no database attaches to
    /// the one focused last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focused: Option<u64>,
}

/// `initialize`'s parameters: who the client is, what it speaks, which
/// database it means.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initialize {
    /// The client (`binbun-py/0.4.0`).
    pub client: String,
    /// The protocol versions it speaks: lowest and highest.
    pub protocol: [u32; 2],
    /// The Python surface's version it has (informational).
    pub api: [u32; 2],
    /// The database it means (its [`DatabaseInfo::id`]); the only one
    /// open if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<u64>,
    /// Who makes the writes made outside a transaction (`script:<name>`,
    /// `plugin:<id>`, `agent`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// The agent this connection is (`Codex`, `Claude Code`), if one: a
    /// participant with its own key, held by the server's install, which
    /// signs its writes (made by `agent`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentHello>,
}

/// An agent saying who it is at `initialize`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHello {
    /// Its name (`Codex`).
    pub name: String,
    /// Its version, if it said (`0.98.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `initialize`'s result.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initialized {
    /// The server (`binbun-gui/0.4.0`).
    pub server: String,
    /// The protocol version chosen.
    pub protocol: u32,
    /// The engine's version.
    pub engine: String,
    /// What it can do.
    pub capabilities: Vec<String>,
    /// The databases it has open.
    pub databases: Vec<DatabaseInfo>,
    /// The one this connection reads and writes.
    pub database: DatabaseInfo,
    /// The identity key (hexadecimal) the server's changes are signed by:
    /// whom a mention names to reach this server's scripts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// The agent's identity key (hexadecimal), if the client is one
    /// ([`Initialize::agent`]): its writes are signed by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

/// The version both speak: the highest of the client's range that the
/// server's (`1..=PROTOCOL_VERSION`) has.
///
/// # Errors
///
/// None ([`FaultKind::Version`]).
pub fn negotiate(client: [u32; 2]) -> Result<u32, Fault> {
    let [low, high] = client;
    let chosen = high.min(PROTOCOL_VERSION);
    if low > high || chosen < low || chosen == 0 {
        return Err(Fault::new(
            FaultKind::Version,
            format!(
                "no common protocol version: the client speaks {low}..={high}, the server 1..={PROTOCOL_VERSION}"
            ),
        ));
    }
    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::{PROTOCOL_VERSION, negotiate};
    use crate::fault::FaultKind;

    #[test]
    fn the_highest_common_version_is_chosen_or_none_is() {
        assert_eq!(negotiate([1, 1]).unwrap(), 1);
        assert_eq!(negotiate([1, 9]).unwrap(), PROTOCOL_VERSION);
        for refused in [[2, 2], [0, 0], [3, 1]] {
            assert_eq!(negotiate(refused).unwrap_err().kind, FaultKind::Version);
        }
    }
}
