//! What crosses the socket: the methods a server answers ([`method`]),
//! their parameters and results, and the notifications it sends
//! ([`notification`]). Over the socket go the writes, transactions, undo
//! and history, events, the GUI's cursor and selection, cheap reads
//! (functions' entries and names, names, comments, bookmarks, a
//! function's C as text) and the change log a client in process follows;
//! everything heavier is read in the client's own process.

use serde::{Deserialize, Serialize};

use crate::hex;
use crate::types::{HistoryItem, RevisionData, Viewed};
use crate::write::Write;

/// The methods, by name.
pub mod method {
    /// The handshake ([`crate::handshake::Initialize`]).
    pub const INITIALIZE: &str = "initialize";
    /// Opens a transaction of the connection ([`super::Begin`]).
    pub const BEGIN: &str = "edits.begin";
    /// Commits it ([`crate::Committed`] as [`super::CommitResult`]).
    pub const COMMIT: &str = "edits.commit";
    /// Rolls it back.
    pub const ROLLBACK: &str = "edits.rollback";
    /// Makes a write ([`super::Apply`] → [`crate::Applied`]).
    pub const APPLY: &str = "edits.apply";
    /// Undoes this install's last change (→ `Option<HistoryItem>`).
    pub const UNDO: &str = "edits.undo";
    /// Makes the last change undone again (→ `Option<HistoryItem>`).
    pub const REDO: &str = "edits.redo";
    /// The history, newest first (→ `Vec<HistoryItem>`).
    pub const HISTORY: &str = "edits.history";
    /// Waits for a new analysis to be swapped in ([`super::Settle`] →
    /// whether none is under way).
    pub const SETTLE: &str = "edits.settle";
    /// Starts the notifications ([`super::Subscribe`]).
    pub const SUBSCRIBE: &str = "events.subscribe";
    /// The GUI's cursor, moved first if an address is given
    /// ([`super::Cursor`] → [`super::Cursor`]).
    pub const CURSOR: &str = "ui.cursor";
    /// The GUI's selection (→ `Option<Span>`).
    pub const SELECTION: &str = "ui.selection";
    /// A page of the functions ([`super::ListFunctions`] →
    /// [`super::FunctionPage`]).
    pub const FUNCTIONS: &str = "functions.list";
    /// Every function's entry, packed ([`super::Entries`]).
    pub const ENTRIES: &str = "functions.entries";
    /// One function ([`super::At`] → `Option<FunctionInfo>`).
    pub const FUNCTION: &str = "functions.info";
    /// The functions whose blocks hold an address, by entry ([`super::At`]
    /// → `Vec<FunctionInfo>`).
    pub const CONTAINING: &str = "functions.containing";
    /// The name of an address ([`super::At`] → `Option<String>`).
    pub const NAME: &str = "names.get";
    /// Every comment (→ `Vec<Note>`).
    pub const COMMENTS: &str = "comments.all";
    /// Every bookmark (→ `Vec<Note>`).
    pub const BOOKMARKS: &str = "bookmarks.all";
    /// A function's C as text ([`super::Text`] → `String`).
    pub const TEXT: &str = "c.text";
    /// The signed changes the client lacks ([`super::ChangesSince`] →
    /// [`super::Changes`]).
    pub const CHANGES_SINCE: &str = "sync.changes_since";
    /// Where an agent's code works ([`super::Presence`] → `null`): its
    /// cursor in the GUI, as a collaborator's (an agent connection only).
    pub const PRESENCE: &str = "presence.set";
    /// Who is in the session, people and agents (→
    /// `Vec<`[`super::Member`]`>`).
    pub const MEMBERS: &str = "session.members";
}

/// The notifications, by name.
pub mod notification {
    /// Changes entered the history ([`super::HistoryNote`]).
    pub const HISTORY: &str = "event.history";
    /// Documents or listing lines changed ([`super::ChangedNote`]).
    pub const CHANGED: &str = "event.changed";
    /// A stage was reached ([`super::StageNote`]).
    pub const STAGE: &str = "event.stage";
    /// A new analysis was swapped in ([`super::ReanalysedNote`]).
    pub const REANALYSED: &str = "event.reanalysed";
}

/// `edits.begin`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Begin {
    /// The undo step's label.
    pub label: String,
    /// Who makes it (`script:<name>`, `plugin:<id>`, `agent`, `user`);
    /// the connection's author if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// `edits.commit`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitResult {
    /// The change made (none for an inner transaction or one that wrote
    /// nothing).
    pub entry: Option<HistoryItem>,
    /// Whether the binary is being analysed anew.
    pub reanalysing: bool,
}

/// `edits.apply`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Apply {
    /// The write.
    pub write: Write,
}

/// `presence.set`'s parameters: the address an agent's code works at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    /// The address.
    #[serde(default, with = "hex::option")]
    pub address: Option<u64>,
}

/// Someone in the session (`session.members`): a person or an agent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Their identity key, hexadecimal: whom a `Mention` names.
    pub key: String,
    /// Their name.
    pub name: String,
    /// `person` or `agent`.
    pub kind: String,
    /// Their role in the shared project (`owner`, `editor`, `viewer`,
    /// `agent`), if it is shared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Whether they are here now.
    pub online: bool,
    /// Whether it is the server's own user.
    #[serde(default)]
    pub you: bool,
}

/// `edits.settle`'s parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settle {
    /// How long to wait, in milliseconds.
    pub timeout_ms: u64,
}

/// `events.subscribe`'s parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscribe {
    /// The notifications wanted (`event.history`...); all if empty.
    #[serde(default)]
    pub kinds: Vec<String>,
}

/// `ui.cursor`'s parameters (the address to move to, if any) and result
/// (where the cursor is; none without a GUI pane showing the binary).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The address.
    #[serde(default, with = "hex::option")]
    pub address: Option<u64>,
}

/// An address range: `start` up to, not including, `end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// Its first address.
    #[serde(with = "hex")]
    pub start: u64,
    /// The address after its last.
    #[serde(with = "hex")]
    pub end: u64,
}

/// `functions.list`'s parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListFunctions {
    /// The functions with entries above this one (from the first if
    /// none).
    #[serde(default, with = "hex::option")]
    pub after: Option<u64>,
    /// How many at most.
    pub limit: usize,
}

/// A function as the cheap reads give it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// Its entry.
    #[serde(with = "hex")]
    pub entry: u64,
    /// Its name: the user's, else the image's, else `sub_XXXX`.
    pub name: String,
    /// The user's name, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    /// Where its name comes from (`binbun_session::signatures::NameSource`'s
    /// name: `user`, `script`, `plugin`, `agent`, `signature`, `symbol`,
    /// `debug`); none for binbun's own (`sub_XXXX`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_source: Option<String>,
    /// Its blocks' address ranges, merged, in order.
    pub ranges: Vec<Span>,
}

/// `functions.list`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionPage {
    /// The functions, by entry.
    pub items: Vec<FunctionInfo>,
    /// The entry to ask after for the next page; none after the last.
    #[serde(default, with = "hex::option")]
    pub next: Option<u64>,
    /// The revision read.
    pub revision: RevisionData,
}

/// `functions.entries`' result: every function's entry, in order, packed
/// as little-endian `u64`s in base64 (one string, not a list of 1,801).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entries {
    /// The entries.
    pub entries: String,
    /// The revision read.
    pub revision: RevisionData,
}

/// An address as a parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct At {
    /// The address.
    #[serde(with = "hex")]
    pub address: u64,
}

/// A comment or bookmark: where, and its text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// Where.
    #[serde(with = "hex")]
    pub address: u64,
    /// The text.
    pub text: String,
}

/// `c.text`'s parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Text {
    /// The function's entry.
    #[serde(with = "hex")]
    pub entry: u64,
    /// The view.
    #[serde(default)]
    pub view: Viewed,
}

/// How far a client knows one chain of changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Known {
    /// The chain, hexadecimal.
    pub chain: String,
    /// The changes known of it.
    pub seq: u64,
}

/// `sync.changes_since`'s parameters: what the client knows.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesSince {
    /// Its frontier.
    #[serde(default)]
    pub frontier: Vec<Known>,
}

/// `sync.changes_since`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changes {
    /// What the changes' chains are of.
    pub binding: Binding,
    /// The signed changes the client lacks ([`crate::sync::encode`]).
    pub changes: Vec<String>,
}

/// What a session's chains are of: a binary (the whole file's SHA-256,
/// hexadecimal, and the slice of a universal file), or a set log (no
/// digest).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The binary's SHA-256, hexadecimal.
    pub sha256: Option<String>,
    /// The slice's architecture, of a universal file.
    pub slice: Option<String>,
}

/// `event.history`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryNote {
    /// The changes, newest first.
    pub entries: Vec<HistoryItem>,
}

/// `event.changed`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedNote {
    /// The functions whose C reads differently now, by entry.
    #[serde(with = "hex::list")]
    pub functions: Vec<u64>,
    /// The address ranges whose listing lines read differently.
    pub listing: Vec<Span>,
}

/// `event.stage`'s parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageNote {
    /// The stage reached (`binbun.Stage`'s value).
    pub stage: u8,
}

/// `event.reanalysed`'s parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReanalysedNote {
    /// The new analysis's revision.
    pub revision: RevisionData,
}
