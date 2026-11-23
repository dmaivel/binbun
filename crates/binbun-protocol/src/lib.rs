//! binbun's client protocol: what a client of an opened binary (a Python
//! script in process or connected to the GUI, later an MCP server) says
//! and is told, framework-free. It owns no domain logic: that stays in
//! `binbun-session`.
//!
//! - [`write`]: every write a client makes as data ([`Write`]) and what
//!   it does to a session.
//! - [`host`]: transactions owned by one client, each one undo step;
//!   writes outside one, each its own; undo and redo; corrections
//!   analysed anew and swapped in ([`Host`]).
//! - [`fault`]: why a request failed, one kind per Python exception
//!   ([`Fault`]).
//! - [`hex`]: addresses as `"0x…"` strings on the wire.
//! - The socket: [`framing`] (length-prefixed messages), [`rpc`]
//!   (JSON-RPC 2.0), [`handshake`] (versions and capabilities),
//!   [`messages`] (the methods and notifications), [`sync`] (the change
//!   log), [`discovery`] (where servers are found), [`server`] and
//!   [`client`], over a Unix socket (`socket`; on Windows a named pipe).
//! - [`talk`]: threads, posts and suggestions (`threads.*`,
//!   `suggestions.*`), answered alike by a server and in process.

pub mod base64;
pub mod client;
pub mod discovery;
pub mod fault;
pub mod framing;
pub mod handshake;
pub mod hex;
pub mod host;
pub mod messages;
pub mod rpc;
pub mod server;
mod socket;
pub mod sync;
pub mod talk;
pub mod types;
pub mod write;

pub use fault::{Fault, FaultKind};
pub use host::{Committed, Host, Owner, USER};
pub use types::{AuthorData, HistoryItem, RevisionData, Viewed, stage_number};
pub use write::{Applied, Correction, Member, VariableRef, Write};
