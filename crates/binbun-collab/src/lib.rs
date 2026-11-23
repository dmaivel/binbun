//! binbun's collaboration: a project's edit log
//! ([`binbun_session::journal`]) shared between peers, end-to-end
//! encrypted, over a transport that proves who each peer is.
//!
//! - [`crypto`]: epoch keys, change envelopes (XChaCha20-Poly1305, on
//!   [`binbun_sync::envelope`]), key wraps (HPKE), history links.
//! - [`membership`]: the owner's membership chain, roles, cuts and
//!   epochs, checked by every peer alike.
//! - [`authority`]: the membership chain as the journal's authority:
//!   what is taken, not yet, or never.
//! - [`ticket`]: join tickets and identity cards, which hold no secret.
//! - [`transport`]: the [`Transport`] trait and its framing; [`net`]
//!   puts it on iroh, [`mem`] in memory for tests.
//! - [`wire`]: the messages, each kind's frame limit, and the one
//!   encoder and decoder of them; every type decoded from bytes another
//!   party wrote holds only bounded lists and strings ([`bounded`]). The
//!   sync lane's are [`binbun_sync::Sync`].
//! - [`Peer`]: a session shared or joined: the owner adds members by
//!   their cards (or approves ticket holders live, if asked to); peers
//!   sync the log through [`binbun_sync::Machine`] (tips and pulls of
//!   signed heads, forks proved and spread), and every change taken is
//!   judged against the membership chain as the journal takes it.
//! - [`live`]: the live session beside the log: who is there, their
//!   cursors (presence datagrams), the session's chat; never persisted.
//! - [`blob`], [`blobs`]: files by hash (the binary, debug files) sealed
//!   as blobs (STREAM over Padmé-padded plaintext, a key per blob), kept
//!   and fetched with iroh-blobs over the peers' links, offered only if
//!   the sharer chose to send them.
//! - [`fetches`]: where a file fetched is kept while it comes (binbun's
//!   cache) and once whole (where the user chose, or binbun's downloads
//!   folder, under a name binbun gives it).
//! - [`budgets`]: what a remote party can make this process spend, hard
//!   ceilings and members' default rates, each given back by a guard.
//!
//! `binbun-session` knows nothing of this crate: a peer drives a session
//! through its journal's points ([`binbun_session::Session::tip`],
//! [`binbun_session::Session::changes_after`],
//! [`binbun_session::Session::receive`] and the rest) and judges what it
//! takes through the [`binbun_session::journal::Authority`] it attaches.

pub mod authority;
pub mod blob;
pub mod blobs;
pub mod budgets;
pub mod crypto;
pub mod fetches;
mod link;
pub mod live;
pub mod mem;
pub mod membership;
pub mod net;
mod peer;
mod share;
mod store;
pub mod ticket;
pub mod transport;
pub mod wire;

use std::fmt;

pub use binbun_bounded as bounded;
pub use peer::{
    Approver, Config, Flushed, Listable, Notice, Notifier, Peer, Received, Request, listable,
};
pub use transport::Transport;

/// What went wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    /// An error saying `message`.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<bounded::Error> for Error {
    fn from(error: bounded::Error) -> Self {
        Self(error.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}
