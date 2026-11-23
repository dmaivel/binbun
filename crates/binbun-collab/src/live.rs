//! The live session: who is there,
//! what binbun and analysis each runs, where each one's cursor is, whom
//! each follows, and the session's chat. None of it is the project's: it
//! lives in memory while the session does and is never written to the
//! log or anywhere else.
//!
//! - **Presence** travels in datagrams ([`crate::transport::Link`]):
//!   `nonce:24 ‖ XChaCha20-Poly1305(postcard(Presence))` under the
//!   epoch's `presence` subkey, at most [`MAX_PRESENCE`] bytes of
//!   plaintext, so at most [`MAX_DATAGRAM`] on the wire. A peer's cursor
//!   is coalesced to at most one datagram per [`EVERY`] (20 per second),
//!   the latest winning; a heartbeat ([`What::Here`]) goes every
//!   [`HEARTBEAT`]; a cursor not heard of for [`GONE`] is stale. Each
//!   sender numbers its datagrams; older ones are dropped.
//! - **Who is there and chat** travel on the [`crate::transport::Lane::Live`]
//!   lane, reliably, each frame `nonce:24 ‖ AEAD(postcard(Said))` under
//!   the epoch's `live` subkey (no name or chat in plaintext above TLS,
//!   as the log's): each side's [`Hi`] (identity card, binbun, analysis
//!   fingerprint) when the link comes up and when its analysis changes;
//!   chat messages of at most [`MAX_CHAT`] bytes of text, one a second
//!   with bursts of five.
//!   A message carries the places its text names, resolved by its author
//!   when sent ([`ChatLink`]: a byte range of the text and an address, so
//!   a later rename keeps them), and whom it @mentions.
//!   Each peer keeps the last [`BACKLOG`] messages it took, in the order
//!   it took them (whatever time their authors' clocks give), in memory
//!   and gives them to whoever links to it, so a late joiner sees what
//!   the host saw; it takes each message once, by its id, of the last
//!   [`CHAT_SEEN`].
//! - **Authors**: every member holds the live and presence keys, so the
//!   keys prove nothing of who speaks. Each introduction, presence
//!   datagram and chat message is signed by its author's identity key,
//!   over a label of its kind, the share's genesis (the hash of the
//!   membership chain's first record), the author, their run
//!   ([`Hi::run`]: random, new each time they come) and number, and what
//!   it says; never the routing project id, which two shares can have
//!   (a home log shared twice). Nothing is signed or taken before this
//!   peer holds the genesis. A peer shows, keeps and forwards one only if
//!   the signature holds under its own share's genesis (one made in
//!   another share is dropped, its author a member of both or not) and
//!   its author is a member in the owner-signed membership chain (not
//!   removed, not a store: [`Role::Store`]); one whose author the chain
//!   does not name yet waits for it as long as for the keys (a joiner's
//!   come on the sync lane). Whether a participant is an agent is their
//!   role in the chain
//!   ([`Participant::agent`]), whatever their [`Hi`] says.
//! - **Replays**: a peer keeps the number of the last introduction it
//!   took of each run of a participant's, and of their last datagram,
//!   after they leave too. An introduction no newer than one taken of its
//!   run (one of theirs given again, or replayed) shows them only once a
//!   datagram newer than any taken of that run comes by the same link.
//! - **Routes**: a participant is kept with the link that brought them
//!   ([`Participant::via`]): their own, or the first that forwarded them.
//!   Another link's forwarding of them is dropped: it does not take the
//!   place of the route, their own link does. Their presence and their
//!   leaving ([`Said::Gone`]) are taken from that link only.
//! - **Limits** on what comes ([`crate::budgets`]): frames of at most 16
//!   KiB, each reserved before it is read; per member's link, 64 frames
//!   and 256 KiB a second (bursts of 512 frames and 1 MiB), 1,000
//!   datagrams a second; per participant, 40 datagrams a second; per
//!   author, chat as its sender limits it (past one backlog's worth of
//!   messages, given when the link comes up, that fills again over five
//!   minutes). These rates are kept by identity, so linking again does
//!   not fill them. [`crate::budgets::LINK_STREAMS`] blob streams of a
//!   link are served at once; others are refused. State is kept for
//!   members only. What this peer sends a link waits in a queue of
//!   [`LANE_QUEUE`] frames past the link's greeting; a link that falls
//!   further behind is closed.
//! - **Moderation**: the owner removes a chat message
//!   ([`Peer::remove_chat`]): [`Said::Removed`], signed by the owner's
//!   identity key, over the share's genesis and the message's id, author,
//!   time and number;
//!   forwarded like a message and given to late joiners in place of the
//!   message. Every peer drops the message's text and shows it "removed
//!   by the owner" ([`ChatMessage::removed`]), also one that comes after
//!   its removal, or never.
//!
//! Sessions are a star around their host: a peer forwards what one link
//! brings it to its other links (each datagram once, by its number), and
//! says who left when a link goes ([`Said::Gone`]).
//!
//! - **Agents** connected to a peer's window are participants too: the
//!   peer speaks for each one that is a member ([`Peer::host_agents`]),
//!   with its [`Hi`] (the agent's own card; [`Hi::agent`] says which
//!   harness it is) and its presence datagrams, numbered apart, with a
//!   heartbeat of their own, all signed with the agent's identity, which
//!   the peer holds; and [`Said::Gone`] when it disconnects or is
//!   removed. Its host's links bring it, so it goes when they do.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use binbun_bounded::{self as bounded, Bounded, Bounds, Text};
use binbun_session::identity::Identity;
use binbun_session::journal::{EngineVersion, PublicKey};
use binbun_sync::{LinkId, Phase};
use chacha20poly1305::XChaCha20Poly1305;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use zeroize::Zeroizing;

use crate::Error;
use crate::budgets::LinkBudget;
use crate::crypto;
use crate::membership::Role;
use crate::peer::{Inner, Peer};
use crate::ticket::{self, Card};
use crate::transport::{Lane, Link, read_frame_body, read_frame_length, write_frame};
use crate::wire::{self, Engine, Frame as _, LiveFrame, MAX_LIVE_SEALED};

/// The most bytes of a presence message's plaintext.
pub const MAX_PRESENCE: usize = 192;

/// The most bytes of a presence datagram: the plaintext, a 24-byte nonce
/// and a 16-byte tag.
pub const MAX_DATAGRAM: usize = MAX_PRESENCE + 40;

/// The least time between two cursor datagrams of one peer: at most 20 a
/// second.
pub const EVERY: Duration = Duration::from_millis(50);

/// How often a peer says it is still there.
pub const HEARTBEAT: Duration = Duration::from_secs(5);

/// How long a participant's cursor is shown unheard of.
pub const GONE: Duration = Duration::from_secs(15);

/// The chat messages kept, newest last.
pub const BACKLOG: usize = 100;

/// The chat message ids remembered, the last taken, to take each message
/// once.
pub const CHAT_SEEN: usize = 16 * BACKLOG;

/// The most bytes of a chat message's text.
pub const MAX_CHAT: usize = 2048;

/// The most links and the most mentions a chat message carries.
pub const MAX_CHAT_LINKS: usize = 64;

/// The frames a link's live lane may fall behind by, past its greeting,
/// before the link is closed.
pub const LANE_QUEUE: usize = 256;

/// The most characters of a binbun's release or build, an agent's
/// version, or a debug file's name, as a participant tells them.
const MAX_LABEL: usize = 128;

/// The most bytes of those: [`MAX_LABEL`] characters of four bytes.
const LABEL_BYTES: usize = wire::MAX_LABEL;

/// The most bytes of a [`Said`]'s postcard: sealed, a nonce and a tag
/// more, it fits a live frame.
const MAX_SAID: usize = MAX_LIVE_SEALED - 40;

/// The runs of a participant's whose last numbers are kept.
const RUNS: usize = 8;

/// Datagram numbers remembered per sender, to forward each once.
const SEEN: usize = 64;

/// How long a live frame that does not open, or whose author the
/// membership chain does not name, waits for this peer's keys and chain
/// (a joiner's come on the sync lane).
const KEYS_WAIT: Duration = Duration::from_secs(10);

/// How often a live frame waiting for this peer's keys looks again.
const KEYS_POLL: Duration = Duration::from_millis(20);

/// Where in the binary a participant's cursor is, and in which view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Place {
    /// The listing.
    Listing,
    /// A function's C: its entry, the view (reading or exact), the line.
    C {
        /// The function's entry.
        function: u64,
        /// The reading view (else the exact one).
        reading: bool,
        /// The line, from 0.
        line: u32,
    },
    /// The hex view.
    Hex,
    /// A function's graph: its entry.
    Graph {
        /// The function's entry.
        function: u64,
    },
    /// A list of cross-references.
    Xrefs,
}

/// A participant's cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cursor {
    /// The view it is in.
    pub place: Place,
    /// Its address.
    pub address: u64,
    /// Its column on its line, in characters: where its caret is drawn
    /// (in the listing, on the listing's line; in the C, on the C line).
    pub column: u32,
    /// What is selected, if anything.
    pub selection: Option<Selection>,
}

/// A participant's selection, in their view's units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Selection {
    /// Addresses: the items of the listing's lines selected, the hex
    /// view's bytes.
    Addresses {
        /// The first.
        first: u64,
        /// The last.
        last: u64,
    },
    /// The C's text, on [`Place::C`]'s function and view: from a line and
    /// column to another, in characters, the end excluded.
    Text {
        /// Where it starts: line, column.
        from: (u32, u32),
        /// Where it ends: line, column.
        to: (u32, u32),
    },
}

/// What a presence datagram says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum What {
    /// Still here (the heartbeat), following this participant.
    Here {
        /// The participant followed, if any.
        following: Option<PublicKey>,
    },
    /// The cursor moved.
    Cursor(Cursor),
    /// Leaving.
    Bye,
}

/// A presence datagram's plaintext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    /// Who says it.
    pub from: PublicKey,
    /// Their run that says it ([`Hi::run`]).
    pub run: u64,
    /// Its number among the run's: an older one is dropped.
    pub seq: u32,
    /// What it says.
    pub what: What,
    /// `from`'s signature of `"binbun/v1/presence" ‖ genesis ‖
    /// postcard((from, run, seq, what))`.
    #[serde(with = "wire::signature")]
    pub sig: Signature,
}

impl Bounds for Presence {}

/// A debug file as a participant's analysis read it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DebugRef {
    /// Its file name.
    pub name: Text<LABEL_BYTES>,
    /// Its SHA-256.
    pub sha256: [u8; 32],
}

/// What a participant's analysis is.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Analysis {
    /// The analysis fingerprint ([`binbun_session::Session::fingerprint`]).
    pub fingerprint: [u8; 32],
    /// The debug file read, if any.
    pub debug: Option<DebugRef>,
}

/// A participant introduced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hi {
    /// Their identity card.
    pub card: Card,
    /// The binbun they run.
    pub engine: Engine,
    /// Their analysis, once made.
    pub analysis: Option<Analysis>,
    /// Their cursor when they said hi (presence after it comes in
    /// datagrams), so one following them goes there at once.
    pub cursor: Option<Cursor>,
    /// The participant they follow.
    pub following: Option<PublicKey>,
    /// What they say of themselves if they are an agent (whose host
    /// speaks for it): shown only for a member the membership chain makes
    /// an agent.
    pub agent: Option<Agent>,
    /// Their run: random, new each time they come (a peer's session, an
    /// agent's time on a window). Their presence names it.
    pub run: u64,
    /// Its number among the run's introductions: an older one is dropped.
    pub n: u64,
    /// The card's key's signature of `"binbun/v1/hi" ‖ genesis ‖
    /// postcard((card, engine, analysis, cursor, following, agent, run,
    /// n))`.
    #[serde(with = "wire::signature")]
    pub sig: Signature,
}

/// What an agent participant says of itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Agent {
    /// Its harness's version, if it said.
    pub version: Option<Text<LABEL_BYTES>>,
}

/// An agent connected to this peer's window, which this peer speaks for
/// ([`Peer::host_agents`]).
#[derive(Clone, Debug)]
pub struct HostedAgent {
    /// Its identity, which this peer holds: it signs the agent's card and
    /// what this peer says for it.
    pub identity: Identity,
    /// Its name.
    pub name: String,
    /// What it says of itself.
    pub agent: Agent,
    /// Where its code works, if anywhere yet.
    pub cursor: Option<Cursor>,
}

/// What the live lane carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Said {
    /// A participant: the sender, or one it forwards.
    Hi(Box<Hi>),
    /// A participant forwarded before left.
    Gone(PublicKey),
    /// A chat message.
    Chat(ChatMessage),
    /// A chat message removed by the owner.
    Removed(Removal),
    /// A participant's latest presence of its kind, given to one linking
    /// after it came (taken as its datagram is).
    Presence(Presence),
}

impl Bounds for Said {}

/// One chat message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Random: to take each once.
    pub id: u64,
    /// Its author.
    pub from: PublicKey,
    /// When it was sent: Unix milliseconds, the author's clock.
    pub time: u64,
    /// Its number among its author's messages.
    pub seq: u64,
    /// The text.
    pub text: Text<MAX_CHAT>,
    /// The places the text names, as its author resolved them when
    /// sending.
    pub links: Bounded<ChatLink, MAX_CHAT_LINKS>,
    /// Whom it @mentions.
    pub mentions: Bounded<PublicKey, MAX_CHAT_LINKS>,
    /// `from`'s signature of `"binbun/v1/chat" ‖ genesis ‖
    /// postcard((id, from, time, seq, text, links, mentions))`.
    #[serde(with = "wire::signature")]
    pub sig: Signature,
    /// Whether the owner removed it (its text dropped): this peer's
    /// knowledge, never sent.
    #[serde(skip)]
    pub removed: bool,
}

/// A place a chat message's text names: an address or a name its author
/// resolved when sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChatLink {
    /// The text's bytes naming it: its first.
    pub start: u32,
    /// Past its last.
    pub end: u32,
    /// Where it goes.
    pub address: u64,
    /// An ordinary word that is a name (`free`, `read`): drawn as a link
    /// only while Ctrl is held.
    pub word: bool,
}

impl ChatLink {
    /// Whether it is a range of `text` between characters.
    fn fits(&self, text: &str) -> bool {
        let (Ok(start), Ok(end)) = (usize::try_from(self.start), usize::try_from(self.end)) else {
            return false;
        };
        start < end && text.get(start..end).is_some()
    }
}

/// A chat message removed: which, signed by the owner who removed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removal {
    /// The message.
    pub id: u64,
    /// Its author.
    pub from: PublicKey,
    /// When it was sent ([`ChatMessage::time`]).
    pub time: u64,
    /// Its number among its author's ([`ChatMessage::seq`]).
    pub seq: u64,
    /// The owner.
    pub by: PublicKey,
    /// `by`'s signature of `"binbun/v1/chat-removed" ‖ genesis ‖
    /// postcard((id, from, time, seq))`.
    #[serde(with = "wire::signature")]
    pub sig: Signature,
}

impl Removal {
    /// The message it removes, as shown: its text, links and mentions
    /// dropped.
    fn message(&self) -> ChatMessage {
        ChatMessage {
            id: self.id,
            from: self.from,
            time: self.time,
            seq: self.seq,
            text: Text::new(),
            links: Bounded::new(),
            mentions: Bounded::new(),
            sig: unsigned(),
            removed: true,
        }
    }
}

/// What is signed of `body` in the share whose genesis is `genesis`:
/// `label ‖ genesis ‖ postcard(body)`; `None` if it does not encode
/// within a live frame (I2: no body signed is larger than one carried).
fn signed_bytes<T: Serialize>(label: &[u8], genesis: &[u8; 32], body: &T) -> Option<Vec<u8>> {
    let mut bytes = label.to_vec();
    bytes.extend_from_slice(genesis);
    bytes.extend_from_slice(&bounded::encode(body, wire::LIVE_FRAME).ok()?);
    Some(bytes)
}

/// The signature of a value not signed yet.
fn unsigned() -> Signature {
    Signature::from_bytes(&[0; 64])
}

/// What its author signs in the live session.
trait Signed: Sized {
    /// Its author.
    fn author(&self) -> PublicKey;
    /// The bytes signed, in the share whose genesis is `genesis`.
    fn bytes(&self, genesis: &[u8; 32]) -> Option<Vec<u8>>;
    /// Its signature.
    fn sig(&self) -> &Signature;
    /// Its signature, to set.
    fn sig_mut(&mut self) -> &mut Signature;

    /// Signed by `signer` (its author) in the share whose genesis is
    /// `genesis`.
    fn signed(mut self, signer: &SigningKey, genesis: &[u8; 32]) -> Option<Self> {
        let bytes = self.bytes(genesis)?;
        *self.sig_mut() = signer.sign(&bytes);
        Some(self)
    }

    /// Whether its author signed it in the share whose genesis is
    /// `genesis`.
    fn verifies(&self, genesis: &[u8; 32]) -> bool {
        let (Some(bytes), Ok(key)) = (
            self.bytes(genesis),
            VerifyingKey::from_bytes(&self.author().0),
        ) else {
            return false;
        };
        key.verify_strict(&bytes, self.sig()).is_ok()
    }
}

impl Signed for Presence {
    fn author(&self) -> PublicKey {
        self.from
    }
    fn bytes(&self, genesis: &[u8; 32]) -> Option<Vec<u8>> {
        signed_bytes(
            b"binbun/v1/presence",
            genesis,
            &(self.from, self.run, self.seq, &self.what),
        )
    }
    fn sig(&self) -> &Signature {
        &self.sig
    }
    fn sig_mut(&mut self) -> &mut Signature {
        &mut self.sig
    }
}

impl Signed for Hi {
    fn author(&self) -> PublicKey {
        self.card.key
    }
    fn bytes(&self, genesis: &[u8; 32]) -> Option<Vec<u8>> {
        signed_bytes(
            b"binbun/v1/hi",
            genesis,
            &(
                &self.card,
                &self.engine,
                &self.analysis,
                &self.cursor,
                &self.following,
                &self.agent,
                self.run,
                self.n,
            ),
        )
    }
    fn sig(&self) -> &Signature {
        &self.sig
    }
    fn sig_mut(&mut self) -> &mut Signature {
        &mut self.sig
    }
}

impl Signed for ChatMessage {
    fn author(&self) -> PublicKey {
        self.from
    }
    fn bytes(&self, genesis: &[u8; 32]) -> Option<Vec<u8>> {
        signed_bytes(
            b"binbun/v1/chat",
            genesis,
            &(
                self.id,
                self.from,
                self.time,
                self.seq,
                &self.text,
                &self.links,
                &self.mentions,
            ),
        )
    }
    fn sig(&self) -> &Signature {
        &self.sig
    }
    fn sig_mut(&mut self) -> &mut Signature {
        &mut self.sig
    }
}

impl Signed for Removal {
    fn author(&self) -> PublicKey {
        self.by
    }
    fn bytes(&self, genesis: &[u8; 32]) -> Option<Vec<u8>> {
        signed_bytes(
            b"binbun/v1/chat-removed",
            genesis,
            &(self.id, self.from, self.time, self.seq),
        )
    }
    fn sig(&self) -> &Signature {
        &self.sig
    }
    fn sig_mut(&mut self) -> &mut Signature {
        &mut self.sig
    }
}

/// Whether what `hi` tells of its participant's binbun, analysis and
/// harness is plain text ([`ticket::plain`]) of at most [`MAX_LABEL`]
/// characters each.
fn plain_labels(hi: &Hi) -> bool {
    let plain = |text: &str| ticket::plain(text, MAX_LABEL);
    plain_engine(&hi.engine)
        && hi
            .analysis
            .as_ref()
            .and_then(|analysis| analysis.debug.as_ref())
            .is_none_or(|debug| plain(&debug.name))
        && hi
            .agent
            .as_ref()
            .and_then(|agent| agent.version.as_deref())
            .is_none_or(plain)
}

/// Whether `engine`'s release and build are plain text
/// ([`ticket::plain`]) of at most [`MAX_LABEL`] characters each, as a
/// [`Hi`] or a hello tells them.
pub(crate) fn plain_engine(engine: &Engine) -> bool {
    ticket::plain(&engine.release, MAX_LABEL) && ticket::plain(&engine.build, MAX_LABEL)
}

impl ChatMessage {
    /// Removed by the owner: its text, links and mentions dropped.
    fn remove(&mut self) {
        self.text.clear();
        self.links.clear();
        self.mentions.clear();
        self.removed = true;
    }

    /// Of `links`, those that fit `text` (each a range of it between
    /// characters), the first [`MAX_CHAT_LINKS`] of them.
    fn fitting(
        text: &str,
        links: impl IntoIterator<Item = ChatLink>,
    ) -> Bounded<ChatLink, MAX_CHAT_LINKS> {
        Bounded::truncated(
            links
                .into_iter()
                .filter(|link| link.fits(text))
                .take(MAX_CHAT_LINKS)
                .collect(),
        )
    }

    /// Whether it is as a sender makes it: its links fitting
    /// ([`Self::fitting`]; its text and lists are within their bounds as
    /// read).
    fn fits(&self) -> bool {
        self.links.iter().all(|link| link.fits(&self.text))
    }
}

/// A participant as this peer knows them.
#[derive(Clone, Debug)]
pub struct Participant {
    /// Their identity card.
    pub card: Card,
    /// The binbun they run.
    pub engine: EngineVersion,
    /// Their analysis, once told.
    pub analysis: Option<Analysis>,
    /// The member whose link brought them (themselves, if linked).
    pub via: PublicKey,
    /// Their cursor, once told.
    pub cursor: Option<Cursor>,
    /// When it was told.
    pub moved: Option<Instant>,
    /// The participant they follow.
    pub following: Option<PublicKey>,
    /// When they were last heard of.
    pub heard: Instant,
    /// What they say of themselves if the membership chain makes them an
    /// agent ([`Role::Agent`]); `None` for any other member, whatever
    /// they say.
    pub agent: Option<Agent>,
}

impl Participant {
    /// Their cursor, unless not heard of for [`GONE`].
    pub fn live_cursor(&self, now: Instant) -> Option<Cursor> {
        self.cursor
            .filter(|_| now.saturating_duration_since(self.heard) < GONE)
    }
}

/// What the live session tells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiveEvent {
    /// A participant came, or told their analysis anew.
    Hi(PublicKey),
    /// A participant left.
    Gone(PublicKey),
    /// A participant's cursor moved.
    Cursor(PublicKey, Cursor),
    /// A participant's heartbeat: whom they follow.
    Here(PublicKey),
    /// A chat message came (or was sent by this peer).
    Chat(ChatMessage),
    /// The owner removed a chat message (this peer, or another): its id.
    ChatRemoved(u64),
}

/// Hears what the live session tells.
pub type LiveListener = Arc<dyn Fn(&LiveEvent) + Send + Sync>;

/// A new run's number ([`Hi::run`]): random, else the time in
/// nanoseconds.
fn new_run() -> u64 {
    crypto::random().map_or_else(
        |_| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| {
                    u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
                })
        },
        u64::from_le_bytes,
    )
}

/// What this peer says of itself.
#[derive(Debug)]
struct Mine {
    cursor: Option<Cursor>,
    following: Option<PublicKey>,
    analysis: Option<Analysis>,
    /// A cursor not sent yet.
    pending: bool,
    /// A heartbeat (whom it follows) not sent yet.
    here: bool,
    /// When the last presence finished going (to every link), so the
    /// next waits [`EVERY`] from there: the spacing holds on the wire
    /// however long sealing and sending took.
    sent: Option<Instant>,
    seq: u32,
    /// This peer's run ([`Hi::run`]).
    run: u64,
    /// The introductions it made.
    said: u64,
}

impl Default for Mine {
    fn default() -> Self {
        Self {
            cursor: None,
            following: None,
            analysis: None,
            pending: false,
            here: false,
            sent: None,
            seq: 0,
            run: new_run(),
            said: 0,
        }
    }
}

/// An agent this peer speaks for.
#[derive(Debug)]
struct Hosted {
    card: Card,
    /// Its identity key, which signs what this peer says for it.
    signer: SigningKey,
    agent: Agent,
    cursor: Option<Cursor>,
    /// A cursor not sent yet.
    pending: bool,
    /// A heartbeat not sent yet.
    here: bool,
    /// Its last datagram's number.
    seq: u32,
    /// Its run ([`Hi::run`]).
    run: u64,
    /// The introductions made of it.
    said: u64,
}

impl Hosted {
    /// Its next [`Hi`], on the binbun `engine` of the peer speaking for it
    /// (no analysis of its own: it works on its host's), signed for
    /// the share whose genesis is `genesis`.
    fn hi(&mut self, engine: &EngineVersion, genesis: &[u8; 32]) -> Option<Hi> {
        self.said += 1;
        Hi {
            card: self.card.clone(),
            engine: Engine::of(engine),
            analysis: None,
            cursor: self.cursor,
            following: None,
            agent: Some(self.agent.clone()),
            run: self.run,
            n: self.said,
            sig: unsigned(),
        }
        .signed(&self.signer, genesis)
    }

    /// Its next presence datagram's plaintext, saying `what`, signed for
    /// the share whose genesis is `genesis`.
    fn presence(&mut self, what: What, genesis: &[u8; 32]) -> Option<Presence> {
        self.seq = self.seq.wrapping_add(1);
        Presence {
            from: self.card.key,
            run: self.run,
            seq: self.seq,
            what,
            sig: unsigned(),
        }
        .signed(&self.signer, genesis)
    }
}

/// A participant as this peer keeps them.
#[derive(Debug)]
struct Known {
    /// Their introduction taken last, as signed: what this peer gives
    /// others.
    hi: Hi,
    /// The member whose link brought them (themselves, if linked): the
    /// one link their presence and leaving are taken from.
    via: PublicKey,
    /// The generation of `via`'s link that brought them
    /// ([`crate::budgets::LinkBudget::generation`]).
    link: u64,
    cursor: Option<Cursor>,
    moved: Option<Instant>,
    following: Option<PublicKey>,
    heard: Instant,
    /// Their run's datagram numbers seen lately (the last taken: its
    /// [`Run`]).
    seen: BTreeSet<u32>,
    /// Their latest presence of each kind taken (cursor or leaving,
    /// heartbeat), as signed, in the order taken: what this peer gives
    /// one linking later.
    said: Vec<Presence>,
    /// Whether they are shown (told, given and forwarded): not while all
    /// that came of them is no newer than what was taken of their run
    /// before.
    shown: bool,
}

impl Known {
    /// As told outside, `agent` as they say it.
    fn participant(&self) -> Participant {
        Participant {
            card: self.hi.card.clone(),
            engine: self.hi.engine.version(),
            analysis: self.hi.analysis.clone(),
            via: self.via,
            cursor: self.cursor,
            moved: self.moved,
            following: self.following,
            heard: self.heard,
            agent: self.hi.agent.clone(),
        }
    }
}

/// What was taken last of one run of a participant's: their introduction's
/// number and their datagram's.
#[derive(Clone, Copy, Debug)]
struct Run {
    /// The run ([`Hi::run`]).
    id: u64,
    n: u64,
    last: Option<u32>,
}

/// The live session's state.
#[derive(Default)]
struct State {
    mine: Mine,
    /// The agents this peer speaks for, by key.
    hosted: BTreeMap<PublicKey, Hosted>,
    /// The participants, by key: members whose introduction held.
    participants: BTreeMap<PublicKey, Known>,
    /// Each participant's last [`RUNS`] runs taken, kept after they leave.
    runs: BTreeMap<PublicKey, Vec<Run>>,
    /// Each linked member's live lane, [`LANE_QUEUE`] frames past its
    /// greeting at most, and its link's generation.
    lanes: BTreeMap<PublicKey, (u64, mpsc::Sender<Said>)>,
    chat: Vec<ChatMessage>,
    /// The ids of the last [`CHAT_SEEN`] chat messages taken.
    chat_ids: BTreeSet<u64>,
    /// Those ids, in the order taken.
    chat_seen: VecDeque<u64>,
    /// The chat messages the owner removed, by id.
    removed: BTreeMap<u64, Removal>,
    /// This peer's chat messages sent.
    chat_seq: u64,
    listeners: Vec<LiveListener>,
}

/// A peer's live session.
#[derive(Default)]
pub(crate) struct Live {
    state: Mutex<State>,
    /// Woken when this peer's cursor moved.
    moved: Notify,
}

impl Live {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Tells the listeners `event`.
    fn tell(&self, event: &LiveEvent) {
        let listeners = self.state().listeners.clone();
        for listener in listeners {
            listener(event);
        }
    }
}

/// The current time in Unix milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Whether `seq` is newer than `last`, numbers wrapping.
fn newer(seq: u32, last: u32) -> bool {
    seq != last && seq.wrapping_sub(last) < u32::MAX / 2
}

/// What an author is to the membership chain as this peer has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// A member who takes part in live sessions.
    Member,
    /// Not in it: perhaps admitted where this peer has not heard yet.
    Unknown,
    /// Removed, or of the role given no key ([`Role::Store`]).
    Refused,
}

/// What became of a live frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Heard {
    /// Taken, or refused.
    Done,
    /// It does not open, or the membership chain does not name its
    /// author: not yet, perhaps.
    Wait,
}

impl Inner {
    /// The ciphers for `purpose` of the epochs this peer holds, newest
    /// first.
    fn ciphers(&self, purpose: &str) -> Vec<XChaCha20Poly1305> {
        let state = self.state();
        let project = state.membership.project();
        state
            .keys
            .values()
            .rev()
            .map(|key| key.cipher(project, purpose))
            .collect()
    }

    /// The share's genesis, once this peer holds the membership chain's
    /// first record: what every live statement is signed and checked in.
    fn genesis(&self) -> Option<[u8; 32]> {
        self.state().membership.genesis()
    }

    /// What `key` is to the membership chain now.
    fn standing(&self, key: PublicKey) -> Standing {
        let state = self.state();
        match state.membership.role(key) {
            Some(Role::Owner | Role::Editor | Role::Viewer | Role::Agent) => Standing::Member,
            Some(Role::Store) => Standing::Refused,
            None if state.membership.members().contains_key(&key) => Standing::Refused,
            None => Standing::Unknown,
        }
    }

    /// The links up now whose sync reached Reader: the live lanes are
    /// theirs only.
    fn live_links(&self) -> Vec<(PublicKey, Arc<dyn Link>)> {
        self.state()
            .links
            .iter()
            .filter(|(_, link)| link.is_reader())
            .map(|(key, link)| (*key, Arc::clone(&link.link)))
            .collect()
    }

    /// This peer's next [`Hi`], signed; `None` before the genesis is held.
    fn hi(&self) -> Option<Hi> {
        let genesis = self.genesis()?;
        let hi = {
            let mut live = self.live.state();
            live.mine.said += 1;
            Hi {
                card: self.card.clone(),
                engine: Engine::of(&self.engine),
                analysis: live.mine.analysis.clone(),
                cursor: live.mine.cursor,
                following: live.mine.following,
                agent: None,
                run: live.mine.run,
                n: live.mine.said,
                sig: unsigned(),
            }
        };
        hi.signed(&SigningKey::from_bytes(&self.secret), &genesis)
    }

    /// Signs, seals and sends `what` to every link, as this peer (nothing
    /// before the genesis is held).
    fn say(&self, what: What) {
        let Some(genesis) = self.genesis() else {
            return;
        };
        let (run, seq) = {
            let mut live = self.live.state();
            live.mine.seq = live.mine.seq.wrapping_add(1);
            (live.mine.run, live.mine.seq)
        };
        let presence = Presence {
            from: self.me,
            run,
            seq,
            what,
            sig: unsigned(),
        }
        .signed(&SigningKey::from_bytes(&self.secret), &genesis);
        if let Some(presence) = presence {
            self.send_presence(&presence);
        }
    }

    /// Seals and sends `presence` (signed) to every link.
    fn send_presence(&self, presence: &Presence) {
        let Ok(plain) = bounded::encode(presence, MAX_PRESENCE) else {
            return;
        };
        let Some(cipher) = self.ciphers("presence").into_iter().next() else {
            return;
        };
        let Ok(sealed) = crypto::seal_bare(&cipher, &plain) else {
            return;
        };
        for (_, link) in self.live_links() {
            // Lost if it cannot go: presence is best effort.
            let _ = link.send_datagram(sealed.clone());
        }
    }

    /// Sends this peer's presence, one datagram per [`EVERY`] at most:
    /// whom it follows when that changed and every [`HEARTBEAT`], else
    /// its cursor when it moved (the latest one); and as often that of
    /// each agent it speaks for (its heartbeat, else its cursor).
    pub(crate) async fn presence(self: Arc<Self>) {
        let mut heartbeat = tokio::time::interval(HEARTBEAT);
        loop {
            tokio::select! {
                () = self.live.moved.notified() => {}
                _ = heartbeat.tick() => {
                    let mut live = self.live.state();
                    live.mine.here = true;
                    for hosted in live.hosted.values_mut() {
                        hosted.here = true;
                    }
                }
            }
            loop {
                let wait = {
                    let live = self.live.state();
                    live.mine
                        .sent
                        .map_or(Duration::ZERO, |sent| EVERY.saturating_sub(sent.elapsed()))
                };
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
                let genesis = self.genesis();
                let (what, theirs, any) = {
                    let mut live = self.live.state();
                    let mine = &mut live.mine;
                    let what = if mine.here {
                        mine.here = false;
                        Some(What::Here {
                            following: mine.following,
                        })
                    } else if let (true, Some(cursor)) = (mine.pending, mine.cursor) {
                        mine.pending = false;
                        Some(What::Cursor(cursor))
                    } else {
                        None
                    };
                    let mut any = what.is_some();
                    let theirs: Vec<Presence> = live
                        .hosted
                        .values_mut()
                        .filter_map(|hosted| {
                            let what = if hosted.here {
                                hosted.here = false;
                                What::Here { following: None }
                            } else if let (true, Some(cursor)) = (hosted.pending, hosted.cursor) {
                                hosted.pending = false;
                                What::Cursor(cursor)
                            } else {
                                return None;
                            };
                            any = true;
                            hosted.presence(what, genesis.as_ref()?)
                        })
                        .collect();
                    (what, theirs, any)
                };
                if !any {
                    break;
                }
                if let Some(what) = what {
                    self.say(what);
                }
                for presence in &theirs {
                    self.send_presence(presence);
                }
                self.live.state().mine.sent = Some(Instant::now());
            }
        }
    }

    /// The live session over `link` while it is up: this peer's lane to
    /// it (its [`Hi`], those it knows of, its chat backlog, then what
    /// comes), the remote's lane and datagrams. Never returns: it ends
    /// with the link (dropped), forgetting whom the link brought; it
    /// closes the link if its lane falls [`LANE_QUEUE`] frames behind.
    /// What it brings is drawn from the budgets: the remote's rates, by
    /// identity; `budget`'s streams; frames' bytes. Until the link's sync
    /// is a reader's (`up`), only the home binary is served on its
    /// blob lane and nothing else of the live session goes or comes.
    pub(crate) async fn live(
        self: Arc<Self>,
        link: Arc<dyn Link>,
        budget: Arc<LinkBudget>,
        up: watch::Receiver<bool>,
    ) {
        let remote = link.remote();
        let generation = budget.generation();
        let id = LinkId(generation);
        let read = |mut reader: watch::Receiver<bool>| async move {
            let _ = reader.wait_for(|up| *up).await;
        };
        let _gone = Unlive {
            inner: Arc::clone(&self),
            remote,
            generation,
        };
        let writer = async {
            read(up.clone()).await;
            let mut queue = self.greet(remote, generation);
            let (mut send, _) = link.open(Lane::Live).await?;
            while let Some(said) = queue.recv().await {
                // A joiner's first key comes on the sync lane: what it
                // says waits for it a while.
                let start = Instant::now();
                let cipher = loop {
                    if let Some(cipher) = self.ciphers("live").into_iter().next() {
                        break cipher;
                    }
                    if start.elapsed() >= KEYS_WAIT {
                        return Err(Error::new("no key for the live lane"));
                    }
                    tokio::time::sleep(KEYS_POLL).await;
                };
                let plain = Zeroizing::new(bounded::encode(&said, MAX_SAID)?);
                let sealed = crypto::seal_bare(&cipher, &plain)?;
                // Rights at each use (sync §3.6): a link revoked, or its
                // member removed, is written nothing more.
                if self.serving(remote, id) != Some(Phase::Reader) {
                    return Err(Error::new("the live lane's member is no longer served"));
                }
                write_frame(&mut *send, &LiveFrame(bounded::Bytes::try_from(sealed)?)).await?;
            }
            // The lane was dropped: it fell behind.
            link.close("fell behind the live session");
            Ok::<_, Error>(())
        };
        // The streams the remote opens from now: its live lane, once, and
        // a stream per blob it asks for, on a task, while the link and the
        // process have places for both (one past them is dropped).
        let (live_lane, lane_opened) = oneshot::channel();
        let streams = async {
            let mut live_lane = Some(live_lane);
            loop {
                match link.accept().await? {
                    (Lane::Live, _, recv) => {
                        if let Some(lane) = live_lane.take() {
                            let _ = lane.send(recv);
                        }
                    }
                    (Lane::Blob, send, recv) => {
                        if let Some(stream) = budget.stream()
                            && let Some(task) = self.budgets.task()
                        {
                            let inner = Arc::clone(&self);
                            self.spawn(async move {
                                let _task = task;
                                inner.serve_blob(remote, id, stream, send, recv).await;
                            });
                        }
                    }
                    (Lane::Control | Lane::Sync, ..) => {
                        return Err::<(), Error>(Error::new("a lane opened twice"));
                    }
                }
            }
        };
        let reader = async {
            read(up.clone()).await;
            let mut recv = lane_opened.await.map_err(|_| Error::new("no live lane"))?;
            while let Some(length) = read_frame_length(&mut *recv, LiveFrame::LIMIT).await? {
                // Its bytes reserved before they are read, until handled.
                let Some(_frame) = self.budgets.frame(length).await else {
                    return Err(Error::new("a live frame past the frames' ceiling"));
                };
                let LiveFrame(sealed) = read_frame_body(&mut *recv, length).await?;
                if !self.budgets.live_frame(remote, sealed.len()) {
                    continue;
                }
                // A joiner's first key and the membership chain naming
                // whoever speaks come on the sync lane, maybe after the
                // host's first words: they wait for them a while.
                let start = Instant::now();
                loop {
                    let heard = self.hear(remote, &sealed);
                    if heard == Heard::Done || start.elapsed() >= KEYS_WAIT {
                        break;
                    }
                    tokio::time::sleep(KEYS_POLL).await;
                }
            }
            Ok::<_, Error>(())
        };
        let datagrams = async {
            read(up.clone()).await;
            loop {
                match link.recv_datagram().await {
                    Ok(bytes) => self.datagram(remote, &bytes),
                    Err(error) => return Err::<(), Error>(error),
                }
            }
        };
        // Whatever ends first, the link's other lanes say when it is
        // down: this waits for that.
        let _ = tokio::join!(writer, reader, datagrams, streams);
        std::future::pending::<()>().await;
    }

    /// Starts `remote`'s lane: this peer's [`Hi`], those of the agents it
    /// speaks for and of the participants it knows of with their latest
    /// presence, its chat backlog and the removals; then what comes,
    /// [`LANE_QUEUE`] frames at most at a time. What the lane is to send.
    fn greet(&self, remote: PublicKey, generation: u64) -> mpsc::Receiver<Said> {
        let genesis = self.genesis();
        let mine = self.hi();
        let mut guard = self.live.state();
        let live = &mut *guard;
        let mut greeting: Vec<Said> = mine.map(|hi| Said::Hi(Box::new(hi))).into_iter().collect();
        for hosted in live.hosted.values_mut() {
            greeting.extend(
                genesis
                    .as_ref()
                    .and_then(|genesis| hosted.hi(&self.engine, genesis))
                    .map(|hi| Said::Hi(Box::new(hi))),
            );
        }
        for (key, known) in &live.participants {
            if known.shown && known.via != remote && *key != remote {
                greeting.push(Said::Hi(Box::new(known.hi.clone())));
                greeting.extend(known.said.iter().cloned().map(Said::Presence));
            }
        }
        // A removed message goes as its removal, which shows it.
        greeting.extend(
            live.chat
                .iter()
                .filter(|message| !message.removed)
                .cloned()
                .map(Said::Chat),
        );
        greeting.extend(live.removed.values().cloned().map(Said::Removed));
        let (out, queue) = mpsc::channel(greeting.len() + LANE_QUEUE);
        for said in greeting {
            let _ = out.try_send(said);
        }
        // Never in place of a newer link's lane.
        if live
            .lanes
            .get(&remote)
            .is_none_or(|(newest, _)| *newest <= generation)
        {
            live.lanes.insert(remote, (generation, out));
        }
        queue
    }

    /// Takes the live frame `sealed` from the lane of `remote`.
    fn hear(&self, remote: PublicKey, sealed: &[u8]) -> Heard {
        match self.open_live(sealed) {
            Some(said) => self.take(remote, said),
            None => Heard::Wait,
        }
    }

    /// Takes `said` from the lane of `remote` if its author signed it in
    /// this share (under its genesis: not yet before it is held) and is a
    /// member, within `remote`'s rates.
    fn take(&self, remote: PublicKey, said: Said) -> Heard {
        let Some(genesis) = self.genesis() else {
            return Heard::Wait;
        };
        match said {
            Said::Hi(hi) => {
                if !(hi.card.verifies() && plain_labels(&hi) && hi.verifies(&genesis)) {
                    return Heard::Done;
                }
                match self.standing(hi.card.key) {
                    Standing::Member => self.take_hi(remote, hi),
                    Standing::Unknown => return Heard::Wait,
                    Standing::Refused => {}
                }
            }
            Said::Chat(message) => {
                // One taken already costs its link nothing (a backlog
                // given again).
                if self.live.state().chat_ids.contains(&message.id)
                    || !(message.fits() && message.verifies(&genesis))
                {
                    return Heard::Done;
                }
                match self.standing(message.from) {
                    Standing::Member => {
                        if self.budgets.chat(remote, message.from) {
                            self.take_chat(remote, message);
                        }
                    }
                    Standing::Unknown => return Heard::Wait,
                    Standing::Refused => {}
                }
            }
            Said::Presence(presence) => self.take_presence(remote, &presence, None),
            Said::Gone(key) => self.take_gone(remote, key),
            Said::Removed(removal) => {
                if self.removal_signed(&removal, &genesis) {
                    self.take_removal(remote, removal);
                }
            }
        }
        Heard::Done
    }

    /// Takes `hi` (checked) from the lane of `remote`, unless it is older
    /// than the one taken, or `remote` is neither the participant nor the
    /// link that brought them while they are shown. One no newer than an
    /// introduction taken of its run before (they may have left since)
    /// keeps them unshown until a newer datagram of theirs comes
    /// ([`Self::take_presence`]).
    fn take_hi(&self, remote: PublicKey, hi: Box<Hi>) {
        let key = hi.card.key;
        if key == self.me {
            return;
        }
        {
            let mut guard = self.live.state();
            let live = &mut *guard;
            // An agent this peer speaks for is its own.
            if live.hosted.contains_key(&key) {
                return;
            }
            let link = live
                .lanes
                .get(&remote)
                .map_or(0, |(generation, _)| *generation);
            let known = live.participants.get_mut(&key);
            // Another link's forwarding does not take the place of the
            // route they came by; their own link does.
            if known
                .as_ref()
                .is_some_and(|known| known.shown && remote != key && remote != known.via)
            {
                return;
            }
            let runs = live.runs.entry(key).or_default();
            let newer_hi = match runs.iter_mut().find(|run| run.id == hi.run) {
                Some(run) if hi.n <= run.n => false,
                Some(run) => {
                    run.n = hi.n;
                    true
                }
                None => {
                    if runs.len() >= RUNS {
                        runs.remove(0);
                    }
                    runs.push(Run {
                        id: hi.run,
                        n: hi.n,
                        last: None,
                    });
                    true
                }
            };
            let now = Instant::now();
            let shown = if let Some(known) = known {
                if known.shown && !newer_hi {
                    return;
                }
                if hi.run != known.hi.run {
                    known.seen.clear();
                    known.said.clear();
                }
                known.via = remote;
                known.link = link;
                known.cursor = hi.cursor.or(known.cursor);
                known.following = hi.following;
                known.heard = now;
                known.hi = (*hi).clone();
                known.shown |= newer_hi;
                known.shown
            } else {
                live.participants.insert(
                    key,
                    Known {
                        hi: (*hi).clone(),
                        via: remote,
                        link,
                        cursor: hi.cursor,
                        moved: None,
                        following: hi.following,
                        heard: now,
                        seen: BTreeSet::new(),
                        said: Vec::new(),
                        shown: newer_hi,
                    },
                );
                newer_hi
            };
            if !shown {
                return;
            }
            forward(live, Some(remote), &Said::Hi(hi));
        }
        self.live.tell(&LiveEvent::Hi(key));
    }

    /// Takes that `key` left from the lane of `remote`, the link that
    /// brought them (told if they were shown).
    fn take_gone(&self, remote: PublicKey, key: PublicKey) {
        {
            let mut live = self.live.state();
            if live
                .participants
                .get(&key)
                .is_none_or(|known| known.via != remote)
            {
                return;
            }
            if live
                .participants
                .remove(&key)
                .is_none_or(|known| !known.shown)
            {
                return;
            }
            forward(&mut live, Some(remote), &Said::Gone(key));
        }
        self.live.tell(&LiveEvent::Gone(key));
    }

    /// Takes `message` (checked) from the lane of `remote`: kept,
    /// forwarded and told, once.
    fn take_chat(&self, remote: PublicKey, mut message: ChatMessage) {
        {
            let mut live = self.live.state();
            if !keep(&mut live, message.clone()) {
                return;
            }
            if live.removed.contains_key(&message.id) {
                message.remove();
            } else {
                forward(&mut live, Some(remote), &Said::Chat(message.clone()));
            }
        }
        self.live.tell(&LiveEvent::Chat(message));
    }

    /// Whether `removal` is signed by the project's owner in the share
    /// whose genesis is `genesis`.
    fn removal_signed(&self, removal: &Removal, genesis: &[u8; 32]) -> bool {
        let owner = self.state().membership.owner();
        removal.by == owner && removal.verifies(genesis)
    }

    /// Takes `removal` (checked) from the lane of `from` (this peer's own:
    /// [`Self::me`]): the message's text dropped (the message shown
    /// removed if it never came), the removal forwarded and told, once.
    fn take_removal(&self, from: PublicKey, removal: Removal) {
        let id = removal.id;
        let blank = {
            let mut live = self.live.state();
            if live.removed.contains_key(&id) {
                return;
            }
            live.removed.insert(id, removal.clone());
            let blank = if let Some(message) = live.chat.iter_mut().find(|m| m.id == id) {
                message.remove();
                None
            } else {
                let blank = removal.message();
                keep(&mut live, blank.clone()).then_some(blank)
            };
            forward(&mut live, Some(from), &Said::Removed(removal));
            blank
        };
        self.live.tell(&LiveEvent::ChatRemoved(id));
        if let Some(blank) = blank {
            self.live.tell(&LiveEvent::Chat(blank));
        }
    }

    /// Takes a presence datagram `bytes` from `remote`'s link, within its
    /// rate; forwards it to the other links if new.
    fn datagram(&self, remote: PublicKey, bytes: &[u8]) {
        if bytes.len() > MAX_DATAGRAM || !self.budgets.datagram(remote) {
            return;
        }
        let Some(presence) = self.ciphers("presence").iter().find_map(|cipher| {
            let plain = crypto::open_bare(cipher, bytes)?;
            bounded::decode::<Presence>(&plain).ok()
        }) else {
            return;
        };
        self.take_presence(remote, &presence, Some(bytes));
    }

    /// Takes `presence` from `remote`'s link if a participant it brought
    /// signed it, within their rate; `datagram`, the datagram it came in,
    /// is forwarded to the other links if new. One newer than any taken of
    /// its run shows its participant if unshown ([`Self::take_hi`]).
    #[expect(clippy::too_many_lines, reason = "each check of a datagram in turn")]
    fn take_presence(&self, remote: PublicKey, presence: &Presence, datagram: Option<&[u8]>) {
        let from = presence.from;
        let ours = |known: &Known| {
            known.via == remote
                && known.hi.run == presence.run
                && !known.seen.contains(&presence.seq)
        };
        {
            let mut live = self.live.state();
            let Some(known) = live.participants.get_mut(&from) else {
                return;
            };
            if !ours(known) {
                return;
            }
        }
        if !self.budgets.presence(from) {
            return;
        }
        let signed = self
            .genesis()
            .is_some_and(|genesis| presence.verifies(&genesis));
        if self.standing(from) != Standing::Member || !signed {
            return;
        }
        let (shown, event, others) = {
            let mut guard = self.live.state();
            let live = &mut *guard;
            let others: Vec<PublicKey> = live
                .lanes
                .keys()
                .copied()
                .filter(|key| *key != remote && *key != from)
                .collect();
            let Some(known) = live.participants.get_mut(&from) else {
                return;
            };
            if !ours(known) {
                return;
            }
            if known.seen.len() >= SEEN {
                known.seen.pop_first();
            }
            known.seen.insert(presence.seq);
            let run = live
                .runs
                .get_mut(&from)
                .and_then(|runs| runs.iter_mut().find(|run| run.id == presence.run));
            let fresh = run
                .as_ref()
                .is_none_or(|run| run.last.is_none_or(|last| newer(presence.seq, last)));
            if fresh && let Some(run) = run {
                run.last = Some(presence.seq);
            }
            let shown = (fresh && !known.shown).then(|| {
                known.shown = true;
                Said::Hi(Box::new(known.hi.clone()))
            });
            let event = fresh.then(|| {
                known.heard = Instant::now();
                let here = matches!(presence.what, What::Here { .. });
                known
                    .said
                    .retain(|said| matches!(said.what, What::Here { .. }) != here);
                known.said.push(presence.clone());
                match &presence.what {
                    What::Here { following } => {
                        known.following = *following;
                        LiveEvent::Here(from)
                    }
                    What::Cursor(cursor) => {
                        known.cursor = Some(*cursor);
                        known.moved = Some(Instant::now());
                        LiveEvent::Cursor(from, *cursor)
                    }
                    What::Bye => {
                        known.cursor = None;
                        LiveEvent::Here(from)
                    }
                }
            });
            if let Some(hi) = &shown {
                forward(live, Some(remote), hi);
            }
            (shown.is_some(), event, others)
        };
        if let Some(bytes) = datagram
            && !others.is_empty()
        {
            let links = self.state();
            for key in others {
                if let Some(link) = links.links.get(&key) {
                    let _ = link.link.send_datagram(bytes.to_vec());
                }
            }
        }
        if shown {
            self.live.tell(&LiveEvent::Hi(from));
        }
        if let Some(event) = event {
            self.live.tell(&event);
        }
    }

    /// Says goodbye to every link (closing).
    pub(crate) fn bye(&self) {
        self.say(What::Bye);
    }

    /// No longer speaks for agent `key` (removed from the project).
    pub(crate) fn unhost(&self, key: PublicKey) {
        unhost(&mut self.live.state(), key);
    }

    /// What the live frame `sealed` says, opened under any epoch's key
    /// held.
    fn open_live(&self, sealed: &[u8]) -> Option<Said> {
        self.ciphers("live").iter().find_map(|cipher| {
            let plain = crypto::open_bare(cipher, sealed)?;
            bounded::decode(&plain).ok()
        })
    }
}

/// Forgets what a link brought when it goes (dropped with its task): its
/// lane, and those it brought, unless a newer link to the same peer has
/// taken their place.
struct Unlive {
    inner: Arc<Inner>,
    remote: PublicKey,
    /// The link's generation.
    generation: u64,
}

impl Drop for Unlive {
    fn drop(&mut self) {
        let gone: Vec<PublicKey> = {
            let mut live = self.inner.live.state();
            if live
                .lanes
                .get(&self.remote)
                .is_some_and(|(generation, _)| *generation == self.generation)
            {
                live.lanes.remove(&self.remote);
            }
            let gone: Vec<PublicKey> = live
                .participants
                .iter()
                .filter(|(_, known)| known.via == self.remote && known.link == self.generation)
                .map(|(key, _)| *key)
                .collect();
            let mut told = Vec::new();
            for key in gone {
                if live
                    .participants
                    .remove(&key)
                    .is_some_and(|known| known.shown)
                {
                    forward(&mut live, Some(self.remote), &Said::Gone(key));
                    told.push(key);
                }
            }
            told
        };
        for key in gone {
            self.inner.live.tell(&LiveEvent::Gone(key));
        }
    }
}

/// Sends `said` on every lane but `from`'s; a lane too far behind to take
/// it is dropped (and its link closed: [`Inner::live`]).
fn forward(live: &mut State, from: Option<PublicKey>, said: &Said) {
    live.lanes
        .retain(|key, (_, lane)| Some(*key) == from || lane.try_send(said.clone()).is_ok());
}

/// No longer speaks for agent `key`: the others told it left.
fn unhost(live: &mut State, key: PublicKey) {
    if live.hosted.remove(&key).is_some() {
        forward(live, None, &Said::Gone(key));
    }
}

/// Keeps `message` last in the backlog, the oldest past [`BACKLOG`]
/// dropped, its text dropped if it was removed already, unless it is
/// among the last [`CHAT_SEEN`] taken: whether it was new.
fn keep(live: &mut State, mut message: ChatMessage) -> bool {
    let id = message.id;
    if !live.chat_ids.insert(id) {
        return false;
    }
    live.chat_seen.push_back(id);
    if live.chat_seen.len() > CHAT_SEEN
        && let Some(forgotten) = live.chat_seen.pop_front()
    {
        live.chat_ids.remove(&forgotten);
    }
    if live.removed.contains_key(&id) {
        message.remove();
    }
    live.chat.push(message);
    if live.chat.len() > BACKLOG {
        live.chat.remove(0);
    }
    true
}

impl Peer {
    /// The participants linked, directly or through the host, besides
    /// this peer: members now.
    pub fn participants(&self) -> Vec<Participant> {
        let inner = self.inner();
        let known: Vec<Participant> = inner
            .live
            .state()
            .participants
            .values()
            .filter(|known| known.shown)
            .map(Known::participant)
            .collect();
        let state = inner.state();
        known
            .into_iter()
            .filter_map(|mut participant| {
                let role = state.membership.role(participant.card.key)?;
                match role {
                    Role::Agent => {
                        participant.agent.get_or_insert_default();
                    }
                    Role::Owner | Role::Editor | Role::Viewer => participant.agent = None,
                    Role::Store => return None,
                }
                Some(participant)
            })
            .collect()
    }

    /// The chat messages kept (the last [`BACKLOG`] taken), in the order
    /// taken.
    pub fn chat_log(&self) -> Vec<ChatMessage> {
        self.inner().live.state().chat.clone()
    }

    /// Calls `listener` with what the live session tells from now on.
    pub fn on_live(&self, listener: LiveListener) {
        self.inner().live.state().listeners.push(listener);
    }

    /// Says where this peer's cursor is: sent at once, or within [`EVERY`]
    /// of the last (the latest of those said meanwhile).
    pub fn set_cursor(&self, cursor: Cursor) {
        let inner = self.inner();
        {
            let mut live = inner.live.state();
            if live.mine.cursor == Some(cursor) {
                return;
            }
            live.mine.cursor = Some(cursor);
            live.mine.pending = true;
        }
        inner.live.moved.notify_one();
    }

    /// Says whom this peer follows (`None`: no one): sent at once, or
    /// within [`EVERY`] of the last datagram.
    pub fn follow(&self, leader: Option<PublicKey>) {
        let inner = self.inner();
        {
            let mut live = inner.live.state();
            live.mine.following = leader;
            live.mine.here = true;
        }
        inner.live.moved.notify_one();
    }

    /// Tells every participant this peer's analysis (once made, or made
    /// anew); a debug file's name as plain text ([`ticket::plain_text`]).
    pub fn announce(&self, analysis: Option<Analysis>) {
        let inner = self.inner();
        let analysis = analysis.map(|mut analysis| {
            if let Some(debug) = &mut analysis.debug {
                debug.name = Text::truncated(&ticket::plain_text(&debug.name, MAX_LABEL));
            }
            analysis
        });
        inner.live.state().mine.analysis = analysis;
        if let Some(hi) = inner.hi() {
            forward(&mut inner.live.state(), None, &Said::Hi(Box::new(hi)));
        }
    }

    /// Speaks for `agents`, those connected to this peer's window now,
    /// each one that is a member (the owner sets its role; one removed is
    /// no participant): the others are told of one new (or renamed) at
    /// once, its cursor as this peer's (within [`EVERY`]), and that one
    /// no longer here left.
    pub fn host_agents(&self, agents: Vec<HostedAgent>) {
        let inner = self.inner();
        let (genesis, agents) = {
            let state = inner.state();
            let agents: Vec<HostedAgent> = agents
                .into_iter()
                .filter(|agent| {
                    let key = agent.identity.public();
                    key != inner.me && state.membership.role(key).is_some()
                })
                .collect();
            (state.membership.genesis(), agents)
        };
        // Nothing is said for them before the genesis is held.
        let Some(genesis) = genesis else {
            return;
        };
        let mut moved = false;
        {
            let mut live = inner.live.state();
            let gone: Vec<PublicKey> = live
                .hosted
                .keys()
                .filter(|key| !agents.iter().any(|agent| agent.identity.public() == **key))
                .copied()
                .collect();
            for key in gone {
                unhost(&mut live, key);
            }
            for agent in agents {
                let card = Card::new(&agent.identity, &agent.name);
                let described =
                    Agent {
                        version: agent.agent.version.as_deref().map(|version| {
                            Text::truncated(&ticket::plain_text(version, MAX_LABEL))
                        }),
                    };
                let key = card.key;
                let hi = match live.hosted.get_mut(&key) {
                    Some(hosted) if hosted.card == card && hosted.agent == described => {
                        if hosted.cursor != agent.cursor {
                            hosted.cursor = agent.cursor;
                            hosted.pending = agent.cursor.is_some();
                            moved |= hosted.pending;
                        }
                        continue;
                    }
                    Some(hosted) => {
                        hosted.card = card;
                        hosted.agent = described;
                        hosted.cursor = agent.cursor;
                        hosted.pending = false;
                        hosted.hi(&inner.engine, &genesis)
                    }
                    None => {
                        let mut hosted = Hosted {
                            card,
                            signer: SigningKey::from_bytes(&agent.identity.secret()),
                            agent: described,
                            cursor: agent.cursor,
                            pending: false,
                            here: false,
                            seq: 0,
                            run: new_run(),
                            said: 0,
                        };
                        let hi = hosted.hi(&inner.engine, &genesis);
                        live.hosted.insert(key, hosted);
                        hi
                    }
                };
                if let Some(hi) = hi {
                    forward(&mut live, None, &Said::Hi(Box::new(hi)));
                }
            }
        }
        if moved {
            inner.live.moved.notify_one();
        }
    }

    /// Sends `text` to the session's chat with the places it names
    /// (`links`, ranges of `text`) and whom it mentions: the message as
    /// sent (`text` trimmed, its links moved with it; those outside it
    /// dropped), signed by this peer's identity.
    ///
    /// # Errors
    ///
    /// Empty or longer than [`MAX_CHAT`] bytes; more than one a second
    /// (five at once); no key yet (not admitted); no randomness.
    pub fn chat(
        &self,
        text: &str,
        links: &[ChatLink],
        mentions: &[PublicKey],
    ) -> Result<ChatMessage, Error> {
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_CHAT {
            return Err(Error::new(format!(
                "a chat message holds 1 to {MAX_CHAT} bytes"
            )));
        }
        let lead = u32::try_from(text.len() - text.trim_start().len()).unwrap_or(u32::MAX);
        let links = ChatMessage::fitting(
            trimmed,
            links.iter().filter_map(|link| {
                Some(ChatLink {
                    start: link.start.checked_sub(lead)?,
                    end: link.end.checked_sub(lead)?,
                    ..*link
                })
            }),
        );
        let inner = self.inner();
        let genesis = inner
            .genesis()
            .filter(|_| !inner.ciphers("live").is_empty())
            .ok_or_else(|| Error::new("not admitted yet"))?;
        let seq = {
            if !inner.budgets.say_chat() {
                return Err(Error::new("one chat message a second at most"));
            }
            let mut live = inner.live.state();
            live.chat_seq += 1;
            live.chat_seq
        };
        let message = ChatMessage {
            id: u64::from_le_bytes(crypto::random()?),
            from: inner.me,
            time: now_ms(),
            seq,
            text: Text::truncated(trimmed),
            links,
            mentions: Bounded::truncated(mentions.to_vec()),
            sig: unsigned(),
            removed: false,
        };
        let message = message
            .signed(&SigningKey::from_bytes(&inner.secret), &genesis)
            .ok_or_else(|| Error::new("a chat message that does not encode"))?;
        {
            let mut live = inner.live.state();
            keep(&mut live, message.clone());
            forward(&mut live, None, &Said::Chat(message.clone()));
        }
        inner.live.tell(&LiveEvent::Chat(message.clone()));
        Ok(message)
    }

    /// Removes chat message `id` for everyone (the owner only): its text
    /// dropped on every peer, shown "removed by the owner".
    ///
    /// # Errors
    ///
    /// This peer is not the project's owner, or does not have the message.
    pub fn remove_chat(&self, id: u64) -> Result<(), Error> {
        let inner = self.inner();
        let (genesis, owner) = {
            let state = inner.state();
            (state.membership.genesis(), state.membership.owner())
        };
        if owner != inner.me {
            return Err(Error::new("only the owner removes chat messages"));
        }
        let genesis = genesis.ok_or_else(|| Error::new("no membership chain held yet"))?;
        let removal = {
            let live = inner.live.state();
            let message = live
                .chat
                .iter()
                .find(|message| message.id == id)
                .ok_or_else(|| Error::new("no such chat message"))?;
            Removal {
                id,
                from: message.from,
                time: message.time,
                seq: message.seq,
                by: owner,
                sig: unsigned(),
            }
        };
        let removal = removal
            .signed(&SigningKey::from_bytes(&inner.secret), &genesis)
            .ok_or_else(|| Error::new("a removal that does not encode"))?;
        inner.take_removal(inner.me, removal);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use binbun_bounded::{self as bounded, Bounded, Text};
    use binbun_session::identity::Identity;
    use binbun_session::journal::{EngineVersion, ProjectId, PublicKey};
    use binbun_session::{Options, Session, Stage};
    use ed25519_dalek::SigningKey;
    use tokio::sync::mpsc;

    use super::{
        Agent, Analysis, BACKLOG, CHAT_SEEN, ChatLink, ChatMessage, Cursor, Heard, Hi, LANE_QUEUE,
        LiveEvent, MAX_CHAT_LINKS, MAX_PRESENCE, MAX_SAID, Place, Presence, Removal, Said,
        Selection, Signed as _, State, Unlive, What, forward, keep, newer, now_ms, signed_bytes,
        unsigned,
    };
    use crate::crypto::{self, EpochKey};
    use crate::mem::MemNet;
    use crate::membership::{Membership, Role};
    use crate::ticket::Card;
    use crate::wire::{Engine, LIVE_FRAME};
    use crate::{Approver, Config, Peer};

    /// A body to sign is encoded within a live frame or not at all.
    #[test]
    fn a_body_past_a_live_frame_has_nothing_to_sign() {
        let genesis = [7; 32];
        let within = vec![1u8; LIVE_FRAME - 4];
        let bytes = signed_bytes(b"label", &genesis, &within).unwrap();
        assert_eq!(&bytes[..5], b"label");
        assert_eq!(&bytes[5..37], &genesis);
        assert_eq!(bytes[37..], bounded::encode(&within, usize::MAX).unwrap());
        let past = vec![1u8; LIVE_FRAME];
        assert_eq!(signed_bytes(b"label", &genesis, &past), None);
    }

    /// `identity`'s signing key.
    fn signer(identity: &Identity) -> SigningKey {
        SigningKey::from_bytes(&identity.secret())
    }

    /// Message `id` of `from`, unsigned.
    fn chat(from: PublicKey, id: u64, text: &str) -> ChatMessage {
        ChatMessage {
            id,
            from,
            time: now_ms(),
            seq: id,
            text: Text::truncated(text),
            links: Bounded::new(),
            mentions: Bounded::new(),
            sig: unsigned(),
            removed: false,
        }
    }

    /// One in a test's session: an identity and a session on
    /// `tests/fixtures/program-x86_64.elf`, under a fresh directory.
    fn person(test: &str, name: &str) -> (Identity, Arc<Session>) {
        let home = std::env::temp_dir()
            .join(format!("binbun-live-{test}-{}", std::process::id()))
            .join(name);
        let _ = std::fs::remove_dir_all(&home);
        let identity = Identity::load_or_create(&home.join("identity")).unwrap();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/program-x86_64.elf");
        let session = Session::open(
            fixture,
            Options {
                project: Some(home.join("project")),
                identity: Some(home.join("identity")),
                warm: false,
                ..Options::default()
            },
        )
        .unwrap();
        session.wait(Stage::Analysed, None);
        (identity, Arc::new(session))
    }

    /// Waits (up to 30 s) until `done`.
    async fn until(what: &str, mut done: impl FnMut() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(start.elapsed() < Duration::from_secs(30), "never: {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Ann shares, Bob and Mallory join as editors, over [`MemNet`]; each
    /// knows the two others.
    async fn three(test: &str) -> ([Identity; 3], [Peer; 3]) {
        let net = MemNet::new();
        let config = |identity: &Identity, name: &str, approve: Option<Approver>| Config {
            identity: identity.clone(),
            name: name.to_owned(),
            approve,
            notify: None,
            engine: EngineVersion::this(),
        };
        let (ann_id, ann_session) = person(test, "ann");
        let editors: Approver = Arc::new(|_| Box::pin(async { Some(Role::Editor) }));
        let (ann, ticket) = Peer::share(
            ann_session,
            Arc::new(net.endpoint(ann_id.public())),
            config(&ann_id, "Ann", Some(editors)),
        )
        .await
        .unwrap();
        let mut ids = vec![ann_id];
        let mut peers = vec![ann];
        for name in ["Bob", "Mallory"] {
            let (id, session) = person(test, name);
            let peer = Peer::join(
                session,
                Arc::new(net.endpoint(id.public())),
                config(&id, name, None),
                &ticket,
            )
            .await
            .unwrap();
            ids.push(id);
            peers.push(peer);
        }
        until("each knows the others", || {
            peers
                .iter()
                .all(|peer| peer.role().is_some() && peer.participants().len() == 2)
        })
        .await;
        let (Ok(ids), Ok(peers)) = (ids.try_into(), peers.try_into()) else {
            unreachable!("three of each");
        };
        (ids, peers)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_member_chats_and_moves_only_as_herself() {
        let ([_, bob_id, mal_id], [ann, bob, mallory]) = three("forge").await;
        let (b, m) = (bob_id.public(), mal_id.public());
        let inner = ann.inner();
        let genesis = inner.genesis().unwrap();

        // Chat in Bob's name over Mallory's link: signed by her, by no
        // one, or by Bob with its text changed on the way.
        let forged = chat(b, 1, "I am Bob").signed(&signer(&mal_id), &genesis);
        let mut altered = chat(b, 2, "hello")
            .signed(&signer(&bob_id), &genesis)
            .unwrap();
        altered.text = Text::truncated("goodbye");
        for message in [forged.unwrap(), chat(b, 3, "unsigned"), altered] {
            assert_eq!(inner.take(m, Said::Chat(message)), Heard::Done);
        }
        // Signed by a key the membership chain does not name: it waits
        // for the chain, and is not kept meanwhile.
        let stranger = Identity::ephemeral().unwrap();
        let outsider = chat(stranger.public(), 4, "let me in").signed(&signer(&stranger), &genesis);
        assert_eq!(inner.take(m, Said::Chat(outsider.unwrap())), Heard::Wait);
        // Hers, and Bob's as he signed it, are taken whichever link
        // brings them.
        let hers = chat(m, 5, "I am Mallory").signed(&signer(&mal_id), &genesis);
        let his = chat(b, 6, "I am Bob").signed(&signer(&bob_id), &genesis);
        inner.take(m, Said::Chat(hers.unwrap()));
        inner.take(m, Said::Chat(his.unwrap()));
        let mut kept: Vec<(u64, PublicKey)> =
            ann.chat_log().iter().map(|c| (c.id, c.from)).collect();
        kept.sort_unstable();
        assert_eq!(kept, [(5, m), (6, b)]);

        // Mallory moves Bob's cursor: presence in his name she signed,
        // over her link or as if over his; and one he signed, over her
        // link (not the one that brought him).
        let run = inner.live.state().participants[&b].hi.run;
        let cipher = inner.ciphers("presence").into_iter().next().unwrap();
        let datagram = |identity: &Identity, seq: u32, address: u64| {
            let presence = Presence {
                from: b,
                run,
                seq,
                what: What::Cursor(Cursor {
                    place: Place::Listing,
                    address,
                    column: 0,
                    selection: None,
                }),
                sig: unsigned(),
            }
            .signed(&signer(identity), &genesis)
            .unwrap();
            crypto::seal_bare(&cipher, &postcard::to_allocvec(&presence).unwrap()).unwrap()
        };
        let bob_at_ann = || {
            ann.participants()
                .into_iter()
                .find(|p| p.card.key == b)
                .unwrap()
        };
        inner.datagram(m, &datagram(&mal_id, 1000, 0xbad));
        inner.datagram(b, &datagram(&mal_id, 1001, 0xbad));
        inner.datagram(m, &datagram(&bob_id, 1002, 0xbad));
        assert_eq!(bob_at_ann().cursor, None);
        // His own, over his link, moves it.
        inner.datagram(b, &datagram(&bob_id, 1003, 0x600d));
        assert_eq!(bob_at_ann().cursor.map(|c| c.address), Some(0x600d));

        for peer in [ann, bob, mallory] {
            peer.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_member_introduces_only_herself_and_is_an_agent_only_by_her_role() {
        let ([_, bob_id, mal_id], [ann, bob, mallory]) = three("introduce").await;
        let (b, m) = (bob_id.public(), mal_id.public());
        let inner = ann.inner();
        let genesis = inner.genesis().unwrap();
        let bob_at_ann = || {
            ann.participants()
                .into_iter()
                .find(|p| p.card.key == b)
                .unwrap()
        };

        // Mallory forwards an introduction of Bob's, his own and newer,
        // with an analysis he never told: Bob came on his own link, which
        // hers does not replace. Nor does she say he left.
        let known = inner.live.state().participants[&b].hi.clone();
        let told = Some(Analysis {
            fingerprint: [7; 32],
            debug: None,
        });
        let newer_hi = Hi {
            n: known.n + 100,
            analysis: told.clone(),
            ..known.clone()
        }
        .signed(&signer(&bob_id), &genesis)
        .unwrap();
        inner.take(m, Said::Hi(Box::new(newer_hi.clone())));
        inner.take(m, Said::Gone(b));
        assert_eq!((bob_at_ann().via, bob_at_ann().analysis), (b, None));
        // One in his name she signed is refused on any link.
        let forged_hi = Hi {
            n: known.n + 200,
            analysis: told.clone(),
            ..known
        }
        .signed(&signer(&mal_id), &genesis)
        .unwrap();
        inner.take(b, Said::Hi(Box::new(forged_hi)));
        assert_eq!(bob_at_ann().analysis, None);
        // His own, over his link, is taken.
        inner.take(b, Said::Hi(Box::new(newer_hi)));
        assert_eq!(bob_at_ann().analysis, told);

        // Mallory says she is an agent: the chain makes her an editor, so
        // she is none (what else she says is taken).
        let hers = inner.live.state().participants[&m].hi.clone();
        let claim = Hi {
            n: hers.n + 1,
            analysis: told.clone(),
            agent: Some(Agent {
                version: Some(Text::truncated("9.9")),
            }),
            ..hers
        }
        .signed(&signer(&mal_id), &genesis)
        .unwrap();
        inner.take(m, Said::Hi(Box::new(claim)));
        let her = ann
            .participants()
            .into_iter()
            .find(|p| p.card.key == m)
            .unwrap();
        assert_eq!((her.analysis, her.agent), (told, None));

        for peer in [ann, bob, mallory] {
            peer.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[expect(clippy::too_many_lines, reason = "each limit set up, then checked")]
    async fn what_a_link_brings_is_kept_for_members_only_and_within_its_rates() {
        let ([_, bob_id, mal_id], [ann, bob, mallory]) = three("limits").await;
        let (b, m) = (bob_id.public(), mal_id.public());
        let inner = ann.inner();
        let genesis = inner.genesis().unwrap();
        let cipher = inner.ciphers("presence").into_iter().next().unwrap();
        let seal = |presence: &Presence| {
            crypto::seal_bare(&cipher, &postcard::to_allocvec(presence).unwrap()).unwrap()
        };

        // Presence and introductions of identities Mallory made up, each
        // signed by its own key: none is kept.
        for _ in 0..200 {
            let invented = Identity::ephemeral().unwrap();
            let key = invented.public();
            let presence = Presence {
                from: key,
                run: 1,
                seq: 1,
                what: What::Here { following: None },
                sig: unsigned(),
            }
            .signed(&signer(&invented), &genesis)
            .unwrap();
            inner.datagram(m, &seal(&presence));
            let hi = Hi {
                card: Card::new(&invented, "Invented"),
                engine: Engine::of(&EngineVersion::this()),
                analysis: None,
                cursor: None,
                following: None,
                agent: None,
                run: 1,
                n: 1,
                sig: unsigned(),
            }
            .signed(&signer(&invented), &genesis)
            .unwrap();
            assert_eq!(inner.take(m, Said::Hi(Box::new(hi))), Heard::Wait);
        }
        let keys: Vec<PublicKey> = inner.live.state().participants.keys().copied().collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&b) && keys.contains(&m));

        // Mallory's chat through her link: a backlog's worth, then five
        // at once; Bob's through it still goes.
        let told: Arc<Mutex<Vec<PublicKey>>> = Arc::default();
        let listened = Arc::clone(&told);
        ann.on_live(Arc::new(move |event| {
            if let LiveEvent::Chat(message) = event {
                listened.lock().unwrap().push(message.from);
            }
        }));
        let many = u64::try_from(BACKLOG).unwrap() + 10;
        let spam: Vec<ChatMessage> = (0..many)
            .map(|id| {
                chat(m, id, "spam")
                    .signed(&signer(&mal_id), &genesis)
                    .unwrap()
            })
            .collect();
        let start = Instant::now();
        for message in spam {
            inner.take(m, Said::Chat(message));
        }
        // One more a second while they came.
        let refilled = usize::try_from(start.elapsed().as_secs()).unwrap();
        let his = chat(b, many, "still here").signed(&signer(&bob_id), &genesis);
        inner.take(m, Said::Chat(his.unwrap()));
        let told = told.lock().unwrap().clone();
        let mallorys = told.iter().filter(|from| **from == m).count();
        assert!(
            (BACKLOG + 5..=BACKLOG + 6 + refilled).contains(&mallorys),
            "{mallorys} of Mallory's taken"
        );
        assert_eq!(told.iter().filter(|from| **from == b).count(), 1);

        // Bob's cursor, 100 datagrams at once over his link: 40 taken, and
        // 40 a second while they came (one may have gone to a heartbeat of
        // his).
        let moved = Arc::new(Mutex::new(0usize));
        let hears = Arc::clone(&moved);
        ann.on_live(Arc::new(move |event| {
            if matches!(event, LiveEvent::Cursor(..)) {
                *hears.lock().unwrap() += 1;
            }
        }));
        let run = inner.live.state().participants[&b].hi.run;
        let datagrams: Vec<Vec<u8>> = (0..100)
            .map(|seq| {
                let presence = Presence {
                    from: b,
                    run,
                    seq: 10_000 + seq,
                    what: What::Cursor(Cursor {
                        place: Place::Hex,
                        address: u64::from(seq),
                        column: 0,
                        selection: None,
                    }),
                    sig: unsigned(),
                }
                .signed(&signer(&bob_id), &genesis)
                .unwrap();
                seal(&presence)
            })
            .collect();
        let start = Instant::now();
        for datagram in &datagrams {
            inner.datagram(b, datagram);
        }
        let refilled = start.elapsed().as_millis() * 40 / 1000;
        let refilled = usize::try_from(refilled).unwrap();
        let moved = *moved.lock().unwrap();
        assert!(
            (39..=41 + refilled).contains(&moved) && moved < datagrams.len(),
            "{moved} datagrams taken"
        );

        for peer in [ann, bob, mallory] {
            peer.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_backlog_dated_ahead_does_not_keep_a_new_message_from_being_told() {
        let ([_, bob_id, mal_id], [ann, bob, mallory]) = three("ahead").await;
        let (b, m) = (bob_id.public(), mal_id.public());
        let inner = ann.inner();
        let genesis = inner.genesis().unwrap();
        let told: Arc<Mutex<Vec<u64>>> = Arc::default();
        let listened = Arc::clone(&told);
        ann.on_live(Arc::new(move |event| {
            if let LiveEvent::Chat(message) = event {
                listened.lock().unwrap().push(message.id);
            }
        }));

        // Mallory's backlog: a hundred messages she dated far ahead.
        for id in 0..u64::try_from(BACKLOG).unwrap() {
            let ahead = ChatMessage {
                time: u64::MAX - id,
                ..chat(m, id, "from the future")
            };
            let ahead = ahead.signed(&signer(&mal_id), &genesis).unwrap();
            inner.take(m, Said::Chat(ahead));
        }
        // Bob's, now: told, and kept last.
        let his = chat(b, 1000, "hello")
            .signed(&signer(&bob_id), &genesis)
            .unwrap();
        inner.take(b, Said::Chat(his));
        assert!(told.lock().unwrap().contains(&1000));
        assert_eq!(ann.chat_log().last().map(|c| c.id), Some(1000));

        for peer in [ann, bob, mallory] {
            peer.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_member_who_left_is_not_shown_by_their_introduction_given_again() {
        let ([_, bob_id, mal_id], [ann, bob, mallory]) = three("replay").await;
        let (b, m) = (bob_id.public(), mal_id.public());
        let inner = ann.inner();
        let genesis = inner.genesis().unwrap();
        let present = || ann.participants().iter().any(|p| p.card.key == b);
        let last = || {
            let live = inner.live.state();
            let run = live.participants.get(&b).map(|known| known.hi.run)?;
            live.runs.get(&b)?.iter().find(|r| r.id == run)?.last
        };
        until("Ann takes a datagram of Bob's", || last().is_some()).await;
        let (hi, said) = {
            let live = inner.live.state();
            let known = &live.participants[&b];
            (known.hi.clone(), known.said.clone())
        };

        bob.close().await;
        until("Bob leaves", || !present()).await;
        // Mallory gives his introduction and presence again, as signed:
        // he is not shown.
        inner.take(m, Said::Hi(Box::new(hi.clone())));
        for presence in said {
            inner.take(m, Said::Presence(presence));
        }
        assert!(!present());

        // A datagram of his run newer than any taken (as a host gives him
        // again once he is back) shows him.
        let newer_one = Presence {
            from: b,
            run: hi.run,
            seq: inner.live.state().runs[&b]
                .iter()
                .find(|r| r.id == hi.run)
                .and_then(|r| r.last)
                .unwrap()
                .wrapping_add(1000),
            what: What::Here { following: None },
            sig: unsigned(),
        }
        .signed(&signer(&bob_id), &genesis)
        .unwrap();
        inner.take(m, Said::Presence(newer_one));
        assert!(present());

        for peer in [ann, mallory] {
            peer.close().await;
        }
    }

    /// What `peer` forwards from now on: a lane of its own, as a linked
    /// member's.
    fn watch(peer: &Peer) -> mpsc::Receiver<Said> {
        let (lane, queue) = mpsc::channel(4 * LANE_QUEUE);
        let key = Identity::ephemeral().unwrap().public();
        peer.inner()
            .live
            .state()
            .lanes
            .insert(key, (u64::MAX, lane));
        queue
    }

    /// What `queue` holds now.
    fn drained(queue: &mut mpsc::Receiver<Said>) -> Vec<Said> {
        std::iter::from_fn(|| queue.try_recv().ok()).collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[expect(
        clippy::too_many_lines,
        reason = "each kind of statement, refused, then taken"
    )]
    async fn a_statement_made_in_another_share_of_its_routing_id_is_neither_shown_kept_nor_forwarded()
     {
        let ([ann_id, bob_id, _], [ann, bob, mallory]) = three("genesis").await;
        let (a, b) = (ann_id.public(), bob_id.public());
        let inner = ann.inner();
        let genesis = inner.genesis().unwrap();
        // Ann's home log shared a second time: a first record of its own
        // for the same routing id, so another genesis. Bob is a member of
        // both.
        let project = inner.state().membership.project();
        let (first, key) = Membership::create(
            project,
            &inner.secret,
            inner.card.agreement,
            &BTreeMap::new(),
            &inner.binary,
        )
        .unwrap();
        let mut second = Membership::expecting(project, a);
        second.take(&first).unwrap();
        let added = second
            .add(&inner.secret, &key, b, bob_id.agreement(), Role::Editor)
            .unwrap();
        second.take(&added).unwrap();
        assert_eq!(second.role(b), Some(Role::Editor));
        let other = second.genesis().unwrap();
        assert_ne!(other, genesis);
        let mut lane = watch(&ann);
        let told: Arc<Mutex<Vec<u64>>> = Arc::default();
        let listened = Arc::clone(&told);
        ann.on_live(Arc::new(move |event| {
            if let LiveEvent::Chat(message) = event {
                listened.lock().unwrap().push(message.id);
            }
        }));

        // Bob's chat message, signed in the other share, over his link.
        let message = |genesis: &[u8; 32]| {
            chat(b, 1, "said in the other share")
                .signed(&signer(&bob_id), genesis)
                .unwrap()
        };
        let elsewhere = message(&other);
        assert_eq!(inner.take(b, Said::Chat(elsewhere.clone())), Heard::Done);
        assert!(!ann.chat_log().iter().any(|kept| kept.id == 1));
        assert!(!told.lock().unwrap().contains(&1));
        assert!(!drained(&mut lane).contains(&Said::Chat(elsewhere)));
        // Signed in this share, it is.
        let here = message(&genesis);
        inner.take(b, Said::Chat(here.clone()));
        assert!(ann.chat_log().contains(&here));
        assert!(told.lock().unwrap().contains(&1));
        assert!(drained(&mut lane).contains(&Said::Chat(here)));

        // His introduction, newer, with an analysis.
        let known = inner.live.state().participants[&b].hi.clone();
        let analysis = Some(Analysis {
            fingerprint: [9; 32],
            debug: None,
        });
        let introduction = |genesis: &[u8; 32]| {
            Hi {
                n: known.n + 1,
                analysis: analysis.clone(),
                ..known.clone()
            }
            .signed(&signer(&bob_id), genesis)
            .unwrap()
        };
        let bob_at_ann = || {
            ann.participants()
                .into_iter()
                .find(|p| p.card.key == b)
                .unwrap()
        };
        let elsewhere = introduction(&other);
        inner.take(b, Said::Hi(Box::new(elsewhere.clone())));
        assert_eq!(bob_at_ann().analysis, known.analysis);
        assert!(!drained(&mut lane).contains(&Said::Hi(Box::new(elsewhere))));
        let here = introduction(&genesis);
        inner.take(b, Said::Hi(Box::new(here.clone())));
        assert_eq!(bob_at_ann().analysis, analysis);
        assert!(drained(&mut lane).contains(&Said::Hi(Box::new(here))));

        // His cursor, by datagram and on the lane.
        let cipher = inner.ciphers("presence").into_iter().next().unwrap();
        let cursor = |genesis: &[u8; 32], seq: u32| {
            let presence = Presence {
                from: b,
                run: known.run,
                seq,
                what: What::Cursor(Cursor {
                    place: Place::Listing,
                    address: 0x5eed,
                    column: 0,
                    selection: None,
                }),
                sig: unsigned(),
            }
            .signed(&signer(&bob_id), genesis)
            .unwrap();
            let sealed =
                crypto::seal_bare(&cipher, &postcard::to_allocvec(&presence).unwrap()).unwrap();
            (presence, sealed)
        };
        let (elsewhere, sealed) = cursor(&other, 50_000);
        inner.datagram(b, &sealed);
        inner.take(b, Said::Presence(elsewhere.clone()));
        assert_ne!(bob_at_ann().cursor.map(|c| c.address), Some(0x5eed));
        {
            // Not kept, so not forwarded: a datagram goes on once seen.
            let live = inner.live.state();
            let kept = &live.participants[&b];
            assert!(!kept.said.contains(&elsewhere) && !kept.seen.contains(&50_000));
        }
        let (_, sealed) = cursor(&genesis, 50_001);
        inner.datagram(b, &sealed);
        assert_eq!(bob_at_ann().cursor.map(|c| c.address), Some(0x5eed));

        // The owner's removal of a message of hers, signed in the other
        // share, at Bob's.
        let to_remove = ann.chat("to be removed", &[], &[]).unwrap();
        let at_bob = || {
            bob.chat_log()
                .into_iter()
                .find(|kept| kept.id == to_remove.id)
        };
        until("Bob has Ann's message", || at_bob().is_some()).await;
        let mut bob_lane = watch(&bob);
        let removal = |genesis: &[u8; 32]| {
            Removal {
                id: to_remove.id,
                from: a,
                time: to_remove.time,
                seq: to_remove.seq,
                by: a,
                sig: unsigned(),
            }
            .signed(&signer(&ann_id), genesis)
            .unwrap()
        };
        let elsewhere = removal(&other);
        bob.inner().take(a, Said::Removed(elsewhere.clone()));
        assert_eq!(at_bob().map(|kept| kept.removed), Some(false));
        assert!(!drained(&mut bob_lane).contains(&Said::Removed(elsewhere)));
        let here = removal(&genesis);
        bob.inner().take(a, Said::Removed(here.clone()));
        assert_eq!(at_bob().map(|kept| kept.removed), Some(true));
        assert!(drained(&mut bob_lane).contains(&Said::Removed(here)));

        for peer in [ann, bob, mallory] {
            peer.close().await;
        }
    }

    #[test]
    fn a_lane_too_far_behind_is_dropped_and_the_others_kept() {
        let key = || Identity::ephemeral().unwrap().public();
        let (slow, fast, left) = (key(), key(), key());
        let mut state = State::default();
        let (to_slow, _slow) = mpsc::channel(LANE_QUEUE);
        let (to_fast, mut from_fast) = mpsc::channel(LANE_QUEUE);
        state.lanes.insert(slow, (1, to_slow));
        state.lanes.insert(fast, (2, to_fast));
        for n in 0..=LANE_QUEUE {
            assert!(state.lanes.contains_key(&slow), "dropped after {n}");
            forward(&mut state, None, &Said::Gone(left));
            while from_fast.try_recv().is_ok() {}
        }
        assert!(!state.lanes.contains_key(&slow));
        assert!(state.lanes.contains_key(&fast));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_old_links_cleanup_leaves_what_its_successor_brought() {
        let ([_, bob_id, _], [ann, bob, mallory]) = three("successor").await;
        let b = bob_id.public();
        let inner = ann.inner();
        let current = inner.live.state().lanes[&b].0;
        let present = || {
            let live = inner.live.state();
            (
                live.lanes.contains_key(&b),
                live.participants.contains_key(&b),
            )
        };
        assert_eq!(present(), (true, true));
        // The link to Bob before this one goes: his lane and he stay.
        drop(Unlive {
            inner: Arc::clone(inner),
            remote: b,
            generation: current - 1,
        });
        assert_eq!(present(), (true, true));
        // This one goes: both go.
        drop(Unlive {
            inner: Arc::clone(inner),
            remote: b,
            generation: current,
        });
        assert_eq!(present(), (false, false));

        for peer in [ann, bob, mallory] {
            peer.close().await;
        }
    }

    #[test]
    fn the_backlog_keeps_the_last_hundred_taken_in_their_order_each_once() {
        let from = Identity::ephemeral().unwrap().public();
        let message = |id: u64, time: u64| ChatMessage {
            time,
            text: Text::truncated(&id.to_string()),
            ..chat(from, id, "")
        };
        let mut state = State::default();
        // Their authors' times in any order, far ahead of now: each new
        // one is kept, the last hundred taken.
        for id in 0..150 {
            assert!(keep(&mut state, message(id, u64::MAX - id)));
        }
        let ids: Vec<u64> = state.chat.iter().map(|m| m.id).collect();
        assert_eq!(ids, (50..150).collect::<Vec<_>>());
        // Taken again, one no longer in the backlog is not new.
        assert!(!keep(&mut state, message(0, 0)));
        assert!(!keep(&mut state, message(149, 0)));
        // A new one, dated before them all, is kept last.
        assert!(keep(&mut state, message(1000, 1)));
        assert_eq!(state.chat.last().map(|m| m.id), Some(1000));
        assert_eq!(state.chat.len(), BACKLOG);
        // The ids remembered are bounded too: the oldest forgotten.
        let past = u64::try_from(CHAT_SEEN).unwrap();
        for id in 2000..2000 + past {
            keep(&mut state, message(id, 1));
        }
        assert_eq!(state.chat_ids.len(), CHAT_SEEN);
        assert!(!state.chat_ids.contains(&0));
    }

    #[test]
    fn a_chat_message_travels_whole_and_its_signature_covers_all_it_says() {
        let author = Identity::ephemeral().unwrap();
        let bob = Identity::ephemeral().unwrap().public();
        let genesis = [1; 32];
        let message = ChatMessage {
            links: Bounded::truncated(vec![ChatLink {
                start: 4,
                end: 18,
                address: 0x1E75A,
                word: false,
            }]),
            mentions: Bounded::truncated(vec![bob]),
            ..chat(author.public(), 7, "see push_stream+3A at 0x1E720")
        }
        .signed(&signer(&author), &genesis)
        .unwrap();
        // Round trip, as the live lane frames it.
        let bytes = bounded::encode(&Said::Chat(message.clone()), MAX_SAID).unwrap();
        let Ok(Said::Chat(read)) = bounded::decode::<Said>(&bytes) else {
            panic!("it does not read back");
        };
        assert_eq!(read, message);
        assert!(read.verifies(&genesis));
        // Another share's.
        assert!(!read.verifies(&[2; 32]));
        let changed: [fn(&mut ChatMessage); 7] = [
            |m| m.id += 1,
            |m| m.from = m.mentions[0],
            |m| m.time += 1,
            |m| m.seq += 1,
            |m| m.text = Text::truncated(&format!("{}!", m.text)),
            |m| m.links[0].address += 1,
            |m| m.mentions.clear(),
        ];
        for change in changed {
            let mut other = message.clone();
            change(&mut other);
            assert!(!other.verifies(&genesis), "{other:?} verifies");
        }
    }

    #[test]
    fn a_chat_messages_links_are_kept_only_inside_its_text() {
        let from = Identity::ephemeral().unwrap().public();
        let link = |start: u32, end: u32| ChatLink {
            start,
            end,
            address: 0x1000,
            word: false,
        };
        let mut message = ChatMessage {
            // `é` is two bytes: 1..2 cuts it.
            links: Bounded::truncated(vec![
                link(3, 7),
                link(1, 2),
                link(5, 5),
                link(3, 8),
                link(6, 3),
            ]),
            mentions: Bounded::truncated(vec![from; MAX_CHAT_LINKS]),
            ..chat(from, 1, "é main")
        };
        assert!(!message.fits());
        message.links = ChatMessage::fitting(&message.text, message.links.clone());
        assert_eq!(*message.links, [link(3, 7)]);
        assert!(message.fits());
        // Past the bound, the first that fit are kept.
        let many = ChatMessage::fitting(
            "main",
            vec![link(5, 6), link(0, 4), link(0, 1)]
                .into_iter()
                .chain(std::iter::repeat_n(link(1, 2), MAX_CHAT_LINKS)),
        );
        assert_eq!(many.len(), MAX_CHAT_LINKS);
        assert_eq!(many[..2], [link(0, 4), link(0, 1)]);
        message.remove();
        assert!(message.text.is_empty() && message.links.is_empty() && message.mentions.is_empty());
    }

    #[test]
    fn the_largest_presence_fits_its_datagram_and_opens_only_with_its_key() {
        let author = Identity::ephemeral().unwrap();
        let from = author.public();
        let cursor = |selection| {
            What::Cursor(Cursor {
                place: Place::C {
                    function: u64::MAX,
                    reading: true,
                    line: u32::MAX,
                },
                address: u64::MAX,
                column: u32::MAX,
                selection: Some(selection),
            })
        };
        let largest = [
            cursor(Selection::Addresses {
                first: u64::MAX,
                last: u64::MAX,
            }),
            cursor(Selection::Text {
                from: (u32::MAX, u32::MAX),
                to: (u32::MAX, u32::MAX),
            }),
            What::Here {
                following: Some(from),
            },
        ];
        let key = EpochKey::random().unwrap();
        let project = ProjectId([1; 16]);
        let genesis = [1; 32];
        let cipher = key.cipher(project, "presence");
        for what in largest {
            let presence = Presence {
                from,
                run: u64::MAX,
                seq: u32::MAX,
                what,
                sig: unsigned(),
            }
            .signed(&signer(&author), &genesis)
            .unwrap();
            let plain = postcard::to_allocvec(&presence).unwrap();
            println!(
                "largest presence: {} bytes plaintext, {} sealed",
                plain.len(),
                plain.len() + 40
            );
            assert!(plain.len() <= MAX_PRESENCE, "{} bytes", plain.len());
            // What it says comes back as it was, signed.
            let read = postcard::from_bytes::<Presence>(&plain).unwrap();
            assert!(read == presence && read.verifies(&genesis));
            let sealed = crypto::seal_bare(&cipher, &plain).unwrap();
            assert_eq!(sealed.len(), plain.len() + 40);
            assert!(sealed.len() <= super::MAX_DATAGRAM);
            assert_eq!(*crypto::open_bare(&cipher, &sealed).unwrap(), plain);
            let other = key.cipher(ProjectId([2; 16]), "presence");
            assert!(crypto::open_bare(&other, &sealed).is_none());
            let chat = key.cipher(project, "live");
            assert!(crypto::open_bare(&chat, &sealed).is_none());
        }
        assert!(newer(1, 0) && newer(0, u32::MAX) && !newer(5, 5) && !newer(4, 5));
    }
}
