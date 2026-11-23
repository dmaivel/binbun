//! The journal: the user's edits as a log of signed changes, of which
//! [`crate::Edits`] is the projection.
//!
//! - **Changes** ([`SignedChange`]: a signed [`Head`] and a [`Body`];
//!   [`change`] has the format): one per group of edits
//!   ([`crate::Session::begin`] … [`crate::Session::commit`]) or per edit
//!   made outside one; one undo step (a group too large for one change
//!   is split into up to 16, one step, one history entry: [`Group`]).
//!   Each holds **ops** ([`Op`]) on typed
//!   keys ([`Key`]) with the leaves of the key its author saw (`prev`), is
//!   stamped by a hybrid logical clock ([`Hlc`]) and signed by its
//!   author's identity key. Each author's changes make a chain
//!   ([`ChainId`]): numbered from 1, each naming its predecessor's hash;
//!   the first is the chain's **start**, which says whose it is and what
//!   it is of ([`Bound`]: the share, if any, and the binary) and edits
//!   nothing.
//! - **Changes from elsewhere** ([`remote`]) are checked before they are
//!   taken, and in a share's journal judged by an [`Authority`]; a chain
//!   its author equivocates on or writes what it may never freezes, with
//!   its evidence kept ([`Evidence`]). A share's journal tells apart
//!   what is admitted, pending and apart ([`shared`]).
//! - **Keys** are multi-value registers: the value shown is the leaf with
//!   the highest [`Stamp`] (a bookmark's name before its removal), and more
//!   than one leaf is a [`Conflict`], never silent. The projection applies
//!   each key's winner through the edits' setters; corrections' items in
//!   stamp order, so a later item replaces those it overlaps on every
//!   peer alike.
//! - **Undo** is per author and by compare-and-set: undoing a
//!   change writes a change of the values before it on the keys still as
//!   it left them; a key changed since by someone else is skipped and
//!   reported ([`Undone::skipped`]).
//! - **Bookmarks** ([`private`]): each author's are their own keys,
//!   this author's shown in the edits, every other's beside them
//!   ([`Journal::others_bookmarks`]); this install's private ones are
//!   kept apart from the log, their edits undo steps in order with this
//!   author's changes.
//! - **Conversation** ([`talk`]): threads anchored to addresses, posts
//!   and suggestions are append-only keys of the same log, never part of
//!   the edits' projection.

mod authority;
pub mod change;
mod private;
mod register;
pub mod remote;
pub mod shared;
#[cfg(test)]
mod shared_tests;
pub(crate) mod store;
pub mod talk;
#[cfg(test)]
mod talk_tests;
#[cfg(test)]
mod tests;
pub(crate) mod wire;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use binbun::corrections::{Bounds, Corrections, Item};
use ed25519_dalek::SigningKey;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::edits::{Edit, Edits, Identified, NumberForm, Typed, Variable};
use crate::identity::Identity;
use crate::number::canonical;
use crate::project::{Project, write_safely};
pub use authority::{Authority, Cause, FrozenBy, MAX_WHY, Verdict, Why};
pub use change::{
    Body, Bound, Canonical, ChangeHash, Evidence, FIRST_HEAD, ForkProof, Group, HEAD, Head,
    MAX_BODY, MAX_OPS, MAX_PARTS, MAX_PROOF, MAX_SIGNED_HEAD, MAX_START, Malformed, Of, SIG,
    SignedChange, SignedHead, TIP, Tip, Under,
};
pub(crate) use private::{LABEL as PRIVATE_LABEL, PrivateEdit, holds as private_holds};
use private::{Private, Step};
use register::{Entry, Register};
pub use remote::{
    Applied, ForkTaken, Learnt, MAX_CHAINS, MAX_CHAINS_PER_AUTHOR, Refused, Stop, Stopped,
    VersionVector,
};
pub use shared::{Bringable, LocalEdit};
pub use store::Intent;
use store::Store;
use talk::{Author, PostOp, SuggestionOp, SuggestionState, ThreadOp};

/// A hybrid logical clock's time (Kulkarni et al. 2014): 48 bits of Unix
/// milliseconds, then 16 bits of counter; ordered as a number.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Hlc(pub u64);

impl Hlc {
    /// The time `millis` with counter `counter`.
    pub fn new(millis: u64, counter: u16) -> Self {
        Self((millis << 16) | u64::from(counter))
    }

    /// Its Unix milliseconds.
    pub fn millis(self) -> u64 {
        self.0 >> 16
    }

    /// Its counter.
    pub fn counter(self) -> u16 {
        u16::try_from(self.0 & 0xffff).unwrap_or(u16::MAX)
    }

    /// The time a change made now (`now` Unix milliseconds) takes, after
    /// this one: later than every time seen.
    #[must_use]
    pub fn send(self, now: u64) -> Self {
        if now > self.millis() {
            Self::new(now, 0)
        } else {
            Self::next_of(self.millis(), self.counter())
        }
    }

    /// The clock after a change stamped `remote` is received at `now`.
    #[must_use]
    pub fn receive(self, remote: Self, now: u64) -> Self {
        let (mine, theirs) = (self.millis(), remote.millis());
        let millis = mine.max(theirs).max(now);
        match (millis == mine, millis == theirs) {
            (true, true) => Self::next_of(millis, self.counter().max(remote.counter())),
            (true, false) => Self::next_of(millis, self.counter()),
            (false, true) => Self::next_of(millis, remote.counter()),
            (false, false) => Self::new(millis, 0),
        }
    }

    /// `counter` + 1 at `millis`, or the next millisecond's first.
    fn next_of(millis: u64, counter: u16) -> Self {
        counter.checked_add(1).map_or_else(
            || Self::new(millis + 1, 0),
            |counter| Self::new(millis, counter),
        )
    }
}

/// Now, in Unix milliseconds.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Writes `bytes` in lower-case hexadecimal.
fn hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    bytes.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
}

/// A project's identity in the log: random at its first change, never
/// derived from the binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProjectId(pub [u8; 16]);

impl fmt::Display for ProjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(&self.0, f)
    }
}

/// One author's changes to one project: `BLAKE3(author ‖ project ‖ 16
/// random bytes)`'s first 16 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChainId(pub [u8; 16]);

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(&self.0, f)
    }
}

/// What a chain's id is made of, which its first change carries, signed
/// by its author: whoever passes the change on, anyone can tell whose the
/// chain is ([`Self::chain`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChainOrigin {
    /// Its author.
    pub author: PublicKey,
    /// The project its author's changes are of (not the one shared, if
    /// they joined with a project of their own).
    pub project: ProjectId,
    /// 16 random bytes.
    pub salt: [u8; 16],
}

impl ChainOrigin {
    /// The chain it makes: `BLAKE3(author ‖ project ‖ salt)`'s first 16
    /// bytes.
    pub fn chain(&self) -> ChainId {
        chain_id(self.author, self.project, &self.salt)
    }
}

/// A change: its chain and its number there (from 1, contiguous).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChangeId {
    /// The chain.
    pub chain: ChainId,
    /// Its number in the chain.
    pub seq: u64,
}

/// An op: its change and its place there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OpId {
    /// The change.
    pub change: ChangeId,
    /// Its index among the change's ops.
    pub index: u16,
}

/// An op's place in the total order: by time, then chain, number, index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Stamp {
    /// Its change's time.
    pub hlc: Hlc,
    /// Its chain.
    pub chain: ChainId,
    /// Its change's number.
    pub seq: u64,
    /// Its index in the change.
    pub index: u16,
}

/// An ed25519 public key: an author's identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(&self.0, f)
    }
}

/// An encrypted blob's id: the BLAKE3 of its ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlobId(pub [u8; 32]);

/// The binbun that made a change.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EngineVersion {
    /// The release.
    #[serde(deserialize_with = "wire::text")]
    pub release: String,
    /// The build: `BINBUN_BUILD` as set when binbun was built, else 12
    /// hexadecimal digits of a hash of the engine's source (`build.rs`),
    /// the same for the same source on every machine.
    #[serde(deserialize_with = "wire::text")]
    pub build: String,
}

impl EngineVersion {
    /// This binbun's.
    pub fn this() -> Self {
        Self {
            release: env!("CARGO_PKG_VERSION").to_owned(),
            build: env!("BINBUN_BUILD").to_owned(),
        }
    }
}

/// Who or what made a change.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Origin {
    /// The user, in a front end.
    User,
    /// A script (`script:<name>`).
    Script(#[serde(deserialize_with = "wire::text")] String),
    /// A plugin (`plugin:<id>`).
    Plugin(#[serde(deserialize_with = "wire::text")] String),
    /// An agent.
    Agent,
    /// Edits taken from elsewhere (a project file written outside the
    /// log, an exported project without one).
    Import(#[serde(deserialize_with = "wire::text")] String),
    /// Undoing this change.
    Undo(ChangeId),
    /// Making this undone change again.
    Redo(ChangeId),
    /// Accepting this suggestion.
    Accept(OpId),
    /// Library signatures applied: the pack and its revision
    /// (`musl-1.2.5@1`).
    Signature(#[serde(deserialize_with = "wire::text")] String),
}

impl Origin {
    /// `user`, `script:<name>`, `plugin:<id>`, `agent`, as Python spells
    /// a change's author: an origin of one of those (else `None`).
    pub fn parse(author: &str) -> Option<Self> {
        match author {
            "user" => Some(Self::User),
            "agent" => Some(Self::Agent),
            _ => {
                if let Some(name) = author.strip_prefix("script:") {
                    Some(Self::Script(name.to_owned()))
                } else {
                    author
                        .strip_prefix("plugin:")
                        .map(|id| Self::Plugin(id.to_owned()))
                }
            }
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => f.write_str("user"),
            Self::Script(name) => write!(f, "script:{name}"),
            Self::Plugin(id) => write!(f, "plugin:{id}"),
            Self::Agent => f.write_str("agent"),
            Self::Import(from) => write!(f, "import:{from}"),
            Self::Undo(_) => f.write_str("undo"),
            Self::Redo(_) => f.write_str("redo"),
            Self::Accept(_) => f.write_str("accept"),
            Self::Signature(pack) => write!(f, "sig:{pack}"),
        }
    }
}

/// What a key names: one per kind of edit, by the identity it survives
/// re-analysis by. New kinds are only ever added after these, so a
/// stored change always reads.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Key {
    /// The name of the function at this entry.
    FunctionName(u64),
    /// The name of the global at this address.
    GlobalName(u64),
    /// A variable's name.
    VariableName(Variable),
    /// The name of a frame slot: its function's entry, its offset.
    Slot(u64, i64),
    /// The comment at this address.
    Comment(u64),
    /// A bookmark: its author's (bookmarks are each author's own) at this
    /// address.
    Bookmark(PublicKey, u64),
    /// The form of a number an instruction uses: its address, the
    /// number's [`canonical`] value (one form per number at every width).
    Number(u64, u64),
    /// A user's type.
    Type(Typed),
    /// A user's definition, by the key it defines.
    Definition(#[serde(deserialize_with = "wire::text")] String),
    /// A correction: what the bytes at this address are.
    Item(u64),
    /// A correction: the bounds of the function at this entry.
    Bounds(u64),
    /// The debug information analysed with.
    DebugFile,
    /// A thread: the op opening it ([`talk::ThreadOp`]).
    Thread(OpId),
    /// A post: the op posting it ([`talk::PostOp`]).
    Post(OpId),
    /// A suggestion: the op making it ([`talk::SuggestionOp`]).
    Suggestion(OpId),
    /// What a library signature says of the function at this entry
    /// ([`Identified`]).
    Signature(u64),
}

/// A number as an instruction uses it, and its form.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Stated {
    /// The number's bits, at the width stated.
    pub value: u64,
    /// Its form.
    pub form: NumberForm,
}

/// The debug information a project is analysed with.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DebugRef {
    /// Its file's SHA-256.
    pub sha256: [u8; 32],
    /// Its file name.
    #[serde(deserialize_with = "wire::text")]
    pub name: String,
    /// The build id it names, if any.
    #[serde(deserialize_with = "wire::opt_bytes")]
    pub build_id: Option<Vec<u8>>,
    /// Its blob, if shared.
    pub blob: Option<BlobId>,
}

/// A key's value; `None`s clear (tombstones).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Value {
    /// A name, comment, bookmark's name, type or definition as C.
    Text(#[serde(deserialize_with = "wire::opt_text")] Option<String>),
    /// A number's form.
    Number(Option<Stated>),
    /// What bytes are.
    Item(#[serde(with = "wire::item")] Option<Item>),
    /// A function's bounds.
    Bounds(#[serde(with = "wire::bounds")] Option<Bounds>),
    /// The debug information.
    DebugFile(Option<DebugRef>),
    /// An op on a thread.
    Thread(ThreadOp),
    /// An op on a post.
    Post(PostOp),
    /// An op on a suggestion.
    Suggestion(SuggestionOp),
    /// What a signature says of a function.
    Signature(Option<Box<Identified>>),
}

impl Value {
    /// Whether it sets something (not a tombstone; conversation ops
    /// always do).
    pub fn is_some(&self) -> bool {
        match self {
            Self::Text(text) => text.is_some(),
            Self::Number(stated) => stated.is_some(),
            Self::Item(item) => item.is_some(),
            Self::Bounds(bounds) => bounds.is_some(),
            Self::DebugFile(debug) => debug.is_some(),
            Self::Signature(identified) => identified.is_some(),
            Self::Thread(_) | Self::Post(_) | Self::Suggestion(_) => true,
        }
    }

    /// The tombstone of `key`'s kind (a conversation key's: a thread
    /// opened again, a post deleted, a suggestion pending).
    pub fn none(key: &Key) -> Self {
        match key {
            Key::FunctionName(_)
            | Key::GlobalName(_)
            | Key::VariableName(_)
            | Key::Slot(..)
            | Key::Comment(_)
            | Key::Bookmark(..)
            | Key::Type(_)
            | Key::Definition(_) => Self::Text(None),
            Key::Number(..) => Self::Number(None),
            Key::Item(_) => Self::Item(None),
            Key::Bounds(_) => Self::Bounds(None),
            Key::DebugFile => Self::DebugFile(None),
            Key::Thread(_) => Self::Thread(ThreadOp::Resolve(false)),
            Key::Post(_) => Self::Post(PostOp::Delete),
            Key::Suggestion(_) => Self::Suggestion(SuggestionOp::State(SuggestionState::Pending)),
            Key::Signature(_) => Self::Signature(None),
        }
    }

    /// Whether it is a value `key` can take.
    pub fn fits(&self, key: &Key) -> bool {
        match (key, self) {
            (Key::Number(_, canon), Self::Number(stated)) => stated
                .as_ref()
                .is_none_or(|stated| canonical(stated.value) == *canon),
            (Key::Item(_), Self::Item(item)) => item.as_ref().is_none_or(wire::item::holds),
            (key, value) => {
                std::mem::discriminant(&Self::none(key)) == std::mem::discriminant(value)
            }
        }
    }

    /// Its text, if a text.
    fn text(&self) -> Option<String> {
        match self {
            Self::Text(text) => text.clone(),
            Self::Number(_)
            | Self::Item(_)
            | Self::Bounds(_)
            | Self::DebugFile(_)
            | Self::Thread(_)
            | Self::Post(_)
            | Self::Suggestion(_)
            | Self::Signature(_) => None,
        }
    }
}

/// An op: a key's new value, and the leaves of the key its author saw.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Op {
    /// The key.
    pub key: Key,
    /// Its value.
    pub value: Value,
    /// The leaves of the key its author saw: its causal context.
    #[serde(deserialize_with = "wire::list::<_, OpId, { wire::LIST }>")]
    pub prev: Vec<OpId>,
}

/// An author's identity key, which signs their changes.
#[derive(Clone)]
pub struct Signer {
    key: SigningKey,
    public: PublicKey,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// The key whose secret is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let public = PublicKey(key.verifying_key().to_bytes());
        Self { key, public }
    }

    /// A new key, kept nowhere (an ephemeral session's).
    ///
    /// # Errors
    ///
    /// The system has no randomness.
    pub fn ephemeral() -> Result<Self, String> {
        Ok(Self::from_seed(&random()?))
    }

    /// Its public half.
    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// Its secret.
    pub(crate) fn secret(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

/// `N` random bytes.
///
/// # Errors
///
/// The system has no randomness.
pub(crate) fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "the system has no randomness".to_owned())?;
    Ok(bytes)
}

/// A change taken: its id, body, signed form, author and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) id: ChangeId,
    pub(crate) body: Body,
    pub(crate) signed: SignedChange,
    pub(crate) author: PublicKey,
    pub(crate) hash: ChangeHash,
}

impl Record {
    /// Whether it is its chain's start (no edits).
    pub(crate) fn is_start(&self) -> bool {
        self.id.seq == 1
    }
}

/// An agent this install signs for.
#[derive(Clone, Debug)]
struct LocalAgent {
    identity: Identity,
    /// The chain its changes go on.
    chain: ChainId,
    /// What it is called (`Codex`).
    name: String,
}

/// What is known of a chain.
#[derive(Clone, Debug)]
struct Chain {
    author: PublicKey,
    /// What makes its id.
    origin: ChainOrigin,
    /// Its start, as verified: kept whatever is frozen after it.
    start: SignedChange,
    /// What its start binds it to.
    bound: Bound,
    /// Its last change taken (its start at least): number and hash.
    seq: u64,
    hash: ChangeHash,
}

/// A key with more than one leaf: concurrent edits, shown, never silent.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Conflict {
    /// The key.
    pub key: Key,
    /// Its leaves, by stamp.
    pub leaves: Vec<LeafInfo>,
    /// The leaf shown.
    pub shown: OpId,
}

/// One leaf of a conflicted key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LeafInfo {
    /// The op.
    pub op: OpId,
    /// Its author.
    pub author: PublicKey,
    /// Its stamp.
    pub stamp: Stamp,
    /// Its value.
    pub value: Value,
}

/// A change in the history.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HistoryEntry {
    /// The change.
    pub id: ChangeId,
    /// Its author's identity.
    pub author: PublicKey,
    /// Who or what made it.
    pub origin: Origin,
    /// What it did.
    pub label: String,
    /// When.
    pub time: Hlc,
    /// The edits it made.
    pub edits: usize,
    /// Whether this install's identity made it.
    pub mine: bool,
    /// Who made the suggestion it accepted, if it accepted one
    /// ([`Origin::Accept`]).
    pub suggested_by: Option<Author>,
}

/// An op an undo or redo did not write: its key was changed since.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Skipped {
    /// The key.
    pub key: Key,
    /// Who changed it since (the authors of its leaves now).
    pub by: Vec<PublicKey>,
    /// Its value now.
    pub value: Option<Value>,
}

/// What an undo or redo did.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Undone {
    /// The change undone or made again; none for a private bookmark's
    /// edit alone ([`crate::Session::bookmark_private`]).
    pub target: Option<ChangeId>,
    /// Its label.
    pub label: String,
    /// The change written.
    pub change: Option<HistoryEntry>,
    /// The ops not undone: changed since.
    pub skipped: Vec<Skipped>,
}

/// An undo or redo to write: its ops and what it skips.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub(crate) target: ChangeId,
    pub(crate) origin: Origin,
    pub(crate) label: String,
    pub(crate) ops: Vec<(Key, Value)>,
    pub(crate) skipped: Vec<Skipped>,
    /// The private bookmark's edit to make with it (the step moved a
    /// bookmark between shared and private).
    pub(crate) private: Option<PrivateEdit>,
    /// The freezes marked when it was planned ([`Journal::begin_planned`]):
    /// a freeze since may have withdrawn a value it restores.
    pub(crate) freezes: u64,
}

/// The change being made: its ops so far, one per key, in the order
/// last written.
#[derive(Clone, Debug)]
pub(crate) struct Pending {
    label: String,
    origin: Origin,
    /// The agent of this install's that makes it (signed by its key, on
    /// its chain); `None`: this install's identity.
    by: Option<PublicKey>,
    /// Groups begun and not committed.
    depth: u32,
    ops: Vec<Option<Op>>,
    index: BTreeMap<Key, usize>,
    /// The threads, posts and suggestions made so far ([`OpId::index`]
    /// of the next).
    created: u16,
    /// The private bookmark's edit made with it, one undo step
    /// ([`Journal::attach_private`]).
    private: Option<PrivateEdit>,
    /// The freezes marked when the undo or redo it writes was planned
    /// ([`Journal::begin_planned`]); none for any other group.
    planned: Option<u64>,
}

impl Pending {
    /// The value written to `key`, if it was.
    fn value(&self, key: &Key) -> Option<&Value> {
        let &at = self.index.get(key)?;
        self.ops.get(at)?.as_ref().map(|op| &op.value)
    }
}

/// What committing came to.
#[derive(Clone, Debug)]
pub(crate) enum Committed {
    /// No group was open, or it wrote nothing.
    Empty,
    /// An inner group: the outer one is still open.
    Open,
    /// The changes made, in order: its chain's start first if this began
    /// the chain, then its parts (more than one: a group too large for one
    /// change). One undo step.
    Sealed(Vec<Arc<Record>>),
}

/// A shared journal's state of admission (sync §4.5).
#[derive(Clone, Debug)]
pub(crate) struct Share {
    /// The share's genesis.
    pub(crate) genesis: [u8; 32],
    /// The prefixes of chains begun in no share that the share's first
    /// record lists: up to which number, the hash there.
    pub(crate) before: BTreeMap<ChainId, (u64, ChangeHash)>,
    /// The marks as the log keeps them: what is told, served and
    /// acknowledged.
    pub(crate) marks: BTreeMap<ChainId, (u64, ChangeHash)>,
    /// The marks as admitted here, kept once the changes and the marks
    /// are written ([`Journal::flush`]).
    pub(crate) admitted: BTreeMap<ChainId, (u64, ChangeHash)>,
    /// The chains with changes kept apart: never written to again.
    pub(crate) apart: BTreeSet<ChainId>,
    /// The grants the share last gave this install and its agents, by
    /// key (`log/grants`): what a chain begun while collaboration is not
    /// attached names.
    pub(crate) grants: BTreeMap<PublicKey, u64>,
}

/// The changes of a project known to this session, its keys' state, and
/// this author's undo and redo.
#[derive(Clone)]
pub(crate) struct Journal {
    /// The log's id: the origin of the chains begun here.
    project: ProjectId,
    /// What the chains of this journal are of (`log/bound`).
    of: Of,
    signer: Signer,
    /// The chain this author's next change goes on.
    chain: ChainId,
    /// What makes the ids of the chains this install and its agents write
    /// and have not begun yet (a chain begun says it in its start).
    origins: BTreeMap<ChainId, ChainOrigin>,
    /// The chains this install and its agents write, begun (`log/local`).
    mine: BTreeSet<ChainId>,
    /// Whether `mine` changed since the log last kept it.
    mine_unsaved: bool,
    /// The agents this install signs for (`binbun mcp`, `binbun.connect(agent=…)`),
    /// by key: each writes on a chain of its own, its changes on this
    /// install's undo.
    agents: BTreeMap<PublicKey, LocalAgent>,
    clock: Hlc,
    engine: EngineVersion,
    records: BTreeMap<ChangeId, Arc<Record>>,
    chains: BTreeMap<ChainId, Chain>,
    registers: BTreeMap<Key, Register>,
    /// This author's steps to undo, last last.
    undo: Vec<Step>,
    /// The steps undone, last last, each with the change undoing it (none
    /// for a private bookmark's edit alone).
    redo: Vec<(Step, Option<ChangeId>)>,
    pending: Option<Pending>,
    /// Changes made and not saved yet, in order.
    unsaved: Vec<ChangeId>,
    /// Changes waiting, by the change each waits for: [`remote::MAX_HELD`]
    /// and [`remote::MAX_HELD_BYTES`] at most.
    held: BTreeMap<ChangeId, Vec<SignedChange>>,
    /// How many changes wait.
    holding: usize,
    /// The bytes of the changes waiting (as signed).
    held_bytes: usize,
    /// Changes refused, in the order refused: the latest
    /// [`remote::MAX_REFUSED`].
    refused: Vec<Refused>,
    /// The chains frozen: from which change, and why; as the log keeps
    /// them (written before they take effect).
    frozen: BTreeMap<ChainId, (u64, FrozenBy)>,
    /// The chains frozen whose changes past the freeze are still to be
    /// taken out of the keys, from which change: a freeze marks under one
    /// hold and takes them out afterwards, a batch at a time
    /// ([`Self::settle_step`]). Not told, served or depended on meanwhile.
    withdrawing: BTreeMap<ChainId, u64>,
    /// The freezes marked so far, counted ([`Self::mark_frozen`]): an
    /// undo or redo planned under fewer is planned again before it is
    /// made ([`Plan::freezes`]).
    freezes: u64,
    /// Whether held changes may be let go, past the most a turn takes
    /// ([`remote::MAX_RELEASED`]) or since a freeze.
    releasing: bool,
    /// Whether a thread is settling them ([`crate::Session`]'s).
    pub(crate) settling: bool,
    /// What the batches came to since last asked, while collaboration is
    /// attached ([`Self::take_settled`]).
    settled: Applied,
    /// Per chain frozen by its author's own doing, what shows it: a fork
    /// proof or a refused head; as the log keeps it.
    evidence: BTreeMap<ChainId, Evidence>,
    /// The share, if the journal is a share's.
    share: Option<Share>,
    /// Who may write what in the share, while collaboration is attached.
    authority: Option<Arc<dyn Authority>>,
    /// Whether the last commit refused was refused by the share (or a join
    /// under way), not for its own bounds ([`Self::refused_at_source`]).
    at_source: std::cell::Cell<bool>,
    /// The authors whose clocks run ahead.
    ahead: BTreeSet<PublicKey>,
    /// Where its changes are kept; none in an ephemeral session.
    store: Option<Store>,
    /// The conversation ops taken since [`Self::talked`] was last asked,
    /// with their keys.
    heard: Vec<(Key, OpId)>,
    /// The project's owners (ever): who may delete anyone's post.
    owners: BTreeSet<PublicKey>,
    /// The identities besides this one whose mentions are told here.
    voices: BTreeSet<PublicKey>,
    /// This install's private bookmarks of the project.
    private: Private,
}

impl fmt::Debug for Journal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Journal")
            .field("project", &self.project)
            .field("of", &self.of)
            .field("chain", &self.chain)
            .field("changes", &self.records.len())
            .field("share", &self.share)
            .field("attached", &self.authority.is_some())
            .finish_non_exhaustive()
    }
}

impl Journal {
    /// No changes yet, in the log `project` of chains of `of`, made by
    /// `signer` on a chain of its own.
    ///
    /// # Errors
    ///
    /// The system has no randomness.
    pub(crate) fn new(project: ProjectId, of: Of, signer: Signer) -> Result<Self, String> {
        let mut journal = Self {
            project,
            of,
            chain: ChainId([0; 16]),
            signer,
            origins: BTreeMap::new(),
            mine: BTreeSet::new(),
            mine_unsaved: false,
            agents: BTreeMap::new(),
            clock: Hlc::default(),
            engine: EngineVersion::this(),
            records: BTreeMap::new(),
            chains: BTreeMap::new(),
            registers: BTreeMap::new(),
            undo: Vec::new(),
            redo: Vec::new(),
            pending: None,
            unsaved: Vec::new(),
            held: BTreeMap::new(),
            holding: 0,
            held_bytes: 0,
            refused: Vec::new(),
            frozen: BTreeMap::new(),
            withdrawing: BTreeMap::new(),
            freezes: 0,
            releasing: false,
            settling: false,
            settled: Applied::default(),
            evidence: BTreeMap::new(),
            share: None,
            authority: None,
            at_source: std::cell::Cell::new(false),
            ahead: BTreeSet::new(),
            store: None,
            heard: Vec::new(),
            owners: BTreeSet::new(),
            voices: BTreeSet::new(),
            private: Private::default(),
        };
        journal.chain = journal.fresh_chain(journal.author())?;
        Ok(journal)
    }

    /// An ephemeral one: a random project, a key kept nowhere, of a binary
    /// not known yet ([`Self::bind`]).
    ///
    /// # Errors
    ///
    /// The system has no randomness.
    pub(crate) fn ephemeral() -> Result<Self, String> {
        let unknown = Of::Binary {
            sha256: [0; 32],
            slice: None,
        };
        Self::new(ProjectId(random()?), unknown, Signer::ephemeral()?)
    }

    /// What its chains are of.
    pub(crate) fn of(&self) -> &Of {
        &self.of
    }

    /// Its chains are of `of` from now on, if none is begun yet (an
    /// ephemeral session's, once its binary is known; a session following
    /// another's); whether they are.
    pub(crate) fn bind(&mut self, of: Of) -> bool {
        if self.chains.is_empty() || self.of == of {
            self.of = of;
            true
        } else {
            false
        }
    }

    /// This author's identity.
    pub(crate) fn author(&self) -> PublicKey {
        self.signer.public
    }

    /// Whose the change being made is: the group open's agent, else (or
    /// none open) this install's identity.
    pub(crate) fn writing_as(&self) -> PublicKey {
        self.pending
            .as_ref()
            .and_then(|pending| pending.by)
            .unwrap_or_else(|| self.author())
    }

    /// Signs for agent `name` with `identity` from now on, on a chain of
    /// its own (its last one here, unless that one is broken); its key.
    ///
    /// # Errors
    ///
    /// The key is this install's; the system has no randomness.
    pub(crate) fn add_agent(
        &mut self,
        identity: Identity,
        name: &str,
    ) -> Result<PublicKey, String> {
        let key = identity.public();
        if key == self.author() {
            return Err("an agent's key is not this install's".to_owned());
        }
        if let Some(agent) = self.agents.get_mut(&key) {
            name.clone_into(&mut agent.name);
            return Ok(key);
        }
        let last = self
            .chains
            .iter()
            .filter(|(_, chain)| chain.author == key)
            .max_by_key(|(_, chain)| chain.seq)
            .map(|(&id, _)| id)
            .filter(|&chain| self.writable(chain));
        let chain = match last {
            Some(chain) => chain,
            None => self.fresh_chain(key)?,
        };
        self.agents.insert(
            key,
            LocalAgent {
                identity,
                chain,
                name: name.to_owned(),
            },
        );
        Ok(key)
    }

    /// The agents this install signs for: key and name.
    pub(crate) fn agents(&self) -> Vec<(PublicKey, String)> {
        self.agents
            .iter()
            .map(|(&key, agent)| (key, agent.name.clone()))
            .collect()
    }

    /// The identity of agent `key`, if this install signs for it.
    pub(crate) fn agent_identity(&self, key: PublicKey) -> Option<&Identity> {
        self.agents.get(&key).map(|agent| &agent.identity)
    }

    /// Signs for `from`'s agents too (each on a new chain of this
    /// project's).
    ///
    /// # Errors
    ///
    /// The system has no randomness.
    pub(crate) fn carry_agents(&mut self, from: &Self) -> Result<(), String> {
        for agent in from.agents.values() {
            self.add_agent(agent.identity.clone(), &agent.name)?;
        }
        Ok(())
    }

    /// Whether `chain` is written here: this install's or one of its
    /// agents'.
    fn local(&self, chain: ChainId) -> bool {
        chain == self.chain || self.agents.values().any(|agent| agent.chain == chain)
    }

    /// Whether a chain this install or an agent of it wrote may go on: it
    /// is bound as a chain its author begun here now would be (the same
    /// share and log, and the grant the share gives its author now, while
    /// collaboration is attached), nothing of it is frozen, held, refused
    /// or apart, and its file reads.
    fn writable(&self, chain: ChainId) -> bool {
        let Some(known) = self.chains.get(&chain) else {
            return false;
        };
        let genesis = self.share.as_ref().map(|share| share.genesis);
        let granted = match (&self.authority, known.bound.share) {
            (Some(authority), Some(under)) => authority.grant(known.author) == Some(under.grant),
            (None, _) | (Some(_), None) => true,
        };
        known.bound.of == self.of
            && known.bound.share.map(|under| under.genesis) == genesis
            && granted
            && !self.frozen.contains_key(&chain)
            && !self.held.keys().any(|id| id.chain == chain)
            && !self
                .refused
                .iter()
                .any(|refused| refused.change.is_some_and(|id| id.chain == chain))
            && !self
                .share
                .as_ref()
                .is_some_and(|share| share.apart.contains(&chain))
            && !self
                .store
                .as_ref()
                .is_some_and(|store| store.unreadable(chain))
    }

    /// What a chain `author` begins here now names: what its chains are
    /// of and, if the journal is a share's, the share with the grant it is
    /// written under: the one the authority attached gives the author, or
    /// with none attached, the one it last gave (judged when it is told:
    /// a grant since closed leaves its work apart).
    ///
    /// # Errors
    ///
    /// The journal is a share's and no grant of the author's is known
    /// here.
    pub(crate) fn binding(&self, author: PublicKey) -> Result<Bound, String> {
        let share = match &self.share {
            None => None,
            Some(share) => {
                let grant = match &self.authority {
                    Some(authority) => authority.grant(author),
                    None => share.grants.get(&author).copied(),
                };
                let grant = grant.ok_or_else(|| {
                    // Refused by the share: the author has no role in it.
                    self.at_source.set(true);
                    format!("no grant of {author} in the share is known here: nothing is written")
                })?;
                Some(Under {
                    genesis: share.genesis,
                    grant,
                })
            }
        };
        Ok(Bound {
            share,
            of: self.of.clone(),
        })
    }

    /// Writes this install's (and each agent's) changes on a new chain
    /// from now on where the chain begun is not of the grant the authority
    /// attached gives its author now (a record set their entry: a raise, a
    /// lowering, a readmission): new rights are used on a new chain, and
    /// a chain keeps the role of its own grant (sync §4.3).
    ///
    /// # Errors
    ///
    /// A group is open; no randomness.
    pub(crate) fn regrant(&mut self) -> Result<(), String> {
        let Some(authority) = self.authority.clone() else {
            return Ok(());
        };
        self.keep_grants()?;
        let other = |journal: &Self, chain: ChainId| {
            journal.chains.get(&chain).is_some_and(|known| {
                known.bound.share.is_some_and(|under| {
                    authority
                        .grant(known.author)
                        .is_some_and(|grant| grant != under.grant)
                })
            })
        };
        let me = other(self, self.chain);
        let agents: Vec<PublicKey> = self
            .agents
            .iter()
            .filter(|(_, agent)| other(self, agent.chain))
            .map(|(&key, _)| key)
            .collect();
        if (me || !agents.is_empty()) && self.pending.is_some() {
            return Err("a group is open: commit or roll it back first".to_owned());
        }
        if me {
            self.chain = self.fresh_chain(self.author())?;
        }
        for key in agents {
            let fresh = self.fresh_chain(key)?;
            if let Some(agent) = self.agents.get_mut(&key) {
                agent.chain = fresh;
            }
        }
        Ok(())
    }

    /// Keeps the grants the authority attached gives this install and its
    /// agents now, in the share's state and in the log if they changed.
    ///
    /// # Errors
    ///
    /// They cannot be written.
    pub(crate) fn keep_grants(&mut self) -> Result<(), String> {
        let (Some(authority), Some(share)) = (&self.authority, &self.share) else {
            return Ok(());
        };
        let grants: BTreeMap<PublicKey, u64> = std::iter::once(self.author())
            .chain(self.agents.keys().copied())
            .filter_map(|key| Some((key, authority.grant(key)?)))
            .collect();
        if grants == share.grants {
            return Ok(());
        }
        if let Some(store) = &self.store {
            store.set_grants(&grants)?;
        }
        if let Some(share) = &mut self.share {
            share.grants = grants;
        }
        Ok(())
    }

    /// A new chain of `author`'s in this log, not begun (its start is made
    /// with its first change).
    ///
    /// # Errors
    ///
    /// The system has no randomness.
    fn fresh_chain(&mut self, author: PublicKey) -> Result<ChainId, String> {
        let origin = ChainOrigin {
            author,
            project: self.project,
            salt: random()?,
        };
        let chain = origin.chain();
        self.origins.insert(chain, origin);
        Ok(chain)
    }

    /// The origin of chain `chain`, as its start says it.
    pub(crate) fn chain_origin(&self, chain: ChainId) -> Option<ChainOrigin> {
        self.chains.get(&chain).map(|known| known.origin)
    }

    /// The project its changes are of.
    pub(crate) fn project(&self) -> ProjectId {
        self.project
    }

    /// Whether a group is open.
    pub(crate) fn in_group(&self) -> bool {
        self.pending.is_some()
    }

    /// Opens a group labelled `label` made by `origin`, or joins the one
    /// open (its label and origin kept).
    pub(crate) fn begin(&mut self, label: &str, origin: Origin) {
        self.begin_as(label, origin, None);
    }

    /// Opens a group labelled `label` made by `origin` as agent `by` (one
    /// of [`Self::add_agent`]'s; `None`: this install), or joins the one
    /// open (its label, origin and author kept).
    pub(crate) fn begin_as(&mut self, label: &str, origin: Origin, by: Option<PublicKey>) {
        match &mut self.pending {
            Some(pending) => pending.depth += 1,
            None => {
                self.pending = Some(Pending {
                    label: label.to_owned(),
                    origin,
                    by: by.filter(|key| self.agents.contains_key(key)),
                    depth: 1,
                    ops: Vec::new(),
                    index: BTreeMap::new(),
                    created: 0,
                    private: None,
                    planned: None,
                });
            }
        }
    }

    /// Opens a group labelled `label` writing undo or redo `origin`,
    /// planned when `freezes` freezes were marked ([`Plan::freezes`]): if
    /// one is marked before it is committed, the commit is refused and the
    /// step is to be planned again ([`Self::freezes`]), so that no value a
    /// freeze withdrew is written back.
    pub(crate) fn begin_planned(&mut self, label: &str, origin: Origin, freezes: u64) {
        let outer = self.pending.is_none();
        self.begin(label, origin);
        if outer && let Some(pending) = &mut self.pending {
            pending.planned = Some(freezes);
        }
    }

    /// The freezes marked so far, counted: an undo or redo planned under
    /// fewer ([`Plan::freezes`]) is refused at its commit, to be planned
    /// again.
    pub(crate) fn freezes(&self) -> u64 {
        self.freezes
    }

    /// Writes `value` to `key` in the group open (none open: nothing),
    /// in place of what the group wrote to it before (a conversation
    /// key's ops are each kept); `edits` show it. The key's frozen ops
    /// are taken out first ([`Self::settle_key`]): it names none.
    pub(crate) fn write(&mut self, key: &Key, value: Value, edits: &mut Edits) {
        if self.pending.is_none() {
            return;
        }
        self.settle_key(key);
        let prev = self
            .registers
            .get(key)
            .map(|register| register.leaves().map(|(id, _)| *id).collect())
            .unwrap_or_default();
        let Some(pending) = &mut self.pending else {
            return;
        };
        if key.talk().is_some() {
            pending.ops.push(Some(Op {
                key: key.clone(),
                value,
                prev,
            }));
            return;
        }
        if let Some(at) = pending.index.remove(key)
            && let Some(slot) = pending.ops.get_mut(at)
        {
            *slot = None;
        }
        pending.index.insert(key.clone(), pending.ops.len());
        pending.ops.push(Some(Op {
            key: key.clone(),
            value,
            prev,
        }));
        self.show(key, edits);
    }

    /// Commits the group open: the outermost seals its change (none if it
    /// wrote nothing): its chain's start first if this begins the chain,
    /// and more than one change, one undo step, if its edits pass one
    /// change's bounds ([`MAX_BODY`], [`MAX_OPS`]). In a shared journal
    /// with collaboration attached and nothing of its chain pending, the
    /// [`Authority`] judges it first: one not taken is not written.
    /// One taken is written to the log and flushed before it is taken
    /// here, then marked.
    ///
    /// # Errors
    ///
    /// The change cannot be made (an edit larger than a change, more than
    /// [`MAX_PARTS`] changes' worth), the share does not take it, or it is
    /// taken and cannot be written; an undo or redo was planned before a
    /// freeze marked since ([`Self::begin_planned`]). The group is dropped
    /// then, `edits` shown as before it.
    pub(crate) fn commit(&mut self, edits: &mut Edits) -> Result<Committed, String> {
        let Some(pending) = &mut self.pending else {
            return Ok(Committed::Empty);
        };
        if pending.depth > 1 {
            pending.depth -= 1;
            return Ok(Committed::Open);
        }
        let Some(pending) = self.pending.take() else {
            return Ok(Committed::Empty);
        };
        if pending.planned.is_some_and(|at| at != self.freezes) {
            // Planned before a freeze marked since: a value it restores
            // may be one the freeze withdrew. Dropped, to be planned again.
            let keys: Vec<Key> = pending
                .ops
                .iter()
                .flatten()
                .map(|op| op.key.clone())
                .collect();
            self.reproject(&keys, edits);
            return Err("a freeze came after the step was planned: it is planned again".to_owned());
        }
        let undoing = matches!(pending.origin, Origin::Undo(_) | Origin::Redo(_));
        let private = pending.private;
        let ops: Vec<Op> = pending.ops.into_iter().flatten().collect();
        if ops.is_empty() && !undoing {
            return Ok(Committed::Empty);
        }
        let ops = self.unfrozen(ops);
        let keys: Vec<Key> = ops.iter().map(|op| op.key.clone()).collect();
        let talk = ops.iter().all(|op| op.key.talk().is_some());
        let sealed = self.seal(&pending.label, &pending.origin, pending.by, ops);
        let judged = sealed.and_then(|records| Ok((self.judge_own(&records)?, records)));
        let (admitted, records) = match judged {
            Ok(judged) => judged,
            Err(error) => {
                self.reproject(&keys, edits);
                return Err(error);
            }
        };
        if admitted && let Err(error) = self.write_ahead(&records) {
            // Not written: not made, nothing of it shown or told.
            self.reproject(&keys, edits);
            return Err(error);
        }
        for record in &records {
            self.take(record);
            if !admitted {
                self.unsaved.push(record.id);
            }
        }
        if let Some(first) = records.iter().find(|record| !record.is_start()) {
            self.stack(first.id, &first.body.origin, talk, private);
        }
        if admitted {
            self.admit_taken(&records);
            // Marked now, so that it can be told. Marks that cannot be
            // written lag the change, durable already: written again at
            // the next save (which tells the failure), the change told
            // nothing meanwhile.
            let _ = self.keep_marks();
        }
        // A concurrent change taken meanwhile may show instead (a
        // bookmark's name over a removal).
        self.reproject(&keys, edits);
        Ok(Committed::Sealed(records))
    }

    /// Drops the group open, `edits` shown as before it; the keys it had
    /// written.
    pub(crate) fn rollback(&mut self, edits: &mut Edits) -> Vec<Key> {
        let Some(pending) = self.pending.take() else {
            return Vec::new();
        };
        let keys: Vec<Key> = pending.ops.into_iter().flatten().map(|op| op.key).collect();
        self.reproject(&keys, edits);
        keys
    }

    /// Shows `keys` in `edits` as the journal has them now.
    fn reproject(&self, keys: &[Key], edits: &mut Edits) {
        for key in keys {
            self.show(key, edits);
        }
    }

    /// Takes the group open out of the way (a draft's begins beside it).
    pub(crate) fn stash(&mut self) -> Option<Pending> {
        self.pending.take()
    }

    /// The keys and values the group open wrote, in order.
    pub(crate) fn drafted(&self) -> Vec<(Key, Value)> {
        self.pending
            .iter()
            .flat_map(|pending| pending.ops.iter().flatten())
            .map(|op| (op.key.clone(), op.value.clone()))
            .collect()
    }

    /// Drops the group open (a draft) for `stashed`, `edits` shown as
    /// they were before the draft; the keys the draft wrote.
    pub(crate) fn unstash(&mut self, stashed: Option<Pending>, edits: &mut Edits) -> Vec<Key> {
        let draft = std::mem::replace(&mut self.pending, stashed);
        let keys: Vec<Key> = draft
            .into_iter()
            .flat_map(|pending| pending.ops.into_iter().flatten())
            .map(|op| op.key)
            .collect();
        self.reproject(&keys, edits);
        keys
    }

    /// The changes of the group `label`, `origin` and `ops`, numbered next
    /// in its author's chain (agent `by`'s, else this install's), stamped,
    /// signed: the chain's start first if it is not begun, then the group
    /// as one change, or split in up to [`MAX_PARTS`] if it passes one
    /// change's bounds.
    fn seal(
        &mut self,
        label: &str,
        origin: &Origin,
        by: Option<PublicKey>,
        ops: Vec<Op>,
    ) -> Result<Vec<Arc<Record>>, String> {
        let (chain, author) = match by.and_then(|key| Some((key, self.agents.get(&key)?))) {
            Some((key, agent)) => (agent.chain, key),
            None => (self.chain, self.author()),
        };
        if let Some(op) = ops.iter().find(|op| !owns(&op.key, author)) {
            return Err(format!(
                "{:?} is another's bookmark: each author's bookmarks are their own",
                op.key
            ));
        }
        let undoes = match *origin {
            Origin::Undo(id) | Origin::Redo(id) => Some(id),
            Origin::User
            | Origin::Script(_)
            | Origin::Plugin(_)
            | Origin::Agent
            | Origin::Import(_)
            | Origin::Accept(_)
            | Origin::Signature(_) => None,
        };
        let parts = self.split(label, origin, undoes, ops)?;
        self.clock = self.clock.send(now());
        let mut records = Vec::new();
        let (mut seq, mut prev) = if let Some(known) = self.chains.get(&chain) {
            (known.seq + 1, known.hash)
        } else {
            let made = *self
                .origins
                .get(&chain)
                .ok_or_else(|| format!("what makes chain {chain} is not kept"))?;
            let body = Body {
                bound: Some(self.binding(author)?),
                hlc: self.clock,
                membership: 0,
                engine: self.engine.clone(),
                origin: origin.clone(),
                label: String::new(),
                undoes: None,
                group: None,
                ops: Vec::new(),
                blind: random()?,
            };
            let start = self.signed(author, chain, 1, ChangeHash::ZERO, Some(made), body)?;
            self.mine.insert(chain);
            self.mine_unsaved = true;
            let next = (2, start.hash);
            records.push(start);
            next
        };
        let group = match u16::try_from(parts.len()) {
            Ok(1) => None,
            Ok(count) => Some(Group { first: seq, count }),
            Err(_) => return Err("a group of too many changes".to_owned()),
        };
        for ops in parts {
            let body = Body {
                bound: None,
                hlc: self.clock,
                membership: 0,
                engine: self.engine.clone(),
                origin: origin.clone(),
                label: label.to_owned(),
                undoes,
                group,
                ops,
                blind: random()?,
            };
            let record = self.signed(author, chain, seq, prev, None, body)?;
            prev = record.hash;
            seq += 1;
            records.push(record);
        }
        Ok(records)
    }

    /// `ops` as the parts of one group: each part within [`MAX_BODY`] and
    /// [`MAX_OPS`], in op order but conversation first (so the threads,
    /// posts and suggestions it makes are named for its first part, as
    /// [`Self::next_talk`] named them), at most [`MAX_PARTS`].
    ///
    /// # Errors
    ///
    /// One op passes a change's bounds alone, or the parts would be more
    /// than [`MAX_PARTS`].
    fn split(
        &self,
        label: &str,
        origin: &Origin,
        undoes: Option<ChangeId>,
        ops: Vec<Op>,
    ) -> Result<Vec<Vec<Op>>, String> {
        let empty = Body {
            bound: None,
            hlc: Hlc(u64::MAX),
            membership: u64::MAX,
            engine: self.engine.clone(),
            origin: origin.clone(),
            label: label.to_owned(),
            undoes,
            group: Some(Group {
                first: u64::MAX,
                count: MAX_PARTS,
            }),
            ops: Vec::new(),
            blind: [0; 16],
        };
        // The body without ops, and room for the ops' count.
        let base = binbun_bounded::size(&empty, MAX_BODY).map_err(|error| error.to_string())? + 3;
        let (talk, edits): (Vec<Op>, Vec<Op>) =
            ops.into_iter().partition(|op| op.key.talk().is_some());
        let mut parts: Vec<Vec<Op>> = vec![Vec::new()];
        let mut size = base;
        for op in talk.into_iter().chain(edits) {
            let bytes = binbun_bounded::size(&op, MAX_BODY - base)
                .map_err(|_| format!("{:?}: an edit larger than a change", op.key))?;
            let full = parts.last().is_some_and(|part| part.len() >= MAX_OPS);
            if full || size + bytes > MAX_BODY {
                if parts.len() >= usize::from(MAX_PARTS) {
                    return Err(format!(
                        "more edits in one group than {MAX_PARTS} changes hold"
                    ));
                }
                parts.push(Vec::new());
                size = base;
            }
            size += bytes;
            if let Some(part) = parts.last_mut() {
                part.push(op);
            }
        }
        Ok(parts)
    }

    /// The change of `author` at `seq` of `chain` after `prev` with `body`
    /// (`made`: what makes the chain, at 1), signed.
    ///
    /// # Errors
    ///
    /// Its body is more than [`MAX_BODY`] bytes.
    fn signed(
        &self,
        author: PublicKey,
        chain: ChainId,
        seq: u64,
        prev: ChangeHash,
        made: Option<ChainOrigin>,
        body: Body,
    ) -> Result<Arc<Record>, String> {
        let bytes = body.encode()?;
        let head = Head {
            chain,
            seq,
            prev,
            body: Body::commitment(&bytes),
            origin: made,
        };
        let key = match self.agents.get(&author) {
            Some(agent) => agent.identity.signer(),
            None => &self.signer,
        };
        let signed = SignedChange {
            head: SignedHead::sign(head, key),
            body: bytes,
        };
        Ok(Arc::new(Record {
            id: head.id(),
            body,
            hash: head.hash(),
            signed,
            author,
        }))
    }

    /// Takes `record` (checked): its ops into their keys, its chain's head
    /// moved (a start: the chain known).
    fn take(&mut self, record: &Arc<Record>) {
        let id = record.id;
        for (index, op) in record.body.ops.iter().enumerate() {
            let Ok(index) = u16::try_from(index) else {
                break;
            };
            let op_id = OpId { change: id, index };
            let stamp = Stamp {
                hlc: record.body.hlc,
                chain: id.chain,
                seq: id.seq,
                index,
            };
            if op.key.talk().is_some() {
                self.heard.push((op.key.clone(), op_id));
            }
            self.registers.entry(op.key.clone()).or_default().insert(
                op_id,
                Entry {
                    stamp,
                    value: op.value.clone(),
                    prev: op.prev.clone(),
                },
            );
        }
        match (record.signed.head.head.origin, &record.body.bound) {
            (Some(origin), Some(bound)) if id.seq == 1 => {
                self.origins.remove(&id.chain);
                self.chains.insert(
                    id.chain,
                    Chain {
                        author: record.author,
                        origin,
                        start: record.signed.clone(),
                        bound: bound.clone(),
                        seq: 1,
                        hash: record.hash,
                    },
                );
            }
            _ => {
                if let Some(known) = self.chains.get_mut(&id.chain) {
                    known.seq = id.seq;
                    known.hash = record.hash;
                }
            }
        }
        self.records.insert(id, Arc::clone(record));
    }

    /// Moves this author's undo and redo for its change `id` (a group's
    /// first part) made by `origin` (`talk`: of conversation alone) with
    /// the private bookmark's edit `private`: an undo's target goes to
    /// redo, a redo's change back to undo (each with the private edit of
    /// its step), any other edit is undoable and ends redo (an import, or
    /// conversation alone, is neither).
    fn stack(&mut self, id: ChangeId, origin: &Origin, talk: bool, private: Option<PrivateEdit>) {
        self.steps_changed();
        match origin {
            Origin::Undo(target) => {
                let at = self
                    .undo
                    .iter()
                    .position(|step| step.change == Some(*target));
                let step = at.map_or_else(|| Step::change(*target), |at| self.undo.remove(at));
                self.redo.push((step, Some(id)));
            }
            Origin::Redo(target) => {
                let at = self
                    .redo
                    .iter()
                    .rposition(|(step, _)| step.change == Some(*target));
                let private = at.and_then(|at| self.redo.remove(at).0.private);
                self.undo.push(Step {
                    change: Some(id),
                    private,
                });
            }
            Origin::Import(_) => {}
            Origin::User
            | Origin::Script(_)
            | Origin::Plugin(_)
            | Origin::Agent
            | Origin::Accept(_)
            | Origin::Signature(_) => {
                if !talk {
                    self.undo.push(Step {
                        change: Some(id),
                        private,
                    });
                    self.redo.clear();
                }
            }
        }
    }

    /// Whether there is a change of this author's to undo.
    pub(crate) fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    /// The label of change `id`, if taken.
    pub(crate) fn label(&self, id: ChangeId) -> Option<String> {
        Some(self.records.get(&id)?.body.label.clone())
    }

    /// The parts taken of the step change `id` begins: of its group, if it
    /// is a group's first part (as many as there are), else it alone.
    fn parts(&self, id: ChangeId) -> Vec<&Arc<Record>> {
        let Some(first) = self.records.get(&id) else {
            return Vec::new();
        };
        let Some(group) = first.body.group.filter(|group| group.first == id.seq) else {
            return vec![first];
        };
        (id.seq..id.seq.saturating_add(u64::from(group.count)))
            .map_while(|seq| {
                self.records
                    .get(&ChangeId {
                        chain: id.chain,
                        seq,
                    })
                    .filter(|part| part.body.group == Some(group))
            })
            .collect()
    }

    /// Whether `record` begins a history entry: an edit not a start, and
    /// not a later part of a group.
    fn begins(record: &Record) -> bool {
        !record.is_start()
            && record
                .body
                .group
                .is_none_or(|group| group.first == record.id.seq)
    }

    /// The change the next undo undoes (none for a private bookmark's
    /// edit alone, or nothing to undo).
    pub(crate) fn next_undo(&self) -> Option<HistoryEntry> {
        let id = self.undo.last()?.change?;
        Some(self.entry(self.records.get(&id)?))
    }

    /// Whether there is an undone change to make again.
    pub(crate) fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    /// Undoing this author's last change not undone: the values before it
    /// on the keys still as it left them (and its private bookmark's edit
    /// undone). None if the last step is a private bookmark's edit alone
    /// ([`Self::undo_private`]). Its keys' frozen ops are taken out first
    /// ([`Self::settle_step_keys`]): no frozen value is restored.
    pub(crate) fn plan_undo(&mut self) -> Option<Plan> {
        let step = self.undo.last()?;
        let target = step.change?;
        self.settle_step_keys(target);
        let step = self.undo.last()?;
        let label = format!("Undo: {}", self.records.get(&target)?.body.label);
        let mut plan = self.inverse(&self.parts(target), Origin::Undo(target), label);
        plan.private = step.private.as_ref().map(PrivateEdit::inverse);
        Some(plan)
    }

    /// Making the last undone change again: undoing its undo (and its
    /// private bookmark's edit made again). None if the last undone is a
    /// private bookmark's edit alone ([`Self::redo_private`]). Its keys'
    /// frozen ops are taken out first ([`Self::settle_step_keys`]).
    pub(crate) fn plan_redo(&mut self) -> Option<Plan> {
        let (step, undo) = self.redo.last()?;
        let (target, undo) = (step.change?, (*undo)?);
        self.settle_step_keys(undo);
        let (step, _) = self.redo.last()?;
        let label = self.records.get(&target)?.body.label.clone();
        self.records.get(&undo)?;
        let mut plan = self.inverse(&self.parts(undo), Origin::Redo(target), label);
        plan.private.clone_from(&step.private);
        Some(plan)
    }

    /// The ops undoing those of `parts` (one step: a change, or a group's
    /// parts), last first, by compare-and-set: each key's value before it
    /// where the key is still as it left it. Of conversation, only a
    /// suggestion's state is undone (accepted: pending again); another's
    /// bookmark (an agent's) is skipped.
    fn inverse(&self, parts: &[&Arc<Record>], origin: Origin, label: String) -> Plan {
        let first = parts.first().map_or(
            ChangeId {
                chain: self.chain,
                seq: 0,
            },
            |part| part.id,
        );
        let mut plan = Plan {
            target: match origin {
                Origin::Undo(id) | Origin::Redo(id) => id,
                Origin::User
                | Origin::Script(_)
                | Origin::Plugin(_)
                | Origin::Agent
                | Origin::Import(_)
                | Origin::Accept(_)
                | Origin::Signature(_) => first,
            },
            origin,
            label,
            ops: Vec::new(),
            skipped: Vec::new(),
            private: None,
            freezes: self.freezes,
        };
        let ops = parts.iter().rev().flat_map(|part| {
            part.body
                .ops
                .iter()
                .enumerate()
                .rev()
                .map(move |(index, op)| (part.id, index, op))
        });
        for (change, index, op) in ops {
            let Ok(index) = u16::try_from(index) else {
                continue;
            };
            if op.key.talk().is_some()
                && !matches!(op.value, Value::Suggestion(SuggestionOp::State(_)))
            {
                continue;
            }
            let id = OpId { change, index };
            let Some(register) = self.registers.get(&op.key) else {
                continue;
            };
            if owns(&op.key, self.author()) && self.unchanged(register, id, &op.value) {
                plan.ops
                    .push((op.key.clone(), Self::before(register, &op.key, &op.prev)));
            } else {
                plan.skipped.push(Skipped {
                    key: op.key.clone(),
                    by: register
                        .leaves()
                        .filter_map(|(leaf, _)| Some(self.chains.get(&leaf.change.chain)?.author))
                        .collect(),
                    value: register
                        .winner(adds(&op.key))
                        .map(|(_, entry)| entry.value.clone()),
                });
            }
        }
        plan
    }

    /// Whether `register` is as op `id` (of `value`) left it: it is the one
    /// leaf, or the one leaf is this author's own with the same value (an
    /// undo of a later change brought it back).
    fn unchanged(&self, register: &Register, id: OpId, value: &Value) -> bool {
        let mut leaves = register.leaves();
        match (leaves.next(), leaves.next()) {
            (Some((&leaf, entry)), None) => {
                leaf == id || (self.local(leaf.change.chain) && entry.value == *value)
            }
            (Some(_), Some(_)) | (None, _) => false,
        }
    }

    /// The value `key` showed among `prev` (none: its tombstone).
    fn before(register: &Register, key: &Key, prev: &[OpId]) -> Value {
        match register.winner_of(prev.iter(), adds(key)) {
            // A suggestion's state before its making: pending.
            Some((_, entry)) if entry.value.creates() => Value::none(key),
            Some((_, entry)) => entry.value.clone(),
            None => Value::none(key),
        }
    }

    /// The changes, newest first: one entry per group.
    pub(crate) fn history(&self) -> Vec<HistoryEntry> {
        let mut records: Vec<&Arc<Record>> = self
            .records
            .values()
            .filter(|record| Self::begins(record))
            .collect();
        records.sort_by_key(|record| std::cmp::Reverse((record.body.hlc, record.id)));
        records
            .into_iter()
            .map(|record| self.entry(record))
            .collect()
    }

    /// The edits change `id` made (with the rest of its group, if it begins
    /// one): each key, the value it gave, and the value the key showed
    /// among those its author saw (a tombstone: none of the user's, the
    /// engine's own).
    pub(crate) fn edits_of(&self, id: ChangeId) -> Vec<(Key, Value, Value)> {
        self.parts(id)
            .into_iter()
            .flat_map(|part| part.body.ops.iter())
            .map(|op| {
                let before = self.registers.get(&op.key).map_or_else(
                    || Value::none(&op.key),
                    |register| Self::before(register, &op.key, &op.prev),
                );
                (op.key.clone(), op.value.clone(), before)
            })
            .collect()
    }

    /// The history entry of the step `records` made (by a commit: a start
    /// first, if one, then the step's parts).
    pub(crate) fn step_entry(&self, records: &[Arc<Record>]) -> Option<HistoryEntry> {
        records
            .iter()
            .find(|record| Self::begins(record))
            .map(|record| self.entry(record))
    }

    /// `record` as a history entry (a group's first part: the group).
    pub(crate) fn entry(&self, record: &Record) -> HistoryEntry {
        HistoryEntry {
            id: record.id,
            author: record.author,
            origin: record.body.origin.clone(),
            label: record.body.label.clone(),
            time: record.body.hlc,
            edits: self
                .parts(record.id)
                .iter()
                .map(|part| part.body.ops.len())
                .sum(),
            mine: record.author == self.author(),
            suggested_by: self.suggested_by(&record.body.origin),
        }
    }

    /// The keys with more than one leaf, by key (conversation never: its
    /// keys are append-only).
    pub(crate) fn conflicts(&self) -> Vec<Conflict> {
        self.registers
            .iter()
            .filter(|(key, register)| register.width() > 1 && key.talk().is_none())
            .filter_map(|(key, register)| self.conflict(key, register))
            .collect()
    }

    /// `key`'s conflict, if it has more than one leaf.
    fn conflict(&self, key: &Key, register: &Register) -> Option<Conflict> {
        if register.width() < 2 || key.talk().is_some() {
            return None;
        }
        let mut leaves: Vec<LeafInfo> = register
            .leaves()
            .filter_map(|(&op, entry)| {
                Some(LeafInfo {
                    op,
                    author: self.chains.get(&op.change.chain)?.author,
                    stamp: entry.stamp,
                    value: entry.value.clone(),
                })
            })
            .collect();
        leaves.sort_by_key(|leaf| leaf.stamp);
        let (&shown, _) = register.winner(adds(key))?;
        Some(Conflict {
            key: key.clone(),
            leaves,
            shown,
        })
    }

    /// The value `key` shows: the group's open, else its winning leaf's.
    fn shown(&self, key: &Key) -> Option<&Value> {
        if let Some(value) = self.pending.as_ref().and_then(|pending| pending.value(key)) {
            return Some(value);
        }
        self.registers
            .get(key)?
            .winner(adds(key))
            .map(|(_, entry)| &entry.value)
    }

    /// Who wrote the value `key` shows: the group's open's origin, else
    /// the winning leaf's change's; `None` if nothing wrote it.
    pub(crate) fn origin(&self, key: &Key) -> Option<&Origin> {
        if let Some(pending) = &self.pending
            && pending.value(key).is_some()
        {
            return Some(&pending.origin);
        }
        let (id, _) = self.registers.get(key)?.winner(adds(key))?;
        Some(&self.records.get(&id.change)?.body.origin)
    }

    /// Whose key wrote the value `key` shows: the group open's author,
    /// else the winning leaf's change's; `None` if nothing wrote it.
    pub(crate) fn writer(&self, key: &Key) -> Option<PublicKey> {
        if let Some(pending) = &self.pending
            && pending.value(key).is_some()
        {
            return Some(pending.by.unwrap_or_else(|| self.author()));
        }
        let (id, _) = self.registers.get(key)?.winner(adds(key))?;
        Some(self.records.get(&id.change)?.author)
    }

    /// Shows `key` in `edits` as the journal has it.
    fn show(&self, key: &Key, edits: &mut Edits) {
        let text = || self.shown(key).and_then(Value::text);
        match key {
            Key::FunctionName(entry) => edits.set_function(*entry, text()),
            Key::GlobalName(address) => edits.set_global(*address, text()),
            Key::VariableName(variable) => edits.set_variable(variable.clone(), text()),
            Key::Slot(function, offset) => edits.set_slot(*function, *offset, text()),
            Key::Comment(address) => edits.set_comment(*address, text()),
            Key::Bookmark(author, address) => {
                if *author == self.author() {
                    edits.set_bookmark(*address, text());
                }
            }
            Key::Number(address, canon) => match self.shown(key) {
                Some(Value::Number(Some(stated))) => {
                    edits.set_number(*address, stated.value, Some(stated.form.clone()));
                }
                _ => edits.set_number(*address, *canon, None),
            },
            Key::Type(typed) => edits.set_type(typed.clone(), text()),
            Key::Definition(name) => edits.set_definition(name.clone(), text()),
            Key::Item(_) | Key::Bounds(_) => edits.set_corrections(self.corrections()),
            Key::Signature(entry) => {
                let identified = match self.shown(key) {
                    Some(Value::Signature(identified)) => identified.as_deref().cloned(),
                    _ => None,
                };
                edits.set_signature(*entry, identified);
            }
            Key::DebugFile | Key::Thread(_) | Key::Post(_) | Key::Suggestion(_) => {}
        }
    }

    /// The corrections the keys hold: each item's winner in stamp order
    /// (a later one replacing those it overlaps), the group's open last;
    /// each function's bounds.
    fn corrections(&self) -> Corrections {
        let pending = self.pending.as_ref();
        let written = |key: &Key| pending.and_then(|pending| pending.value(key));
        let mut items: Vec<(Stamp, u64, Option<Item>)> = Vec::new();
        let mut corrections = Corrections::default();
        for (key, register) in self.registers.range(Key::Item(0)..=Key::Bounds(u64::MAX)) {
            if written(key).is_some() {
                continue;
            }
            let Some((_, entry)) = register.winner(false) else {
                continue;
            };
            match (key, &entry.value) {
                (Key::Item(address), Value::Item(item)) => {
                    items.push((entry.stamp, *address, *item));
                }
                (Key::Bounds(entry_address), Value::Bounds(bounds)) => {
                    corrections.set_bounds(*entry_address, *bounds);
                }
                _ => {}
            }
        }
        items.sort_by_key(|&(stamp, ..)| stamp);
        for (_, address, item) in items {
            corrections.set_item(address, item);
        }
        for op in pending
            .into_iter()
            .flat_map(|pending| pending.ops.iter().flatten())
        {
            match (&op.key, &op.value) {
                (Key::Item(address), Value::Item(item)) => {
                    if item.is_some() || corrections.item(*address).is_some() {
                        corrections.set_item(*address, *item);
                    }
                }
                (Key::Bounds(entry), Value::Bounds(bounds)) => {
                    corrections.set_bounds(*entry, *bounds);
                }
                _ => {}
            }
        }
        corrections
    }

    /// The edits the journal shows: every key's value.
    pub(crate) fn projection(&self) -> Edits {
        let mut edits = Edits::default();
        let pending = self.pending.iter().flat_map(|pending| pending.index.keys());
        let keys: BTreeSet<&Key> = self.registers.keys().chain(pending).collect();
        for key in keys {
            if !matches!(key, Key::Item(_) | Key::Bounds(_)) {
                self.show(key, &mut edits);
            }
        }
        edits.set_corrections(self.corrections());
        edits
    }

    /// The key an edit `edit` (as [`Edits`] lists it) is the value of.
    pub(crate) fn key_of(&self, edit: &Edit) -> Key {
        match edit {
            Edit::Function { entry, .. } => Key::FunctionName(*entry),
            Edit::Global { address, .. } => Key::GlobalName(*address),
            Edit::Variable { variable, .. } => Key::VariableName(variable.clone()),
            Edit::Comment { address, .. } => Key::Comment(*address),
            Edit::Bookmark { address, .. } => Key::Bookmark(self.author(), *address),
            Edit::Slot {
                function, offset, ..
            } => Key::Slot(*function, *offset),
            Edit::Number { address, value, .. } => Key::Number(*address, canonical(*value)),
            Edit::Type { typed, .. } => Key::Type(typed.clone()),
            Edit::Definition { key, .. } => Key::Definition(key.clone()),
            Edit::Item { address, .. } => Key::Item(*address),
            Edit::Bounds { entry, .. } => Key::Bounds(*entry),
        }
    }

    /// Appends the changes made and not saved yet to the log (made first
    /// if this is its first), flushed to the disk; nothing in an
    /// ephemeral session. Those it could not write stay to be saved. Then,
    /// in a shared journal, the marks of what was admitted since, so that
    /// it can be told.
    ///
    /// # Errors
    ///
    /// The log cannot be written.
    pub(crate) fn flush(&mut self) -> Result<(), String> {
        let ids = std::mem::take(&mut self.unsaved);
        let mine = self.mine_unsaved.then_some(&self.mine);
        let appended = Self::append(
            self.store.as_mut(),
            self.project,
            &self.of,
            mine,
            &self.records,
            &ids,
        );
        if appended.is_err() {
            self.unsaved = ids;
            return appended;
        }
        self.mine_unsaved &= ids.is_empty();
        self.keep_marks()
    }

    /// Writes this author's own changes `records` (sealed and judged, not
    /// taken yet) to the log after what is not saved yet, flushed to the
    /// disk: a change is durable before it is taken and marked (sync
    /// §4.5 rule 1).
    ///
    /// # Errors
    ///
    /// The log cannot be written.
    fn write_ahead(&mut self, records: &[Arc<Record>]) -> Result<(), String> {
        self.flush()?;
        let ids: Vec<ChangeId> = records.iter().map(|record| record.id).collect();
        let written: BTreeMap<ChangeId, Arc<Record>> = records
            .iter()
            .map(|record| (record.id, Arc::clone(record)))
            .collect();
        let mine = self.mine_unsaved.then_some(&self.mine);
        Self::append(
            self.store.as_mut(),
            self.project,
            &self.of,
            mine,
            &written,
            &ids,
        )?;
        self.mine_unsaved = false;
        Ok(())
    }

    /// Keeps the marks of what was admitted since they were last kept (a
    /// shared journal's; written changes only: [`Self::flush`]).
    ///
    /// # Errors
    ///
    /// The marks cannot be written: they stay as they were.
    fn keep_marks(&mut self) -> Result<(), String> {
        let Some(share) = &mut self.share else {
            return Ok(());
        };
        if share.admitted == share.marks || !self.unsaved.is_empty() {
            return Ok(());
        }
        if let Some(store) = &self.store {
            store.set_admitted(&store::Admitted {
                genesis: share.genesis,
                of: self.of.clone(),
                before: share.before.clone(),
                marks: share.admitted.clone(),
            })?;
        }
        share.marks.clone_from(&share.admitted);
        Ok(())
    }

    /// Appends changes `ids` of `records` to `store` (none: nothing), the
    /// log of id `project`, of chains of `of`, made first if this is its
    /// first, the chains written here (`mine`, if they changed) kept
    /// first.
    fn append(
        store: Option<&mut Store>,
        project: ProjectId,
        of: &Of,
        mine: Option<&BTreeSet<ChainId>>,
        records: &BTreeMap<ChangeId, Arc<Record>>,
        ids: &[ChangeId],
    ) -> Result<(), String> {
        let Some(store) = store else {
            return Ok(());
        };
        if ids.is_empty() {
            return Ok(());
        }
        if store.project()?.is_none() {
            store.create(project, of)?;
        }
        if let Some(mine) = mine {
            store.set_local(mine)?;
        }
        let mut chains: BTreeMap<ChainId, Vec<&SignedChange>> = BTreeMap::new();
        for id in ids {
            if let Some(record) = records.get(id) {
                chains.entry(id.chain).or_default().push(&record.signed);
            }
        }
        for (chain, signed) in chains {
            store.append(chain, &signed)?;
        }
        Ok(())
    }

    /// Writes this author's changes on a new chain from now on, the one
    /// before left as it is.
    ///
    /// # Errors
    ///
    /// A group is open; no randomness.
    pub(crate) fn new_chain(&mut self) -> Result<(), String> {
        if self.pending.is_some() {
            return Err("a group is open: commit or roll it back first".to_owned());
        }
        self.chain = self.fresh_chain(self.author())?;
        Ok(())
    }

    /// The chain this author's next change goes on.
    pub(crate) fn chain(&self) -> ChainId {
        self.chain
    }

    /// Takes `incoming` from outside the log ([`Self::apply`]), `edits`
    /// showing them: in a shared journal written and marked at once, so
    /// that they can be told; else kept in the log at the next save. What
    /// it came to, the keys it touched.
    pub(crate) fn receive(
        &mut self,
        incoming: Vec<SignedChange>,
        edits: &mut Edits,
    ) -> (Applied, Vec<Key>) {
        let mut touched = BTreeSet::new();
        let applied = self.apply(incoming, &mut touched, remote::Source::Remote);
        self.settle(applied, touched, edits)
    }

    /// What `applied` (touching `touched`) leaves: the changes taken (kept
    /// to be saved by [`Self::apply`]) in a shared journal written and
    /// marked now, `edits` showing the keys; the conflicts on them; the
    /// keys. If they cannot be written and marked, the changes taken from
    /// outside since the last write are taken back ([`Self::take_back`]):
    /// nothing of them is shown, told, depended on or admitted, and the
    /// failure is in [`Applied::failed`].
    pub(crate) fn settle(
        &mut self,
        mut applied: Applied,
        mut touched: BTreeSet<Key>,
        edits: &mut Edits,
    ) -> (Applied, Vec<Key>) {
        if self.share.is_some() {
            // Every change taken from outside since the last write: on
            // chains this install does not write.
            let staged: Vec<ChangeId> = self
                .unsaved
                .iter()
                .filter(|id| !self.mine.contains(&id.chain))
                .copied()
                .collect();
            if let Err(error) = self.flush() {
                touched.extend(self.take_back(&staged, &mut applied));
                applied.failed.push(error);
            }
        }
        let keys: Vec<Key> = touched.into_iter().collect();
        self.reproject(&keys, edits);
        applied.conflicts = keys
            .iter()
            .filter_map(|key| self.conflict(key, self.registers.get(key)?))
            .collect();
        applied.reanalyse = keys
            .iter()
            .any(|key| matches!(key, Key::Item(_) | Key::Bounds(_) | Key::DebugFile));
        (applied, keys)
    }

    /// Freezes chains `freezes` (each from a change, for a cause): written
    /// to the log first, then in effect ([`Self::freeze_durably`]), `edits`
    /// showing the keys as they are without the changes frozen. What it
    /// came to, the keys it touched.
    ///
    /// # Errors
    ///
    /// The freezes cannot be written: none takes effect.
    pub(crate) fn freeze_and_keep(
        &mut self,
        freezes: &[(ChainId, u64, FrozenBy)],
        edits: &mut Edits,
    ) -> Result<(Applied, Vec<Key>), String> {
        let applied = self.freeze_durably(freezes)?;
        Ok(self.settle(applied, BTreeSet::new(), edits))
    }

    /// One turn of what freezes and releases left ([`Self::step`]),
    /// settled as taking changes is ([`Self::settle`]) and kept for
    /// collaboration ([`Self::take_settled`]). What it came to, the keys
    /// it touched.
    pub(crate) fn settle_step(&mut self, edits: &mut Edits) -> (Applied, Vec<Key>) {
        let mut touched = BTreeSet::new();
        let applied = self.step(&mut touched);
        let settled = self.settle(applied, touched, edits);
        self.keep_settled(&settled.0);
        settled
    }

    /// The chains known: each one's author and last change taken.
    pub(crate) fn chains(&self) -> Vec<(ChainId, PublicKey, u64)> {
        self.chains
            .iter()
            .map(|(&id, chain)| (id, chain.author, chain.seq))
            .collect()
    }

    /// The chains known that are of a share: each one's author and the
    /// grant its start names.
    pub(crate) fn grants(&self) -> Vec<(ChainId, PublicKey, u64)> {
        self.chains
            .iter()
            .filter_map(|(&id, chain)| Some((id, chain.author, chain.bound.share?.grant)))
            .collect()
    }

    /// The chains frozen, from which change (any cause).
    pub(crate) fn frozen(&self) -> BTreeMap<ChainId, u64> {
        self.frozen
            .iter()
            .map(|(&chain, (from, _))| (chain, *from))
            .collect()
    }

    /// Saves: the changes not saved yet appended to the log and the
    /// project file written as `edits` (the projection) say, each
    /// crash-safely and both at once, then the file recorded as the
    /// journal's own. A crash between them leaves the log ahead (the file
    /// is written again at the next opening) or the file ahead (taken as an
    /// import of what it holds more): nothing is lost. The private
    /// bookmarks' file first, if they changed.
    ///
    /// # Errors
    ///
    /// The log, the project file or the private bookmarks' file cannot be
    /// written.
    pub(crate) fn save(&mut self, edits: &Edits, project: &Project) -> Result<(), String> {
        let text = edits.to_toml()?;
        self.save_private()?;
        let ids = std::mem::take(&mut self.unsaved);
        let mine = self.mine_unsaved.then_some(&self.mine);
        let (store, id, of, records) = (self.store.as_mut(), self.project, &self.of, &self.records);
        let (logged, written) = std::thread::scope(|scope| {
            let log = scope.spawn(|| Self::append(store, id, of, mine, records, &ids));
            let written = write_safely(&project.edits(), &text);
            let logged = log
                .join()
                .unwrap_or_else(|_| Err("the log's writer stopped".to_owned()));
            (logged, written)
        });
        if logged.is_err() {
            self.unsaved = ids;
        } else {
            self.mine_unsaved &= ids.is_empty();
        }
        logged.and(written)?;
        self.keep_marks()?;
        self.mark(&text)
    }

    /// Records `text` as the project file the journal wrote, if it keeps a
    /// log.
    fn mark(&self, text: &str) -> Result<(), String> {
        match &self.store {
            Some(store) if store.project()?.is_some() => store.set_projected(text),
            Some(_) | None => Ok(()),
        }
    }

    /// Takes `from` (edits written outside the log: a project file, an
    /// exported project without a log) as changes [`Origin::Import`]
    /// labelled `label`, at most 65,535 to a change; `edits` show them. In
    /// place of the journal's (`concurrent` false: each key whose value
    /// differs takes `from`'s, cleared where `from` has none), or beside
    /// them (`concurrent`: each key `from` sets differently, as an edit
    /// made without seeing the journal's, a conflict where both have
    /// one). The changes made.
    ///
    /// # Errors
    ///
    /// A change cannot be sealed.
    pub(crate) fn import(
        &mut self,
        from: &Edits,
        label: &str,
        concurrent: bool,
        edits: &mut Edits,
    ) -> Result<Vec<Arc<Record>>, String> {
        let author = self.author();
        let wanted = keyed(from, author);
        let now = keyed(&self.projection(), author);
        let gone = now.keys().filter(|_| !concurrent);
        let keys: BTreeSet<&Key> = wanted.keys().chain(gone).collect();
        let ops: Vec<(Key, Value)> = keys
            .into_iter()
            .filter(|key| wanted.get(*key) != now.get(*key))
            .map(|key| {
                let value = wanted.get(key).cloned().unwrap_or_else(|| Value::none(key));
                (key.clone(), value)
            })
            .collect();
        let mut made = Vec::new();
        for chunk in ops.chunks(usize::from(u16::MAX) - 1) {
            self.begin(label, Origin::Import(label.to_owned()));
            for (key, value) in chunk {
                self.write(key, value.clone(), edits);
                if concurrent
                    && let Some(pending) = &mut self.pending
                    && let Some(op) = pending.ops.last_mut().and_then(Option::as_mut)
                {
                    op.prev.clear();
                }
            }
            if let Committed::Sealed(records) = self.commit(edits)? {
                made.extend(records);
            }
        }
        Ok(made)
    }

    /// Takes this author's chain as the one found in the log written to
    /// last (a new one if none is, or it may not go on:
    /// [`Self::writable`]), its undo and redo as its changes left them.
    fn adopt(&mut self) {
        let me = self.author();
        let mine = self
            .chains
            .iter()
            .filter(|(_, chain)| chain.author == me)
            .max_by_key(|&(&id, chain)| {
                let last = ChangeId {
                    chain: id,
                    seq: chain.seq,
                };
                let time = self.records.get(&last).map(|record| record.body.hlc);
                (time, chain.seq)
            })
            .map(|(&id, _)| id);
        let Some(chain) = mine else {
            return;
        };
        if !self.writable(chain) {
            return;
        }
        self.chain = chain;
        let steps: Vec<(ChangeId, Origin, bool)> = self
            .records
            .range(
                ChangeId { chain, seq: 0 }..=ChangeId {
                    chain,
                    seq: u64::MAX,
                },
            )
            .filter(|(_, record)| Self::begins(record))
            .map(|(&id, record)| {
                let talk = self
                    .parts(id)
                    .iter()
                    .flat_map(|part| part.body.ops.iter())
                    .all(|op| op.key.talk().is_some());
                (id, record.body.origin.clone(), talk)
            })
            .collect();
        for (id, origin, talk) in steps {
            self.stack(id, &origin, talk, None);
        }
    }
}

/// Every edit of `edits` as a key's value, `author`'s bookmarks.
fn keyed(edits: &Edits, author: PublicKey) -> BTreeMap<Key, Value> {
    let mut keyed = BTreeMap::new();
    for edit in edits.all() {
        let (key, value) = match edit {
            Edit::Function { entry, name } => (Key::FunctionName(entry), Value::Text(Some(name))),
            Edit::Global { address, name } => (Key::GlobalName(address), Value::Text(Some(name))),
            Edit::Variable { variable, name } => {
                (Key::VariableName(variable), Value::Text(Some(name)))
            }
            Edit::Comment { address, text } => (Key::Comment(address), Value::Text(Some(text))),
            Edit::Bookmark { address, name } => {
                (Key::Bookmark(author, address), Value::Text(Some(name)))
            }
            Edit::Slot {
                function,
                offset,
                name,
            } => (Key::Slot(function, offset), Value::Text(Some(name))),
            Edit::Number {
                address,
                value,
                form,
            } => (
                Key::Number(address, canonical(value)),
                Value::Number(Some(Stated { value, form })),
            ),
            Edit::Type { typed, c } => (Key::Type(typed), Value::Text(Some(c))),
            Edit::Definition { key, c } => (Key::Definition(key), Value::Text(Some(c))),
            Edit::Item { address, item } => (Key::Item(address), Value::Item(Some(item))),
            Edit::Bounds { entry, bounds } => (Key::Bounds(entry), Value::Bounds(Some(bounds))),
        };
        keyed.insert(key, value);
    }
    for (&entry, identified) in edits.signatures() {
        keyed.insert(
            Key::Signature(entry),
            Value::Signature(Some(Box::new(identified.clone()))),
        );
    }
    keyed
}

/// The edits of `project` and the journal they are the projection of,
/// its log in the project's `log/`, `identity` writing its changes, its
/// chains of `of` if the log does not say yet ([`open_in`]).
///
/// # Errors
///
/// As [`open_in`].
pub(crate) fn open(
    project: &Project,
    identity: &Identity,
    of: Of,
) -> Result<(Edits, Journal), String> {
    open_in(project, project.dir().join("log"), identity, of)
}

/// The edits of `project` and the journal they are the projection of,
/// its log in directory `log`, `identity` writing its changes:
///
/// - the freezes of a membership record being taken (an intent kept in
///   the project's directory, [`Intent`]) written to the log first;
/// - its log's changes taken (checked: a change refused is listed), after
///   its freezes, evidence and (a share's) marks, judged by no authority
///   ([`Journal::replay`]); its chains of what `log/bound` says, else of
///   `of` (a new log);
/// - a project file the journal did not write (one without a log yet, or
///   edited outside it, by hand) taken as a change [`Origin::Import`] of
///   what differs; a project file the
///   journal wrote but that lags its log (a crash between them) written
///   again;
/// - edits waiting in the log's `import/` (an exported project without a
///   log, imported) taken beside the journal's, as concurrent edits.
/// - this install's private bookmarks, from the project's `private.toml`.
///
/// An unchanged project's file is never written.
///
/// # Errors
///
/// The project file, log or private bookmarks' file cannot be read or
/// written, or the project file is not one; the log has no binding, or is
/// a share's without its freezes, evidence or matching marks, or with a
/// chain's file that does not read or is not there; an intent does not
/// read; no randomness.
pub(crate) fn open_in(
    project: &Project,
    log: std::path::PathBuf,
    identity: &Identity,
    of: Of,
) -> Result<(Edits, Journal), String> {
    let path = project.edits();
    let text = match fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let file = match &text {
        Some(text) => Edits::parse(text).map_err(|error| format!("{}: {error}", path.display()))?,
        None => Edits::default(),
    };
    let mut store = Store::new(log);
    let signer = identity.signer().clone();
    let logged = store.project()?;
    let mut journal = match logged {
        None => Journal::new(ProjectId(random()?), store.bound()?.unwrap_or(of), signer)?,
        Some(id) => {
            let bound = store.bound()?.ok_or_else(|| {
                format!(
                    "{}: the log says not what its chains are of: it is not opened",
                    store.dir().display()
                )
            })?;
            let mut journal = Journal::new(id, bound, signer)?;
            // A membership record taken when the process stopped: its
            // freezes in force before anything of the log is read.
            store.freeze_intents(project.dir())?;
            journal.replay(&mut store)?;
            journal
        }
    };
    let imports = store.imports();
    journal.store = Some(store);
    if logged.is_some() {
        journal.adopt();
    }
    journal.private = Private::load(project.private())?;
    journal.restore_steps();
    let mut edits = journal.projection();
    let ours = match (&text, journal.store.as_ref().and_then(Store::projected)) {
        (Some(text), Some(hash)) => *blake3::hash(text.as_bytes()).as_bytes() == hash,
        (None, _) => logged.is_some(),
        (Some(_), None) => false,
    };
    // Lagging the log (a crash between them): written again; written by
    // another: taken.
    let lags = ours && edits != file;
    if !ours && edits != file {
        journal.import(&file, "project.toml", false, &mut edits)?;
    }
    for path in &imports {
        let from = Edits::load(path)?;
        let label = path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        journal.import(&from, &label, true, &mut edits)?;
    }
    let made = !journal.unsaved.is_empty();
    match &text {
        // A project file without a log: the log made, the file kept as
        // written.
        Some(text) if logged.is_none() && imports.is_empty() && made => {
            journal.flush()?;
            journal.mark(text)?;
        }
        _ if lags || made => journal.save(&edits, project)?,
        Some(text) if !ours => journal.mark(text)?,
        Some(_) | None => {}
    }
    for path in &imports {
        let _ = fs::remove_file(path);
    }
    // What the log held is not news.
    journal.heard.clear();
    Ok((edits, journal))
}

/// Whether `key`'s winner is add-wins (a bookmark).
fn adds(key: &Key) -> bool {
    matches!(key, Key::Bookmark(..))
}

/// Whether `author` may write `key`: anything but another's bookmark.
fn owns(key: &Key, author: PublicKey) -> bool {
    !matches!(key, Key::Bookmark(owner, _) if *owner != author)
}

/// The chain of `author` in `project` salted with `salt`.
fn chain_id(author: PublicKey, project: ProjectId, salt: &[u8; 16]) -> ChainId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&author.0);
    hasher.update(&project.0);
    hasher.update(salt);
    let mut id = [0; 16];
    id.copy_from_slice(hasher.finalize().as_bytes().get(..16).unwrap_or(&[0; 16]));
    ChainId(id)
}
