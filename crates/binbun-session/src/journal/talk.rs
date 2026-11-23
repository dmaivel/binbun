//! Conversation in the log: threads anchored to addresses, their posts,
//! and suggestions.
//! Each is an append-only key ([`Key::Thread`], [`Key::Post`],
//! [`Key::Suggestion`]) named by the change that made it and its number
//! among the threads, posts and suggestions that change made (an
//! [`OpId`]: known as soon as it is written, before the change is
//! sealed). The ops on a key are its making ([`ThreadOp::Open`],
//! [`PostOp::New`], [`SuggestionOp::New`]) and what came after:
//!
//! - a thread's resolved state, last writer wins ([`ThreadOp::Resolve`]);
//! - a post's edits, last writer wins among its author's own: an edit by
//!   anyone else counts for nothing ([`PostOp::Edit`]);
//! - a post's deletion, by its author or an owner of the project
//!   ([`Journal::set_owners`]): once deleted it stays deleted, whatever
//!   edit is concurrent with or later than the deletion, on every peer
//!   ([`PostOp::Delete`]);
//! - a suggestion's state, last writer wins: accepted (some of its
//!   edits), dismissed, superseded by its author's next version
//!   ([`SuggestionOp::State`]; superseded by anyone else counts for
//!   nothing).
//!
//! A rule about another change (a post's thread, a post's or a
//! suggestion's author) never refuses a change: the op that breaks it is
//! **inert**, counted in nothing shown, told, notified or undone, and
//! taking no value away, decided from the ops held, so it follows its
//! target if a freeze withdraws it. A post in no thread is not shown.
//!
//! They are never part of the edits' projection, never a conflict, and a
//! change of conversation alone is never undone (it is not an edit); an
//! accepted suggestion's state is undone with its edits (pending again).

use std::collections::{BTreeMap, BTreeSet};

use binbun::corrections::{Bounds, Item};
use serde::{Deserialize, Serialize};

use super::register::{Entry, Register};
use super::{
    Body, ChainId, ChangeId, DebugRef, Hlc, Journal, Key, Op, OpId, Origin, PublicKey, Stated,
    Value, wire,
};
use crate::edits::{Identified, Variable};
use crate::number::canonical;

/// The most characters of a thread's quote.
pub const MAX_QUOTE: usize = 200;

/// The most bytes of a post's body, a suggestion's rationale, an
/// evidence's text or quote.
pub const MAX_TEXT: usize = 16 * 1024;

/// The most bytes of a suggestion's label.
pub const MAX_LABEL: usize = 200;

/// The most mentions of a post, items of an evidence, edits of a
/// suggestion.
pub const MAX_ITEMS: usize = 1024;

/// What a thread is about: what survives re-analysis (addresses), as
/// comments do.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Anchor {
    /// The function at this entry.
    Function(u64),
    /// The instruction at this address.
    Instruction(u64),
    /// The data item at this address.
    Data(u64),
    /// A line of a function's C, by the first instruction it was made
    /// from: found again wherever that instruction prints after a
    /// re-analysis.
    Line {
        /// The function's entry.
        function: u64,
        /// The reading view (else the exact one).
        reading: bool,
        /// The line's first instruction.
        address: u64,
    },
    /// A variable.
    Variable(Variable),
    /// A type, by the key its definition defines (`struct pair`).
    Type(#[serde(deserialize_with = "wire::text")] String),
    /// A suggestion: its discussion.
    Suggestion(OpId),
}

impl Anchor {
    /// The address it is at: a function's entry, an instruction's or data
    /// item's address, a C line's first instruction, a variable's
    /// function's entry; none for a type or a suggestion.
    pub fn address(&self) -> Option<u64> {
        match self {
            Self::Function(address)
            | Self::Instruction(address)
            | Self::Data(address)
            | Self::Line { address, .. } => Some(*address),
            Self::Variable(variable) => Some(variable.function),
            Self::Type(_) | Self::Suggestion(_) => None,
        }
    }

    /// The function it names, by entry, if it names one.
    pub fn function(&self) -> Option<u64> {
        match self {
            Self::Function(entry)
            | Self::Line {
                function: entry, ..
            } => Some(*entry),
            Self::Variable(variable) => Some(variable.function),
            Self::Instruction(_) | Self::Data(_) | Self::Type(_) | Self::Suggestion(_) => None,
        }
    }
}

/// An op on a thread.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreadOp {
    /// Opened.
    Open(Box<Opening>),
    /// Resolved (`true`) or opened again.
    Resolve(bool),
}

/// A thread as opened.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Opening {
    /// What it is about.
    pub anchor: Anchor,
    /// The anchor's text then (a C line's, an instruction's), at most
    /// [`MAX_QUOTE`] characters: shown if the anchor no longer resolves.
    #[serde(deserialize_with = "wire::text")]
    pub quote: String,
}

/// An op on a post.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PostOp {
    /// Posted.
    New(Box<Posting>),
    /// Its body now (its author's only).
    Edit(#[serde(deserialize_with = "wire::text")] String),
    /// Deleted (by its author, or an owner).
    Delete,
}

/// A post as posted.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Posting {
    /// Its thread.
    pub thread: OpId,
    /// The post it answers, if any.
    pub reply_to: Option<OpId>,
    /// What it says (Markdown), at most [`MAX_TEXT`] bytes.
    #[serde(deserialize_with = "wire::text")]
    pub body: String,
    /// Who it mentions.
    #[serde(deserialize_with = "wire::list::<_, Mention, MAX_ITEMS>")]
    pub mentions: Vec<Mention>,
    /// What it rests on, if anything.
    pub evidence: Option<Evidence>,
}

/// Someone mentioned (`@name`): an identity, and which of its scripts or
/// agents if one (none: the person).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Mention {
    /// The identity.
    pub key: PublicKey,
    /// Its script, plugin or agent (`script:helper`, `agent`), as the
    /// changes it makes are authored; none: the person.
    #[serde(deserialize_with = "wire::opt_text")]
    pub agent: Option<String>,
}

/// An op on a suggestion.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuggestionOp {
    /// Suggested.
    New(Box<Suggest>),
    /// What became of it.
    State(SuggestionState),
}

/// A suggestion as made: edits proposed, why, and what it rests on.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Suggest {
    /// What it does, for people (`Name crypto helpers`), at most
    /// [`MAX_LABEL`] bytes.
    #[serde(deserialize_with = "wire::text")]
    pub label: String,
    /// The edits proposed, each with what its key held when proposed.
    #[serde(deserialize_with = "wire::list::<_, Proposed, MAX_ITEMS>")]
    pub edits: Vec<Proposed>,
    /// Why (Markdown), at most [`MAX_TEXT`] bytes.
    #[serde(deserialize_with = "wire::text")]
    pub rationale: String,
    /// What it rests on.
    pub evidence: Evidence,
    /// The thread it answers, if any.
    pub thread: Option<OpId>,
    /// The suggestion of its author's it is the next version of.
    pub supersedes: Option<OpId>,
}

/// An edit proposed: a key's value, and the leaves of the key its author
/// saw.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Proposed {
    /// The key.
    pub key: Key,
    /// Its value.
    pub value: EditValue,
    /// The leaves of the key when proposed.
    #[serde(deserialize_with = "wire::list::<_, OpId, { wire::LIST }>")]
    pub prev: Vec<OpId>,
}

/// A value an edit sets: a [`Value`] of an edit's key, never a chain's
/// author nor a conversation op, so a proposed edit holds no suggestion
/// (and reads at a fixed depth).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EditValue {
    /// [`Value::Text`].
    Text(#[serde(deserialize_with = "wire::opt_text")] Option<String>),
    /// [`Value::Number`].
    Number(Option<Stated>),
    /// [`Value::Item`].
    Item(#[serde(with = "super::wire::item")] Option<Item>),
    /// [`Value::Bounds`].
    Bounds(#[serde(with = "super::wire::bounds")] Option<Bounds>),
    /// [`Value::DebugFile`].
    DebugFile(Option<DebugRef>),
    /// [`Value::Signature`].
    Signature(Option<Box<Identified>>),
}

impl EditValue {
    /// Whether a suggestion may propose it for `key`: `key` is an edit's
    /// other than a bookmark (each author's are their own), and takes it.
    pub fn fits(&self, key: &Key) -> bool {
        if !key.is_edit() || matches!(key, Key::Bookmark(..)) {
            return false;
        }
        match (key, self) {
            (Key::Number(_, canon), Self::Number(stated)) => stated
                .as_ref()
                .is_none_or(|stated| canonical(stated.value) == *canon),
            (Key::Item(_), Self::Item(item)) => item.as_ref().is_none_or(wire::item::holds),
            (key, value) => Self::try_from(Value::none(key))
                .is_ok_and(|none| std::mem::discriminant(&none) == std::mem::discriminant(value)),
        }
    }
}

impl From<EditValue> for Value {
    fn from(value: EditValue) -> Self {
        match value {
            EditValue::Text(text) => Self::Text(text),
            EditValue::Number(stated) => Self::Number(stated),
            EditValue::Item(item) => Self::Item(item),
            EditValue::Bounds(bounds) => Self::Bounds(bounds),
            EditValue::DebugFile(debug) => Self::DebugFile(debug),
            EditValue::Signature(identified) => Self::Signature(identified),
        }
    }
}

impl TryFrom<Value> for EditValue {
    /// The value, not an edit's.
    type Error = Value;

    fn try_from(value: Value) -> Result<Self, Value> {
        match value {
            Value::Text(text) => Ok(Self::Text(text)),
            Value::Number(stated) => Ok(Self::Number(stated)),
            Value::Item(item) => Ok(Self::Item(item)),
            Value::Bounds(bounds) => Ok(Self::Bounds(bounds)),
            Value::DebugFile(debug) => Ok(Self::DebugFile(debug)),
            Value::Signature(identified) => Ok(Self::Signature(identified)),
            Value::Thread(_) | Value::Post(_) | Value::Suggestion(_) => Err(value),
        }
    }
}

/// What became of a suggestion.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuggestionState {
    /// Waiting for review (again, if its acceptance was undone).
    Pending,
    /// Accepted: these of its edits (by their number).
    Accepted(#[serde(deserialize_with = "wire::list::<_, u16, MAX_ITEMS>")] Vec<u16>),
    /// Dismissed: why.
    Dismissed(#[serde(deserialize_with = "wire::text")] String),
    /// Superseded by its author's next version.
    Superseded(OpId),
}

/// What a post or suggestion cites: items any peer can ask again (the
/// engine is deterministic), each with what it said when quoted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Evidence {
    /// The items.
    #[serde(deserialize_with = "wire::list::<_, EvidenceItem, MAX_ITEMS>")]
    pub items: Vec<EvidenceItem>,
}

/// An item of evidence: what it cites, and what it said when quoted.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// What it cites.
    pub reference: EvidenceRef,
    /// Its answer when quoted (`Session::quote`); none: not quoted.
    #[serde(deserialize_with = "wire::opt_text")]
    pub quote: Option<String>,
}

/// What an item of evidence cites, by what asks it again.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceRef {
    /// These lines (from 0) of a function's C.
    Lines {
        /// The function's entry.
        function: u64,
        /// The reading view (else the exact one).
        reading: bool,
        /// The lines.
        #[serde(deserialize_with = "wire::list::<_, u32, { wire::LIST }>")]
        lines: Vec<u32>,
    },
    /// A function's verification's verdict.
    Verification {
        /// The function's entry.
        function: u64,
        /// The reading view (else the exact one).
        reading: bool,
    },
    /// Why a variable has its name and type (`binbun why`).
    Why {
        /// The function's entry.
        function: u64,
        /// The reading view (else the exact one).
        reading: bool,
        /// The variable.
        variable: Variable,
    },
    /// What refers to an address.
    Xrefs {
        /// The address.
        to: u64,
    },
    /// The string at an address.
    String {
        /// The address.
        address: u64,
    },
    /// A call site: its caller's C line.
    Call {
        /// The call instruction.
        site: u64,
    },
    /// Its author's own words.
    Text(#[serde(deserialize_with = "wire::text")] String),
}

/// Who made something: an identity, and as whom (the person, a script,
/// an agent).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Author {
    /// The identity.
    pub key: PublicKey,
    /// As whom: its change's origin.
    pub origin: Origin,
}

impl Author {
    /// The script, plugin or agent it is (`script:helper`), as a
    /// [`Mention`] names it; none for the person.
    pub fn agent(&self) -> Option<String> {
        match &self.origin {
            Origin::Script(_) | Origin::Plugin(_) | Origin::Agent => Some(self.origin.to_string()),
            Origin::User
            | Origin::Import(_)
            | Origin::Undo(_)
            | Origin::Redo(_)
            | Origin::Accept(_)
            | Origin::Signature(_) => None,
        }
    }

    /// Whether `mention` names it.
    pub fn is(&self, mention: &Mention) -> bool {
        self.key == mention.key && self.agent() == mention.agent
    }
}

/// A thread as it is now.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Thread {
    /// Its id.
    pub id: OpId,
    /// What it is about.
    pub anchor: Anchor,
    /// The anchor's text when it was opened.
    pub quote: String,
    /// Who opened it.
    pub opened_by: Author,
    /// When.
    pub time: Hlc,
    /// Whether it is resolved.
    pub resolved: bool,
    /// Who resolved it, or opened it again, last.
    pub resolved_by: Option<Author>,
    /// Its posts, in order (deleted ones too, as deleted).
    pub posts: Vec<Post>,
    /// The suggestions answering it, in order.
    pub suggestions: Vec<OpId>,
}

/// A post as it is now.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Post {
    /// Its id.
    pub id: OpId,
    /// Its thread.
    pub thread: OpId,
    /// The post it answers, if any.
    pub reply_to: Option<OpId>,
    /// Who posted it.
    pub author: Author,
    /// When.
    pub time: Hlc,
    /// What it says now (empty once deleted).
    pub body: String,
    /// When its author last edited it, if they did.
    pub edited: Option<Hlc>,
    /// Who deleted it, if it is.
    pub deleted: Option<Deleted>,
    /// Who it mentions (none once deleted).
    pub mentions: Vec<Mention>,
    /// What it rests on (none once deleted).
    pub evidence: Option<Evidence>,
}

/// Who deleted a post.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Deleted {
    /// The identity.
    pub by: PublicKey,
    /// As whom: its change's origin.
    pub origin: Origin,
    /// Whether an owner removed it (not its author): "removed by the
    /// owner".
    pub by_owner: bool,
}

/// A suggestion as it is now.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Suggestion {
    /// Its id.
    pub id: OpId,
    /// Who made it.
    pub author: Author,
    /// When.
    pub time: Hlc,
    /// What it does.
    pub label: String,
    /// Its edits, each against what its key holds now.
    pub edits: Vec<Proposal>,
    /// Why.
    pub rationale: String,
    /// What it rests on, as quoted.
    pub evidence: Evidence,
    /// The thread it answers, if any.
    pub thread: Option<OpId>,
    /// The suggestion it is the next version of.
    pub supersedes: Option<OpId>,
    /// What became of it.
    pub state: SuggestionState,
    /// Who decided that (accepted, dismissed, superseded it) last.
    pub decided_by: Option<Author>,
}

/// An edit proposed, against what its key holds now.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Proposal {
    /// The key.
    pub key: Key,
    /// The value proposed.
    pub value: Value,
    /// The leaves of the key when proposed.
    pub prev: Vec<OpId>,
    /// The value it shows now, if any.
    pub now: Option<Value>,
    /// Whether the key changed since it was proposed (its leaves moved):
    /// what to show against the proposal before accepting it.
    pub moved: bool,
}

/// What conversation came (made here or taken from elsewhere).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Talked {
    /// The threads with something new (opened, posted to, a post edited
    /// or deleted, resolved, a suggestion answering them), by id.
    pub threads: Vec<OpId>,
    /// The suggestions made or decided, by id.
    pub suggestions: Vec<OpId>,
}

/// A post mentioning this identity (or one it answers for), as
/// `Event::Mentioned` tells it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Mentioned {
    /// The post's thread.
    pub thread: OpId,
    /// The post.
    pub post: OpId,
    /// Who posted it.
    pub by: Author,
    /// The mention.
    pub mention: Mention,
    /// What it says.
    pub body: String,
}

impl Key {
    /// The thread, post or suggestion it names, if a conversation key.
    pub fn talk(&self) -> Option<OpId> {
        match self {
            Self::Thread(id) | Self::Post(id) | Self::Suggestion(id) => Some(*id),
            Self::FunctionName(_)
            | Self::GlobalName(_)
            | Self::VariableName(_)
            | Self::Slot(..)
            | Self::Comment(_)
            | Self::Bookmark(..)
            | Self::Number(..)
            | Self::Type(_)
            | Self::Definition(_)
            | Self::Item(_)
            | Self::Bounds(_)
            | Self::DebugFile
            | Self::Signature(_) => None,
        }
    }

    /// Whether it is an edit's (what a suggestion may propose).
    pub fn is_edit(&self) -> bool {
        self.talk().is_none()
    }
}

impl Value {
    /// Whether it makes its key (opens a thread, posts, suggests).
    pub fn creates(&self) -> bool {
        matches!(
            self,
            Self::Thread(ThreadOp::Open(_))
                | Self::Post(PostOp::New(_))
                | Self::Suggestion(SuggestionOp::New(_))
        )
    }

    /// The threads, posts and suggestions it names (besides its key).
    fn names(&self) -> Vec<OpId> {
        match self {
            Self::Thread(ThreadOp::Open(opening)) => match opening.anchor {
                Anchor::Suggestion(id) => vec![id],
                Anchor::Function(_)
                | Anchor::Instruction(_)
                | Anchor::Data(_)
                | Anchor::Line { .. }
                | Anchor::Variable(_)
                | Anchor::Type(_) => Vec::new(),
            },
            Self::Post(PostOp::New(posting)) => std::iter::once(posting.thread)
                .chain(posting.reply_to)
                .collect(),
            Self::Suggestion(SuggestionOp::New(suggest)) => suggest
                .thread
                .into_iter()
                .chain(suggest.supersedes)
                .collect(),
            Self::Suggestion(SuggestionOp::State(SuggestionState::Superseded(by))) => vec![*by],
            Self::Thread(ThreadOp::Resolve(_))
            | Self::Post(PostOp::Edit(_) | PostOp::Delete)
            | Self::Suggestion(SuggestionOp::State(
                SuggestionState::Pending
                | SuggestionState::Accepted(_)
                | SuggestionState::Dismissed(_),
            ))
            | Self::Text(_)
            | Self::Number(_)
            | Self::Item(_)
            | Self::Bounds(_)
            | Self::DebugFile(_)
            | Self::Signature(_) => Vec::new(),
        }
    }

    /// Why it is too large or malformed, if it is.
    fn oversized(&self) -> Option<String> {
        let long = |what: &str, text: &str, most: usize| {
            (text.len() > most).then(|| format!("{what} longer than {most} bytes"))
        };
        match self {
            Self::Thread(ThreadOp::Open(opening)) => (opening.quote.chars().count() > MAX_QUOTE)
                .then(|| format!("a quote longer than {MAX_QUOTE} characters")),
            Self::Post(PostOp::New(posting)) => long("a post", &posting.body, MAX_TEXT)
                .or_else(|| {
                    (posting.mentions.len() > MAX_ITEMS)
                        .then(|| format!("more than {MAX_ITEMS} mentions"))
                })
                .or_else(|| posting.evidence.as_ref().and_then(Evidence::oversized)),
            Self::Post(PostOp::Edit(body)) => long("a post", body, MAX_TEXT),
            Self::Suggestion(SuggestionOp::New(suggest)) => suggest.oversized(),
            Self::Suggestion(SuggestionOp::State(SuggestionState::Dismissed(why))) => {
                long("a reason", why, MAX_TEXT)
            }
            Self::Thread(ThreadOp::Resolve(_))
            | Self::Post(PostOp::Delete)
            | Self::Suggestion(SuggestionOp::State(
                SuggestionState::Pending
                | SuggestionState::Accepted(_)
                | SuggestionState::Superseded(_),
            ))
            | Self::Text(_)
            | Self::Number(_)
            | Self::Item(_)
            | Self::Bounds(_)
            | Self::DebugFile(_)
            | Self::Signature(_) => None,
        }
    }
}

impl Evidence {
    /// Why it is too large, if it is.
    fn oversized(&self) -> Option<String> {
        if self.items.len() > MAX_ITEMS {
            return Some(format!("more than {MAX_ITEMS} items of evidence"));
        }
        self.items.iter().find_map(|item| {
            let text = match &item.reference {
                EvidenceRef::Text(text) => text.len(),
                EvidenceRef::Lines { lines, .. } => lines.len().saturating_mul(4),
                EvidenceRef::Verification { .. }
                | EvidenceRef::Why { .. }
                | EvidenceRef::Xrefs { .. }
                | EvidenceRef::String { .. }
                | EvidenceRef::Call { .. } => 0,
            };
            let quote = item.quote.as_ref().map_or(0, String::len);
            (text > MAX_TEXT || quote > MAX_TEXT)
                .then(|| format!("evidence longer than {MAX_TEXT} bytes"))
        })
    }
}

impl Suggest {
    /// Why it is too large or proposes what it may not, if it is.
    fn oversized(&self) -> Option<String> {
        if self.label.len() > MAX_LABEL {
            return Some(format!("a label longer than {MAX_LABEL} bytes"));
        }
        if self.rationale.len() > MAX_TEXT {
            return Some(format!("a rationale longer than {MAX_TEXT} bytes"));
        }
        if self.edits.is_empty() || self.edits.len() > MAX_ITEMS {
            return Some(format!("a suggestion proposes 1 to {MAX_ITEMS} edits"));
        }
        if let Some(edit) = self.edits.iter().find(|edit| !edit.value.fits(&edit.key)) {
            return Some(format!("a suggestion proposes no edit: {:?}", edit.key));
        }
        self.evidence.oversized()
    }
}

/// Why the conversation ops of change `change` (body `body`) cannot be
/// taken, if they cannot (what a change says of itself): each thread,
/// post or suggestion it makes is named for it, once; an op on one it
/// makes comes after the making; no text is too long; a suggestion
/// proposes edits only.
pub(super) fn malformed(change: ChangeId, body: &Body) -> Option<String> {
    let mut made = BTreeSet::new();
    for op in &body.ops {
        let Some(id) = op.key.talk() else {
            continue;
        };
        if op.value.creates() {
            if id.change != change || !made.insert(id) {
                return Some(format!(
                    "{:?} is not named for the change making it",
                    op.key
                ));
            }
        } else if id.change == change && !made.contains(&id) {
            return Some(format!("{:?} is changed before it is made", op.key));
        }
        if let Some(why) = op.value.oversized() {
            return Some(why);
        }
    }
    None
}

/// The changes the conversation ops of change `change` (body `body`) name
/// besides itself: those making a thread, post or suggestion they name.
pub(super) fn named(change: ChangeId, body: &Body) -> impl Iterator<Item = ChangeId> + '_ {
    body.ops
        .iter()
        .filter(|op| op.key.talk().is_some())
        .flat_map(|op| op.key.talk().into_iter().chain(op.value.names()))
        .map(|id| id.change)
        .filter(move |id| *id != change)
}

/// The first and last ids a conversation key can have.
const FIRST: OpId = OpId {
    change: ChangeId {
        chain: ChainId([0; 16]),
        seq: 0,
    },
    index: 0,
};
const LAST: OpId = OpId {
    change: ChangeId {
        chain: ChainId([0xff; 16]),
        seq: u64::MAX,
    },
    index: u16::MAX,
};

impl Journal {
    /// The id the next thread, post or suggestion made in the group open
    /// takes, on the chain its change is sealed on (an agent's, or this
    /// install's; none open: none).
    pub(crate) fn next_talk(&mut self) -> Option<OpId> {
        let pending = self.pending.as_mut()?;
        let chain = pending
            .by
            .and_then(|key| self.agents.get(&key))
            .map_or(self.chain, |agent| agent.chain);
        // A chain not begun begins with its start: its first edit is 2.
        let seq = self.chains.get(&chain).map_or(2, |chain| chain.seq + 1);
        let index = pending.created;
        pending.created = index.checked_add(1)?;
        Some(OpId {
            change: ChangeId { chain, seq },
            index,
        })
    }

    /// The owners of the project (ever): who may delete anyone's post.
    pub(crate) fn set_owners(&mut self, owners: BTreeSet<PublicKey>) -> bool {
        let changed = self.owners != owners;
        self.owners = owners;
        changed
    }

    /// Mentions of `key` are told here too (a session following another
    /// process's, whose identity it answers for).
    pub(crate) fn answer_for(&mut self, key: PublicKey) {
        self.voices.insert(key);
    }

    /// Whether `key` is an owner of the project.
    pub(crate) fn is_owner(&self, key: PublicKey) -> bool {
        self.owners.contains(&key)
    }

    /// Whether thread `id` is made (taken, or written in the group open).
    pub(crate) fn is_thread(&self, id: OpId) -> bool {
        matches!(
            self.made(&Key::Thread(id)),
            Some((Value::Thread(ThreadOp::Open(_)), _))
        )
    }

    /// The making of the thread, post or suggestion `key` names: its op
    /// and value, made in a change taken.
    fn making(&self, key: &Key) -> Option<(OpId, &Value)> {
        let (op, value, _) = making_of(self.registers.get(key)?)?;
        Some((op, value))
    }

    /// The value making `key`, and who made it: from the changes taken,
    /// else from the group open.
    fn made(&self, key: &Key) -> Option<(Value, PublicKey)> {
        if let Some((op, value)) = self.making(key) {
            let author = self.chains.get(&op.change.chain)?.author;
            return Some((value.clone(), author));
        }
        let making = |op: &&Op| op.key == *key && op.value.creates();
        self.pending
            .iter()
            .flat_map(|pending| pending.ops.iter().flatten())
            .find(making)
            .map(|op| (op.value.clone(), self.author()))
    }

    /// Op `op`'s author, as whom it made it.
    fn author_of_op(&self, op: OpId) -> Option<Author> {
        let record = self.records.get(&op.change)?;
        Some(Author {
            key: record.author,
            origin: record.body.origin.clone(),
        })
    }

    /// The register of every conversation key of a kind, by its id.
    fn kind(&self, kind: fn(OpId) -> Key) -> impl Iterator<Item = (OpId, &Register)> {
        self.registers
            .range(kind(FIRST)..=kind(LAST))
            .filter_map(|(key, register)| Some((key.talk()?, register)))
    }

    /// Every thread, in the order opened.
    pub(crate) fn threads(&self) -> Vec<Thread> {
        let mut posts: BTreeMap<OpId, Vec<Post>> = BTreeMap::new();
        for (id, register) in self.kind(Key::Post) {
            if let Some(post) = self.post(id, register) {
                posts.entry(post.thread).or_default().push(post);
            }
        }
        let mut answering: BTreeMap<OpId, Vec<(Hlc, OpId)>> = BTreeMap::new();
        for (id, register) in self.kind(Key::Suggestion) {
            if let Some((_, Value::Suggestion(SuggestionOp::New(suggest)), time)) =
                making_of(register)
                && let Some(thread) = suggest.thread
            {
                answering.entry(thread).or_default().push((time, id));
            }
        }
        let mut threads: Vec<Thread> = self
            .kind(Key::Thread)
            .filter_map(|(id, register)| {
                let mut posts = posts.remove(&id).unwrap_or_default();
                posts.sort_by_key(|post| (post.time, post.id));
                let mut suggestions = answering.remove(&id).unwrap_or_default();
                suggestions.sort_unstable();
                self.thread(id, register, posts, suggestions.into_iter().map(|(_, s)| s))
            })
            .collect();
        threads.sort_by_key(|thread| (thread.time, thread.id));
        threads
    }

    /// Thread `id` as its register, posts and suggestions say.
    fn thread(
        &self,
        id: OpId,
        register: &Register,
        posts: Vec<Post>,
        suggestions: impl Iterator<Item = OpId>,
    ) -> Option<Thread> {
        let (op, Value::Thread(ThreadOp::Open(opening)), time) = making_of(register)? else {
            return None;
        };
        let (resolved, resolved_by) = match register.winner(false) {
            Some((
                last,
                Entry {
                    value: Value::Thread(ThreadOp::Resolve(resolved)),
                    ..
                },
            )) => (*resolved, self.author_of_op(*last)),
            _ => (false, None),
        };
        Some(Thread {
            id,
            anchor: opening.anchor.clone(),
            quote: opening.quote.clone(),
            opened_by: self.author_of_op(op)?,
            time,
            resolved,
            resolved_by,
            posts,
            suggestions: suggestions.collect(),
        })
    }

    /// Post `id` as its register says: its author's last edit, deleted
    /// by its author or an owner (whatever was edited meanwhile or since);
    /// none if its thread is not opened (an inert post). Edits by anyone
    /// else, and deletions by anyone but its author or an owner, count
    /// for nothing.
    fn post(&self, id: OpId, register: &Register) -> Option<Post> {
        let (op, Value::Post(PostOp::New(posting)), time) = making_of(register)? else {
            return None;
        };
        let Some((_, Value::Thread(ThreadOp::Open(_)))) = self.making(&Key::Thread(posting.thread))
        else {
            return None;
        };
        let author = self.author_of_op(op)?;
        let mut body = posting.body.clone();
        let mut edited = None;
        let mut deleted = None;
        let mut ops: Vec<(&OpId, &Entry)> = register.ops().collect();
        ops.sort_by_key(|(_, entry)| entry.stamp);
        for (other, entry) in ops {
            let Some(by) = self
                .chains
                .get(&other.change.chain)
                .map(|chain| chain.author)
            else {
                continue;
            };
            if let Value::Post(PostOp::Edit(text)) = &entry.value
                && by == author.key
            {
                body.clone_from(text);
                edited = Some(entry.stamp.hlc);
            } else if entry.value == Value::Post(PostOp::Delete)
                && deleted.is_none()
                && (by == author.key || self.owners.contains(&by))
                && let Some(deleter) = self.author_of_op(*other)
            {
                deleted = Some(Deleted {
                    by,
                    origin: deleter.origin,
                    by_owner: by != author.key,
                });
            }
        }
        let gone = deleted.is_some();
        Some(Post {
            id,
            thread: posting.thread,
            reply_to: posting.reply_to,
            author,
            time,
            body: if gone { String::new() } else { body },
            edited,
            deleted,
            mentions: if gone {
                Vec::new()
            } else {
                posting.mentions.clone()
            },
            evidence: if gone { None } else { posting.evidence.clone() },
        })
    }

    /// Every suggestion, in the order made.
    pub(crate) fn suggestions(&self) -> Vec<Suggestion> {
        let mut suggestions: Vec<Suggestion> = self
            .kind(Key::Suggestion)
            .filter_map(|(id, register)| self.suggestion(id, register))
            .collect();
        suggestions.sort_by_key(|suggestion| (suggestion.time, suggestion.id));
        suggestions
    }

    /// Suggestion `id` as its register says, its edits against their keys
    /// now. Of its states, one superseding it counts only if its author
    /// wrote it, and it supersedes another only of its author's.
    fn suggestion(&self, id: OpId, register: &Register) -> Option<Suggestion> {
        let (op, Value::Suggestion(SuggestionOp::New(suggest)), time) = making_of(register)? else {
            return None;
        };
        let author = self.author_of_op(op)?;
        let by = |id: &OpId| self.chains.get(&id.change.chain).map(|chain| chain.author);
        let counts = |id: &OpId, entry: &Entry| {
            !matches!(
                entry.value,
                Value::Suggestion(SuggestionOp::State(SuggestionState::Superseded(_)))
            ) || by(id) == Some(author.key)
        };
        let (state, decided_by) = match counted_winner(register, counts) {
            Some((
                last,
                Entry {
                    value: Value::Suggestion(SuggestionOp::State(state)),
                    ..
                },
            )) => (state.clone(), self.author_of_op(*last)),
            _ => (SuggestionState::Pending, None),
        };
        let supersedes = suggest.supersedes.filter(|old| {
            self.making(&Key::Suggestion(*old))
                .is_some_and(|(made, _)| by(&made) == Some(author.key))
        });
        let edits = suggest
            .edits
            .iter()
            .map(|proposed| {
                let register = self.registers.get(&proposed.key);
                let leaves: BTreeSet<OpId> = register
                    .map(|register| register.leaves().map(|(id, _)| *id).collect())
                    .unwrap_or_default();
                let seen: BTreeSet<OpId> = proposed.prev.iter().copied().collect();
                Proposal {
                    key: proposed.key.clone(),
                    value: proposed.value.clone().into(),
                    prev: proposed.prev.clone(),
                    now: self.shown(&proposed.key).cloned(),
                    moved: leaves != seen,
                }
            })
            .collect();
        Some(Suggestion {
            id,
            author,
            time,
            label: suggest.label.clone(),
            edits,
            rationale: suggest.rationale.clone(),
            evidence: suggest.evidence.clone(),
            thread: suggest.thread,
            supersedes,
            state,
            decided_by,
        })
    }

    /// Thread `id`, if made.
    pub(crate) fn find_thread(&self, id: OpId) -> Option<Thread> {
        self.threads().into_iter().find(|thread| thread.id == id)
    }

    /// Post `id`, if made.
    pub(crate) fn find_post(&self, id: OpId) -> Option<Post> {
        self.post(id, self.registers.get(&Key::Post(id))?)
    }

    /// Suggestion `id`, if made.
    pub(crate) fn find_suggestion(&self, id: OpId) -> Option<Suggestion> {
        self.suggestion(id, self.registers.get(&Key::Suggestion(id))?)
    }

    /// The leaves of `key` now.
    pub(crate) fn leaves_of(&self, key: &Key) -> Vec<OpId> {
        self.registers
            .get(key)
            .map(|register| register.leaves().map(|(id, _)| *id).collect())
            .unwrap_or_default()
    }

    /// Who made the suggestion change `record` accepted, if it accepted
    /// one.
    pub(super) fn suggested_by(&self, origin: &Origin) -> Option<Author> {
        let Origin::Accept(id) = origin else {
            return None;
        };
        let (op, _) = self.making(&Key::Suggestion(*id))?;
        self.author_of_op(op)
    }

    /// What conversation came since this was last asked (and clears it):
    /// the threads and suggestions touched, the new posts mentioning this
    /// identity or one it answers for (never by whom they mention).
    pub(crate) fn talked(&mut self) -> Option<(Talked, Vec<Mentioned>)> {
        if self.heard.is_empty() {
            return None;
        }
        let heard = std::mem::take(&mut self.heard);
        let mut threads = BTreeSet::new();
        let mut suggestions = BTreeSet::new();
        let mut mentions = Vec::new();
        for (key, op) in heard {
            match &key {
                Key::Thread(id) => {
                    threads.insert(*id);
                }
                Key::Post(id) => {
                    let Some(post) = self.find_post(*id) else {
                        continue;
                    };
                    threads.insert(post.thread);
                    let creates = self
                        .registers
                        .get(&key)
                        .and_then(|register| register.ops().find(|(o, _)| **o == op))
                        .is_some_and(|(_, entry)| entry.value.creates());
                    if creates {
                        mentions.extend(self.mentions_in(&post));
                    }
                }
                Key::Suggestion(id) => {
                    suggestions.insert(*id);
                    if let Some(thread) = self.find_suggestion(*id).and_then(|s| s.thread) {
                        threads.insert(thread);
                    }
                }
                Key::FunctionName(_)
                | Key::GlobalName(_)
                | Key::VariableName(_)
                | Key::Slot(..)
                | Key::Comment(_)
                | Key::Bookmark(..)
                | Key::Number(..)
                | Key::Type(_)
                | Key::Definition(_)
                | Key::Item(_)
                | Key::Bounds(_)
                | Key::DebugFile
                | Key::Signature(_) => {}
            }
        }
        Some((
            Talked {
                threads: threads.into_iter().collect(),
                suggestions: suggestions.into_iter().collect(),
            },
            mentions,
        ))
    }

    /// The mentions in `post` of this identity, an agent it signs for or
    /// one it answers for, but of its own author.
    fn mentions_in(&self, post: &Post) -> Vec<Mentioned> {
        let me = self.author();
        post.mentions
            .iter()
            .filter(|mention| {
                (mention.key == me
                    || self.agents.contains_key(&mention.key)
                    || self.voices.contains(&mention.key))
                    && !post.author.is(mention)
            })
            .map(|mention| Mentioned {
                thread: post.thread,
                post: post.id,
                by: post.author.clone(),
                mention: mention.clone(),
                body: post.body.clone(),
            })
            .collect()
    }
}

/// The op making a conversation key, its value and time.
fn making_of(register: &Register) -> Option<(OpId, &Value, Hlc)> {
    register
        .ops()
        .find(|(_, entry)| entry.value.creates())
        .map(|(id, entry)| (*id, &entry.value, entry.stamp.hlc))
}

/// The op shown of `register` among those that `counts`: the highest
/// stamp among them that no other of them names. An op that does not
/// count takes no value away.
fn counted_winner(
    register: &Register,
    counts: impl Fn(&OpId, &Entry) -> bool,
) -> Option<(&OpId, &Entry)> {
    let counted: Vec<(&OpId, &Entry)> = register
        .ops()
        .filter(|(id, entry)| counts(id, entry))
        .collect();
    let named: BTreeSet<OpId> = counted
        .iter()
        .flat_map(|(_, entry)| entry.prev.iter().copied())
        .collect();
    counted
        .into_iter()
        .filter(|(id, _)| !named.contains(id))
        .max_by_key(|(_, entry)| entry.stamp)
}
