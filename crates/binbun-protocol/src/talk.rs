//! Threads and suggestions over the protocol (capabilities `threads` and
//! `suggestions`): their JSON forms and the methods ([`answer`]), which a
//! server answers for its
//! connections and a script in process answers for itself, through the
//! same [`Host`] (a client's conversation joins its transaction, if one
//! is open; else it is a change of its own, authored by the client).
//!
//! Ids are `"<chain hex>:<seq>:<n>"` (a thread, post or suggestion: the
//! change that made it and its number among those the change made);
//! identity keys hexadecimal; addresses `"0x…"`.

use std::time::Duration;

use binbun_session::journal::talk::{Proposal, SuggestionState};
use binbun_session::journal::{ChainId, ChangeId, Hlc, Key, OpId, Origin, PublicKey, Value};
use binbun_session::talk::{
    Anchor, Author, Evidence, EvidenceItem, EvidenceRef, Mention, Mentioned, Post, Suggestion,
    Talked, Thread,
};
use binbun_session::{Error, Rechecked, Say, Session, Suggesting, Variable};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::fault::{Fault, FaultKind};
use crate::hex;
use crate::host::{Host, Owner};
use crate::messages::CommitResult;
use crate::types::{AuthorData, Viewed};
use crate::write::Write;

/// The methods, by name.
pub mod method {
    /// Every thread (→ `Vec<ThreadData>`).
    pub const LIST: &str = "threads.list";
    /// The threads anchored at an address ([`super::At`] →
    /// `Vec<ThreadData>`).
    pub const AT: &str = "threads.at";
    /// The threads about a function ([`super::Of`] → `Vec<ThreadData>`).
    pub const OF: &str = "threads.of";
    /// One thread ([`super::ById`] → `Option<ThreadData>`).
    pub const GET: &str = "threads.get";
    /// Opens a thread, with a first post if a body is given
    /// ([`super::Create`] → `ThreadData`).
    pub const CREATE: &str = "threads.create";
    /// Posts in a thread ([`super::PostParams`] → `PostData`).
    pub const POST: &str = "threads.post";
    /// Edits one's own post ([`super::Edit`] → `PostData`).
    pub const EDIT: &str = "threads.edit";
    /// Deletes a post: one's own, or anyone's by an owner ([`super::ById`]
    /// → `PostData`).
    pub const DELETE: &str = "threads.delete";
    /// Resolves or reopens a thread ([`super::Resolve`] → `ThreadData`).
    pub const RESOLVE: &str = "threads.resolve";
    /// Every suggestion, or those in one state ([`super::ListSuggestions`]
    /// → `Vec<SuggestionData>`).
    pub const SUGGESTIONS: &str = "suggestions.list";
    /// One suggestion ([`super::ById`] → `Option<SuggestionData>`).
    pub const SUGGESTION: &str = "suggestions.get";
    /// Makes a suggestion of writes ([`super::Make`] → `SuggestionData`).
    pub const MAKE: &str = "suggestions.make";
    /// Supersedes one's own suggestion by a new version
    /// ([`super::Supersede`] → `SuggestionData`, the new one).
    pub const SUPERSEDE: &str = "suggestions.supersede";
    /// Accepts a suggestion's edits, some or all ([`super::Accept`] →
    /// `crate::messages::CommitResult`).
    pub const ACCEPT: &str = "suggestions.accept";
    /// Dismisses a suggestion ([`super::Dismiss`] → `SuggestionData`).
    pub const DISMISS: &str = "suggestions.dismiss";
    /// Asks a suggestion's evidence again ([`super::ById`] →
    /// `Vec<RecheckedData>`).
    pub const RECHECK: &str = "suggestions.recheck";
}

/// The notifications, by name.
pub mod notification {
    /// Conversation came ([`super::ThreadNote`]).
    pub const THREAD: &str = "event.thread";
    /// A post mentions the server's identity ([`super::MentionedNote`]).
    pub const MENTIONED: &str = "event.mentioned";
}

/// How long the evidence of a suggestion made is waited for when quoted.
const QUOTING: Duration = Duration::from_secs(120);

/// An id as text.
pub fn id_text(id: OpId) -> String {
    format!("{}:{}:{}", id.change.chain, id.change.seq, id.index)
}

/// The id `text` names.
///
/// # Errors
///
/// It names none ([`FaultKind::Protocol`]).
pub fn parse_id(text: &str) -> Result<OpId, Fault> {
    let bad = || Fault::new(FaultKind::Protocol, format!("not an id: {text:?}"));
    let mut parts = text.split(':');
    let (Some(chain), Some(seq), Some(index), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    let chain =
        <[u8; 16]>::try_from(bytes_of(chain).ok_or_else(bad)?.as_slice()).map_err(|_| bad())?;
    Ok(OpId {
        change: ChangeId {
            chain: ChainId(chain),
            seq: seq.parse().map_err(|_| bad())?,
        },
        index: index.parse().map_err(|_| bad())?,
    })
}

/// The bytes hexadecimal `text` spells.
fn bytes_of(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// The identity key hexadecimal `text` spells.
///
/// # Errors
///
/// It spells none ([`FaultKind::Protocol`]).
pub fn parse_key(text: &str) -> Result<PublicKey, Fault> {
    bytes_of(text)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .map(PublicKey)
        .ok_or_else(|| Fault::new(FaultKind::Protocol, format!("not a key: {text:?}")))
}

/// Milliseconds since the Unix epoch of `time`.
fn millis(time: Hlc) -> u64 {
    time.millis()
}

/// A variable as a thread or evidence names it: its function's entry
/// (given beside it), what it was made from, its place among those.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableData {
    /// Its function's entry.
    #[serde(with = "hex")]
    pub function: u64,
    /// What it was made from.
    pub origins: Vec<String>,
    /// Its place among the function's variables made from the same.
    #[serde(default)]
    pub ordinal: usize,
}

impl VariableData {
    fn of(variable: &Variable) -> Self {
        Self {
            function: variable.function,
            origins: variable.origins.clone(),
            ordinal: variable.ordinal,
        }
    }

    fn identity(&self) -> Variable {
        Variable {
            function: self.function,
            origins: self.origins.clone(),
            ordinal: self.ordinal,
        }
    }
}

/// What a thread is about (`Anchor`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnchorData {
    /// A function.
    Function {
        /// Its entry.
        #[serde(with = "hex")]
        address: u64,
    },
    /// An instruction.
    Instruction {
        /// Its address.
        #[serde(with = "hex")]
        address: u64,
    },
    /// A data item.
    Data {
        /// Its address.
        #[serde(with = "hex")]
        address: u64,
    },
    /// An address, as a client sends it without saying what is there:
    /// taken as an instruction if a recovered block holds it, else as a
    /// data item (never sent back).
    Address {
        /// The address.
        #[serde(with = "hex")]
        address: u64,
    },
    /// A line of a function's C, by its first instruction.
    Line {
        /// The function's entry.
        #[serde(with = "hex")]
        function: u64,
        /// The view.
        #[serde(default)]
        view: Viewed,
        /// The line's first instruction.
        #[serde(with = "hex")]
        address: u64,
    },
    /// A variable.
    Variable {
        /// The variable.
        variable: VariableData,
    },
    /// A type, by the key its definition defines.
    Type {
        /// The key (`struct pair`).
        key: String,
    },
    /// A suggestion.
    Suggestion {
        /// Its id.
        id: String,
    },
}

impl AnchorData {
    /// `anchor` as sent.
    pub fn of(anchor: &Anchor) -> Self {
        match anchor {
            Anchor::Function(address) => Self::Function { address: *address },
            Anchor::Instruction(address) => Self::Instruction { address: *address },
            Anchor::Data(address) => Self::Data { address: *address },
            Anchor::Line {
                function,
                reading,
                address,
            } => Self::Line {
                function: *function,
                view: viewed(*reading),
                address: *address,
            },
            Anchor::Variable(variable) => Self::Variable {
                variable: VariableData::of(variable),
            },
            Anchor::Type(key) => Self::Type { key: key.clone() },
            Anchor::Suggestion(id) => Self::Suggestion { id: id_text(*id) },
        }
    }

    /// The anchor it names in `session`.
    ///
    /// # Errors
    ///
    /// A suggestion's id that names none.
    pub fn anchor(&self, session: &Session) -> Result<Anchor, Fault> {
        Ok(match self {
            Self::Function { address } => Anchor::Function(*address),
            Self::Instruction { address } => Anchor::Instruction(*address),
            Self::Data { address } => Anchor::Data(*address),
            Self::Address { address } => {
                let code = session.database().is_some_and(|database| {
                    database.program().block_containing(*address).is_some()
                });
                if code {
                    Anchor::Instruction(*address)
                } else {
                    Anchor::Data(*address)
                }
            }
            Self::Line {
                function,
                view,
                address,
            } => Anchor::Line {
                function: *function,
                reading: *view == Viewed::Reading,
                address: *address,
            },
            Self::Variable { variable } => Anchor::Variable(variable.identity()),
            Self::Type { key } => Anchor::Type(key.clone()),
            Self::Suggestion { id } => Anchor::Suggestion(parse_id(id)?),
        })
    }
}

/// The view `reading` names.
const fn viewed(reading: bool) -> Viewed {
    if reading {
        Viewed::Reading
    } else {
        Viewed::Exact
    }
}

/// Someone mentioned (`Mention`): an identity (the server's if none), and
/// which of its scripts or agents (none: the person).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentionData {
    /// The identity key, hexadecimal; the server's if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The script or agent (`script:helper`, `agent`); none: the person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

impl MentionData {
    fn of(mention: &Mention) -> Self {
        Self {
            key: Some(mention.key.to_string()),
            agent: mention.agent.clone(),
        }
    }

    fn mention(&self, me: PublicKey) -> Result<Mention, Fault> {
        Ok(Mention {
            key: self
                .key
                .as_deref()
                .map(parse_key)
                .transpose()?
                .unwrap_or(me),
            agent: self.agent.clone(),
        })
    }
}

/// What an item of evidence cites, by what asks it again (`EvidenceRef`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceRefData {
    /// Lines (from 0) of a function's C.
    Lines {
        /// The function's entry.
        #[serde(with = "hex")]
        function: u64,
        /// The view.
        #[serde(default)]
        view: Viewed,
        /// The lines.
        lines: Vec<u32>,
    },
    /// A function's verification.
    Verification {
        /// The function's entry.
        #[serde(with = "hex")]
        function: u64,
        /// The view.
        #[serde(default)]
        view: Viewed,
    },
    /// Why a variable has its name and type.
    Why {
        /// The view.
        #[serde(default)]
        view: Viewed,
        /// The variable (its function's entry with it).
        variable: VariableData,
    },
    /// What refers to an address.
    XrefsTo {
        /// The address.
        #[serde(with = "hex")]
        to: u64,
    },
    /// The string at an address.
    String {
        /// The address.
        #[serde(with = "hex")]
        address: u64,
    },
    /// A call site.
    Call {
        /// The call instruction.
        #[serde(with = "hex")]
        site: u64,
    },
    /// Its author's words.
    Text {
        /// The words.
        text: String,
    },
}

impl EvidenceRefData {
    fn of(reference: &EvidenceRef) -> Self {
        match reference {
            EvidenceRef::Lines {
                function,
                reading,
                lines,
            } => Self::Lines {
                function: *function,
                view: viewed(*reading),
                lines: lines.clone(),
            },
            EvidenceRef::Verification { function, reading } => Self::Verification {
                function: *function,
                view: viewed(*reading),
            },
            EvidenceRef::Why {
                reading, variable, ..
            } => Self::Why {
                view: viewed(*reading),
                variable: VariableData::of(variable),
            },
            EvidenceRef::Xrefs { to } => Self::XrefsTo { to: *to },
            EvidenceRef::String { address } => Self::String { address: *address },
            EvidenceRef::Call { site } => Self::Call { site: *site },
            EvidenceRef::Text(text) => Self::Text { text: text.clone() },
        }
    }

    fn reference(&self) -> EvidenceRef {
        match self {
            Self::Lines {
                function,
                view,
                lines,
            } => EvidenceRef::Lines {
                function: *function,
                reading: *view == Viewed::Reading,
                lines: lines.clone(),
            },
            Self::Verification { function, view } => EvidenceRef::Verification {
                function: *function,
                reading: *view == Viewed::Reading,
            },
            Self::Why { view, variable } => EvidenceRef::Why {
                function: variable.function,
                reading: *view == Viewed::Reading,
                variable: variable.identity(),
            },
            Self::XrefsTo { to } => EvidenceRef::Xrefs { to: *to },
            Self::String { address } => EvidenceRef::String { address: *address },
            Self::Call { site } => EvidenceRef::Call { site: *site },
            Self::Text { text } => EvidenceRef::Text(text.clone()),
        }
    }
}

/// An item of evidence: what it cites, and what it said when quoted (none:
/// quoted by the server when the suggestion is made).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceData {
    /// What it cites.
    pub reference: EvidenceRefData,
    /// What it said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
}

/// `evidence` as sent.
fn evidence_data(evidence: &Evidence) -> Vec<EvidenceData> {
    evidence
        .items
        .iter()
        .map(|item| EvidenceData {
            reference: EvidenceRefData::of(&item.reference),
            quote: item.quote.clone(),
        })
        .collect()
}

/// The evidence `items` name.
fn evidence(items: &[EvidenceData]) -> Evidence {
    Evidence {
        items: items
            .iter()
            .map(|item| EvidenceItem {
                reference: item.reference.reference(),
                quote: item.quote.clone(),
            })
            .collect(),
    }
}

impl AuthorData {
    /// `author` as sent.
    pub fn of(author: &Author) -> Self {
        Self {
            key: author.key.to_string(),
            author: author.origin.to_string(),
        }
    }
}

/// Who deleted a post.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedData {
    /// Their identity key.
    pub key: String,
    /// As whom: `user`, `script:<name>`, `plugin:<id>`, `agent`, ...
    pub author: String,
    /// Whether an owner removed it ("removed by the owner").
    pub by_owner: bool,
}

/// A post (`Post`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostData {
    /// Its id.
    pub id: String,
    /// Its thread's.
    pub thread: String,
    /// The post it answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Who posted it.
    pub author: AuthorData,
    /// When (milliseconds since the Unix epoch).
    pub millis: u64,
    /// What it says now (empty once deleted).
    pub body: String,
    /// When its author last edited it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited: Option<u64>,
    /// Who deleted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<DeletedData>,
    /// Who it mentions.
    #[serde(default)]
    pub mentions: Vec<MentionData>,
    /// What it rests on.
    #[serde(default)]
    pub evidence: Vec<EvidenceData>,
}

impl PostData {
    /// `post` as sent.
    pub fn of(post: &Post) -> Self {
        Self {
            id: id_text(post.id),
            thread: id_text(post.thread),
            reply_to: post.reply_to.map(id_text),
            author: AuthorData::of(&post.author),
            millis: millis(post.time),
            body: post.body.clone(),
            edited: post.edited.map(millis),
            deleted: post.deleted.as_ref().map(|deleted| DeletedData {
                key: deleted.by.to_string(),
                author: deleted.origin.to_string(),
                by_owner: deleted.by_owner,
            }),
            mentions: post.mentions.iter().map(MentionData::of).collect(),
            evidence: post
                .evidence
                .as_ref()
                .map(evidence_data)
                .unwrap_or_default(),
        }
    }
}

/// A thread (`Thread`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadData {
    /// Its id.
    pub id: String,
    /// What it is about.
    pub anchor: AnchorData,
    /// The anchor's text when opened.
    pub quote: String,
    /// Who opened it.
    pub opened_by: AuthorData,
    /// When (milliseconds since the Unix epoch).
    pub millis: u64,
    /// Whether it is resolved.
    pub resolved: bool,
    /// Its posts, in order.
    pub posts: Vec<PostData>,
    /// The suggestions answering it, by id.
    pub suggestions: Vec<String>,
}

impl ThreadData {
    /// `thread` as sent.
    pub fn of(thread: &Thread) -> Self {
        Self {
            id: id_text(thread.id),
            anchor: AnchorData::of(&thread.anchor),
            quote: thread.quote.clone(),
            opened_by: AuthorData::of(&thread.opened_by),
            millis: millis(thread.time),
            resolved: thread.resolved,
            posts: thread.posts.iter().map(PostData::of).collect(),
            suggestions: thread.suggestions.iter().copied().map(id_text).collect(),
        }
    }
}

/// An edit a suggestion proposes, against its key now (`Proposal`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalData {
    /// What it changes (`function_name`, `comment`, `variable_name`,
    /// `type`…).
    pub kind: String,
    /// Its address, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex::option")]
    pub address: Option<u64>,
    /// The key, in full (as the log names it).
    pub key: String,
    /// The value proposed, as text (a name, a comment, a type's C).
    pub value: Option<String>,
    /// The value it holds now.
    pub now: Option<String>,
    /// Whether it changed since it was proposed.
    pub moved: bool,
}

/// What `key` changes, and its address.
fn kind_of(key: &Key) -> (&'static str, Option<u64>) {
    match key {
        Key::FunctionName(entry) => ("function_name", Some(*entry)),
        Key::GlobalName(address) => ("global_name", Some(*address)),
        Key::VariableName(variable) => ("variable_name", Some(variable.function)),
        Key::Slot(entry, _) => ("slot_name", Some(*entry)),
        Key::Comment(address) => ("comment", Some(*address)),
        Key::Bookmark(_, address) => ("bookmark", Some(*address)),
        Key::Number(address, _) => ("number_form", Some(*address)),
        Key::Type(_) => ("type", None),
        Key::Definition(_) => ("definition", None),
        Key::Item(address) => ("item", Some(*address)),
        Key::Bounds(entry) => ("bounds", Some(*entry)),
        Key::DebugFile => ("debug_file", None),
        Key::Thread(_) => ("thread", None),
        Key::Post(_) => ("post", None),
        Key::Suggestion(_) => ("suggestion", None),
        Key::Signature(entry) => ("signature", Some(*entry)),
    }
}

/// `value` as text: a name's, comment's, type's text; else as the log
/// has it.
fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::Text(text) => text.clone(),
        other @ (Value::Number(_)
        | Value::Item(_)
        | Value::Bounds(_)
        | Value::DebugFile(_)
        | Value::Thread(_)
        | Value::Post(_)
        | Value::Suggestion(_)
        | Value::Signature(_)) => other.is_some().then(|| format!("{other:?}")),
    }
}

impl ProposalData {
    fn of(proposal: &Proposal) -> Self {
        let (kind, address) = kind_of(&proposal.key);
        Self {
            kind: kind.to_owned(),
            address,
            key: format!("{:?}", proposal.key),
            value: value_text(&proposal.value),
            now: proposal.now.as_ref().and_then(value_text),
            moved: proposal.moved,
        }
    }
}

/// A suggestion (`Suggestion`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestionData {
    /// Its id.
    pub id: String,
    /// Who made it.
    pub author: AuthorData,
    /// When (milliseconds since the Unix epoch).
    pub millis: u64,
    /// What it does.
    pub label: String,
    /// Its edits, each against its key now.
    pub edits: Vec<ProposalData>,
    /// Why.
    pub rationale: String,
    /// What it rests on, as quoted.
    pub evidence: Vec<EvidenceData>,
    /// The thread it answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    /// The suggestion it is the next version of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// What became of it: `pending`, `accepted`, `dismissed`,
    /// `superseded`.
    pub state: String,
    /// The edits accepted (by number), if accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<u16>,
    /// Why it was dismissed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The suggestion superseding it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    /// Who decided that last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<AuthorData>,
}

impl SuggestionData {
    /// `suggestion` as sent.
    pub fn of(suggestion: &Suggestion) -> Self {
        let (state, accepted, reason, superseded_by) = match &suggestion.state {
            SuggestionState::Pending => ("pending", Vec::new(), None, None),
            SuggestionState::Accepted(chosen) => ("accepted", chosen.clone(), None, None),
            SuggestionState::Dismissed(why) => ("dismissed", Vec::new(), Some(why.clone()), None),
            SuggestionState::Superseded(by) => ("superseded", Vec::new(), None, Some(id_text(*by))),
        };
        Self {
            id: id_text(suggestion.id),
            author: AuthorData::of(&suggestion.author),
            millis: millis(suggestion.time),
            label: suggestion.label.clone(),
            edits: suggestion.edits.iter().map(ProposalData::of).collect(),
            rationale: suggestion.rationale.clone(),
            evidence: evidence_data(&suggestion.evidence),
            thread: suggestion.thread.map(id_text),
            supersedes: suggestion.supersedes.map(id_text),
            state: state.to_owned(),
            accepted,
            reason,
            superseded_by,
            decided_by: suggestion.decided_by.as_ref().map(AuthorData::of),
        }
    }
}

/// An item of evidence asked again (`Rechecked`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecheckedData {
    /// The item, as quoted.
    pub item: EvidenceData,
    /// What it says now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    /// Why it cannot be asked now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether it no longer says what was quoted.
    pub stale: bool,
}

impl RecheckedData {
    fn of(rechecked: &Rechecked) -> Self {
        Self {
            item: EvidenceData {
                reference: EvidenceRefData::of(&rechecked.item.reference),
                quote: rechecked.item.quote.clone(),
            },
            now: rechecked.now.as_ref().ok().cloned(),
            error: rechecked.now.as_ref().err().cloned(),
            stale: rechecked.stale,
        }
    }
}

/// `event.thread`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadNote {
    /// The threads with something new, by id.
    pub threads: Vec<String>,
    /// The suggestions made or decided, by id.
    pub suggestions: Vec<String>,
}

impl ThreadNote {
    /// `talked` as sent.
    pub fn of(talked: &Talked) -> Self {
        Self {
            threads: talked.threads.iter().copied().map(id_text).collect(),
            suggestions: talked.suggestions.iter().copied().map(id_text).collect(),
        }
    }
}

/// `event.mentioned`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentionedNote {
    /// The post's thread.
    pub thread: String,
    /// The post.
    pub post: String,
    /// Who posted it.
    pub by: AuthorData,
    /// Who it mentions.
    pub mention: MentionData,
    /// What it says.
    pub body: String,
}

impl MentionedNote {
    /// `mentioned` as sent.
    pub fn of(mentioned: &Mentioned) -> Self {
        Self {
            thread: id_text(mentioned.thread),
            post: id_text(mentioned.post),
            by: AuthorData::of(&mentioned.by),
            mention: MentionData::of(&mentioned.mention),
            body: mentioned.body.clone(),
        }
    }
}

/// An address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct At {
    /// The address.
    #[serde(with = "hex")]
    pub address: u64,
}

/// A function, by entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Of {
    /// Its entry.
    #[serde(with = "hex")]
    pub entry: u64,
}

/// A thread, post or suggestion, by id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ById {
    /// Its id.
    pub id: String,
}

/// What a post says.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Words {
    /// The body (Markdown).
    #[serde(default)]
    pub body: String,
    /// The post it answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Who it mentions.
    #[serde(default)]
    pub mentions: Vec<MentionData>,
    /// What it rests on (quoted by the server where not quoted).
    #[serde(default)]
    pub evidence: Vec<EvidenceData>,
}

/// `threads.create`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Create {
    /// What it is about.
    pub anchor: AnchorData,
    /// The anchor's text now.
    #[serde(default)]
    pub quote: String,
    /// Its first post, if its body is not empty.
    #[serde(flatten)]
    pub first: Words,
}

/// `threads.post`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostParams {
    /// The thread.
    pub thread: String,
    /// What it says.
    #[serde(flatten)]
    pub words: Words,
}

/// `threads.edit`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    /// The post.
    pub id: String,
    /// What it says now.
    pub body: String,
}

/// `threads.resolve`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolve {
    /// The thread.
    pub id: String,
    /// Resolved (else opened again).
    #[serde(default = "yes")]
    pub resolved: bool,
}

const fn yes() -> bool {
    true
}

/// `suggestions.list`'s parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSuggestions {
    /// Only those in this state (`pending`, `accepted`, `dismissed`,
    /// `superseded`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// `suggestions.make`'s parameters: the writes proposed (as
/// `edits.apply` states them), drafted into keys and values, nothing
/// written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Make {
    /// What it does.
    pub label: String,
    /// The writes proposed.
    pub edits: Vec<Write>,
    /// Why.
    #[serde(default)]
    pub rationale: String,
    /// What it rests on (quoted by the server where not quoted).
    #[serde(default)]
    pub evidence: Vec<EvidenceData>,
    /// The thread it answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
}

/// `suggestions.supersede`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Supersede {
    /// The suggestion superseded (one's own).
    pub id: String,
    /// The new version.
    #[serde(flatten)]
    pub make: Make,
}

/// `suggestions.accept`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accept {
    /// The suggestion.
    pub id: String,
    /// The edits accepted, by number; all if none.
    #[serde(default)]
    pub edits: Vec<usize>,
}

/// `suggestions.dismiss`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dismiss {
    /// The suggestion.
    pub id: String,
    /// Why.
    #[serde(default)]
    pub reason: String,
}

/// `params` read as `T`.
fn read<T: DeserializeOwned>(params: Json) -> Result<T, Fault> {
    serde_json::from_value(params)
        .map_err(|error| Fault::new(FaultKind::Protocol, format!("bad parameters: {error}")))
}

/// `value` as JSON.
fn json<T: Serialize>(value: &T) -> Result<Json, Fault> {
    serde_json::to_value(value).map_err(|error| Fault::new(FaultKind::Protocol, error.to_string()))
}

/// A session's refusal as a fault.
fn refused(error: &Error) -> Fault {
    Fault::session(error, None)
}

/// No such thread, post or suggestion.
fn none_such(what: &str) -> Fault {
    Fault::new(FaultKind::Conversation, format!("no such {what}"))
}

/// The answer to `method` (`threads.*`, `suggestions.*`) with `params`,
/// for `owner` (a connection, a thread in process) writing as `origin`.
///
/// # Errors
///
/// Bad parameters, no such method; the session refuses (as its fault).
pub fn answer(
    host: &Host,
    owner: Owner,
    origin: &Origin,
    by: Option<PublicKey>,
    method: &str,
    params: Json,
) -> Result<Json, Fault> {
    if method.starts_with("suggestions.") {
        return suggestions(host, owner, origin, by, method, params);
    }
    let session = host.session();
    let threads = |found: Vec<Thread>| json(&found.iter().map(ThreadData::of).collect::<Vec<_>>());
    match method {
        method::LIST => threads(session.threads()),
        method::AT => threads(session.threads_at(read::<At>(params)?.address)),
        method::OF => threads(session.threads_of(read::<Of>(params)?.entry)),
        method::GET => json(
            &session
                .thread(parse_id(&read::<ById>(params)?.id)?)
                .map(|t| ThreadData::of(&t)),
        ),
        method::CREATE => {
            let create: Create = read(params)?;
            let anchor = create.anchor.anchor(&session)?;
            let say = (!create.first.body.is_empty())
                .then(|| say(&session, create.first))
                .transpose()?;
            let id = host.converse(owner, origin, by, "Open thread", |session| {
                let id = session
                    .open_thread(anchor, &create.quote)
                    .map_err(|e| refused(&e))?;
                if let Some(say) = say {
                    session.post(id, say).map_err(|e| refused(&e))?;
                }
                Ok(id)
            })?;
            json(&host.session().thread(id).map(|t| ThreadData::of(&t)))
        }
        method::POST => {
            let post: PostParams = read(params)?;
            let thread = parse_id(&post.thread)?;
            let say = say(&session, post.words)?;
            let id = host.converse(owner, origin, by, "Post", |session| {
                session.post(thread, say).map_err(|e| refused(&e))
            })?;
            posted(host, id)
        }
        method::EDIT => {
            let edit: Edit = read(params)?;
            let id = parse_id(&edit.id)?;
            host.converse(owner, origin, by, "Edit post", |session| {
                session.edit_post(id, &edit.body).map_err(|e| refused(&e))
            })?;
            posted(host, id)
        }
        method::DELETE => {
            let id = parse_id(&read::<ById>(params)?.id)?;
            host.converse(owner, origin, by, "Delete post", |session| {
                session.delete_post(id).map_err(|e| refused(&e))
            })?;
            posted(host, id)
        }
        method::RESOLVE => {
            let resolve: Resolve = read(params)?;
            let id = parse_id(&resolve.id)?;
            host.converse(owner, origin, by, "Resolve thread", |session| {
                session
                    .resolve_thread(id, resolve.resolved)
                    .map_err(|e| refused(&e))
            })?;
            json(&host.session().thread(id).map(|t| ThreadData::of(&t)))
        }
        _ => Err(Fault::new(
            FaultKind::Protocol,
            format!("no method {method:?}"),
        )),
    }
}

/// Post `id` as sent.
fn posted(host: &Host, id: OpId) -> Result<Json, Fault> {
    let post = host
        .session()
        .post_of(id)
        .ok_or_else(|| none_such("post"))?;
    json(&PostData::of(&post))
}

/// What `words` say, mentions of none named the server's identity, the
/// evidence quoted where it is not.
fn say(session: &Session, words: Words) -> Result<Say, Fault> {
    let me = session.identity();
    let mut evidence = evidence(&words.evidence);
    session.quote_evidence(&mut evidence, Some(QUOTING));
    Ok(Say {
        body: words.body,
        reply_to: words.reply_to.as_deref().map(parse_id).transpose()?,
        mentions: words
            .mentions
            .iter()
            .map(|mention| mention.mention(me))
            .collect::<Result<_, _>>()?,
        evidence: (!evidence.items.is_empty()).then_some(evidence),
    })
}

/// The answer to `suggestions.*` method `method`.
fn suggestions(
    host: &Host,
    owner: Owner,
    origin: &Origin,
    by: Option<PublicKey>,
    method: &str,
    params: Json,
) -> Result<Json, Fault> {
    let session = host.session();
    match method {
        method::SUGGESTIONS => {
            let list: ListSuggestions = read(params)?;
            let found: Vec<SuggestionData> = session
                .suggestions()
                .iter()
                .map(SuggestionData::of)
                .filter(|data| list.state.as_ref().is_none_or(|state| *state == data.state))
                .collect();
            json(&found)
        }
        method::SUGGESTION => {
            let id = parse_id(&read::<ById>(params)?.id)?;
            json(&session.suggestion(id).map(|s| SuggestionData::of(&s)))
        }
        method::MAKE => {
            let make: Make = read(params)?;
            let suggesting = suggesting(host, owner, &session, make)?;
            let id = host.converse(owner, origin, by, "Suggest", |session| {
                session.suggest(suggesting).map_err(|e| refused(&e))
            })?;
            suggested(host, id)
        }
        method::SUPERSEDE => {
            let supersede: Supersede = read(params)?;
            let old = parse_id(&supersede.id)?;
            let suggesting = suggesting(host, owner, &session, supersede.make)?;
            let id = host.converse(owner, origin, by, "Supersede suggestion", |session| {
                session.supersede(old, suggesting).map_err(|e| refused(&e))
            })?;
            suggested(host, id)
        }
        method::ACCEPT => {
            let accept: Accept = read(params)?;
            let committed = host.accept(parse_id(&accept.id)?, &accept.edits)?;
            json(&CommitResult {
                entry: committed.entry,
                reanalysing: committed.reanalysing,
            })
        }
        method::DISMISS => {
            let dismiss: Dismiss = read(params)?;
            let id = parse_id(&dismiss.id)?;
            host.converse(owner, origin, by, "Dismiss suggestion", |session| {
                session
                    .dismiss(id, &dismiss.reason)
                    .map_err(|e| refused(&e))
            })?;
            suggested(host, id)
        }
        method::RECHECK => {
            let id = parse_id(&read::<ById>(params)?.id)?;
            let suggestion = session
                .suggestion(id)
                .ok_or_else(|| none_such("suggestion"))?;
            let rechecked: Vec<RecheckedData> = session
                .recheck(&suggestion.evidence, Some(QUOTING))
                .iter()
                .map(RecheckedData::of)
                .collect();
            json(&rechecked)
        }
        _ => Err(Fault::new(
            FaultKind::Protocol,
            format!("no method {method:?}"),
        )),
    }
}

/// Suggestion `id` as sent.
fn suggested(host: &Host, id: OpId) -> Result<Json, Fault> {
    let suggestion = host
        .session()
        .suggestion(id)
        .ok_or_else(|| none_such("suggestion"))?;
    json(&SuggestionData::of(&suggestion))
}

/// The suggestion `make` states: its writes drafted into keys and values
/// (none written), its evidence quoted where it is not.
fn suggesting(
    host: &Host,
    owner: Owner,
    session: &Session,
    make: Make,
) -> Result<Suggesting, Fault> {
    let (_, edits) = host.draft(owner, &make.edits)?;
    let mut evidence = evidence(&make.evidence);
    session.quote_evidence(&mut evidence, Some(QUOTING));
    Ok(Suggesting {
        label: make.label,
        edits,
        rationale: make.rationale,
        evidence,
        thread: make.thread.as_deref().map(parse_id).transpose()?,
    })
}
