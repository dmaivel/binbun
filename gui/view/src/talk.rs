//! Conversation as the window shows it, without the framework: threads
//! anchored to
//! addresses and their posts, mentions, suggestions under review, and the
//! history's lines.
//!
//! - **Marks** ([`listing_marks`], [`c_marks`]): the lines of the listing
//!   and of a function's C that a thread is about, found as the engine
//!   finds a thread's place (a C line by the first instruction it was made
//!   from), resolved ones apart.
//! - **Anchors** ([`anchor_shown`]): where a thread is now, as its title
//!   says it and a click goes there; a detached one by the quote kept.
//! - **Posts** ([`group_posts`]): consecutive posts of one author (5
//!   minutes apart at most) under one header, as the chat groups messages;
//!   a deleted one says by whom ([`PostText`]).
//! - **Mentions** ([`mention_at`], [`completions`], [`complete`],
//!   [`mentions_in`], [`mention_ranges`]): `@` and a name's start offer
//!   the participants, the one taken written in; the post (or a chat
//!   message) mentions those it names.
//! - **Unread** ([`ChatUnread`], [`ThreadsUnread`]): what this person has
//!   not seen, each surface its own dot: the chat's (the title bar's chat
//!   icon) messages that came while it was hidden and its mentions, cleared
//!   by showing the chat; the threads' (the status bar's threads button)
//!   new threads, replies in threads one is part of and mentions, cleared
//!   by showing the thread; the newest mention gone to first.
//! - **Suggestions** ([`edit_rows`], [`Chosen`], [`evidence_rows`],
//!   [`may_decide`]): each proposed edit against what its key holds now,
//!   which of them are chosen, what the suggestion rests on (stale items
//!   marked once asked again), and whether this person may accept.
//! - **History** ([`history_line`]): who made a change, and who suggested
//!   what they accepted.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use binbun_session::HistoryEntry;
use binbun_session::Rechecked;
use binbun_session::journal::{Key, OpId, Origin, PublicKey, Value};
use binbun_session::talk::{
    Anchor, Author, Evidence, EvidenceRef, Mention, Mentioned, Post, Suggestion, SuggestionState,
    Thread,
};
use binbun_session::{Located, View};

use crate::cdoc::CDocument;
use crate::collab::{Role, key_text, value_text};

/// How long apart two posts of one author may be and share a header.
const GROUPED_MS: u64 = 5 * 60 * 1000;

/// The most participants the `@` completion offers.
const OFFERED: usize = 8;

/// The threads about one line: how many, and whether every one of them
/// is resolved (the mark muted).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mark {
    /// The threads, in the order opened.
    pub threads: Vec<OpId>,
    /// Whether all of them are resolved.
    pub resolved: bool,
}

impl Mark {
    fn add(&mut self, thread: &Thread) {
        self.resolved = thread.resolved && (self.threads.is_empty() || self.resolved);
        self.threads.push(thread.id);
    }
}

/// The listing's marks: by address (a function's entry, an instruction's
/// or data item's, a C line's first instruction), each thread at the
/// address its anchor names.
pub fn listing_marks(threads: &[Thread]) -> BTreeMap<u64, Mark> {
    let mut marks: BTreeMap<u64, Mark> = BTreeMap::new();
    for thread in threads {
        if let Some(address) = thread.anchor.address() {
            marks.entry(address).or_default().add(thread);
        }
    }
    marks
}

/// The marks of `document`'s lines, by line: a thread on the function or
/// one of its variables on its signature's line
/// ([`CDocument::body_start`]), one on a C line, an instruction or data
/// where a bookmark there shows ([`CDocument::marked_lines`]; `inside`
/// says which addresses are the function's): on the first line printing
/// its address (as `Session::locate` finds it), the entry's on the
/// signature, one no line is made from (folded away) on the next
/// statement.
pub fn c_marks(
    threads: &[Thread],
    document: &CDocument,
    inside: impl Fn(u64) -> bool,
) -> BTreeMap<usize, Mark> {
    let addresses: BTreeMap<u64, OpId> = threads
        .iter()
        .filter_map(|thread| match &thread.anchor {
            Anchor::Line { address, .. } | Anchor::Instruction(address) | Anchor::Data(address) => {
                Some((*address, thread.id))
            }
            Anchor::Function(_) | Anchor::Variable(_) | Anchor::Type(_) | Anchor::Suggestion(_) => {
                None
            }
        })
        .collect();
    // Each address on the first line it shows on.
    let mut placed: BTreeMap<u64, usize> = BTreeMap::new();
    for (line, found) in document.marked_lines(&addresses, inside) {
        for (address, _) in found {
            placed.entry(address).or_insert(line);
        }
    }
    let mut marks: BTreeMap<usize, Mark> = BTreeMap::new();
    let body_start = std::cell::OnceCell::new();
    let signature = || *body_start.get_or_init(|| document.body_start());
    for thread in threads {
        let line = match &thread.anchor {
            Anchor::Function(entry) => (*entry == document.entry).then(signature),
            Anchor::Variable(variable) => (variable.function == document.entry).then(signature),
            Anchor::Line { address, .. } | Anchor::Instruction(address) | Anchor::Data(address) => {
                placed.get(address).copied()
            }
            Anchor::Type(_) | Anchor::Suggestion(_) => None,
        };
        if let Some(line) = line {
            marks.entry(line).or_default().add(thread);
        }
    }
    marks
}

/// Where a click on an anchor or an evidence item goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Goes {
    /// An address (the listing's cursor there, the C following).
    Address(u64),
    /// A line of a function's C.
    Line {
        /// The function's entry.
        function: u64,
        /// The view.
        view: View,
        /// The line, from 0.
        line: usize,
    },
}

/// A thread's anchor as its title shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorShown {
    /// What it says: the function, line or address; a detached thread's
    /// quote.
    pub text: String,
    /// Whether the thread is detached (its function gone).
    pub detached: bool,
    /// Where a click goes, if anywhere.
    pub goes: Option<Goes>,
}

/// `thread`'s anchor as shown, `located` where the engine finds it now;
/// `name` names an address (a function's entry by its name).
pub fn anchor_shown(
    thread: &Thread,
    located: &Located,
    name: &dyn Fn(u64) -> String,
) -> AnchorShown {
    let at = thread.anchor.address();
    let shown = |text: String, goes: Option<Goes>| AnchorShown {
        text,
        detached: false,
        goes,
    };
    match located {
        Located::Function(_) => {
            let entry = at.unwrap_or_default();
            shown(name(entry), Some(Goes::Address(entry)))
        }
        Located::Line { view, line, .. } => {
            let (entry, address) = match &thread.anchor {
                Anchor::Line {
                    function, address, ..
                } => (*function, *address),
                Anchor::Function(entry) => (*entry, *entry),
                Anchor::Instruction(address) | Anchor::Data(address) => (*address, *address),
                Anchor::Variable(variable) => (variable.function, variable.function),
                Anchor::Type(_) | Anchor::Suggestion(_) => (0, 0),
            };
            match line {
                Some(line) => shown(
                    format!("{} \u{b7} line {}", name(entry), line + 1),
                    Some(Goes::Line {
                        function: entry,
                        view: *view,
                        line: *line,
                    }),
                ),
                None => shown(
                    format!("{} \u{b7} {address:X}", name(entry)),
                    Some(Goes::Address(address)),
                ),
            }
        }
        Located::Address(address) => shown(
            format!("{} \u{b7} {address:X}", name(*address)),
            Some(Goes::Address(*address)),
        ),
        Located::Type(key) => shown(key.clone(), None),
        Located::Suggestion(_) => shown("A suggestion".to_owned(), None),
        Located::Detached => AnchorShown {
            text: thread.quote.clone(),
            detached: true,
            goes: None,
        },
    }
}

/// What a post shows: its body, or who deleted it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostText {
    /// What it says.
    Body(String),
    /// Its author deleted it.
    Deleted,
    /// An owner removed it (moderation).
    Removed,
}

impl PostText {
    /// `post`'s.
    pub fn of(post: &Post) -> Self {
        match &post.deleted {
            Some(deleted) if deleted.by_owner => Self::Removed,
            Some(_) => Self::Deleted,
            None => Self::Body(post.body.clone()),
        }
    }

    /// The text shown.
    pub fn shown(&self) -> &str {
        match self {
            Self::Body(body) => body,
            Self::Deleted => "deleted",
            Self::Removed => "removed by the owner",
        }
    }

    /// Whether it is gone (deleted or removed): shown muted, no actions.
    pub fn gone(&self) -> bool {
        !matches!(self, Self::Body(_))
    }
}

/// One post under its author's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostLine {
    /// The post.
    pub id: OpId,
    /// What it shows.
    pub text: PostText,
    /// Whether its author edited it.
    pub edited: bool,
    /// Whether this identity wrote it (as the person: editable).
    pub mine: bool,
    /// How many items of evidence it carries.
    pub evidence: usize,
}

/// Posts one after another by one author.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostGroup {
    /// Their author.
    pub author: PublicKey,
    /// Which of the author's scripts or agents, if one.
    pub agent: Option<String>,
    /// The first one's time (Unix milliseconds).
    pub time: u64,
    /// The posts, in order.
    pub posts: Vec<PostLine>,
}

/// `posts` grouped for showing: consecutive posts of one author (the
/// same person, or the same script or agent of theirs), 5 minutes apart
/// at most, under one header. `me` is this identity.
pub fn group_posts(posts: &[Post], me: PublicKey) -> Vec<PostGroup> {
    let mut groups: Vec<PostGroup> = Vec::new();
    let mut last = 0;
    for post in posts {
        let agent = post.author.agent();
        let time = post.time.millis();
        let line = PostLine {
            id: post.id,
            text: PostText::of(post),
            edited: post.edited.is_some() && post.deleted.is_none(),
            mine: post.author.key == me && agent.is_none(),
            evidence: post.evidence.as_ref().map_or(0, |e| e.items.len()),
        };
        let joins = groups.last().is_some_and(|group| {
            group.author == post.author.key
                && group.agent == agent
                && time.saturating_sub(last) <= GROUPED_MS
        });
        last = time;
        if joins && let Some(group) = groups.last_mut() {
            group.posts.push(line);
        } else {
            groups.push(PostGroup {
                author: post.author.key,
                agent,
                time,
                posts: vec![line],
            });
        }
    }
    groups
}

/// Someone a post can mention: a person, or one of their scripts or
/// agents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Participant {
    /// Their identity.
    pub key: PublicKey,
    /// Which of their scripts or agents (`agent`, `script:helper`); none:
    /// the person.
    pub agent: Option<String>,
    /// Their name.
    pub name: String,
}

impl Participant {
    /// What follows the `@` that mentions them: their name (an agent's as
    /// `Name/agent`), spaces as `_`.
    pub fn handle(&self) -> String {
        let name = self.name.split_whitespace().collect::<Vec<_>>().join("_");
        match &self.agent {
            Some(agent) => format!("{name}/{agent}"),
            None => name,
        }
    }

    /// The mention naming them.
    pub fn mention(&self) -> Mention {
        Mention {
            key: self.key,
            agent: self.agent.clone(),
        }
    }
}

/// Whether `c` may be part of a handle.
fn handle_char(c: char) -> bool {
    !c.is_whitespace() && !matches!(c, ',' | '.' | ';' | '!' | '?' | ')' | '(' | '"' | '\'')
}

/// The mention being typed before `cursor` (a byte offset in `text`):
/// the bytes from its `@` (at the start or after a space) to the cursor,
/// and what follows the `@` so far.
pub fn mention_at(text: &str, cursor: usize) -> Option<(Range<usize>, String)> {
    let before = text.get(..cursor)?;
    let at = before.rfind('@')?;
    let query = before.get(at + 1..)?;
    if !query.chars().all(handle_char) {
        return None;
    }
    let opens = before
        .get(..at)
        .is_some_and(|b| b.chars().next_back().is_none_or(char::is_whitespace));
    opens.then(|| (at..cursor, query.to_owned()))
}

/// The participants `query` (what follows an `@`) may mean: those whose
/// handle starts with it, then those holding it, case aside, in the order
/// given; [`OFFERED`] at most.
pub fn completions<'a>(people: &'a [Participant], query: &str) -> Vec<&'a Participant> {
    let query = query.to_lowercase();
    let handles: Vec<String> = people.iter().map(|p| p.handle().to_lowercase()).collect();
    let starting = people
        .iter()
        .zip(&handles)
        .filter(|(_, h)| h.starts_with(&query));
    let holding = people
        .iter()
        .zip(&handles)
        .filter(|(_, h)| !h.starts_with(&query) && h.contains(&query));
    starting
        .chain(holding)
        .map(|(p, _)| p)
        .take(OFFERED)
        .collect()
}

/// `text` with the mention being typed at `range` written as `who`'s
/// (`@handle` and a space), and the cursor after it (a byte offset).
pub fn complete(text: &str, range: Range<usize>, who: &Participant) -> (String, usize) {
    let inserted = format!("@{} ", who.handle());
    let mut out = String::with_capacity(text.len() + inserted.len());
    out.push_str(text.get(..range.start).unwrap_or(text));
    out.push_str(&inserted);
    let cursor = out.len();
    out.push_str(text.get(range.end..).unwrap_or_default());
    (out, cursor)
}

/// The participants `text` mentions (`@handle`, not inside a longer
/// handle), each once, in the order given.
pub fn mentions_in(text: &str, people: &[Participant]) -> Vec<Mention> {
    let mut out: Vec<Mention> = Vec::new();
    for person in people {
        let mention = person.mention();
        if !mention_ranges(text, &person.handle()).is_empty() && !out.contains(&mention) {
            out.push(mention);
        }
    }
    out
}

/// Where `text` mentions `handle`: each `@handle` at the start or after a
/// space, not inside a longer handle.
pub fn mention_ranges(text: &str, handle: &str) -> Vec<Range<usize>> {
    let needle = format!("@{handle}");
    text.match_indices(&needle)
        .map(|(at, _)| at..at + needle.len())
        .filter(|range| {
            let opens = text
                .get(..range.start)
                .is_some_and(|b| b.chars().next_back().is_none_or(char::is_whitespace));
            let closes = text
                .get(range.end..)
                .is_some_and(|a| a.chars().next().is_none_or(|c| !handle_char(c)));
            opens && closes
        })
        .collect()
}

/// A surface's notification dot (the title bar's chat icon, the status
/// bar's threads button).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dot {
    /// Something came not yet seen (the accent).
    Unread,
    /// Someone mentioned this person there (red).
    Mention,
}

/// What this person has not seen of the chat: messages that came while
/// it was not shown, and those mentioning them in the order they came;
/// the chat icon's dot says it ([`Self::dot`]) and a click goes to the
/// newest mention ([`Self::newest`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChatUnread {
    /// Messages not seen.
    messages: usize,
    /// The messages mentioning this person not seen, oldest first.
    mentions: Vec<u64>,
}

impl ChatUnread {
    /// Message `id` came, mentioning this person or not, while the chat
    /// was `shown` or not: unread unless it was shown.
    pub fn chat(&mut self, id: u64, mentions_me: bool, shown: bool) {
        if shown {
            return;
        }
        self.messages += 1;
        if mentions_me && !self.mentions.contains(&id) {
            self.mentions.push(id);
        }
    }

    /// The chat is shown: its messages and mentions seen.
    pub fn seen(&mut self) {
        self.messages = 0;
        self.mentions.clear();
    }

    /// Message `id` was removed (by the owner): not to go to.
    pub fn removed(&mut self, id: u64) {
        self.mentions.retain(|&m| m != id);
    }

    /// The chat icon's dot: red for a mention not seen, else the accent
    /// for messages not seen; none when all is seen.
    pub fn dot(&self) -> Option<Dot> {
        if !self.mentions.is_empty() {
            Some(Dot::Mention)
        } else if self.messages > 0 {
            Some(Dot::Unread)
        } else {
            None
        }
    }

    /// The newest message mentioning this person not seen: where a click
    /// on the chat icon goes.
    pub fn newest(&self) -> Option<u64> {
        self.mentions.last().copied()
    }
}

/// What this person has not seen of the threads: new threads, and new
/// replies (posts by others) in threads they are part of (opened or
/// posted in), and mentions of them, each in the order it came; seen once
/// the thread shows in the panel. The threads button's dot says it
/// ([`Self::dot`]) and a click goes to the newest ([`Self::newest`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadsUnread {
    /// Each thread's posts as last told, by thread; none until the
    /// threads were first taken (what was there then is not new).
    known: Option<BTreeMap<OpId, BTreeSet<OpId>>>,
    /// The threads new or with new replies not seen, oldest first.
    news: Vec<OpId>,
    /// The mentions not seen, by thread and post, oldest first.
    mentions: Vec<(OpId, OpId)>,
}

impl ThreadsUnread {
    /// Takes the threads as they are now, those in `talked` with something
    /// new (an `Event::Talked`; none for a reading again), as this person
    /// (`me`), the thread shown in the panel (`open`) seen.
    pub fn take(&mut self, threads: &[Thread], talked: &[OpId], me: PublicKey, open: Option<OpId>) {
        let primed = self.known.is_some();
        let known = self.known.get_or_insert_default();
        let here: BTreeSet<OpId> = threads.iter().map(|t| t.id).collect();
        known.retain(|id, _| here.contains(id));
        self.news.retain(|id| here.contains(id));
        self.mentions.retain(|(id, _)| here.contains(id));
        let mine = |author: &Author| author.key == me && author.agent().is_none();
        for thread in threads {
            let was = known.get(&thread.id);
            let told = primed && talked.contains(&thread.id);
            let new = told
                && match was {
                    None => !mine(&thread.opened_by),
                    Some(was) => {
                        let part =
                            mine(&thread.opened_by) || thread.posts.iter().any(|p| mine(&p.author));
                        part && thread
                            .posts
                            .iter()
                            .any(|p| !was.contains(&p.id) && !mine(&p.author))
                    }
                };
            if new {
                self.news.retain(|&id| id != thread.id);
                self.news.push(thread.id);
            }
            if told || was.is_none() {
                known.insert(thread.id, thread.posts.iter().map(|p| p.id).collect());
            }
        }
        if let Some(open) = open {
            self.seen(open);
        }
    }

    /// Takes `mentioned` (an `Event::Mentioned`): unread unless its thread
    /// is the one shown (`open`), or it mentions one of this identity's
    /// scripts or agents (theirs to answer). Whether it counts.
    pub fn mentioned(&mut self, mentioned: &Mentioned, open: Option<OpId>) -> bool {
        let at = (mentioned.thread, mentioned.post);
        if mentioned.mention.agent.is_some()
            || open == Some(mentioned.thread)
            || self.mentions.contains(&at)
        {
            return false;
        }
        self.mentions.push(at);
        true
    }

    /// Thread `thread` shows in the panel: what is new in it seen.
    pub fn seen(&mut self, thread: OpId) {
        self.news.retain(|&id| id != thread);
        self.mentions.retain(|&(id, _)| id != thread);
    }

    /// Whether `thread` has a mention not seen.
    pub fn has(&self, thread: OpId) -> bool {
        self.mentions.iter().any(|&(id, _)| id == thread)
    }

    /// The threads button's dot: red for a mention not seen, else the
    /// accent for a new thread or reply not seen; none when all is seen.
    pub fn dot(&self) -> Option<Dot> {
        if !self.mentions.is_empty() {
            Some(Dot::Mention)
        } else if !self.news.is_empty() {
            Some(Dot::Unread)
        } else {
            None
        }
    }

    /// Where a click on the threads button goes: the thread of the newest
    /// mention not seen, else the newest thread with news.
    pub fn newest(&self) -> Option<OpId> {
        self.mentions
            .last()
            .map(|&(id, _)| id)
            .or_else(|| self.news.last().copied())
    }
}

/// A proposed edit as its row shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditRow {
    /// Its number in the suggestion.
    pub n: usize,
    /// What it is about (`Function 1E720`).
    pub what: String,
    /// Where that is, if at an address.
    pub address: Option<u64>,
    /// What its key shows now (the engine's name where nobody named it);
    /// none once it shows the proposal (accepted).
    pub now: Option<String>,
    /// What it proposes.
    pub proposed: String,
    /// Whether the key changed since it was proposed, while the
    /// suggestion waits (once decided, its own acceptance moved it).
    pub moved: bool,
}

/// `value` as a card's row shows it: a text as itself; none for a value
/// that removes (the key's engine name shows instead).
fn row_value(value: &Value) -> Option<String> {
    match value {
        Value::Text(Some(text)) => Some(text.clone()),
        Value::Text(None)
        | Value::Number(None)
        | Value::Item(None)
        | Value::Bounds(None)
        | Value::DebugFile(None)
        | Value::Signature(None) => None,
        Value::Number(Some(_))
        | Value::Item(Some(_))
        | Value::Bounds(Some(_))
        | Value::DebugFile(Some(_))
        | Value::Signature(Some(_))
        | Value::Thread(_)
        | Value::Post(_)
        | Value::Suggestion(_) => Some(value_text(value)),
    }
}

/// `suggestion`'s edits as rows; `engine_name` names a key nobody named
/// (`v15`), if known.
pub fn edit_rows(
    suggestion: &Suggestion,
    engine_name: &dyn Fn(&Key) -> Option<String>,
) -> Vec<EditRow> {
    let pending = suggestion.state == SuggestionState::Pending;
    suggestion
        .edits
        .iter()
        .enumerate()
        .map(|(n, edit)| {
            let (what, address) = key_text(&edit.key);
            let proposed = row_value(&edit.value).unwrap_or_else(|| "(removed)".to_owned());
            let now = edit
                .now
                .as_ref()
                .and_then(row_value)
                .or_else(|| engine_name(&edit.key))
                .unwrap_or_else(|| "(none)".to_owned());
            EditRow {
                n,
                what,
                address,
                now: (now != proposed).then_some(now),
                proposed,
                moved: edit.moved && pending,
            }
        })
        .collect()
}

/// Which of a suggestion's edits are chosen to accept: all at first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Chosen {
    off: BTreeSet<usize>,
}

impl Chosen {
    /// Whether edit `n` is chosen.
    pub fn is_on(&self, n: usize) -> bool {
        !self.off.contains(&n)
    }

    /// Chooses edit `n`, or no longer.
    pub fn toggle(&mut self, n: usize) {
        if !self.off.remove(&n) {
            self.off.insert(n);
        }
    }

    /// The edits chosen of `len`, by number: what Accept Selected takes.
    pub fn chosen(&self, len: usize) -> Vec<usize> {
        (0..len).filter(|&n| self.is_on(n)).collect()
    }
}

/// Whether this person may accept or dismiss suggestions, in a session
/// as `role` (none: not in one, the project their own); else why not.
///
/// # Errors
///
/// A viewer, or a member of another kind, decides nothing.
pub fn may_decide(role: Option<Role>) -> Result<(), &'static str> {
    match role {
        None | Some(Role::Owner | Role::Editor) => Ok(()),
        Some(Role::Viewer) => Err("Viewers see suggestions but cannot accept or dismiss them"),
        Some(Role::Store | Role::Agent) => {
            Err("Only editors and the owner accept or dismiss suggestions")
        }
    }
}

/// What became of a suggestion, as its card says it; `by` names who
/// decided.
pub fn state_text(suggestion: &Suggestion, by: Option<&str>) -> Option<String> {
    let by = by.map(|by| format!(" by {by}")).unwrap_or_default();
    match &suggestion.state {
        SuggestionState::Pending => None,
        SuggestionState::Accepted(taken) => Some(format!(
            "Accepted{by}: {} of {}",
            taken.len(),
            suggestion.edits.len()
        )),
        SuggestionState::Dismissed(why) if why.is_empty() => Some(format!("Dismissed{by}")),
        SuggestionState::Dismissed(why) => Some(format!("Dismissed{by}: {why}")),
        SuggestionState::Superseded(_) => Some(format!("Superseded{by}")),
    }
}

/// An item of evidence as its row shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRow {
    /// What it is (`Lines 4–6 of push_stream`).
    pub what: String,
    /// What it said when quoted (none for its author's own words, which
    /// are [`Self::what`]).
    pub quote: Option<String>,
    /// Where a click goes.
    pub goes: Option<Goes>,
    /// Asked again: what it says now if it no longer says the quote (or
    /// why it cannot be asked); none: not asked yet, or the same.
    pub stale: Option<String>,
}

/// `evidence`'s items as rows, marked stale where `rechecked` (asked
/// again, in the same order) says so; `name` names an address.
pub fn evidence_rows(
    evidence: &Evidence,
    rechecked: Option<&[Rechecked]>,
    name: &dyn Fn(u64) -> String,
) -> Vec<EvidenceRow> {
    let view = |reading: bool| if reading { View::Reading } else { View::Exact };
    evidence
        .items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let (what, goes) = match &item.reference {
                EvidenceRef::Lines {
                    function,
                    reading,
                    lines,
                } => {
                    let first = lines.iter().min().copied().unwrap_or_default();
                    let last = lines.iter().max().copied().unwrap_or_default();
                    let which = if first == last {
                        format!("Line {}", first + 1)
                    } else {
                        format!("Lines {}\u{2013}{}", first + 1, last + 1)
                    };
                    (
                        format!("{which} of {}", name(*function)),
                        Some(Goes::Line {
                            function: *function,
                            view: view(*reading),
                            line: usize::try_from(first).unwrap_or_default(),
                        }),
                    )
                }
                EvidenceRef::Verification { function, .. } => (
                    format!("Verification of {}", name(*function)),
                    Some(Goes::Address(*function)),
                ),
                EvidenceRef::Why { function, .. } => (
                    format!("Why a variable of {} is as it is", name(*function)),
                    Some(Goes::Address(*function)),
                ),
                EvidenceRef::Xrefs { to } => (
                    format!("References to {}", name(*to)),
                    Some(Goes::Address(*to)),
                ),
                EvidenceRef::String { address } => (
                    format!("The string at {address:X}"),
                    Some(Goes::Address(*address)),
                ),
                EvidenceRef::Call { site } => {
                    (format!("The call at {site:X}"), Some(Goes::Address(*site)))
                }
                EvidenceRef::Text(text) => (text.clone(), None),
            };
            let stale = rechecked
                .and_then(|r| r.get(i))
                .filter(|r| r.stale)
                .map(|r| match &r.now {
                    Ok(now) => now.trim().to_owned(),
                    Err(why) => why.clone(),
                });
            EvidenceRow {
                what,
                // A text's quote is the text itself, shown once.
                quote: item
                    .quote
                    .as_ref()
                    .filter(|_| !matches!(item.reference, EvidenceRef::Text(_)))
                    .map(|q| q.trim().to_owned()),
                goes,
                stale,
            }
        })
        .collect()
}

/// A change as the history lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryLine {
    /// Who made it (a script's or agent's name after its person's).
    pub who: String,
    /// What it did: its label, or for an accepted suggestion "accepted
    /// Bob's suggestion: …".
    pub what: String,
}

/// `name`'s `origin` as the history says it: `Ann`, `Ann's script:x`; an
/// agent that signs its own changes (`own`) by its name alone: `Codex`.
fn as_whom(name: &str, origin: &Origin, own: bool) -> String {
    match origin {
        Origin::Agent if own => name.to_owned(),
        Origin::Script(_) | Origin::Plugin(_) | Origin::Agent | Origin::Signature(_) => {
            format!("{name}'s {origin}")
        }
        Origin::User
        | Origin::Import(_)
        | Origin::Undo(_)
        | Origin::Redo(_)
        | Origin::Accept(_) => name.to_owned(),
    }
}

/// `entry` as the history lists it, `name` naming identities, `agent`
/// telling an agent's own key (its changes are its own: `Codex`, not
/// "Ann's agent"; its label's `Codex: ` said once, as who).
pub fn history_line(
    entry: &HistoryEntry,
    name: &dyn Fn(PublicKey) -> String,
    agent: &dyn Fn(PublicKey) -> bool,
) -> HistoryLine {
    let who = as_whom(&name(entry.author), &entry.origin, agent(entry.author));
    match &entry.suggested_by {
        Some(by) => {
            let by = as_whom(&name(by.key), &by.origin, agent(by.key));
            let label = entry.label.strip_prefix("Accept: ").unwrap_or(&entry.label);
            HistoryLine {
                what: format!("accepted {by}'s suggestion: {label}"),
                who,
            }
        }
        None => HistoryLine {
            what: entry
                .label
                .strip_prefix(&who)
                .and_then(|rest| rest.strip_prefix(": "))
                .filter(|_| entry.origin == Origin::Agent)
                .unwrap_or(&entry.label)
                .to_owned(),
            who,
        },
    }
}

/// The text of `line` of a listing or C line kept as a thread's quote:
/// trimmed, at most the engine's quote length in characters.
pub fn quote_of(line: &str) -> String {
    line.trim()
        .chars()
        .take(binbun_session::talk::MAX_QUOTE)
        .collect()
}

#[cfg(test)]
mod tests {
    use binbun::cfg::FunctionId;
    use binbun_semantics::core::Id as _;
    use binbun_session::journal::{ChainId, ChangeId, Hlc};
    use binbun_session::talk::{Deleted, EvidenceItem, Proposal};

    use super::*;
    use crate::cdoc::tests::made;

    fn key(n: u8) -> PublicKey {
        PublicKey([n; 32])
    }

    fn op(seq: u64, index: u16) -> OpId {
        OpId {
            change: ChangeId {
                chain: ChainId([1; 16]),
                seq,
            },
            index,
        }
    }

    fn author(n: u8, origin: Origin) -> Author {
        Author {
            key: key(n),
            origin,
        }
    }

    fn post(seq: u64, who: u8, origin: Origin, minute: u64, body: &str) -> Post {
        Post {
            id: op(seq, 0),
            thread: op(1, 0),
            reply_to: None,
            author: author(who, origin),
            time: Hlc::new(minute * 60_000, 0),
            body: body.to_owned(),
            edited: None,
            deleted: None,
            mentions: Vec::new(),
            evidence: None,
        }
    }

    fn thread(anchor: Anchor, resolved: bool) -> Thread {
        Thread {
            id: op(u64::from(resolved) + 7, 0),
            anchor,
            quote: "if (fd < 0)".to_owned(),
            opened_by: author(1, Origin::User),
            time: Hlc::new(0, 0),
            resolved,
            resolved_by: None,
            posts: Vec::new(),
            suggestions: Vec::new(),
        }
    }

    /// A thread at an instruction no C line is made from (folded away)
    /// shows on the next statement, as a bookmark there does; one at the
    /// entry on the signature, none at another function's address or past
    /// the last statement.
    #[test]
    fn c_marks_fall_to_the_next_statement_for_folded_instructions() {
        let doc = made(
            View::Exact,
            &[
                ("int f(void)", &[]),
                ("{", &[]),
                ("    a = 1;", &[0x10]),
                ("    b = 2;", &[0x18, 0x1c]),
                ("    return b;", &[0x24]),
                ("}", &[]),
            ],
        );
        let at = |address: u64, n: u64| Thread {
            id: op(n, 0),
            ..thread(Anchor::Instruction(address), false)
        };
        let threads = [
            at(0x14, 1),
            at(0x1c, 2),
            at(0x10, 3),
            at(0x0, 4),
            at(0x8, 5),
            at(0x50, 6),
            Thread {
                id: op(7, 0),
                ..thread(Anchor::Function(0), true)
            },
        ];
        let inside = |a: u64| a < 0x40 && a != 0x8;
        let marks: Vec<(usize, Vec<u64>)> = c_marks(&threads, &doc, inside)
            .into_iter()
            .map(|(n, mark)| (n, mark.threads.iter().map(|id| id.change.seq).collect()))
            .collect();
        assert_eq!(
            marks,
            [(0, vec![4, 7]), (2, vec![3]), (3, vec![1, 2])],
            "by line, in the order opened"
        );
    }

    #[test]
    fn posts_group_by_author_and_agent_within_five_minutes_and_removals_say_so() {
        let mut removed = post(4, 2, Origin::User, 3, "rude");
        removed.deleted = Some(Deleted {
            by: key(1),
            origin: Origin::User,
            by_owner: true,
        });
        removed.body.clear();
        let mut deleted = post(5, 2, Origin::User, 4, "");
        deleted.deleted = Some(Deleted {
            by: key(2),
            origin: Origin::User,
            by_owner: false,
        });
        let mut edited = post(2, 1, Origin::User, 1, "second");
        edited.edited = Some(Hlc::new(90_000, 0));
        let posts = vec![
            post(1, 1, Origin::User, 0, "first"),
            edited,
            // The same identity's agent is someone else.
            post(3, 1, Origin::Agent, 2, "I checked the callers"),
            removed,
            deleted,
            // Past five minutes: a new header.
            post(6, 2, Origin::User, 10, "later"),
        ];
        let groups = group_posts(&posts, key(1));
        let shape: Vec<(u8, Option<&str>, usize)> = groups
            .iter()
            .map(|g| (g.author.0[0], g.agent.as_deref(), g.posts.len()))
            .collect();
        assert_eq!(
            shape,
            vec![
                (1, None, 2),
                (1, Some("agent"), 1),
                (2, None, 2),
                (2, None, 1)
            ]
        );
        let first = &groups[0];
        assert!(first.posts.iter().all(|p| p.mine));
        assert!(first.posts[1].edited && !first.posts[0].edited);
        // The agent's post is not the person's to edit.
        assert!(!groups[1].posts[0].mine);
        let gone = &groups[2].posts;
        assert_eq!(gone[0].text, PostText::Removed);
        assert_eq!(gone[0].text.shown(), "removed by the owner");
        assert_eq!(gone[1].text.shown(), "deleted");
        assert!(gone.iter().all(|p| p.text.gone() && !p.mine));
    }

    #[test]
    fn a_mention_is_offered_written_in_and_found_on_sending() {
        let people = vec![
            Participant {
                key: key(1),
                agent: None,
                name: "Ann Lee".to_owned(),
            },
            Participant {
                key: key(2),
                agent: None,
                name: "Bob".to_owned(),
            },
            Participant {
                key: key(2),
                agent: Some("agent".to_owned()),
                name: "Bob".to_owned(),
            },
            Participant {
                key: key(3),
                agent: None,
                name: "Abigail".to_owned(),
            },
        ];
        // Typing `@b` at the end: Bob first (starts), then his agent; an
        // `@` inside a word is no mention.
        let text = "why size_t here @b";
        let (range, query) = mention_at(text, text.len()).unwrap();
        assert_eq!((range.clone(), query.as_str()), (16..18, "b"));
        assert_eq!(mention_at("mail@bo", 7), None);
        assert_eq!(mention_at("@bob is", 7), None);
        let offered: Vec<String> = completions(&people, &query)
            .iter()
            .map(|p| p.handle())
            .collect();
        // Those starting with it, then Abigail, who holds a `b`.
        assert_eq!(offered, vec!["Bob", "Bob/agent", "Abigail"]);
        let (written, cursor) = complete(text, range, &people[2]);
        assert_eq!(written, "why size_t here @Bob/agent ");
        assert_eq!(cursor, written.len());
        // A name with a space takes `_`; `@Bob` inside `@Bob/agent` is not
        // Bob.
        let sent = "@Ann_Lee and @Bob/agent, see this; not @Bobby";
        assert_eq!(
            mentions_in(sent, &people),
            vec![people[0].mention(), people[2].mention()]
        );
    }

    #[test]
    fn chat_messages_and_mentions_are_unread_until_the_chat_shows() {
        let mut unread = ChatUnread::default();
        assert_eq!(unread.dot(), None);
        // A message while the chat is hidden: the accent dot; one while it
        // is shown is seen.
        unread.chat(1, false, true);
        assert_eq!(unread.dot(), None);
        unread.chat(2, false, false);
        assert_eq!((unread.dot(), unread.newest()), (Some(Dot::Unread), None));
        // Mentions: red, the newest gone to first.
        unread.chat(3, true, false);
        unread.chat(4, true, false);
        assert_eq!(
            (unread.dot(), unread.newest()),
            (Some(Dot::Mention), Some(4))
        );
        // One the owner removed is not gone to; the message stays unread.
        unread.removed(4);
        unread.removed(3);
        assert_eq!((unread.dot(), unread.newest()), (Some(Dot::Unread), None));
        unread.chat(5, true, false);
        unread.seen();
        assert_eq!((unread.dot(), unread.newest()), (None, None));
    }

    #[test]
    fn thread_news_and_mentions_are_unread_until_the_thread_shows() {
        let mention = |thread: OpId, post: u64, agent: Option<&str>| Mentioned {
            thread,
            post: op(post, 0),
            by: author(2, Origin::User),
            mention: Mention {
                key: key(1),
                agent: agent.map(str::to_owned),
            },
            body: "@Ann look".to_owned(),
        };
        // Ann is key 1; a thread `n` opened by `by` with posts by `posts`.
        let me = key(1);
        let at = |n: u64, by: u8, posts: &[(u64, u8)]| Thread {
            id: op(n, 0),
            opened_by: author(by, Origin::User),
            posts: posts
                .iter()
                .map(|&(seq, who)| post(seq, who, Origin::User, 0, ""))
                .collect(),
            ..thread(Anchor::Function(0), false)
        };
        let (a, b, c) = (op(1, 0), op(2, 0), op(3, 0));
        let mut unread = ThreadsUnread::default();
        // What is there when first taken is not new, even if told.
        unread.take(&[at(1, 2, &[(10, 2)])], &[a], me, None);
        assert_eq!((unread.dot(), unread.newest()), (None, None));
        // A reply in a thread Ann is not part of: nothing; one she
        // posted in, then a reply by Bob: the accent, gone to.
        unread.take(&[at(1, 2, &[(10, 2), (11, 3)])], &[a], me, None);
        assert_eq!(unread.dot(), None);
        unread.take(&[at(1, 2, &[(10, 2), (11, 3), (12, 1)])], &[a], me, None);
        assert_eq!(unread.dot(), None);
        let replied = at(1, 2, &[(10, 2), (11, 3), (12, 1), (13, 2)]);
        unread.take(std::slice::from_ref(&replied), &[a], me, None);
        assert_eq!(
            (unread.dot(), unread.newest()),
            (Some(Dot::Unread), Some(a))
        );
        // A new thread by another: the newest; one of her own is not news;
        // reading again (nothing told) learns of threads silently.
        let all = [replied, at(2, 3, &[(20, 3)]), at(3, 1, &[(30, 1)])];
        unread.take(&all, &[b, c], me, None);
        assert_eq!(unread.newest(), Some(b));
        let mut more = all.to_vec();
        more.push(at(4, 3, &[(40, 3)]));
        unread.take(&more, &[], me, None);
        assert_eq!(unread.newest(), Some(b));
        assert!(unread.mentioned(&mention(a, 10, None), None));
        assert!(unread.mentioned(&mention(a, 11, None), None));
        // Told twice, counted once; the agent's mention is not the dot's;
        // a mention in the thread shown is seen at once.
        assert!(!unread.mentioned(&mention(a, 11, None), None));
        assert!(!unread.mentioned(&mention(b, 12, Some("agent")), None));
        assert!(!unread.mentioned(&mention(b, 13, None), Some(b)));
        assert!(unread.has(a) && !unread.has(b));
        // The mention first, red, though b is newer news.
        assert_eq!(
            (unread.dot(), unread.newest()),
            (Some(Dot::Mention), Some(a))
        );
        // Thread a shown: its reply and mentions seen; b left (accent).
        unread.take(&all, &[], me, Some(a));
        assert!(!unread.has(a));
        assert_eq!(
            (unread.dot(), unread.newest()),
            (Some(Dot::Unread), Some(b))
        );
        // A reply in the thread shown is seen as it comes.
        let shown = at(1, 2, &[(10, 2), (11, 3), (12, 1), (13, 2), (14, 2)]);
        unread.take(&[shown, all[1].clone()], &[a], me, Some(a));
        assert_eq!(unread.newest(), Some(b));
        unread.seen(b);
        assert_eq!((unread.dot(), unread.newest()), (None, None));
    }

    fn suggestion() -> Suggestion {
        let name = |s: &str| Value::Text(Some(s.to_owned()));
        Suggestion {
            id: op(9, 0),
            author: author(2, Origin::Agent),
            time: Hlc::new(0, 0),
            label: "Name the stream helpers".to_owned(),
            edits: vec![
                Proposal {
                    key: Key::FunctionName(0x1e720),
                    value: name("push_stream"),
                    prev: Vec::new(),
                    now: None,
                    moved: false,
                },
                Proposal {
                    key: Key::Comment(0x1e730),
                    value: name("the stream's head"),
                    prev: Vec::new(),
                    now: Some(name("Ann's note")),
                    moved: true,
                },
                Proposal {
                    key: Key::GlobalName(0x40_0000),
                    value: name("g_streams"),
                    prev: Vec::new(),
                    now: None,
                    moved: false,
                },
            ],
            rationale: "Called with a stream each time".to_owned(),
            evidence: Evidence {
                items: vec![
                    EvidenceItem {
                        reference: EvidenceRef::Lines {
                            function: 0x1e720,
                            reading: true,
                            lines: vec![5, 3, 4],
                        },
                        quote: Some("s->next = p;\n".to_owned()),
                    },
                    EvidenceItem {
                        reference: EvidenceRef::Xrefs { to: 0x1e720 },
                        quote: Some("0x1e800 Call".to_owned()),
                    },
                    EvidenceItem {
                        reference: EvidenceRef::Text("Every caller passes a stream".to_owned()),
                        quote: None,
                    },
                ],
            },
            thread: None,
            supersedes: None,
            state: SuggestionState::Pending,
            decided_by: None,
        }
    }

    #[test]
    fn a_suggestions_rows_say_now_against_proposed_and_only_the_chosen_are_taken() {
        let s = suggestion();
        let engine =
            |key: &Key| matches!(key, Key::FunctionName(_)).then(|| "sub_1E720".to_owned());
        let rows = edit_rows(&s, &engine);
        let shown: Vec<(Option<&str>, &str, bool)> = rows
            .iter()
            .map(|r| (r.now.as_deref(), r.proposed.as_str(), r.moved))
            .collect();
        assert_eq!(
            shown,
            vec![
                (Some("sub_1E720"), "push_stream", false),
                (Some("Ann's note"), "the stream's head", true),
                (Some("(none)"), "g_streams", false),
            ]
        );
        // Accepted: the edit taken shows its value alone, nothing moved.
        let mut taken = s.clone();
        taken.state = SuggestionState::Accepted(vec![0]);
        taken.edits[0].now = Some(taken.edits[0].value.clone());
        taken.edits[0].moved = true;
        let rows_taken = edit_rows(&taken, &engine);
        assert_eq!(rows_taken[0].now, None);
        assert!(rows_taken.iter().all(|r| !r.moved));
        assert_eq!(rows[0].address, Some(0x1e720));
        let mut chosen = Chosen::default();
        assert_eq!(chosen.chosen(rows.len()), vec![0, 1, 2]);
        chosen.toggle(1);
        assert!(!chosen.is_on(1));
        assert_eq!(chosen.chosen(rows.len()), vec![0, 2]);
        chosen.toggle(0);
        chosen.toggle(2);
        // None chosen: nothing to accept (the engine would take all).
        assert_eq!(chosen.chosen(rows.len()), Vec::<usize>::new());
        chosen.toggle(1);
        assert_eq!(chosen.chosen(rows.len()), vec![1]);
        // Viewers see but do not decide; alone, the project is one's own.
        assert!(may_decide(None).is_ok());
        assert!(may_decide(Some(Role::Editor)).is_ok());
        assert!(may_decide(Some(Role::Viewer)).is_err());
        let mut accepted = s.clone();
        accepted.state = SuggestionState::Accepted(vec![0, 2]);
        assert_eq!(
            state_text(&accepted, Some("Ann")).as_deref(),
            Some("Accepted by Ann: 2 of 3")
        );
        assert_eq!(state_text(&s, None), None);
    }

    #[test]
    fn evidence_goes_where_it_cites_and_stale_items_say_what_they_say_now() {
        let s = suggestion();
        let name = |a: u64| format!("f_{a:X}");
        let fresh = evidence_rows(&s.evidence, None, &name);
        assert_eq!(fresh[0].what, "Lines 4\u{2013}6 of f_1E720");
        assert_eq!(
            fresh[0].goes,
            Some(Goes::Line {
                function: 0x1e720,
                view: View::Reading,
                line: 3
            })
        );
        assert_eq!(fresh[1].goes, Some(Goes::Address(0x1e720)));
        assert_eq!(fresh[2].goes, None);
        assert!(fresh.iter().all(|r| r.stale.is_none()));
        let rechecked: Vec<Rechecked> = s
            .evidence
            .items
            .iter()
            .zip([
                (Ok("s->next = q;\n".to_owned()), true),
                (Ok("0x1e800 Call".to_owned()), false),
                (Ok("Every caller passes a stream".to_owned()), false),
            ])
            .map(|(item, (now, stale))| Rechecked {
                item: item.clone(),
                now,
                stale,
            })
            .collect();
        let rows = evidence_rows(&s.evidence, Some(&rechecked), &name);
        assert_eq!(rows[0].stale.as_deref(), Some("s->next = q;"));
        assert_eq!(rows[0].quote.as_deref(), Some("s->next = p;"));
        assert_eq!(rows[1].stale, None);
    }

    #[test]
    fn a_thread_shows_where_it_is_or_its_quote_when_detached_and_marks_its_lines() {
        let name = |a: u64| format!("f_{a:X}");
        let line = thread(
            Anchor::Line {
                function: 0x100,
                reading: true,
                address: 0x108,
            },
            false,
        );
        let here = Located::Line {
            function: FunctionId::from_raw(3),
            view: View::Reading,
            line: Some(4),
        };
        let shown = anchor_shown(&line, &here, &name);
        assert_eq!(shown.text, "f_100 \u{b7} line 5");
        assert!(!shown.detached);
        assert_eq!(
            shown.goes,
            Some(Goes::Line {
                function: 0x100,
                view: View::Reading,
                line: 4
            })
        );
        let gone = anchor_shown(&line, &Located::Detached, &name);
        assert_eq!(
            gone,
            AnchorShown {
                text: "if (fd < 0)".to_owned(),
                detached: true,
                goes: None
            }
        );
        // The listing marks the line's instruction; resolved apart.
        let resolved = thread(Anchor::Instruction(0x108), true);
        let other = thread(Anchor::Data(0x2000), true);
        let marks = listing_marks(&[line, resolved.clone(), other]);
        assert_eq!(marks[&0x108].threads.len(), 2);
        assert!(!marks[&0x108].resolved);
        assert!(marks[&0x2000].resolved);
        let only = listing_marks(std::slice::from_ref(&resolved));
        assert!(only[&0x108].resolved);
    }

    #[test]
    fn history_says_who_accepted_whose_suggestion() {
        let name = |k: PublicKey| {
            match k.0[0] {
                1 => "Ann",
                3 => "Codex",
                _ => "Bob",
            }
            .to_owned()
        };
        // Key 3 is an agent's own (its install signs for it).
        let agent = |k: PublicKey| k == key(3);
        let by_whom =
            |author: PublicKey, origin: Origin, by: Option<Author>, label: &str| HistoryEntry {
                id: op(1, 0).change,
                author,
                origin,
                label: label.to_owned(),
                time: Hlc::new(0, 0),
                edits: 1,
                mine: true,
                suggested_by: by,
            };
        let entry =
            |origin: Origin, by: Option<Author>, label: &str| by_whom(key(1), origin, by, label);
        let accepted = entry(
            Origin::Accept(op(9, 0)),
            Some(author(2, Origin::Agent)),
            "Accept: Name the stream helpers",
        );
        assert_eq!(
            history_line(&accepted, &name, &agent),
            HistoryLine {
                who: "Ann".to_owned(),
                what: "accepted Bob's agent's suggestion: Name the stream helpers".to_owned(),
            }
        );
        let renamed = entry(Origin::Script("helper".to_owned()), None, "Rename");
        let line = history_line(&renamed, &name, &agent);
        assert_eq!(
            (line.who.as_str(), line.what.as_str()),
            ("Ann's script:helper", "Rename")
        );
        // An agent's own change is its own, by its name; so is its
        // suggestion accepted.
        let codex = by_whom(key(3), Origin::Agent, None, "Codex: Rename helpers of main");
        assert_eq!(
            history_line(&codex, &name, &agent),
            HistoryLine {
                who: "Codex".to_owned(),
                what: "Rename helpers of main".to_owned(),
            }
        );
        let taken = entry(
            Origin::Accept(op(9, 0)),
            Some(author(3, Origin::Agent)),
            "Accept: Name the stream helpers",
        );
        assert_eq!(
            history_line(&taken, &name, &agent).what,
            "accepted Codex's suggestion: Name the stream helpers"
        );
        assert_eq!(quote_of("   x = 1;   "), "x = 1;");
    }
}
