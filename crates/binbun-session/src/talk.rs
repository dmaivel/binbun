//! Conversation through a session:
//! threads anchored to addresses ([`Session::open_thread`]), posts
//! ([`Session::post`], edited by their author, deleted by their author
//! or an owner), and suggestions ([`Session::suggest`], superseded by
//! their author, accepted in whole or in part as one change by the person
//! accepting, [`Session::accept`]). They are kept in the journal
//! ([`crate::journal::talk`]) beside the edits, synced with them, and
//! told as [`Event::Thread`] and, to the identity a post mentions,
//! [`Event::Mentioned`].
//!
//! An anchor is an address, so it follows re-analysis as comments do:
//! [`Session::locate`] finds where it is now (a C line by the
//! instruction it was made from). Evidence is asked again against the
//! analysis now ([`Session::recheck`]), stale items marked.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use binbun::cfg::FunctionId;
use binbun::queries::verify::Verdict;

pub use crate::journal::talk::{
    Anchor, Author, Deleted, EditValue, Evidence, EvidenceItem, EvidenceRef, MAX_ITEMS, MAX_LABEL,
    MAX_QUOTE, MAX_TEXT, Mention, Mentioned, Post, Proposal, Proposed, Suggestion, SuggestionState,
    Talked, Thread,
};
use crate::journal::talk::{Opening, PostOp, Posting, Suggest, SuggestionOp, ThreadOp};
use crate::journal::{HistoryEntry, Journal, Key, OpId, Origin, PublicKey, Value};
use crate::worker::State;
use crate::{Answer, Edits, Error, Event, Question, Session, Variable, View};

/// A post to make ([`Session::post`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Say {
    /// What it says (Markdown).
    pub body: String,
    /// The post it answers, if any (of the same thread).
    pub reply_to: Option<OpId>,
    /// Who it mentions.
    pub mentions: Vec<Mention>,
    /// What it rests on.
    pub evidence: Option<Evidence>,
}

/// A suggestion to make ([`Session::suggest`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Suggesting {
    /// What it does, for people.
    pub label: String,
    /// The edits it proposes: keys and their values.
    pub edits: Vec<(Key, Value)>,
    /// Why.
    pub rationale: String,
    /// What it rests on.
    pub evidence: Evidence,
    /// The thread it answers, if any.
    pub thread: Option<OpId>,
}

/// Where an anchor is now ([`Session::locate`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Located {
    /// In this function.
    Function(FunctionId),
    /// On a line of a function's C (none: the function no longer prints
    /// the instruction).
    Line {
        /// The function.
        function: FunctionId,
        /// The view.
        view: View,
        /// The line, from 0.
        line: Option<usize>,
    },
    /// At this address.
    Address(u64),
    /// On this type.
    Type(String),
    /// On this suggestion.
    Suggestion(OpId),
    /// Nowhere now (its function is gone): shown with its quote among
    /// the detached threads.
    Detached,
}

/// An item of evidence asked again ([`Session::recheck`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rechecked {
    /// The item.
    pub item: EvidenceItem,
    /// What it says now, or why it cannot be asked.
    pub now: Result<String, String>,
    /// Whether it no longer says what was quoted.
    pub stale: bool,
}

/// `text`, refused if longer than `most` bytes.
fn bounded(what: &str, text: &str, most: usize) -> Result<(), Error> {
    if text.len() > most {
        return Err(Error::Conversation(format!(
            "{what} holds at most {most} bytes"
        )));
    }
    Ok(())
}

/// A conversation refusal.
fn refuse(why: impl Into<String>) -> Error {
    Error::Conversation(why.into())
}

/// The view `reading` names.
const fn view_of(reading: bool) -> View {
    if reading { View::Reading } else { View::Exact }
}

impl Session {
    /// This session's identity: the key signing its changes.
    pub fn identity(&self) -> PublicKey {
        self.shared.state().journal.author()
    }

    /// Writes conversation with `step` in the group open, else as a
    /// change of its own labelled `label` made by the user; what `step`
    /// returned.
    fn talk<T>(
        &self,
        label: &str,
        step: impl FnOnce(&mut Journal, &mut Edits) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (alone, written) = {
            let mut state = self.shared.state();
            let alone = !state.journal.in_group();
            if alone {
                state.journal.begin(label, Origin::User);
            }
            let State { journal, edits, .. } = &mut *state;
            let written = step(journal, edits);
            if written.is_err() && alone {
                journal.rollback(edits);
            }
            (alone, written)
        };
        let written = written?;
        if alone {
            self.commit()?;
        }
        Ok(written)
    }

    /// Tells what conversation the journal took since last told:
    /// [`Event::Thread`], then [`Event::Mentioned`] for each mention of
    /// this identity (or one it answers for).
    pub(crate) fn tell_talk(&self) {
        let talked = self.shared.state().journal.talked();
        let Some((talked, mentions)) = talked else {
            return;
        };
        self.shared.emit(&Event::Thread(Arc::new(talked)));
        for mention in mentions {
            self.shared.emit(&Event::Mentioned(Arc::new(mention)));
        }
    }

    /// Opens a thread on `anchor`, quoting its text now (`quote`, cut to
    /// [`MAX_QUOTE`] characters): in the group open, else as a change of
    /// its own. Its id.
    ///
    /// # Errors
    ///
    /// The suggestion it is anchored to is not known
    /// ([`Error::Conversation`]); the change cannot be made.
    pub fn open_thread(&self, anchor: Anchor, quote: &str) -> Result<OpId, Error> {
        if let Anchor::Suggestion(id) = anchor
            && self.suggestion(id).is_none()
        {
            return Err(refuse("no such suggestion"));
        }
        let quote: String = quote.chars().take(MAX_QUOTE).collect();
        self.talk("Open thread", |journal, edits| {
            let id = journal
                .next_talk()
                .ok_or_else(|| refuse("too many threads, posts and suggestions in one change"))?;
            let opening = Opening { anchor, quote };
            journal.write(
                &Key::Thread(id),
                Value::Thread(ThreadOp::Open(Box::new(opening))),
                edits,
            );
            Ok(id)
        })
    }

    /// Posts `say` in thread `thread`: in the group open, else as a
    /// change of its own. Its id.
    ///
    /// # Errors
    ///
    /// No such thread (or post it answers in it), a body or evidence too
    /// large ([`Error::Conversation`]); the change cannot be made.
    pub fn post(&self, thread: OpId, say: Say) -> Result<OpId, Error> {
        bounded("a post", &say.body, MAX_TEXT)?;
        if say.mentions.len() > MAX_ITEMS {
            return Err(refuse(format!("a post mentions at most {MAX_ITEMS}")));
        }
        self.talk("Post", |journal, edits| {
            if !journal.is_thread(thread) {
                return Err(refuse("no such thread"));
            }
            if let Some(answered) = say.reply_to
                && journal
                    .find_post(answered)
                    .is_none_or(|post| post.thread != thread)
            {
                return Err(refuse("the post answered is not in this thread"));
            }
            let id = journal
                .next_talk()
                .ok_or_else(|| refuse("too many threads, posts and suggestions in one change"))?;
            let posting = Posting {
                thread,
                reply_to: say.reply_to,
                body: say.body,
                mentions: say.mentions,
                evidence: say.evidence,
            };
            journal.write(
                &Key::Post(id),
                Value::Post(PostOp::New(Box::new(posting))),
                edits,
            );
            Ok(id)
        })
    }

    /// Edits post `post` to say `body`: its author's own only.
    ///
    /// # Errors
    ///
    /// No such post, another's, deleted, a body too large
    /// ([`Error::Conversation`]); the change cannot be made.
    pub fn edit_post(&self, post: OpId, body: &str) -> Result<(), Error> {
        bounded("a post", body, MAX_TEXT)?;
        self.talk("Edit post", |journal, edits| {
            let found = journal
                .find_post(post)
                .ok_or_else(|| refuse("no such post"))?;
            if found.author.key != journal.author() {
                return Err(refuse("only its author edits a post"));
            }
            if found.deleted.is_some() {
                return Err(refuse("the post is deleted"));
            }
            journal.write(
                &Key::Post(post),
                Value::Post(PostOp::Edit(body.to_owned())),
                edits,
            );
            Ok(())
        })
    }

    /// Deletes post `post`: its author, or an owner of the project
    /// (shown "removed by the owner"). Deleted, it stays deleted on every
    /// peer, whatever edit is concurrent with it.
    ///
    /// # Errors
    ///
    /// No such post, deleted already, another's and this identity no
    /// owner ([`Error::Conversation`]); the change cannot be made.
    pub fn delete_post(&self, post: OpId) -> Result<(), Error> {
        self.talk("Delete post", |journal, edits| {
            let found = journal
                .find_post(post)
                .ok_or_else(|| refuse("no such post"))?;
            let me = journal.author();
            if found.author.key != me && !journal.is_owner(me) {
                return Err(refuse("only its author or an owner deletes a post"));
            }
            if found.deleted.is_some() {
                return Err(refuse("the post is deleted already"));
            }
            journal.write(&Key::Post(post), Value::Post(PostOp::Delete), edits);
            Ok(())
        })
    }

    /// Resolves thread `thread` (`resolved`), or opens it again.
    ///
    /// # Errors
    ///
    /// No such thread ([`Error::Conversation`]); the change cannot be
    /// made.
    pub fn resolve_thread(&self, thread: OpId, resolved: bool) -> Result<(), Error> {
        let label = if resolved {
            "Resolve thread"
        } else {
            "Reopen thread"
        };
        self.talk(label, |journal, edits| {
            if !journal.is_thread(thread) {
                return Err(refuse("no such thread"));
            }
            journal.write(
                &Key::Thread(thread),
                Value::Thread(ThreadOp::Resolve(resolved)),
                edits,
            );
            Ok(())
        })
    }

    /// The suggestion `suggesting` as written: each edit with its key's
    /// leaves now, checked.
    fn suggestion_of(
        journal: &Journal,
        suggesting: Suggesting,
        supersedes: Option<OpId>,
    ) -> Result<Suggest, Error> {
        bounded("a label", &suggesting.label, MAX_LABEL)?;
        bounded("a rationale", &suggesting.rationale, MAX_TEXT)?;
        if suggesting.edits.is_empty() || suggesting.edits.len() > MAX_ITEMS {
            return Err(refuse(format!(
                "a suggestion proposes 1 to {MAX_ITEMS} edits"
            )));
        }
        let edits = suggesting
            .edits
            .into_iter()
            .map(|(key, value)| match EditValue::try_from(value) {
                Ok(value) if value.fits(&key) => {
                    let prev = journal.leaves_of(&key);
                    Ok(Proposed { key, value, prev })
                }
                Ok(_) | Err(_) => Err(refuse(format!("not an edit: {key:?}"))),
            })
            .collect::<Result<Vec<_>, Error>>()?;
        if suggesting
            .thread
            .is_some_and(|thread| !journal.is_thread(thread))
        {
            return Err(refuse("no such thread"));
        }
        Ok(Suggest {
            label: suggesting.label,
            edits,
            rationale: suggesting.rationale,
            evidence: suggesting.evidence,
            thread: suggesting.thread,
            supersedes,
        })
    }

    /// Suggests `suggesting`'s edits (nothing applied: a person reviews
    /// and accepts them, [`Self::accept`]): in the group open, else as a
    /// change of its own. Its id.
    ///
    /// # Errors
    ///
    /// No edit, one that is not an edit, the thread it answers unknown, a
    /// text too large ([`Error::Conversation`]); the change cannot be
    /// made.
    pub fn suggest(&self, suggesting: Suggesting) -> Result<OpId, Error> {
        self.talk("Suggest", |journal, edits| {
            let suggest = Self::suggestion_of(journal, suggesting, None)?;
            let id = journal
                .next_talk()
                .ok_or_else(|| refuse("too many threads, posts and suggestions in one change"))?;
            journal.write(
                &Key::Suggestion(id),
                Value::Suggestion(SuggestionOp::New(Box::new(suggest))),
                edits,
            );
            Ok(id)
        })
    }

    /// Supersedes suggestion `old` (this identity's) by a new version,
    /// `suggesting`: the new one made and the old one marked superseded by
    /// it, in one change. The new one's id.
    ///
    /// # Errors
    ///
    /// No such suggestion, another's, accepted or superseded already;
    /// what [`Self::suggest`] refuses ([`Error::Conversation`]).
    pub fn supersede(&self, old: OpId, suggesting: Suggesting) -> Result<OpId, Error> {
        self.talk("Supersede suggestion", |journal, edits| {
            let found = journal
                .find_suggestion(old)
                .ok_or_else(|| refuse("no such suggestion"))?;
            if found.author.key != journal.author() {
                return Err(refuse("only its author supersedes a suggestion"));
            }
            if matches!(
                found.state,
                SuggestionState::Accepted(_) | SuggestionState::Superseded(_)
            ) {
                return Err(refuse("the suggestion is accepted or superseded already"));
            }
            let suggest = Self::suggestion_of(journal, suggesting, Some(old))?;
            let id = journal
                .next_talk()
                .ok_or_else(|| refuse("too many threads, posts and suggestions in one change"))?;
            journal.write(
                &Key::Suggestion(id),
                Value::Suggestion(SuggestionOp::New(Box::new(suggest))),
                edits,
            );
            journal.write(
                &Key::Suggestion(old),
                Value::Suggestion(SuggestionOp::State(SuggestionState::Superseded(id))),
                edits,
            );
            Ok(id)
        })
    }

    /// Accepts suggestion `id`'s edits `chosen` (by their number; all if
    /// empty): one change authored by this identity
    /// ([`Origin::Accept`], one undo step: undone, the suggestion is
    /// pending again) making those edits and marking the suggestion
    /// accepted; the history shows who accepted it and who suggested it
    /// ([`HistoryEntry::suggested_by`]). The change made.
    ///
    /// # Errors
    ///
    /// A group is open ([`Error::Transaction`]); no such suggestion, not
    /// pending, an edit number it lacks ([`Error::Conversation`]); the
    /// change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    pub fn accept(&self, id: OpId, chosen: &[usize]) -> Result<Option<HistoryEntry>, Error> {
        if self.in_group() {
            return Err(Error::Transaction(
                "a group of edits is open: commit or roll it back first".to_owned(),
            ));
        }
        let suggestion = self
            .suggestion(id)
            .ok_or_else(|| refuse("no such suggestion"))?;
        if suggestion.state != SuggestionState::Pending {
            return Err(refuse("the suggestion is not pending"));
        }
        let all: Vec<usize> = (0..suggestion.edits.len()).collect();
        let chosen: BTreeSet<usize> = if chosen.is_empty() {
            all.into_iter().collect()
        } else {
            chosen.iter().copied().collect()
        };
        let mut numbers = Vec::with_capacity(chosen.len());
        let mut edits = Vec::with_capacity(chosen.len());
        for &n in &chosen {
            let edit = suggestion
                .edits
                .get(n)
                .ok_or_else(|| refuse(format!("the suggestion has no edit {n}")))?;
            numbers.push(u16::try_from(n).map_err(|_| refuse("too many edits"))?);
            edits.push((edit.key.clone(), edit.value.clone()));
        }
        let label = format!("Accept: {}", suggestion.label);
        self.begin(&label, Origin::Accept(id));
        for (key, value) in edits {
            let (change, retype) = self.effect(&key);
            self.write(&label, vec![(key, value)], change, retype)?;
        }
        {
            let mut state = self.shared.state();
            let State { journal, edits, .. } = &mut *state;
            journal.write(
                &Key::Suggestion(id),
                Value::Suggestion(SuggestionOp::State(SuggestionState::Accepted(numbers))),
                edits,
            );
        }
        self.commit()
    }

    /// Dismisses suggestion `id`, saying why.
    ///
    /// # Errors
    ///
    /// No such suggestion, not pending, a reason too long
    /// ([`Error::Conversation`]); the change cannot be made.
    pub fn dismiss(&self, id: OpId, reason: &str) -> Result<(), Error> {
        bounded("a reason", reason, MAX_TEXT)?;
        self.talk("Dismiss suggestion", |journal, edits| {
            let found = journal
                .find_suggestion(id)
                .ok_or_else(|| refuse("no such suggestion"))?;
            if found.state != SuggestionState::Pending {
                return Err(refuse("the suggestion is not pending"));
            }
            journal.write(
                &Key::Suggestion(id),
                Value::Suggestion(SuggestionOp::State(SuggestionState::Dismissed(
                    reason.to_owned(),
                ))),
                edits,
            );
            Ok(())
        })
    }

    /// Every thread, in the order opened, each with its posts.
    pub fn threads(&self) -> Vec<Thread> {
        self.shared.state().journal.threads()
    }

    /// Thread `id`, if made.
    pub fn thread(&self, id: OpId) -> Option<Thread> {
        self.shared.state().journal.find_thread(id)
    }

    /// Post `id`, if made.
    pub fn post_of(&self, id: OpId) -> Option<Post> {
        self.shared.state().journal.find_post(id)
    }

    /// The threads anchored at `address` (a function's entry, an
    /// instruction, a data item, a C line's first instruction).
    pub fn threads_at(&self, address: u64) -> Vec<Thread> {
        self.threads_in(address..address.saturating_add(1))
    }

    /// The threads anchored at an address of `range` (what a listing or
    /// a C document shows).
    pub fn threads_in(&self, range: Range<u64>) -> Vec<Thread> {
        self.threads()
            .into_iter()
            .filter(|thread| {
                thread
                    .anchor
                    .address()
                    .is_some_and(|address| range.contains(&address))
            })
            .collect()
    }

    /// The threads about the function at `entry`: anchored to it, a line
    /// or variable of it, or an instruction it holds.
    pub fn threads_of(&self, entry: u64) -> Vec<Thread> {
        let id = self
            .database()
            .and_then(|database| database.function_at(entry));
        self.threads()
            .into_iter()
            .filter(|thread| {
                thread.anchor.function() == Some(entry)
                    || matches!(
                        (&thread.anchor, id),
                        (Anchor::Instruction(address) | Anchor::Data(address), Some(id))
                            if self.holding(*address).contains(&id)
                    )
            })
            .collect()
    }

    /// Every suggestion, in the order made.
    pub fn suggestions(&self) -> Vec<Suggestion> {
        self.shared.state().journal.suggestions()
    }

    /// The suggestions waiting for review.
    pub fn pending_suggestions(&self) -> Vec<Suggestion> {
        self.suggestions()
            .into_iter()
            .filter(|suggestion| suggestion.state == SuggestionState::Pending)
            .collect()
    }

    /// Suggestion `id`, if made.
    pub fn suggestion(&self, id: OpId) -> Option<Suggestion> {
        self.shared.state().journal.find_suggestion(id)
    }

    /// The owners of the project (ever; `binbun-collab` says): who may
    /// delete anyone's post. Told as [`Event::Thread`] (every thread) if
    /// it changed.
    pub fn set_owners(&self, owners: impl IntoIterator<Item = PublicKey>) {
        let changed = self
            .shared
            .state()
            .journal
            .set_owners(owners.into_iter().collect());
        if changed {
            let threads = self.threads().into_iter().map(|thread| thread.id).collect();
            self.shared.emit(&Event::Thread(Arc::new(Talked {
                threads,
                suggestions: Vec::new(),
            })));
        }
    }

    /// Tells mentions of `key` here too ([`Event::Mentioned`]): a session
    /// following another process's whose identity it answers for (a
    /// script's in-process copy of a GUI's binary).
    pub fn answer_for(&self, key: PublicKey) {
        self.shared.state().journal.answer_for(key);
    }

    /// Where `anchor` is now: its function by entry (decompiled first, in
    /// the view a line names, to find the line printing its address).
    /// [`Located::Detached`] if the function it names is gone, or before
    /// the functions are recovered.
    pub fn locate(&self, anchor: &Anchor) -> Located {
        let function = |entry: u64| self.database().and_then(|d| d.function_at(entry));
        match anchor {
            Anchor::Function(entry) => {
                function(*entry).map_or(Located::Detached, Located::Function)
            }
            Anchor::Variable(variable) => {
                function(variable.function).map_or(Located::Detached, Located::Function)
            }
            Anchor::Line {
                function: entry,
                reading,
                address,
            } => {
                let Some(id) = function(*entry) else {
                    return Located::Detached;
                };
                let view = view_of(*reading);
                let line = self
                    .document_view(id, view)
                    .ok()
                    .and_then(|document| document.lines_of(*address).next());
                Located::Line {
                    function: id,
                    view,
                    line,
                }
            }
            Anchor::Instruction(address) | Anchor::Data(address) => {
                let held = self
                    .image()
                    .is_some_and(|image| image.segment(*address).is_some());
                if held {
                    Located::Address(*address)
                } else {
                    Located::Detached
                }
            }
            Anchor::Type(key) => Located::Type(key.clone()),
            Anchor::Suggestion(id) => {
                if self.suggestion(*id).is_some() {
                    Located::Suggestion(*id)
                } else {
                    Located::Detached
                }
            }
        }
    }

    /// The function at `entry`, decompiled in the view `reading` names.
    fn function_in(&self, entry: u64) -> Result<FunctionId, String> {
        self.database()
            .ok_or_else(|| "the functions are not recovered yet".to_owned())?
            .function_at(entry)
            .ok_or_else(|| format!("no function starts at {entry:#x}"))
    }

    /// What `reference` says now, waiting up to `timeout` for questions
    /// asked anew, never a kept answer (a verification can take a
    /// while): the text a quote holds.
    ///
    /// # Errors
    ///
    /// Why it cannot be answered: no such function, line or variable, it
    /// does not decompile, the time ran out.
    pub fn quote(
        &self,
        reference: &EvidenceRef,
        timeout: Option<Duration>,
    ) -> Result<String, String> {
        let asked = |entry: u64, reading: bool, question: Question| {
            let id = self.function_in(entry)?;
            let view = view_of(reading);
            self.answers.forget(id, view, &question);
            self.ask(id, view, question)
                .wait(timeout)
                .map_err(|why| format!("{why:?}"))
                .map(|answer| (id, answer))
        };
        match reference {
            EvidenceRef::Text(text) => Ok(text.clone()),
            EvidenceRef::Lines {
                function,
                reading,
                lines,
            } => {
                let id = self.function_in(*function)?;
                let document = self.document_view(id, view_of(*reading))?;
                let mut out = String::new();
                for &line in lines {
                    let n = usize::try_from(line).map_err(|e| e.to_string())?;
                    if n >= document.lines().len() {
                        return Err(format!("no line {line}"));
                    }
                    let _ = writeln!(out, "{}", document.line_text(n));
                }
                Ok(out)
            }
            EvidenceRef::Verification { function, reading } => {
                // On the architecture: evidence others read is no one's
                // processor setting.
                let (_, answer) = asked(*function, *reading, Question::Verify(None))?;
                let Answer::Verified(verification) = answer else {
                    return Err(format!("not a verification: {answer:?}"));
                };
                Ok(verdict(&verification.verdict))
            }
            EvidenceRef::Why {
                function,
                reading,
                variable,
            } => self.why(*function, *reading, variable, &asked),
            EvidenceRef::Xrefs { to } => {
                let database = self
                    .database()
                    .ok_or_else(|| "the functions are not recovered yet".to_owned())?;
                let mut out = String::new();
                for reference in database.references().to(*to) {
                    let _ = writeln!(out, "{:#x} {:?}", reference.from, reference.kind);
                }
                Ok(out)
            }
            EvidenceRef::String { address } => self
                .database()
                .ok_or_else(|| "the functions are not recovered yet".to_owned())?
                .strings(1)
                .into_iter()
                .find(|literal| literal.address == *address)
                .map(|literal| literal.text)
                .ok_or_else(|| format!("no string at {address:#x}")),
            EvidenceRef::Call { site } => self.call_line(*site, timeout),
        }
    }

    /// Why `variable` of the function at `entry` is as it is, as text.
    fn why(
        &self,
        entry: u64,
        reading: bool,
        variable: &Variable,
        asked: &dyn Fn(u64, bool, Question) -> Result<(FunctionId, Answer), String>,
    ) -> Result<String, String> {
        let view = view_of(reading);
        let id = self.function_in(entry)?;
        // Its variables are known once its document is.
        self.document_view(id, view)?;
        let (_, answer) = asked(entry, reading, Question::Explain)?;
        let Answer::Explained(explained) = answer else {
            return Err(format!("not an explanation: {answer:?}"));
        };
        let explanation = explained?;
        let item = explanation
            .items
            .iter()
            .find(|item| {
                item.var
                    .and_then(|var| self.variable(id, view, var).ok())
                    .is_some_and(|found| found == *variable)
            })
            .ok_or_else(|| "no such variable now".to_owned())?;
        let clues: Vec<&str> = item.clues.iter().map(|clue| clue.reason.as_str()).collect();
        Ok(format!(
            "{} {}: {:?} type, name {:?}; {}",
            item.ty,
            item.name,
            item.source,
            item.name_source,
            clues.join("; ")
        ))
    }

    /// The C line making the call at `site`, as its caller prints it.
    fn call_line(&self, site: u64, timeout: Option<Duration>) -> Result<String, String> {
        let callers = self.holding(site);
        let id = *callers
            .first()
            .ok_or_else(|| format!("no function holds {site:#x}"))?;
        let view = self.view;
        let answer = self
            .ask(id, view, Question::Callees)
            .wait(timeout)
            .map_err(|why| format!("{why:?}"))?;
        let Answer::Calls(calls) = answer else {
            return Err(format!("not call sites: {answer:?}"));
        };
        calls
            .iter()
            .find(|call| call.call.site == site)
            .map(|call| call.line.clone().unwrap_or_default())
            .ok_or_else(|| format!("no call at {site:#x}"))
    }

    /// `evidence` with each item not quoted yet quoted ([`Self::quote`]);
    /// an item that cannot be answered stays unquoted.
    pub fn quote_evidence(&self, evidence: &mut Evidence, timeout: Option<Duration>) {
        for item in &mut evidence.items {
            if item.quote.is_none() {
                item.quote = self.quote(&item.reference, timeout).ok();
            }
        }
    }

    /// Each item of `evidence` asked again against the analysis now: stale
    /// where it no longer says what was quoted.
    pub fn recheck(&self, evidence: &Evidence, timeout: Option<Duration>) -> Vec<Rechecked> {
        evidence
            .items
            .iter()
            .map(|item| {
                let now = self.quote(&item.reference, timeout);
                let stale = match (&item.quote, &now) {
                    (Some(quoted), Ok(now)) => quoted != now,
                    (Some(_), Err(_)) => true,
                    (None, _) => false,
                };
                Rechecked {
                    item: item.clone(),
                    now,
                    stale,
                }
            })
            .collect()
    }
}

/// A verification's verdict as text.
fn verdict(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Agreed(agreement) => format!(
            "agreed on {} of {} sampled states",
            agreement.agreed, agreement.states
        ),
        Verdict::Differs(difference) => format!("differs: {difference:?}"),
        Verdict::NotCheckable(why) => format!("not checkable: {why}"),
    }
}
