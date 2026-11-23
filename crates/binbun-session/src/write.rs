//! How a session writes its edits: through its journal ([`crate::journal`])
//! in groups ([`Session::begin`], [`Session::commit`],
//! [`Session::rollback`]; an edit made outside one is a group of its own),
//! each committed group one change, one undo step, one save and one
//! merged [`Event::Changed`]; undone and made again by compare-and-set
//! ([`Session::undo`], [`Session::redo`]), in order with this install's
//! private bookmarks' edits ([`Session::bookmark_private`]).

use std::slice;
use std::sync::Arc;

use binbun::cfg::FunctionId;
use binbun::decompile::View;

use crate::identity::Identity;
use crate::journal::{
    ChangeId, Committed, Conflict, HistoryEntry, Journal, Key, Origin, Plan, PublicKey, Undone,
    Value,
};
use crate::worker::{self, State};
use crate::{Change, Error, Event, Session, types};

/// What a group of edits changed so far: its edits' effects merged.
#[derive(Clone, Debug, Default)]
pub(crate) struct Group {
    /// The documents and listing lines changed.
    change: Change,
    /// Whether a type edit was made (the database took the user's types).
    retyped: bool,
}

impl Group {
    /// Adds an edit's effects: `change`'s documents and listing lines,
    /// whether it typed.
    pub(crate) fn add(&mut self, change: &Change, retyped: bool) {
        self.change.documents.extend(&change.documents);
        self.change.documents.sort_unstable();
        self.change.documents.dedup();
        self.change.listing.extend(change.listing.iter().cloned());
        self.change.listing = worker::merge(std::mem::take(&mut self.change.listing));
        self.retyped |= retyped;
    }

    /// What changed.
    pub(crate) fn change(&self) -> &Change {
        &self.change
    }

    /// Whether an edit typed.
    pub(crate) fn retyped(&self) -> bool {
        self.retyped
    }
}

/// Why a step that is a group of its own cannot be made: one is open.
pub(crate) fn group_open() -> Error {
    Error::Transaction("a group of edits is open: commit or roll it back first".to_owned())
}

/// The directory of agent `name`'s identity: its name in lower case, each
/// run of other characters than ASCII letters and digits one `-`
/// (`Claude Code`: `claude-code`); `agent` if nothing is left.
fn agent_dir(name: &str) -> String {
    let mut dir = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            dir.push(c.to_ascii_lowercase());
        } else if !dir.is_empty() && !dir.ends_with('-') {
            dir.push('-');
        }
    }
    let dir = dir.trim_end_matches('-');
    if dir.is_empty() {
        "agent".to_owned()
    } else {
        dir.to_owned()
    }
}

impl Session {
    /// Opens a group of edits labelled `label` (`Rename crypto helpers`),
    /// made by `origin` (the user, a script, a plugin): the edits made
    /// until it is committed apply at once (read and printed with them)
    /// and become one change, one undo step, one save of the project and
    /// one [`Event::Changed`] at [`Self::commit`]. A group opened inside
    /// one joins it (its label and origin dropped).
    pub fn begin(&self, label: &str, origin: Origin) {
        self.shared.state().journal.begin(label, origin);
    }

    /// Opens a group of edits as [`Self::begin`] made by agent `by` (one
    /// of [`Self::add_agent`]'s; `None`: this install): its change signed
    /// by the agent's key, on its chain, one step of this install's undo.
    pub fn begin_as(&self, label: &str, origin: Origin, by: Option<PublicKey>) {
        self.shared.state().journal.begin_as(label, origin, by);
    }

    /// Signs for the agent called `name` (`Codex`, `Claude Code`) from now
    /// on: an identity of its own, held by this install, kept beside this
    /// install's identity in `agents/<name>` (made at first use; an
    /// ephemeral session's made for it and kept nowhere), so that the
    /// same agent is the same participant in every project. Its key.
    ///
    /// # Errors
    ///
    /// Its identity cannot be read or made; no randomness.
    pub fn add_agent(&self, name: &str) -> Result<PublicKey, Error> {
        let identity = match self.shared.agents_dir() {
            Some(dir) => Identity::load_or_create(&dir.join(agent_dir(name))),
            None => Identity::ephemeral(),
        }
        .map_err(Error::Project)?;
        self.shared
            .state()
            .journal
            .add_agent(identity, name.trim())
            .map_err(Error::Project)
    }

    /// The agents this install signs for ([`Self::add_agent`]): each
    /// one's key and name.
    pub fn agents(&self) -> Vec<(PublicKey, String)> {
        self.shared.state().journal.agents()
    }

    /// The identity of agent `key` (one of [`Self::agents`]): what its
    /// card is made of when it joins a shared project.
    pub fn agent_identity(&self, key: PublicKey) -> Option<Identity> {
        self.shared.state().journal.agent_identity(key).cloned()
    }

    /// Whose key gave the function at `entry` the name it shows, if an
    /// edit did.
    pub fn name_writer(&self, entry: u64) -> Option<PublicKey> {
        self.shared
            .state()
            .journal
            .writer(&Key::FunctionName(entry))
    }

    /// Whether a group is open ([`Self::begin`]).
    pub fn in_group(&self) -> bool {
        self.shared.state().journal.in_group()
    }

    /// Commits the group open ([`Self::begin`]): the outermost makes its
    /// change (saved if autosaving), tells [`Event::Changed`] (every
    /// edit's documents and listing lines merged) and [`Event::History`]
    /// (and [`Event::Thread`], [`Event::Mentioned`] for conversation,
    /// [`Event::Bookmarks`] for another author's bookmark).
    /// The change made: none for an inner group, a group that wrote
    /// nothing, or none open.
    ///
    /// # Errors
    ///
    /// The change cannot be made (more than 65,535 edits in one): the
    /// group is dropped as by [`Self::rollback`]; the share does not take
    /// it, or a join is under way ([`Error::Refused`]): it is not written,
    /// nor shown.
    pub fn commit(&self) -> Result<Option<HistoryEntry>, Error> {
        let (entry, group, saved, others) = {
            let mut state = self.shared.state();
            let State { journal, edits, .. } = &mut *state;
            let committed = match journal.commit(edits) {
                Ok(committed) => committed,
                Err(error) => {
                    let refused = journal.refused_at_source();
                    let group = state.group.take().unwrap_or_default();
                    drop(state);
                    self.restored(&group);
                    return Err(if refused {
                        Error::Refused(error)
                    } else {
                        Error::Transaction(error)
                    });
                }
            };
            let records = match committed {
                Committed::Open => return Ok(None),
                Committed::Empty => {
                    state.group = None;
                    return Ok(None);
                }
                Committed::Sealed(records) => records,
            };
            let Some(entry) = state.journal.step_entry(&records) else {
                state.group = None;
                return Ok(None);
            };
            let group = state.group.take().unwrap_or_default();
            state.changes += 1;
            let keys = records
                .iter()
                .flat_map(|record| record.body.ops.iter().map(|op| &op.key));
            let others = state.journal.others_bookmark(keys);
            let saved = self.persist(&mut state);
            (entry, group, saved, others)
        };
        if let Some(Err(message)) = saved {
            self.shared.emit(&Event::Failed(message));
        }
        self.shared.emit(&Event::Changed(Arc::new(group.change)));
        self.shared
            .emit(&Event::History(Arc::from([entry.clone()].as_slice())));
        if others {
            self.shared.emit(&Event::Bookmarks);
        }
        self.tell_talk();
        Ok(Some(entry))
    }

    /// Drops the group open, its edits undone (as if never made: nothing
    /// enters the history, nothing is saved).
    pub fn rollback(&self) {
        let group = {
            let mut state = self.shared.state();
            let State { journal, edits, .. } = &mut *state;
            if journal.rollback(edits).is_empty() && state.group.is_none() {
                return;
            }
            state.group.take().unwrap_or_default()
        };
        self.restored(&group);
    }

    /// What `step` writes, as keys and values, without writing it: made in
    /// a group of its own beside the one open (if any) and dropped, the
    /// edits shown as before. What a suggestion proposes, from the writes
    /// a script states (`binbun-protocol`). What `step` returned, and the
    /// keys and values it wrote, in order.
    pub fn draft<R>(&self, step: impl FnOnce(&Self) -> R) -> (R, Vec<(Key, Value)>) {
        let (stashed, group) = {
            let mut state = self.shared.state();
            let group = state.group.take();
            (state.journal.stash(), group)
        };
        self.begin("Draft", Origin::User);
        let returned = step(self);
        let (ops, keys) = {
            let mut state = self.shared.state();
            let ops = state.journal.drafted();
            let State { journal, edits, .. } = &mut *state;
            let keys = journal.unstash(stashed, edits);
            state.group = group;
            (ops, keys)
        };
        self.effects(&keys);
        (returned, ops)
    }

    /// The edits of `group` undone: what printed them marked to print
    /// again, the user's types taken again if it typed.
    fn restored(&self, group: &Group) {
        {
            let mut state = self.shared.state();
            Self::touched(&mut state, &group.change);
        }
        if group.retyped {
            self.take_types(&group.change.documents);
        }
    }

    /// Saves the changes made (if autosaving and the project is known):
    /// what it came to.
    pub(crate) fn persist(&self, state: &mut State) -> Option<Result<(), String>> {
        if !state.autosave {
            return None;
        }
        let project = self.project()?;
        state.saves += 1;
        let State { journal, edits, .. } = state;
        Some(journal.save(edits, project))
    }

    /// The project files written so far (a test's count of saves).
    #[doc(hidden)]
    pub fn saves(&self) -> u64 {
        self.shared.state().saves
    }

    /// Marks what `change` changed: documents to print again, the overlay
    /// to lay again.
    pub(crate) fn touched(state: &mut State, change: &Change) {
        state.generation += 1;
        state.overlay = None;
        for &function in &change.documents {
            for view in [View::Exact, View::Reading] {
                let key = (function, worker::slot(view));
                if state.documents.contains_key(&key) {
                    state.stale.insert(key);
                }
            }
        }
    }

    /// Writes `ops` as one edit whose effects are `change` (the documents
    /// it reaches decompiled again if `retype`): into the group open, else
    /// as a change of its own labelled `label`, made by the user. What
    /// changed.
    ///
    /// # Errors
    ///
    /// A change of its own that cannot be made, or that the share does not
    /// take ([`Error::Refused`]): nothing of it is kept or shown.
    pub(crate) fn write(
        &self,
        label: &str,
        ops: Vec<(Key, Value)>,
        change: Change,
        retype: bool,
    ) -> Result<Arc<Change>, Error> {
        let change = Arc::new(change);
        let alone = {
            let mut state = self.shared.state();
            let alone = !state.journal.in_group();
            if alone {
                state.journal.begin(label, Origin::User);
            }
            let State { journal, edits, .. } = &mut *state;
            let keys: Vec<Key> = ops.iter().map(|(key, _)| key.clone()).collect();
            for (key, value) in ops {
                journal.write(&key, value, edits);
            }
            // An earlier report of an edit of the same key is dropped.
            self.shared
                .unresolved()
                .retain(|unresolved| !keys.contains(&journal.key_of(&unresolved.edit)));
            Self::touched(&mut state, &change);
            let group = state.group.get_or_insert_with(Group::default);
            group.add(&change, retype);
            alone
        };
        if retype {
            self.take_types(&change.documents);
        }
        if alone {
            self.commit()?;
        }
        Ok(change)
    }

    /// Has the database take the user's types as the edits hold them, the
    /// `documents` they reach decompiled again (a function decompiling
    /// now, with the old types, is decompiled again).
    pub(crate) fn take_types(&self, documents: &[FunctionId]) {
        let Some(database) = self.database() else {
            return;
        };
        let edits = self.shared.state().edits.clone();
        let (user, unresolved) = types::user_types(database, &edits);
        database.set_user(user);
        let mut state = self.shared.state();
        state.retyped += 1;
        for &function in documents {
            for view in [View::Exact, View::Reading] {
                state.decompiled.remove(&(function, worker::slot(view)));
            }
        }
        drop(state);
        self.shared.found_unresolved(unresolved);
    }

    /// What a new value of `key` changes, and whether the database takes
    /// the user's types again for it.
    pub(crate) fn effect(&self, key: &Key) -> (Change, bool) {
        let line = |address: u64| {
            let line = address..address.saturating_add(1);
            vec![line]
        };
        let function = |entry: u64| {
            self.database()
                .and_then(|database| database.function_at(entry))
        };
        match key {
            Key::FunctionName(address) | Key::GlobalName(address) => {
                (self.printing(*address), false)
            }
            Key::VariableName(variable) => {
                let at = function(variable.function);
                let listing = match at {
                    Some(at) if variable.slot().is_some() => self.code(at),
                    Some(_) | None => Vec::new(),
                };
                let documents = at.into_iter().collect();
                (Change { documents, listing }, false)
            }
            Key::Slot(entry, _) => {
                let listing = function(*entry).map(|at| self.code(at)).unwrap_or_default();
                (
                    Change {
                        documents: Vec::new(),
                        listing,
                    },
                    false,
                )
            }
            Key::Comment(address) | Key::Number(address, _) => (
                Change {
                    documents: self.holding(*address),
                    listing: line(*address),
                },
                false,
            ),
            Key::Bookmark(_, address) => (
                Change {
                    documents: Vec::new(),
                    listing: line(*address),
                },
                false,
            ),
            Key::Type(typed) => (self.reached(slice::from_ref(typed)), true),
            Key::Definition(_) => (self.redefined(), true),
            Key::Item(_)
            | Key::Bounds(_)
            | Key::DebugFile
            | Key::Thread(_)
            | Key::Post(_)
            | Key::Suggestion(_)
            | Key::Signature(_) => (Change::default(), false),
        }
    }

    /// Whether there is a step of this author's to undo: a change, or a
    /// private bookmark's edit.
    pub fn can_undo(&self) -> bool {
        self.shared.state().journal.can_undo()
    }

    /// Whether there is an undone step to make again.
    pub fn can_redo(&self) -> bool {
        self.shared.state().journal.can_redo()
    }

    /// The change the next [`Self::undo`] undoes, if it is one (not a
    /// private bookmark's edit alone): its label and author say what
    /// Undo will do (`Undo Codex: Rename helpers of main`).
    pub fn next_undo(&self) -> Option<HistoryEntry> {
        self.shared.state().journal.next_undo()
    }

    /// Undoes this author's last step not undone (never another's): a
    /// change, as a change of its own (`Undo: …`): each key it wrote gets
    /// its value before it back, where the key is still as the change left
    /// it; a key changed since by someone else is skipped and reported. A
    /// private bookmark's edit ([`Self::bookmark_private`]) is undone
    /// locally (no change: [`Undone::target`] none), and a bookmark moved
    /// between shared and private moves back ([`Self::set_bookmark_private`]),
    /// each told as [`Event::Bookmarks`]. What it did; `None` if nothing
    /// is left to undo. A correction undone is not recovered with here
    /// ([`Self::recovered_as_corrected`]).
    ///
    /// # Errors
    ///
    /// A group is open ([`Error::Transaction`]).
    pub fn undo(&self) -> Result<Option<Undone>, Error> {
        if let Some(undone) = self.step_private(Journal::undo_private)? {
            return Ok(Some(undone));
        }
        self.planned(Journal::plan_undo)
    }

    /// Makes the last step undone again (a change by compare-and-set, as
    /// [`Self::undo`]); `None` if none is undone.
    ///
    /// # Errors
    ///
    /// A group is open ([`Error::Transaction`]).
    pub fn redo(&self) -> Result<Option<Undone>, Error> {
        if let Some(undone) = self.step_private(Journal::redo_private)? {
            return Ok(Some(undone));
        }
        self.planned(Journal::plan_redo)
    }

    /// Writes the step `plan` makes of the journal, planned again while a
    /// freeze marked between its planning and its commit refuses it (one
    /// may have withdrawn a value it restores).
    fn planned(
        &self,
        plan: impl Fn(&mut Journal) -> Option<Plan>,
    ) -> Result<Option<Undone>, Error> {
        loop {
            let Some(planned) = self.plan(&plan)? else {
                return Ok(None);
            };
            let freezes = planned.freezes;
            match self.replay(planned) {
                Err(_) if self.shared.state().journal.freezes() != freezes => {}
                made => return made.map(Some),
            }
        }
    }

    /// The plan `plan` makes of the journal, outside a group.
    fn plan(&self, plan: impl FnOnce(&mut Journal) -> Option<Plan>) -> Result<Option<Plan>, Error> {
        let mut state = self.shared.state();
        if state.journal.in_group() {
            return Err(group_open());
        }
        Ok(plan(&mut state.journal))
    }

    /// Writes `plan` as one change, with its private bookmark's edit.
    fn replay(&self, plan: Plan) -> Result<Undone, Error> {
        let Plan {
            target,
            origin,
            label,
            ops,
            skipped,
            private,
            freezes,
        } = plan;
        let effects: Vec<(Key, Value, Change, bool)> = ops
            .into_iter()
            .map(|(key, value)| {
                let (change, retype) = self.effect(&key);
                (key, value, change, retype)
            })
            .collect();
        let change = self.with_private(private.as_ref(), || {
            self.shared
                .state()
                .journal
                .begin_planned(&label, origin, freezes);
            for (key, value, change, retype) in effects {
                self.write(&label, vec![(key, value)], change, retype)?;
            }
            self.commit()
        })?;
        let label = self
            .shared
            .state()
            .journal
            .label(target)
            .unwrap_or_default();
        Ok(Undone {
            target: Some(target),
            label,
            change,
            skipped,
        })
    }

    /// The changes, newest first: every author's.
    pub fn history(&self) -> Vec<HistoryEntry> {
        self.shared.state().journal.history()
    }

    /// The edits change `id` made (one of [`Self::history`]): each key,
    /// the value it gave, and the value the key showed before for its
    /// author (a tombstone: none of the user's, the engine's own); none if
    /// no such change is known. What a front end says of a peer's change
    /// ("Bob renamed v15 → fd").
    pub fn edits_of(&self, id: ChangeId) -> Vec<(Key, Value, Value)> {
        self.shared.state().journal.edits_of(id)
    }

    /// The keys concurrent edits left with more than one value, each with
    /// its values (the one shown and the others).
    pub fn conflicts(&self) -> Vec<Conflict> {
        self.shared.state().journal.conflicts()
    }
}
