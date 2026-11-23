//! A binary's sessions ([`Lineage`]) as clients write to them ([`Host`]):
//! transactions owned by one client (a Python thread in process, a
//! connection over the socket), each one undo step authored by its
//! client, rolled back whole; writes made outside one, each a step of its
//! own; undo and redo; corrections of recovery analysed anew once a
//! transaction commits, and the new analysis swapped in where writes
//! cannot overlap the swap.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use binbun_session::journal::{Key, OpId, Origin, PublicKey, Value};
use binbun_session::{Lineage, Session, Stage, Swapped, Waited};

use crate::fault::{Fault, FaultKind};
use crate::types::HistoryItem;
use crate::write::{Applied, Write};

/// Who writes: a thread of a process, a connection of a server.
pub type Owner = u64;

/// The GUI's user, as an owner: never a script's thread or a connection.
pub const USER: Owner = 0;

/// How often [`Host::settle`] looks whether the lineage's holder swapped
/// the new analysis in.
const SWAP_POLL: Duration = Duration::from_millis(20);

/// The transaction open, and whose it is.
#[derive(Clone, Copy, Debug)]
struct Group {
    /// Its client.
    owner: Owner,
    /// How many transactions deep (an inner one joins the outer).
    depth: u32,
    /// Rolled back by an inner transaction: nothing more is written in
    /// it, and committing it is refused.
    doomed: bool,
}

/// What [`Host::draft`] drafted: what each write did, in order, and the
/// keys and values they would write.
pub type Drafted = (Vec<Applied>, Vec<(Key, Value)>);

/// What committing a transaction did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    /// The change it made, outermost only (none for an inner
    /// transaction, or one that wrote nothing).
    pub entry: Option<HistoryItem>,
    /// Whether the binary is being analysed anew (its corrections):
    /// [`Host::settle`] waits for the swap.
    pub reanalysing: bool,
}

/// A binary's sessions as clients write to them.
#[derive(Debug)]
pub struct Host {
    lineage: Arc<Lineage>,
    /// The transaction open. Held while writing and while swapping in a
    /// new analysis, so that the two never overlap.
    group: Mutex<Option<Group>>,
    /// Whether reading swaps in a new analysis once ready (in process);
    /// else whoever holds the lineage swaps (the GUI, on its own thread).
    swaps: bool,
}

impl Host {
    /// `lineage`, written through this host; a new analysis swapped in on
    /// the next read once ready if `swaps`.
    pub fn new(lineage: Arc<Lineage>, swaps: bool) -> Self {
        Self {
            lineage,
            group: Mutex::new(None),
            swaps,
        }
    }

    /// The lineage.
    pub fn lineage(&self) -> &Arc<Lineage> {
        &self.lineage
    }

    fn group(&self) -> MutexGuard<'_, Option<Group>> {
        self.group.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The session in use; with `swaps`, a new analysis whose functions
    /// are recovered swapped in first.
    pub fn session(&self) -> Arc<Session> {
        if self.swaps && self.lineage.reanalysing() {
            let _held = self.group();
            self.lineage.swap();
        }
        self.lineage.session()
    }

    /// Whose transaction is open, if one is.
    pub fn holder(&self) -> Option<Owner> {
        self.group().map(|group| group.owner)
    }

    /// Runs `edit` (the GUI user's edits, made on the session as the GUI
    /// makes them) unless a client's transaction is open: no client's
    /// transaction opens while it runs.
    ///
    /// # Errors
    ///
    /// A client's transaction is open ([`FaultKind::Transaction`]).
    pub fn exclusive<R>(&self, edit: impl FnOnce() -> R) -> Result<R, Fault> {
        let group = self.group();
        if group.is_some() {
            return Err(Fault::new(
                FaultKind::Transaction,
                "a script's transaction is open: edits wait until it is committed or rolled back",
            ));
        }
        let done = edit();
        drop(group);
        Ok(done)
    }

    /// Swaps in the new analysis once its functions are recovered
    /// ([`Lineage::swap`]), never while a write is being made: for
    /// whoever holds the lineage when this host does not swap (the GUI).
    pub fn swap(&self) -> Option<Swapped> {
        let _held = self.group();
        self.lineage.swap()
    }

    /// Opens a transaction of `owner` labelled `label`, made by `origin`
    /// (signed by agent `by`, one the session signs for, if given); one of
    /// its own open already: this one joins it (its label and origin
    /// dropped).
    ///
    /// # Errors
    ///
    /// Another's transaction is open ([`FaultKind::Transaction`]).
    pub fn begin(
        &self,
        owner: Owner,
        label: &str,
        origin: Origin,
        by: Option<PublicKey>,
    ) -> Result<(), Fault> {
        let mut group = self.group();
        match &mut *group {
            Some(open) if open.owner == owner => open.depth += 1,
            Some(_) => return Err(held_by_another()),
            None => {
                self.lineage.session().begin_as(label, origin, by);
                *group = Some(Group {
                    owner,
                    depth: 1,
                    doomed: false,
                });
            }
        }
        Ok(())
    }

    /// Commits `owner`'s transaction: the outermost makes its change (one
    /// undo step, one save, one merged change event), then has the binary
    /// analysed anew if it corrected recovery.
    ///
    /// # Errors
    ///
    /// None of `owner`'s is open, or an inner one rolled it back
    /// ([`FaultKind::Transaction`]); the change cannot be made.
    pub fn commit(&self, owner: Owner) -> Result<Committed, Fault> {
        let entry = {
            let mut group = self.group();
            let open = owned(&mut group, owner)?;
            if open.depth > 1 {
                open.depth -= 1;
                return Ok(Committed {
                    entry: None,
                    reanalysing: false,
                });
            }
            let doomed = open.doomed;
            *group = None;
            if doomed {
                return Err(Fault::new(
                    FaultKind::Transaction,
                    "an inner transaction rolled this one back: nothing was committed",
                ));
            }
            let session = self.lineage.session();
            session
                .commit()
                .map_err(|error| Fault::session(&error, None))?
                .map(|entry| HistoryItem::of(&entry, &[]))
        };
        Ok(Committed {
            entry,
            reanalysing: self.reanalyse()?,
        })
    }

    /// Rolls `owner`'s transaction back: its writes undone at once, as if
    /// never made. Inside another of its own, the outer one is rolled back
    /// too (nothing more is written in it; committing it is refused).
    ///
    /// # Errors
    ///
    /// None of `owner`'s is open ([`FaultKind::Transaction`]).
    pub fn rollback(&self, owner: Owner) -> Result<(), Fault> {
        let mut group = self.group();
        let open = owned(&mut group, owner)?;
        if !open.doomed {
            self.lineage.session().rollback();
        }
        if open.depth > 1 {
            open.depth -= 1;
            open.doomed = true;
        } else {
            *group = None;
        }
        Ok(())
    }

    /// Rolls back whatever transaction `owner` has open, at any depth (its
    /// client is gone); whether one was.
    pub fn abandon(&self, owner: Owner) -> bool {
        let mut group = self.group();
        match *group {
            Some(open) if open.owner == owner => {
                if !open.doomed {
                    self.lineage.session().rollback();
                }
                *group = None;
                true
            }
            Some(_) | None => false,
        }
    }

    /// Makes `write` for `owner`: in its transaction if one is open, else
    /// as a change of its own labelled by the write and made by `origin`
    /// (signed by agent `by` if given)
    /// (the binary analysed anew if it corrected recovery). What it did;
    /// `corrected` says, outside a transaction, that a new analysis is
    /// under way.
    ///
    /// # Errors
    ///
    /// Another's transaction is open, or one of `owner`'s was rolled back
    /// ([`FaultKind::Transaction`]); the session refuses the write (then
    /// nothing is changed).
    pub fn apply(
        &self,
        owner: Owner,
        origin: &Origin,
        by: Option<PublicKey>,
        write: &Write,
    ) -> Result<Applied, Fault> {
        let in_group = self.holder() == Some(owner);
        let mut applied = self.converse(owner, origin, by, write.label(), |session| {
            write.apply(session)
        })?;
        if in_group {
            return Ok(applied);
        }
        applied.corrected = applied.corrected && self.reanalyse()?;
        Ok(applied)
    }

    /// Runs `write` for `owner` on the session: in its transaction if one
    /// is open, else as a change of its own labelled `label` and made by
    /// `origin` (signed by agent `by` if given; committed if `write`
    /// succeeds, else rolled back). What `write` returned.
    ///
    /// # Errors
    ///
    /// Another's transaction is open, or one of `owner`'s was rolled back
    /// ([`FaultKind::Transaction`]); `write`'s fault (then nothing is
    /// changed).
    pub fn converse<T>(
        &self,
        owner: Owner,
        origin: &Origin,
        by: Option<PublicKey>,
        label: &str,
        write: impl FnOnce(&Session) -> Result<T, Fault>,
    ) -> Result<T, Fault> {
        let group = self.group();
        let session = self.lineage.session();
        match *group {
            Some(open) if open.owner != owner => return Err(held_by_another()),
            Some(open) if open.doomed => {
                return Err(Fault::new(
                    FaultKind::Transaction,
                    "the transaction was rolled back by an inner one",
                ));
            }
            Some(_) => return write(&session),
            None => {}
        }
        session.begin_as(label, origin.clone(), by);
        match write(&session) {
            Ok(done) => {
                session
                    .commit()
                    .map_err(|error| Fault::session(&error, None))?;
                Ok(done)
            }
            Err(fault) => {
                session.rollback();
                Err(fault)
            }
        }
    }

    /// What each of `writes` did, in order, and the keys and values they
    /// would write, none written ([`Session::draft`]): what a suggestion
    /// of them proposes. Beside `owner`'s transaction if one is open,
    /// never while another's is.
    ///
    /// # Errors
    ///
    /// Another's transaction is open ([`FaultKind::Transaction`]); a
    /// write the session refuses.
    pub fn draft(&self, owner: Owner, writes: &[Write]) -> Result<Drafted, Fault> {
        let group = self.group();
        if group.is_some_and(|open| open.owner != owner) {
            return Err(held_by_another());
        }
        let session = self.lineage.session();
        let (applied, ops) = session.draft(|session| {
            writes
                .iter()
                .map(|write| write.apply(session))
                .collect::<Result<Vec<_>, _>>()
        });
        drop(group);
        Ok((applied?, ops))
    }

    /// Accepts suggestion `id`'s edits `chosen` (all if empty) as one
    /// change by this install's identity ([`Session::accept`]), analysed
    /// anew if they correct recovery.
    ///
    /// # Errors
    ///
    /// A transaction is open ([`FaultKind::Transaction`]); the session
    /// refuses (no such suggestion, not pending).
    pub fn accept(&self, id: OpId, chosen: &[usize]) -> Result<Committed, Fault> {
        let entry = {
            let group = self.group();
            if group.is_some() {
                return Err(Fault::new(
                    FaultKind::Transaction,
                    "a transaction is open: commit or roll it back first",
                ));
            }
            self.lineage
                .session()
                .accept(id, chosen)
                .map_err(|error| Fault::session(&error, None))?
        };
        Ok(Committed {
            entry: entry.map(|entry| HistoryItem::of(&entry, &[])),
            reanalysing: self.reanalyse()?,
        })
    }

    /// Undoes `owner`'s install's last change not undone (never another
    /// identity's), by compare-and-set; the change written, with the keys
    /// skipped (changed by someone since); `None` if nothing is left to
    /// undo. A private bookmark's edit alone (the GUI's, local) is undone
    /// as a step too, told as an item of no change
    /// ([`HistoryItem::private`]). The binary is analysed anew if a
    /// correction was undone.
    ///
    /// # Errors
    ///
    /// A transaction is open ([`FaultKind::Transaction`]).
    pub fn undo(&self) -> Result<Option<HistoryItem>, Fault> {
        self.replay(false)
    }

    /// Makes the last change undone again, as [`Self::undo`].
    ///
    /// # Errors
    ///
    /// A transaction is open ([`FaultKind::Transaction`]).
    pub fn redo(&self) -> Result<Option<HistoryItem>, Fault> {
        self.replay(true)
    }

    /// An undo, or a redo if `redo`.
    fn replay(&self, redo: bool) -> Result<Option<HistoryItem>, Fault> {
        let (done, key) = {
            let group = self.group();
            if group.is_some() {
                return Err(Fault::new(
                    FaultKind::Transaction,
                    "a transaction is open: commit or roll it back first",
                ));
            }
            let session = self.lineage.session();
            let done = if redo { session.redo() } else { session.undo() };
            let done = done.map_err(|error| Fault::session(&error, None))?;
            (done, session.identity())
        };
        self.reanalyse()?;
        Ok(done.and_then(|done| match (&done.change, done.target) {
            (Some(entry), _) => Some(HistoryItem::of(entry, &done.skipped)),
            (None, None) => Some(HistoryItem::private(&done.label, redo, key)),
            (None, Some(_)) => None,
        }))
    }

    /// The changes, newest first.
    pub fn history(&self) -> Vec<HistoryItem> {
        self.lineage
            .session()
            .history()
            .iter()
            .map(|entry| HistoryItem::of(entry, &[]))
            .collect()
    }

    /// Has the binary analysed anew if the corrections changed since the
    /// session in use was recovered; whether a new analysis is under way.
    fn reanalyse(&self) -> Result<bool, Fault> {
        self.lineage
            .reanalyse()
            .map_err(|error| Fault::session(&error, None))?;
        Ok(self.lineage.reanalysing())
    }

    /// Waits up to `timeout` for every new analysis under way to be
    /// swapped in (one started by corrections made meanwhile too):
    /// whether none is under way now.
    ///
    /// # Errors
    ///
    /// The new analysis stopped before recovering the functions (its
    /// failure, [`FaultKind::Binbun`]).
    pub fn settle(&self, timeout: Duration) -> Result<bool, Fault> {
        let deadline = Instant::now().checked_add(timeout);
        loop {
            let left = deadline.map_or(timeout, |deadline| {
                deadline.saturating_duration_since(Instant::now())
            });
            match self.lineage.wait_next(Some(left)) {
                None => return Ok(true),
                Some(Waited::Reached(_)) if self.swaps => {
                    let _held = self.group();
                    self.lineage.swap();
                }
                // Whoever holds the lineage swaps it (on its thread).
                Some(Waited::Reached(_)) => thread::sleep(SWAP_POLL.min(left)),
                Some(Waited::TimedOut(_)) => return Ok(false),
                Some(Waited::Stopped { stage, failure }) => {
                    return Err(Fault::new(
                        FaultKind::Binbun,
                        format!(
                            "the new analysis stopped at {stage:?}{}",
                            failure.map(|f| format!(": {f}")).unwrap_or_default()
                        ),
                    ));
                }
            }
            if left.is_zero() {
                return Ok(!self.lineage.reanalysing());
            }
        }
    }

    /// The stage the session in use reached.
    pub fn stage(&self) -> Stage {
        self.lineage.session().stage()
    }

    /// Closes the sessions (a transaction open is dropped with them).
    pub fn close(self) {
        match Arc::try_unwrap(self.lineage) {
            Ok(lineage) => lineage.close(),
            Err(shared) => shared.session().cancel(),
        }
    }
}

/// The transaction open in `group` if it is `owner`'s.
fn owned(group: &mut Option<Group>, owner: Owner) -> Result<&mut Group, Fault> {
    match group {
        Some(open) if open.owner == owner => Ok(open),
        Some(_) => Err(held_by_another()),
        None => Err(Fault::new(FaultKind::Transaction, "no transaction is open")),
    }
}

/// Another client's transaction is open.
fn held_by_another() -> Fault {
    Fault::new(
        FaultKind::Transaction,
        "another thread or client has a transaction open",
    )
}
