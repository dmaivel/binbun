//! Changes from elsewhere through a session: taken into the journal
//! ([`Session::receive`]: checked, held, stopped or refused as
//! [`crate::journal`] says, judged by the [`Authority`] attached in a
//! share's journal), their engine effects made as a local edit's are,
//! kept in the log; what this session tells and serves a peer, point by
//! point ([`Session::tip`], [`Session::tips_after`],
//! [`Session::changes_after`] and the rest: sync §3.1); a share's journal
//! made and its pending work judged ([`Session::share`],
//! [`Session::promote`]); conflicts shown and resolved
//! ([`Session::resolve`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Arc;

use crate::identity::Identity;
use crate::journal::{
    Applied, Authority, Bringable, ChainId, ChangeHash, Committed, Evidence, ForkProof, ForkTaken,
    FrozenBy, Journal, Key, Learnt, LocalEdit, Of, ProjectId, PublicKey, Refused, SignedChange,
    SignedHead, Tip, Value,
};
use crate::project::Project;
use crate::worker::State;
use crate::write::Group;
use crate::{Change, Edits, Error, Event, HistoryEntry, Session};

impl Session {
    /// Takes `changes` from elsewhere (a peer's, a session followed): each
    /// checked (its chain known here and followed, signed by its author,
    /// its body the one its head commits to and well formed, the changes
    /// it names taken) and, in a share's journal, judged by the authority
    /// attached ([`Self::attach`]) immediately before it is taken; else
    /// held until what it names comes, stopped ([`Applied::stopped`]), or
    /// refused and listed ([`Self::refused`]), its chain frozen if its
    /// author wrote what it may never. In a share's journal what is taken
    /// is written and marked before this returns. What they change is told
    /// as an edit's is ([`Event::Changed`], [`Event::History`];
    /// [`Event::Conflicts`] if they leave conflicts; [`Event::Bookmarks`]
    /// if they touch another author's bookmark). Corrections among them
    /// need the binary analysed anew ([`Applied::reanalyse`];
    /// [`crate::Lineage::reanalyse`]).
    pub fn receive(&self, changes: Vec<SignedChange>) -> Applied {
        self.take(|journal, edits| journal.receive(changes, edits))
    }

    /// Freezes chains `freezes`, each from a change for a cause (a cut by
    /// a membership record, `binbun-collab`): kept in the log before this
    /// returns and before they take effect; then, from this call on, those
    /// changes are not told, served, depended on or taken, now or when the
    /// project opens again, and every author's undo and redo forget them
    /// (a chain's start stays). Changes of a chain from there are refused
    /// from now on. Afterwards, a turn at a time on a thread of the
    /// session's own ([`Self::settle`]), each key they wrote comes to show
    /// what its other writers left, they leave the history, and changes
    /// held waiting for them are let go; told as taking changes is. A
    /// chain frozen from an earlier change stays so.
    ///
    /// # Errors
    ///
    /// The freezes cannot be written ([`Error::Project`]): none takes
    /// effect.
    pub fn freeze(&self, freezes: &[(ChainId, u64, FrozenBy)]) -> Result<Applied, Error> {
        let mut failed = None;
        let applied = self.take(|journal, edits| {
            journal
                .freeze_and_keep(freezes, edits)
                .unwrap_or_else(|error| {
                    failed = Some(error);
                    (Applied::default(), Vec::new())
                })
        });
        match failed {
            Some(error) => Err(Error::Project(error)),
            None => Ok(applied),
        }
    }

    /// Takes fork proof `proof`, if it is of a chain known here and lower
    /// than any kept: kept in the log with the chain's freeze from its
    /// place, both before this returns and before they take effect; the
    /// freeze then settles as [`Self::freeze`]'s does.
    ///
    /// # Errors
    ///
    /// They cannot be written ([`Error::Project`]): nothing is kept.
    pub fn take_fork(&self, proof: &ForkProof) -> Result<ForkTaken, Error> {
        let mut taken = Ok(ForkTaken::Held);
        self.take(|journal, edits| match journal.take_fork(proof) {
            Ok((fork, applied)) => {
                taken = Ok(fork);
                journal.settle(applied, BTreeSet::new(), edits)
            }
            Err(error) => {
                taken = Err(error);
                (Applied::default(), Vec::new())
            }
        });
        taken.map_err(Error::Project)
    }

    /// Takes chain start `start` from elsewhere: its chain known here if
    /// it is bound to this journal, by an author the share names or named,
    /// within the bounds of chains known (sync §3.1, §7).
    pub fn learn_chain(&self, start: SignedChange) -> Learnt {
        let mut learnt = Learnt::Known;
        self.take(|journal, edits| {
            let mut touched = BTreeSet::new();
            learnt = journal.learn_chain(start, &mut touched);
            journal.settle(Applied::default(), touched, edits)
        });
        learnt
    }

    /// Judges every held change again (after a membership record: those
    /// of chains frozen dropped now, those whose wait is over through the
    /// authority afterwards, as [`Self::freeze`] settles).
    pub fn recheck_held(&self) -> Applied {
        self.take(|journal, edits| {
            let applied = journal.recheck_held();
            journal.settle(applied, BTreeSet::new(), edits)
        })
    }

    /// Runs now, on this thread, the turns freezes and releases left (each
    /// in a hold of its own, as the session's thread would): what bringing
    /// values and an export wait for, since they copy values out.
    pub fn settle(&self) {
        while self.turn() {}
    }

    /// Whether nothing is left to settle ([`Self::settle`]): every key
    /// shows what freezes left of it.
    pub fn settled(&self) -> bool {
        !self.shared.state().journal.busy()
    }

    /// What the turns since last asked came to ([`Self::settle`]), while
    /// collaboration is attached: the changes they took and the chains
    /// they made known or froze, the refusals (the latest 1,024) and the
    /// writes that failed. For collaboration to tell its links.
    pub fn take_settled(&self) -> Applied {
        self.shared.state().journal.take_settled()
    }

    /// Starts the session's thread on what freezes and releases left, if
    /// any is and none is at it (sync §4.3): it settles a turn per hold
    /// of the state, outside every caller's locks, until none is left or
    /// the session is cancelled.
    fn settle_later(&self) {
        {
            let mut state = self.shared.state();
            let journal = &mut state.journal;
            if journal.settling || !journal.busy() {
                return;
            }
            journal.settling = true;
        }
        let shared = Arc::clone(&self.shared);
        let spawned = std::thread::Builder::new()
            .name("binbun-settle".to_owned())
            .spawn(move || {
                let session = Self::handle(shared);
                loop {
                    while !session.shared.cancelled() && session.turn() {}
                    // Done under the hold that would see more come.
                    let mut state = session.shared.state();
                    if session.shared.cancelled() || !state.journal.busy() {
                        state.journal.settling = false;
                        return;
                    }
                }
            });
        if spawned.is_err() {
            // Tried again at the next change taken.
            self.shared.state().journal.settling = false;
        }
    }

    /// One turn of what freezes and releases left, told as taking changes
    /// is; whether more are left.
    fn turn(&self) -> bool {
        let applied = self.take_now(Journal::settle_step);
        if applied != Applied::default() {
            self.shared.emit(&Event::History(Arc::from([])));
        }
        self.shared.state().journal.busy()
    }

    /// Judges this session's changes and its agents' with `authority` from
    /// now on, those from elsewhere and its own commits alike (none:
    /// detached, as without collaboration).
    pub fn attach(&self, authority: Option<Arc<dyn Authority>>) {
        self.shared.state().journal.attach(authority);
    }

    /// Judges this install's pending work in the share (sync §4.5 rule 4):
    /// with a link a reader's (`reader`), what the authority takes is
    /// admitted and what it does not is moved apart, never promoted, new
    /// work going on new chains; with none, only what the membership chain
    /// already makes final is judged (moved apart), the rest left pending.
    ///
    /// # Errors
    ///
    /// The log cannot be written ([`Error::Project`]).
    pub fn promote(&self, reader: bool) -> Result<Applied, Error> {
        let mut failed = None;
        let applied = self.take(|journal, edits| {
            let mut touched = BTreeSet::new();
            match journal.promote(reader, &mut touched) {
                Ok(applied) => journal.settle(applied, touched, edits),
                Err(error) => {
                    failed = Some(error);
                    journal.settle(Applied::default(), touched, edits)
                }
            }
        });
        match failed {
            Some(error) => Err(Error::Project(error)),
            None => Ok(applied),
        }
    }

    /// Judges this install's pending work in the share by `authority` in
    /// place of the one attached, as [`Self::promote`] does with no reader:
    /// what `authority` makes final is moved apart, nothing admitted. For a
    /// membership record being taken (sync §4.3): judged under the
    /// membership it leaves, which no other caller sees until it is taken.
    ///
    /// # Errors
    ///
    /// The log cannot be written ([`Error::Project`]).
    pub fn judge_final(&self, authority: &dyn Authority) -> Result<Applied, Error> {
        let mut failed = None;
        let applied = self.take(|journal, edits| {
            let mut touched = BTreeSet::new();
            match journal.refuse_final(authority, &mut touched) {
                Ok(applied) => journal.settle(applied, touched, edits),
                Err(error) => {
                    failed = Some(error);
                    journal.settle(Applied::default(), touched, edits)
                }
            }
        });
        match failed {
            Some(error) => Err(Error::Project(error)),
            None => Ok(applied),
        }
    }

    /// Makes this session's journal share `genesis`'s (the hash of its first
    /// membership record), of binary `of`, with the prefixes of its chains
    /// `before` (that record's list: up to which number, the hash there)
    /// the only work from before, judged by the authority attached; every
    /// other chain moved apart; new work on new chains naming the share.
    /// A joiner's empty journal is made the share's the same way. Sharing
    /// again in the same share does nothing.
    ///
    /// # Errors
    ///
    /// The journal is another share's or of another binary, a listed
    /// prefix is not held, no authority is attached, or the log cannot be
    /// written ([`Error::Project`]).
    pub fn share(
        &self,
        genesis: [u8; 32],
        of: Of,
        before: &BTreeMap<ChainId, (u64, ChangeHash)>,
    ) -> Result<Applied, Error> {
        let mut failed = None;
        let applied = self.take(|journal, edits| {
            let mut touched = BTreeSet::new();
            match journal.share(genesis, of, before, &mut touched) {
                Ok(applied) => journal.settle(applied, touched, edits),
                Err(error) => {
                    failed = Some(error);
                    journal.settle(Applied::default(), touched, edits)
                }
            }
        });
        match failed {
            Some(error) => Err(Error::Project(error)),
            None => Ok(applied),
        }
    }

    /// The share's genesis, if this session's journal is a share's.
    pub fn genesis(&self) -> Option<[u8; 32]> {
        self.shared.state().journal.genesis()
    }

    /// Whether a join is under way: collaboration is attached and the
    /// journal is no share's yet. No edit is taken meanwhile
    /// ([`Error::Refused`]).
    pub fn joining(&self) -> bool {
        self.shared.state().journal.joining()
    }

    /// This install's (and its agents') changes in the share's journal
    /// written and not yet judged by the share: shown, told to no one.
    pub fn pending(&self) -> Vec<LocalEdit> {
        self.shared.state().journal.pending_edits()
    }

    /// The changes kept apart in the share's journal, "not in this
    /// project": work the share refused when it judged it, the chains of
    /// a private history or another share, a merged bundle's. Applied to
    /// nothing; their values can be copied out or brought in.
    pub fn not_in_project(&self) -> Vec<LocalEdit> {
        self.shared.state().journal.apart_edits()
    }

    /// What this session's chains are of (`log/bound`).
    pub fn binding(&self) -> Of {
        self.shared.state().journal.of().clone()
    }

    /// Binds this session's journal to `of`, if it has no chain yet: a
    /// session following another's ([`Self::receive`] takes only chains
    /// bound to the same binary). Whether it is bound so.
    pub fn follow(&self, of: Of) -> bool {
        self.shared.state().journal.bind(of)
    }

    /// The values this session may bring into another (sync §5.1): every
    /// edit's value shown, with who wrote it; no conversation, no other
    /// author's bookmark. What freezes left to settle is settled first
    /// ([`Self::settle`]): no frozen value is among them.
    pub fn bringable(&self) -> Vec<Bringable> {
        loop {
            self.settle();
            let state = self.shared.state();
            if !state.journal.busy() {
                return state.journal.bringable();
            }
        }
    }

    /// The values `identity` may bring from project `from`
    /// ([`Self::bringable`]): read through this session if `from` is its
    /// own project (an owner's private project is the share's), never by
    /// a second journal beside the one writing it; else read from its log
    /// alone, held for writing meanwhile ([`Project::bringable`]).
    ///
    /// # Errors
    ///
    /// As [`Project::bringable`].
    pub fn bringable_from(
        &self,
        from: &Project,
        identity: &Identity,
    ) -> Result<Vec<Bringable>, String> {
        let same = |own: &Project| {
            own.dir() == from.dir()
                || matches!(
                    (fs::canonicalize(own.dir()), fs::canonicalize(from.dir())),
                    (Ok(own), Ok(from)) if own == from
                )
        };
        if self.project().is_some_and(same) {
            return Ok(self.bringable());
        }
        from.bringable(identity)
    }

    /// Brings `values` (chosen from another session's
    /// [`Self::bringable`]) into this one: one new change of this author's,
    /// signed now, labelled `label`, naming nothing of where they came
    /// from; in a share's journal judged as any commit. The change made.
    ///
    /// # Errors
    ///
    /// A group is open, or the change cannot be made or is not taken
    /// ([`Error::Transaction`]).
    pub fn bring(&self, values: &[Bringable], label: &str) -> Result<Option<HistoryEntry>, Error> {
        let (entry, keys) = {
            let mut state = self.shared.state();
            let State { journal, edits, .. } = &mut *state;
            let committed = journal
                .bring(values, label, edits)
                .map_err(Error::Transaction)?;
            let Committed::Sealed(records) = committed else {
                return Ok(None);
            };
            let entry = journal.step_entry(&records);
            let keys: Vec<Key> = records
                .iter()
                .flat_map(|record| record.body.ops.iter().map(|op| op.key.clone()))
                .collect();
            state.changes += 1;
            if let Some(Err(message)) = self.persist(&mut state) {
                self.shared.emit(&Event::Failed(message));
            }
            (entry, keys)
        };
        let group = self.effects(&keys);
        self.shared.emit(&Event::Changed(Arc::new(group.0)));
        if let Some(entry) = &entry {
            self.shared
                .emit(&Event::History(Arc::from([entry.clone()].as_slice())));
        }
        Ok(entry)
    }

    /// Chain `chain` as told to a peer: how far it is admitted here, below
    /// any fork; none for a chain not known.
    pub fn tip(&self, chain: ChainId) -> Option<Tip> {
        self.shared.state().journal.tip(chain)
    }

    /// The tips of the chains after `after` (exclusive; none: from the
    /// first), ascending by chain, `most` at most.
    pub fn tips_after(&self, after: Option<ChainId>, most: usize) -> Vec<Tip> {
        self.shared.state().journal.tips_after(after, most)
    }

    /// A page of the tips of the chains after `after` (exclusive; none:
    /// from the first), ascending by chain, of origin `project` if one is
    /// given: `most` at most, from `scan` chains looked at at most, so it
    /// may come back short or empty. With it, where the next page starts
    /// (the last chain looked at), unless none is left.
    pub fn tips_page(
        &self,
        after: Option<ChainId>,
        project: Option<ProjectId>,
        most: usize,
        scan: usize,
    ) -> (Vec<Tip>, Option<ChainId>) {
        self.shared
            .state()
            .journal
            .tips_page(after, project, most, scan)
    }

    /// The signed head of change `seq` of chain `chain`, if told here.
    pub fn head_at(&self, chain: ChainId, seq: u64) -> Option<SignedHead> {
        self.shared.state().journal.head_at(chain, seq)
    }

    /// The start of chain `chain`: kept whatever is frozen after it.
    pub fn chain_start(&self, chain: ChainId) -> Option<SignedChange> {
        self.shared.state().journal.start(chain)
    }

    /// The changes of chain `chain` past number `after`, in order, as told
    /// here (the start for `after` 0): `most` at most, and `bytes` at most
    /// encoded (one past it, if it is the first).
    pub fn changes_after(
        &self,
        chain: ChainId,
        after: u64,
        most: usize,
        bytes: usize,
    ) -> Vec<SignedChange> {
        self.shared
            .state()
            .journal
            .changes_after(chain, after, most, bytes)
    }

    /// The evidence kept of chain `chain` (a fork proof, or a refused
    /// head).
    pub fn evidence(&self, chain: ChainId) -> Option<Evidence> {
        self.shared.state().journal.evidence(chain)
    }

    /// The first number of chain `chain` no longer kept, if it is frozen.
    pub fn frozen_from(&self, chain: ChainId) -> Option<u64> {
        self.shared.state().journal.frozen_from(chain)
    }

    /// The chains known: each one's author and how far it is taken.
    pub fn chains(&self) -> Vec<(ChainId, PublicKey, u64)> {
        self.shared.state().journal.chains()
    }

    /// The chains known that are of the share (begun in it, not a prefix
    /// from before it): each one's author and the membership record its
    /// start names as its grant.
    pub fn grants(&self) -> Vec<(ChainId, PublicKey, u64)> {
        self.shared.state().journal.grants()
    }

    /// The chains frozen ([`Self::freeze`], or by their authors' doing),
    /// from which change.
    pub fn frozen(&self) -> BTreeMap<ChainId, u64> {
        self.shared.state().journal.frozen()
    }

    /// What `step` does to the journal and its projection, kept in the log
    /// (if autosaving), its engine effects made and told; then what it
    /// left to settle started ([`Self::settle_later`]).
    fn take(&self, step: impl FnOnce(&mut Journal, &mut Edits) -> (Applied, Vec<Key>)) -> Applied {
        let applied = self.take_now(step);
        self.settle_later();
        applied
    }

    /// What `step` does to the journal and its projection, kept in the log
    /// (if autosaving), its engine effects made and told.
    fn take_now(
        &self,
        step: impl FnOnce(&mut Journal, &mut Edits) -> (Applied, Vec<Key>),
    ) -> Applied {
        let (applied, keys, saved, others) = {
            let mut state = self.shared.state();
            let State { journal, edits, .. } = &mut *state;
            let (applied, keys) = step(journal, edits);
            let others = journal.others_bookmark(keys.iter());
            state.changes += applied.changes.len() as u64;
            let saved = if keys.is_empty() && applied.changes.is_empty() {
                None
            } else {
                self.persist(&mut state)
            };
            (applied, keys, saved, others)
        };
        if let Some(Err(message)) = saved {
            self.shared.emit(&Event::Failed(message));
        }
        for message in &applied.failed {
            self.shared.emit(&Event::Failed(message.clone()));
        }
        if keys.is_empty() {
            if applied.changes.is_empty() && !applied.frozen.is_empty() {
                self.shared.emit(&Event::History(Arc::from([])));
            }
            return applied;
        }
        let group = self.effects(&keys);
        self.shared.emit(&Event::Changed(Arc::new(group.0)));
        if !applied.changes.is_empty() || !applied.frozen.is_empty() {
            self.shared
                .emit(&Event::History(Arc::from(applied.changes.as_slice())));
        }
        self.shared
            .emit(&Event::Conflicts(Arc::from(self.conflicts().as_slice())));
        if others {
            self.shared.emit(&Event::Bookmarks);
        }
        self.tell_talk();
        applied
    }

    /// The engine effects of new values of `keys`, made: documents marked
    /// to print again (decompiled again where types changed), the overlay
    /// laid again, earlier reports of their edits dropped. What changed.
    pub(crate) fn effects(&self, keys: &[Key]) -> (Change, bool) {
        let mut group = Group::default();
        for key in keys {
            let (change, retype) = self.effect(key);
            group.add(&change, retype);
        }
        {
            let mut state = self.shared.state();
            let journal = &state.journal;
            self.shared
                .unresolved()
                .retain(|unresolved| !keys.contains(&journal.key_of(&unresolved.edit)));
            Self::touched(&mut state, group.change());
        }
        if group.retyped() {
            self.take_types(&group.change().documents);
        }
        (group.change().clone(), group.retyped())
    }

    /// Writes this author's changes on a new chain from now on (the one
    /// before kept as it is, and adopted again only if written to
    /// later): what a member admitted again after a removal does, since
    /// its peers refuse the old chain past the removal (`binbun-collab`).
    ///
    /// # Errors
    ///
    /// A group is open ([`Error::Transaction`]); no randomness.
    pub fn new_chain(&self) -> Result<(), Error> {
        self.shared
            .state()
            .journal
            .new_chain()
            .map_err(Error::Transaction)
    }

    /// Writes this author's (and its agents') changes on a new chain from
    /// now on where the chain begun names another grant than the share
    /// gives its author now: what a member does once a record sets their
    /// entry (a raise, a lowering, a readmission), since a chain keeps its
    /// own grant's role for good (`binbun-collab`).
    ///
    /// # Errors
    ///
    /// A group is open ([`Error::Transaction`]); no randomness.
    pub fn regrant(&self) -> Result<(), Error> {
        self.shared
            .state()
            .journal
            .regrant()
            .map_err(Error::Transaction)
    }

    /// The chain this author's next change goes on.
    pub fn chain(&self) -> ChainId {
        self.shared.state().journal.chain()
    }

    /// The log this session's chains are begun in, hexadecimal: the
    /// origin of its chains, and a share's id when it is shared.
    pub fn project_id(&self) -> String {
        self.shared.state().journal.project().to_string()
    }

    /// The changes refused so far (signatures that do not verify, changes
    /// refused for good, chains that equivocate, changes a freeze took
    /// out), never dropped quietly.
    pub fn refused(&self) -> Vec<Refused> {
        self.shared.state().journal.refused().to_vec()
    }

    /// Resolves the conflict on `key` with `value` (one of its values, or
    /// another): an edit naming every value it had as seen, so the key has
    /// one again for everyone; what changed. Keeping the value shown
    /// writes it again.
    ///
    /// # Errors
    ///
    /// The value is not one `key` can take ([`Error::Transaction`]); the
    /// change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    pub fn resolve(&self, key: Key, value: Value) -> Result<Arc<Change>, Error> {
        if !value.fits(&key) || !key.is_edit() {
            return Err(Error::Transaction(format!(
                "{value:?} is not a value of {key:?}"
            )));
        }
        let (change, retype) = self.effect(&key);
        let change = self.write("Resolve conflict", vec![(key, value)], change, retype)?;
        self.shared
            .emit(&Event::Conflicts(Arc::from(self.conflicts().as_slice())));
        Ok(change)
    }

    /// The authors whose clocks run ahead (a change of theirs stamped more
    /// than 60 s past this clock): flagged, their changes still taken.
    pub fn clocks_ahead(&self) -> Vec<PublicKey> {
        self.shared
            .state()
            .journal
            .ahead()
            .iter()
            .copied()
            .collect()
    }
}
