//! A share's journal (sync §4.5, §5.1, §14): what of it is **admitted**
//! (taken by the [`Authority`] in the share: only this is told, served,
//! acknowledged and satisfies a dependency), **pending** (this install's
//! and its agents' own work on chains bound to the share, made while
//! collaboration was not attached, not judged yet) and **apart** (refused
//! work, chains of another share or of none: kept in `log/apart/`,
//! applied to nothing, never promoted).
//!
//! - Admitted is a mark per chain: the number admitted up to and the hash
//!   there (`log/admitted`, under the share's genesis and binding),
//!   checked against the log at opening, failing closed.
//! - Pending and apart differ on disk: a refused suffix is written to
//!   `log/apart/` and made durable, and only then cut off its chain's
//!   file; after a crash between the two the move is completed at
//!   opening. Nothing apart becomes pending again.
//! - Sharing a journal (or joining with an empty one) writes, in order:
//!   the chains not listed moved apart, the marks, the freezes and
//!   evidence, and last the share's genesis (`log/share`): a log without
//!   it is not a share's.
//! - Replay judges nothing: it loads the freezes, evidence and marks,
//!   completes moves, and takes what the log holds.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::remote::{Applied, Source};
use super::store::{Admitted, Read, Store};
use super::{
    Authority, Cause, ChainId, ChangeHash, ChangeId, Committed, Edits, Evidence, FrozenBy, Journal,
    Key, Of, Origin, PublicKey, Record, Refused, Share, Value, Verdict, Why, adds,
};

/// Why nothing is committed while a join is under way.
const JOINING: &str = "the project is still joining its share: no edit is taken until its \
                       membership and key have come";

/// What a verdict of not now waits for, for people.
fn waiting(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::NotYet(Cause::Change(_)) => "it names work not taken yet",
        Verdict::NotYet(Cause::ViewOnly(_)) => "its author is linked view-only on another build",
        Verdict::Decline => "its grant is not here yet, or its author has too many chains",
        Verdict::Admit | Verdict::Never(_) => "",
    }
}

/// A change of the user's own (or an agent's), pending or kept apart, as
/// it is listed: what it did, by whom, with its values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEdit {
    /// The change.
    pub change: ChangeId,
    /// Its author.
    pub author: PublicKey,
    /// What it did, for people.
    pub label: String,
    /// Who or what made it.
    pub origin: Origin,
    /// Its values, in order.
    pub values: Vec<(Key, Value)>,
}

impl LocalEdit {
    /// Change `change` of `author`, of `body`.
    fn of(change: ChangeId, author: PublicKey, body: &super::Body) -> Self {
        Self {
            change,
            author,
            label: body.label.clone(),
            origin: body.origin.clone(),
            values: body
                .ops
                .iter()
                .map(|op| (op.key.clone(), op.value.clone()))
                .collect(),
        }
    }
}

/// A value that may be brought into a share ([`Journal::bringable`]): its
/// key, the value shown, and who wrote it (an agent's chain is its
/// agent's key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bringable {
    /// The key.
    pub key: Key,
    /// Its value now.
    pub value: Value,
    /// Whose key wrote it.
    pub writer: PublicKey,
    /// As whom.
    pub origin: Origin,
}

impl Journal {
    /// The share's genesis, if the journal is a share's.
    pub(crate) fn genesis(&self) -> Option<[u8; 32]> {
        self.share.as_ref().map(|share| share.genesis)
    }

    /// Whether a join is under way: an authority attached and no share.
    pub(crate) fn joining(&self) -> bool {
        self.authority.is_some() && self.share.is_none()
    }

    /// This author's (and its agents') changes on the share's chains past
    /// what the share admitted: pending.
    pub(crate) fn pending_edits(&self) -> Vec<LocalEdit> {
        let mut edits = Vec::new();
        for chain in self.pending_chains() {
            let from = self.admitted_to(chain) + 1;
            edits.extend(
                self.records
                    .range(
                        ChangeId { chain, seq: from }..=ChangeId {
                            chain,
                            seq: u64::MAX,
                        },
                    )
                    .filter(|(_, record)| !record.is_start())
                    .map(|(_, record)| LocalEdit::of(record.id, record.author, &record.body)),
            );
        }
        edits
    }

    /// The changes kept in `log/apart/`, each with its author (from its
    /// chain's start) and values; none in a journal kept nowhere, and none
    /// of a file that does not read.
    pub(crate) fn apart_edits(&self) -> Vec<LocalEdit> {
        let Some(store) = &self.store else {
            return Vec::new();
        };
        let mut edits = Vec::new();
        for (chain, read) in store.read_apart().unwrap_or_default() {
            let Read::Changes(changes) = read else {
                continue;
            };
            let author = changes
                .first()
                .and_then(|first| first.head.head.author())
                .or_else(|| self.chains.get(&chain).map(|known| known.author));
            let Some(author) = author else {
                continue;
            };
            for change in &changes {
                if let Ok(body) = super::Body::decode(&change.body)
                    && !body.is_start()
                {
                    edits.push(LocalEdit::of(change.id(), author, &body));
                }
            }
        }
        edits
    }

    /// Judges `authority` to judge what comes from outside, and this
    /// author's own commits, from now on (none: detached).
    pub(crate) fn attach(&mut self, authority: Option<Arc<dyn Authority>>) {
        self.authority = authority;
    }

    /// Whether the authority attached takes this author's own changes
    /// `records` (just sealed, of one chain) now (sync §4.5 rule 6). They
    /// are pending (`false`) with none to ask, with work of the chain
    /// pending below them or a change they name pending, or while no link
    /// is a reader's and the membership chain does not make them final.
    /// With collaboration attached and no share yet (a join under way)
    /// nothing is taken.
    ///
    /// # Errors
    ///
    /// The authority does not take them, or a join is under way: they are
    /// not written ([`Self::refused_at_source`] says so).
    pub(super) fn judge_own(&self, records: &[Arc<Record>]) -> Result<bool, String> {
        let Some(authority) = &self.authority else {
            return Ok(false);
        };
        let Some(share) = &self.share else {
            self.at_source.set(true);
            return Err(JOINING.to_owned());
        };
        let Some(first) = records.first() else {
            return Ok(false);
        };
        let chain = first.id.chain;
        let admitted = share.admitted.get(&chain).map_or(0, |(seq, _)| *seq);
        let taken = self.chains.get(&chain).map_or(0, |known| known.seq);
        let waits = admitted != taken
            || records.iter().any(|record| {
                self.awaited(record.id, &record.body, Source::Remote)
                    .is_some_and(|named| !records.iter().any(|record| record.id == named))
            });
        let reader = authority.reader();
        let mut taken_all = !waits && reader;
        for record in records {
            let verdict = self.judged(authority.as_ref(), record, records);
            match verdict {
                Verdict::Admit => {}
                Verdict::NotYet(_) | Verdict::Decline if waits || !reader => taken_all = false,
                Verdict::NotYet(_) | Verdict::Decline => {
                    self.at_source.set(true);
                    return Err(format!(
                        "not taken in the share now ({})",
                        waiting(&verdict)
                    ));
                }
                Verdict::Never(why) => {
                    self.at_source.set(true);
                    return Err(format!("not taken in the share: {why}"));
                }
            }
        }
        Ok(taken_all)
    }

    /// What `authority` makes of `record`, this install's own (or an
    /// agent's), judged under the grant its chain's start names (the
    /// chain known, or its start among `sealed`, not taken yet): a chain
    /// that names none (of no share) is not the share's.
    fn judged(
        &self,
        authority: &dyn Authority,
        record: &Record,
        sealed: &[Arc<Record>],
    ) -> Verdict {
        let chain = record.id.chain;
        let bound = match self.chains.get(&chain) {
            Some(known) => Some(&known.bound),
            None => sealed
                .iter()
                .find(|start| start.id.chain == chain && start.is_start())
                .and_then(|start| start.body.bound.as_ref()),
        };
        let grant = bound.and_then(|bound| bound.share).map(|under| under.grant);
        match grant {
            Some(grant) => {
                authority.admit(record.author, grant, &record.signed.head.head, &record.body)
            }
            None => Verdict::Never(Why::new("a chain that names no grant in the share")),
        }
    }

    /// Whether the last commit refused was refused by the share (or a join
    /// under way), not for its own bounds; forgotten as it is asked.
    pub(crate) fn refused_at_source(&self) -> bool {
        self.at_source.replace(false)
    }

    /// Counts `records` (this author's own, judged) as admitted.
    pub(super) fn admit_taken(&mut self, records: &[Arc<Record>]) {
        if let Some(share) = &mut self.share {
            for record in records {
                share
                    .admitted
                    .insert(record.id.chain, (record.id.seq, record.hash));
            }
        }
    }

    /// The chains written here with changes taken past their admitted mark:
    /// pending work.
    fn pending_chains(&self) -> Vec<ChainId> {
        let Some(share) = &self.share else {
            return Vec::new();
        };
        self.mine
            .iter()
            .filter(|chain| {
                let admitted = share.admitted.get(chain).map_or(0, |(seq, _)| *seq);
                self.chains
                    .get(chain)
                    .is_some_and(|known| known.seq > admitted)
            })
            .copied()
            .collect()
    }

    /// Judges the pending work (sync §4.5 rule 4): each pending change, in
    /// its chain's order, through the authority; a change naming pending
    /// work of another chain after it. With a link a reader's (`reader`),
    /// what it takes is admitted and what it does not (and whatever names
    /// that) is moved apart; without one, only what the membership chain
    /// already makes final (`Never`) is judged, and moved apart, the rest
    /// left pending. New work goes on new chains after a move. The keys
    /// whose ops changed are `touched`.
    ///
    /// # Errors
    ///
    /// A refused suffix or the marks cannot be written.
    pub(crate) fn promote(
        &mut self,
        reader: bool,
        touched: &mut BTreeSet<Key>,
    ) -> Result<Applied, String> {
        let Some(authority) = self.authority.clone() else {
            return Ok(Applied::default());
        };
        if !reader {
            return self.refuse_final(authority.as_ref(), touched);
        }
        let mut applied = Applied::default();
        loop {
            let mut moved = false;
            for chain in self.pending_chains() {
                let admitted = self.admitted_to(chain);
                let id = ChangeId {
                    chain,
                    seq: admitted + 1,
                };
                let Some(record) = self.record_or_start(id) else {
                    continue;
                };
                let verdict = match self.awaited(id, &record.body, Source::Remote) {
                    Some(named) if self.pending(named) => continue,
                    Some(named) => Verdict::NotYet(Cause::Change(named)),
                    None => self.judged(authority.as_ref(), &record, &[]),
                };
                moved = true;
                match verdict {
                    Verdict::Admit => {
                        if let Some(share) = &mut self.share {
                            share.admitted.insert(chain, (id.seq, record.hash));
                        }
                        applied.taken.push((id, record.hash));
                        if record.is_start() {
                            applied.known.push(chain);
                        }
                    }
                    Verdict::NotYet(_) | Verdict::Decline => {
                        let why = format!("not taken in the share ({})", waiting(&verdict));
                        self.refuse_pending(chain, id.seq, &why, touched, &mut applied)?;
                    }
                    Verdict::Never(why) => {
                        let why = format!("not taken in the share: {why}");
                        self.refuse_pending(chain, id.seq, &why, touched, &mut applied)?;
                    }
                }
            }
            if !moved {
                break;
            }
        }
        // What still waits names work that never was admitted.
        for chain in self.pending_chains() {
            let from = self.admitted_to(chain) + 1;
            let why = "it names work not taken in the share";
            self.refuse_pending(chain, from, why, touched, &mut applied)?;
        }
        self.flush()?;
        Ok(applied)
    }

    /// The number chain `chain` is admitted up to.
    fn admitted_to(&self, chain: ChainId) -> u64 {
        self.share
            .as_ref()
            .and_then(|share| share.admitted.get(&chain))
            .map_or(0, |(seq, _)| *seq)
    }

    /// Judges the pending work by `authority` (the one attached, or a
    /// candidate's: the membership as a record being taken leaves it,
    /// shown to no other caller) as [`Self::promote`] does with no reader:
    /// only what it makes final (`Never`), the first change of each
    /// pending chain refused for good and all after it, is moved apart;
    /// nothing is admitted. The keys whose ops changed are `touched`.
    ///
    /// # Errors
    ///
    /// A refused suffix cannot be written.
    pub(crate) fn refuse_final(
        &mut self,
        authority: &dyn Authority,
        touched: &mut BTreeSet<Key>,
    ) -> Result<Applied, String> {
        let mut applied = Applied::default();
        for chain in self.pending_chains() {
            let from = self.admitted_to(chain) + 1;
            let never = self
                .records
                .range(
                    ChangeId { chain, seq: from }..=ChangeId {
                        chain,
                        seq: u64::MAX,
                    },
                )
                .find_map(|(id, record)| match self.judged(authority, record, &[]) {
                    Verdict::Never(why) => Some((id.seq, why)),
                    Verdict::Admit | Verdict::NotYet(_) | Verdict::Decline => None,
                });
            if let Some((seq, why)) = never {
                let why = format!("not taken in the share: {why}");
                self.refuse_pending(chain, seq, &why, touched, &mut applied)?;
            }
        }
        self.flush()?;
        Ok(applied)
    }

    /// Whether change `id` is pending work: taken, not admitted.
    fn pending(&self, id: ChangeId) -> bool {
        self.mine.contains(&id.chain)
            && self.record_or_start(id).is_some()
            && id.seq > self.admitted_to(id.chain)
    }

    /// The record of change `id`, its chain's start included.
    fn record_or_start(&self, id: ChangeId) -> Option<Arc<Record>> {
        self.records.get(&id).cloned()
    }

    /// Moves this install's pending work on `chain` from `from` apart
    /// because `why`: written to `log/apart/` and made durable, then cut
    /// off its chain's file, then out of the projection; new work on a
    /// new chain.
    ///
    /// # Errors
    ///
    /// The move cannot be written: nothing is moved.
    fn refuse_pending(
        &mut self,
        chain: ChainId,
        from: u64,
        why: &str,
        touched: &mut BTreeSet<Key>,
        applied: &mut Applied,
    ) -> Result<(), String> {
        let moved: Vec<Arc<Record>> = self
            .records
            .range(
                ChangeId { chain, seq: from }..=ChangeId {
                    chain,
                    seq: u64::MAX,
                },
            )
            .map(|(_, record)| Arc::clone(record))
            .collect();
        // Not yet in the log: written there first, so that the move is
        // the only way out of it.
        if !self.unsaved.is_empty() {
            self.flush()?;
        }
        if let Some(store) = &mut self.store {
            let signed: Vec<_> = moved.iter().map(|record| &record.signed).collect();
            store.move_apart(chain, &signed, from)?;
        }
        if let Some(share) = &mut self.share {
            share.apart.insert(chain);
        }
        let (keys, mut dropped) = self.withdraw(chain, from, why);
        touched.extend(keys);
        if from <= 1 {
            self.records.remove(&ChangeId { chain, seq: 1 });
            self.chains.remove(&chain);
            if let Some(author) = moved.first().map(|record| record.author) {
                dropped.push(Refused {
                    change: Some(ChangeId { chain, seq: 1 }),
                    author: Some(author),
                    why: why.to_owned(),
                });
            }
        }
        applied.refused.extend(dropped);
        self.leave(chain)
    }

    /// Writes new work on a new chain where `chain` was being written (by
    /// this install or an agent of it).
    ///
    /// # Errors
    ///
    /// No randomness.
    fn leave(&mut self, chain: ChainId) -> Result<(), String> {
        if self.chain == chain {
            self.chain = self.fresh_chain(self.author())?;
        }
        let agents: Vec<PublicKey> = self
            .agents
            .iter()
            .filter(|(_, agent)| agent.chain == chain)
            .map(|(&key, _)| key)
            .collect();
        for key in agents {
            let fresh = self.fresh_chain(key)?;
            if let Some(agent) = self.agents.get_mut(&key) {
                agent.chain = fresh;
            }
        }
        Ok(())
    }

    /// Makes the journal share `genesis`'s, of binary `of`, its chains
    /// `before` (the prefixes the share's first record lists: up to which
    /// number, the hash there) the only ones of it from before, admitted
    /// on the strength of that listing alone (sync §14.2). In the log, in
    /// order: every other chain, and what of a listed chain is past its
    /// prefix, moved apart; the freezes and evidence; the marks, which name
    /// the share and make the log a share's (sync §4.5 rule 3); the
    /// share's genesis last. A crash before the marks leaves the log
    /// unshared, and sharing again redoes it; one after them leaves it a
    /// share's, its genesis written again at its opening. New work goes on
    /// new chains that name the share. Sharing a journal of the same share
    /// again does nothing.
    ///
    /// # Errors
    ///
    /// The journal is another share's, of another binary, a listed prefix
    /// is not what the log holds, or the log cannot be written.
    pub(crate) fn share(
        &mut self,
        genesis: [u8; 32],
        of: Of,
        before: &BTreeMap<ChainId, (u64, ChangeHash)>,
        touched: &mut BTreeSet<Key>,
    ) -> Result<Applied, String> {
        match &self.share {
            Some(share) if share.genesis == genesis => return Ok(Applied::default()),
            Some(_) => return Err("the journal is another share's".to_owned()),
            None => {}
        }
        if !self.bind(of) {
            return Err("the journal is of another binary than the share's".to_owned());
        }
        for (chain, &(through, hash)) in before {
            // A joiner holds none of them yet: they are verified as they
            // come (sync §3.3).
            if !self.chains.contains_key(chain) {
                continue;
            }
            let held = self.records.get(&ChangeId {
                chain: *chain,
                seq: through,
            });
            if held.is_none_or(|record| record.hash != hash) {
                return Err(format!(
                    "chain {chain} does not hold the change listed at {through}"
                ));
            }
        }
        if !self.unsaved.is_empty() {
            self.flush()?;
        }
        let mut applied = Applied::default();
        let mut marks = BTreeMap::new();
        let chains: Vec<ChainId> = self.chains.keys().copied().collect();
        for chain in chains {
            let upto = match before.get(&chain) {
                Some(&(through, _)) => through,
                None => 0,
            };
            if upto > 0
                && let Some(record) = self.records.get(&ChangeId { chain, seq: upto })
            {
                marks.insert(chain, (upto, record.hash));
            }
            let past = self.chains.get(&chain).map_or(0, |known| known.seq);
            if past > upto {
                self.move_apart(chain, upto + 1, touched, &mut applied)?;
            }
        }
        let share = Share {
            genesis,
            before: before.clone(),
            marks: marks.clone(),
            admitted: marks,
            apart: applied
                .refused
                .iter()
                .filter_map(|refused| Some(refused.change?.chain))
                .collect(),
            grants: BTreeMap::new(),
        };
        if let Some(store) = &self.store {
            if store.project()?.is_none() {
                store.create(self.project, &self.of)?;
            }
            store.set_frozen(&self.frozen)?;
            store.set_evidence(&self.evidence)?;
            store.set_admitted(&Admitted {
                genesis,
                of: self.of.clone(),
                before: share.before.clone(),
                marks: share.marks.clone(),
            })?;
            store.set_share(&genesis)?;
        }
        applied.taken = share
            .marks
            .iter()
            .flat_map(|(&chain, &(through, _))| {
                (1..=through).map(move |seq| ChangeId { chain, seq })
            })
            .filter_map(|id| Some((id, self.records.get(&id)?.hash)))
            .collect();
        self.share = Some(share);
        self.keep_grants()?;
        // From the share on, every chain begun here names it.
        let me = self.author();
        self.chain = self.fresh_chain(me)?;
        let agents: Vec<PublicKey> = self.agents.keys().copied().collect();
        for key in agents {
            let fresh = self.fresh_chain(key)?;
            if let Some(agent) = self.agents.get_mut(&key) {
                agent.chain = fresh;
            }
        }
        Ok(applied)
    }

    /// Moves chain `chain` from `from` apart (of no share, or not taken):
    /// written there durably, cut off its file, out of the projection.
    ///
    /// # Errors
    ///
    /// The move cannot be written.
    fn move_apart(
        &mut self,
        chain: ChainId,
        from: u64,
        touched: &mut BTreeSet<Key>,
        applied: &mut Applied,
    ) -> Result<(), String> {
        let why = "kept apart: not of the share";
        let mut refused = Applied::default();
        self.refuse_pending(chain, from, why, touched, &mut refused)?;
        applied.refused.append(&mut refused.refused);
        Ok(())
    }

    /// Takes the changes of a merged bundle: in a journal of no share, as
    /// any from outside (those of chains bound to this binary); in a
    /// share's, those it holds already (the same number and hash, admitted
    /// or pending) left as they are, and the rest (a chain that diverges
    /// from what it holds, or goes past it) written apart, applied to
    /// nothing: a merge never cuts or replaces what the journal holds. The
    /// keys whose ops changed are `touched`.
    ///
    /// # Errors
    ///
    /// They cannot be written apart.
    pub(crate) fn merge_bundle(
        &mut self,
        changes: Vec<super::SignedChange>,
        touched: &mut BTreeSet<Key>,
    ) -> Result<Applied, String> {
        if self.share.is_none() {
            return Ok(self.apply(changes, touched, Source::Remote));
        }
        let mut chains: BTreeMap<ChainId, Vec<&super::SignedChange>> = BTreeMap::new();
        let held = |change: &super::SignedChange| {
            self.records
                .get(&change.id())
                .is_some_and(|record| record.hash == change.hash())
        };
        for change in changes.iter().filter(|change| !held(change)) {
            chains.entry(change.id().chain).or_default().push(change);
        }
        if let Some(store) = &self.store {
            for (chain, changes) in &chains {
                store.put_apart(*chain, changes)?;
            }
        }
        Ok(Applied::default())
    }

    /// The values a Bring may publish ([`Self::bring`]): every edit key's
    /// value shown, with who wrote it, this author's bookmarks among them;
    /// no conversation, no other author's bookmark.
    pub(crate) fn bringable(&self) -> Vec<Bringable> {
        let me = self.author();
        self.registers
            .iter()
            .filter(|(key, _)| key.is_edit() && super::owns(key, me))
            .filter_map(|(key, register)| {
                let (id, entry) = register.winner(adds(key))?;
                let record = self.records.get(&id.change)?;
                entry.value.is_some().then(|| Bringable {
                    key: key.clone(),
                    value: entry.value.clone(),
                    writer: record.author,
                    origin: record.body.origin.clone(),
                })
            })
            .collect()
    }

    /// Brings `values` (chosen from another journal's [`Self::bringable`],
    /// of this author's identity) into this one: one new change of this
    /// author's, signed now, labelled `label`, of the values as they are
    /// (a bookmark as this author's own), naming nothing of where they
    /// came from. In a share's journal with collaboration attached it is
    /// judged as any commit: not taken, it is not written.
    ///
    /// # Errors
    ///
    /// A group is open, or the change cannot be made or is not taken.
    pub(crate) fn bring(
        &mut self,
        values: &[Bringable],
        label: &str,
        edits: &mut Edits,
    ) -> Result<Committed, String> {
        if self.pending.is_some() {
            return Err("a group is open: commit or roll it back first".to_owned());
        }
        let me = self.author();
        self.begin(label, Origin::Import(format!("brought: {label}")));
        for brought in values {
            let key = if let Key::Bookmark(_, address) = &brought.key {
                Key::Bookmark(me, *address)
            } else {
                brought.key.clone()
            };
            if key.is_edit() && brought.value.fits(&key) {
                self.write(&key, brought.value.clone(), edits);
            }
        }
        self.commit(edits)
    }

    /// Loads the log's freezes, evidence, marks and moves before replay:
    /// a share's log (one naming its genesis, or with marks: a lost
    /// genesis is written again from them) without readable freezes,
    /// evidence or marks, or marks of another share or binary, is not
    /// opened; a proof without its freeze is completed into it; a refused
    /// head without its freeze is dropped; moves apart cut short are
    /// completed. Then what the log holds is taken ([`Self::replayed`]),
    /// and a share's log is opened only if every marked change not frozen
    /// is taken, the one marked with the hash marked.
    ///
    /// # Errors
    ///
    /// The log is a share's and lacks what it must have or a marked change
    /// is not taken, or it cannot be read or written.
    pub(crate) fn replay(&mut self, store: &mut Store) -> Result<(), String> {
        let header = store.share()?;
        let frozen = store.frozen()?;
        let evidence = store.evidence()?;
        let admitted = store.admitted()?;
        let genesis = header.or_else(|| admitted.as_ref().map(|admitted| admitted.genesis));
        if let Some(genesis) = genesis {
            let (Some(_), Some(_), Some(admitted)) = (&frozen, &evidence, &admitted) else {
                return Err(format!(
                    "{}: a share's log without its freezes, evidence or marks is not opened",
                    store.dir().display()
                ));
            };
            if admitted.genesis != genesis || admitted.of != self.of {
                return Err(format!(
                    "{}: marks of another share or binary: the log is not opened as shared",
                    store.dir().display()
                ));
            }
            if header.is_none() {
                // Lost after the marks were written: written again.
                store.set_share(&genesis)?;
            }
            let apart = store
                .read_apart()?
                .into_iter()
                .map(|(chain, _)| chain)
                .collect();
            self.share = Some(Share {
                genesis,
                before: admitted.before.clone(),
                marks: admitted.marks.clone(),
                admitted: admitted.marks.clone(),
                apart,
                grants: store.grants()?,
            });
        }
        self.frozen = frozen.unwrap_or_default();
        self.evidence = evidence.unwrap_or_default();
        let mut completed = false;
        let evidence: Vec<(ChainId, Evidence)> = self
            .evidence
            .iter()
            .map(|(&chain, evidence)| (chain, evidence.clone()))
            .collect();
        for (chain, evidence) in evidence {
            let from = self.frozen.get(&chain).map(|(from, _)| *from);
            match evidence {
                Evidence::Proof(proof) if from.is_none_or(|from| from > proof.place()) => {
                    self.frozen.insert(chain, (proof.place(), FrozenBy::Fork));
                    completed = true;
                }
                Evidence::Refused(head) if from.is_none_or(|from| from > head.head.seq) => {
                    self.evidence.remove(&chain);
                    completed = true;
                }
                Evidence::Proof(_) | Evidence::Refused(_) => {}
            }
        }
        if completed {
            store.set_evidence(&self.evidence)?;
            store.set_frozen(&self.frozen)?;
        }
        let marks = admitted
            .filter(|_| genesis.is_some())
            .map(|admitted| admitted.marks)
            .unwrap_or_default();
        store.complete_moves(&marks)?;
        self.mine = store.local()?;
        let read: Vec<(ChainId, Read)> = store.read()?;
        let changes = self.replayed(read, store)?;
        let mut touched = BTreeSet::new();
        self.apply(changes, &mut touched, Source::Replay);
        self.marks_taken()
    }

    /// Whether replay took every change a share's marks admit (sync §4.5
    /// rule 3): of each chain, the change marked, with the hash marked;
    /// of a chain frozen at or below its mark, the change before the
    /// freeze.
    ///
    /// # Errors
    ///
    /// A marked change is not taken (refused, held or not there).
    fn marks_taken(&self) -> Result<(), String> {
        let Some(share) = &self.share else {
            return Ok(());
        };
        for (&chain, &(seq, hash)) in &share.marks {
            let upto = self
                .frozen_from(chain)
                .map_or(seq, |from| seq.min(from.saturating_sub(1).max(1)));
            let taken = self.records.get(&ChangeId { chain, seq: upto });
            if taken.is_none_or(|record| upto == seq && record.hash != hash) {
                return Err(format!(
                    "change {upto} of chain {chain}, admitted by the marks, is not taken: the \
                     log is not opened as shared"
                ));
            }
        }
        Ok(())
    }
}
