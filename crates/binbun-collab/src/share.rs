//! A share's journal and membership chain as the sync machine reads and
//! writes them ([`View`], `binbun_sync::Storage`), and the budgets it
//! draws from ([`Charges`], `binbun_sync::Budget`).
//!
//! - Membership records travel as opaque bytes with their numbers and
//!   hashes; taking them is [`crate::peer`]'s recoverable step.
//! - A change is judged when it is taken: its signed head checked against
//!   its chain (a fork of either shape proved from two signed heads), its
//!   body opened with the key of its epoch (an earlier epoch's derived
//!   through the history links, walked once per share, membership head
//!   and epoch), then given to the session, whose journal asks the
//!   [`crate::authority::Judge`].
//! - What changed in the journal is told to the machine as events: from
//!   what taking changes came to, and from this install's own chains
//!   (its own commits, its agents', pending work admitted) by their tips.

use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use binbun_bounded as bounded;
use binbun_session::journal::ForkTaken as Kept;
use binbun_session::journal::{
    Applied, Cause, ChainId, ChainOrigin, ChangeHash, ChangeId, Evidence, ForkProof, ProjectId,
    PublicKey, SignedChange, SignedHead, Stopped, Tip, Why,
};
use binbun_sync::envelope::Envelope;
use binbun_sync::wire::{Hash, Mark, PAGE_BYTES, RECORDS, RECORDS_BYTES};
use binbun_sync::{
    Admission, Budget, Event, ForkTaken, LinkId, Local, Records, RecordsRefused, Storage,
    TIPS_SCAN, Taken, Walk, Work,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::budgets::{Budgets, Held, LinkBudget};
use crate::crypto;
use crate::membership::{MAX_RECORD, Record, Role, SignedRecord};
use crate::peer::{Inner, Notice, State};

/// What the machine's storage keeps beside the journal and the chain.
#[derive(Default)]
pub(crate) struct Book {
    /// Events not yet told to the machine.
    events: Vec<Event>,
    /// Fork proofs the journal took while judging a change, not yet given
    /// to the machine's [`Storage::take_fork`].
    forks: Vec<ForkProof>,
    /// The walks of listed prefixes, per chain.
    walks: BTreeMap<ChainId, Walking>,
    /// This install's own chains (and its agents'), each with the tip
    /// told to the machine.
    pub(crate) own: BTreeMap<ChainId, u64>,
    /// The `log` subkeys of earlier epochs, derived through the history
    /// links: for one membership head and the epoch walked down from.
    history: Option<History>,
    /// Local events for the machine, from what the storage did.
    pub(crate) locals: Vec<Local>,
    /// Changes taken per member, and the keys in conflict after them,
    /// since last told.
    pub(crate) took: BTreeMap<PublicKey, (usize, usize)>,
    /// A page sealed before the machine asks for it ([`Inner::serve_job`]).
    pub(crate) prepared: Option<Prepared>,
}

/// A walk of a listed prefix: the lowest number checked, the hash the
/// head below it must have, and the hashes checked, by run (each run's
/// lowest number, and the hashes of the numbers from it up), held among
/// the process's walks ([`crate::budgets::WALKS`]) while it lasts.
struct Walking {
    lowest: u64,
    next: ChangeHash,
    runs: BTreeMap<u64, Box<[ChangeHash]>>,
    held: Held,
}

impl Walking {
    /// The hash checked at `seq`, if one was.
    fn hash(&self, seq: u64) -> Option<ChangeHash> {
        let (lowest, run) = self.runs.range(..=seq).next_back()?;
        run.get(usize::try_from(seq - lowest).ok()?).copied()
    }

    /// Extends `chain`'s walk among `walks` with `hashes`, those of the
    /// numbers from `lowest` up, `next` the `prev` of the lowest: whether
    /// it was. Not past the process's [`crate::budgets::WALKS`] (an
    /// availability limit, not a security one: a walk is the owner's
    /// chosen prefix, run by run as it checks): the walk is then
    /// refused, its hashes dropped and their places given back, before
    /// anything more is allocated.
    fn extend(
        walks: &mut BTreeMap<ChainId, Self>,
        budgets: &Budgets,
        chain: ChainId,
        (lowest, next): (u64, ChangeHash),
        hashes: &[ChangeHash],
    ) -> bool {
        let Some(held) = budgets.walk(hashes.len()) else {
            walks.remove(&chain);
            return false;
        };
        let run = Box::from(hashes);
        match walks.entry(chain) {
            btree_map::Entry::Occupied(mut walking) => {
                let walking = walking.get_mut();
                walking.held.merge(held);
                walking.runs.insert(lowest, run);
                walking.lowest = lowest;
                walking.next = next;
            }
            btree_map::Entry::Vacant(walking) => {
                walking.insert(Self {
                    lowest,
                    next,
                    runs: BTreeMap::from([(lowest, run)]),
                    held,
                });
            }
        }
        true
    }
}

/// The `log` subkeys of earlier epochs walked down from `top`, under the
/// membership head `head`.
struct History {
    head: Mark,
    top: u32,
    logs: BTreeMap<u32, Zeroizing<[u8; 32]>>,
}

/// What changes are sealed for: the share (its routing id and genesis),
/// the epoch now and its `log` subkey (the latest held, if not the
/// current one's).
pub(crate) struct Sealing {
    project: ProjectId,
    genesis: [u8; 32],
    epoch: u32,
    log: Zeroizing<[u8; 32]>,
}

/// A page of changes sealed for one request: `asked` (chain, after,
/// most), the chain's tip and freeze as they stood before it was read
/// (`held`), its envelopes in order, and whether more follow them.
pub(crate) struct Prepared {
    asked: (ChainId, u64, usize),
    held: (Option<Tip>, Option<u64>),
    envelopes: Vec<Vec<u8>>,
    more: bool,
}

impl Prepared {
    /// Whether it may still be served for `asked`: asked for that, and
    /// its chain admitted and frozen as when it was read (sync §3.6). A
    /// cut or fork since may have withdrawn what it holds.
    fn holds(&self, inner: &Inner, asked: (ChainId, u64, usize)) -> bool {
        self.asked == asked && self.held == held(inner, asked.0)
    }

    /// Its envelopes that fit `room` bytes (one at least), and whether
    /// more follow them.
    fn fitting(self, room: usize) -> (Vec<Vec<u8>>, bool) {
        let mut bytes = 0usize;
        let count = self
            .envelopes
            .iter()
            .enumerate()
            .take_while(|(n, envelope)| {
                bytes = bytes.saturating_add(envelope.len());
                *n == 0 || bytes <= room
            })
            .count();
        let more = self.more || count < self.envelopes.len();
        let mut envelopes = self.envelopes;
        envelopes.truncate(count);
        let more = more && !envelopes.is_empty();
        (envelopes, more)
    }
}

impl Sealing {
    /// The sealing `state` holds the key for, if it holds any.
    pub(crate) fn of(state: &State) -> Option<Self> {
        let project = state.membership.project();
        let genesis = state.membership.genesis()?;
        let now = state.membership.epoch();
        let (epoch, key) = state
            .keys
            .get_key_value(&now)
            .or_else(|| state.keys.last_key_value())?;
        Some(Self {
            project,
            genesis,
            epoch: *epoch,
            log: key.log(project),
        })
    }

    /// The admitted changes of `chain` after `after`, `most` at most and
    /// within a page, sealed by `inner`'s identity: read from the session
    /// and sealed with no lock of the peer's held.
    pub(crate) fn page(&self, inner: &Inner, chain: ChainId, after: u64, most: usize) -> Prepared {
        let room = PAGE_BYTES;
        let held = held(inner, chain);
        let session = inner.session();
        let changes = session.changes_after(chain, after, most, room);
        let by = SigningKey::from_bytes(&inner.secret);
        let mut envelopes = Vec::with_capacity(changes.len());
        let mut last = after;
        for change in &changes {
            let Ok(envelope) = crypto::seal(
                &self.log,
                self.project,
                &self.genesis,
                self.epoch,
                change,
                &by,
            ) else {
                break;
            };
            last = change.id().seq;
            envelopes.push(envelope);
        }
        let tip = session.tip(chain).map_or(0, |tip| tip.seq);
        Prepared {
            asked: (chain, after, most),
            held,
            more: !envelopes.is_empty() && last < tip,
            envelopes,
        }
    }
}

/// `chain`'s tip and the first number of it not kept, as `inner`'s
/// session holds them now.
fn held(inner: &Inner, chain: ChainId) -> (Option<Tip>, Option<u64>) {
    let session = inner.session();
    (session.tip(chain), session.frozen_from(chain))
}

/// The encoding of `signed` as records travel.
pub(crate) fn record_bytes(signed: &SignedRecord) -> Option<Vec<u8>> {
    bounded::encode(signed, MAX_RECORD).ok()
}

/// The share as the machine sees it: the peer's insides and its state,
/// locked.
pub(crate) struct View<'a> {
    pub(crate) inner: &'a Inner,
    pub(crate) state: &'a mut State,
}

impl View<'_> {
    /// [`Storage::take_records`]: each record of `records` (after number
    /// `after`) taken whole, as its own recoverable step, and counted in
    /// `taken` before the next is looked at; the first that fails stops
    /// the page there.
    fn take_each(
        &mut self,
        after: u64,
        records: &[&[u8]],
        taken: &mut Taken,
    ) -> Result<(), RecordsRefused> {
        let mut decoded = Vec::with_capacity(records.len());
        for bytes in records {
            let signed: SignedRecord =
                bounded::decode(bytes).map_err(|_| RecordsRefused::Invalid)?;
            decoded.push(signed);
        }
        let mut fresh = Vec::new();
        for (i, signed) in decoded.iter().enumerate() {
            let seq = after.saturating_add(1).saturating_add(i as u64);
            match self.state.membership.record(seq) {
                Some(held) if held == signed => continue,
                Some(_) => return Err(RecordsRefused::Mismatch),
                None => {}
            }
            if seq != self.state.membership.seq() + 1 + fresh.len() as u64 {
                return Err(RecordsRefused::Mismatch);
            }
            fresh.push(signed);
        }
        if fresh.is_empty() {
            return Ok(());
        }
        if self.state.membership.seq() == 0 && !self.inner.first_chain_fits(self.state, &fresh) {
            return Err(RecordsRefused::Invalid);
        }
        for signed in fresh {
            let record: Record =
                bounded::decode(&signed.bytes).map_err(|_| RecordsRefused::Invalid)?;
            let (seq, hash) = self.state.membership.head();
            if record.seq == seq + 1 && record.prev != hash {
                return Err(RecordsRefused::Mismatch);
            }
            if let Err(error) = self.inner.take_record(self.state, signed) {
                self.inner.tell(&Notice::Failed(error.to_string()));
                return Err(RecordsRefused::Invalid);
            }
            taken.records += 1;
        }
        Ok(())
    }

    /// The hash the walk of `chain`'s listed prefix checked at `seq`, if
    /// it did: from a backward walk from the listed hash only.
    fn walk_hash(&self, chain: ChainId, seq: u64) -> Option<ChangeHash> {
        self.state.book.walks.get(&chain)?.hash(seq)
    }

    /// Tells the machine what `applied` (changes taken or released, from
    /// `from` if they came over a link) came to; lists its refusals.
    pub(crate) fn take_applied(&mut self, applied: &Applied, from: Option<PublicKey>) {
        let book = &mut self.state.book;
        book.events
            .extend(applied.known.iter().map(|chain| Event::Known(*chain)));
        book.events
            .extend(applied.taken.iter().map(|(change, hash)| Event::Applied {
                change: *change,
                hash: *hash,
            }));
        for (chain, from) in &applied.frozen {
            book.events.push(Event::Frozen {
                chain: *chain,
                from: *from,
            });
            if *from <= 2 {
                self.inner.judge.forget(*chain);
            }
        }
        if let Some(from) = from
            && !applied.taken.is_empty()
        {
            let took = book.took.entry(from).or_default();
            took.0 += applied.taken.len();
            took.1 = applied.conflicts.len();
        }
        for refused in &applied.refused {
            self.inner.list(self.state, refused);
        }
        for failed in &applied.failed {
            self.inner.tell(&Notice::Failed(failed.clone()));
        }
    }

    /// The `log` subkey that opens envelopes sealed in `epoch`: of an
    /// epoch whose key is held, or derived from the latest held through
    /// the history links.
    fn log_key(&mut self, epoch: u32) -> Option<Zeroizing<[u8; 32]>> {
        let state = &mut *self.state;
        let project = state.membership.project();
        if let Some(key) = state.keys.get(&epoch) {
            return Some(key.log(project));
        }
        let head = state.membership.head();
        let (&top, key) = state.keys.last_key_value()?;
        if epoch > top {
            return None;
        }
        let walked = state
            .book
            .history
            .as_ref()
            .is_some_and(|history| history.head == head && history.top == top);
        if !walked {
            let logs = match state.membership.history(top, key, &state.keys) {
                Ok(subkeys) => subkeys
                    .into_iter()
                    .map(|(epoch, keys)| (epoch, Zeroizing::new(*keys.log())))
                    .collect(),
                Err(error) => {
                    self.inner.tell(&Notice::Failed(error.to_string()));
                    BTreeMap::new()
                }
            };
            state.book.history = Some(History { head, top, logs });
        }
        state
            .book
            .history
            .as_ref()
            .and_then(|history| history.logs.get(&epoch).cloned())
    }

    /// The machine's events from this install's own chains: each change
    /// admitted on them since last told, once the session said something
    /// changed.
    fn own_events(&mut self) {
        if !self.inner.own_dirty.swap(false, Ordering::SeqCst) {
            return;
        }
        let session = self.inner.session();
        let agents: BTreeSet<PublicKey> =
            session.agents().into_iter().map(|(key, _)| key).collect();
        let mut chains: BTreeSet<ChainId> = self.state.book.own.keys().copied().collect();
        chains.insert(session.chain());
        if !agents.is_empty() {
            chains.extend(
                session
                    .chains()
                    .into_iter()
                    .filter(|(_, author, _)| agents.contains(author))
                    .map(|(chain, ..)| chain),
            );
        }
        for chain in chains {
            let own = session.chain_origin(chain).is_some_and(|origin| {
                origin.author == self.inner.me || agents.contains(&origin.author)
            });
            let Some(tip) = session.tip(chain).filter(|_| own) else {
                continue;
            };
            let before = self.state.book.own.insert(chain, tip.seq);
            if before.is_none() {
                self.state.book.events.push(Event::Known(chain));
            }
            for seq in before.unwrap_or(0) + 1..=tip.seq {
                if let Some(head) = session.head_at(chain, seq) {
                    self.state.book.events.push(Event::Applied {
                        change: ChangeId { chain, seq },
                        hash: head.hash(),
                    });
                }
            }
        }
    }

    /// What `signed`, of a chain known here (of `origin`, its prefix
    /// `listed` by the first record if it is) comes to against the heads
    /// held: the same, a fork, frozen, turned away; `None` if it is the
    /// next change and is to be opened.
    fn against_held(
        &self,
        origin: ChainOrigin,
        signed: SignedHead,
        listed: Option<(u64, ChangeHash)>,
    ) -> Option<Admission> {
        let head = signed.head;
        let chain = head.chain;
        let session = self.inner.session();
        // Another head at a listed number is not of the share: no fork.
        let other = |admission: Admission| {
            if matches!(admission, Admission::Fork(_))
                && listed.is_some_and(|(through, _)| head.seq <= through)
            {
                Admission::TurnedAway
            } else {
                admission
            }
        };
        let compare = |seq: u64| match session.head_at(chain, seq) {
            Some(mine) if mine.hash() == signed.hash() => Admission::Same,
            Some(mine) => other(fork(origin, mine, signed)),
            None => Admission::Same,
        };
        if head.seq == 1 {
            return Some(compare(1));
        }
        if session
            .frozen_from(chain)
            .is_some_and(|from| head.seq >= from)
        {
            return Some(Admission::Frozen);
        }
        let Some(tip) = session.tip(chain) else {
            return Some(Admission::Frozen);
        };
        if head.seq <= tip.seq {
            return Some(compare(head.seq));
        }
        if head.seq > tip.seq + 1 {
            return Some(Admission::Same);
        }
        if let Some((through, hash)) = listed
            && (head.seq > through || (head.seq == through && signed.hash() != hash))
        {
            return Some(Admission::TurnedAway);
        }
        if head.prev != tip.hash {
            return Some(match session.head_at(chain, tip.seq) {
                Some(mine) => other(fork(origin, mine, signed)),
                None => Admission::Same,
            });
        }
        None
    }

    /// What taking `signed` from `from`, opened, `applied` came to.
    fn admission(&mut self, signed: SignedHead, applied: &Applied, from: PublicKey) -> Admission {
        let id = signed.head.id();
        let chain = id.chain;
        self.take_applied(applied, Some(from));
        if applied.taken.iter().any(|(taken, _)| *taken == id) {
            return Admission::Applied;
        }
        if let Some(proof) = applied.forks.iter().find(|proof| proof.chain() == chain) {
            self.state.book.forks.push(*proof);
            return Admission::Fork(Box::new(*proof));
        }
        if let Some(stop) = applied.stopped.iter().find(|stop| stop.id == id) {
            let stopped = |cause: Cause| Admission::Stopped {
                cause,
                head: Box::new(signed),
            };
            // A stop only on a chain known, from a body that opened and
            // matched its head; anything else is this source's to answer
            // for, on its link only.
            return match &stop.why {
                Stopped::Held(awaited) | Stopped::Full(awaited) => stopped(Cause::Change(*awaited)),
                Stopped::NotYet(cause) => stopped(*cause),
                Stopped::Declined | Stopped::Detached | Stopped::Sealing => Admission::Declined,
                Stopped::Turned(_) | Stopped::Unknown => Admission::TurnedAway,
                Stopped::OutOfOrder => Admission::Same,
            };
        }
        if let Some(refused) = applied
            .refused
            .iter()
            .find(|refused| refused.change == Some(id))
        {
            let frozen = self
                .inner
                .session()
                .frozen_from(chain)
                .is_some_and(|from| from <= id.seq);
            if frozen && applied.frozen.iter().any(|(at, _)| *at == chain) {
                return Admission::Never {
                    why: Why::new(&refused.why),
                };
            }
            return if frozen {
                Admission::Frozen
            } else {
                Admission::TurnedAway
            };
        }
        if applied.failed.is_empty() {
            Admission::Same
        } else {
            Admission::Declined
        }
    }
}

/// A fork of `origin`'s chain from the head held, `mine`, and `theirs`,
/// both signed by its author.
fn fork(origin: ChainOrigin, mine: SignedHead, theirs: SignedHead) -> Admission {
    ForkProof::new(origin, mine, theirs)
        .map_or(Admission::Invalid, |proof| Admission::Fork(Box::new(proof)))
}

impl Storage for View<'_> {
    fn genesis(&self) -> Hash {
        self.state.membership.genesis().unwrap_or_default()
    }

    fn membership(&self) -> Mark {
        self.state.membership.head()
    }

    fn record_hash(&self, seq: u64) -> Option<Hash> {
        self.state.membership.record_hash(seq)
    }

    fn is_member(&self, key: PublicKey) -> bool {
        self.state
            .membership
            .role(key)
            .is_some_and(|role| role != Role::Store)
    }

    fn can_ready(&self, remote: PublicKey) -> bool {
        let state = &*self.state;
        self.is_member(remote)
            && self.is_member(self.inner.me)
            && state.keys.contains_key(&state.membership.epoch())
            && self.inner.on_binary(state)
            && state.membership.genesis().is_some()
            && self.inner.session().genesis() == state.membership.genesis()
    }

    fn records_after(&self, after: u64, at: Hash) -> Records {
        let membership = &self.state.membership;
        match membership.record_hash(after) {
            None => {
                return Records::Page {
                    records: Vec::new(),
                    more: false,
                };
            }
            Some(hash) if hash != at => {
                return Records::Diverged(
                    membership
                        .record(after)
                        .and_then(record_bytes)
                        .unwrap_or_default(),
                );
            }
            Some(_) => {}
        }
        let rest = membership.since(after);
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for signed in rest.iter().take(RECORDS) {
            let Some(encoded) = record_bytes(signed) else {
                break;
            };
            if !records.is_empty() && bytes + encoded.len() > RECORDS_BYTES {
                break;
            }
            bytes += encoded.len();
            records.push(encoded);
        }
        let more = records.len() < rest.len();
        Records::Page { records, more }
    }

    fn take_records(
        &mut self,
        after: u64,
        records: &[&[u8]],
    ) -> (Taken, Result<(), RecordsRefused>) {
        let mut taken = Taken::default();
        let refused = self.take_each(after, records, &mut taken);
        (taken, refused)
    }

    fn recovering(&self) -> bool {
        self.state.recovery.is_some()
    }

    fn listed(&self, chain: ChainId) -> Option<(u64, ChangeHash)> {
        self.state.membership.before().get(&chain).copied()
    }

    fn local(&self) -> PublicKey {
        self.inner.me
    }

    fn tip(&self, chain: ChainId) -> Option<Tip> {
        self.inner.session().tip(chain)
    }

    fn tips_after(
        &self,
        after: Option<ChainId>,
        project: Option<ProjectId>,
        most: usize,
    ) -> (Vec<Tip>, Option<ChainId>) {
        self.inner
            .session()
            .tips_page(after, project, most, TIPS_SCAN)
    }

    fn head_at(&self, chain: ChainId, seq: u64) -> Option<SignedHead> {
        self.inner.session().head_at(chain, seq)
    }

    fn author(&self, chain: ChainId) -> Option<PublicKey> {
        self.inner
            .session()
            .chain_origin(chain)
            .map(|origin| origin.author)
    }

    fn origin(&self, chain: ChainId) -> Option<ProjectId> {
        self.inner
            .session()
            .chain_origin(chain)
            .map(|origin| origin.project)
    }

    fn changes_after(
        &mut self,
        chain: ChainId,
        after: u64,
        most: usize,
        room: usize,
    ) -> (Vec<Vec<u8>>, bool) {
        // A page sealed for this request before the lock was taken, if its
        // chain is as it was then; else sealed again now.
        if let Some(page) = self
            .state
            .book
            .prepared
            .take()
            .filter(|page| page.holds(self.inner, (chain, after, most)))
        {
            return page.fitting(room);
        }
        let Some(sealing) = Sealing::of(self.state) else {
            return (Vec::new(), false);
        };
        sealing.page(self.inner, chain, after, most).fitting(room)
    }

    fn evidence(&self, chain: ChainId) -> Option<ForkProof> {
        match self.inner.session().evidence(chain)? {
            Evidence::Proof(proof) => Some(*proof),
            Evidence::Refused(_) => None,
        }
    }

    fn frozen(&self, chain: ChainId) -> Option<u64> {
        self.inner.session().frozen_from(chain)
    }

    fn admit(&mut self, from: PublicKey, envelope: &Envelope<'_>) -> Admission {
        let Ok(signed) = SignedHead::parse(envelope.signed_head()) else {
            return Admission::Invalid;
        };
        let head = signed.head;
        let chain = head.chain;
        let known = self.inner.session().chain_origin(chain);
        let Some(origin) = known.or(head.origin) else {
            return Admission::TurnedAway;
        };
        if !head.well_formed() || !signed.verify(origin.author) {
            return Admission::Invalid;
        }
        if known.is_some()
            && let Some(admission) = self.against_held(origin, signed, self.listed(chain))
        {
            return admission;
        }
        // A listed prefix: every number at or below its listed end is
        // taken only on a hash a backward walk from the listed hash
        // checked, before the body is opened (sync §3.3); with none, it is
        // turned away and leaves nothing. Links, files and the API alike.
        if let Some((through, _)) = self.listed(chain)
            && head.seq <= through
            && self.walk_hash(chain, head.seq) != Some(signed.hash())
        {
            return Admission::TurnedAway;
        }
        if envelope.project() != self.state.membership.project() {
            return Admission::Declined;
        }
        // The epoch is its sealer's claim: a sealing this replica cannot
        // open is declined on its link and stops nothing (sync §2.2).
        let Some(genesis) = self.state.membership.genesis() else {
            return Admission::Declined;
        };
        let Some(log) = self.log_key(envelope.epoch()) else {
            return Admission::Declined;
        };
        let Some(body) = crypto::open(&log, &genesis, envelope, signed.hash()) else {
            return Admission::Declined;
        };
        let applied = self
            .inner
            .session()
            .receive(vec![SignedChange { head: signed, body }]);
        self.admission(signed, &applied, from)
    }

    fn verify(&self, chain: ChainId, head: &SignedHead) -> bool {
        self.author(chain).is_some_and(|author| {
            head.head.chain == chain && head.head.well_formed() && head.verify(author)
        })
    }

    fn prove(&self, theirs: &SignedHead) -> Option<ForkProof> {
        let chain = theirs.head.chain;
        if self.listed(chain).is_some() || !self.verify(chain, theirs) {
            return None;
        }
        let session = self.inner.session();
        let origin = session.chain_origin(chain)?;
        if let Some(mine) = session.head_at(chain, theirs.head.seq)
            && mine.hash() != theirs.hash()
        {
            return ForkProof::new(origin, mine, *theirs);
        }
        let before = session.head_at(chain, theirs.head.seq.checked_sub(1)?)?;
        (theirs.head.prev != before.hash())
            .then(|| ForkProof::new(origin, before, *theirs))
            .flatten()
    }

    fn prove_pair(&self, stopped: &SignedHead, theirs: &SignedHead) -> Option<ForkProof> {
        let chain = theirs.head.chain;
        if stopped.head.chain != chain
            || self.listed(chain).is_some()
            || !self.verify(chain, stopped)
            || !self.verify(chain, theirs)
        {
            return None;
        }
        let origin = self.inner.session().chain_origin(chain)?;
        ForkProof::new(origin, *stopped, *theirs)
    }

    fn take_fork(&mut self, proof: &ForkProof) -> ForkTaken {
        if let Some(at) = self.state.book.forks.iter().position(|held| held == proof) {
            self.state.book.forks.remove(at);
            return ForkTaken::Lowered;
        }
        if self.listed(proof.chain()).is_some() {
            return ForkTaken::Unknown;
        }
        match self.inner.session().take_fork(proof) {
            Ok(Kept::Unknown) => ForkTaken::Unknown,
            Ok(Kept::Invalid) => ForkTaken::Invalid,
            Ok(Kept::Held) => ForkTaken::Held,
            Ok(Kept::Lowered(place)) => {
                self.state.book.events.push(Event::Frozen {
                    chain: proof.chain(),
                    from: place,
                });
                if place <= 2 {
                    self.inner.judge.forget(proof.chain());
                }
                ForkTaken::Lowered
            }
            Err(error) => {
                self.inner.tell(&Notice::Failed(error.to_string()));
                ForkTaken::Held
            }
        }
    }

    fn events(&mut self) -> Vec<Event> {
        self.own_events();
        // What the session's turns came to since (a freeze's releases,
        // the changes it took out), told as taking changes is.
        let settled = self.inner.session().take_settled();
        self.take_applied(&settled, None);
        std::mem::take(&mut self.state.book.events)
    }

    fn walk(&self, chain: ChainId) -> Option<Walk> {
        self.state.book.walks.get(&chain).map(|walking| Walk {
            lowest: walking.lowest,
            next: walking.next,
        })
    }

    fn walk_extend(
        &mut self,
        chain: ChainId,
        lowest: u64,
        next: ChangeHash,
        hashes: &[ChangeHash],
    ) -> bool {
        Walking::extend(
            &mut self.state.book.walks,
            &self.inner.budgets,
            chain,
            (lowest, next),
            hashes,
        )
    }

    fn walk_end(&mut self, chain: ChainId) {
        self.state.book.walks.remove(&chain);
    }
}

/// The links' budgets as the machine draws from them.
pub(crate) struct Charges<'a> {
    pub(crate) links: &'a BTreeMap<LinkId, Arc<LinkBudget>>,
}

impl Budget for Charges<'_> {
    fn charge(&mut self, link: LinkId, bytes: usize) -> bool {
        self.links
            .get(&link)
            .is_some_and(|budget| budget.charge_sync(bytes))
    }

    fn refund(&mut self, link: LinkId, bytes: usize) {
        if let Some(budget) = self.links.get(&link) {
            budget.refund_sync(bytes);
        }
    }

    fn spend(&mut self, _: Option<LinkId>, _: Work) {}
}

#[cfg(test)]
mod tests {
    use binbun_sync::wire::RUN;

    use super::*;
    use crate::budgets::WALKS;

    /// The hash a walk checks at `seq`, made up.
    fn hash(seq: u64) -> ChangeHash {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&seq.to_le_bytes());
        ChangeHash(bytes)
    }

    /// Extends `chain`'s walk by the run of `RUN` numbers through `upto`.
    fn run(
        walks: &mut BTreeMap<ChainId, Walking>,
        budgets: &Budgets,
        chain: ChainId,
        upto: u64,
    ) -> bool {
        let lowest = upto + 1 - RUN as u64;
        let hashes: Vec<ChangeHash> = (lowest..=upto).map(hash).collect();
        Walking::extend(walks, budgets, chain, (lowest, hash(lowest - 1)), &hashes)
    }

    #[test]
    fn walks_past_the_process_ceiling_are_refused_and_give_back_what_they_held() {
        let budgets = Budgets::default();
        let mut walks = BTreeMap::new();
        let (long, other) = (ChainId([1; 16]), ChainId([2; 16]));
        // A walk of the longest listed prefix fills the ceiling run by run.
        let runs = (WALKS / RUN) as u64;
        let top = runs * RUN as u64 + 1;
        for n in 0..runs {
            assert!(run(&mut walks, &budgets, long, top - n * RUN as u64));
        }
        assert_eq!(budgets.walks_free(), 0);
        let walking = &walks[&long];
        assert_eq!(walking.held.count(), WALKS);
        let kept: usize = walking.runs.values().map(|run| run.len()).sum();
        assert_eq!(kept, WALKS);
        assert_eq!(walking.hash(top), Some(hash(top)));
        assert_eq!(walking.hash(2), Some(hash(2)));
        assert_eq!(walking.hash(1), None);
        // Another chain's walk is refused while it lasts, and holds nothing.
        assert!(!run(&mut walks, &budgets, other, 9000));
        assert!(!walks.contains_key(&other));
        // One more run of the long walk is refused: the walk is dropped and
        // what it held given back, so the other chain may walk.
        assert!(!run(&mut walks, &budgets, long, RUN as u64));
        assert!(walks.is_empty());
        assert_eq!(budgets.walks_free(), WALKS);
        assert!(run(&mut walks, &budgets, other, 9000));
        assert_eq!(budgets.walks_free(), WALKS - RUN);
        drop(walks);
        assert_eq!(budgets.walks_free(), WALKS);
    }
}
