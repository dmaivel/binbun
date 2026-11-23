//! Changes taken from outside the log (a peer's, a merged bundle's, a
//! session followed) and from the log itself at opening, each checked
//! before its ops join their keys (sync §2.1, §4.2): its chain is known
//! (its start verified and bound to this journal) and it follows it, its
//! author signed it, its body is the one its head commits to and reads
//! within its bounds, it is well formed, and every change its ops name is
//! taken (in a shared journal: admitted) or dead. Then, from outside the
//! log of a shared journal, the [`Authority`] judges it, immediately
//! before it is taken.
//!
//! - One waiting for another change is held ([`MAX_HELD`] changes of
//!   [`MAX_HELD_BYTES`] at most) until that one is taken or dies; one
//!   that cannot be taken now is not kept: its chain is stopped
//!   ([`Stop`]), and it comes again.
//! - One its author signed wrongly for good (`Never`: malformed, or its
//!   author may never write it) freezes its chain from it, its signed head
//!   kept as evidence; two heads of one place freeze it from there, the
//!   two kept as a [`ForkProof`]. Evidence and freezes are written before
//!   they take effect.
//! - A start bound elsewhere is turned away and leaves nothing.
//!
//! Replay of the log calls no authority: the marks say what was admitted.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::store::Read;
use super::{
    Body, Cause, ChainId, ChangeHash, ChangeId, Conflict, Evidence, ForkProof, FrozenBy,
    HistoryEntry, Journal, Key, MAX_OPS, MAX_START, Op, OpId, ProjectId, PublicKey, Record,
    SignedChange, SignedHead, Tip, Verdict, Why, now, owns,
};

/// A change refused, and why.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Refused {
    /// The change, if it reads.
    pub change: Option<ChangeId>,
    /// Its chain's author, if known.
    pub author: Option<PublicKey>,
    /// Why.
    pub why: String,
}

/// Why a change was not taken now, nor refused for good.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Stopped {
    /// It waits, held, for this change.
    Held(ChangeId),
    /// It would wait for this change, but the held changes are at their
    /// bound: not kept.
    Full(ChangeId),
    /// The authority does not take it now (a change of a chain known).
    NotYet(Cause),
    /// A start the authority does not take now (its grant's record not
    /// here yet, a local guard, the engine rule): its chain is not known,
    /// so nothing stops; it is declined where it came from.
    Declined,
    /// Its chain is not known here (no verified start).
    Unknown,
    /// It is past the next number of its chain here.
    OutOfOrder,
    /// Its body is not the one its head commits to: a fault of whoever
    /// sealed it, no fork.
    Sealing,
    /// The journal is a share's and no authority is attached.
    Detached,
    /// A start bound to another share or binary, of an author the share
    /// never named, past the bound of chains known, or no start; or a
    /// change past the prefix the share lists of its chain: turned away,
    /// nothing kept.
    Turned(String),
}

/// A chain stopped at a change: its signed head (verified, unless the
/// chain is unknown or the start turned away), and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stop {
    /// The change.
    pub id: ChangeId,
    /// Its signed head.
    pub head: SignedHead,
    /// Why.
    pub why: Stopped,
}

/// What taking changes came to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// The changes taken, as the history lists them.
    pub changes: Vec<HistoryEntry>,
    /// The changes taken (in a shared journal: admitted), starts included,
    /// with their hashes, in the order taken.
    pub taken: Vec<(ChangeId, ChangeHash)>,
    /// The chains that became known (their starts taken).
    pub known: Vec<ChainId>,
    /// The chains frozen, from which change (any cause).
    pub frozen: Vec<(ChainId, u64)>,
    /// The fork proofs found or lowered (kept, their chains frozen).
    pub forks: Vec<ForkProof>,
    /// The keys with more than one value after them.
    pub conflicts: Vec<Conflict>,
    /// The changes refused (for good, or not signed by their chain's
    /// author) and those a freeze took out (in the turns after it,
    /// [`crate::Session::settle`]).
    pub refused: Vec<Refused>,
    /// The changes stopped: not taken now, and why.
    pub stopped: Vec<Stop>,
    /// How many are held, waiting for a change before them.
    pub held: usize,
    /// Whether they change what recovery takes (corrections): the binary
    /// is to be analysed anew.
    pub reanalyse: bool,
    /// The writes that failed (what they would have kept is not kept).
    pub failed: Vec<String>,
}

/// How far each chain is known: its last change's number, by chain (the
/// snapshot format's).
pub type VersionVector = BTreeMap<ChainId, u64>;

/// What became of a fork proof given to [`Journal::take_fork`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkTaken {
    /// Its chain is not known here (or of another origin): nothing kept.
    Unknown,
    /// It does not verify.
    Invalid,
    /// Kept, and the chain frozen from its place, lower than any proof
    /// before.
    Lowered(u64),
    /// A proof at its place or lower is kept already.
    Held,
}

/// What became of a start given to [`Journal::learn_chain`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Learnt {
    /// Its chain is known now.
    New,
    /// It is known already, with this start.
    Known,
    /// Another start of its chain is kept: the two are a fork at 1.
    Fork(Box<ForkProof>),
    /// Not taken.
    Not(Stopped),
    /// Not signed by the author its origin names, or no start.
    Refused(String),
}

/// Where changes come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// From outside the log: judged by the authority in a shared journal.
    Remote,
    /// From the log, at opening: what was taken before, judged nothing
    /// anew.
    Replay,
}

/// What became of one change.
enum Outcome {
    Taken(Arc<Record>),
    /// A start taken as its chain's witness, the chain refused for good
    /// from it (its grant does not give its author a role, or a later
    /// record closed it at its start).
    Closed(Arc<Record>, Why),
    Known,
    Held {
        signed: Box<SignedChange>,
        awaited: ChangeId,
    },
    Stopped(Stopped),
    Refused(String),
    Never(Why),
    Fork(Box<ForkProof>),
}

/// More than 60 s ahead of this clock: its author's clock is flagged.
const AHEAD_MS: u64 = 60_000;

/// The most changes held waiting for others.
pub(super) const MAX_HELD: usize = 4096;

/// The most bytes of the changes held (as signed).
pub(super) const MAX_HELD_BYTES: usize = 16 << 20;

/// The most refusals listed: the oldest go first.
pub(super) const MAX_REFUSED: usize = 1024;

/// The most chains known in one journal.
pub const MAX_CHAINS: usize = 65_536;

/// The most chains of one author known in one journal.
pub const MAX_CHAINS_PER_AUTHOR: usize = 4096;

/// The most ops a batch of a freeze's withdrawal takes out of the keys
/// (a change with more is a batch of its own): the keys recomputed in one
/// hold (sync §4.3).
pub(super) const WITHDRAW_BATCH: usize = 1024;

/// The most held changes let go in one turn (sync §3.5): the rest wait
/// for the next.
pub(super) const MAX_RELEASED: usize = 256;

impl Journal {
    /// The changes held waiting for change `id`, let go.
    fn release(&mut self, id: ChangeId) -> Vec<SignedChange> {
        self.release_some(id, usize::MAX)
    }

    /// The first `most` changes held waiting for change `id`, let go.
    fn release_some(&mut self, id: ChangeId, most: usize) -> Vec<SignedChange> {
        let Some(waiting) = self.held.get_mut(&id) else {
            return Vec::new();
        };
        let released: Vec<SignedChange> = if waiting.len() <= most {
            self.held.remove(&id).unwrap_or_default()
        } else {
            waiting.drain(..most).collect()
        };
        self.holding -= released.len();
        self.held_bytes -= released
            .iter()
            .map(|signed| signed.body.len())
            .sum::<usize>();
        released
    }

    /// Up to `most` changes held whose wait is over: what each waits for
    /// counts (taken, in a shared journal admitted) or is dead, or it is
    /// of a chain frozen at or before it (dropped). Whether more may be is
    /// kept ([`Self::releasing`]).
    fn released(&mut self, most: usize) -> Vec<SignedChange> {
        let over: Vec<ChangeId> = self
            .held
            .keys()
            .filter(|id| self.satisfies(**id, Source::Remote))
            .copied()
            .collect();
        let mut released = Vec::new();
        for id in over {
            let room = most.saturating_sub(released.len());
            if room == 0 {
                break;
            }
            released.extend(self.release_some(id, room));
        }
        self.releasing = released.len() >= most;
        released
            .into_iter()
            .filter(|signed| !self.is_frozen(signed.id()))
            .collect()
    }

    /// Lists `refused`, the latest [`MAX_REFUSED`] kept.
    fn list(&mut self, refused: Refused) {
        self.list_all(vec![refused]);
    }

    /// Lists each of `refused`, the latest [`MAX_REFUSED`] kept.
    fn list_all(&mut self, refused: Vec<Refused>) {
        self.refused.extend(refused);
        let past = self.refused.len().saturating_sub(MAX_REFUSED);
        self.refused.drain(..past);
    }

    /// Takes `incoming` from `source`: each change checked, taken, held,
    /// stopped or refused; then the changes held that a change taken lets
    /// go: from outside the log, [`MAX_RELEASED`] at most, the rest left
    /// for the next turn ([`Self::settle_step`]); a freeze's are let go
    /// there too. The keys whose ops changed are `touched`.
    pub(crate) fn apply(
        &mut self,
        incoming: Vec<SignedChange>,
        touched: &mut BTreeSet<Key>,
        source: Source,
    ) -> Applied {
        self.apply_within(incoming, touched, source, 0)
    }

    /// [`Self::apply`], `released` changes let go already this turn.
    fn apply_within(
        &mut self,
        incoming: Vec<SignedChange>,
        touched: &mut BTreeSet<Key>,
        source: Source,
        mut released: usize,
    ) -> Applied {
        let mut applied = Applied::default();
        // Taken in the order they came (a chain's in order); those let go
        // next.
        let mut queue = incoming;
        queue.reverse();
        while let Some(signed) = queue.pop() {
            let id = signed.id();
            let head = signed.head;
            let author = self.chains.get(&id.chain).map(|chain| chain.author);
            match self.receive_one(signed, source) {
                Outcome::Taken(record) => {
                    touched.extend(record.body.ops.iter().map(|op| op.key.clone()));
                    let room = match source {
                        Source::Replay => usize::MAX,
                        Source::Remote => MAX_RELEASED.saturating_sub(released),
                    };
                    let let_go = self.release_some(record.id, room);
                    released += let_go.len();
                    if self.held.contains_key(&record.id) {
                        self.releasing = true;
                    }
                    queue.extend(let_go.into_iter().rev());
                    if record.is_start() {
                        applied.known.push(record.id.chain);
                    } else if Self::begins(&record) {
                        applied.changes.push(self.entry(&record));
                    }
                    if source == Source::Remote {
                        self.unsaved.push(record.id);
                        if let Some(share) = &mut self.share {
                            share
                                .admitted
                                .insert(record.id.chain, (record.id.seq, record.hash));
                        }
                    }
                    if self.counts(record.id) {
                        applied.taken.push((record.id, record.hash));
                    }
                }
                Outcome::Closed(record, why) => {
                    applied.known.push(record.id.chain);
                    self.unsaved.push(record.id);
                    if let Some(share) = &mut self.share {
                        share
                            .admitted
                            .insert(record.id.chain, (record.id.seq, record.hash));
                    }
                    applied.taken.push((record.id, record.hash));
                    let refused = Refused {
                        change: Some(id),
                        author: Some(record.author),
                        why: why.as_str().to_owned(),
                    };
                    self.list(refused.clone());
                    applied.refused.push(refused);
                    let never = self.never(head);
                    Self::froze(never, &mut applied);
                }
                Outcome::Known => {}
                Outcome::Held { signed, awaited } => {
                    if let Some(why) = self.hold(*signed, awaited) {
                        applied.stopped.push(Stop { id, head, why });
                    }
                }
                Outcome::Stopped(why) => applied.stopped.push(Stop { id, head, why }),
                Outcome::Refused(why) => {
                    let refused = Refused {
                        change: Some(id),
                        author,
                        why,
                    };
                    self.list(refused.clone());
                    applied.refused.push(refused);
                }
                Outcome::Never(why) => {
                    let refused = Refused {
                        change: Some(id),
                        author,
                        why: why.as_str().to_owned(),
                    };
                    self.list(refused.clone());
                    applied.refused.push(refused);
                    let never = self.never(head);
                    Self::froze(never, &mut applied);
                }
                Outcome::Fork(proof) => {
                    let kept = self.keep_fork(&proof);
                    let lowered = matches!(kept, Ok((ForkTaken::Lowered(_), _)));
                    if Self::froze(kept.map(|(_, frozen)| frozen), &mut applied) && lowered {
                        applied.forks.push(*proof);
                    }
                }
            }
        }
        applied.held = self.holding;
        applied.reanalyse = touched
            .iter()
            .any(|key| matches!(key, Key::Item(_) | Key::Bounds(_) | Key::DebugFile));
        applied
            .changes
            .sort_by_key(|entry| std::cmp::Reverse((entry.time, entry.id)));
        applied
    }

    /// Holds `signed` until change `awaited` is taken or dies, if there is
    /// room (held already: nothing); why it stops.
    fn hold(&mut self, signed: SignedChange, awaited: ChangeId) -> Option<Stopped> {
        if self
            .held
            .get(&awaited)
            .is_some_and(|waiting| waiting.contains(&signed))
        {
            return None;
        }
        let size = signed.body.len();
        if self.holding >= MAX_HELD || self.held_bytes.saturating_add(size) > MAX_HELD_BYTES {
            return Some(Stopped::Full(awaited));
        }
        self.held.entry(awaited).or_default().push(signed);
        self.holding += 1;
        self.held_bytes += size;
        Some(Stopped::Held(awaited))
    }

    /// Adds what a freeze came to (`frozen`) to `applied`; whether it took
    /// effect (a write that failed is listed).
    fn froze(frozen: Result<Applied, String>, applied: &mut Applied) -> bool {
        match frozen {
            Ok(frozen) => {
                applied.frozen.extend(frozen.frozen);
                applied.refused.extend(frozen.refused);
                true
            }
            Err(error) => {
                applied.failed.push(error);
                false
            }
        }
    }

    /// Whether change `id`, taken, counts as admitted: any in a journal of
    /// no share; in a share's, one at or below its chain's mark as
    /// admitted.
    fn counts(&self, id: ChangeId) -> bool {
        match &self.share {
            None => true,
            Some(share) => share
                .admitted
                .get(&id.chain)
                .is_some_and(|(seq, _)| id.seq <= *seq),
        }
    }

    /// One change from `source`: checked, then taken, held, stopped or
    /// refused.
    fn receive_one(&mut self, signed: SignedChange, source: Source) -> Outcome {
        let id = signed.id();
        if !signed.head.head.well_formed() {
            return Outcome::Refused("a head whose origin does not make its chain".to_owned());
        }
        if self.is_frozen(id) && id.seq > 1 {
            return Outcome::Refused(format!(
                "its chain is frozen from change {}",
                self.frozen.get(&id.chain).map_or(0, |(from, _)| *from)
            ));
        }
        if id.seq == 1 {
            return self.start_of(signed, source);
        }
        let Some(chain) = self.chains.get(&id.chain) else {
            return Outcome::Stopped(Stopped::Unknown);
        };
        let (author, last, tip) = (chain.author, chain.seq, chain.hash);
        let grant = chain.bound.share.map(|under| under.grant);
        if !signed.head.verify(author) {
            return Outcome::Refused("its signature does not verify".to_owned());
        }
        if let Some(held) = self.head_held(id) {
            return if held.hash() == signed.hash() {
                Outcome::Known
            } else {
                self.fork_of(held, signed.head, source)
            };
        }
        if id.seq > last + 1 {
            let before = ChangeId {
                chain: id.chain,
                seq: id.seq - 1,
            };
            let waits = self.held.values().flatten().any(|held| held.id() == before);
            return if waits {
                Outcome::Held {
                    signed: Box::new(signed),
                    awaited: before,
                }
            } else {
                Outcome::Stopped(Stopped::OutOfOrder)
            };
        }
        if signed.head.head.prev != tip {
            return match self.head_held(ChangeId {
                chain: id.chain,
                seq: last,
            }) {
                Some(ours) => self.fork_of(ours, signed.head, source),
                None => Outcome::Stopped(Stopped::OutOfOrder),
            };
        }
        if !signed.opens() {
            return match source {
                Source::Remote => Outcome::Stopped(Stopped::Sealing),
                Source::Replay => {
                    Outcome::Refused("its body is not the one its head commits to".to_owned())
                }
            };
        }
        let body = match Body::decode(&signed.body) {
            Ok(body) => body,
            Err(why) => return Self::never_from(source, &why),
        };
        if let Some(why) = self.malformed(id, author, &body) {
            return Self::never_from(source, &why);
        }
        if let Some(why) = self.past_listed(id, signed.hash()) {
            return Outcome::Stopped(Stopped::Turned(why));
        }
        if let Some(awaited) = self.awaited(id, &body, source) {
            return Outcome::Held {
                signed: Box::new(signed),
                awaited,
            };
        }
        // A prefix the share's first record lists is authorised by the
        // listing alone; every other chain of the share by its grant.
        if source == Source::Remote && self.share.is_some() && self.listed(id.chain).is_none() {
            let Some(authority) = &self.authority else {
                return Outcome::Stopped(Stopped::Detached);
            };
            let Some(grant) = grant else {
                return Outcome::Stopped(Stopped::Turned(
                    "a chain of no share that the share does not list".to_owned(),
                ));
            };
            match authority.admit(author, grant, &signed.head.head, &body) {
                Verdict::Admit => {}
                Verdict::NotYet(cause) => return Outcome::Stopped(Stopped::NotYet(cause)),
                Verdict::Decline => return Outcome::Stopped(Stopped::Declined),
                Verdict::Never(why) => return Outcome::Never(why),
            }
        }
        Outcome::Taken(self.taken(signed, body, author))
    }

    /// `signed` with `body`, of `author`, as a record taken: the clock
    /// moved past it, its ops in their keys.
    fn taken(&mut self, signed: SignedChange, body: Body, author: PublicKey) -> Arc<Record> {
        let now = now();
        if body.hlc.millis() > now.saturating_add(AHEAD_MS) {
            self.ahead.insert(author);
        }
        self.clock = self.clock.receive(body.hlc, now);
        let record = Arc::new(Record {
            id: signed.id(),
            hash: signed.hash(),
            body,
            signed,
            author,
        });
        self.take(&record);
        record
    }

    /// A chain's start from `source`: verified, bound to this journal,
    /// of an author the share names or named, within the bounds of chains
    /// known, and (from outside, in a share) taken by the authority under
    /// the grant it names; then its chain is known. One the authority
    /// refuses for good is still taken as its chain's witness, the chain
    /// frozen from it.
    fn start_of(&mut self, signed: SignedChange, source: Source) -> Outcome {
        let Some(origin) = signed.head.head.origin else {
            return Outcome::Refused("a first change that names no origin".to_owned());
        };
        if let Some(chain) = self.chains.get(&signed.id().chain) {
            let start = chain.start.head;
            return if start.hash() == signed.hash() {
                Outcome::Known
            } else if signed.head.verify(origin.author) {
                self.fork_of(start, signed.head, source)
            } else {
                Outcome::Refused("its signature does not verify".to_owned())
            };
        }
        if !signed.head.verify(origin.author) {
            return Outcome::Refused("its signature does not verify".to_owned());
        }
        if !signed.opens() {
            return Outcome::Stopped(Stopped::Sealing);
        }
        let turned = |why: &str| Outcome::Stopped(Stopped::Turned(why.to_owned()));
        let Ok(body) = Body::decode(&signed.body) else {
            return turned("a start that does not read");
        };
        if !body.is_start() || signed.body.len() > MAX_START {
            return turned("a start that is more than a start");
        }
        if let Some(why) = self.routes(signed.id().chain, &body) {
            return turned(why);
        }
        let theirs = self
            .chains
            .values()
            .filter(|chain| chain.author == origin.author)
            .count();
        if self.chains.len() >= MAX_CHAINS || theirs >= MAX_CHAINS_PER_AUTHOR {
            return turned("past the most chains known");
        }
        let mut closed = None;
        if source == Source::Remote
            && self.share.is_some()
            && self.listed(signed.id().chain).is_none()
        {
            let Some(authority) = &self.authority else {
                return Outcome::Stopped(Stopped::Detached);
            };
            if !authority.knows(origin.author) {
                return turned("a start by an author the share never named");
            }
            let Some(under) = body.bound.as_ref().and_then(|bound| bound.share) else {
                return turned("a start of no share that the share does not list");
            };
            match authority.admit(origin.author, under.grant, &signed.head.head, &body) {
                Verdict::Admit => {}
                Verdict::NotYet(_) | Verdict::Decline => {
                    return Outcome::Stopped(Stopped::Declined);
                }
                Verdict::Never(why) => closed = Some(why),
            }
        }
        let record = self.taken(signed, body, origin.author);
        match closed {
            Some(why) => Outcome::Closed(record, why),
            None => Outcome::Taken(record),
        }
    }

    /// Why a chain whose start says `body` is not of this journal, if it
    /// is not: in a share's, its start names the share and this binary, or
    /// names no share and this binary and the share lists it; in another,
    /// it names this binary.
    fn routes(&self, chain: ChainId, body: &Body) -> Option<&'static str> {
        let bound = body.bound.as_ref()?;
        if bound.of != self.of {
            return Some("a start bound to another binary");
        }
        match (&self.share, bound.share) {
            (None, _) => None,
            (Some(share), Some(under)) if under.genesis == share.genesis => None,
            (Some(share), None) if share.before.contains_key(&chain) => None,
            (Some(_), _) => Some("a start bound to another share"),
        }
    }

    /// The prefix the share's first record lists of chain `chain` (up to
    /// which number, the hash there), if it lists it and the chain is
    /// begun in no share: authorised by the listing alone, touched by no
    /// fork and no cut (sync §14.2).
    pub(super) fn listed(&self, chain: ChainId) -> Option<(u64, ChangeHash)> {
        let &prefix = self.share.as_ref()?.before.get(&chain)?;
        self.chains
            .get(&chain)
            .is_none_or(|known| known.bound.share.is_none())
            .then_some(prefix)
    }

    /// Why change `id` (hash `hash`) is not of the share, if its chain is
    /// one the share's first record lists and it is past the number listed
    /// or another change than the one listed there.
    fn past_listed(&self, id: ChangeId, hash: ChangeHash) -> Option<String> {
        let share = self.share.as_ref()?;
        let chain = self.chains.get(&id.chain)?;
        if chain.bound.share.is_some() {
            return None;
        }
        let &(through, listed) = share.before.get(&id.chain)?;
        if id.seq > through {
            Some(format!(
                "past change {through}, as far as the share lists its chain"
            ))
        } else if id.seq == through && hash != listed {
            Some("not the change the share lists at its number".to_owned())
        } else {
            None
        }
    }

    /// What a `Never` from `source` is: from outside, a freeze; from the
    /// log, a refusal (replay judges nothing anew).
    fn never_from(source: Source, why: &str) -> Outcome {
        match source {
            Source::Remote => Outcome::Never(Why::new(why)),
            Source::Replay => Outcome::Refused(why.to_owned()),
        }
    }

    /// The fork `ours` and `theirs` (both verified) make, from `source`.
    fn fork_of(&self, ours: SignedHead, theirs: SignedHead, source: Source) -> Outcome {
        let Some(origin) = self.chains.get(&ours.head.chain).map(|chain| chain.origin) else {
            return Outcome::Stopped(Stopped::Unknown);
        };
        if self.listed(ours.head.chain).is_some() {
            // Another branch of a listed prefix is not of the share.
            return Outcome::Stopped(Stopped::Turned(
                "another change at a number of a prefix the share lists".to_owned(),
            ));
        }
        match (ForkProof::new(origin, ours, theirs), source) {
            (Some(proof), Source::Remote) => Outcome::Fork(Box::new(proof)),
            (Some(_), Source::Replay) => {
                Outcome::Refused("a second change at one place of its chain".to_owned())
            }
            (None, _) => Outcome::Refused("its signature does not verify".to_owned()),
        }
    }

    /// The signed head of change `id`, if taken (its chain's start
    /// included).
    fn head_held(&self, id: ChangeId) -> Option<SignedHead> {
        if id.seq == 1 {
            return self.chains.get(&id.chain).map(|chain| chain.start.head);
        }
        self.records.get(&id).map(|record| record.signed.head)
    }

    /// Why change `id`'s body `body`, of `author`, is malformed, if it is:
    /// a value its key cannot take, too many ops, a binding past a start,
    /// another's bookmark, a group part that does not continue its group,
    /// conversation that names itself wrongly or is too long.
    fn malformed(&self, id: ChangeId, author: PublicKey, body: &Body) -> Option<String> {
        if body.ops.len() > MAX_OPS {
            return Some("too many edits in one change".to_owned());
        }
        if body.bound.is_some() {
            return Some("a change past its chain's start that binds it".to_owned());
        }
        for op in &body.ops {
            if !op.value.fits(&op.key) {
                return Some(format!("a value its key cannot take: {:?}", op.key));
            }
            if !owns(&op.key, author) {
                return Some(format!(
                    "{:?} is another's bookmark: each author's bookmarks are their own",
                    op.key
                ));
            }
        }
        if let Some(group) = body.group {
            if !group.holds(id.seq) {
                return Some("a part of a group it cannot be in".to_owned());
            }
            if group.first != id.seq {
                let before = self.records.get(&ChangeId {
                    chain: id.chain,
                    seq: id.seq - 1,
                });
                let continues = before.is_some_and(|before| {
                    before.body.group == Some(group)
                        && before.body.label == body.label
                        && before.body.origin == body.origin
                });
                if !continues {
                    return Some("a part of a group that does not follow its group".to_owned());
                }
            }
        }
        super::talk::malformed(id, body)
    }

    /// A change change `id` (body `body`) names that does not count yet:
    /// in its ops' causes, or making a thread, post or suggestion they
    /// name. A change counts once taken (from outside a shared journal:
    /// admitted) or dead (frozen at or before it).
    pub(super) fn awaited(&self, id: ChangeId, body: &Body, source: Source) -> Option<ChangeId> {
        body.ops
            .iter()
            .flat_map(|op| op.prev.iter())
            .map(|prev| prev.change)
            .chain(super::talk::named(id, body))
            .find(|named| *named != id && !self.satisfies(*named, source))
    }

    /// Whether change `id` satisfies a dependency of a change from
    /// `source`.
    fn satisfies(&self, id: ChangeId, source: Source) -> bool {
        self.is_frozen(id)
            || (self.records.contains_key(&id) && (source == Source::Replay || self.counts(id)))
    }

    /// Whether change `id` is of a chain frozen at or before it.
    pub(super) fn is_frozen(&self, id: ChangeId) -> bool {
        self.frozen
            .get(&id.chain)
            .is_some_and(|(from, _)| id.seq >= *from)
    }

    /// Freezes chain `chain` from change `from` on, in memory only (the
    /// caller keeps it in the log first), by marking it alone (sync
    /// §4.3): from now on its changes from there (never its start) are not
    /// told, served, depended on or taken, its head is moved back before
    /// them, held changes of it from there are dropped and this author's
    /// undo and redo forget them. Their ops leave the keys afterwards, a
    /// batch at a time, each listed refused then, and the held changes the
    /// freeze lets go are taken then too ([`Self::settle_step`]). The work
    /// here is the held cache's and the steps', not the history's. It is
    /// counted: an undo planned before it is planned again.
    fn mark_frozen(&mut self, chain: ChainId, from: u64, by: FrozenBy) {
        let from = from.max(1);
        self.freezes = self.freezes.wrapping_add(1);
        match self.frozen.get_mut(&chain) {
            Some((known, _)) if *known <= from => {}
            Some(known) => *known = (from, by),
            None => {
                self.frozen.insert(chain, (from, by));
            }
        }
        let gone_from = from.max(2);
        let before = gone_from - 1;
        if let Some(hash) = self
            .head_held(ChangeId { chain, seq: before })
            .map(|head| head.hash())
            && let Some(known) = self.chains.get_mut(&chain)
            && known.seq > before
        {
            known.seq = before;
            known.hash = hash;
        }
        // Compared with the mark, not looked up among the changes.
        let past =
            |id: Option<ChangeId>| id.is_some_and(|id| id.chain == chain && id.seq >= gone_from);
        self.undo.retain(|step| !past(step.change));
        self.redo
            .retain(|(step, undo)| !past(step.change) && !past(*undo));
        self.drop_held(chain, from);
        let range = ChangeId {
            chain,
            seq: gone_from,
        }..=ChangeId {
            chain,
            seq: u64::MAX,
        };
        if self.records.range(range).next().is_some() {
            let at = self.withdrawing.entry(chain).or_insert(gone_from);
            *at = (*at).min(gone_from);
        }
        self.releasing = true;
    }

    /// Drops the held changes of chain `chain` from change `from` on.
    fn drop_held(&mut self, chain: ChainId, from: u64) {
        let waiting: Vec<ChangeId> = self.held.keys().copied().collect();
        for awaited in waiting {
            let kept: Vec<SignedChange> = self
                .release(awaited)
                .into_iter()
                .filter(|signed| !(signed.id().chain == chain && signed.id().seq >= from))
                .collect();
            for signed in kept {
                self.holding += 1;
                self.held_bytes += signed.body.len();
                self.held.entry(awaited).or_default().push(signed);
            }
        }
    }

    /// Whether freezes or releases are left to settle
    /// ([`Self::settle_step`]).
    pub(crate) fn busy(&self) -> bool {
        !self.withdrawing.is_empty() || self.releasing
    }

    /// One turn of what freezes and releases left: the changes past a
    /// freeze not yet taken out, up to [`WITHDRAW_BATCH`] ops of them (at
    /// least one change), out of the keys and listed refused; with none
    /// left, up to [`MAX_RELEASED`] held changes whose wait is over let go
    /// and taken, each through the authority. The keys whose ops changed
    /// are `touched`. What it came to.
    pub(crate) fn step(&mut self, touched: &mut BTreeSet<Key>) -> Applied {
        if !self.withdrawing.is_empty() {
            return self.withdraw_batch(touched);
        }
        if !self.releasing {
            return Applied::default();
        }
        let released = self.released(MAX_RELEASED);
        let count = released.len();
        self.apply_within(released, touched, Source::Remote, count)
    }

    /// Takes the next batch of a frozen chain's changes past its freeze
    /// out of the keys and the history ([`Self::step`]).
    fn withdraw_batch(&mut self, touched: &mut BTreeSet<Key>) -> Applied {
        let Some((&chain, &from)) = self.withdrawing.first_key_value() else {
            return Applied::default();
        };
        let why = self
            .frozen
            .get(&chain)
            .map_or_else(|| "frozen".to_owned(), |(_, by)| format!("frozen: {by}"));
        let range = ChangeId { chain, seq: from }..=ChangeId {
            chain,
            seq: u64::MAX,
        };
        let mut ids = Vec::new();
        let mut ops = 0usize;
        let mut rest = false;
        for (id, record) in self.records.range(range) {
            let size = record.body.ops.len().max(1);
            if !ids.is_empty() && ops + size > WITHDRAW_BATCH {
                rest = true;
                break;
            }
            ops += size;
            ids.push(*id);
        }
        if !rest {
            self.withdrawing.remove(&chain);
        }
        let mut keys = BTreeSet::new();
        let mut refused = Vec::new();
        for id in ids {
            let Some(record) = self.records.remove(&id) else {
                continue;
            };
            for (index, op) in record.body.ops.iter().enumerate() {
                let Ok(index) = u16::try_from(index) else {
                    break;
                };
                if let Some(register) = self.registers.get_mut(&op.key) {
                    register.remove_op(OpId { change: id, index });
                }
                keys.insert(op.key.clone());
            }
            refused.push(Refused {
                change: Some(id),
                author: Some(record.author),
                why: why.clone(),
            });
        }
        // Conversation it held is told again (gone).
        for key in &keys {
            if let Some(id) = key.talk() {
                self.heard.push((key.clone(), id));
            }
        }
        self.list_all(refused.clone());
        touched.extend(keys);
        Applied {
            refused,
            ..Applied::default()
        }
    }

    /// Takes the ops of changes frozen and not yet taken out of the keys
    /// out of `key` now (the work of its register, not of the history):
    /// what a commit does to each key it reads or writes, so that it names
    /// no frozen op and restores no frozen value.
    pub(super) fn settle_key(&mut self, key: &Key) {
        if self.withdrawing.is_empty() {
            return;
        }
        let withdrawing = &self.withdrawing;
        if let Some(register) = self.registers.get_mut(key) {
            register.remove(|op| {
                withdrawing
                    .get(&op.change.chain)
                    .is_some_and(|from| op.change.seq >= *from)
            });
        }
    }

    /// `ops`, a commit's, each naming no frozen op: one whose `prev` names
    /// one (a freeze marked since it was written) has its key's frozen ops
    /// taken out ([`Self::settle_key`]) and names the key's leaves then.
    pub(super) fn unfrozen(&mut self, mut ops: Vec<Op>) -> Vec<Op> {
        for op in &mut ops {
            if op.prev.iter().any(|prev| self.is_frozen(prev.change)) {
                self.settle_key(&op.key);
                op.prev = self
                    .registers
                    .get(&op.key)
                    .map(|register| register.leaves().map(|(id, _)| *id).collect())
                    .unwrap_or_default();
            }
        }
        ops
    }

    /// Takes the frozen ops not yet taken out of the keys step `id` (a
    /// change, or a group's first part) wrote out of them now
    /// ([`Self::settle_key`]): what undoing or redoing it reads.
    pub(super) fn settle_step_keys(&mut self, id: ChangeId) {
        if self.withdrawing.is_empty() {
            return;
        }
        let keys: BTreeSet<Key> = self
            .parts(id)
            .iter()
            .flat_map(|part| part.body.ops.iter().map(|op| op.key.clone()))
            .collect();
        for key in &keys {
            self.settle_key(key);
        }
    }

    /// What collaboration has not been told of the turns since last asked
    /// ([`Self::step`]), the refusals the latest [`MAX_REFUSED`].
    pub(crate) fn take_settled(&mut self) -> Applied {
        std::mem::take(&mut self.settled)
    }

    /// Keeps what a turn came to, `applied`, for collaboration, if it is
    /// attached.
    pub(super) fn keep_settled(&mut self, applied: &Applied) {
        if self.authority.is_none() {
            return;
        }
        let settled = &mut self.settled;
        settled.taken.extend_from_slice(&applied.taken);
        settled.known.extend_from_slice(&applied.known);
        settled.frozen.extend_from_slice(&applied.frozen);
        settled.forks.extend_from_slice(&applied.forks);
        settled.refused.extend_from_slice(&applied.refused);
        settled.failed.extend_from_slice(&applied.failed);
        let past = settled.refused.len().saturating_sub(MAX_REFUSED);
        settled.refused.drain(..past);
    }

    /// Takes chain `chain`'s changes from `from` on (never its start) out
    /// of the keys, listed refused because `why`, and the held changes of
    /// it from there; the keys whose ops changed, and the changes taken
    /// out.
    pub(super) fn withdraw(
        &mut self,
        chain: ChainId,
        from: u64,
        why: &str,
    ) -> (BTreeSet<Key>, Vec<Refused>) {
        let (keys, gone) = self.take_out(chain, from.max(2));
        let mut dropped = Vec::new();
        for record in &gone {
            let refused = Refused {
                change: Some(record.id),
                author: Some(record.author),
                why: why.to_owned(),
            };
            self.list(refused.clone());
            dropped.push(refused);
        }
        // Conversation it held is told again (gone).
        for key in &keys {
            if let Some(id) = key.talk() {
                self.heard.push((key.clone(), id));
            }
        }
        self.drop_held(chain, from);
        (keys, dropped)
    }

    /// Takes chain `chain`'s changes from `gone_from` on (at least 2: never
    /// its start) out of the keys, the history, undo and redo, its head
    /// moved back before them; the keys whose ops changed, and the changes
    /// taken out.
    fn take_out(&mut self, chain: ChainId, gone_from: u64) -> (BTreeSet<Key>, Vec<Arc<Record>>) {
        let range = ChangeId {
            chain,
            seq: gone_from,
        }..=ChangeId {
            chain,
            seq: u64::MAX,
        };
        let ids: BTreeSet<ChangeId> = self.records.range(range).map(|(id, _)| *id).collect();
        let mut keys = BTreeSet::new();
        let mut gone = Vec::new();
        for id in &ids {
            if let Some(record) = self.records.remove(id) {
                keys.extend(record.body.ops.iter().map(|op| op.key.clone()));
                gone.push(record);
            }
        }
        for key in &keys {
            if let Some(register) = self.registers.get_mut(key) {
                register.remove(|op| op.change.chain == chain && op.change.seq >= gone_from);
            }
        }
        let before = gone_from - 1;
        if let Some(hash) = self
            .head_held(ChangeId { chain, seq: before })
            .map(|head| head.hash())
            && let Some(known) = self.chains.get_mut(&chain)
            && known.seq > before
        {
            known.seq = before;
            known.hash = hash;
        }
        let kept = |id: Option<ChangeId>| id.is_none_or(|id| !ids.contains(&id));
        self.undo.retain(|step| kept(step.change));
        self.redo
            .retain(|(step, undo)| kept(step.change) && kept(*undo));
        (keys, gone)
    }

    /// Takes back changes `staged`, taken from outside the log of a share's
    /// journal, whose write or marks failed (sync §4.5 rule 1): out of the
    /// keys, the history, the dependencies and what `applied` tells, their
    /// conversation not told, a chain whose start is among them not known;
    /// they come again. What was admitted here and not marked is admitted
    /// no longer: this install's own such work is pending again. The keys
    /// whose ops changed.
    pub(super) fn take_back(
        &mut self,
        staged: &[ChangeId],
        applied: &mut Applied,
    ) -> BTreeSet<Key> {
        let staged: BTreeSet<ChangeId> = staged
            .iter()
            .filter(|id| self.records.contains_key(id))
            .copied()
            .collect();
        let mut from: BTreeMap<ChainId, u64> = BTreeMap::new();
        for id in &staged {
            from.entry(id.chain).or_insert(id.seq);
        }
        let mut keys = BTreeSet::new();
        let mut unknown = BTreeSet::new();
        for (chain, from) in from {
            keys.extend(self.take_out(chain, from.max(2)).0);
            if from == 1 {
                self.records.remove(&ChangeId { chain, seq: 1 });
                self.chains.remove(&chain);
                unknown.insert(chain);
            }
        }
        self.unsaved.retain(|id| !staged.contains(id));
        self.heard.retain(|(_, op)| !staged.contains(&op.change));
        if let Some(share) = &mut self.share {
            share.admitted.clone_from(&share.marks);
        }
        applied.taken.retain(|(id, _)| !staged.contains(id));
        applied.changes.retain(|entry| !staged.contains(&entry.id));
        applied.known.retain(|chain| !unknown.contains(chain));
        keys
    }

    /// Writes `frozen` and `evidence` to the log (evidence first; nothing
    /// in an ephemeral session).
    ///
    /// # Errors
    ///
    /// The log cannot be written.
    fn keep_frozen(
        &mut self,
        frozen: &super::store::Freezes,
        evidence: Option<&BTreeMap<ChainId, Evidence>>,
    ) -> Result<(), String> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        if store.project()?.is_none() {
            store.create(self.project, &self.of)?;
        }
        if let Some(evidence) = evidence {
            store.set_evidence(evidence)?;
        }
        store.set_frozen(frozen)
    }

    /// Freezes chains `freezes` (each from a change, for a cause): the log
    /// keeping them first, then marked ([`Self::mark_frozen`]); what they take out
    /// and let go follows in turns ([`Self::settle_step`]).
    ///
    /// # Errors
    ///
    /// They cannot be written: none takes effect.
    pub(crate) fn freeze_durably(
        &mut self,
        freezes: &[(ChainId, u64, FrozenBy)],
    ) -> Result<Applied, String> {
        let mut next = self.frozen.clone();
        let mut lowered = Vec::new();
        for &(chain, from, by) in freezes {
            // No cut reaches into a prefix the share lists.
            let from = from.max(self.listed(chain).map_or(1, |(through, _)| through + 1));
            if next.get(&chain).is_none_or(|(known, _)| from < *known) {
                next.insert(chain, (from, by));
                lowered.push((chain, from, by));
            }
        }
        if lowered.is_empty() {
            return Ok(Applied::default());
        }
        self.keep_frozen(&next, None)?;
        let mut frozen = Applied::default();
        for (chain, from, by) in lowered {
            self.mark_frozen(chain, from, by);
            frozen.frozen.push((chain, from));
        }
        Ok(frozen)
    }

    /// Freezes the chain of `head` (refused for good) from it: its head
    /// kept as evidence (unless a proof is), both written first, then
    /// marked ([`Self::mark_frozen`]). What it came to.
    fn never(&mut self, head: SignedHead) -> Result<Applied, String> {
        let (chain, from) = (head.head.chain, head.head.seq);
        if self
            .frozen
            .get(&chain)
            .is_some_and(|(known, _)| *known <= from)
        {
            return Ok(Applied::default());
        }
        let mut evidence = self.evidence.clone();
        if !matches!(evidence.get(&chain), Some(Evidence::Proof(_))) {
            evidence.insert(chain, Evidence::Refused(Box::new(head)));
        }
        let mut frozen = self.frozen.clone();
        frozen.insert(chain, (from, FrozenBy::Never));
        self.keep_frozen(&frozen, Some(&evidence))?;
        self.evidence = evidence;
        self.mark_frozen(chain, from, FrozenBy::Never);
        Ok(Applied {
            frozen: vec![(chain, from)],
            ..Applied::default()
        })
    }

    /// Keeps fork proof `proof` if it is of a chain known here and lower
    /// than any kept, and freezes the chain from its place: proof and
    /// freeze written first, then marked ([`Self::mark_frozen`]). What became of
    /// it, and what the freeze came to.
    ///
    /// # Errors
    ///
    /// The log cannot be written: nothing is kept.
    pub(crate) fn keep_fork(&mut self, proof: &ForkProof) -> Result<(ForkTaken, Applied), String> {
        if !proof.verify() {
            return Ok((ForkTaken::Invalid, Applied::default()));
        }
        let chain = proof.chain();
        if self
            .chains
            .get(&chain)
            .is_none_or(|known| known.origin != proof.origin)
            || self.listed(chain).is_some()
        {
            return Ok((ForkTaken::Unknown, Applied::default()));
        }
        let place = proof.place();
        if let Some(Evidence::Proof(kept)) = self.evidence.get(&chain)
            && kept.place() <= place
        {
            return Ok((ForkTaken::Held, Applied::default()));
        }
        let mut evidence = self.evidence.clone();
        evidence.insert(chain, Evidence::Proof(Box::new(*proof)));
        let mut frozen = self.frozen.clone();
        if frozen.get(&chain).is_none_or(|(from, _)| place < *from) {
            frozen.insert(chain, (place, FrozenBy::Fork));
        }
        self.keep_frozen(&frozen, Some(&evidence))?;
        self.evidence = evidence;
        self.mark_frozen(chain, place, FrozenBy::Fork);
        Ok((
            ForkTaken::Lowered(place),
            Applied {
                frozen: vec![(chain, place)],
                ..Applied::default()
            },
        ))
    }

    /// Takes fork proof `proof` ([`Self::keep_fork`]): marked in this
    /// hold, whatever the chain's length; what it takes out and lets go
    /// follows in turns ([`Self::settle_step`]).
    ///
    /// # Errors
    ///
    /// The log cannot be written: nothing is kept.
    pub(crate) fn take_fork(&mut self, proof: &ForkProof) -> Result<(ForkTaken, Applied), String> {
        let (taken, mut frozen) = self.keep_fork(proof)?;
        if let ForkTaken::Lowered(_) = taken {
            frozen.forks.push(*proof);
        }
        Ok((taken, frozen))
    }

    /// Takes chain start `start` from outside the log: its chain known if
    /// it is bound here, of an author the share names or named, within
    /// the bounds of chains known.
    pub(crate) fn learn_chain(
        &mut self,
        start: SignedChange,
        touched: &mut BTreeSet<Key>,
    ) -> Learnt {
        if start.id().seq != 1 {
            return Learnt::Refused("no chain's start".to_owned());
        }
        let known = self.chains.contains_key(&start.id().chain);
        let mut applied = self.apply(vec![start], touched, Source::Remote);
        if let Some(proof) = applied.forks.pop() {
            Learnt::Fork(Box::new(proof))
        } else if !applied.known.is_empty() {
            Learnt::New
        } else if let Some(stop) = applied.stopped.pop() {
            Learnt::Not(stop.why)
        } else if let Some(refused) = applied.refused.pop() {
            Learnt::Refused(refused.why)
        } else if known {
            Learnt::Known
        } else {
            Learnt::Refused(applied.failed.join("; "))
        }
    }

    /// Judges the held changes again (after a membership record): those
    /// of chains frozen dropped now; those whose wait is over taken or
    /// stopped through the authority in turns ([`Self::settle_step`]), not
    /// in this hold; the rest held still.
    pub(crate) fn recheck_held(&mut self) -> Applied {
        let waiting: Vec<ChangeId> = self.held.keys().copied().collect();
        for awaited in waiting {
            let kept: Vec<SignedChange> = self
                .release(awaited)
                .into_iter()
                .filter(|signed| !self.is_frozen(signed.id()))
                .collect();
            for signed in kept {
                self.holding += 1;
                self.held_bytes += signed.body.len();
                self.held.entry(awaited).or_default().push(signed);
            }
        }
        self.releasing = true;
        Applied {
            held: self.holding,
            ..Applied::default()
        }
    }

    /// Chain `chain` as told: how far it is admitted here, below any fork
    /// (a fork at its first: the empty tip); none for a chain not known, or
    /// whose start is not admitted.
    pub(crate) fn tip(&self, chain: ChainId) -> Option<Tip> {
        let known = self.chains.get(&chain)?;
        let fork = match self.evidence.get(&chain) {
            Some(Evidence::Proof(proof)) => proof.place(),
            Some(Evidence::Refused(_)) | None => 0,
        };
        let project = known.origin.project;
        if fork == 1 {
            return Some(Tip {
                chain,
                project,
                seq: 0,
                hash: ChangeHash::ZERO,
                fork,
            });
        }
        let mut seq = match &self.share {
            Some(share) => share.marks.get(&chain).map_or(0, |(seq, _)| *seq),
            None => known.seq,
        };
        if seq == 0 {
            return None;
        }
        if let Some((from, _)) = self.frozen.get(&chain) {
            seq = seq.min(from.saturating_sub(1)).max(1);
        }
        let hash = self.head_held(ChangeId { chain, seq })?.hash();
        Some(Tip {
            chain,
            project,
            seq,
            hash,
            fork,
        })
    }

    /// The tips of the chains after `after` (exclusive; none: from the
    /// first), ascending by chain, `most` at most.
    pub(crate) fn tips_after(&self, after: Option<ChainId>, most: usize) -> Vec<Tip> {
        let range = match after {
            Some(after) => self
                .chains
                .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded)),
            None => self.chains.range(..),
        };
        range
            .filter_map(|(&chain, _)| self.tip(chain))
            .take(most)
            .collect()
    }

    /// A page of the tips of the chains after `after` (exclusive; none:
    /// from the first), ascending by chain, of origin `project` if one is
    /// given: `most` at most, from `scan` chains looked at at most, so it
    /// may come back short or empty. With it, the last chain looked at if
    /// any is left past it: where the next page starts.
    pub(crate) fn tips_page(
        &self,
        after: Option<ChainId>,
        project: Option<ProjectId>,
        most: usize,
        scan: usize,
    ) -> (Vec<Tip>, Option<ChainId>) {
        let mut range = match after {
            Some(after) => self
                .chains
                .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded)),
            None => self.chains.range(..),
        }
        .peekable();
        let mut tips = Vec::new();
        let mut last = None;
        for _ in 0..scan {
            if tips.len() >= most {
                break;
            }
            let Some((&chain, known)) = range.next() else {
                break;
            };
            last = Some(chain);
            if project.is_none_or(|project| known.origin.project == project)
                && let Some(tip) = self.tip(chain)
            {
                tips.push(tip);
            }
        }
        let next = range.peek().and(last);
        (tips, next)
    }

    /// The signed head of change `seq` of chain `chain`, if it is told
    /// here (at or below its tip; the start always).
    pub(crate) fn head_at(&self, chain: ChainId, seq: u64) -> Option<SignedHead> {
        if seq != 1 && seq > self.tip(chain)?.seq {
            return None;
        }
        self.head_held(ChangeId { chain, seq })
    }

    /// The start of chain `chain`, as verified: kept whatever is frozen
    /// after it.
    pub(crate) fn start(&self, chain: ChainId) -> Option<SignedChange> {
        self.chains.get(&chain).map(|known| known.start.clone())
    }

    /// The changes of chain `chain` past number `after`, in order, as told
    /// here (at or below its tip; the start for `after` 0, whatever the
    /// tip): `most` at most, and `bytes` at most as encoded (one past it,
    /// if it is the first).
    pub(crate) fn changes_after(
        &self,
        chain: ChainId,
        after: u64,
        most: usize,
        bytes: usize,
    ) -> Vec<SignedChange> {
        let Some(known) = self.chains.get(&chain) else {
            return Vec::new();
        };
        let tip = self.tip(chain).map_or(0, |tip| tip.seq);
        let mut changes = Vec::new();
        let mut size = 0usize;
        let mut push = |signed: &SignedChange, changes: &mut Vec<SignedChange>| {
            let length = signed.encode().len();
            if changes.len() >= most || (!changes.is_empty() && size + length > bytes) {
                return false;
            }
            size += length;
            changes.push(signed.clone());
            true
        };
        if after == 0 && !push(&known.start, &mut changes) {
            return changes;
        }
        let from = after.max(1).saturating_add(1);
        if from > tip {
            return changes;
        }
        let range = ChangeId { chain, seq: from }..=ChangeId { chain, seq: tip };
        for record in self.records.range(range).map(|(_, record)| record) {
            if !push(&record.signed, &mut changes) {
                break;
            }
        }
        changes
    }

    /// The evidence kept of chain `chain`.
    pub(crate) fn evidence(&self, chain: ChainId) -> Option<Evidence> {
        self.evidence.get(&chain).cloned()
    }

    /// The first number of chain `chain` no longer kept, if it is frozen
    /// (any cause).
    pub(crate) fn frozen_from(&self, chain: ChainId) -> Option<u64> {
        self.frozen.get(&chain).map(|(from, _)| *from)
    }

    /// The latest [`MAX_REFUSED`] changes refused.
    pub(crate) fn refused(&self) -> &[Refused] {
        &self.refused
    }

    /// The authors whose clocks run ahead (a change stamped more than 60 s
    /// past this clock).
    pub(crate) fn ahead(&self) -> &BTreeSet<PublicKey> {
        &self.ahead
    }

    /// The chains of a log `read` gave, as replay takes them: in a share's
    /// journal each chain no further than its mark, unless it is written
    /// here (then what is past the mark is pending); a chain of another's
    /// past its mark cut back to it in the file (a crash between a change
    /// and its mark: it comes again). In a journal of no share a chain's
    /// file that does not read is listed and passed over.
    ///
    /// # Errors
    ///
    /// In a share's journal: a chain's file does not read (what it holds
    /// of the marks cannot be checked), a mark names a chain with no file
    /// or a change the log does not hold at its number; or a chain's file
    /// cannot be cut. The log is not opened as shared then.
    pub(crate) fn replayed(
        &mut self,
        read: Vec<(ChainId, Read)>,
        store: &mut super::store::Store,
    ) -> Result<Vec<SignedChange>, String> {
        let files: BTreeSet<ChainId> = read.iter().map(|(chain, _)| *chain).collect();
        if let Some(share) = &self.share
            && let Some(chain) = share.marks.keys().find(|chain| !files.contains(chain))
        {
            return Err(format!(
                "the mark of chain {chain} names a chain the log has no file of: the log is not \
                 opened as shared"
            ));
        }
        let mut changes = Vec::new();
        for (chain, read) in read {
            let held = match read {
                Read::Changes(held) => held,
                Read::Unreadable(why) if self.share.is_some() => {
                    return Err(format!(
                        "{why}: a share's log with a chain that does not read is not opened"
                    ));
                }
                Read::Unreadable(why) => {
                    self.list(Refused {
                        change: None,
                        author: None,
                        why,
                    });
                    continue;
                }
            };
            let Some(share) = &self.share else {
                changes.extend(held);
                continue;
            };
            let mark = share.marks.get(&chain).copied();
            if let Some((seq, hash)) = mark {
                let at = held.iter().find(|signed| signed.id().seq == seq);
                if at.is_none_or(|signed| signed.hash() != hash) {
                    return Err(format!(
                        "the mark of chain {chain} names a change its log does not hold: \
                         the log is not opened as shared"
                    ));
                }
                if share
                    .before
                    .get(&chain)
                    .is_some_and(|(through, _)| seq > *through)
                {
                    return Err(format!(
                        "the mark of chain {chain} is past the prefix the share lists"
                    ));
                }
            }
            let upto = mark.map_or(0, |(seq, _)| seq);
            if self.mine.contains(&chain) {
                changes.extend(held);
            } else {
                if held.iter().any(|signed| signed.id().seq > upto) {
                    store.cut(chain, upto + 1)?;
                }
                changes.extend(held.into_iter().filter(|signed| signed.id().seq <= upto));
            }
        }
        Ok(changes)
    }
}
