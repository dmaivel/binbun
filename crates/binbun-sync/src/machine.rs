//! The sync protocol of one journal over all its links (sync §3), as a
//! state machine without I/O: [`Machine::on_message`],
//! [`Machine::on_local`] and [`Machine::on_timer`] each return the
//! messages to send and the effects for the caller ([`Output`]).
//!
//! - **Phases** (§3.6): a link is in Bootstrap until each side has sent
//!   `Ready` and accepted the other's, then Reader. Bootstrap passes only
//!   the membership head, records and `Ready`; anything else closes the
//!   link. A link whose other side a record removes is Revoked: its
//!   generation passes, and nothing made for the old one may be written
//!   ([`Machine::is_current`]).
//! - **Per link** (§3.1): `told` holds the other side's tips exactly as
//!   it told them, and nothing else writes it: only an inbound `Tips`,
//!   `TipsPage` or `Summary` acknowledges a tip, and only an inbound
//!   `MembershipHead`, `Ready` or `Summary` the membership (P12). `sent` is what
//!   was pushed, for scheduling only. Requests carry ids, at most 8 out
//!   each way (4 `Want`, one each of the others; [`REQUESTS`]); each
//!   reply is checked against its request before it is used. Tasks, one
//!   per chain, at most 3 per told tip and 4 running, pull, bisect, ask
//!   for proofs, compare stopped heads and walk listed prefixes.
//! - **Per journal**: stops (§4.4), one per chain with the signed head
//!   judged, woken by index; another verified head at a stop's number is
//!   proved against it on the spot. The walks of listed prefixes, one per
//!   chain. What a link declined (a sealing that cannot be opened here, a
//!   start not taken now) is not asked of that link again until this
//!   replica's membership head or the link's changes, a chain freezes, a
//!   key arrives or the link's build changes.
//! - Each inbound message causes at most one request; scheduled tasks
//!   start on [`Machine::on_timer`] and on local events.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use std::time::Duration;

use binbun_bounded::{Bounded, PageBuilder};
use binbun_session::journal::{
    Cause, ChainId, ChangeHash, ChangeId, ForkProof, Head, MAX_CHAINS, ProjectId, PublicKey,
    SignedHead, Tip,
};

use crate::budget::{Budget, PER_CHAIN, PER_DECLINED, Work};
use crate::envelope::Envelope;
use crate::storage::{Admission, Event, ForkTaken, Records, RecordsRefused, Storage, Taken};
use crate::wire::{
    BOOTSTRAP_FRAME, CHANGES, Digest, EnvelopeBytes, FRAME, FRESH, HeadBytes, Mark, PAGE_BYTES,
    PROBE, ProofBytes, RECORDS, RECORDS_BYTES, REFUSED, RUN, RecordBytes, SignedHeadBytes, Sync,
    TIPS, TIPS_PAGE, Why,
};

/// A request's time from the taking of its slot to the reading of its
/// reply.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// How often a Reader link is sent a `Summary`.
pub const SUMMARY_EVERY: Duration = Duration::from_secs(30);

/// The least time between two resets of one link's view after its
/// digests disagreed twice.
pub const RESET_EVERY: Duration = Duration::from_mins(1);

/// Replies with no outstanding id a link may send before it is closed.
pub const STRAYS: u8 = 16;

/// The most pages of one walk of a link's tips: an honest walk of a share
/// takes [`MAX_CHAINS`] / [`TIPS_PAGE`] full pages and [`MAX_CHAINS`] /
/// [`crate::TIPS_SCAN`] scans that found too few (sync §3.2). Past it,
/// the responder is moving its cursor without end, and the link closes.
pub const TIPS_WALK: u16 = 144;

/// Tasks per told tip.
pub const ATTEMPTS: u8 = 3;

/// Tasks running at once per link.
pub const RUNNING: usize = 4;

/// `Want`s outstanding per link, each way.
pub const WANTS: usize = 4;

/// Requests outstanding per link, each way: [`WANTS`] `Want`s and one
/// each of the other four kinds (records, tips, probes and walks, forks).
/// The other side's count as outstanding until the last byte of their
/// reply is written, made at once or built later as a page alike: the
/// caller writing them closes a link that would pass it.
pub const REQUESTS: usize = WANTS + 4;

/// A stop's first wait before it is retried; it doubles to [`STOP_MOST`].
pub const STOP_FIRST: Duration = Duration::from_secs(1);

/// A stop's longest wait.
pub const STOP_MOST: Duration = Duration::from_mins(5);

/// Bytes of a page's message around its items.
const AROUND_PAGE: usize = 64;

/// A link, numbered by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub u64);

/// Where a link is (§3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// From link-up until each side has sent `Ready` and accepted the
    /// other's.
    Bootstrap,
    /// After that.
    Reader,
    /// A record removed the other side: nothing more passes.
    Revoked,
    /// Closed for a fault; nothing more passes.
    Closed,
}

/// Why the machine closed a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// A frame past its phase's limit, or one that does not decode.
    Malformed,
    /// A message its phase does not allow.
    Phase(&'static str),
    /// A reply that fails its validity against its request.
    Reply(&'static str),
    /// A request past the slots.
    Requests,
    /// Too many replies with no outstanding id.
    Strays,
    /// A request unanswered past its deadline.
    Stalled,
    /// The other side's genesis is not this share's.
    Genesis,
    /// This link's membership chain does not match.
    Membership,
    /// Records that do not verify.
    Records,
    /// It names too many chains, or its state passed its budget.
    TooManyChains,
    /// A tip's origin that its chain's start proved false.
    Claim,
    /// A head or proof that does not verify.
    Invalid,
    /// The other side is no longer a member: the kick.
    Revoked,
    /// It asked for records while this side's chain does not name it a
    /// member.
    NotServed,
    /// The share is in recovery: it serves and takes nothing.
    Recovering,
}

/// A page to build once the caller holds a page permit: answered by
/// [`Machine::serve`], which checks the link is still of `generation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    /// The link.
    pub link: LinkId,
    /// The generation it was made for.
    pub generation: u64,
    /// What to build.
    pub page: Page,
}

/// What a [`Job`] builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// The answer to a `Want`.
    Changes {
        /// The request.
        id: u32,
        /// The chain.
        chain: ChainId,
        /// After this number.
        after: u64,
        /// Whose hash the asker holds.
        at: ChangeHash,
        /// At most this many.
        most: u16,
    },
    /// The answer to a `RecordsAsk`.
    Records {
        /// The request.
        id: u32,
        /// After this number.
        after: u64,
        /// Whose hash the asker holds.
        at: [u8; 32],
    },
    /// A change just applied, pushed.
    Fresh {
        /// The change.
        change: ChangeId,
    },
}

/// A message to write on a link, if the link is still of `generation`
/// when the writer takes it up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Send {
    /// The link.
    pub link: LinkId,
    /// The generation it was made for.
    pub generation: u64,
    /// The message.
    pub message: Sync,
}

/// What the other side of a link told, kept for a flush's report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Its tips as told.
    pub tips: BTreeMap<ChainId, Tip>,
    /// Its membership head as it last told it (`MembershipHead`, `Ready`
    /// or `Summary`).
    pub membership: Option<Mark>,
}

impl Report {
    /// Whether it says the other side has `chain` up to `seq`: its told
    /// tip is at or past `seq` and is this side's head at the told number.
    pub fn has(&self, storage: &impl Storage, chain: ChainId, seq: u64) -> bool {
        self.tips.get(&chain).is_some_and(|tip| {
            tip.seq >= seq
                && storage
                    .head_at(chain, tip.seq)
                    .is_some_and(|head| head.hash() == tip.hash)
        })
    }

    /// Whether it says the other side has the membership chain up to
    /// `seq`: its told head is at or past `seq` and is this side's record
    /// at the told number.
    pub fn has_membership(&self, storage: &impl Storage, seq: u64) -> bool {
        self.membership
            .is_some_and(|(told, hash)| told >= seq && storage.record_hash(told) == Some(hash))
    }
}

/// What the caller is to do besides sending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Close the link (and, for [`Closed::Revoked`], kick it first).
    Close {
        /// The link.
        link: LinkId,
        /// Why.
        why: Closed,
    },
    /// Build a page when a permit is held.
    Serve(Job),
    /// The link reached Reader: its live and blob lanes open, and pending
    /// work goes through `admit`.
    Reader(LinkId),
    /// The other side refused changes of this replica's.
    Refused {
        /// Who refused.
        from: PublicKey,
        /// The changes, each held here and made by this replica.
        changes: Vec<(ChangeId, Vec<u8>)>,
    },
    /// The other side holds another membership record at a number: shown
    /// beside this side's, nothing chosen.
    Diverged {
        /// The link.
        link: LinkId,
        /// The number: the head this side asked after.
        at: u64,
        /// Its record as signed.
        record: Vec<u8>,
    },
    /// A link was dropped: what it had told, for the flush's report.
    Unlinked {
        /// The link.
        link: LinkId,
        /// Its remote.
        remote: PublicKey,
        /// What it had told.
        report: Report,
    },
}

/// What one call gives the caller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// Messages to send.
    pub sends: Vec<Send>,
    /// Effects.
    pub effects: Vec<Effect>,
}

/// Something that happened here, not on a link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Local {
    /// A link came up to `remote`, whose key the transport proved.
    Linked {
        /// The link.
        link: LinkId,
        /// The proved key.
        remote: PublicKey,
    },
    /// A link went.
    Unlinked(LinkId),
    /// The journal changed (the user's own changes, releases): its events
    /// are to be read.
    Journal,
    /// Membership records were taken here.
    Membership(Taken),
    /// The key of an epoch arrived.
    Key(u32),
    /// The build of `remote`'s link changed.
    Build(PublicKey),
    /// Something `Ready` waits for changed (a key, the binary), or a
    /// record was taken elsewhere: a link whose other side it removed is
    /// revoked, whatever its phase.
    Readiness,
}

/// One chain's tip as a link told it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Told {
    /// The tip.
    pub tip: Tip,
    /// A pull for it took nothing: it causes no further pull.
    pub tried: bool,
    /// Tasks made for it.
    pub attempts: u8,
}

/// A request of mine outstanding.
#[derive(Clone, Debug)]
struct Asked {
    deadline: Duration,
    ask: Ask,
}

#[derive(Clone, Debug)]
enum Ask {
    Records {
        after: u64,
    },
    Tips {
        after: Option<ChainId>,
        project: Option<ProjectId>,
    },
    Want {
        chain: ChainId,
        after: u64,
        most: u16,
    },
    Probe {
        chain: ChainId,
        seqs: Vec<u64>,
    },
    Heads {
        chain: ChainId,
        upto: u64,
        n: u64,
        expect: ChangeHash,
    },
    Fork {
        chain: ChainId,
    },
}

/// The slot a request takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Want,
    Records,
    Tips,
    Probe,
    Fork,
}

impl Ask {
    fn slot(&self) -> Slot {
        match self {
            Self::Records { .. } => Slot::Records,
            Self::Tips { .. } => Slot::Tips,
            Self::Want { .. } => Slot::Want,
            Self::Probe { .. } | Self::Heads { .. } => Slot::Probe,
            Self::Fork { .. } => Slot::Fork,
        }
    }
}

/// Work scheduled for one chain on one link.
#[derive(Clone, Debug)]
struct Task {
    kind: Kind,
    running: bool,
}

/// A link's way out of Bootstrap (§3.3 step 3).
#[derive(Clone, Copy, Debug, Default)]
struct Bootstrap {
    /// This side sent `Ready`.
    sent: bool,
    /// The other's `Ready` was accepted.
    accepted: bool,
    /// The other side's membership head as it last said.
    their_head: Option<Mark>,
    /// The membership head its `Ready` named.
    their_ready: Option<Mark>,
}

#[derive(Clone, Debug)]
enum Kind {
    Pull,
    Witness {
        hi: u64,
        restarted: bool,
    },
    Bisect {
        lo: u64,
        hi: u64,
        witness: Box<SignedHead>,
        restarted: bool,
    },
    AskFork,
    /// Compares the stop's head (judged here, not admitted) with the one
    /// the link holds at its number.
    Compare {
        stopped: Box<SignedHead>,
        hash: ChangeHash,
    },
    Walk,
}

#[derive(Clone, Debug)]
struct Link {
    remote: PublicKey,
    generation: u64,
    phase: Phase,
    bootstrap: Bootstrap,
    told: BTreeMap<ChainId, Told>,
    told_membership: Option<Mark>,
    told_digest: Option<(u32, [u8; 32])>,
    mismatches: u8,
    reset_at: Option<Duration>,
    sent: BTreeMap<ChainId, (u64, ChangeHash)>,
    asked: BTreeMap<u32, Asked>,
    next_id: u32,
    tasks: BTreeMap<ChainId, Task>,
    dirty: BTreeSet<ChainId>,
    compared: BTreeSet<(ChainId, u64, ChangeHash)>,
    declined: BTreeSet<ChainId>,
    wants_pending: usize,
    records_pending: bool,
    strays: u8,
    tips_pages: u16,
    charged: usize,
    summary_at: Duration,
    summary_due: bool,
}

impl Link {
    fn new(remote: PublicKey, generation: u64, now: Duration) -> Self {
        Self {
            remote,
            generation,
            phase: Phase::Bootstrap,
            bootstrap: Bootstrap::default(),
            told: BTreeMap::new(),
            told_membership: None,
            told_digest: None,
            mismatches: 0,
            reset_at: None,
            sent: BTreeMap::new(),
            asked: BTreeMap::new(),
            next_id: 0,
            tasks: BTreeMap::new(),
            dirty: BTreeSet::new(),
            compared: BTreeSet::new(),
            declined: BTreeSet::new(),
            wants_pending: 0,
            records_pending: false,
            strays: 0,
            tips_pages: 0,
            charged: 0,
            summary_at: now.saturating_add(SUMMARY_EVERY),
            summary_due: false,
        }
    }

    fn open(&self) -> bool {
        matches!(self.phase, Phase::Bootstrap | Phase::Reader)
    }

    fn slot_free(&self, slot: Slot) -> bool {
        let taken = self.asked.values().filter(|a| a.ask.slot() == slot).count();
        match slot {
            Slot::Want => taken < WANTS,
            Slot::Records | Slot::Tips | Slot::Probe | Slot::Fork => taken == 0,
        }
    }

    fn running(&self) -> usize {
        self.tasks.values().filter(|task| task.running).count()
    }

    fn report(&self) -> Report {
        Report {
            tips: self
                .told
                .iter()
                .map(|(chain, told)| (*chain, told.tip))
                .collect(),
            membership: self.told_membership,
        }
    }
}

/// What wakes a stop (§4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Wake {
    /// The change awaited applied, or dead.
    Change(ChangeId),
    /// The view-only author's link ended or changed build.
    Link(PublicKey),
}

/// Why a chain is not advancing here: made only on a chain known, from a
/// body that opened and matched its signed head, which it keeps.
#[derive(Clone, Debug)]
struct Stop {
    head: Box<SignedHead>,
    hash: ChangeHash,
    wake: Wake,
    retry_after: Duration,
    woken: bool,
}

impl Stop {
    /// The number stopped at.
    fn seq(&self) -> u64 {
        self.head.head.seq
    }
}

/// The sync protocol of one journal over all its links.
#[derive(Debug, Default)]
pub struct Machine {
    links: BTreeMap<LinkId, Link>,
    generations: u64,
    stops: BTreeMap<ChainId, Stop>,
    wakes: BTreeMap<Wake, BTreeSet<ChainId>>,
    backoffs: BTreeMap<ChainId, (u64, Duration)>,
    walking: BTreeMap<ChainId, LinkId>,
    own_digest: Option<(u32, [u8; 32])>,
}

impl Machine {
    /// One with no links.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes `bytes`, a frame read from `link`.
    pub fn on_message<S: Storage, B: Budget>(
        &mut self,
        storage: &mut S,
        budget: &mut B,
        now: Duration,
        link: LinkId,
        bytes: &[u8],
    ) -> Output {
        let mut step = Step::new(self, storage, budget, now, Some(1));
        step.message(link, bytes);
        step.finish()
    }

    /// Takes something that happened here.
    pub fn on_local<S: Storage, B: Budget>(
        &mut self,
        storage: &mut S,
        budget: &mut B,
        now: Duration,
        local: Local,
    ) -> Output {
        let mut step = Step::new(self, storage, budget, now, None);
        step.local(local);
        step.finish()
    }

    /// Lets time pass: deadlines, summaries, stops to retry, tasks to
    /// start.
    pub fn on_timer<S: Storage, B: Budget>(
        &mut self,
        storage: &mut S,
        budget: &mut B,
        now: Duration,
    ) -> Output {
        let mut step = Step::new(self, storage, budget, now, None);
        step.timer();
        step.finish()
    }

    /// The message `job` builds, if its link is still of its generation
    /// and in the phase it needs; built from the state as it is now.
    pub fn serve<S: Storage, B: Budget>(
        &mut self,
        storage: &mut S,
        budget: &mut B,
        job: &Job,
    ) -> Option<Send> {
        let mut step = Step::new(self, storage, budget, Duration::ZERO, Some(0));
        step.serve(job)
    }

    /// Whether output made for `generation` of `link` may still be
    /// written.
    pub fn is_current(&self, link: LinkId, generation: u64) -> bool {
        self.links
            .get(&link)
            .is_some_and(|l| l.open() && l.generation == generation)
    }

    /// `link`'s phase.
    pub fn phase(&self, link: LinkId) -> Option<Phase> {
        self.links.get(&link).map(|l| l.phase)
    }

    /// What `link` told, for a flush.
    pub fn report(&self, link: LinkId) -> Option<Report> {
        self.links.get(&link).map(Link::report)
    }

    /// The tip `link` told for `chain`.
    pub fn told(&self, link: LinkId, chain: ChainId) -> Option<Told> {
        self.links.get(&link)?.told.get(&chain).copied()
    }

    /// The chain stopped here at `chain`, if any: its number and head's
    /// hash.
    pub fn stop(&self, chain: ChainId) -> Option<(u64, ChangeHash)> {
        self.stops.get(&chain).map(|stop| (stop.seq(), stop.hash))
    }

    /// Drops every stop (they are caches, §4.4).
    pub fn drop_stops(&mut self) {
        self.stops.clear();
        self.wakes.clear();
    }

    /// The links.
    pub fn links(&self) -> impl Iterator<Item = (LinkId, PublicKey, Phase)> + '_ {
        self.links.iter().map(|(id, l)| (*id, l.remote, l.phase))
    }

    /// The bytes charged for `link`'s state.
    pub fn charged(&self, link: LinkId) -> usize {
        self.links.get(&link).map_or(0, |l| l.charged)
    }
}

/// One call's work: the machine, the storage, the budget and the output.
struct Step<'a, S, B> {
    m: &'a mut Machine,
    s: &'a mut S,
    b: &'a mut B,
    now: Duration,
    out: Output,
    /// Requests this call may still make (none: no limit).
    requests: Option<usize>,
}

/// The hash of `head` at `seq` of `chain` held, if any.
fn hash_at(storage: &impl Storage, chain: ChainId, seq: u64) -> Option<ChangeHash> {
    if seq == 0 {
        Some(ChangeHash::ZERO)
    } else {
        storage.head_at(chain, seq).map(|head| head.hash())
    }
}

/// Up to [`PROBE`] numbers spread over `[lo, hi)`, ascending.
fn spread(lo: u64, hi: u64) -> Vec<u64> {
    let span = hi.saturating_sub(lo);
    let parts = PROBE as u64;
    if span <= parts {
        return (lo..hi).collect();
    }
    let mut seqs: Vec<u64> = (0..parts)
        .filter_map(|i| {
            let offset = u128::from(span) * u128::from(i) / u128::from(parts);
            u64::try_from(offset).ok().and_then(|o| lo.checked_add(o))
        })
        .collect();
    seqs.dedup();
    seqs
}

impl<'a, S: Storage, B: Budget> Step<'a, S, B> {
    fn new(
        m: &'a mut Machine,
        s: &'a mut S,
        b: &'a mut B,
        now: Duration,
        requests: Option<usize>,
    ) -> Self {
        Self {
            m,
            s,
            b,
            now,
            out: Output::default(),
            requests,
        }
    }

    fn finish(mut self) -> Output {
        self.events();
        self.retry_stops();
        self.flush();
        self.out
    }

    fn link(&mut self, link: LinkId) -> Option<&mut Link> {
        self.m.links.get_mut(&link)
    }

    fn alive(&self, link: LinkId) -> bool {
        self.m.links.get(&link).is_some_and(Link::open)
    }

    fn send(&mut self, link: LinkId, message: Sync) {
        if let Some(l) = self.m.links.get(&link)
            && l.open()
        {
            self.out.sends.push(Send {
                link,
                generation: l.generation,
                message,
            });
        }
    }

    fn close(&mut self, link: LinkId, why: Closed) {
        if let Some(l) = self.m.links.get_mut(&link)
            && l.open()
        {
            l.phase = Phase::Closed;
            l.asked.clear();
            l.tasks.clear();
            self.out.effects.push(Effect::Close { link, why });
            self.walker_gone(link);
        }
    }

    /// `link` can walk no more: its walks are offered to the other links
    /// that told those chains.
    fn walker_gone(&mut self, link: LinkId) {
        let chains: Vec<ChainId> = self
            .m
            .walking
            .iter()
            .filter(|(_, walker)| **walker == link)
            .map(|(chain, _)| *chain)
            .collect();
        for chain in chains {
            self.m.walking.remove(&chain);
            self.schedule_everywhere(chain);
        }
    }

    /// Decides `chain`'s task again on every link.
    fn schedule_everywhere(&mut self, chain: ChainId) {
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in links {
            self.schedule(link, chain);
        }
    }

    // --- Local events ---

    fn local(&mut self, local: Local) {
        match local {
            Local::Linked { link, remote } => self.linked(link, remote),
            Local::Unlinked(link) => self.unlinked(link),
            Local::Journal => {}
            Local::Membership(taken) => self.membership_taken(&taken),
            // A sealing declined for its epoch may open now.
            Local::Key(_) => self.ask_declined_everywhere(),
            Local::Build(remote) => {
                self.wake(Wake::Link(remote));
                let links: Vec<LinkId> = self
                    .m
                    .links
                    .iter()
                    .filter(|(_, l)| l.remote == remote)
                    .map(|(id, _)| *id)
                    .collect();
                for link in links {
                    self.ask_declined(link);
                }
            }
            Local::Readiness => {
                // A record taken elsewhere may have removed the other side
                // of a link of either phase.
                self.revoke_removed();
                let links: Vec<LinkId> = self.m.links.keys().copied().collect();
                for link in links {
                    self.try_ready(link);
                }
            }
        }
        self.pump_all();
    }

    fn linked(&mut self, link: LinkId, remote: PublicKey) {
        self.m.generations += 1;
        let generation = self.m.generations;
        self.m
            .links
            .insert(link, Link::new(remote, generation, self.now));
        if self.s.recovering() {
            self.close(link, Closed::Recovering);
            return;
        }
        let membership = self.s.membership();
        self.send(link, Sync::MembershipHead { membership });
    }

    fn unlinked(&mut self, link: LinkId) {
        let Some(l) = self.m.links.remove(&link) else {
            return;
        };
        self.b.refund(link, l.charged);
        self.out.effects.push(Effect::Unlinked {
            link,
            remote: l.remote,
            report: l.report(),
        });
        self.walker_gone(link);
        self.wake(Wake::Link(l.remote));
    }

    // --- Messages ---

    fn message(&mut self, link: LinkId, bytes: &[u8]) {
        let Some(l) = self.m.links.get(&link) else {
            return;
        };
        if !l.open() {
            return;
        }
        if self.s.recovering() {
            self.close(link, Closed::Recovering);
            return;
        }
        let limit = if l.phase == Phase::Bootstrap {
            BOOTSTRAP_FRAME
        } else {
            FRAME
        };
        if bytes.len() > limit {
            self.close(link, Closed::Malformed);
            return;
        }
        let Ok(message) = Sync::decode(bytes) else {
            self.close(link, Closed::Malformed);
            return;
        };
        let phase = l.phase;
        if phase == Phase::Bootstrap && !message.in_bootstrap() {
            self.close(link, Closed::Phase(message.name()));
            return;
        }
        if phase == Phase::Reader && matches!(message, Sync::Ready { .. }) {
            self.close(link, Closed::Phase("Ready"));
            return;
        }
        self.dispatch(link, message);
        self.pump(link);
    }

    fn dispatch(&mut self, link: LinkId, message: Sync) {
        match message {
            Sync::MembershipHead { membership } => self.membership_head(link, membership),
            Sync::Ready {
                genesis,
                membership,
            } => self.ready(link, genesis, membership),
            Sync::Summary { membership, tips } => self.summary(link, membership, tips),
            Sync::RecordsAsk { id, after, at } => self.records_ask(link, id, after, at),
            Sync::Records { id, records, more } => self.records(link, id, &records, more),
            Sync::RecordsDiverged { id, record } => {
                // Only the answer to a request for records names the
                // number its record is at.
                match self.reply(link, id) {
                    Some(Ask::Records { after }) => {
                        self.out.effects.push(Effect::Diverged {
                            link,
                            at: after,
                            record: record.into_vec(),
                        });
                        self.close(link, Closed::Membership);
                    }
                    Some(_) => self.close(
                        link,
                        Closed::Reply("a records divergence answering another request"),
                    ),
                    None => {}
                }
            }
            Sync::TipsAsk { id, after, project } => self.tips_ask(link, id, after, project),
            Sync::TipsPage { id, tips, next } => self.tips_page(link, id, &tips, next),
            Sync::Tips { tips } => {
                for tip in tips {
                    if !self.alive(link) {
                        return;
                    }
                    self.on_tip(link, tip);
                }
            }
            Sync::Want {
                id,
                chain,
                after,
                at,
                most,
            } => self.want(link, id, chain, after, at, most),
            Sync::Changes {
                id,
                chain,
                changes,
                more,
            } => self.changes(link, id, chain, &changes, more),
            Sync::Diverged { id, chain } => self.diverged(link, id, chain),
            Sync::Fresh { changes } => self.fresh(link, &changes),
            Sync::Probe { id, chain, seqs } => self.probe(link, id, chain, &seqs),
            Sync::Heads { id, chain, heads } => self.heads(link, id, chain, &heads),
            Sync::HeadsAsk {
                id,
                chain,
                upto,
                most,
            } => self.heads_ask(link, id, chain, upto, most),
            Sync::HeadsRun { id, chain, heads } => self.heads_run(link, id, chain, &heads),
            Sync::ForkAsk { id, chain } => {
                let proof = self
                    .s
                    .evidence(chain)
                    .and_then(|proof| ProofBytes::try_from(&*proof.bytes()).ok());
                self.b.spend(Some(link), Work::Read(1));
                self.send(
                    link,
                    Sync::Fork {
                        id: Some(id),
                        chain,
                        proof,
                    },
                );
            }
            Sync::Fork { id, chain, proof } => self.fork(link, id, chain, proof.as_deref()),
            Sync::Refused { changes } => self.refused(link, changes),
        }
    }

    /// The request `id` answered, removed; a stray is counted and none
    /// given.
    fn reply(&mut self, link: LinkId, id: u32) -> Option<Ask> {
        let l = self.link(link)?;
        if let Some(asked) = l.asked.remove(&id) {
            return Some(asked.ask);
        }
        l.strays = l.strays.saturating_add(1);
        if l.strays >= STRAYS {
            self.close(link, Closed::Strays);
        }
        None
    }

    // --- Membership and phases ---

    fn membership_head(&mut self, link: LinkId, membership: Mark) {
        if let Some(l) = self.link(link) {
            l.bootstrap.their_head = Some(membership);
        }
        // The other side's statement of its head: an acknowledgement
        // (§3.3, I31), as a `Ready` or `Summary` is.
        self.told_membership(link, membership);
        self.catch_up(link, membership);
        self.try_ready(link);
    }

    /// `link` told its membership head: if it changed, what was declined
    /// on the link is asked for again.
    fn told_membership(&mut self, link: LinkId, membership: Mark) {
        let Some(l) = self.link(link) else {
            return;
        };
        let changed = l.told_membership != Some(membership);
        l.told_membership = Some(membership);
        if changed {
            self.ask_declined(link);
        }
    }

    /// Asks for records if `theirs` is ahead; closes the link if it is a
    /// record this side holds another of.
    fn catch_up(&mut self, link: LinkId, theirs: Mark) {
        let mine = self.s.membership();
        if theirs.0 > mine.0 {
            let asking = self
                .m
                .links
                .get(&link)
                .is_some_and(|l| !l.slot_free(Slot::Records));
            if !asking {
                self.request(link, Ask::Records { after: mine.0 }, |id| {
                    Sync::RecordsAsk {
                        id,
                        after: mine.0,
                        at: mine.1,
                    }
                });
            }
        } else if self.s.record_hash(theirs.0) != Some(theirs.1) {
            self.close(link, Closed::Membership);
        }
    }

    fn ready(&mut self, link: LinkId, genesis: [u8; 32], membership: Mark) {
        if genesis != self.s.genesis() {
            self.close(link, Closed::Genesis);
            return;
        }
        // Its sender had our head, so it names a record we hold (§3.3).
        if self.s.record_hash(membership.0) != Some(membership.1) {
            self.close(link, Closed::Membership);
            return;
        }
        if let Some(l) = self.link(link) {
            if l.bootstrap.their_ready.is_some() {
                self.close(link, Closed::Phase("Ready"));
                return;
            }
            l.bootstrap.their_ready = Some(membership);
        }
        self.told_membership(link, membership);
        self.try_ready(link);
    }

    fn try_ready(&mut self, link: LinkId) {
        let now = self.now;
        let Some(l) = self.m.links.get(&link) else {
            return;
        };
        if l.phase != Phase::Bootstrap {
            return;
        }
        let held = |mark: Option<Mark>| {
            mark.is_some_and(|(seq, hash)| self.s.record_hash(seq) == Some(hash))
        };
        // `Ready` names this side's head, which the other side must hold to
        // accept it: so it is sent only once the other side has said the
        // same head. Otherwise this side could reach Reader on the other's
        // `Ready` and send tips while the other still lacks a record this
        // side's `Ready` named.
        let membership = self.s.membership();
        let send = !l.bootstrap.sent
            && self.s.can_ready(l.remote)
            && l.bootstrap.their_head == Some(membership);
        let accept = !l.bootstrap.accepted && held(l.bootstrap.their_ready);
        if send {
            let genesis = self.s.genesis();
            self.send(
                link,
                Sync::Ready {
                    genesis,
                    membership,
                },
            );
        }
        let Some(l) = self.link(link) else {
            return;
        };
        l.bootstrap.sent |= send;
        l.bootstrap.accepted |= accept;
        if l.bootstrap.sent && l.bootstrap.accepted {
            l.phase = Phase::Reader;
            l.summary_at = now.saturating_add(SUMMARY_EVERY);
            self.out.effects.push(Effect::Reader(link));
            self.request(
                link,
                Ask::Tips {
                    after: None,
                    project: None,
                },
                |id| Sync::TipsAsk {
                    id,
                    after: None,
                    project: None,
                },
            );
        }
    }

    fn records_ask(&mut self, link: LinkId, id: u32, after: u64, at: [u8; 32]) {
        let Some(l) = self.m.links.get(&link) else {
            return;
        };
        if !self.s.is_member(l.remote) {
            self.close(link, Closed::NotServed);
            return;
        }
        if l.records_pending {
            self.close(link, Closed::Requests);
            return;
        }
        let generation = l.generation;
        if let Some(l) = self.link(link) {
            l.records_pending = true;
        }
        self.out.effects.push(Effect::Serve(Job {
            link,
            generation,
            page: Page::Records { id, after, at },
        }));
    }

    fn records(
        &mut self,
        link: LinkId,
        id: Option<u32>,
        records: &Bounded<RecordBytes, RECORDS>,
        more: bool,
    ) {
        let bytes: usize = records.iter().map(|record| record.len()).sum();
        let slices: Vec<&[u8]> = records.iter().map(|record| &record[..]).collect();
        let Some(id) = id else {
            // Unsolicited: taken only as far as it extends this chain
            // exactly; a push that raced another is no fault.
            let after = self.s.membership().0;
            if bytes <= RECORDS_BYTES {
                let _ = self.take_page(after, &slices);
            }
            return;
        };
        let Some(ask) = self.reply(link, id) else {
            return;
        };
        let Ask::Records { after } = ask else {
            self.close(link, Closed::Reply("records answering another request"));
            return;
        };
        if bytes > RECORDS_BYTES || (more && records.is_empty()) {
            self.close(link, Closed::Reply("a page of records past its bounds"));
            return;
        }
        match self.take_page(after, &slices) {
            Ok(()) => {
                if more && self.alive(link) {
                    let mine = self.s.membership();
                    self.request(link, Ask::Records { after: mine.0 }, |id| {
                        Sync::RecordsAsk {
                            id,
                            after: mine.0,
                            at: mine.1,
                        }
                    });
                }
            }
            Err(RecordsRefused::Mismatch) => self.close(link, Closed::Membership),
            Err(RecordsRefused::Invalid) => self.close(link, Closed::Records),
        }
    }

    /// Takes a page of records, `records`, after number `after`: what was
    /// taken stays taken, with the links it revokes, whether or not a
    /// later record failed (sync §4.3); why one did, after.
    fn take_page(&mut self, after: u64, records: &[&[u8]]) -> Result<(), RecordsRefused> {
        let (taken, refused) = self.s.take_records(after, records);
        if taken.records > 0 || refused.is_ok() {
            self.membership_taken(&taken);
        }
        refused
    }

    /// Revokes every open link, Bootstrap or Reader, whose other side the
    /// membership chain no longer names a member, once it names this side
    /// one: a joiner still taking the chain revokes none, what it is
    /// linked to being named further on.
    fn revoke_removed(&mut self) {
        if !self.s.is_member(self.s.local()) {
            return;
        }
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in links {
            let Some(l) = self.m.links.get(&link) else {
                continue;
            };
            if l.open() && !self.s.is_member(l.remote) {
                self.revoke(link);
            }
        }
    }

    /// Records were taken: links whose other side is no longer a member
    /// are revoked, what each link declined is asked for again (a start
    /// may name a record just taken as its grant), and the others told.
    fn membership_taken(&mut self, taken: &Taken) {
        self.events();
        self.revoke_removed();
        if taken.records > 0 {
            self.ask_declined_everywhere();
        }
        let membership = self.s.membership();
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in links {
            match self.m.links.get(&link).map(|l| l.phase) {
                Some(Phase::Bootstrap) => {
                    self.send(link, Sync::MembershipHead { membership });
                    self.try_ready(link);
                }
                Some(Phase::Reader) => {
                    self.send(link, Sync::MembershipHead { membership });
                    if let Some(l) = self.link(link) {
                        l.summary_due = true;
                    }
                }
                Some(Phase::Revoked | Phase::Closed) | None => {}
            }
        }
    }

    fn revoke(&mut self, link: LinkId) {
        self.m.generations += 1;
        let generation = self.m.generations;
        if let Some(l) = self.link(link) {
            l.generation = generation;
            l.phase = Phase::Revoked;
            l.asked.clear();
            l.tasks.clear();
        }
        self.out.effects.push(Effect::Close {
            link,
            why: Closed::Revoked,
        });
        self.walker_gone(link);
    }

    fn summary(&mut self, link: LinkId, membership: Mark, tips: (u32, [u8; 32])) {
        if !self.m.links.contains_key(&link) {
            return;
        }
        self.told_membership(link, membership);
        self.catch_up(link, membership);
        let Some(l) = self.m.links.get_mut(&link) else {
            return;
        };
        if !l.open() {
            return;
        }
        let digest = *l.told_digest.get_or_insert_with(|| {
            let mut digest = Digest::default();
            for told in l.told.values() {
                digest.add(&told.tip);
            }
            digest.finish()
        });
        self.b.spend(Some(link), Work::Read(l.told.len()));
        if digest == tips {
            l.mismatches = 0;
            return;
        }
        l.mismatches = l.mismatches.saturating_add(1);
        let due = l
            .reset_at
            .is_none_or(|at| self.now >= at.saturating_add(RESET_EVERY));
        let asking = !l.slot_free(Slot::Tips);
        if l.mismatches >= 2 && due && !asking {
            l.mismatches = 0;
            l.reset_at = Some(self.now);
            let refund = l.told.len().saturating_mul(PER_CHAIN);
            l.told.clear();
            l.told_digest = None;
            l.charged = l.charged.saturating_sub(refund);
            self.b.refund(link, refund);
            self.request(
                link,
                Ask::Tips {
                    after: None,
                    project: None,
                },
                |id| Sync::TipsAsk {
                    id,
                    after: None,
                    project: None,
                },
            );
        }
    }

    // --- Tips ---

    fn tips_ask(
        &mut self,
        link: LinkId,
        id: u32,
        after: Option<ChainId>,
        project: Option<ProjectId>,
    ) {
        // Short or empty, `next` set, where the scan ran out first.
        let (tips, next) = self.s.tips_after(after, project, TIPS_PAGE);
        self.b.spend(Some(link), Work::Read(tips.len()));
        self.send(
            link,
            Sync::TipsPage {
                id,
                tips: Bounded::truncated(tips),
                next,
            },
        );
    }

    fn tips_page(
        &mut self,
        link: LinkId,
        id: u32,
        tips: &Bounded<Tip, TIPS_PAGE>,
        next: Option<ChainId>,
    ) {
        let Some(ask) = self.reply(link, id) else {
            return;
        };
        let Ask::Tips { after, project } = ask else {
            self.close(link, Closed::Reply("tips answering another request"));
            return;
        };
        let ascending = tips.windows(2).all(|pair| match pair {
            [a, b] => a.chain < b.chain,
            _ => true,
        });
        let past = tips
            .first()
            .is_none_or(|first| after.is_none_or(|after| first.chain > after));
        let of = tips
            .iter()
            .all(|tip| project.is_none_or(|project| tip.project == project));
        // A page may end short of `next`: the responder's scan is bounded
        // by the chains it looks at, not the tips it finds. `next` moves
        // on, so the pages end.
        let joins = next.is_none_or(|next| {
            tips.last().is_none_or(|last| last.chain <= next)
                && after.is_none_or(|after| next > after)
        });
        if !(ascending && past && of && joins) {
            self.close(link, Closed::Reply("a page of tips out of order"));
            return;
        }
        // Counted per walk, from its first page (asked after none).
        let Some(l) = self.link(link) else {
            return;
        };
        l.tips_pages = if after.is_none() {
            1
        } else {
            l.tips_pages.saturating_add(1)
        };
        if l.tips_pages > TIPS_WALK {
            self.close(link, Closed::Reply("a walk of tips past its most pages"));
            return;
        }
        if let Some(next) = next {
            self.request(
                link,
                Ask::Tips {
                    after: Some(next),
                    project,
                },
                |id| Sync::TipsAsk {
                    id,
                    after: Some(next),
                    project,
                },
            );
        }
        for tip in tips {
            if !self.alive(link) {
                return;
            }
            self.on_tip(link, *tip);
        }
    }

    /// A tip told on `link`: the only writer of `told` (§3.3).
    fn on_tip(&mut self, link: LinkId, tip: Tip) {
        let chain = tip.chain;
        if self
            .s
            .origin(chain)
            .is_some_and(|origin| origin != tip.project)
        {
            self.close(link, Closed::Claim);
            return;
        }
        let Some(l) = self.m.links.get_mut(&link) else {
            return;
        };
        let known = l.told.get(&chain).copied();
        if known.is_none() {
            if l.told.len() >= MAX_CHAINS || !self.b.charge(link, PER_CHAIN) {
                self.close(link, Closed::TooManyChains);
                return;
            }
            l.charged = l.charged.saturating_add(PER_CHAIN);
        }
        let same = known.is_some_and(|told| told.tip == tip);
        if !same {
            l.told.insert(
                chain,
                Told {
                    tip,
                    tried: false,
                    attempts: 0,
                },
            );
            l.told_digest = None;
        }
        if l.sent.get(&chain).is_some_and(|sent| sent.0 <= tip.seq) {
            l.sent.remove(&chain);
        }
        self.schedule(link, chain);
    }

    /// Decides the task for `chain` on `link` from its told tip and this
    /// side's (§3.3 `on_tip`, §4.4).
    fn schedule(&mut self, link: LinkId, chain: ChainId) {
        let Some(l) = self.m.links.get(&link) else {
            return;
        };
        if l.phase != Phase::Reader || l.tasks.contains_key(&chain) {
            return;
        }
        let Some(told) = l.told.get(&chain).copied() else {
            return;
        };
        if told.attempts >= ATTEMPTS {
            return;
        }
        let generation = l.generation;
        let declined = l.declined.contains(&chain);
        let t = told.tip;
        self.b.spend(Some(link), Work::Read(1));
        let mine = self.s.tip(chain);
        // A listed prefix is the first record's, for good: it cannot fork
        // in the share, so a told fork place on it is ignored and another
        // head at a listed number is not compared (§14.2).
        let listed = self.s.listed(chain);
        if let Some(mine) = mine
            && listed.is_none()
            && t.fork != 0
            && (mine.fork == 0 || mine.fork > t.fork)
        {
            self.task(link, chain, Kind::AskFork);
            return;
        }
        let Some(mine) = mine else {
            if declined {
                return;
            }
            if listed.is_some() && !self.walked(chain) {
                self.walk(link, chain);
            } else if !told.tried {
                self.task(link, chain, Kind::Pull);
            }
            return;
        };
        if mine.seq == 0 && mine.fork == 1 {
            // Two starts: the empty tip everywhere, nothing to compare.
            return;
        }
        if let Some(stop) = self.m.stops.get(&chain)
            && stop.seq() <= t.seq
        {
            let key = (chain, stop.seq(), stop.hash);
            let compared = self
                .m
                .links
                .get(&link)
                .is_some_and(|l| l.compared.contains(&key) || l.generation != generation);
            if !compared {
                let (stopped, hash) = (stop.head.clone(), stop.hash);
                self.task(link, chain, Kind::Compare { stopped, hash });
            }
            return;
        }
        if t.seq <= mine.seq {
            if listed.is_none() && t.seq >= 1 && hash_at(self.s, chain, t.seq) != Some(t.hash) {
                self.task(
                    link,
                    chain,
                    Kind::Witness {
                        hi: t.seq,
                        restarted: false,
                    },
                );
            }
            return;
        }
        let next = mine.seq.saturating_add(1);
        let frozen = self.s.frozen(chain).is_some_and(|from| from <= next);
        let past_pin = listed.is_some_and(|(through, _)| mine.seq >= through);
        if frozen || past_pin || told.tried || declined {
            return;
        }
        if listed.is_some() && !self.walked(chain) {
            // Part of a listed prefix held, its walk lost (a torn file is
            // no file): walked again before more is taken.
            self.walk(link, chain);
        } else {
            self.task(link, chain, Kind::Pull);
        }
    }

    /// Walks `chain`'s listed prefix on `link`, unless a walk of it runs.
    fn walk(&mut self, link: LinkId, chain: ChainId) {
        if let Entry::Vacant(walker) = self.m.walking.entry(chain) {
            walker.insert(link);
            self.task(link, chain, Kind::Walk);
        }
    }

    /// Whether `chain`'s listed prefix has been walked to its start, or is
    /// held already.
    fn walked(&self, chain: ChainId) -> bool {
        self.s.walk(chain).is_some_and(|walk| walk.lowest == 1)
    }

    fn task(&mut self, link: LinkId, chain: ChainId, kind: Kind) {
        let Some(l) = self.link(link) else {
            return;
        };
        if let Some(told) = l.told.get_mut(&chain) {
            told.attempts = told.attempts.saturating_add(1);
        }
        l.tasks.insert(
            chain,
            Task {
                kind,
                running: false,
            },
        );
        self.b.spend(Some(link), Work::Task);
    }

    fn end_task(&mut self, link: LinkId, chain: ChainId) {
        let Some(l) = self.link(link) else {
            return;
        };
        if let Some(task) = l.tasks.remove(&chain) {
            self.b.spend(Some(link), Work::TaskEnded);
            if matches!(task.kind, Kind::Walk) {
                // The walk went as far as this link could take it: the
                // chain is decided again on every link.
                self.m.walking.remove(&chain);
                self.schedule_everywhere(chain);
            } else {
                self.schedule(link, chain);
            }
        }
    }

    /// Ends `chain`'s task as tried: its told tip causes no further pull.
    fn tried(&mut self, link: LinkId, chain: ChainId) {
        if let Some(told) = self.link(link).and_then(|l| l.told.get_mut(&chain)) {
            told.tried = true;
        }
        self.end_task(link, chain);
    }

    /// Restarts a bisection once (from a new witness at their told tip),
    /// then ends it.
    fn restart(&mut self, link: LinkId, chain: ChainId, restarted: bool) {
        let told = self
            .m
            .links
            .get(&link)
            .and_then(|l| l.told.get(&chain))
            .map(|t| t.tip.seq);
        match told {
            Some(hi) if !restarted && hi >= 1 => {
                if let Some(task) = self.link(link).and_then(|l| l.tasks.get_mut(&chain)) {
                    task.kind = Kind::Witness {
                        hi,
                        restarted: true,
                    };
                    task.running = false;
                }
            }
            Some(_) | None => self.end_task(link, chain),
        }
    }

    // --- Requests and tasks ---

    /// Makes a request on `link`, if this call may make one and its slot
    /// is free.
    fn request(&mut self, link: LinkId, ask: Ask, message: impl FnOnce(u32) -> Sync) -> bool {
        if self.requests == Some(0) {
            return false;
        }
        let deadline = self.now.saturating_add(DEADLINE);
        let Some(l) = self.m.links.get_mut(&link) else {
            return false;
        };
        if !l.open() || !l.slot_free(ask.slot()) {
            return false;
        }
        let mut id = l.next_id;
        while l.asked.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        l.next_id = id.wrapping_add(1);
        l.asked.insert(id, Asked { deadline, ask });
        if let Some(left) = &mut self.requests {
            *left -= 1;
        }
        self.b.spend(Some(link), Work::Request);
        self.send(link, message(id));
        true
    }

    fn pump_all(&mut self) {
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in links {
            self.pump(link);
        }
    }

    /// Starts scheduled tasks on `link` while slots and the running count
    /// allow.
    fn pump(&mut self, link: LinkId) {
        let mut skipped = BTreeSet::new();
        loop {
            if self.requests == Some(0) {
                return;
            }
            let Some(l) = self.m.links.get(&link) else {
                return;
            };
            if l.phase != Phase::Reader || l.running() >= RUNNING {
                return;
            }
            let next = l
                .tasks
                .iter()
                .find(|(chain, task)| !task.running && !skipped.contains(*chain))
                .map(|(chain, _)| *chain);
            let Some(chain) = next else {
                return;
            };
            if !self.start(link, chain) {
                skipped.insert(chain);
            }
        }
    }

    /// Starts `chain`'s task: makes its request, or ends it if there is
    /// nothing to ask. False if its slot is taken.
    fn start(&mut self, link: LinkId, chain: ChainId) -> bool {
        let Some(kind) = self
            .m
            .links
            .get(&link)
            .and_then(|l| l.tasks.get(&chain))
            .map(|task| task.kind.clone())
        else {
            return false;
        };
        let asked = match kind {
            Kind::Pull => return self.start_pull(link, chain),
            Kind::Witness { hi, .. } => self.probe_for(link, chain, vec![hi]),
            Kind::Compare { stopped, .. } => self.probe_for(link, chain, vec![stopped.head.seq]),
            Kind::Bisect { lo, hi, .. } => self.probe_for(link, chain, spread(lo, hi)),
            Kind::AskFork => {
                self.request(link, Ask::Fork { chain }, |id| Sync::ForkAsk { id, chain })
            }
            Kind::Walk => return self.start_walk(link, chain),
        };
        if asked && let Some(task) = self.link(link).and_then(|l| l.tasks.get_mut(&chain)) {
            task.running = true;
        }
        asked
    }

    fn probe_for(&mut self, link: LinkId, chain: ChainId, seqs: Vec<u64>) -> bool {
        let Ok(bounded) = Bounded::<u64, PROBE>::try_from(seqs.clone()) else {
            return false;
        };
        self.request(link, Ask::Probe { chain, seqs }, |id| Sync::Probe {
            id,
            chain,
            seqs: bounded,
        })
    }

    fn start_pull(&mut self, link: LinkId, chain: ChainId) -> bool {
        self.b.spend(Some(link), Work::Read(1));
        let mine = self.s.tip(chain);
        let listed = self.s.listed(chain);
        let unwalked = listed.is_some() && !self.walked(chain);
        if unwalked {
            self.end_task(link, chain);
            return true;
        }
        let (after, at) = mine.map_or((0, ChangeHash::ZERO), |tip| (tip.seq, tip.hash));
        let mut most = if mine.is_none() { 1 } else { CHANGES as u64 };
        if let Some((through, _)) = listed {
            most = most.min(through.saturating_sub(after));
        }
        let Ok(most) = u16::try_from(most) else {
            return false;
        };
        if most == 0 {
            self.end_task(link, chain);
            return true;
        }
        let asked = self.request(link, Ask::Want { chain, after, most }, |id| Sync::Want {
            id,
            chain,
            after,
            at,
            most,
        });
        if asked && let Some(task) = self.link(link).and_then(|l| l.tasks.get_mut(&chain)) {
            task.running = true;
        }
        asked
    }

    fn start_walk(&mut self, link: LinkId, chain: ChainId) -> bool {
        let Some((through, listed)) = self.s.listed(chain) else {
            self.end_task(link, chain);
            return true;
        };
        let (upto, expect) = match self.s.walk(chain) {
            Some(walk) if walk.lowest <= 1 => {
                self.end_task(link, chain);
                return true;
            }
            Some(walk) => (walk.lowest - 1, walk.next),
            None => (through, listed),
        };
        let n = upto.min(RUN as u64);
        let Ok(most) = u16::try_from(n) else {
            return false;
        };
        let asked = self.request(
            link,
            Ask::Heads {
                chain,
                upto,
                n,
                expect,
            },
            |id| Sync::HeadsAsk {
                id,
                chain,
                upto,
                most,
            },
        );
        if asked && let Some(task) = self.link(link).and_then(|l| l.tasks.get_mut(&chain)) {
            task.running = true;
        }
        asked
    }

    /// Marks `chain`'s task on `link` as waiting to start again (its
    /// next request, made now if this call may).
    fn go_on(&mut self, link: LinkId, chain: ChainId) {
        if let Some(task) = self.link(link).and_then(|l| l.tasks.get_mut(&chain)) {
            task.running = false;
        }
        self.start(link, chain);
    }

    // --- Changes ---

    #[allow(clippy::too_many_arguments, reason = "the request's fields")]
    fn want(
        &mut self,
        link: LinkId,
        id: u32,
        chain: ChainId,
        after: u64,
        at: ChangeHash,
        most: u16,
    ) {
        let Some(l) = self.m.links.get(&link) else {
            return;
        };
        if most == 0 || usize::from(most) > CHANGES {
            self.close(link, Closed::Reply("a Want of no changes or past a page"));
            return;
        }
        if l.wants_pending >= WANTS {
            self.close(link, Closed::Requests);
            return;
        }
        let generation = l.generation;
        if let Some(l) = self.link(link) {
            l.wants_pending += 1;
        }
        self.out.effects.push(Effect::Serve(Job {
            link,
            generation,
            page: Page::Changes {
                id,
                chain,
                after,
                at,
                most,
            },
        }));
    }

    fn changes(
        &mut self,
        link: LinkId,
        id: u32,
        chain: ChainId,
        changes: &Bounded<EnvelopeBytes, CHANGES>,
        more: bool,
    ) {
        let Some(ask) = self.reply(link, id) else {
            return;
        };
        let Ask::Want {
            chain: asked,
            after,
            most,
        } = ask
        else {
            self.close(link, Closed::Reply("changes answering another request"));
            return;
        };
        let mut envelopes = Vec::with_capacity(changes.len());
        for (i, bytes) in changes.iter().enumerate() {
            let Some(envelope) = Envelope::parse(bytes) else {
                self.close(link, Closed::Reply("an envelope that does not parse"));
                return;
            };
            let expected = u64::try_from(i)
                .ok()
                .and_then(|i| after.checked_add(i)?.checked_add(1));
            if envelope.chain() != chain || Some(envelope.seq()) != expected {
                self.close(link, Closed::Reply("changes not numbered after the asked"));
                return;
            }
            envelopes.push(envelope);
        }
        let bytes: usize = changes.iter().map(|change| change.len()).sum();
        if chain != asked
            || changes.len() > usize::from(most)
            || (more && changes.is_empty())
            || bytes > PAGE_BYTES
        {
            self.close(link, Closed::Reply("a page of changes past its request"));
            return;
        }
        let (took, ended) = self.take(link, chain, &envelopes);
        if !self.alive(link) {
            return;
        }
        if !took {
            self.tried(link, chain);
        } else if ended || !more {
            self.end_task(link, chain);
        } else {
            self.go_on(link, chain);
        }
    }

    /// Admits `envelopes` of `chain` in order until one does not apply;
    /// whether any was taken, and whether one ended the page. A verified
    /// head at the number the chain is stopped at, with another hash than
    /// the stop's, is proved against the stop's head first (§4.4).
    fn take(&mut self, link: LinkId, chain: ChainId, envelopes: &[Envelope<'_>]) -> (bool, bool) {
        let Some(remote) = self.m.links.get(&link).map(|l| l.remote) else {
            return (false, true);
        };
        let mut took = false;
        for envelope in envelopes {
            if let Some(proof) = self.prove_at_stop(link, chain, envelope) {
                self.take_fork(&proof);
                return (took, true);
            }
            self.b.spend(Some(link), Work::Admit);
            let admission = self.s.admit(remote, envelope);
            self.events();
            if !self.alive(link) {
                return (took, true);
            }
            match admission {
                Admission::Applied => took = true,
                Admission::Same => {}
                Admission::Stopped { cause, head } => {
                    self.stopped(chain, head, cause);
                    return (took, true);
                }
                Admission::Frozen => return (took, true),
                Admission::Never { why } => {
                    self.refuse(envelope.chain(), envelope.seq(), why.as_str().as_bytes());
                    return (took, true);
                }
                Admission::Fork(proof) => {
                    if self.s.listed(chain).is_some() {
                        // Not a fork: another branch, not of the share.
                        self.decline(link, chain);
                    } else {
                        self.take_fork(&proof);
                    }
                    return (took, true);
                }
                Admission::Declined | Admission::TurnedAway => {
                    self.decline(link, chain);
                    return (took, true);
                }
                Admission::Invalid => {
                    self.close(link, Closed::Invalid);
                    return (took, true);
                }
            }
        }
        (took, false)
    }

    /// A proof from `envelope`'s head and the head `chain` is stopped at,
    /// if the two are at one number and are a fork.
    fn prove_at_stop(
        &mut self,
        link: LinkId,
        chain: ChainId,
        envelope: &Envelope<'_>,
    ) -> Option<ForkProof> {
        let stop = self.m.stops.get(&chain)?;
        if stop.seq() != envelope.seq() {
            return None;
        }
        let theirs = SignedHead::parse(envelope.signed_head()).ok()?;
        self.b.spend(Some(link), Work::Hash(1));
        if theirs.hash() == stop.hash {
            return None;
        }
        self.b.spend(Some(link), Work::Verify);
        self.s.prove_pair(&stop.head, &theirs)
    }

    fn diverged(&mut self, link: LinkId, id: u32, chain: ChainId) {
        let Some(ask) = self.reply(link, id) else {
            return;
        };
        let Ask::Want {
            chain: asked,
            after,
            ..
        } = ask
        else {
            self.close(link, Closed::Reply("diverged answering another request"));
            return;
        };
        if chain != asked || after == 0 {
            self.close(link, Closed::Reply("diverged where nothing can"));
            return;
        }
        if let Some(task) = self.link(link).and_then(|l| l.tasks.get_mut(&chain)) {
            task.kind = Kind::Witness {
                hi: after,
                restarted: false,
            };
            task.running = false;
        }
        self.start(link, chain);
    }

    fn fresh(&mut self, link: LinkId, changes: &Bounded<EnvelopeBytes, FRESH>) {
        for bytes in changes {
            let Some(envelope) = Envelope::parse(bytes) else {
                self.close(link, Closed::Malformed);
                return;
            };
            let chain = envelope.chain();
            self.b.spend(Some(link), Work::Read(1));
            let Some(mine) = self.s.tip(chain) else {
                continue;
            };
            let declined = self
                .m
                .links
                .get(&link)
                .is_none_or(|l| l.declined.contains(&chain));
            let empty = mine.seq == 0 && mine.fork == 1;
            if declined || empty || envelope.seq() > mine.seq.saturating_add(1) {
                continue;
            }
            self.take(link, chain, &[envelope]);
            if !self.alive(link) {
                return;
            }
        }
    }

    // --- Heads: probes, bisection, comparison ---

    fn probe(&mut self, link: LinkId, id: u32, chain: ChainId, seqs: &Bounded<u64, PROBE>) {
        let ascending = seqs.windows(2).all(|pair| match pair {
            [a, b] => a < b,
            _ => true,
        });
        if !ascending || seqs.is_empty() {
            self.close(link, Closed::Reply("a probe out of order"));
            return;
        }
        let heads: Vec<SignedHeadBytes> = seqs
            .iter()
            .filter_map(|seq| self.s.head_at(chain, *seq))
            .filter_map(|head| SignedHeadBytes::try_from(&*head.bytes()).ok())
            .collect();
        self.b.spend(Some(link), Work::Read(seqs.len()));
        self.send(
            link,
            Sync::Heads {
                id,
                chain,
                heads: Bounded::truncated(heads),
            },
        );
    }

    fn heads(
        &mut self,
        link: LinkId,
        id: u32,
        chain: ChainId,
        heads: &Bounded<SignedHeadBytes, PROBE>,
    ) {
        let Some(ask) = self.reply(link, id) else {
            return;
        };
        let Ask::Probe { chain: asked, seqs } = ask else {
            self.close(link, Closed::Reply("heads answering another request"));
            return;
        };
        if chain != asked {
            self.close(link, Closed::Reply("heads of another chain"));
            return;
        }
        let mut theirs: BTreeMap<u64, SignedHead> = BTreeMap::new();
        let mut last = None;
        for bytes in heads {
            let Ok(head) = SignedHead::parse(bytes) else {
                self.close(link, Closed::Reply("a head that does not parse"));
                return;
            };
            let seq = head.head.seq;
            if head.head.chain != chain || !seqs.contains(&seq) || last.is_some_and(|l| l >= seq) {
                self.close(link, Closed::Reply("a head not asked for"));
                return;
            }
            last = Some(seq);
            self.b.spend(Some(link), Work::Verify);
            if !self.s.verify(chain, &head) {
                self.close(link, Closed::Invalid);
                return;
            }
            theirs.insert(seq, head);
        }
        let Some(kind) = self
            .m
            .links
            .get(&link)
            .and_then(|l| l.tasks.get(&chain))
            .map(|task| task.kind.clone())
        else {
            return;
        };
        match kind {
            Kind::Witness { hi, restarted } => {
                self.witnessed(link, chain, hi, restarted, theirs.remove(&hi));
            }
            Kind::Bisect {
                lo,
                hi,
                witness,
                restarted,
            } => self.bisected(link, chain, (lo, hi), *witness, restarted, &theirs),
            Kind::Compare { stopped, hash } => {
                let seq = stopped.head.seq;
                if let Some(l) = self.link(link) {
                    l.compared.insert((chain, seq, hash));
                }
                if let Some(head) = theirs.get(&seq)
                    && head.hash() != hash
                {
                    // The stop's head is not admitted here: the pair is
                    // proved as it stands.
                    self.b.spend(Some(link), Work::Verify);
                    if let Some(proof) = self.s.prove_pair(&stopped, head) {
                        self.take_fork(&proof);
                    }
                }
                self.end_task(link, chain);
            }
            Kind::Pull | Kind::AskFork | Kind::Walk => self.end_task(link, chain),
        }
    }

    fn witnessed(
        &mut self,
        link: LinkId,
        chain: ChainId,
        hi: u64,
        restarted: bool,
        theirs: Option<SignedHead>,
    ) {
        let Some(theirs) = theirs else {
            self.restart(link, chain, restarted);
            return;
        };
        self.b.spend(Some(link), Work::Read(1));
        if hash_at(self.s, chain, hi) == Some(theirs.hash()) || hash_at(self.s, chain, hi).is_none()
        {
            self.end_task(link, chain);
            return;
        }
        if hi == 1 {
            self.prove(&theirs);
            self.end_task(link, chain);
            return;
        }
        if let Some(task) = self.link(link).and_then(|l| l.tasks.get_mut(&chain)) {
            task.kind = Kind::Bisect {
                lo: 1,
                hi,
                witness: Box::new(theirs),
                restarted,
            };
        }
        self.go_on(link, chain);
    }

    fn bisected(
        &mut self,
        link: LinkId,
        chain: ChainId,
        (lo, hi): (u64, u64),
        witness: SignedHead,
        restarted: bool,
        theirs: &BTreeMap<u64, SignedHead>,
    ) {
        let told = self
            .m
            .links
            .get(&link)
            .and_then(|l| l.told.get(&chain))
            .map_or(0, |t| t.tip.seq);
        let asked = spread(lo, hi);
        let mut new_hi = hi;
        let mut witness = witness;
        let mut agreed = Vec::new();
        for seq in &asked {
            let Some(head) = theirs.get(seq) else {
                if *seq <= told {
                    self.restart(link, chain, restarted);
                    return;
                }
                continue;
            };
            self.b.spend(Some(link), Work::Read(1));
            if hash_at(self.s, chain, *seq) == Some(head.hash()) {
                agreed.push(*seq);
            } else if *seq < new_hi {
                new_hi = *seq;
                witness = *head;
            }
        }
        let new_lo = agreed
            .iter()
            .filter(|seq| **seq < new_hi)
            .max()
            .map_or(lo, |seq| seq.saturating_add(1))
            .max(lo);
        if new_hi.saturating_sub(new_lo) >= hi.saturating_sub(lo) {
            self.restart(link, chain, restarted);
            return;
        }
        if new_lo >= new_hi {
            self.prove(&witness);
            self.end_task(link, chain);
            return;
        }
        if let Some(task) = self.link(link).and_then(|l| l.tasks.get_mut(&chain)) {
            task.kind = Kind::Bisect {
                lo: new_lo,
                hi: new_hi,
                witness: Box::new(witness),
                restarted,
            };
        }
        self.go_on(link, chain);
    }

    /// Asks the storage for a proof from `theirs` and the head held, and
    /// takes it.
    fn prove(&mut self, theirs: &SignedHead) {
        if self.s.listed(theirs.head.chain).is_some() {
            return;
        }
        self.b.spend(None, Work::Verify);
        if let Some(proof) = self.s.prove(theirs) {
            self.take_fork(&proof);
        }
    }

    // --- Listed prefixes (C1) ---

    fn heads_ask(&mut self, link: LinkId, id: u32, chain: ChainId, upto: u64, most: u16) {
        if most == 0 || usize::from(most) > RUN || upto == 0 {
            self.close(link, Closed::Reply("a run of no heads or past its bound"));
            return;
        }
        let n = upto.min(u64::from(most));
        let served = self
            .s
            .listed(chain)
            .is_some_and(|(through, _)| upto <= through)
            && self.s.tip(chain).is_some_and(|tip| tip.seq >= upto);
        let mut heads = Vec::new();
        if served {
            for seq in (upto - n + 1)..=upto {
                let Some(signed) = self.s.head_at(chain, seq) else {
                    heads.clear();
                    break;
                };
                if let Ok(bytes) = HeadBytes::try_from(&*signed.head.bytes()) {
                    heads.push(bytes);
                }
            }
            self.b.spend(Some(link), Work::Read(heads.len()));
        }
        self.send(
            link,
            Sync::HeadsRun {
                id,
                chain,
                heads: Bounded::truncated(heads),
            },
        );
    }

    fn heads_run(
        &mut self,
        link: LinkId,
        id: u32,
        chain: ChainId,
        heads: &Bounded<HeadBytes, RUN>,
    ) {
        let Some(ask) = self.reply(link, id) else {
            return;
        };
        let Ask::Heads {
            chain: asked,
            upto,
            n,
            expect,
        } = ask
        else {
            self.close(link, Closed::Reply("a run answering another request"));
            return;
        };
        if chain != asked {
            self.close(link, Closed::Reply("a run of another chain"));
            return;
        }
        if heads.is_empty() {
            // Not held there: the chain stays untouched.
            self.end_task(link, chain);
            return;
        }
        if u64::try_from(heads.len()).ok() != Some(n) {
            self.close(link, Closed::Reply("a run not of the numbers asked"));
            return;
        }
        let lowest = upto - n + 1;
        let mut parsed = Vec::with_capacity(heads.len());
        for (seq, bytes) in (lowest..=upto).zip(heads.iter()) {
            match Head::parse(bytes) {
                Ok(head) if head.chain == chain && head.seq == seq => parsed.push(head),
                Ok(_) | Err(_) => {
                    self.close(link, Closed::Reply("a run not of the numbers asked"));
                    return;
                }
            }
        }
        self.b.spend(Some(link), Work::Hash(parsed.len()));
        let hashes: Vec<ChangeHash> = parsed.iter().map(Head::hash).collect();
        let links = parsed
            .iter()
            .skip(1)
            .zip(&hashes)
            .all(|(head, before)| head.prev == *before);
        if !links || hashes.last() != Some(&expect) {
            self.close(link, Closed::Reply("a run that does not link"));
            return;
        }
        let next = parsed.first().map_or(ChangeHash::ZERO, |head| head.prev);
        if lowest == 1 && next != ChangeHash::ZERO {
            self.close(link, Closed::Reply("a run that does not link"));
            return;
        }
        if !self.s.walk_extend(chain, lowest, next, &hashes) {
            // Refused (the storage holds no more walks now): the walk
            // ends, and the chain waits until it is told again, not
            // walked again on another link at once.
            self.m.walking.remove(&chain);
            if let Some(l) = self.link(link)
                && l.tasks.remove(&chain).is_some()
            {
                self.b.spend(Some(link), Work::TaskEnded);
            }
        } else if lowest == 1 {
            self.end_task(link, chain);
        } else {
            self.go_on(link, chain);
        }
    }

    // --- Forks ---

    fn fork(&mut self, link: LinkId, id: Option<u32>, chain: ChainId, proof: Option<&[u8]>) {
        if let Some(id) = id {
            let Some(ask) = self.reply(link, id) else {
                return;
            };
            let Ask::Fork { chain: asked } = ask else {
                self.close(link, Closed::Reply("a proof answering another request"));
                return;
            };
            if asked != chain {
                self.close(link, Closed::Reply("a proof of another chain"));
                return;
            }
        }
        if let Some(bytes) = proof {
            let Ok(proof) = ForkProof::parse(bytes) else {
                self.close(link, Closed::Reply("a proof that does not parse"));
                return;
            };
            if proof.chain() != chain {
                self.close(link, Closed::Reply("a proof of another chain"));
                return;
            }
            // Only for a chain known here; never for a listed prefix, which
            // the first record fixes (another head there is not of the
            // share).
            if self.s.author(chain).is_some() && self.s.listed(chain).is_none() {
                self.b.spend(Some(link), Work::Verify);
                self.b.spend(Some(link), Work::Verify);
                if !proof.verify() {
                    self.close(link, Closed::Invalid);
                    return;
                }
                self.take_fork(&proof);
            }
        }
        if id.is_some() {
            self.end_task(link, chain);
        }
    }

    /// Takes `proof`; if it lowered the place, sends it to every Reader
    /// link whose told tip shows the chain unforked or forked higher.
    fn take_fork(&mut self, proof: &ForkProof) {
        let taken = self.s.take_fork(proof);
        self.events();
        if taken != ForkTaken::Lowered {
            return;
        }
        let chain = proof.chain();
        let place = proof.place();
        let Ok(bytes) = ProofBytes::try_from(&*proof.bytes()) else {
            return;
        };
        let links: Vec<LinkId> = self
            .m
            .links
            .iter()
            .filter(|(_, l)| {
                l.phase == Phase::Reader
                    && l.told
                        .get(&chain)
                        .is_some_and(|told| told.tip.fork == 0 || told.tip.fork > place)
            })
            .map(|(id, _)| *id)
            .collect();
        for link in links {
            self.send(
                link,
                Sync::Fork {
                    id: None,
                    chain,
                    proof: Some(bytes.clone()),
                },
            );
        }
    }

    // --- Refusals ---

    /// A change of `chain` was refused for good: told to its author, if
    /// linked.
    fn refuse(&mut self, chain: ChainId, seq: u64, why: &[u8]) {
        let Some(author) = self.s.author(chain) else {
            return;
        };
        let Ok(why) = Why::try_from(why) else {
            return;
        };
        let links: Vec<LinkId> = self
            .m
            .links
            .iter()
            .filter(|(_, l)| l.phase == Phase::Reader && l.remote == author)
            .map(|(id, _)| *id)
            .collect();
        for link in links {
            let mut changes = Bounded::new();
            let _ = changes.push((ChangeId { chain, seq }, why.clone()));
            self.send(link, Sync::Refused { changes });
        }
    }

    fn refused(&mut self, link: LinkId, changes: Bounded<(ChangeId, Why), REFUSED>) {
        let Some(from) = self.m.links.get(&link).map(|l| l.remote) else {
            return;
        };
        let local = self.s.local();
        let mine: Vec<(ChangeId, Vec<u8>)> = changes
            .into_iter()
            .filter(|(change, _)| {
                self.s.author(change.chain) == Some(local)
                    && self.s.head_at(change.chain, change.seq).is_some()
            })
            .map(|(change, why)| (change, why.into_vec()))
            .collect();
        self.b.spend(Some(link), Work::Read(mine.len()));
        if !mine.is_empty() {
            self.out.effects.push(Effect::Refused {
                from,
                changes: mine,
            });
        }
    }

    // --- Stops ---

    /// `chain` is stopped at `head`, judged here from a body that opened
    /// and matched it, until `cause` passes.
    fn stopped(&mut self, chain: ChainId, head: Box<SignedHead>, cause: Cause) {
        let wake = match cause {
            Cause::Change(change) => Wake::Change(change),
            Cause::ViewOnly(key) => Wake::Link(key),
        };
        let seq = head.head.seq;
        let hash = head.hash();
        if let Some(stop) = self.m.stops.get_mut(&chain)
            && stop.seq() == seq
            && stop.hash == hash
        {
            // The same head judged again (from another link): one stop,
            // compared once per link, woken by what it waits for now.
            let old = mem::replace(&mut stop.wake, wake);
            if old != wake {
                if let Some(chains) = self.m.wakes.get_mut(&old) {
                    chains.remove(&chain);
                    if chains.is_empty() {
                        self.m.wakes.remove(&old);
                    }
                }
                self.m.wakes.entry(wake).or_default().insert(chain);
            }
            return;
        }
        let backoff = match self.m.backoffs.get(&chain) {
            Some((at, last)) if *at == seq => last.saturating_mul(2).min(STOP_MOST),
            Some(_) | None => STOP_FIRST,
        };
        self.m.backoffs.insert(chain, (seq, backoff));
        self.clear_stop(chain);
        self.m.stops.insert(
            chain,
            Stop {
                head,
                hash,
                wake,
                retry_after: self.now.saturating_add(backoff),
                woken: false,
            },
        );
        self.m.wakes.entry(wake).or_default().insert(chain);
        // A link whose told tip covers the stop compares it.
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in links {
            self.schedule(link, chain);
        }
    }

    fn clear_stop(&mut self, chain: ChainId) {
        if let Some(stop) = self.m.stops.remove(&chain)
            && let Some(chains) = self.m.wakes.get_mut(&stop.wake)
        {
            chains.remove(&chain);
            if chains.is_empty() {
                self.m.wakes.remove(&stop.wake);
            }
        }
        for l in self.m.links.values_mut() {
            l.compared.retain(|(c, _, _)| *c != chain);
        }
    }

    fn wake(&mut self, wake: Wake) {
        let Some(chains) = self.m.wakes.remove(&wake) else {
            return;
        };
        for chain in chains {
            if let Some(stop) = self.m.stops.get_mut(&chain) {
                stop.woken = true;
            }
        }
    }

    /// Retries the woken stops whose wait has passed: the chain is tried
    /// again on every link that told it.
    fn retry_stops(&mut self) {
        let due: Vec<ChainId> = self
            .m
            .stops
            .iter()
            .filter(|(_, stop)| stop.woken && stop.retry_after <= self.now)
            .map(|(chain, _)| *chain)
            .collect();
        for chain in due {
            self.m.stops.remove(&chain);
            self.retry_chain(chain);
        }
    }

    /// Tries `chain` afresh on every link that told it: what stopped it is
    /// gone.
    fn retry_chain(&mut self, chain: ChainId) {
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in links {
            if let Some(l) = self.link(link) {
                if let Some(told) = l.told.get_mut(&chain) {
                    told.tried = false;
                    told.attempts = 0;
                }
                l.compared.retain(|(c, _, _)| *c != chain);
            }
            self.schedule(link, chain);
        }
    }

    // --- Journal events ---

    fn events(&mut self) {
        loop {
            let events = self.s.events();
            if events.is_empty() {
                return;
            }
            for event in events {
                match event {
                    Event::Applied { change, hash } => self.applied(change, hash),
                    Event::Known(chain) => self.known(chain),
                    Event::Frozen { chain, from } => self.frozen(chain, from),
                }
            }
        }
    }

    fn applied(&mut self, change: ChangeId, hash: ChangeHash) {
        let chain = change.chain;
        self.m.own_digest = None;
        if self
            .m
            .stops
            .get(&chain)
            .is_some_and(|stop| change.seq >= stop.seq())
        {
            // Released past its stop (from the held cache): what the links
            // told beyond it is pulled again.
            self.clear_stop(chain);
            self.m.backoffs.remove(&chain);
            self.retry_chain(chain);
        }
        self.wake(Wake::Change(change));
        if let Some((through, _)) = self.s.listed(chain)
            && change.seq >= through
            && self.s.walk(chain).is_some()
        {
            self.s.walk_end(chain);
        }
        let before = change
            .seq
            .checked_sub(1)
            .and_then(|seq| hash_at(self.s, chain, seq).map(|hash| (seq, hash)));
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in links {
            let Some(l) = self.m.links.get_mut(&link) else {
                continue;
            };
            if l.phase != Phase::Reader {
                continue;
            }
            l.dirty.insert(chain);
            let at_before = |mark: Option<(u64, ChangeHash)>| before.is_some() && mark == before;
            let push = change.seq > 1
                && (at_before(l.told.get(&chain).map(|t| (t.tip.seq, t.tip.hash)))
                    || at_before(l.sent.get(&chain).copied()));
            if push {
                l.sent.insert(chain, (change.seq, hash));
                let generation = l.generation;
                self.out.effects.push(Effect::Serve(Job {
                    link,
                    generation,
                    page: Page::Fresh { change },
                }));
            }
        }
    }

    fn known(&mut self, chain: ChainId) {
        self.m.own_digest = None;
        let origin = self.s.origin(chain);
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in links {
            let Some(l) = self.m.links.get_mut(&link) else {
                continue;
            };
            l.dirty.insert(chain);
            let claim = l.told.get(&chain).map(|told| told.tip.project);
            if let (Some(claim), Some(origin)) = (claim, origin)
                && claim != origin
            {
                self.close(link, Closed::Claim);
                continue;
            }
            self.schedule(link, chain);
        }
    }

    fn frozen(&mut self, chain: ChainId, from: u64) {
        self.m.own_digest = None;
        if self
            .m
            .stops
            .get(&chain)
            .is_some_and(|stop| stop.seq() >= from)
        {
            self.clear_stop(chain);
        }
        // Changes this freeze makes dead wake what waits for them.
        let dead: Vec<Wake> = self
            .m
            .wakes
            .keys()
            .filter(|wake| matches!(wake, Wake::Change(change) if change.chain == chain && change.seq >= from))
            .copied()
            .collect();
        for wake in dead {
            self.wake(wake);
        }
        for l in self.m.links.values_mut() {
            if l.phase == Phase::Reader {
                l.dirty.insert(chain);
            }
        }
        // A start of its author past the local guard may be taken now.
        self.ask_declined_everywhere();
    }

    /// Declines `chain` on `link` (sync §4.4), the entry charged to the
    /// link's state ([`PER_DECLINED`]): the link closed if it is past its
    /// ceiling.
    fn decline(&mut self, link: LinkId, chain: ChainId) {
        let Some(l) = self.m.links.get(&link) else {
            return;
        };
        if l.declined.contains(&chain) {
            return;
        }
        if !self.b.charge(link, PER_DECLINED) {
            self.close(link, Closed::TooManyChains);
            return;
        }
        if let Some(l) = self.link(link) {
            l.declined.insert(chain);
            l.charged = l.charged.saturating_add(PER_DECLINED);
        }
    }

    /// Asks again on `link` for what it declined: each chain's told tip
    /// is tried afresh.
    fn ask_declined(&mut self, link: LinkId) {
        let Some(l) = self.link(link) else {
            return;
        };
        let declined = mem::take(&mut l.declined);
        let refund = declined.len().saturating_mul(PER_DECLINED);
        l.charged = l.charged.saturating_sub(refund);
        for chain in &declined {
            if let Some(told) = l.told.get_mut(chain) {
                told.tried = false;
                told.attempts = 0;
            }
        }
        self.b.refund(link, refund);
        self.b.spend(Some(link), Work::Read(declined.len()));
        for chain in declined {
            self.schedule(link, chain);
        }
    }

    /// Asks again on every link for what it declined.
    fn ask_declined_everywhere(&mut self) {
        let links: Vec<LinkId> = self
            .m
            .links
            .iter()
            .filter(|(_, l)| !l.declined.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for link in links {
            self.ask_declined(link);
        }
    }

    // --- Timer and flushing ---

    fn timer(&mut self) {
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in &links {
            let late = self.m.links.get(link).is_some_and(|l| {
                l.open() && l.asked.values().any(|asked| asked.deadline <= self.now)
            });
            if late {
                self.close(*link, Closed::Stalled);
            }
        }
        for link in &links {
            let now = self.now;
            if let Some(l) = self.link(*link)
                && l.phase == Phase::Reader
                && l.summary_at <= now
            {
                l.summary_at = now.saturating_add(SUMMARY_EVERY);
                l.summary_due = true;
            }
        }
        self.events();
        self.retry_stops();
        self.pump_all();
    }

    /// The count and digest of this side's tips, computed in one bounded
    /// pass when they changed.
    fn own_digest(&mut self) -> (u32, [u8; 32]) {
        if let Some(digest) = self.m.own_digest {
            return digest;
        }
        let mut digest = Digest::default();
        let mut after = None;
        loop {
            let (tips, next) = self.s.tips_after(after, None, TIPS_PAGE);
            self.b.spend(None, Work::Read(tips.len()));
            for tip in &tips {
                digest.add(tip);
            }
            match next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        let digest = digest.finish();
        self.m.own_digest = Some(digest);
        digest
    }

    /// Tells each Reader link its dirty tips, then a `Summary` where one
    /// is due.
    fn flush(&mut self) {
        let links: Vec<LinkId> = self.m.links.keys().copied().collect();
        for link in links {
            let Some(l) = self.m.links.get_mut(&link) else {
                continue;
            };
            if l.phase != Phase::Reader {
                continue;
            }
            let dirty = mem::take(&mut l.dirty);
            let summary = mem::take(&mut l.summary_due);
            let tips: Vec<Tip> = dirty
                .iter()
                .filter_map(|chain| self.s.tip(*chain))
                .collect();
            self.b.spend(Some(link), Work::Read(dirty.len()));
            for chunk in tips.chunks(TIPS) {
                self.send(
                    link,
                    Sync::Tips {
                        tips: Bounded::truncated(chunk.to_vec()),
                    },
                );
            }
            if summary {
                let membership = self.s.membership();
                let tips = self.own_digest();
                self.send(link, Sync::Summary { membership, tips });
            }
        }
    }

    // --- Serving pages ---

    fn serve(&mut self, job: &Job) -> Option<Send> {
        let l = self.m.links.get_mut(&job.link)?;
        match job.page {
            Page::Changes { .. } => l.wants_pending = l.wants_pending.saturating_sub(1),
            Page::Records { .. } => l.records_pending = false,
            Page::Fresh { .. } => {}
        }
        if l.generation != job.generation || !l.open() || self.s.recovering() {
            return None;
        }
        let remote = l.remote;
        // Rights are checked at each use (§3.6): a Reader's link whose
        // other side the chain no longer names a member is served nothing.
        let reader = l.phase == Phase::Reader && self.s.is_member(remote);
        let message = match job.page {
            Page::Changes {
                id,
                chain,
                after,
                at,
                most,
            } => {
                if !reader {
                    return None;
                }
                self.changes_page(job.link, id, chain, after, at, most)
            }
            Page::Records { id, after, at } => {
                if !self.s.is_member(remote) {
                    return None;
                }
                match self.s.records_after(after, at) {
                    Records::Page { records, more } => {
                        let mut page = Vec::new();
                        let mut bytes = 0usize;
                        let mut cut = false;
                        for record in records {
                            bytes = bytes.saturating_add(record.len());
                            match RecordBytes::try_from(record) {
                                Ok(record) if bytes <= RECORDS_BYTES && page.len() < RECORDS => {
                                    page.push(record);
                                }
                                Ok(_) | Err(_) => {
                                    cut = true;
                                    break;
                                }
                            }
                        }
                        self.b.spend(Some(job.link), Work::Served(bytes));
                        Sync::Records {
                            id: Some(id),
                            more: more || cut,
                            records: Bounded::truncated(page),
                        }
                    }
                    Records::Diverged(record) => Sync::RecordsDiverged {
                        id,
                        record: RecordBytes::try_from(record).ok()?,
                    },
                }
            }
            Page::Fresh { change } => {
                if !reader {
                    return None;
                }
                let (envelopes, _) =
                    self.s
                        .changes_after(change.chain, change.seq - 1, 1, PAGE_BYTES - AROUND_PAGE);
                let envelope = envelopes.into_iter().next()?;
                let parsed = Envelope::parse(&envelope)?;
                if parsed.chain() != change.chain || parsed.seq() != change.seq {
                    return None;
                }
                self.b.spend(Some(job.link), Work::Served(envelope.len()));
                let mut changes = Bounded::new();
                changes.push(EnvelopeBytes::try_from(envelope).ok()?).ok()?;
                Sync::Fresh { changes }
            }
        };
        Some(Send {
            link: job.link,
            generation: job.generation,
            message,
        })
    }

    /// The answer to a `Want` (§3.3).
    fn changes_page(
        &mut self,
        link: LinkId,
        id: u32,
        chain: ChainId,
        after: u64,
        at: ChangeHash,
        most: u16,
    ) -> Sync {
        let empty = Sync::Changes {
            id,
            chain,
            changes: Bounded::new(),
            more: false,
        };
        self.b.spend(Some(link), Work::Read(1));
        let seq = self.s.tip(chain).map_or(0, |tip| tip.seq);
        if after > seq {
            return empty;
        }
        if hash_at(self.s, chain, after) != Some(at) {
            return Sync::Diverged { id, chain };
        }
        let room = PAGE_BYTES - AROUND_PAGE;
        let (envelopes, more) = self.s.changes_after(chain, after, usize::from(most), room);
        self.b.spend(Some(link), Work::Read(envelopes.len()));
        let mut page = PageBuilder::<EnvelopeBytes, CHANGES>::new(room);
        let mut served = 0usize;
        for envelope in envelopes {
            let Ok(envelope) = EnvelopeBytes::try_from(envelope) else {
                break;
            };
            let length = envelope.len();
            if page.push(envelope).is_err() {
                break;
            }
            served = served.saturating_add(length);
        }
        self.b.spend(Some(link), Work::Served(served));
        let full = page.is_full();
        let page = page.finish();
        if page.items.len() > usize::from(most) {
            return empty;
        }
        Sync::Changes {
            id,
            chain,
            changes: page.items,
            more: more || full,
        }
    }
}
