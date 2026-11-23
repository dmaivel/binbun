//! A session shared or joined ([`Peer`]): its membership chain and the
//! epoch keys wrapped to it, its links and the sync machine over them,
//! and what it tells ([`Notice`]).
//!
//! A peer runs on the tokio runtime it is made in: one task accepting
//! links, one per link (its sync lane read and written, its control
//! lane, and once a reader's its live and blob lanes), one driving the
//! sync machine on time and on what changed here and, for a joiner, one
//! dialling the host again whenever the link is lost; and the live
//! session's ([`crate::live`]): one sending this peer's presence.
//!
//! **Admission** is by the owner, ahead of time: they add a key from an
//! identity card whose fingerprint they checked ([`Peer::add`]); a key the
//! chain names, proved by the transport, is let in at once. Asking the
//! owner live, for those holding the ticket, is an option
//! ([`Config::approve`]).
//!
//! **Where the journal is**: the owner's share is its own project, made
//! the share's in place (the prefixes of its own chains and its agents'
//! listed in the first record; the rest kept apart). A joiner's session
//! is in a project directory of its own for the share (its caller's
//! choice: `binbun_session::project::share_dir`), whose journal is made
//! the share's once the chain and its key have come.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant};

use binbun_bounded::{self as bounded, Text};
use binbun_session::identity::Identity;
use binbun_session::journal::{
    Authority, ChainId, ChangeHash, ChangeId, EngineVersion, FrozenBy, ProjectId, PublicKey,
    Refused,
};
use binbun_session::{Event, Session, Stage, Waited};
use binbun_sync::budget::PER_CHAIN;
use binbun_sync::envelope::Envelope;
use binbun_sync::wire::{CHANGES, PAGE_BYTES, WHY};
use binbun_sync::{
    Admission, Closed, Effect, Job, LinkId, Local, Machine, Output, Page, Phase, Report,
    Send as Outgoing, Storage as _, Taken,
};
#[cfg(test)]
use tokio::sync::oneshot;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::Error;
use crate::authority::Judge;
use crate::blobs::{Kind, Shelf};
use crate::budgets::{Budgets, Held, LinkBudget, ShareBudget};
use crate::crypto::{self, EpochKey};
use crate::link::{self, Dial, LinkState, Out};
use crate::live::Live;
use crate::membership::{
    self, Binary, Cut, MAX_BEFORE, MAX_THROUGH, Membership, Op, Record, Role, SignedRecord,
};
use crate::share::{Book, Charges, Sealing, View};
use crate::store::{Intent, Kept, Store};
use crate::ticket::{Card, JoinTicket};
use crate::transport::{BoxFuture, Transport};

/// Who asks to join, as the approver sees them (live approval only).
#[derive(Clone, Debug)]
pub struct Request {
    /// Their identity card (its key the one the link proved).
    pub card: Card,
    /// How their link reaches this peer.
    pub path: String,
    /// The binbun they run.
    pub engine: EngineVersion,
}

/// Decides who joins by the ticket, live: a role to admit them as, or
/// `None` to refuse. The future is dropped, the request withdrawn, when
/// the asker's link closes or the invite is forgotten
/// ([`Peer::stop_inviting`]) first, or after five minutes unanswered (the
/// request is then refused). Each key asks at most three times in fifteen
/// minutes.
pub type Approver = Arc<dyn Fn(Request) -> BoxFuture<'static, Option<Role>> + Send + Sync>;

/// Hears what a peer tells.
pub type Notifier = Arc<dyn Fn(&Notice) + Send + Sync>;

/// What a peer tells.
#[derive(Clone, Debug)]
pub enum Notice {
    /// A link to a member is up.
    Linked {
        /// The member.
        peer: PublicKey,
        /// Their role, if this peer knows it yet (a joiner learns the
        /// host's from the chain the host sends).
        role: Option<Role>,
        /// How the link reaches them.
        path: String,
        /// Why they are view-only in this session, if they are (a host's
        /// view of a peer on another build).
        view_only: Option<String>,
    },
    /// A link is down.
    Unlinked {
        /// The member.
        peer: PublicKey,
        /// Why.
        why: String,
    },
    /// This peer's request waits for the host's approval.
    Waiting,
    /// A member admitted (by this peer, the owner).
    Admitted {
        /// The member.
        member: PublicKey,
        /// Their role.
        role: Role,
    },
    /// Someone asking to join was refused, and why.
    Turned {
        /// Who asked.
        peer: PublicKey,
        /// Why not.
        why: String,
    },
    /// The membership chain grew: its last record and epoch now.
    Membership {
        /// The last record's number.
        seq: u64,
        /// The epoch.
        epoch: u32,
    },
    /// The membership chain, which this peer signs, passed
    /// [`membership::CROWDED`] bytes: past [`membership::MAX_CHAIN`] only
    /// removals are taken, and none past
    /// [`membership::MAX_CHAIN_REMOVING`].
    Crowded {
        /// The chain's bytes ([`Membership::bytes`]).
        bytes: usize,
    },
    /// This peer's request to join was refused.
    Denied(String),
    /// This peer was put out.
    Kicked(String),
    /// This peer is view-only in this session (another build than the
    /// host's), and why: the host does not take its changes while it is
    /// linked.
    ViewOnly(String),
    /// Changes came from a member.
    Took {
        /// The member.
        from: PublicKey,
        /// The changes taken.
        taken: usize,
        /// The keys left in conflict.
        conflicts: usize,
    },
    /// A change refused (by this peer's checks or the session's).
    Refused(Refused),
    /// Sending a member a file this peer offers ([`Peer::offer`]).
    Sending {
        /// The member.
        to: PublicKey,
        /// What it is.
        kind: Kind,
        /// Its file name.
        name: String,
    },
    /// Done sending it (what of it the member lacked), or stopped.
    Sent {
        /// The member.
        to: PublicKey,
        /// What it is.
        kind: Kind,
        /// Its file name.
        name: String,
        /// Why it stopped, if it did.
        error: Option<String>,
    },
    /// Something failed.
    Failed(String),
}

/// What taking envelopes came to ([`Peer::receive`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// The changes taken.
    pub taken: usize,
    /// The changes refused, and why.
    pub refused: Vec<Refused>,
    /// How many were not taken now (waiting for a change, a key, a
    /// record).
    pub held: usize,
}

/// What flushing came to ([`Peer::flush`]): the members linked when it
/// began, by what their links said.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flushed {
    /// Those whose link told tips and a membership head that hold this
    /// peer's own changes and its membership chain.
    pub acknowledged: Vec<PublicKey>,
    /// Those still linked when the time ran out without telling so.
    pub unacknowledged: Vec<PublicKey>,
    /// Those whose link went before they told so.
    pub disconnected: Vec<PublicKey>,
}

/// How often a flush looks at what the links told.
const FLUSH_POLL: Duration = Duration::from_millis(5);

/// How often the sync machine's time passes (deadlines, summaries, stops
/// to retry, tasks to start).
const TICK: Duration = Duration::from_millis(250);

/// How a peer is made.
#[derive(Clone)]
pub struct Config {
    /// The identity of the session's changes (the same key signs them).
    pub identity: Identity,
    /// The name on this peer's card.
    pub name: String,
    /// Who decides, live, who joins by the ticket (an owner's); none:
    /// only those the owner added ([`Peer::add`]) are let in.
    pub approve: Option<Approver>,
    /// Who hears what the peer tells.
    pub notify: Option<Notifier>,
    /// The binbun this peer speaks for ([`EngineVersion::this`]), told in
    /// its hello: a peer of another build is view-only.
    pub engine: EngineVersion,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("identity", &self.identity)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// What a peer knows, behind its lock.
pub(crate) struct State {
    pub(crate) membership: Membership,
    /// The epoch keys this peer holds.
    pub(crate) keys: BTreeMap<u32, EpochKey>,
    /// The changes this peer refused, in order.
    pub(crate) refused: Vec<Refused>,
    /// Those refused, to list each once.
    pub(crate) listed: BTreeSet<(Option<ChangeId>, String)>,
    pub(crate) links: BTreeMap<PublicKey, LinkState>,
    /// What each member's last link told, kept past it for a flush.
    pub(crate) reports: BTreeMap<PublicKey, KeptReport>,
    /// This share's invite (a host's, while sharing).
    pub(crate) invite: Option<[u8; 16]>,
    /// Why this peer is view-only in this session, if the host said so.
    pub(crate) view_only: Option<String>,
    /// This peer's changes each member said it refused: each listed once
    /// per member.
    pub(crate) told: BTreeSet<(PublicKey, ChangeId)>,
    /// Why the chain taken is not this session's to sync, if it is not:
    /// it names another binary.
    pub(crate) foreign: Option<String>,
    /// Why the share is in recovery, if it is: a record's intent is kept
    /// and the rest of taking it failed ([`Inner::take_record`]). Until it
    /// is done, no link is up, nothing is served or taken and no other
    /// record is taken.
    pub(crate) recovery: Option<String>,
    /// What the sync machine's storage keeps.
    pub(crate) book: Book,
}

/// What a member's link told of this install's own chains and of the
/// membership, kept past the link for a flush of it: the link, its
/// report, and the report's charge of the process's `sync.link`.
pub(crate) struct KeptReport {
    pub(crate) link: LinkId,
    pub(crate) report: Report,
    _held: Held,
}

/// The sync machine and the budgets of its links, behind their lock
/// (taken before the state's).
pub(crate) struct Driver {
    pub(crate) machine: Machine,
    pub(crate) budgets: BTreeMap<LinkId, Arc<LinkBudget>>,
}

/// A peer's insides, shared by its tasks.
pub(crate) struct Inner {
    /// The session in use (a newer analysis of the binary takes the
    /// place of the one before: [`Peer::set_session`]).
    session: RwLock<Arc<Session>>,
    pub(crate) transport: Arc<dyn Transport>,
    pub(crate) me: PublicKey,
    pub(crate) secret: Zeroizing<[u8; 32]>,
    pub(crate) agreement: Zeroizing<[u8; 32]>,
    pub(crate) card: Card,
    pub(crate) approve: Option<Approver>,
    notify: Option<Notifier>,
    /// The binbun this peer speaks for.
    pub(crate) engine: EngineVersion,
    /// The binary the session is on: only a chain naming it is synced.
    pub(crate) binary: Binary,
    /// What remote parties may make this process spend (the
    /// transport's).
    pub(crate) budgets: Budgets,
    /// The share's own: the page kept for its membership records.
    pub(crate) records: ShareBudget,
    /// Where the next link to come up is held, before it is put among the
    /// links: told it got there, it waits for the word to go on.
    #[cfg(test)]
    pub(crate) linking: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    /// Told when the invite is forgotten: requests waiting for the
    /// approver are withdrawn.
    pub(crate) uninvited: watch::Sender<()>,
    store: Option<Store>,
    state: Mutex<State>,
    driver: Mutex<Driver>,
    /// The journal's authority.
    pub(crate) judge: Arc<Judge>,
    /// Set when the session's history changed: this install's own chains
    /// are looked at again.
    pub(crate) own_dirty: Arc<AtomicBool>,
    /// Woken when the journal changed here: the machine is told.
    pub(crate) changed: Arc<Notify>,
    /// Told when the membership chain grew from records taken: an epoch
    /// key wrapped to this peer may have come with them
    /// ([`Self::epoch_key`]).
    pub(crate) keyed: watch::Sender<()>,
    /// The live session: participants, presence, chat.
    pub(crate) live: Live,
    /// The files this peer offers, and where it fetches.
    pub(crate) blobs: Shelf,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// When the peer was made: the machine's clock.
    start: Instant,
    /// The step of taking a record after which the next one is stopped,
    /// as a crash or a failing disk would stop it.
    #[cfg(test)]
    stop: Mutex<Option<Step>>,
    /// What a test does after a step of taking a record, before the next
    /// (as another thread of the process would, outside the state's lock).
    #[cfg(test)]
    meanwhile: Mutex<Option<(Step, Meanwhile)>>,
}

/// What a test does between steps of taking a record ([`Inner::after`]).
#[cfg(test)]
type Meanwhile = Box<dyn FnOnce() + Send>;

/// A step of taking a membership record (sync §4.3), each a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The intent written.
    Intent,
    /// The freezes it holds made.
    Frozen,
    /// The record appended to the chain kept.
    Appended,
    /// The record published (before the intent is removed).
    Published,
}

/// What to do once the machine's locks are given back.
#[derive(Default)]
pub(crate) struct After {
    notices: Vec<Notice>,
    /// Judge this install's pending work.
    promote: bool,
}

/// Why the machine closed a link, for people.
fn closed_why(why: Closed) -> String {
    match why {
        Closed::Malformed => "a frame past its limit, or one that does not read".to_owned(),
        Closed::Phase(name) => format!("a message ({name}) its phase does not allow"),
        Closed::Reply(why) => format!("a reply that does not answer its request: {why}"),
        Closed::Requests => "more requests outstanding than allowed".to_owned(),
        Closed::Strays => "too many replies to no request".to_owned(),
        Closed::Stalled => "a request unanswered in time".to_owned(),
        Closed::Genesis => "another share".to_owned(),
        Closed::Membership => "this link's membership chain does not match".to_owned(),
        Closed::Records => "membership records that do not verify".to_owned(),
        Closed::TooManyChains => "it names too many chains".to_owned(),
        Closed::Claim => "a tip whose chain proved to be of another log".to_owned(),
        Closed::Invalid => "a head or proof that does not verify".to_owned(),
        Closed::Revoked => "removed from the project".to_owned(),
        Closed::NotServed => "asked for records while no member".to_owned(),
        Closed::Recovering => "recovering its membership chain".to_owned(),
    }
}

/// Locks `mutex` (as it is, if a holder panicked).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Inner {
    /// The session in use.
    pub(crate) fn session(&self) -> Arc<Session> {
        Arc::clone(&self.session.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Tells the machine whenever `session`'s history changes.
    fn listen(&self, session: &Session) {
        let changed = Arc::clone(&self.changed);
        let dirty = Arc::clone(&self.own_dirty);
        session.on_event(move |event| {
            if matches!(event, Event::History(_)) {
                dirty.store(true, Ordering::SeqCst);
                changed.notify_one();
            }
        });
    }

    /// The state, locked.
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// The machine, locked (before the state, never after).
    pub(crate) fn driver(&self) -> MutexGuard<'_, Driver> {
        lock(&self.driver)
    }

    /// Tells `notice`.
    pub(crate) fn tell(&self, notice: &Notice) {
        if let Some(notify) = &self.notify {
            notify(notice);
        }
    }

    /// Runs `task` as this peer's, stopped when it closes.
    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let handle = tokio::spawn(task);
        let mut tasks = lock(&self.tasks);
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
    }

    /// Runs `step` on the machine with the share as its storage, then
    /// does what it says (and what the storage asked of it since), then,
    /// with no lock held, what is left.
    pub(crate) fn drive(
        self: &Arc<Self>,
        step: impl FnOnce(&mut Machine, &mut View<'_>, &mut Charges<'_>, Duration) -> Output,
    ) {
        let mut after = After::default();
        {
            let mut driver = self.driver();
            let mut state = self.state();
            self.drive_held(&mut driver, &mut state, step, &mut after);
        }
        self.finish(&after);
    }

    /// [`Self::drive`] in a hold of the machine and the state already
    /// taken (`driver`, `state`): what is left for no lock held is put in
    /// `after`, for [`Self::finish`].
    pub(crate) fn drive_held(
        &self,
        driver: &mut Driver,
        state: &mut State,
        step: impl FnOnce(&mut Machine, &mut View<'_>, &mut Charges<'_>, Duration) -> Output,
        after: &mut After,
    ) {
        let now = self.start.elapsed();
        let Driver { machine, budgets } = driver;
        let mut charges = Charges { links: budgets };
        let output = step(machine, &mut View { inner: self, state }, &mut charges, now);
        self.dispatch(machine, state, output, after);
        while !state.book.locals.is_empty() {
            for local in std::mem::take(&mut state.book.locals) {
                let output =
                    machine.on_local(&mut View { inner: self, state }, &mut charges, now, local);
                self.dispatch(machine, state, output, after);
            }
        }
    }

    /// What a drive left for no lock held, `after`: its notices told,
    /// pending work judged.
    pub(crate) fn finish(&self, after: &After) {
        for notice in &after.notices {
            self.tell(notice);
        }
        if after.promote {
            self.promote();
        }
    }

    /// Does what the machine said: messages queued on their links, links
    /// closed (one whose other side was removed kicked first), pages
    /// queued to build, lanes opened, refusals listed, what a link told
    /// kept for a flush.
    fn dispatch(&self, machine: &Machine, state: &mut State, output: Output, after: &mut After) {
        let find = |state: &State, link: LinkId| {
            state
                .links
                .iter()
                .find(|(_, known)| known.id == link)
                .map(|(remote, _)| *remote)
        };
        for send in output.sends {
            if let Some(remote) = find(state, send.link)
                && let Some(known) = state.links.get(&remote)
            {
                let _ = known.out.send(Out::Send(send));
            }
        }
        for effect in output.effects {
            match effect {
                Effect::Close { link, why } => {
                    let Some(remote) = find(state, link) else {
                        continue;
                    };
                    let removed = why == Closed::Revoked && state.membership.role(remote).is_none();
                    let Some(known) = state.links.get(&remote) else {
                        continue;
                    };
                    let reason = closed_why(why);
                    let _ = known.closed.set(reason.clone());
                    // What its writer has in hand is dropped, its permits
                    // given back, whether or not a kick is still to go.
                    known.out.stop();
                    if removed {
                        // Put out with the records saying so, which freeze
                        // what they wrote past the cut on their side too:
                        // from the head the link last told, through the
                        // removal.
                        let theirs = machine
                            .report(link)
                            .and_then(|report| report.membership)
                            .unwrap_or_default();
                        let _ = known.control.try_send(link::kick(
                            &state.membership,
                            remote,
                            theirs,
                            "removed from the project by its owner",
                        ));
                    } else {
                        known.link.close(&reason);
                    }
                }
                Effect::Serve(job) => {
                    if let Some(remote) = find(state, job.link)
                        && let Some(known) = state.links.get(&remote)
                    {
                        let _ = known.out.send(Out::Job(job));
                    }
                }
                Effect::Reader(link) => {
                    if let Some(remote) = find(state, link)
                        && let Some(known) = state.links.get(&remote)
                    {
                        known.reader.send_replace(true);
                    }
                    // Own commits judged at once from now; what was
                    // written pending meanwhile judged now.
                    self.judge.set_reader(true);
                    after.promote = true;
                }
                Effect::Refused { from, changes } => {
                    for (change, why) in changes {
                        if !state.told.insert((from, change)) {
                            continue;
                        }
                        let why = String::from_utf8_lossy(&why);
                        let why: String = why.chars().take(WHY).collect();
                        let refusal = Refused {
                            change: Some(change),
                            author: Some(self.me),
                            why: format!("refused by {from}: {why}"),
                        };
                        self.list(state, &refusal);
                    }
                }
                Effect::Diverged { link, at, record } => {
                    let who = find(state, link).map_or_else(String::new, |key| key.to_string());
                    let conflicts = bounded::decode::<SignedRecord>(&record)
                        .is_ok_and(|theirs| state.membership.conflicts(at, &theirs));
                    let why = if conflicts {
                        format!(
                            "{who} holds another membership record {at}, signed by the owner who \
                             signed this peer's, after the same records: two records by one \
                             signer at one number"
                        )
                    } else {
                        format!("{who}'s membership chain does not match this peer's")
                    };
                    after.notices.push(Notice::Failed(why));
                }
                Effect::Unlinked {
                    link,
                    remote,
                    report,
                } => self.keep_report(state, (remote, link), report),
            }
        }
    }

    /// Keeps `report`, told by link `link` to `remote` that has gone, for
    /// a flush of that link: only what acknowledges this peer's own chains
    /// (I31), charged to the process's `sync.link` (not kept if refused),
    /// and only in place of an older link's.
    pub(crate) fn keep_report(
        &self,
        state: &mut State,
        (remote, link): (PublicKey, LinkId),
        mut report: Report,
    ) {
        if state
            .reports
            .get(&remote)
            .is_some_and(|kept| kept.link > link)
        {
            return;
        }
        let session = self.session();
        report.tips.retain(|chain, _| {
            session
                .chain_origin(*chain)
                .is_some_and(|origin| origin.author == self.me)
        });
        let bytes = report
            .tips
            .len()
            .saturating_add(1)
            .saturating_mul(PER_CHAIN);
        // An older link's report given back before this one is charged.
        state.reports.remove(&remote);
        if let Some(held) = self.budgets.retain(bytes) {
            state.reports.insert(
                remote,
                KeptReport {
                    link,
                    report,
                    _held: held,
                },
            );
        }
    }

    /// Whether output made for `generation` of `link` may still be
    /// written.
    pub(crate) fn current(&self, link: LinkId, generation: u64) -> bool {
        self.driver().machine.is_current(link, generation)
    }

    /// `link`'s phase.
    pub(crate) fn phase(&self, link: LinkId) -> Option<Phase> {
        self.driver().machine.phase(link)
    }

    /// The phase of link `link` to `remote` if it may still be served
    /// (sync §3.6), asked at each use: up in the machine (Bootstrap or
    /// Reader, not revoked), and the membership chain naming `remote` a
    /// member now.
    pub(crate) fn serving(&self, remote: PublicKey, link: LinkId) -> Option<Phase> {
        let phase = self
            .phase(link)
            .filter(|phase| matches!(phase, Phase::Bootstrap | Phase::Reader))?;
        let member = self
            .state()
            .membership
            .role(remote)
            .is_some_and(|role| role != Role::Store);
        member.then_some(phase)
    }

    /// The message `job` builds, if its link is still of its generation.
    /// A page of changes is read and sealed first, outside the state lock
    /// (sync §3.3); the machine then checks the link is still of the
    /// job's generation and builds the reply from it, or drops it.
    pub(crate) fn serve_job(&self, job: &Job) -> Option<Outgoing> {
        let asked = match job.page {
            Page::Changes {
                chain, after, most, ..
            } => Some((chain, after, usize::from(most))),
            Page::Fresh { change } => Some((change.chain, change.seq.saturating_sub(1), 1)),
            Page::Records { .. } => None,
        };
        let prepared = asked.and_then(|(chain, after, most)| {
            let sealing = Sealing::of(&self.state())?;
            Some(sealing.page(self, chain, after, most))
        });
        let mut driver = self.driver();
        let mut state = self.state();
        state.book.prepared = prepared;
        let Driver { machine, budgets } = &mut *driver;
        let send = machine.serve(
            &mut View {
                inner: self,
                state: &mut state,
            },
            &mut Charges { links: budgets },
            job,
        );
        state.book.prepared = None;
        send
    }

    /// Tells the changes taken from each member since last told.
    pub(crate) fn tell_took(&self) {
        let took = std::mem::take(&mut self.state().book.took);
        for (from, (taken, conflicts)) in took {
            self.tell(&Notice::Took {
                from,
                taken,
                conflicts,
            });
        }
    }

    /// Judges this install's pending work in the share (a link is a
    /// reader's): what is not taken is moved apart and told.
    fn promote(&self) {
        match self.session().promote(true) {
            Ok(applied) => {
                let mut state = self.state();
                View {
                    inner: self,
                    state: &mut state,
                }
                .take_applied(&applied, None);
            }
            Err(error) => self.tell(&Notice::Failed(error.to_string())),
        }
        self.own_dirty.store(true, Ordering::SeqCst);
        self.changed.notify_one();
    }

    /// Judges this install's pending work that the membership chain held
    /// makes final, with no link needed (sync §4.5 rule 4): what is past
    /// a cut, or its author removed, is moved apart and told; the rest
    /// stays pending.
    fn judge_final(&self, state: &mut State) {
        match self.session().promote(false) {
            Ok(applied) => View { inner: self, state }.take_applied(&applied, None),
            Err(error) => self.tell(&Notice::Failed(error.to_string())),
        }
    }

    /// Tells the journal's authority whether a link is a reader's.
    pub(crate) fn readers_changed(&self, state: &State) {
        self.judge
            .set_reader(state.links.values().any(LinkState::is_reader));
    }

    /// Tells the machine the membership grew here by `records` records.
    fn grew(self: &Arc<Self>, records: u64) {
        self.state()
            .book
            .locals
            .push(Local::Membership(Taken { records }));
        self.drive(|_, _, _, _| Output::default());
        self.keyed.send_replace(());
    }

    /// The epoch key `record` (of `project`) wraps to this peer, if it
    /// wraps one.
    fn unwrap_mine(&self, project: ProjectId, record: &Record) -> Option<Result<EpochKey, Error>> {
        let (_, wrapped) = record.wraps.iter().find(|(member, _)| *member == self.me)?;
        Some(crypto::unwrap(
            wrapped,
            project,
            record.epoch,
            self.me,
            &self.agreement,
        ))
    }

    /// Takes the epoch key `record`, taken, wraps to this peer; checks the
    /// history link it carries against the key of the epoch before, if
    /// held (a mismatch is told). Whether a key came.
    fn learn(&self, state: &mut State, record: &Record) -> bool {
        match self.unwrap_mine(state.membership.project(), record) {
            None => false,
            Some(Ok(key)) => {
                if let Some(earlier) = record
                    .epoch
                    .checked_sub(1)
                    .filter(|_| matches!(record.op, Op::Remove { .. }))
                    .and_then(|epoch| state.keys.get(&epoch))
                    && let Err(error) = state.membership.check_history(record.epoch, &key, earlier)
                {
                    self.tell(&Notice::Failed(error.to_string()));
                }
                state.keys.insert(record.epoch, key);
                true
            }
            Some(Err(error)) => {
                self.tell(&Notice::Failed(error.to_string()));
                false
            }
        }
    }

    /// Takes the membership records of a kick, `records` (those held
    /// skipped), each as one recoverable step.
    pub(crate) fn take_kick(self: &Arc<Self>, records: &[SignedRecord]) {
        let mut taken = 0;
        {
            let mut state = self.state();
            if !self.recovered(&mut state) {
                return;
            }
            for signed in records {
                if state.membership.since(0).contains(signed) {
                    continue;
                }
                match self.take_record(&mut state, signed) {
                    Ok(_) => taken += 1,
                    Err(error) => {
                        self.tell(&Notice::Failed(error.to_string()));
                        break;
                    }
                }
            }
        }
        if taken > 0 {
            self.grew(taken);
        }
    }

    /// Whether a first chain, `records`, names the session's binary under
    /// a key it wraps to this peer: checked on a copy, nothing taken.
    /// [`State::foreign`] says why not if it names another.
    pub(crate) fn first_chain_fits(&self, state: &mut State, records: &[&SignedRecord]) -> bool {
        let mut trial = state.membership.clone();
        let mut keys = BTreeMap::new();
        for signed in records {
            let Ok(record) = trial.take(signed) else {
                break;
            };
            if let Some(Ok(key)) = self.unwrap_mine(trial.project(), &record) {
                keys.insert(record.epoch, key);
            }
        }
        let foreign = self.chain_other_binary(&trial, &keys);
        state.foreign.clone_from(&foreign);
        foreign.is_none()
    }

    /// Why `record`, the next, is not this session's to sync, if it is
    /// not: it starts an epoch whose key it wraps to this peer and names
    /// another binary under it.
    fn names_other_binary(&self, state: &State, record: &Record) -> Option<String> {
        let Op::Remove { binary, .. } = &record.op else {
            return None;
        };
        let project = state.membership.project();
        let key = self.unwrap_mine(project, record)?.ok()?;
        self.foreign(membership::open_binary(&key, project, binary))
    }

    /// Takes record `signed`, the next, as one recoverable step (sync
    /// §4.3), under the state's lock: verified against the chain; its
    /// intent kept (the record, and the freezes it causes over every chain
    /// known); the freezes made; the record appended to the chain kept;
    /// the record published (the membership, the keys it wraps to this
    /// peer, the journal's authority); the intent removed. A failure
    /// before the intent is written leaves the record untaken; one while
    /// it is written or after puts the share in recovery
    /// ([`State::recovery`]) until the intent kept, if one is, is carried
    /// out (none: the record is untaken). The record.
    ///
    /// # Errors
    ///
    /// The share is in recovery; the record fails a check, or names
    /// another binary; a write fails.
    pub(crate) fn take_record(
        &self,
        state: &mut State,
        signed: &SignedRecord,
    ) -> Result<Record, Error> {
        if !self.recovered(state) {
            return Err(Error::new("the share is in recovery: no record is taken"));
        }
        let record = state.membership.verify(signed)?;
        if let Some(why) = self.names_other_binary(state, &record) {
            state.foreign = Some(why.clone());
            return Err(Error::new(why));
        }
        self.take_verified(state, signed, &record)?;
        Ok(record)
    }

    /// [`Self::take_record`] of `signed`, verified as `record`.
    fn take_verified(
        &self,
        state: &mut State,
        signed: &SignedRecord,
        record: &Record,
    ) -> Result<(), Error> {
        let session = self.session();
        let known = session.grants();
        let frozen = session.frozen();
        let freezes = state
            .membership
            .caused(record, &known)
            .into_iter()
            .filter(|(chain, from)| frozen.get(chain).is_none_or(|at| at > from))
            .collect();
        let genesis = state
            .membership
            .genesis()
            .unwrap_or_else(|| *blake3::hash(&signed.bytes).as_bytes());
        let intent = Intent::new(genesis, signed.clone(), record.seq, freezes)?;
        // A write of the intent that fails may have put it in place: the
        // share is in recovery then, which carries out whatever intent is
        // kept (none: the record is not taken) and never writes another
        // over it.
        let done = match &self.store {
            Some(store) => store.write_intent(&intent),
            None => Ok(()),
        }
        .and_then(|()| self.complete(state, &intent, record));
        if let Err(error) = &done {
            self.recovering(state, error.to_string());
        }
        done
    }

    /// Steps 3 to 6 of taking `intent`'s record, `record` (verified
    /// against the chain, or its last), each done again whole if it was:
    /// the freezes, the append, the publication (unless published), the
    /// intent removed. The share leaves recovery.
    fn complete(&self, state: &mut State, intent: &Intent, record: &Record) -> Result<(), Error> {
        self.after(Step::Intent)?;
        // This install's pending work the record makes final is judged
        // under it first: moved apart and listed, not merely frozen out
        // (sync §4.5 rule 4). Done again with the step, it finds nothing.
        // Judged by a candidate judge of its own: the journal's authority,
        // which this install's commits are judged by meanwhile, goes by
        // the record only once it is published.
        // A judgement that fails fails the step: the share stays in
        // recovery, and the record is completed (its work judged) again.
        if state.membership.since(0).last() != Some(&intent.record) {
            let mut after = state.membership.clone();
            after.commit(&intent.record, record);
            let candidate = self.judge.candidate(after);
            let applied = self
                .session()
                .judge_final(&candidate)
                .map_err(|error| Error::new(error.to_string()))?;
            View { inner: self, state }.take_applied(&applied, None);
        }
        let by = FrozenBy::Cut {
            record: record.seq,
            hash: *blake3::hash(&intent.record.bytes).as_bytes(),
        };
        let freezes: Vec<(ChainId, u64)> = intent
            .freezes
            .iter()
            .map(|(chain, from)| (*chain, *from))
            .collect();
        self.freeze(state, &freezes, by)?;
        self.after(Step::Frozen)?;
        let records = state.membership.since(0);
        let published = records.last() == Some(&intent.record);
        if let Some(store) = &self.store {
            let before = if published {
                records.split_last().map_or(records, |(_, before)| before)
            } else {
                records
            };
            store.append(before, &intent.record)?;
        }
        self.after(Step::Appended)?;
        if !published {
            self.publish(state, &intent.record, record);
        }
        // A chain begun under a grant the record closes while it was
        // being taken (a commit, a change taken outside this lock: under
        // the old judge) is not among the intent's freezes: frozen now as
        // the record requires, the judge already the record's.
        self.enforce_cuts(state)?;
        self.after(Step::Published)?;
        if let Some(store) = &self.store {
            store.remove_intent()?;
        }
        state.recovery = None;
        Ok(())
    }

    /// Step 5: `signed` (`record`) in the membership; the keys it wraps to
    /// this peer taken; the journal's authority told; the journal made the
    /// share's if it is not yet; held changes judged again; the machine
    /// told of a key or of readiness.
    fn publish(&self, state: &mut State, signed: &SignedRecord, record: &Record) {
        let crowded = state.membership.crowded();
        state.membership.commit(signed, record);
        let keyed = self.learn(state, record);
        self.judge.set_membership(state.membership.clone());
        if let Err(error) = self.bind_share(state) {
            self.tell(&Notice::Failed(error.to_string()));
        }
        self.settle(state);
        if !crowded {
            self.warn_crowded(state);
        }
        let applied = self.session().recheck_held();
        View { inner: self, state }.take_applied(&applied, None);
        self.judge_final(state);
        if keyed {
            state.book.locals.push(Local::Key(record.epoch));
        }
        state.book.locals.push(Local::Readiness);
        if let Op::Remove { member, .. } = record.op
            && member == self.me
        {
            self.tell(&Notice::Kicked(
                "removed from the project by its owner".to_owned(),
            ));
        }
    }

    /// Tells this peer, if it signs the chain and the chain is crowded.
    fn warn_crowded(&self, state: &State) {
        if state.membership.signer() == self.me && state.membership.crowded() {
            self.tell(&Notice::Crowded {
                bytes: state.membership.bytes(),
            });
        }
    }

    /// Puts the share in recovery, because of `why`: its links closed;
    /// none is up, nothing served or taken, until the intent kept is
    /// carried out ([`Self::recovered`]).
    fn recovering(&self, state: &mut State, why: String) {
        for link in state.links.values() {
            link.link.close("recovering its membership chain");
        }
        self.tell(&Notice::Failed(format!(
            "a membership record is not written whole ({why}): this share serves nothing until it \
             is"
        )));
        state.recovery = Some(why);
    }

    /// Whether the share is out of recovery: if it is in it, the intent
    /// kept is carried out again first ([`Self::complete`]).
    pub(crate) fn recovered(&self, state: &mut State) -> bool {
        if state.recovery.is_none() {
            return true;
        }
        let done = match self.store.as_ref().map(Store::intent).transpose() {
            Ok(Some(Some(intent))) => self
                .intent_record(state, &intent)
                .and_then(|record| self.complete(state, &intent, &record)),
            Ok(None | Some(None)) => Ok(()),
            Err(error) => Err(error),
        };
        match done {
            Ok(()) => {
                state.recovery = None;
                true
            }
            Err(error) => {
                state.recovery = Some(error.to_string());
                false
            }
        }
    }

    /// The record of `intent`: the chain's next, verified, or its last.
    fn intent_record(&self, state: &State, intent: &Intent) -> Result<Record, Error> {
        let _ = self;
        if state.membership.since(0).last() == Some(&intent.record) {
            bounded::decode(&intent.record.bytes).map_err(Error::from)
        } else {
            state.membership.verify(&intent.record)
        }
    }

    /// Stops after `step` if a test said so, as a crash or a failing disk
    /// would.
    #[cfg(test)]
    fn after(&self, step: Step) -> Result<(), Error> {
        let meanwhile = {
            let mut meanwhile = lock(&self.meanwhile);
            match meanwhile.take() {
                Some((at, then)) if at == step => Some(then),
                other => {
                    *meanwhile = other;
                    None
                }
            }
        };
        if let Some(then) = meanwhile {
            then();
        }
        if *lock(&self.stop) == Some(step) {
            return Err(Error::new(format!("stopped after {step:?}")));
        }
        Ok(())
    }

    /// Goes on after `step`.
    #[cfg(not(test))]
    #[expect(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "a test stops here"
    )]
    fn after(&self, step: Step) -> Result<(), Error> {
        let _ = step;
        Ok(())
    }

    /// Why the chain in `state` is not this session's to sync, if it is
    /// not: it names another binary, or one the key of its epoch does not
    /// open. `None` too while that key is not here.
    pub(crate) fn other_binary(&self, state: &State) -> Option<String> {
        self.chain_other_binary(&state.membership, &state.keys)
    }

    /// Why the share's binary, as the chain in `state` names it last, is
    /// not positively the session's (the file as opened, whole SHA-256
    /// and slice), if it is not: it names another, or names it under a key
    /// not here, or names none yet. Unknown is not a match (sync §14.3).
    fn unbound(&self, state: &State) -> Option<String> {
        let Some(epoch) = state.membership.binary_epoch() else {
            return Some("the share names no binary yet".to_owned());
        };
        if !state.keys.contains_key(&epoch) {
            return Some(format!(
                "the key of epoch {epoch}, which seals the share's binary, is not here: the \
                 binary open is not known to be the share's"
            ));
        }
        self.foreign(state.membership.binary(&state.keys))
    }

    /// [`Self::other_binary`] of `membership`, with `keys`.
    fn chain_other_binary(
        &self,
        membership: &Membership,
        keys: &BTreeMap<u32, EpochKey>,
    ) -> Option<String> {
        let epoch = membership.binary_epoch()?;
        if !keys.contains_key(&epoch) {
            return None;
        }
        self.foreign(membership.binary(keys))
    }

    /// Why `binary`, as a chain names it (`None`: sealed so that its key
    /// does not open it), is not the session's, if it is not.
    fn foreign(&self, binary: Option<Binary>) -> Option<String> {
        let slice = |binary: &Binary| {
            binary
                .slice
                .as_ref()
                .map_or_else(String::new, |slice| format!(", slice {slice}"))
        };
        match binary {
            Some(binary) if binary == self.binary => None,
            Some(binary) => Some(format!(
                "the project shared annotates another binary (SHA-256 {}{}), not the one open \
                 (SHA-256 {}{})",
                data_encoding::HEXLOWER.encode(&binary.sha256),
                slice(&binary),
                data_encoding::HEXLOWER.encode(&self.binary.sha256),
                slice(&self.binary),
            )),
            None => Some(
                "the project shared names its binary sealed so that its key does not open it"
                    .to_owned(),
            ),
        }
    }

    /// Whether changes go and come: the chain names the session's binary
    /// (not before its first record and the key of the epoch that sealed
    /// the binary have come).
    pub(crate) fn on_binary(&self, state: &State) -> bool {
        state.membership.binary(&state.keys).as_ref() == Some(&self.binary)
    }

    /// Makes the session's journal the share's, once the chain names its
    /// binary under a key held (a joiner's empty journal; the owner's, its
    /// listed prefixes the only work from before); this install's own
    /// chains then counted as told and every author's chains with edits
    /// counted for the local guard.
    ///
    /// # Errors
    ///
    /// The journal is another share's, or of another binary, or cannot be
    /// written.
    fn bind_share(&self, state: &mut State) -> Result<(), Error> {
        let Some(genesis) = state.membership.genesis() else {
            return Ok(());
        };
        let session = self.session();
        match session.genesis() {
            Some(held) if held == genesis => return Ok(()),
            Some(_) => {
                return Err(Error::new(
                    "the project open is another share's: open the share's own project",
                ));
            }
            None => {}
        }
        if !self.on_binary(state) {
            return Ok(());
        }
        let applied = session
            .share(genesis, session.binding(), state.membership.before())
            .map_err(|error| Error::new(error.to_string()))?;
        for refused in &applied.refused {
            self.list(state, refused);
        }
        self.count(state);
        Ok(())
    }

    /// Counts the chains as the journal holds them: this install's own
    /// (and its agents') as told to the machine, every author's for the
    /// local guard.
    fn count(&self, state: &mut State) {
        let session = self.session();
        let agents: BTreeSet<PublicKey> =
            session.agents().into_iter().map(|(key, _)| key).collect();
        for (chain, author, _) in session.chains() {
            let Some(tip) = session.tip(chain) else {
                continue;
            };
            if author == self.me || agents.contains(&author) {
                state.book.own.insert(chain, tip.seq);
            }
            self.judge.count(author, chain);
        }
    }

    /// After the membership chain grew: who may delete anyone's post; a
    /// new chain for this peer's changes (and its agents') where the one
    /// begun is of another grant than the chain now gives (a raise, a
    /// lowering, a readmission: sync §4.3) or is frozen; the change told.
    fn settle(&self, state: &State) {
        let session = self.session();
        session.set_owners(state.membership.owners());
        if let Err(error) = session.regrant() {
            self.tell(&Notice::Failed(error.to_string()));
        }
        if state.membership.role(self.me).is_some()
            && session.frozen().contains_key(&session.chain())
            && let Err(error) = session.new_chain()
        {
            self.tell(&Notice::Failed(error.to_string()));
        }
        self.tell(&Notice::Membership {
            seq: state.membership.seq(),
            epoch: state.membership.epoch(),
        });
    }

    /// Freezes the chains a record after their grant closed, from their
    /// first change past what it lets stand ([`Membership::freezes`]),
    /// over every chain of the share known: what collab does as it
    /// attaches.
    fn enforce_cuts(&self, state: &mut State) -> Result<(), Error> {
        let session = self.session();
        let freezes: Vec<(ChainId, u64)> = state
            .membership
            .freezes(&session.grants())
            .into_iter()
            .collect();
        let (seq, hash) = state.membership.head();
        self.freeze(state, &freezes, FrozenBy::Cut { record: seq, hash })
    }

    /// Freezes each chain of `freezes` from its change, for the cause `by`
    /// (one frozen there or before already left as it is), kept in the
    /// log before it takes effect: changes taken before the cut reached
    /// this peer no longer count. The changes dropped are told.
    ///
    /// # Errors
    ///
    /// The freezes cannot be written.
    fn freeze(
        &self,
        state: &mut State,
        freezes: &[(ChainId, u64)],
        by: FrozenBy,
    ) -> Result<(), Error> {
        let session = self.session();
        let frozen = session.frozen();
        let freezes: Vec<(ChainId, u64, FrozenBy)> = freezes
            .iter()
            .filter(|(chain, from)| frozen.get(chain).is_none_or(|at| at > from))
            .map(|(chain, from)| (*chain, *from, by))
            .collect();
        if freezes.is_empty() {
            return Ok(());
        }
        let applied = session
            .freeze(&freezes)
            .map_err(|error| Error::new(error.to_string()))?;
        View { inner: self, state }.take_applied(&applied, None);
        Ok(())
    }

    /// Lists `refusal` (once, its reason cut to [`WHY`] bytes; the oldest
    /// listed dropped past [`MAX_LISTED`]) and tells it.
    pub(crate) fn list(&self, state: &mut State, refusal: &Refused) {
        let mut refusal = refusal.clone();
        if refusal.why.len() > WHY {
            let end = refusal.why.floor_char_boundary(WHY);
            refusal.why.truncate(end);
            refusal.why.push('…');
        }
        if !state.listed.insert((refusal.change, refusal.why.clone())) {
            return;
        }
        if state.refused.len() >= MAX_LISTED {
            let oldest = state.refused.remove(0);
            state.listed.remove(&(oldest.change, oldest.why));
        }
        state.refused.push(refusal.clone());
        self.tell(&Notice::Refused(refusal));
    }

    /// Lets the machine's time pass, and tells it what changed here, until
    /// the peer closes.
    async fn tick(self: Arc<Self>) {
        let mut every = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                () = self.changed.notified() => {
                    self.drive(|machine, view, charges, now| {
                        machine.on_local(view, charges, now, Local::Journal)
                    });
                }
                _ = every.tick() => {
                    // A share in recovery tries again whenever its disk
                    // may allow.
                    if !self.recovered(&mut self.state()) {
                        continue;
                    }
                    self.drive(|machine, view, charges, now| machine.on_timer(view, charges, now));
                }
            }
        }
    }
}

/// The most refusals listed: the oldest go first.
pub(crate) const MAX_LISTED: usize = 1024;

/// A session shared or joined.
pub struct Peer {
    inner: Arc<Inner>,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("me", &self.inner.me)
            .finish_non_exhaustive()
    }
}

/// The share id of `session`: its log's project id.
fn log_id(session: &Session) -> Result<ProjectId, Error> {
    let bytes = data_encoding::HEXLOWER
        .decode(session.project_id().as_bytes())
        .map_err(|_| Error::new("the session's log has no project id"))?;
    Ok(ProjectId(bytes.try_into().map_err(|_| {
        Error::new("the session's log has no project id")
    })?))
}

/// A chain of a project from before its share that the Share may list
/// in the share's first record (sync §14.6): shown to the owner, who
/// chooses which go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listable {
    /// The chain.
    pub chain: ChainId,
    /// Its author.
    pub author: PublicKey,
    /// The name of the agent of this install's that wrote it, if one did.
    pub agent: Option<String>,
    /// Whether this install wrote it (itself, or an agent of it).
    pub mine: bool,
    /// The number it would be listed up to: its changes, at most
    /// [`MAX_THROUGH`].
    pub through: u64,
    /// Whether it is chosen unless the owner says otherwise: this
    /// install's own chains and its agents', the [`MAX_BEFORE`] longest.
    pub chosen: bool,
}

/// The chains of `session` a share of it made now by `me` could list, the
/// longest first, with those chosen by default marked.
pub fn listable(session: &Session, me: PublicKey) -> Vec<Listable> {
    let agents: BTreeMap<PublicKey, String> = session.agents().into_iter().collect();
    let mut chains: Vec<Listable> = session
        .chains()
        .into_iter()
        .filter(|(_, _, seq)| *seq > 0)
        .map(|(chain, author, seq)| Listable {
            chain,
            author,
            agent: agents.get(&author).cloned(),
            mine: author == me || agents.contains_key(&author),
            through: seq.min(MAX_THROUGH),
            chosen: false,
        })
        .collect();
    chains.sort_by_key(|listable| (Reverse(listable.through), listable.chain));
    for listable in chains
        .iter_mut()
        .filter(|listable| listable.mine)
        .take(MAX_BEFORE)
    {
        listable.chosen = true;
    }
    chains
}

/// The prefixes of `session`'s chains `chosen` as a share's first record
/// lists them: each up to the change taken last (at most
/// [`MAX_THROUGH`]), with the hash there.
///
/// # Errors
///
/// More than [`MAX_BEFORE`] chosen, or one the session does not hold.
fn prefixes(
    session: &Session,
    chosen: &BTreeSet<ChainId>,
) -> Result<BTreeMap<ChainId, (u64, ChangeHash)>, Error> {
    if chosen.len() > MAX_BEFORE {
        return Err(Error::new(format!(
            "more than {MAX_BEFORE} chains chosen to go with the share"
        )));
    }
    chosen
        .iter()
        .map(|chain| {
            let held = session
                .tip(*chain)
                .map(|tip| tip.seq.min(MAX_THROUGH))
                .filter(|seq| *seq > 0)
                .and_then(|seq| Some((seq, session.head_at(*chain, seq)?.hash())));
            held.map(|prefix| (*chain, prefix)).ok_or_else(|| {
                Error::new(format!("chain {chain} chosen to go is not in the project"))
            })
        })
        .collect()
}

impl Peer {
    /// Shares `session`'s project over `transport`: a share its journal
    /// is of, read again (its owner's, or one it joined: a member hosting
    /// the others); else the project shared anew, in place (this peer its
    /// owner): its first record lists the prefixes of the chains
    /// [`listable`] chooses by default (this author's and its agents'),
    /// whose changes go with it; [`Self::share_listing`] lists the owner's
    /// own choice. Its other chains are kept apart; new work names the
    /// share. Links are accepted from members, and, if `config` has an
    /// approver, from those holding the ticket returned, whom it admits
    /// (only the owner admits). A chain shared anew names the session's
    /// binary ([`Membership::binary`]): a peer syncs only a session on it.
    ///
    /// # Errors
    ///
    /// `config`'s identity is not `transport`'s; the project's
    /// membership chain cannot be read or written, or names another
    /// binary; the journal is a share's whose chain is not kept here; it
    /// cannot be made the share's; no randomness.
    pub async fn share(
        session: Arc<Session>,
        transport: Arc<dyn Transport>,
        config: Config,
    ) -> Result<(Self, JoinTicket), Error> {
        Self::share_listing(session, transport, config, None).await
    }

    /// [`Self::share`], a share made anew listing the chains `listed`
    /// (from [`listable`], as the owner chose them; none: those it
    /// chooses by default). A project already shared lists what its first
    /// record lists, whatever `listed` says.
    ///
    /// # Errors
    ///
    /// As [`Self::share`]; more than [`MAX_BEFORE`] chains listed, or one
    /// the project does not hold.
    pub async fn share_listing(
        session: Arc<Session>,
        transport: Arc<dyn Transport>,
        config: Config,
        listed: Option<BTreeSet<ChainId>>,
    ) -> Result<(Self, JoinTicket), Error> {
        let (session, binary) = ready(session).await?;
        let dir = session.project().map(|project| project.dir().to_path_buf());
        let mut found = None;
        if let Some(genesis) = session.genesis() {
            let dir = dir
                .as_deref()
                .ok_or_else(|| Error::new("a shared journal with no project"))?;
            for (project, store) in Store::kept_in(dir) {
                let kept = store.load()?;
                let first = kept
                    .records
                    .first()
                    .or(kept.intent.as_ref().map(|intent| &intent.record));
                if first.is_some_and(|first| *blake3::hash(&first.bytes).as_bytes() == genesis) {
                    found = Some((project, Some(store), kept));
                    break;
                }
            }
            if found.is_none() {
                return Err(Error::new(
                    "the project is a share's whose membership chain is not kept here",
                ));
            }
        }
        let (project, store, kept) = if let Some(found) = found {
            found
        } else {
            let project = log_id(&session)?;
            let store = dir.as_deref().map(|dir| Store::new(dir, project));
            let kept = match &store {
                Some(store) => store.load()?,
                None => Kept::default(),
            };
            (project, store, kept)
        };
        let first = kept
            .records
            .first()
            .or(kept.intent.as_ref().map(|intent| &intent.record));
        let owner = match first {
            Some(first) => first_owner(first)?,
            None => config.identity.public(),
        };
        let inner = Inner::new(&session, transport, config, store, project, owner, binary)?;
        {
            let mut state = inner.state();
            inner.attach(&mut state, kept)?;
            if state.membership.seq() == 0 {
                let session = inner.session();
                let chosen = listed.unwrap_or_else(|| {
                    listable(&session, inner.me)
                        .into_iter()
                        .filter(|listable| listable.chosen)
                        .map(|listable| listable.chain)
                        .collect()
                });
                let before = prefixes(&session, &chosen)?;
                let (first, _) = Membership::create(
                    project,
                    &inner.secret,
                    inner.card.agreement,
                    &before,
                    &inner.binary,
                )?;
                inner.take_record(&mut state, &first)?;
                if inner.session().genesis() != state.membership.genesis() {
                    return Err(Error::new("the project could not be made the share's"));
                }
                state.book.locals.clear();
            }
            state.invite = Some(crypto::random()?);
        }
        let ticket = JoinTicket {
            v: 1,
            host: inner.transport.addr(),
            owner,
            project,
            invite: inner.state().invite.unwrap_or_default(),
            flags: 0,
            arch: inner.session().slice().map(Text::truncated),
        };
        let peer = Self::run(inner);
        Ok((peer, ticket))
    }

    /// Joins the project shared by `ticket`'s host with `session` (on the
    /// same binary, in a project of its own for the share) over
    /// `transport`: dials the host; a key the owner added is let in at
    /// once (with live approval on, a ticket holder is asked about);
    /// then syncs, through any member linked; dials again whenever the
    /// link is lost, until refused. Nothing of the log goes or comes until
    /// the chain has come and names the session's binary, and the journal
    /// is the share's; a chain naming another binary ends the join
    /// ([`Notice::Denied`]).
    ///
    /// # Errors
    ///
    /// `config`'s identity is not `transport`'s; the project's membership
    /// chain as kept cannot be read, is not the ticket's, or names another
    /// binary; the session's journal is another share's.
    pub async fn join(
        session: Arc<Session>,
        transport: Arc<dyn Transport>,
        config: Config,
        ticket: &JoinTicket,
    ) -> Result<Self, Error> {
        let (session, binary) = ready(session).await?;
        let store = session
            .project()
            .map(|dir| Store::new(dir.dir(), ticket.project));
        let kept = match &store {
            Some(store) => store.load()?,
            None => Kept::default(),
        };
        let inner = Inner::new(
            &session,
            transport,
            config,
            store,
            ticket.project,
            ticket.owner,
            binary,
        )?;
        {
            let mut state = inner.state();
            inner.attach(&mut state, kept)?;
            if let Some(genesis) = inner.session().genesis()
                && state.membership.genesis() != Some(genesis)
            {
                return Err(Error::new(
                    "the project open is another share's: open the share's own project",
                ));
            }
        }
        let dial = Dial {
            addr: ticket.host.clone(),
            invite: ticket.invite,
        };
        let peer = Self::run(Arc::clone(&inner));
        inner.spawn(Arc::clone(&inner).dial(dial));
        Ok(peer)
    }

    /// Starts `inner`'s tasks: accepting links, driving the machine, the
    /// presence.
    fn run(inner: Arc<Inner>) -> Self {
        inner.spawn(Arc::clone(&inner).accept_links());
        inner.spawn(Arc::clone(&inner).tick());
        inner.spawn(Arc::clone(&inner).presence());
        Self { inner }
    }

    /// The peer's insides.
    pub(crate) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    /// The session in use.
    pub fn session(&self) -> Arc<Session> {
        self.inner.session()
    }

    /// Goes on with `session` in place of the one in use: a newer
    /// analysis of the same binary that took its edits
    /// ([`binbun_session::Lineage::swap`]), judged by this share's
    /// authority from now on.
    pub fn set_session(&self, session: Arc<Session>) {
        self.inner.listen(&session);
        let owners = self.inner.state().membership.owners();
        session.set_owners(owners);
        let judge: Arc<dyn Authority> = Arc::<Judge>::clone(&self.inner.judge);
        session.attach(Some(judge));
        *self
            .inner
            .session
            .write()
            .unwrap_or_else(PoisonError::into_inner) = session;
        self.inner.own_dirty.store(true, Ordering::SeqCst);
        self.inner.changed.notify_one();
    }

    /// This peer's identity key.
    pub fn id(&self) -> PublicKey {
        self.inner.me
    }

    /// This peer's role, as the membership chain says (`None`: not a
    /// member yet, or removed).
    pub fn role(&self) -> Option<Role> {
        self.inner.state().membership.role(self.inner.me)
    }

    /// Why this peer is view-only in this session (the host runs another
    /// build), if it is: the host does not take its changes while linked.
    pub fn view_only(&self) -> Option<String> {
        self.inner.state().view_only.clone()
    }

    /// The membership chain as this peer has it.
    pub fn membership(&self) -> Membership {
        self.inner.state().membership.clone()
    }

    /// The epochs whose keys this peer holds.
    pub fn epochs(&self) -> Vec<u32> {
        self.inner.state().keys.keys().copied().collect()
    }

    /// The changes refused: by this peer's checks (envelopes, what
    /// members said), then by the session's (signatures, chains, roles).
    pub fn refused(&self) -> Vec<Refused> {
        let mut refused = self.inner.state().refused.clone();
        refused.extend(self.inner.session().refused());
        refused
    }

    /// The members linked now, and how each link reaches them.
    pub fn links(&self) -> Vec<(PublicKey, String)> {
        self.inner
            .state()
            .links
            .iter()
            .map(|(key, link)| (*key, link.link.path()))
            .collect()
    }

    /// The members linked now whose links are readers' (the log syncs).
    pub fn readers(&self) -> Vec<PublicKey> {
        self.inner
            .state()
            .links
            .iter()
            .filter(|(_, link)| link.is_reader())
            .map(|(key, _)| *key)
            .collect()
    }

    /// Stops admitting by the ticket: its invite forgotten (as when the
    /// share closes), the requests waiting for the approver withdrawn;
    /// members still link.
    pub fn stop_inviting(&self) {
        self.inner.state().invite = None;
        self.inner.uninvited.send_replace(());
    }

    /// Takes change envelopes from elsewhere (a file, a test), as from a
    /// link: each judged as the sync machine judges what a link brings.
    /// What came of them; refusals are also listed ([`Self::refused`]) and
    /// told. None is taken while the share is in recovery.
    pub fn receive(&self, envelopes: &[Vec<u8>]) -> Received {
        let mut received = Received::default();
        {
            let mut state = self.inner.state();
            let refuse = |why: &str| Refused {
                change: None,
                author: None,
                why: why.to_owned(),
            };
            if !self.inner.recovered(&mut state) {
                let refusal =
                    refuse("the share is in recovery: its membership record is not written whole");
                received.refused = vec![refusal; envelopes.len()];
                return received;
            }
            // Taken only into a journal of the file the share names.
            if let Some(why) = self.inner.unbound(&state) {
                received.refused = vec![refuse(&why); envelopes.len()];
                return received;
            }
            for bytes in envelopes {
                let Some(envelope) = Envelope::parse(bytes) else {
                    received.refused.push(refuse("not an envelope"));
                    continue;
                };
                let id = ChangeId {
                    chain: envelope.chain(),
                    seq: envelope.seq(),
                };
                let mut view = View {
                    inner: &self.inner,
                    state: &mut state,
                };
                let why = match view.admit(self.inner.me, &envelope) {
                    Admission::Applied => {
                        received.taken += 1;
                        continue;
                    }
                    Admission::Same | Admission::Stopped { .. } => {
                        received.held += 1;
                        continue;
                    }
                    Admission::Frozen => "its chain is frozen".to_owned(),
                    Admission::Never { why } => why.as_str().to_owned(),
                    Admission::Fork(proof) => {
                        // Kept and frozen as over a link; its place is
                        // told with the chain's tip, and peers ask.
                        view.take_fork(&proof);
                        format!("its chain forked: frozen from {}", proof.place())
                    }
                    Admission::Declined => {
                        "it does not open, or does not match its head".to_owned()
                    }
                    Admission::TurnedAway => "its chain is not of this share".to_owned(),
                    Admission::Invalid => "its head is not signed by its author".to_owned(),
                };
                let refusal = Refused {
                    change: Some(id),
                    author: None,
                    why,
                };
                self.inner.list(&mut state, &refusal);
                received.refused.push(refusal);
            }
        }
        self.inner.changed.notify_one();
        received
    }

    /// The admitted changes of chain `chain` past number `after`, sealed
    /// under the latest epoch's key this peer holds: one page, as a link
    /// would be served it.
    ///
    /// # Errors
    ///
    /// This peer holds no key (not admitted yet); the share is in
    /// recovery.
    pub fn seal_after(&self, chain: ChainId, after: u64) -> Result<Vec<Vec<u8>>, Error> {
        let mut state = self.inner.state();
        if !self.inner.recovered(&mut state) {
            return Err(Error::new("the share is in recovery: nothing is served"));
        }
        if state.keys.is_empty() {
            return Err(Error::new("no key of any epoch"));
        }
        let mut view = View {
            inner: &self.inner,
            state: &mut state,
        };
        Ok(view.changes_after(chain, after, CHANGES, PAGE_BYTES).0)
    }

    /// Admits a member by their identity card, as `role`: the key from a
    /// card whose fingerprint the owner checked (a fingerprint alone
    /// admits no one). When that key connects it is let in at once. The
    /// owner's only.
    ///
    /// A member removed before is admitted again: their chains stay as the
    /// removal closed them, and they write on a new one.
    ///
    /// # Errors
    ///
    /// Not the owner; a member already; a role not given yet.
    pub fn add(&self, card: &Card, role: Role) -> Result<(), Error> {
        self.inner.admit(card, role)
    }

    /// Gives the project to member `to`: they sign every membership
    /// record after this one, and this peer, the owner before, becomes an
    /// editor. The owner's only.
    ///
    /// # Errors
    ///
    /// Not the owner; `to` no member, or the owner.
    pub fn transfer(&self, to: PublicKey) -> Result<(), Error> {
        {
            let mut state = self.inner.state();
            let signed = state.membership.transfer(&self.inner.secret, to)?;
            self.inner.take_record(&mut state, &signed)?;
        }
        self.inner.grew(1);
        Ok(())
    }

    /// Makes `member` a `role` from now: their new chains have it. A role
    /// that writes less closes their chains of earlier grants past the
    /// changes taken here so far; one that writes no less closes nothing,
    /// their earlier chains keeping their earlier role. The owner's only.
    ///
    /// # Errors
    ///
    /// Not the owner; not a member, or the owner; a role not given yet.
    pub fn set_role(&self, member: PublicKey, role: Role) -> Result<(), Error> {
        {
            let mut state = self.inner.state();
            let cut = self.inner.cut(member);
            let signed = state
                .membership
                .set_role(&self.inner.secret, member, role, cut)?;
            self.inner.take_record(&mut state, &signed)?;
        }
        self.inner.grew(1);
        Ok(())
    }

    /// Removes `member`: their changes past those taken so far refused by
    /// every peer, a new epoch whose key they never get, their link
    /// closed with the records saying so (an agent this peer speaks for
    /// no longer a participant). The owner's only. The new epoch, whose
    /// record links the one before to it.
    ///
    /// # Errors
    ///
    /// Not the owner; not a member, or the owner; the key of the epoch now
    /// not held; no randomness; the record not taken.
    pub fn remove(&self, member: PublicKey) -> Result<u32, Error> {
        let mut after = After::default();
        let epoch = {
            let mut driver = self.inner.driver();
            let mut state = self.inner.state();
            let cut = self.inner.cut(member);
            let epoch = state.membership.epoch();
            let key = state
                .keys
                .get(&epoch)
                .ok_or_else(|| Error::new(format!("no key of epoch {epoch}")))?;
            // The new key comes back from the record, wrapped to this peer.
            let (signed, _) = state.membership.remove(
                &self.inner.secret,
                key,
                member,
                cut,
                &self.inner.binary,
            )?;
            self.inner.take_record(&mut state, &signed)?;
            // Their links revoked in the hold that took the record (sync
            // §4.3): nothing made for them is written after it.
            self.inner.drive_held(
                &mut driver,
                &mut state,
                |machine, view, charges, now| {
                    machine.on_local(view, charges, now, Local::Membership(Taken { records: 1 }))
                },
                &mut after,
            );
            state.membership.epoch()
        };
        self.inner.finish(&after);
        self.inner.keyed.send_replace(());
        self.inner.unhost(member);
        Ok(epoch)
    }

    /// Waits, `limit` at most, until each member linked has told (by its
    /// tips and membership head, nothing else) that it holds this peer's
    /// own changes admitted so far and the membership chain as this peer
    /// has it, or its link is gone: what a peer does before it closes.
    /// Of the members linked when it began: who told so, who was still
    /// linked when the time ran out, and whose link went first (a member
    /// that does not take them, a viewer's, never tells so). Only the link
    /// each was linked by when it began speaks for them (I31): a link
    /// made since, or one before, does not.
    pub async fn flush(&self, limit: Duration) -> Flushed {
        let me = self.inner.me;
        self.inner.own_dirty.store(true, Ordering::SeqCst);
        self.inner.changed.notify_one();
        let members: Vec<(PublicKey, LinkId)> = self
            .inner
            .state()
            .links
            .iter()
            .map(|(member, link)| (*member, link.id))
            .collect();
        let start = Instant::now();
        loop {
            let session = self.inner.session();
            let mine: Vec<(ChainId, u64)> = session
                .chains()
                .into_iter()
                .filter(|(_, author, _)| *author == me)
                .filter_map(|(chain, ..)| Some((chain, session.tip(chain)?.seq)))
                .filter(|(_, seq)| *seq > 0)
                .collect();
            let mut flushed = Flushed::default();
            let mut waiting = false;
            {
                let driver = self.inner.driver();
                let mut state = self.inner.state();
                let records = state.membership.seq();
                let reports: Vec<(PublicKey, Option<Report>, bool)> = members
                    .iter()
                    .map(|(member, id)| match state.links.get(member) {
                        Some(link) if link.id == *id => (*member, driver.machine.report(*id), true),
                        _ => {
                            let kept = state.reports.get(member).filter(|kept| kept.link == *id);
                            (*member, kept.map(|kept| kept.report.clone()), false)
                        }
                    })
                    .collect();
                let view = View {
                    inner: &self.inner,
                    state: &mut state,
                };
                for (member, report, linked) in reports {
                    let has = report.is_some_and(|report| {
                        report.has_membership(&view, records)
                            && mine
                                .iter()
                                .all(|(chain, seq)| report.has(&view, *chain, *seq))
                    });
                    if has {
                        flushed.acknowledged.push(member);
                    } else if linked {
                        waiting = true;
                        flushed.unacknowledged.push(member);
                    } else {
                        flushed.disconnected.push(member);
                    }
                }
            }
            if !waiting || start.elapsed() >= limit {
                return flushed;
            }
            tokio::time::sleep(FLUSH_POLL).await;
        }
    }

    /// Stops: the invite forgotten, the tasks ended, then the links
    /// closed; the session's journal no longer judged by the share. The
    /// tasks go first: a dial in flight, cut by the endpoint closing,
    /// would otherwise say the host was unreachable.
    pub async fn close(self) {
        self.inner.bye();
        self.inner.state().invite = None;
        self.inner.uninvited.send_replace(());
        let tasks = std::mem::take(&mut *lock(&self.inner.tasks));
        for task in &tasks {
            task.abort();
        }
        // Gone, not only asked to go: one running now ends at its next
        // await.
        for task in tasks {
            let _ = task.await;
        }
        self.inner.transport.close().await;
        self.inner.blobs.close().await;
        self.inner.state().links.clear();
        self.inner.session().attach(None);
    }
}

impl Inner {
    /// A peer's insides for `session` over `transport`, in project
    /// `project` owned by `owner`, its chain to be taken, the session on
    /// `binary`: the share's authority attached to the session's journal.
    fn new(
        session: &Arc<Session>,
        transport: Arc<dyn Transport>,
        config: Config,
        store: Option<Store>,
        project: ProjectId,
        owner: PublicKey,
        binary: Binary,
    ) -> Result<Arc<Self>, Error> {
        let me = config.identity.public();
        if transport.id() != me {
            return Err(Error::new("the transport's key is not the identity's"));
        }
        let budgets = transport.budgets().clone();
        let membership = Membership::expecting(project, owner);
        let judge = Arc::new(Judge::new(membership.clone(), config.engine.clone()));
        let authority: Arc<dyn Authority> = Arc::<Judge>::clone(&judge);
        session.attach(Some(authority));
        let inner = Arc::new(Self {
            blobs: Shelf::new(
                session
                    .project()
                    .map(|dir| dir.dir().join("collab").join(project.to_string())),
            ),
            session: RwLock::new(Arc::clone(session)),
            transport,
            me,
            secret: Zeroizing::new(config.identity.secret()),
            agreement: Zeroizing::new(config.identity.agreement_secret()),
            card: Card::new(&config.identity, &config.name),
            approve: config.approve,
            notify: config.notify,
            engine: config.engine,
            binary,
            budgets,
            records: ShareBudget::default(),
            #[cfg(test)]
            linking: Mutex::new(None),
            uninvited: watch::Sender::new(()),
            store,
            state: Mutex::new(State {
                membership,
                keys: BTreeMap::new(),
                refused: Vec::new(),
                listed: BTreeSet::new(),
                links: BTreeMap::new(),
                reports: BTreeMap::new(),
                invite: None,
                view_only: None,
                told: BTreeSet::new(),
                foreign: None,
                recovery: None,
                book: Book::default(),
            }),
            driver: Mutex::new(Driver {
                machine: Machine::new(),
                budgets: BTreeMap::new(),
            }),
            judge,
            own_dirty: Arc::new(AtomicBool::new(false)),
            changed: Arc::new(Notify::new()),
            keyed: watch::Sender::new(()),
            live: Live::default(),
            tasks: Mutex::new(Vec::new()),
            start: Instant::now(),
            #[cfg(test)]
            stop: Mutex::new(None),
            #[cfg(test)]
            meanwhile: Mutex::new(None),
        });
        inner.listen(session);
        Ok(inner)
    }

    /// Per chain of `member`, the last change of it admitted here.
    fn cut(&self, member: PublicKey) -> Cut {
        let session = self.session();
        session
            .chains()
            .into_iter()
            .filter(|(_, author, _)| *author == member)
            .map(|(chain, ..)| (chain, session.tip(chain).map_or(0, |tip| tip.seq)))
            .collect()
    }

    /// Takes what is kept, `kept` (into `state`, nothing taken yet), as
    /// collab attaches, before any link: the chain, then the record of an
    /// intent kept, carried out again from its freezes (sync §4.3); then
    /// the journal made the share's if it is not yet, and the cuts of the
    /// chain enforced over every chain known.
    ///
    /// # Errors
    ///
    /// A record fails its checks; the chain names another binary than
    /// the session's; the intent's record does not follow the chain, or
    /// cannot be written; the journal is another share's.
    fn attach(&self, state: &mut State, kept: Kept) -> Result<(), Error> {
        let Kept {
            mut records,
            intent,
        } = kept;
        // Its record written already is taken again with the intent.
        if let Some(intent) = &intent
            && records.last() == Some(&intent.record)
        {
            records.pop();
        }
        for signed in &records {
            let record = state.membership.take(signed)?;
            self.learn(state, &record);
        }
        self.judge.set_membership(state.membership.clone());
        if let Some(why) = self.other_binary(state) {
            return Err(Error::new(why));
        }
        if let Some(intent) = intent {
            let record = state.membership.verify(&intent.record)?;
            self.complete(state, &intent, &record)?;
        }
        if state.membership.seq() > 0 {
            self.bind_share(state)?;
            self.enforce_cuts(state)?;
            self.judge_final(state);
            self.settle(state);
            self.warn_crowded(state);
            self.count(state);
        }
        state.book.locals.clear();
        Ok(())
    }

    /// Admits `card`'s key as `role`; a member removed before is admitted
    /// again, their chains known closed.
    pub(crate) fn admit(self: &Arc<Self>, card: &Card, role: Role) -> Result<(), Error> {
        self.admit_in(self.state(), card, role)
    }

    /// [`Self::admit`] with the state locked, as `state`: what was checked
    /// under the lock holds as the record is signed.
    pub(crate) fn admit_in(
        self: &Arc<Self>,
        mut state: MutexGuard<'_, State>,
        card: &Card,
        role: Role,
    ) -> Result<(), Error> {
        if !self.recovered(&mut state) {
            return Err(Error::new("the share is in recovery: no record is taken"));
        }
        let epoch = state.membership.epoch();
        let key = state
            .keys
            .get(&epoch)
            .cloned()
            .ok_or_else(|| Error::new(format!("no key of epoch {epoch}")))?;
        let signed = if state.membership.removed(card.key) {
            state.membership.readmit(&self.secret, &key, card, role)?
        } else {
            state
                .membership
                .add(&self.secret, &key, card.key, card.agreement, role)?
        };
        self.take_record(&mut state, &signed)?;
        drop(state);
        self.tell(&Notice::Admitted {
            member: card.key,
            role,
        });
        self.grew(1);
        Ok(())
    }
}

/// `session` once its project is read, and the binary it is on.
async fn ready(session: Arc<Session>) -> Result<(Arc<Session>, Binary), Error> {
    let waiting = Arc::clone(&session);
    let waited = tokio::task::spawn_blocking(move || waiting.wait(Stage::Image, None))
        .await
        .map_err(|error| Error::new(error.to_string()))?;
    match waited {
        Waited::Reached(_) => {}
        Waited::Stopped {
            failure: Some(failure),
            ..
        } => return Err(Error::new(failure)),
        Waited::Stopped { failure: None, .. } | Waited::TimedOut(_) => {
            return Err(Error::new("the session stopped before reading its project"));
        }
    }
    // The file hashed whole, off the runtime's threads, when its key is
    // not that.
    let hashing = Arc::clone(&session);
    let binary = tokio::task::spawn_blocking(move || {
        hashing.file_sha256().map(|sha256| Binary {
            sha256,
            slice: hashing.slice().map(Text::truncated),
        })
    })
    .await
    .map_err(|error| Error::new(error.to_string()))?
    .ok_or_else(|| Error::new("the session's binary is not read"))?;
    Ok((session, binary))
}

/// The owner a membership chain's first record names.
pub(crate) fn first_owner(first: &SignedRecord) -> Result<PublicKey, Error> {
    let record: Record = bounded::decode(&first.bytes)
        .map_err(|_| Error::new("a membership record that does not read"))?;
    match record.op {
        Op::Create { owner, .. } => Ok(owner),
        Op::Add { .. }
        | Op::SetRole { .. }
        | Op::Remove { .. }
        | Op::Readmit { .. }
        | Op::TransferOwner { .. } => Err(Error::new("a membership chain that creates nothing")),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use binbun_session::identity::Identity;
    use binbun_session::journal::{EngineVersion, FrozenBy};
    use binbun_session::{Options, Session, Stage};
    use binbun_sync::Storage as _;
    use binbun_sync::envelope::Envelope;
    use binbun_sync::wire::{CHANGES, PAGE_BYTES};

    use super::{Config, Peer, Step, lock};
    use crate::mem::MemNet;
    use crate::membership::Role;
    use crate::share::{Sealing, View};
    use crate::store::{Store, failing};
    use crate::ticket::{Card, JoinTicket};

    /// A fresh directory for this test, by process.
    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("binbun-peer-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The identity kept in `home`.
    fn identity(home: &Path) -> Identity {
        Identity::load_or_create(&home.join("identity")).unwrap()
    }

    /// A session on `tests/fixtures/program-x86_64.elf`, its project and
    /// identity in `home`.
    fn session(home: &Path) -> Arc<Session> {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/program-x86_64.elf");
        let options = Options {
            project: Some(home.join("project")),
            identity: Some(home.join("identity")),
            warm: false,
            ..Options::default()
        };
        let session = Session::open(fixture, options).unwrap();
        session.wait(Stage::Analysed, None);
        Arc::new(session)
    }

    /// How a peer of `identity` named `name` is made.
    fn config(identity: &Identity, name: &str) -> Config {
        Config {
            identity: identity.clone(),
            name: name.to_owned(),
            approve: None,
            notify: None,
            engine: EngineVersion::this(),
        }
    }

    /// The session in `home` shared over `net`.
    async fn shared(home: &Path, net: &MemNet) -> (Peer, JoinTicket) {
        let me = identity(home);
        let transport = Arc::new(net.endpoint(me.public()));
        Peer::share(session(home), transport, config(&me, "Ann"))
            .await
            .unwrap()
    }

    /// Where `peer` keeps its share.
    fn store(peer: &Peer) -> Store {
        let session = peer.session();
        Store::new(
            session.project().unwrap().dir(),
            peer.membership().project(),
        )
    }

    /// Waits (up to 30 s) until `done`.
    async fn until(what: &str, mut done: impl FnMut() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(start.elapsed() < Duration::from_secs(30), "never: {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Ann's peer, sharing over `net`, with Bob an editor, set to stop
    /// after `stop`; its ticket.
    async fn with_bob(
        home: &Path,
        net: &MemNet,
        bob: &Identity,
        stop: Option<Step>,
    ) -> (Peer, JoinTicket) {
        let (peer, ticket) = shared(home, net).await;
        // The project kept with a change, so that it opens again as
        // itself.
        peer.session().comment(0x1194, Some("ann")).unwrap();
        peer.session().save().unwrap();
        peer.add(&Card::new(bob, "Bob"), Role::Editor).unwrap();
        *lock(&peer.inner().stop) = stop;
        (peer, ticket)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_record_stopped_after_any_step_is_taken_whole_when_the_share_opens_again() {
        let dir = scratch("crash");
        let steps = [Step::Intent, Step::Frozen, Step::Appended, Step::Published];
        for stop in std::iter::once(None).chain(steps.map(Some)) {
            let home = dir.join(format!("{stop:?}"));
            let bob = Identity::ephemeral().unwrap();
            let (peer, _) = with_bob(&home, &MemNet::new(), &bob, stop).await;
            let removed = peer.remove(bob.public());
            let kept = store(&peer).load().unwrap();
            let record = match stop {
                None => {
                    assert_eq!(removed, Ok(1));
                    assert_eq!(kept.intent, None);
                    kept.records.last().unwrap().clone()
                }
                Some(step) => {
                    // Stopped as by a crash: the intent holds the record
                    // whole.
                    assert!(removed.is_err());
                    assert!(peer.inner().state().recovery.is_some());
                    let intent = kept.intent.unwrap();
                    let published = u64::from(step == Step::Published);
                    assert_eq!(peer.membership().seq(), 2 + published);
                    intent.record
                }
            };
            peer.close().await;
            // Opened again: the record is taken whole, its intent gone, as
            // when nothing stopped it.
            let (again, _) = shared(&home, &MemNet::new()).await;
            let membership = again.membership();
            assert_eq!(membership.seq(), 3, "{stop:?}");
            assert_eq!(membership.since(0).last(), Some(&record));
            assert!(membership.removed(bob.public()));
            assert_eq!(again.epochs(), [0, 1]);
            let kept = store(&again).load().unwrap();
            assert_eq!(kept.intent, None);
            assert_eq!(kept.records, membership.since(0));
            again.close().await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_share_whose_record_fails_after_its_intent_serves_nothing_until_it_is_written() {
        let dir = scratch("recovery");
        let net = MemNet::new();
        let bob = Identity::ephemeral().unwrap();
        let (ann, ticket) = with_bob(&dir.join("ann"), &net, &bob, None).await;
        // Cat, a member, linked.
        let cat_home = dir.join("cat");
        let cat_id = identity(&cat_home);
        let cat_session = session(&cat_home);
        let card = Card::new(&cat_id, "Cat");
        ann.add(&card, Role::Editor).unwrap();
        let cat = Peer::join(
            cat_session,
            Arc::new(net.endpoint(cat_id.public())),
            config(&cat_id, "Cat"),
            &ticket,
        )
        .await
        .unwrap();
        until("Cat is a reader", || !ann.readers().is_empty()).await;
        // The disk fails once the record is appended.
        *lock(&ann.inner().stop) = Some(Step::Appended);
        assert!(ann.remove(bob.public()).is_err());
        // No link, nothing served or taken, no other record.
        until("Ann's links are closed", || ann.links().is_empty()).await;
        let chain = cat.session().chain();
        assert!(ann.seal_after(chain, 0).is_err());
        cat.session().comment(0x1190, Some("cat")).unwrap();
        let envelopes = cat.seal_after(cat.session().chain(), 0).unwrap();
        assert_eq!(ann.receive(&envelopes).taken, 0);
        assert_eq!(ann.session().edits().comment(0x1190), None);
        let dan = Identity::ephemeral().unwrap();
        let card = Card::new(&dan, "Dan");
        assert!(ann.add(&card, Role::Viewer).is_err());
        assert_eq!(ann.membership().seq(), 3);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(ann.links(), Vec::new(), "a link up in recovery");
        // The disk allows again: the record is written whole first, then
        // Cat links again, has it, and Ann takes Cat's change.
        *lock(&ann.inner().stop) = None;
        ann.add(&card, Role::Viewer).unwrap();
        assert_eq!(store(&ann).load().unwrap().intent, None);
        assert!(ann.membership().removed(bob.public()));
        assert_eq!(ann.membership().seq(), 5);
        until("Cat has the removal", || {
            cat.membership().removed(bob.public())
        })
        .await;
        until("Ann takes Cat's change", || {
            ann.session().edits().comment(0x1190) == Some("cat")
        })
        .await;
        for peer in [ann, cat] {
            peer.close().await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_intent_whose_directory_sync_fails_is_carried_out_never_written_over() {
        let dir = scratch("intent-sync");
        let bob = Identity::ephemeral().unwrap();
        let (ann, _) = with_bob(&dir, &MemNet::new(), &bob, None).await;
        // The intent renamed into place, its directory's sync failing: it
        // may be kept, so the share is in recovery.
        failing::syncs(true);
        let removed = ann.remove(bob.public());
        failing::syncs(false);
        assert!(removed.is_err());
        // The next record waits for that one: carried out first (here or
        // by the share's timer), then taken after it.
        let dan = Identity::ephemeral().unwrap();
        ann.add(&Card::new(&dan, "Dan"), Role::Viewer).unwrap();
        let membership = ann.membership();
        assert!(membership.removed(bob.public()));
        assert!(membership.role(dan.public()).is_some());
        assert_eq!(membership.seq(), 4);
        assert_eq!(store(&ann).load().unwrap().intent, None);
        ann.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cut_stopped_after_any_step_is_in_force_before_the_log_is_read_again() {
        let dir = scratch("cut-first");
        for stop in [Step::Intent, Step::Frozen, Step::Appended, Step::Published] {
            let home = dir.join(format!("{stop:?}"));
            let net = MemNet::new();
            let bob_id = identity(&home.join("bob"));
            let (ann, ticket) = with_bob(&home.join("ann"), &net, &bob_id, None).await;
            let bob = Peer::join(
                session(&home.join("bob")),
                Arc::new(net.endpoint(bob_id.public())),
                config(&bob_id, "Bob"),
                &ticket,
            )
            .await
            .unwrap();
            until("Bob has joined", || {
                bob.session().genesis().is_some() && !ann.readers().is_empty()
            })
            .await;
            bob.session().comment(0x1190, Some("bob")).unwrap();
            until("Ann takes Bob's change", || {
                ann.session().edits().comment(0x1190) == Some("bob")
            })
            .await;
            // Bob removed, the step stopped after `stop`, as by a crash.
            *lock(&ann.inner().stop) = Some(stop);
            assert!(ann.remove(bob_id.public()).is_err());
            let intent = store(&ann).load().unwrap().intent.unwrap();
            assert!(
                intent
                    .freezes
                    .iter()
                    .any(|(chain, _)| *chain == bob.session().chain())
            );
            for peer in [ann, bob] {
                peer.close().await;
            }
            // Opened again, with no collaboration: every freeze of the
            // record is in force before anything of the log is read.
            let again = session(&home.join("ann"));
            let frozen = again.frozen();
            for (chain, from) in intent.freezes.iter() {
                assert!(
                    frozen.get(chain).is_some_and(|at| at <= from),
                    "{stop:?}: {chain} {frozen:?}"
                );
            }
            drop(again);
            // Shared again: the record taken whole, the intent gone.
            let (ann, _) = shared(&home.join("ann"), &MemNet::new()).await;
            assert!(ann.membership().removed(bob_id.public()), "{stop:?}");
            assert_eq!(
                ann.membership().since(0).last(),
                Some(&intent.record),
                "{stop:?}"
            );
            assert_eq!(store(&ann).load().unwrap().intent, None, "{stop:?}");
            ann.close().await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_page_sealed_before_its_chain_was_cut_is_sealed_again_when_served() {
        let home = scratch("prepared");
        let (peer, _) = shared(&home, &MemNet::new()).await;
        let inner = peer.inner();
        // Ann's own edits admitted at once, as with a reader linked.
        inner.judge.set_reader(true);
        let session = peer.session();
        for text in ["one", "two", "three"] {
            session.comment(0x1194, Some(text)).unwrap();
        }
        let chain = session.chain();
        let tip = session.tip(chain).unwrap().seq;
        assert!(tip >= 3, "{tip}");
        let page = Sealing::of(&inner.state())
            .unwrap()
            .page(inner, chain, 0, CHANGES);
        // Its last two withdrawn after it was sealed, before it is used.
        let envelopes = {
            let mut state = inner.state();
            let cut = FrozenBy::Cut {
                record: 1,
                hash: [0; 32],
            };
            inner.freeze(&mut state, &[(chain, tip - 1)], cut).unwrap();
            state.book.prepared = Some(page);
            View {
                inner,
                state: &mut state,
            }
            .changes_after(chain, 0, CHANGES, PAGE_BYTES)
            .0
        };
        let served: Vec<u64> = envelopes
            .iter()
            .map(|envelope| Envelope::parse(envelope).unwrap().seq())
            .collect();
        assert_eq!(served, (1..tip - 1).collect::<Vec<u64>>());
        peer.close().await;
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_chain_begun_under_the_old_grant_while_a_record_is_taken_is_cut_by_it() {
        let dir = scratch("late-chain");
        let net = MemNet::new();
        let (ann, ticket) = shared(&dir.join("ann"), &net).await;
        let bob_home = dir.join("bob");
        let bob_id = identity(&bob_home);
        ann.add(&Card::new(&bob_id, "Bob"), Role::Editor).unwrap();
        let bob = Peer::join(
            session(&bob_home),
            Arc::new(net.endpoint(bob_id.public())),
            config(&bob_id, "Bob"),
            &ticket,
        )
        .await
        .unwrap();
        until("Bob is an editor", || bob.role() == Some(Role::Editor)).await;
        // Linked to a reader: his own commits are admitted as they are made.
        until("Bob has a reader", || !bob.readers().is_empty()).await;
        // While Bob takes the record making him a viewer, once the freezes
        // its intent lists are made and before it is published, his
        // install begins a chain under the editor's grant and writes on it.
        let late = bob.session();
        let begun = Arc::new(std::sync::Mutex::new(None));
        let told = Arc::clone(&begun);
        *lock(&bob.inner().meanwhile) = Some((
            Step::Frozen,
            Box::new(move || {
                late.new_chain().unwrap();
                late.comment(0x1190, Some("late")).unwrap();
                *lock(&told) = Some(late.chain());
            }),
        ));
        ann.set_role(bob_id.public(), Role::Viewer).unwrap();
        until("Bob is a viewer", || bob.role() == Some(Role::Viewer)).await;
        let chain = lock(&begun).take().expect("the chain begun meanwhile");
        // Cut as the record requires: frozen from its first change, its
        // edit withdrawn.
        let frozen = bob.session().frozen();
        assert!(
            frozen.get(&chain).is_some_and(|from| *from <= 2),
            "{frozen:?}"
        );
        until("Bob's edit is withdrawn", || {
            bob.session().edits().comment(0x1190).is_none()
        })
        .await;
        for peer in [ann, bob] {
            peer.close().await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_judgement_that_fails_while_a_record_is_taken_leaves_the_share_in_recovery() {
        let dir = scratch("judged");
        let net = MemNet::new();
        let (ann, ticket) = shared(&dir.join("ann"), &net).await;
        let bob_home = dir.join("bob");
        let bob_id = identity(&bob_home);
        ann.add(&Card::new(&bob_id, "Bob"), Role::Editor).unwrap();
        let bob_session = session(&bob_home);
        let join = |net: &MemNet| {
            Peer::join(
                Arc::clone(&bob_session),
                Arc::new(net.endpoint(bob_id.public())),
                config(&bob_id, "Bob"),
                &ticket,
            )
        };
        let bob = join(&net).await.unwrap();
        until("Bob has a reader", || !bob.readers().is_empty()).await;
        bob.close().await;
        // Offline, Bob's edit is pending; meanwhile Ann makes him a viewer.
        let bob = join(&MemNet::new()).await.unwrap();
        bob_session.comment(0x1190, Some("pending")).unwrap();
        assert_eq!(bob_session.pending().len(), 1);
        ann.set_role(bob_id.public(), Role::Viewer).unwrap();
        let record = ann.membership().since(0).last().unwrap().clone();
        // Judging his pending work under it fails (nothing can be moved
        // apart): the record is not taken past its intent, and the share
        // serves nothing.
        let apart = bob_session.project().unwrap().dir().join("log/apart");
        let _ = std::fs::remove_dir_all(&apart);
        std::fs::write(&apart, "").unwrap();
        bob.inner().take_kick(std::slice::from_ref(&record));
        assert!(bob.inner().state().recovery.is_some());
        assert_eq!(bob.role(), Some(Role::Editor));
        assert!(bob.seal_after(bob_session.chain(), 0).is_err());
        assert_eq!(bob_session.pending().len(), 1);
        // The disk allows again: the record is taken whole, his edit
        // judged under it (moved apart), the share out of recovery.
        std::fs::remove_file(&apart).unwrap();
        assert!(bob.inner().recovered(&mut bob.inner().state()));
        assert_eq!(bob.role(), Some(Role::Viewer));
        assert_eq!(bob_session.pending(), Vec::new());
        assert_eq!(bob_session.edits().comment(0x1190), None);
        for peer in [ann, bob] {
            peer.close().await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
