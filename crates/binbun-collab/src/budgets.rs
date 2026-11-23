//! What a remote party can make this process spend: drawn from one
//! [`Budgets`] (a transport's, [`crate::Transport::budgets`]: iroh's is
//! the process's, [`Budgets::process`]; each [`crate::mem::MemNet`]
//! endpoint has its own) and given back by a guard, dropped on every
//! path.
//!
//! **Hard ceilings** hold against anyone, as owned permits:
//!
//! - *The stranger pool* ([`STRANGERS`]): every party not yet admitted
//!   holds a place ([`Stranger`]) in each stage from the transport's
//!   accepting of its connection through the signed admission decision.
//!   No place, no handshake. Each stage has a deadline that covers every
//!   write to the stranger: [`HANDSHAKE`] for the TLS handshake, and
//!   again for the hello; [`ASK_FOR`] from the taking of an asking slot.
//! - *Asking* ([`ASKING`]): requests waiting for the approver, one per
//!   key, and [`ASKS`] per key, counted by identity past reconnects; past
//!   [`ASKERS`] identities counted at once, new ones share one count.
//! - *Links* ([`LINKS`]), each numbered by a generation so an old link's
//!   cleanup cannot remove its successor's state ([`LinkBudget`]); each
//!   holds [`SYNC_LINK_BASE`] of `sync.link` for its life.
//! - *Streams* ([`LINK_STREAMS`] per link, [`STREAMS`] per process), the
//!   ask read within [`STREAM_ASK`].
//! - *Frames* ([`FRAMES`] bytes per process), reserved before a frame's
//!   body is read, the reader waiting for them.
//! - *Tasks* ([`TASKS`] per process) a remote party starts.
//! - *Sync* (`sync.link`: [`SYNC_LINK_PER_LINK`] per link, [`SYNC_LINK`]
//!   per process; `sync.pages`: [`SYNC_PAGES_PER_LINK`] per link,
//!   [`SYNC_PAGES`] per process, and one of each share's own kept for its
//!   membership records ([`ShareBudget`]), so that no link of another
//!   share, stalled or not, holds it). A page's permit is held through
//!   its write, which a link must finish within
//!   [`binbun_sync::machine::DEADLINE`] or be closed.
//! - *Walks* ([`WALKS`] heads checked per process, for the walks of listed
//!   prefixes): an availability limit, not only a security one. A walk
//!   that would pass it is refused, its heads given back, and the chain
//!   not taken until it is told again.
//! - *Reports* kept for a flush once their link has gone, charged to
//!   `sync.link` of the process ([`Budgets::retain`]).
//!
//! **Defaults** are rates per member identity (GCRA, [`governor`]):
//! members are colleagues, trusted not to monopolise their own project,
//! so these turn a loop into refusal or backpressure and are no security
//! guarantee. Live frames ([`LIVE_FRAMES`], [`LIVE_BYTES`]), chat
//! ([`CHAT_BACKLOG`], [`CHAT`]), presence ([`DATAGRAMS`], [`PRESENCE`]),
//! and sync bytes each way ([`SYNC_BYTES`]). Being keyed by identity,
//! a member's rates are where their last link left them when they link
//! again; a key's state is dropped once it is no different from a fresh
//! one.
//!
//! Rates run on the budgets' [`Clock`] (tokio's, or a
//! [`FakeRelativeClock`] in tests); deadlines on tokio's timers.
//!
//! What each operation outside sync can cost (sync's rows are the sync
//! design's):
//!
//! | Operation | Who | Memory, and for how long | Bound |
//! |---|---|---|---|
//! | a handshake and a hello | anyone | ≤ 16 KiB, to [`HANDSHAKE`] | hard: the stranger pool; no project state is made |
//! | a join request awaiting an answer | a ticket holder | the request, to [`ASK_FOR`] from its slot, writes included | hard: [`ASKING`] waiting, one per key; [`ASKS`] per key |
//! | a blob stream asked for | a member | the ask, read within [`STREAM_ASK`]; then a megabyte at a time | hard: [`LINK_STREAMS`] per link, [`STREAMS`] per process |
//! | an inbound frame | a member | its length, until handled | hard: [`FRAMES`] per process |
//! | live frames, datagrams, chat | a member | a frame ≤ 16 KiB, a datagram ≤ 232 bytes | default rates per identity |

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::hash::Hash;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use binbun_session::journal::PublicKey;
pub use governor::clock::FakeRelativeClock;
use governor::clock::{Clock as _, Reference as _};
use governor::middleware::NoOpMiddleware;
use governor::nanos::Nanos;
use governor::state::keyed::HashMapStateStore;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// The most parties not admitted at once (handshaking, saying hello,
/// asking).
pub const STRANGERS: usize = 64;

/// How long a stranger's TLS handshake may take, and then its hello.
pub const HANDSHAKE: Duration = Duration::from_secs(10);

/// The most requests waiting for the approver at once.
pub const ASKING: usize = 16;

/// How long a request lasts from the taking of its slot, the approver's
/// answer and every write to the requester included: the approver has
/// all of it but the last [`HANDSHAKE`], which is the final word's.
pub const ASK_FOR: Duration = Duration::from_mins(5);

/// The most identities whose requests are counted apart at once; past
/// it, new ones share one count.
pub const ASKERS: usize = 1024;

/// The most links at once.
pub const LINKS: usize = 1024;

/// The most blob streams of one link served at once.
pub const LINK_STREAMS: usize = 8;

/// The most blob streams served at once.
pub const STREAMS: usize = 256;

/// How long a blob stream's ask may take to come.
pub const STREAM_ASK: Duration = Duration::from_secs(10);

/// The most bytes of inbound frames held at once.
pub const FRAMES: usize = 192 << 20;

/// The most tasks remote parties have started at once.
pub const TASKS: usize = 4096;

/// What a link holds of `sync.link` for its life.
pub const SYNC_LINK_BASE: usize = 16 << 10;

/// The most bytes of sync state one link holds (`sync.link`): every chain
/// of a share at [`binbun_session::journal::MAX_CHAINS`], each charged
/// [`binbun_sync::budget::PER_CHAIN`] bytes, with room for the rest.
pub const SYNC_LINK_PER_LINK: usize = 32 << 20;

/// The most bytes of sync state all links hold (`sync.link`).
pub const SYNC_LINK: usize = 256 << 20;

/// The most sync pages of changes being built at once (`sync.pages`);
/// each share keeps one more of its own for membership records
/// ([`ShareBudget`]).
pub const SYNC_PAGES: usize = 16;

/// The most sync pages being built for one link at once.
pub const SYNC_PAGES_PER_LINK: usize = 4;

/// The most heads the walks of listed prefixes hold checked at once, in
/// all shares: 32 bytes each, 32 MiB in all. One listed prefix may be
/// as long as this ([`crate::membership::MAX_THROUGH`]), so one walk at
/// its longest fits; a walk that would pass it is refused (sync §3.3: the
/// walk's hashes on disk are the design's, this ceiling stands in for
/// them in 0.1 and limits availability: a chain whose walk is refused is
/// not taken until it is told again, by when others may have ended).
pub const WALKS: usize = 1 << 20;

/// A rate: `burst` at once, all of it again over `over`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    /// How many at once.
    pub burst: u32,
    /// How long all of them take to come again.
    pub over: Duration,
}

impl Rate {
    /// As `governor` keeps it: one cell each `over / burst`.
    fn quota(self) -> Quota {
        let burst = NonZeroU32::new(self.burst).unwrap_or(NonZeroU32::MIN);
        Quota::with_period(self.over / burst.get())
            .unwrap_or_else(|| Quota::per_second(burst))
            .allow_burst(burst)
    }

    /// How long a key's state outlasts its last use: past it, it is no
    /// different from a fresh one.
    fn horizon(self) -> Duration {
        self.over + self.over / self.burst.max(1)
    }
}

/// Requests to join of one identity.
pub const ASKS: Rate = Rate {
    burst: 3,
    over: Duration::from_mins(15),
};

/// Live frames from one member's link: 512 at once, 64 a second.
pub const LIVE_FRAMES: Rate = Rate {
    burst: 512,
    over: Duration::from_secs(8),
};

/// Live frames' bytes from one member's link: 1 MiB at once, 256 KiB a
/// second.
pub const LIVE_BYTES: Rate = Rate {
    burst: 1 << 20,
    over: Duration::from_secs(4),
};

/// Chat messages taken through one member's link without their author's
/// rate (the backlog given when it comes up): a backlog's worth (100,
/// [`crate::live::BACKLOG`]) at once, again over five minutes.
pub const CHAT_BACKLOG: Rate = Rate {
    burst: 100,
    over: Duration::from_mins(5),
};

/// Chat messages this peer sends, and those of one author taken through
/// one member's link past its backlog: five at once, one a second.
pub const CHAT: Rate = Rate {
    burst: 5,
    over: Duration::from_secs(5),
};

/// Presence datagrams opened from one member's link.
pub const DATAGRAMS: Rate = Rate {
    burst: 1000,
    over: Duration::from_secs(1),
};

/// Presence datagrams of one participant taken: twice what a peer sends.
pub const PRESENCE: Rate = Rate {
    burst: 40,
    over: Duration::from_secs(1),
};

/// Sync bytes from or to one member (`sync.in`, `sync.out`): 64 MiB at
/// once, 32 MiB a second, so a first sync of a large project is not
/// slowed.
pub const SYNC_BYTES: Rate = Rate {
    burst: 64 << 20,
    over: Duration::from_secs(2),
};

/// The time rates are kept on: tokio's (paused and advanced with it in
/// tests), or a [`FakeRelativeClock`] moved by hand.
#[derive(Clone, Debug)]
pub struct Clock(Source);

#[derive(Clone, Debug)]
enum Source {
    /// Tokio's, from this instant.
    Tokio(Instant),
    Fake(FakeRelativeClock),
}

impl Clock {
    /// Tokio's.
    #[must_use]
    pub fn real() -> Self {
        Self(Source::Tokio(Instant::now()))
    }

    /// `clock`'s: rates move only when it is advanced.
    #[must_use]
    pub fn fake(clock: FakeRelativeClock) -> Self {
        Self(Source::Fake(clock))
    }
}

impl governor::clock::Clock for Clock {
    type Instant = Nanos;

    fn now(&self) -> Nanos {
        match &self.0 {
            Source::Tokio(start) => start.elapsed().into(),
            Source::Fake(clock) => clock.now(),
        }
    }
}

/// A rate per key.
type Keyed<K> = RateLimiter<K, HashMapStateStore<K>, Clock, NoOpMiddleware<Nanos>>;

/// One rate.
type Direct = RateLimiter<NotKeyed, InMemoryState, Clock, NoOpMiddleware<Nanos>>;

/// Whom a request to join is counted against.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Asker {
    Key(PublicKey),
    /// Every identity past [`ASKERS`].
    Overflow,
}

/// A moment by which something must be done (tokio's timers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline(Instant);

impl Deadline {
    /// `span` from now.
    #[must_use]
    pub fn after(span: Duration) -> Self {
        Self(Instant::now() + span)
    }

    /// When.
    #[must_use]
    pub fn at(self) -> Instant {
        self.0
    }

    /// `work`'s output if it is done by then.
    ///
    /// # Errors
    ///
    /// [`Late`]: it was not, and is dropped.
    pub async fn within<F: Future>(self, work: F) -> Result<F::Output, Late> {
        tokio::time::timeout_at(self.0, work)
            .await
            .map_err(|_| Late)
    }

    /// Waits until then.
    pub async fn passed(self) {
        tokio::time::sleep_until(self.0).await;
    }
}

/// Work not done by its deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Late;

impl fmt::Display for Late {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not done in time")
    }
}

impl std::error::Error for Late {}

/// Why a request to join is not asked about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// One of the key's waits already.
    Waiting,
    /// [`ASKING`] wait already.
    Full,
    /// The key asked [`ASKS`] lately.
    Often,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Waiting => f.write_str("a request of this key waits for the host already"),
            Self::Full => write!(
                f,
                "{ASKING} requests wait for the host already: ask again later"
            ),
            Self::Often => write!(
                f,
                "{} requests of this key in {} minutes: ask again later",
                ASKS.burst,
                ASKS.over.as_secs() / 60
            ),
        }
    }
}

/// What remote parties may make this process spend.
#[derive(Clone)]
pub struct Budgets(Arc<Shared>);

struct Shared {
    clock: Clock,
    strangers: Arc<Semaphore>,
    asking: Arc<Semaphore>,
    /// The keys whose request waits.
    waiting: Mutex<BTreeSet<PublicKey>>,
    asks: Keyed<Asker>,
    /// The identities counted apart in `asks`, and when each last asked.
    askers: Mutex<HashMap<PublicKey, Nanos>>,
    links: Arc<Semaphore>,
    /// Each identity's newest link's generation.
    current: Mutex<HashMap<PublicKey, u64>>,
    generations: AtomicU64,
    streams: Arc<Semaphore>,
    frames: Arc<Semaphore>,
    tasks: Arc<Semaphore>,
    sync_link: Arc<Semaphore>,
    /// `sync.pages` but those kept for records.
    pages: Arc<Semaphore>,
    /// The heads walks hold checked.
    walks: Arc<Semaphore>,
    live_frames: Keyed<PublicKey>,
    live_bytes: Keyed<PublicKey>,
    backlog: Keyed<PublicKey>,
    /// By link and author.
    chat: Keyed<(PublicKey, PublicKey)>,
    datagrams: Keyed<PublicKey>,
    presence: Keyed<PublicKey>,
    /// This peer's own chat.
    said: Direct,
    sync_in: Keyed<PublicKey>,
    sync_out: Keyed<PublicKey>,
}

impl fmt::Debug for Budgets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Budgets")
            .field("strangers", &self.0.strangers.available_permits())
            .field("links", &self.0.links.available_permits())
            .field("frames", &self.0.frames.available_permits())
            .finish_non_exhaustive()
    }
}

/// `mutex`, locked (as it is, if a holder panicked).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Takes `n` cells of `key` from `rate` if as many are left.
fn take<K: Hash + Eq + Clone>(rate: &Keyed<K>, key: &K, n: usize) -> bool {
    let Some(n) = NonZeroU32::new(u32::try_from(n).unwrap_or(u32::MAX)) else {
        return true;
    };
    matches!(rate.check_key_n(key, n), Ok(Ok(())))
}

/// `n` permits of `semaphore`, if free.
fn permits(semaphore: &Arc<Semaphore>, n: usize) -> Option<OwnedSemaphorePermit> {
    Arc::clone(semaphore)
        .try_acquire_many_owned(u32::try_from(n).ok()?)
        .ok()
}

impl Default for Budgets {
    /// On tokio's clock.
    fn default() -> Self {
        Self::new(Clock::real())
    }
}

impl Budgets {
    /// Fresh ones, rates kept on `clock`.
    #[must_use]
    pub fn new(clock: Clock) -> Self {
        fn keyed<K: Hash + Eq + Clone>(rate: Rate, clock: &Clock) -> Keyed<K> {
            RateLimiter::hashmap_with_clock(rate.quota(), clock.clone())
        }
        Self(Arc::new(Shared {
            strangers: Arc::new(Semaphore::new(STRANGERS)),
            asking: Arc::new(Semaphore::new(ASKING)),
            waiting: Mutex::default(),
            asks: keyed(ASKS, &clock),
            askers: Mutex::default(),
            links: Arc::new(Semaphore::new(LINKS)),
            current: Mutex::default(),
            generations: AtomicU64::new(0),
            streams: Arc::new(Semaphore::new(STREAMS)),
            frames: Arc::new(Semaphore::new(FRAMES)),
            tasks: Arc::new(Semaphore::new(TASKS)),
            sync_link: Arc::new(Semaphore::new(SYNC_LINK)),
            pages: Arc::new(Semaphore::new(SYNC_PAGES)),
            walks: Arc::new(Semaphore::new(WALKS)),
            live_frames: keyed(LIVE_FRAMES, &clock),
            live_bytes: keyed(LIVE_BYTES, &clock),
            backlog: keyed(CHAT_BACKLOG, &clock),
            chat: keyed(CHAT, &clock),
            datagrams: keyed(DATAGRAMS, &clock),
            presence: keyed(PRESENCE, &clock),
            said: RateLimiter::direct_with_clock(CHAT.quota(), clock.clone()),
            sync_in: keyed(SYNC_BYTES, &clock),
            sync_out: keyed(SYNC_BYTES, &clock),
            clock,
        }))
    }

    /// The process's, on tokio's clock.
    #[must_use]
    pub fn process() -> Self {
        static PROCESS: LazyLock<Budgets> = LazyLock::new(Budgets::default);
        PROCESS.clone()
    }

    /// A place in the stranger pool, for its first stage ([`HANDSHAKE`]
    /// from now); none if the pool is full.
    #[must_use]
    pub fn stranger(&self) -> Option<Stranger> {
        Some(Stranger {
            _place: permits(&self.0.strangers, 1)?,
            deadline: Deadline::after(HANDSHAKE),
        })
    }

    /// The places free in the stranger pool.
    #[cfg(test)]
    pub(crate) fn strangers_free(&self) -> usize {
        self.0.strangers.available_permits()
    }

    /// `key`'s request to join, `stranger` holding its place: counted,
    /// its slot taken, and the stranger's deadline [`ASK_FOR`] from now.
    ///
    /// # Errors
    ///
    /// One of the key's waits already, [`ASKING`] do, or the key asked
    /// [`ASKS`] lately (only a request that passes the first two counts).
    pub fn ask(&self, stranger: &mut Stranger, key: PublicKey) -> Result<Asking, Refused> {
        let mut waiting = lock(&self.0.waiting);
        if waiting.contains(&key) {
            return Err(Refused::Waiting);
        }
        let slot = permits(&self.0.asking, 1).ok_or(Refused::Full)?;
        if !self.counted(key) {
            return Err(Refused::Often);
        }
        waiting.insert(key);
        stranger.deadline = Deadline::after(ASK_FOR);
        Ok(Asking {
            budgets: self.clone(),
            key,
            answer_by: Deadline::after(ASK_FOR.saturating_sub(HANDSHAKE)),
            _slot: slot,
        })
    }

    /// Counts a request of `key`: whether it is within [`ASKS`].
    fn counted(&self, key: PublicKey) -> bool {
        let now = self.0.clock.now();
        let horizon = Nanos::from(ASKS.horizon());
        let mut askers = lock(&self.0.askers);
        askers.retain(|_, last| now.duration_since(*last) < horizon);
        self.0.asks.retain_recent();
        let asker = if askers.contains_key(&key) || askers.len() < ASKERS {
            askers.insert(key, now);
            Asker::Key(key)
        } else {
            Asker::Overflow
        };
        self.0.asks.check_key(&asker).is_ok()
    }

    /// A link to `remote`, its generation the newest; none past
    /// [`LINKS`] or with no room for its [`SYNC_LINK_BASE`].
    #[must_use]
    pub fn link(&self, remote: PublicKey) -> Option<LinkBudget> {
        let place = permits(&self.0.links, 1)?;
        let sync = Arc::new(Semaphore::new(SYNC_LINK_PER_LINK));
        let base = charge(&self.0.sync_link, &sync, SYNC_LINK_BASE)?;
        let generation = self.0.generations.fetch_add(1, Ordering::Relaxed) + 1;
        lock(&self.0.current).insert(remote, generation);
        Some(LinkBudget {
            budgets: self.clone(),
            remote,
            generation,
            streams: Arc::new(Semaphore::new(LINK_STREAMS)),
            sync,
            charged: AtomicUsize::new(0),
            pages: Arc::new(Semaphore::new(SYNC_PAGES_PER_LINK)),
            _base: base,
            _place: place,
        })
    }

    /// The generation of `remote`'s newest link, while it lasts.
    #[must_use]
    pub fn current(&self, remote: PublicKey) -> Option<u64> {
        lock(&self.0.current).get(&remote).copied()
    }

    /// `length` bytes for an inbound frame's body, reserved until
    /// dropped, waiting for them; none if they can never be (past
    /// [`FRAMES`]).
    pub async fn frame(&self, length: usize) -> Option<Frame> {
        if length > FRAMES {
            return None;
        }
        let n = u32::try_from(length).ok()?;
        let held = Arc::clone(&self.0.frames)
            .acquire_many_owned(n)
            .await
            .ok()?;
        Some(Frame { _held: held })
    }

    /// A place for a task a remote party starts; none past [`TASKS`].
    #[must_use]
    pub fn task(&self) -> Option<Task> {
        Some(Task {
            _place: permits(&self.0.tasks, 1)?,
        })
    }

    /// Room for `heads` more heads checked by walks of listed prefixes;
    /// none past [`WALKS`] in all.
    #[must_use]
    pub fn walk(&self, heads: usize) -> Option<Held> {
        Some(Held(permits(&self.0.walks, heads)?))
    }

    /// `bytes` of the process's `sync.link` for what is kept of a link
    /// once it has gone (its report, for a flush); none past
    /// [`SYNC_LINK`].
    #[must_use]
    pub fn retain(&self, bytes: usize) -> Option<Held> {
        Some(Held(permits(&self.0.sync_link, bytes)?))
    }

    /// The pages of changes not being built now, of [`SYNC_PAGES`].
    #[must_use]
    pub fn pages_free(&self) -> usize {
        self.0.pages.available_permits()
    }

    /// The heads walks may yet hold, of [`WALKS`].
    #[must_use]
    pub fn walks_free(&self) -> usize {
        self.0.walks.available_permits()
    }

    /// Whether a live frame of `bytes` from `from`'s link is within its
    /// rates ([`LIVE_FRAMES`], [`LIVE_BYTES`]): counted if so.
    #[must_use]
    pub fn live_frame(&self, from: PublicKey, bytes: usize) -> bool {
        self.0.live_frames.check_key(&from).is_ok() && take(&self.0.live_bytes, &from, bytes)
    }

    /// Whether a chat message of `author` through `via`'s link is within
    /// its rates: the link's backlog ([`CHAT_BACKLOG`]), else the
    /// author's through it ([`CHAT`]). Counted if so.
    #[must_use]
    pub fn chat(&self, via: PublicKey, author: PublicKey) -> bool {
        self.0.backlog.check_key(&via).is_ok() || self.0.chat.check_key(&(via, author)).is_ok()
    }

    /// Whether a presence datagram from `from`'s link may be opened
    /// ([`DATAGRAMS`]): counted if so.
    #[must_use]
    pub fn datagram(&self, from: PublicKey) -> bool {
        self.0.datagrams.check_key(&from).is_ok()
    }

    /// Whether a presence of `participant` may be taken ([`PRESENCE`]):
    /// counted if so.
    #[must_use]
    pub fn presence(&self, participant: PublicKey) -> bool {
        self.0.presence.check_key(&participant).is_ok()
    }

    /// Whether this peer may send a chat message now ([`CHAT`]): counted
    /// if so.
    #[must_use]
    pub fn say_chat(&self) -> bool {
        self.0.said.check().is_ok()
    }

    /// `bytes` of sync from `from` (`sync.in`, [`SYNC_BYTES`]): how long
    /// to wait before taking them; zero if they are taken now (counted).
    /// More than a burst costs a burst.
    #[must_use]
    pub fn sync_in(&self, from: PublicKey, bytes: usize) -> Duration {
        self.wait(&self.0.sync_in, from, bytes)
    }

    /// `bytes` of sync to `to` (`sync.out`, [`SYNC_BYTES`]): as
    /// [`Self::sync_in`].
    #[must_use]
    pub fn sync_out(&self, to: PublicKey, bytes: usize) -> Duration {
        self.wait(&self.0.sync_out, to, bytes)
    }

    fn wait(&self, rate: &Keyed<PublicKey>, key: PublicKey, bytes: usize) -> Duration {
        let n = u32::try_from(bytes)
            .unwrap_or(u32::MAX)
            .min(SYNC_BYTES.burst);
        let Some(n) = NonZeroU32::new(n) else {
            return Duration::ZERO;
        };
        match rate.check_key_n(&key, n) {
            Ok(Err(not_yet)) => not_yet.wait_time_from(self.0.clock.now()),
            Ok(Ok(())) | Err(_) => Duration::ZERO,
        }
    }

    /// Drops the rates' keys no different from fresh ones.
    fn tidy(&self) {
        let shared = &*self.0;
        for rate in [
            &shared.live_frames,
            &shared.live_bytes,
            &shared.backlog,
            &shared.datagrams,
            &shared.presence,
            &shared.sync_in,
            &shared.sync_out,
        ] {
            rate.retain_recent();
        }
        shared.chat.retain_recent();
    }
}

/// `bytes` of `sync.link`, of the process's (`process`) and a link's
/// (`link`).
fn charge(process: &Arc<Semaphore>, link: &Arc<Semaphore>, bytes: usize) -> Option<Charge> {
    let link = permits(link, bytes)?;
    Some(Charge {
        _process: permits(process, bytes)?,
        _link: link,
    })
}

/// A place in the stranger pool, held until dropped.
#[derive(Debug)]
pub struct Stranger {
    _place: OwnedSemaphorePermit,
    deadline: Deadline,
}

impl Stranger {
    /// When its current stage ends: everything said to it is said by
    /// then.
    #[must_use]
    pub fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Starts its next stage (the hello, after the TLS handshake), the
    /// same place held: [`HANDSHAKE`] from now.
    pub fn next_stage(&mut self) {
        self.deadline = Deadline::after(HANDSHAKE);
    }
}

/// A request waiting for the approver, its slot held until dropped.
#[derive(Debug)]
pub struct Asking {
    budgets: Budgets,
    key: PublicKey,
    answer_by: Deadline,
    _slot: OwnedSemaphorePermit,
}

impl Asking {
    /// When the approver's time is up: [`HANDSHAKE`] before the
    /// stranger's deadline, for the last word.
    #[must_use]
    pub fn answer_by(&self) -> Deadline {
        self.answer_by
    }
}

impl Drop for Asking {
    fn drop(&mut self) {
        lock(&self.budgets.0.waiting).remove(&self.key);
    }
}

/// A link's place and its own ceilings, until dropped.
#[derive(Debug)]
pub struct LinkBudget {
    budgets: Budgets,
    remote: PublicKey,
    generation: u64,
    streams: Arc<Semaphore>,
    sync: Arc<Semaphore>,
    /// What the sync machine charged it ([`Self::charge_sync`]), held
    /// until refunded or the link goes.
    charged: AtomicUsize,
    pages: Arc<Semaphore>,
    _base: Charge,
    _place: OwnedSemaphorePermit,
}

impl LinkBudget {
    /// Its number: links made later have larger ones.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether it is its remote's newest link.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.budgets.current(self.remote) == Some(self.generation)
    }

    /// A blob stream of it served, its ask due within [`STREAM_ASK`];
    /// none past [`LINK_STREAMS`] of it or [`STREAMS`] in all.
    #[must_use]
    pub fn stream(&self) -> Option<Stream> {
        let link = permits(&self.streams, 1)?;
        Some(Stream {
            _process: permits(&self.budgets.0.streams, 1)?,
            _link: link,
            ask_by: Deadline::after(STREAM_ASK),
        })
    }

    /// `bytes` of `sync.link` for it; none past [`SYNC_LINK_PER_LINK`]
    /// of it or [`SYNC_LINK`] in all (the link is then closed).
    #[must_use]
    pub fn charge(&self, bytes: usize) -> Option<Charge> {
        charge(&self.budgets.0.sync_link, &self.sync, bytes)
    }

    /// Charges `bytes` more of `sync.link` for the sync machine's state of
    /// it, held until [`Self::refund_sync`] or the link goes: false past
    /// [`SYNC_LINK_PER_LINK`] of it or [`SYNC_LINK`] in all.
    #[must_use]
    pub fn charge_sync(&self, bytes: usize) -> bool {
        let Some(Charge {
            _link: link,
            _process: process,
        }) = self.charge(bytes)
        else {
            return false;
        };
        link.forget();
        process.forget();
        self.charged.fetch_add(bytes, Ordering::Relaxed);
        true
    }

    /// Gives back `bytes` of what [`Self::charge_sync`] charged (no more
    /// than it holds).
    pub fn refund_sync(&self, bytes: usize) {
        let mut given = 0;
        let _ = self
            .charged
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                given = held.min(bytes);
                Some(held - given)
            });
        self.sync.add_permits(given);
        self.budgets.0.sync_link.add_permits(given);
    }

    /// A sync page to build for it, waiting for one (of
    /// [`SYNC_PAGES_PER_LINK`] of its own, and [`SYNC_PAGES`] of the
    /// process's).
    pub async fn page(&self) -> Option<Page> {
        let link = Arc::clone(&self.pages).acquire_owned().await.ok()?;
        let process = Arc::clone(&self.budgets.0.pages)
            .acquire_owned()
            .await
            .ok()?;
        Some(Page {
            _process: process,
            _link: Some(link),
        })
    }
}

impl Drop for LinkBudget {
    fn drop(&mut self) {
        let held = *self.charged.get_mut();
        self.budgets.0.sync_link.add_permits(held);
        {
            let mut current = lock(&self.budgets.0.current);
            if current.get(&self.remote) == Some(&self.generation) {
                current.remove(&self.remote);
            }
        }
        self.budgets.tidy();
    }
}

/// A blob stream's places, until dropped.
#[derive(Debug)]
pub struct Stream {
    _link: OwnedSemaphorePermit,
    _process: OwnedSemaphorePermit,
    ask_by: Deadline,
}

impl Stream {
    /// When its ask is due.
    #[must_use]
    pub fn ask_by(&self) -> Deadline {
        self.ask_by
    }
}

/// Bytes of `sync.link`, until dropped.
#[derive(Debug)]
pub struct Charge {
    _link: OwnedSemaphorePermit,
    _process: OwnedSemaphorePermit,
}

/// A share's own budget: the page kept for its membership records, which
/// a share's links alone wait for. A link of another share, its other
/// side not reading, cannot keep this share's members from catching up
/// with its membership chain.
#[derive(Debug)]
pub struct ShareBudget {
    records: Arc<Semaphore>,
}

impl Default for ShareBudget {
    fn default() -> Self {
        Self {
            records: Arc::new(Semaphore::new(1)),
        }
    }
}

impl ShareBudget {
    /// The page kept for the share's membership records, waiting for it.
    pub async fn records_page(&self) -> Option<Page> {
        let process = Arc::clone(&self.records).acquire_owned().await.ok()?;
        Some(Page {
            _process: process,
            _link: None,
        })
    }
}

/// Places of one of the process's pools ([`Budgets::walk`],
/// [`Budgets::retain`]), until dropped.
#[derive(Debug)]
pub struct Held(OwnedSemaphorePermit);

impl Held {
    /// Holds `other`'s places too, given back with these.
    pub fn merge(&mut self, other: Self) {
        self.0.merge(other.0);
    }

    /// How many places it holds.
    #[must_use]
    pub fn count(&self) -> usize {
        self.0.num_permits()
    }
}

/// A sync page's places, until dropped.
#[derive(Debug)]
pub struct Page {
    _link: Option<OwnedSemaphorePermit>,
    _process: OwnedSemaphorePermit,
}

/// An inbound frame's bytes, until dropped.
#[derive(Debug)]
pub struct Frame {
    _held: OwnedSemaphorePermit,
}

/// A task's place, until dropped.
#[derive(Debug)]
pub struct Task {
    _place: OwnedSemaphorePermit,
}
