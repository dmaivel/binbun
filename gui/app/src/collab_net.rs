//! A shared session's network side (`binbun-collab`, the `collab`
//! feature): the peer, on a tokio runtime of its own, sharing the binary's
//! project or joining one, its approvals asked of the window, what it
//! tells turned into [`NetEvent`]s (the window woken after each), and the
//! live session (people, cursors, chat) as the view models' types.
//!
//! The identity is this install's (the one that signs the journal's
//! changes), held by one process at a time (`collab.lock` beside it, as
//! the CLI's `share` and `join` hold it), and the project by one peer
//! (its lock file, `.<project>.lock` beside it).
//!
//! Files by hash: a sharer may send the binary and its debug file to
//! those who join ([`Sends`], [`Net::send`]); a joiner visits the host
//! first ([`Visit`]), whose membership chain names the binary the project
//! shared annotates ([`Visit::binary`]). If the window lacks it and the
//! host sends it, the window is asked ([`NetEvent::Offer`],
//! [`Net::decide`]) before it is fetched into binbun's downloads folder
//! under a name binbun gives it ([`fetches`]; going on where a fetch cut
//! short stopped, in binbun's cache). The share is joined in a project
//! directory of its own (`<sha256>-<name>@<share>`, named by the name the
//! host offers the binary under; only a file of that binary's bytes is
//! opened there), never in a private project, nothing of which is read or
//! changed: the window opens the binary in the share's project and joins
//! again, as it does with the binary open in another project. A list of
//! offers that cannot be read is skipped. A debug
//! file a peer sends is fetched into the downloads folder too
//! ([`Net::fetch_debug`]). The name a file is offered under is shown
//! ([`shown_name`]), never used as a path.
//!
//! A universal Mach-O file is shared as one slice, which the ticket and
//! the offer name: a joiner on another slice of the same file opens the
//! one shared and joins with it ([`NetEvent::Fetched`]'s `arch`).
//!
//! The owner adds a member by their identity card ([`my_card`] gives
//! one's own; [`Net::add_card`]), with a role, before sharing (each added
//! before the ticket is out, as `binbun share --add CARD` does) or
//! while: they join through any member linked, with an ordinary ticket.
//! Those holding the ticket who are not members are asked of the owner's
//! window, each answer bound to its request's id.
//! An agent connected to the owner's window is added by the card of the
//! identity this install holds for it, with the agent's role
//! ([`Net::add_agent`]). The peer speaks for each agent connected that is
//! a member ([`Net::host_agents`]): the others see it join, its cursor
//! and it leave as anyone's.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use binbun_collab::blobs::{Kind, Offer, OnProgress, Progress, Step, Visit};
use binbun_collab::bounded::Text;
use binbun_collab::fetches::{self, Fetches};
use binbun_collab::live::{
    Agent as LiveAgent, Analysis as LiveAnalysis, ChatLink as LiveLink, Cursor as LiveCursor,
    DebugRef, HostedAgent, LiveEvent, Place as LivePlace, Selection as LiveSelection,
};
use binbun_collab::membership::{Binary, Role as CollabRole};
use binbun_collab::net::{IrohTransport, NetOptions, Relay};
use binbun_collab::ticket::{Card, JoinTicket, LAN_ONLY};
use binbun_collab::{Approver, Config, Flushed, Notice, Notifier, Peer, Request, Transport};
use binbun_gui_view::agents::Agent;
use binbun_gui_view::chat::ChatLink;
use binbun_gui_view::collab::{
    Analysis, CardRefused, ChatLine, Cursor, Fetching, Offered, Person, Place, Role, Selection,
    card_refused, card_text, fingerprint, listed_members, shown_name, size_text,
};
use binbun_gui_view::session::Wake;
use binbun_gui_view::settings::CollabRelay;
use binbun_gui_view::sharing::{Listed, reopen_as};

use binbun_session::Session;
use binbun_session::identity::{self, Identity};
use binbun_session::journal::{ChainId, EngineVersion, PublicKey, Refused};
use binbun_session::project;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

/// How a host is reached (the CLI's `--relay` with the `collab.relay`
/// setting's relay, `--relay none`, `--lan-only`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The `collab.relay` setting's relay.
    #[default]
    Relay,
    /// No relay: direct addresses only.
    NoRelay,
    /// The LAN only: no relay, mDNS, no port mapping.
    Lan,
}

impl Mode {
    /// Its label in the Share and Join dialogs, with `relay` the setting's.
    pub fn label(self, relay: &CollabRelay) -> &'static str {
        match self {
            Self::Relay => relay.label(),
            Self::NoRelay => "No relay",
            Self::Lan => "LAN only",
        }
    }

    /// The endpoint's options, with `relay` the setting's.
    fn options(self, relay: &CollabRelay) -> NetOptions {
        match self {
            Self::Relay => NetOptions {
                relay: match relay {
                    CollabRelay::Binbun => Relay::Binbun,
                    CollabRelay::N0 => Relay::N0,
                    CollabRelay::Custom(url) => Relay::Custom(vec![url.clone()]),
                },
                ..NetOptions::default()
            },
            Self::NoRelay => NetOptions {
                relay: Relay::Disabled,
                ..NetOptions::default()
            },
            Self::Lan => NetOptions {
                relay: Relay::Disabled,
                mdns: true,
                portmap: false,
                bind: None,
            },
        }
    }
}

/// Someone asking to join, for the approval dialog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    /// The request's number (to answer it).
    pub id: u64,
    /// Their identity key (the link proved it).
    pub key: PublicKey,
    /// The name on their card.
    pub name: String,
    /// How their link reaches this peer.
    pub path: String,
    /// The binbun they run.
    pub engine: EngineVersion,
}

/// What the network side tells the window.
#[derive(Clone, Debug)]
pub enum NetEvent {
    /// Sharing: the ticket to hand out.
    Ticket(String),
    /// Someone asks to join.
    Asked(Asked),
    /// A request to join withdrawn before it was answered (the asker
    /// gone, the invite forgotten): its number.
    Withdrawn(u64),
    /// A line for the status (linked, waiting, admitted…).
    Said(String),
    /// This peer's request was refused, or it was put out: the session
    /// is over.
    Ended(String),
    /// This peer is view-only in the session (another build than the
    /// host's), and why: its edits would be refused.
    ViewOnly(String),
    /// Something failed.
    Failed(String),
    /// Changes came from a peer.
    Took,
    /// A change was refused.
    Refused,
    /// The membership changed (roles).
    Members,
    /// A participant's cursor moved.
    Cursor(PublicKey, Cursor),
    /// Someone came, left or said whom they follow.
    People,
    /// A chat message.
    Chat(ChatLine),
    /// The owner removed a chat message: its id.
    ChatRemoved(u64),
    /// The host sends a binary this window lacks: fetch it?
    /// ([`Net::decide`]).
    Offer(Offered),
    /// A fetch under way: how far it is.
    Fetching(Fetching),
    /// A file fetched (or the binary found here) at this path: a binary
    /// to open and join with, a debug file to analyse with.
    Fetched {
        /// Whether it is a debug file.
        debug: bool,
        /// Where it is.
        path: PathBuf,
        /// The slice to open, of a universal binary: the one shared.
        arch: Option<String>,
        /// The project directory to open it in (`None`: its own, as
        /// any file opened): the share's, of a binary joined with.
        project: Option<PathBuf>,
    },
    /// A fetch failed, and why.
    FetchFailed(String),
}

/// What a sharer sends to those who join (nothing by default).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sends {
    /// The binary.
    pub binary: bool,
    /// The debug file the analysis read.
    pub debug: bool,
}

/// What the window makes of a binary the host sends that it lacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Fetch it.
    Fetch,
    /// Join with this file instead (the same bytes, found here).
    Open(PathBuf),
    /// Do not join.
    Cancel,
}

/// The answers awaited, by request.
type Answers = Arc<Mutex<HashMap<u64, oneshot::Sender<Option<CollabRole>>>>>;

/// How long stopping waits for those linked to say they hold this peer's
/// changes.
pub const FLUSH: Duration = Duration::from_secs(5);

/// What is told what a flush came to ([`Net::stop`]): the keys of those
/// who said they hold this peer's changes, of those still linked who had
/// not when the wait ran out, of those whose link went first.
pub type Report = Box<dyn FnOnce([Vec<PublicKey>; 3]) + Send>;

/// Where the window's answer to an offer goes, while one is asked.
type Deciding = Arc<Mutex<Option<oneshot::Sender<Decision>>>>;

/// This window's analysis as last announced: told to the peer once it
/// exists (a small binary is analysed before its share or join is up).
type Announced = Arc<Mutex<Option<LiveAnalysis>>>;

/// Puts `peer` in `slot` and tells it the analysis `announced` so far.
fn settle(slot: &Mutex<Option<Arc<Peer>>>, peer: &Arc<Peer>, announced: &Announced) {
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(peer));
    let analysis = announced
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if analysis.is_some() {
        peer.announce(analysis);
    }
}

/// A shared session's network side.
pub struct Net {
    runtime: Option<Runtime>,
    peer: Arc<Mutex<Option<Arc<Peer>>>>,
    events: Receiver<NetEvent>,
    answers: Answers,
    me: PublicKey,
    hosting: bool,
    /// The peers linked view-only, and why.
    view_only: ViewOnly,
    /// The identity's lock and the project's, held while the peer runs.
    locks: Vec<File>,
    /// Where the window's answer to an offer goes.
    deciding: Deciding,
    /// The analysis announced.
    announced: Announced,
    /// The window's events, and its wake (for fetches and offers).
    sender: Sender<NetEvent>,
    wake: Wake,
}

impl std::fmt::Debug for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Net")
            .field("me", &self.me)
            .field("hosting", &self.hosting)
            .finish_non_exhaustive()
    }
}

/// `role` as shown.
fn shown_role(role: CollabRole) -> Role {
    match role {
        CollabRole::Owner => Role::Owner,
        CollabRole::Editor => Role::Editor,
        CollabRole::Viewer => Role::Viewer,
        CollabRole::Store => Role::Store,
        CollabRole::Agent => Role::Agent,
    }
}

/// `role` as the membership chain has it.
fn collab_role(role: Role) -> CollabRole {
    match role {
        Role::Owner => CollabRole::Owner,
        Role::Editor => CollabRole::Editor,
        Role::Viewer => CollabRole::Viewer,
        Role::Store => CollabRole::Store,
        Role::Agent => CollabRole::Agent,
    }
}

/// The identity card pasted as `text` (whitespace a paste carries left
/// out), and its name.
///
/// # Errors
///
/// Not an identity card, or not signed by its key.
fn parse_card(text: &str) -> Result<(Card, String), String> {
    let text = card_text(text).map_err(|not| not.text().to_owned())?;
    let card: Card = text.parse().map_err(|_: binbun_collab::Error| {
        "Not an identity card, or not signed by its key".to_owned()
    })?;
    let name = card.name.clone().into_string();
    Ok((card, name))
}

/// The key and name of the identity card pasted as `text`: what the Share
/// dialog lists before sharing.
///
/// # Errors
///
/// Not an identity card, or not signed by its key.
pub fn card_of(text: &str) -> Result<(PublicKey, String), String> {
    parse_card(text).map(|(card, name)| (card.key, name))
}

/// `cursor` as the view models have it.
fn shown_cursor(cursor: LiveCursor) -> Cursor {
    Cursor {
        place: match cursor.place {
            LivePlace::Listing => Place::Listing,
            LivePlace::C {
                function,
                reading,
                line,
            } => Place::C {
                function,
                reading,
                line,
            },
            LivePlace::Hex => Place::Hex,
            LivePlace::Graph { function } => Place::Graph { function },
            LivePlace::Xrefs => Place::Xrefs,
        },
        address: cursor.address,
        column: cursor.column,
        selection: cursor.selection.map(|selection| match selection {
            LiveSelection::Addresses { first, last } => Selection::Addresses { first, last },
            LiveSelection::Text { from, to } => Selection::Text { from, to },
        }),
    }
}

/// `cursor` as the live session has it.
fn live_cursor(cursor: Cursor) -> LiveCursor {
    LiveCursor {
        place: match cursor.place {
            Place::Listing => LivePlace::Listing,
            Place::C {
                function,
                reading,
                line,
            } => LivePlace::C {
                function,
                reading,
                line,
            },
            Place::Hex => LivePlace::Hex,
            Place::Graph { function } => LivePlace::Graph { function },
            Place::Xrefs => LivePlace::Xrefs,
        },
        address: cursor.address,
        column: cursor.column,
        selection: cursor.selection.map(|selection| match selection {
            Selection::Addresses { first, last } => LiveSelection::Addresses { first, last },
            Selection::Text { from, to } => LiveSelection::Text { from, to },
        }),
    }
}

/// The lock file at `path`, taken.
fn lock(path: &Path, held: &str) -> Result<File, String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let file = File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.try_lock().map_err(|_| held.to_owned())?;
    Ok(file)
}

/// The name a card carries by default: the login.
pub fn default_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "someone".to_owned())
}

/// The chains of `session`'s history that sharing it anew would list, the
/// longest first, those listed unless left out marked
/// (`collab-sync-v2.md` §14.6); `None` for a share's project, which
/// lists nothing anew.
///
/// # Errors
///
/// No identity.
pub fn listable(session: &Session) -> Result<Option<Vec<Listed>>, String> {
    if session.genesis().is_some() {
        return Ok(None);
    }
    let root = identity::root().ok_or_else(|| binbun_paths::Place::Identity.missing())?;
    let me = Identity::load_or_create(&root)?.public();
    let chains = binbun_collab::listable(session, me).into_iter();
    Ok(Some(
        chains
            .map(|chain| Listed {
                chain: chain.chain,
                author: chain.author,
                agent: chain.agent,
                mine: chain.mine,
                changes: chain.through,
                chosen: chain.chosen,
            })
            .collect(),
    ))
}

/// This install's identity card naming it `name` (`binbunid…`, as
/// `binbun id` prints it): what the owner adds a member by.
///
/// # Errors
///
/// No configuration directory; the identity cannot be read or made.
pub fn my_card(name: &str) -> Result<String, String> {
    let root = identity::root()
        .ok_or("no configuration directory: neither XDG_CONFIG_HOME nor HOME is set")?;
    let identity = Identity::load_or_create(&root)?;
    Ok(Card::new(&identity, name).to_string())
}

/// What starting a peer needs, ready.
struct Start {
    identity: Identity,
    locks: Vec<File>,
    runtime: Runtime,
}

/// This install's identity locked, `session`'s project (if any) read (the
/// session holds it for writing: `Project::hold`), a runtime.
fn start(session: Option<&Session>) -> Result<Start, String> {
    let root = identity::root().ok_or_else(|| binbun_paths::Place::Identity.missing())?;
    let identity = Identity::load_or_create(&root)?;
    let locks = vec![lock(
        &root.join("collab.lock"),
        "another binbun shares or joins with this identity",
    )?];
    if let Some(session) = session {
        session.project().ok_or("the project is not read yet")?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("binbun-collab")
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    Ok(Start {
        identity,
        locks,
        runtime,
    })
}

/// Sends `event`, and wakes the window if it was queued anew (not if it
/// took the place of one queued, or was dropped): what came of it.
fn tell(sender: &Sender<NetEvent>, wake: &Wake, event: NetEvent) -> Queued {
    let queued = sender.send(event);
    if queued == Queued::Added {
        wake();
    }
    queued
}

/// The most events waiting for the window (I37) that are each their own:
/// past it, a status line, a failure, a chat message or its removal is
/// dropped. Every other kind has a bound of its own: requests to join
/// ([`ASKED`], and their withdrawals no more), cursors ([`CURSORS`]), and
/// one of each other kind, the last kept (of a session's end, the first).
const EVENTS: usize = 1024;

/// The most requests to join asked of the window and not answered at
/// once: past it, one is turned away unasked. A withdrawal is queued only
/// for a request the window took and has not answered, so no more of
/// them wait than this either.
const ASKED: usize = 64;

/// The most participants whose cursors wait for the window: past it, the
/// cursor of another is dropped (each one's last is kept).
const CURSORS: usize = 256;

/// What became of an event sent to the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Queued {
    /// Queued at the end: the window is woken.
    Added,
    /// Put in the place of one of its kind queued, or (a withdrawal) taken
    /// with its request out of the queue: the window, woken for what was
    /// there, is not woken again.
    Merged,
    /// Dropped: past its bound, or the window gone.
    Dropped,
}

/// The kinds of event of which one waits at a time ([`EVENTS`]).
#[derive(PartialEq, Eq)]
enum Slot {
    Cursor(PublicKey),
    Ticket,
    ViewOnly,
    Took,
    Refused,
    Members,
    People,
    Offer,
    Fetching,
    Fetched(bool),
    FetchFailed,
}

impl NetEvent {
    /// The kind of which it is the one waiting, if it is of such a kind.
    fn slot(&self) -> Option<Slot> {
        Some(match self {
            Self::Cursor(key, _) => Slot::Cursor(*key),
            Self::Ticket(_) => Slot::Ticket,
            Self::ViewOnly(_) => Slot::ViewOnly,
            Self::Took => Slot::Took,
            Self::Refused => Slot::Refused,
            Self::Members => Slot::Members,
            Self::People => Slot::People,
            Self::Offer(_) => Slot::Offer,
            Self::Fetching(_) => Slot::Fetching,
            Self::Fetched { debug, .. } => Slot::Fetched(*debug),
            Self::FetchFailed(_) => Slot::FetchFailed,
            Self::Asked(_)
            | Self::Withdrawn(_)
            | Self::Said(_)
            | Self::Ended(_)
            | Self::Failed(_)
            | Self::Chat(_)
            | Self::ChatRemoved(_) => return None,
        })
    }
}

/// The events waiting for the window ([`EVENTS`]), and whether it still
/// polls.
struct Queue<T> {
    events: VecDeque<T>,
    open: bool,
}

/// Where the network side's events go ([`EVENTS`]).
struct Sender<T>(Arc<Mutex<Queue<T>>>);

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Sender<NetEvent> {
    /// Queues `event` for the window, within its kind's bound
    /// ([`EVENTS`]): what came of it.
    fn send(&self, event: NetEvent) -> Queued {
        let mut queue = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !queue.open {
            return Queued::Dropped;
        }
        let events = &mut queue.events;
        if let Some(slot) = event.slot() {
            if let Some(queued) = events.iter_mut().find(|q| q.slot().as_ref() == Some(&slot)) {
                *queued = event;
                return Queued::Merged;
            }
            let cursors = || events.iter().filter(|q| matches!(q, NetEvent::Cursor(..)));
            if matches!(slot, Slot::Cursor(_)) && cursors().count() >= CURSORS {
                return Queued::Dropped;
            }
        }
        match &event {
            // The request taken out before the window saw it: nothing to
            // withdraw.
            NetEvent::Withdrawn(id) => {
                let asked = |q: &NetEvent| matches!(q, NetEvent::Asked(a) if a.id == *id);
                if let Some(at) = events.iter().position(asked) {
                    events.remove(at);
                    return Queued::Merged;
                }
            }
            NetEvent::Asked(_) => {
                let asked = events.iter().filter(|q| matches!(q, NetEvent::Asked(_)));
                if asked.count() >= ASKED {
                    return Queued::Dropped;
                }
            }
            NetEvent::Ended(_) if events.iter().any(|q| matches!(q, NetEvent::Ended(_))) => {
                return Queued::Dropped;
            }
            NetEvent::Said(_)
            | NetEvent::Failed(_)
            | NetEvent::Chat(_)
            | NetEvent::ChatRemoved(_)
                if events.len() >= EVENTS =>
            {
                return Queued::Dropped;
            }
            NetEvent::Ended(_)
            | NetEvent::Said(_)
            | NetEvent::Failed(_)
            | NetEvent::Chat(_)
            | NetEvent::ChatRemoved(_)
            | NetEvent::Ticket(_)
            | NetEvent::ViewOnly(_)
            | NetEvent::Took
            | NetEvent::Refused
            | NetEvent::Members
            | NetEvent::Cursor(..)
            | NetEvent::People
            | NetEvent::Offer(_)
            | NetEvent::Fetching(_)
            | NetEvent::Fetched { .. }
            | NetEvent::FetchFailed(_) => {}
        }
        events.push_back(event);
        Queued::Added
    }
}

/// Where the window takes the network side's events from.
struct Receiver<T>(Arc<Mutex<Queue<T>>>);

impl<T> Receiver<T> {
    /// The events waiting, oldest first.
    fn take(&self) -> Vec<T> {
        let mut queue = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        queue.events.drain(..).collect()
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut queue = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        queue.open = false;
        queue.events.clear();
    }
}

/// A channel of events for the window ([`EVENTS`]).
fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let queue = Arc::new(Mutex::new(Queue {
        events: VecDeque::new(),
        open: true,
    }));
    (Sender(Arc::clone(&queue)), Receiver(queue))
}

/// The peers view-only in this session, and why (the host's links say).
type ViewOnly = Arc<Mutex<HashMap<PublicKey, String>>>;

/// The notices of a peer as events; the peers linked view-only kept in
/// `view_only`.
fn notifier(sender: Sender<NetEvent>, wake: Wake, view_only: ViewOnly) -> Notifier {
    let sender = Mutex::new(sender);
    Arc::new(move |notice: &Notice| {
        if let Notice::Linked {
            peer,
            view_only: why,
            ..
        } = notice
        {
            let mut kept = view_only.lock().unwrap_or_else(PoisonError::into_inner);
            match why {
                Some(why) => kept.insert(*peer, why.clone()),
                None => kept.remove(peer),
            };
        }
        let event = notice_event(notice);
        let sender = sender.lock().unwrap_or_else(PoisonError::into_inner);
        tell(&sender, &wake, event);
    })
}

/// What `notice` tells the window: each field a peer could have written
/// escaped ([`shown_name`]) before a line is put together (I11).
fn notice_event(notice: &Notice) -> NetEvent {
    let short = |key: PublicKey| fingerprint(key).chars().take(9).collect::<String>();
    match notice {
        Notice::Linked { peer, path, .. } => NetEvent::Said(format!(
            "Linked to {} via {}",
            short(*peer),
            shown_name(path)
        )),
        Notice::Unlinked { peer, why } => NetEvent::Said(format!(
            "Link to {} down: {}",
            short(*peer),
            shown_name(why)
        )),
        Notice::Waiting => NetEvent::Said("Waiting for the host's approval".to_owned()),
        Notice::Admitted { member, role } => {
            NetEvent::Said(format!("Admitted {} as {role}", short(*member)))
        }
        Notice::Turned { peer, why } => {
            NetEvent::Said(format!("Turned away {}: {}", short(*peer), shown_name(why)))
        }
        Notice::Membership { .. } => NetEvent::Members,
        Notice::Crowded { bytes } => NetEvent::Said(format!(
            "The membership chain is {} MiB: past 32 MiB no member can be removed",
            bytes >> 20
        )),
        Notice::Denied(why) => NetEvent::Ended(format!("Not admitted: {}", shown_name(why))),
        Notice::Kicked(why) => NetEvent::Ended(format!("Put out: {}", shown_name(why))),
        Notice::ViewOnly(why) => NetEvent::ViewOnly(shown_name(why)),
        Notice::Took { .. } => NetEvent::Took,
        Notice::Refused(_) => NetEvent::Refused,
        Notice::Failed(why) => NetEvent::Failed(shown_name(why)),
        Notice::Sending { to, kind, name } => NetEvent::Said(format!(
            "Sending the {kind} {} to {}",
            shown_name(name),
            short(*to)
        )),
        Notice::Sent {
            to,
            kind,
            name,
            error,
        } => NetEvent::Said(match error {
            None => format!("Sent the {kind} {} to {}", shown_name(name), short(*to)),
            Some(why) => format!(
                "Stopped sending the {kind} {} to {}: {}",
                shown_name(name),
                short(*to),
                shown_name(why)
            ),
        }),
    }
}

/// A request asked of the window, while the peer waits for its answer:
/// dropped unanswered (the asker gone, the invite forgotten), its answer
/// is no longer awaited and the window is told
/// ([`NetEvent::Withdrawn`]).
struct Awaited {
    id: u64,
    answers: Answers,
    sender: Arc<Mutex<Sender<NetEvent>>>,
    wake: Wake,
}

impl Drop for Awaited {
    fn drop(&mut self) {
        let unanswered = self
            .answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id)
            .is_some();
        if unanswered {
            let sender = self.sender.lock().unwrap_or_else(PoisonError::into_inner);
            tell(&sender, &self.wake, NetEvent::Withdrawn(self.id));
        }
    }
}

/// The approver of those holding the ticket who are not members: each
/// request asked of the window, answered by [`Net::answer`] (or refused
/// when the session stops), withdrawn when the peer stops waiting for it;
/// when [`ASKED`] wait already, or the window is gone, turned away
/// unasked.
fn approver(sender: Sender<NetEvent>, wake: Wake, answers: Answers) -> Approver {
    let sender = Arc::new(Mutex::new(sender));
    let next = Mutex::new(0u64);
    Arc::new(move |request: Request| {
        let id = {
            let mut next = next.lock().unwrap_or_else(PoisonError::into_inner);
            *next += 1;
            *next
        };
        let (answer, answered) = oneshot::channel();
        {
            let mut waiting = answers.lock().unwrap_or_else(PoisonError::into_inner);
            if waiting.len() >= ASKED {
                return Box::pin(async { None });
            }
            waiting.insert(id, answer);
        }
        let asked = Asked {
            id,
            key: request.card.key,
            name: request.card.name.into_string(),
            path: request.path,
            engine: request.engine,
        };
        let queued = {
            let sender = sender.lock().unwrap_or_else(PoisonError::into_inner);
            tell(&sender, &wake, NetEvent::Asked(asked))
        };
        if queued == Queued::Dropped {
            answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
            return Box::pin(async { None });
        }
        let awaited = Awaited {
            id,
            answers: Arc::clone(&answers),
            sender: Arc::clone(&sender),
            wake: Arc::clone(&wake),
        };
        Box::pin(async move {
            let _awaited = awaited;
            answered.await.ok().flatten()
        })
    })
}

/// The live session's events as the window's (a chat line's author is
/// named by the window, which knows the people).
fn listen(peer: &Peer, sender: Sender<NetEvent>, wake: Wake) {
    let sender = Mutex::new(sender);
    peer.on_live(Arc::new(move |event: &LiveEvent| {
        let event = match event {
            LiveEvent::Cursor(key, cursor) => NetEvent::Cursor(*key, shown_cursor(*cursor)),
            LiveEvent::Hi(_) | LiveEvent::Gone(_) | LiveEvent::Here(_) => NetEvent::People,
            LiveEvent::ChatRemoved(id) => NetEvent::ChatRemoved(*id),
            LiveEvent::Chat(message) => NetEvent::Chat(ChatLine {
                id: message.id,
                from: message.from,
                name: String::new(),
                time: message.time,
                text: message.text.to_string(),
                removed: false,
                links: message
                    .links
                    .iter()
                    .filter_map(|link| {
                        Some(ChatLink {
                            range: usize::try_from(link.start).ok()?
                                ..usize::try_from(link.end).ok()?,
                            address: link.address,
                            word: link.word,
                        })
                    })
                    .collect(),
                mentions: message.mentions.to_vec(),
            }),
        };
        let sender = sender.lock().unwrap_or_else(PoisonError::into_inner);
        tell(&sender, &wake, event);
    }));
}

/// How far a fetch of `offer` from `from` is, as events.
fn progress(sender: &Sender<NetEvent>, wake: &Wake, offer: &Offer, from: PublicKey) -> OnProgress {
    let sender = Mutex::new(sender.clone());
    let wake = Arc::clone(wake);
    let (name, debug) = (shown_name(&offer.name), offer.kind == Kind::DebugFile);
    Arc::new(move |progress: &Progress| {
        let fetching = Fetching {
            name: name.clone(),
            from,
            debug,
            opening: progress.step == Step::Opening,
            done: progress.done,
            total: progress.total,
        };
        let sender = sender.lock().unwrap_or_else(PoisonError::into_inner);
        tell(&sender, &wake, NetEvent::Fetching(fetching));
    })
}

/// Where the file of `offer` fetched from a peer goes: binbun's downloads
/// folder, under a name binbun gives it (never the one offered).
fn fetched_path(offer: &Offer) -> Result<PathBuf, String> {
    let dir = fetches::downloads().map_err(|e| e.to_string())?;
    Ok(dir.join(fetches::local_name(offer)))
}

/// The whole file at `path`'s SHA-256 (of every slice of a universal
/// file, as an offer has it), if it can be read.
fn sha256_of(path: &Path) -> Option<[u8; 32]> {
    let bytes = std::fs::read(path).ok()?;
    Some(*project::Key::new(&bytes, "").sha256())
}

/// The binary `offer` (of the host at the end of `visit`) into binbun's
/// downloads folder ([`fetched_path`]): there already if a file of the
/// same bytes is, else fetched (going on where a fetch cut short
/// stopped), its progress told.
async fn fetch_binary(
    visit: &Visit,
    offer: &Offer,
    from: PublicKey,
    sender: &Sender<NetEvent>,
    wake: &Wake,
) -> Result<PathBuf, String> {
    let to = fetched_path(offer)?;
    if sha256_of(&to) == Some(offer.sha256) {
        return Ok(to);
    }
    let cache = Fetches::new().map_err(|e| e.to_string())?;
    let told = progress(sender, wake, offer, from);
    visit
        .fetch(offer, &cache, &to, Some(told))
        .await
        .map(|fetched| fetched.path)
        .map_err(|e| e.to_string())
}

/// The project directory of the share whose genesis is `genesis` for the
/// binary at `path` (its slice `binary` names, of a universal file), a
/// joiner's project of its own for the share (`collab-sync-v2.md` §14.6):
/// the one there already for these bytes and this share, under whatever
/// name, else `<sha256>-<name>@<share>` in binbun's projects directory,
/// `name` the one the host offers the binary under (else the file's).
/// Only the binary the shared project annotates (`binary`, its owner's
/// chain's) has one: another file is refused. Nothing is written: the
/// session opened there makes it, and the peer joining with it makes its
/// journal the share's once the share's first record has come.
fn share_dir(
    path: &Path,
    binary: &Binary,
    genesis: &[u8; 32],
    name: Option<&str>,
) -> Result<PathBuf, String> {
    if sha256_of(path) != Some(binary.sha256) {
        return Err(format!(
            "{} is not the binary the project shared annotates",
            path.display()
        ));
    }
    let root = project::root().ok_or_else(|| binbun_paths::Place::Projects.missing())?;
    let key = project::Key::of_file_slice(path, binary.slice.as_deref())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let share = project::Choice::Share(project::share_id(genesis));
    if let Ok(located) = project::locate(&root, &key, &share) {
        return Ok(located.project.dir().to_path_buf());
    }
    let key = match name {
        Some(name) => key.renamed(name),
        None => key,
    };
    Ok(root.join(key.share_dir_name(genesis)))
}

/// The binary at `path` (its slice `arch`, of a universal file) to open
/// in the project directory `project` and join with.
fn fetched(path: PathBuf, arch: Option<String>, project: PathBuf) -> NetEvent {
    NetEvent::Fetched {
        debug: false,
        path,
        arch,
        project: Some(project),
    }
}

/// `session` is on `binary`, the binary the share whose genesis is
/// `genesis` annotates: `None` if it is open as the slice the share names
/// in the share's own project ([`share_dir`]), which joins; else the file
/// to open again so (it is open in another project, or as another slice).
fn reopen(
    session: &Session,
    binary: &Binary,
    genesis: &[u8; 32],
) -> Result<Option<NetEvent>, String> {
    let path = session.path().to_path_buf();
    let dir = share_dir(&path, binary, genesis, None)?;
    let in_share = session.project().is_some_and(|open| open.dir() == dir);
    let Some(arch) = reopen_as(session.slice(), in_share, Some(binary.slice.as_deref())) else {
        return Ok(None);
    };
    Ok(Some(fetched(path, arch, dir)))
}

/// Offers the session's file of `kind` through `peer`, what came of it
/// told.
async fn offer(peer: &Peer, kind: Kind, sender: &Sender<NetEvent>, wake: &Wake) {
    let event = match peer.offer(kind).await {
        Ok(prepared) => NetEvent::Said(format!(
            "Sending the {kind} {} ({}) to people who join{}",
            shown_name(&prepared.offer.name),
            size_text(prepared.offer.length),
            if prepared.kept {
                String::new()
            } else {
                format!(": sealed in {:.1} s", prepared.sealing.as_secs_f64())
            }
        )),
        Err(error) => NetEvent::Failed(format!(
            "Cannot send the {kind}: {}",
            shown_name(&error.to_string())
        )),
    };
    tell(sender, wake, event);
}

/// A join under way: the session joining with (if any), the host to visit
/// first, and where the window is told and answers.
struct Joining {
    session: Option<Arc<Session>>,
    config: Config,
    ticket: JoinTicket,
    asking: Deciding,
    sender: Sender<NetEvent>,
    wake: Wake,
}

impl Joining {
    /// Visits the host as `identity`, reached per `options`; joins with
    /// the session if it is on the binary the project shared annotates (as
    /// its owner's membership chain names it) in the share's own project;
    /// on that binary in another project, has the window open it in the
    /// share's ([`NetEvent::Fetched`]); else asks the window about that
    /// binary, if the host sends it, and fetches it (the same event): the
    /// peer joined, or none. A list of offers
    /// that cannot be read is skipped; an offer of another binary is not
    /// taken.
    async fn run(self, identity: &Identity, options: &NetOptions) -> Result<Option<Peer>, String> {
        let Self {
            session,
            config,
            ticket,
            asking,
            sender,
            wake,
        } = self;
        // Nothing is opened on the ticket's word (its slice is unsigned):
        // another slice of the file shared is opened again as the slice
        // the owner's membership chain names ([`reopen`]).
        let transport: Arc<dyn Transport> = Arc::new(
            IrohTransport::bind(&identity.secret(), options)
                .await
                .map_err(|e| e.to_string())?,
        );
        let visit = Visit::new(&transport, &config, &ticket)
            .await
            .map_err(|e| e.to_string())?;
        let Some(binary) = visit.binary().cloned() else {
            visit.close();
            transport.close().await;
            return Err(
                "The project shared names its binary so that its key does not open it".to_owned(),
            );
        };
        let genesis = visit.genesis();
        let open = session.as_ref().and_then(|s| s.file_sha256());
        if open == Some(binary.sha256)
            && let Some(session) = session
        {
            visit.close();
            let reopen = reopen(&session, &binary, &genesis);
            if matches!(reopen, Ok(None)) {
                return Peer::join(session, transport, config, &ticket)
                    .await
                    .map(Some)
                    .map_err(|e| e.to_string());
            }
            transport.close().await;
            if let Some(event) = reopen? {
                tell(&sender, &wake, event);
            }
            return Ok(None);
        }
        let offers = match visit.offers().await {
            Ok(offers) => offers,
            Err(error) => {
                visit.close();
                transport.close().await;
                return Err(format!("Cannot read what the host sends: {error}"));
            }
        };
        let offered = offers
            .into_iter()
            .find(|offer| offer.kind == Kind::Binary && offer.sha256 == binary.sha256);
        let Some(offer) = offered else {
            visit.close();
            transport.close().await;
            return Err(if session.is_some() {
                "the project shared annotates another binary than the one open, and the host \
                 does not send it: open it, then join"
            } else {
                "the host does not send the binary: open it, then join"
            }
            .to_owned());
        };
        let (answer, answered) = oneshot::channel();
        *asking.lock().unwrap_or_else(PoisonError::into_inner) = Some(answer);
        let from = ticket.host.id;
        let shown = Offered {
            name: shown_name(&offer.name),
            length: offer.length,
            sha256: offer.sha256,
            from,
            arch: offer.arch.as_deref().map(shown_name),
        };
        tell(&sender, &wake, NetEvent::Offer(shown));
        let path = match answered.await.unwrap_or(Decision::Cancel) {
            Decision::Fetch => fetch_binary(&visit, &offer, from, &sender, &wake).await,
            Decision::Open(path) => Ok(path),
            Decision::Cancel => Err("Not joined".to_owned()),
        };
        visit.close();
        transport.close().await;
        let path = path?;
        let dir = share_dir(&path, &binary, &genesis, Some(&*offer.name))?;
        tell(
            &sender,
            &wake,
            fetched(path, binary.slice.map(Text::into_string), dir),
        );
        Ok(None)
    }
}

impl Net {
    /// Shares `session`'s project as `name`, reached as `mode` says (its
    /// relay `relay`, the setting's): the
    /// endpoint bound and the peer started on a runtime of its own, the
    /// members `members` (identity cards, each with its role) added
    /// before the ticket comes ([`NetEvent::Ticket`]), so their first link
    /// is let in; others holding the ticket asked about; the chains of
    /// its history listed `listed` (`None`: those [`listable`] chooses; a
    /// share's project lists nothing anew); `wake` after each event.
    ///
    /// # Errors
    ///
    /// No identity, the identity or the project held by another binbun,
    /// no runtime.
    #[expect(
        clippy::too_many_arguments,
        reason = "what the Share dialog chose, each its own"
    )]
    pub fn share(
        session: Arc<Session>,
        name: &str,
        mode: Mode,
        relay: &CollabRelay,
        sends: Sends,
        members: Vec<(String, Role)>,
        listed: Option<BTreeSet<ChainId>>,
        wake: Wake,
    ) -> Result<Self, String> {
        let options = mode.options(relay);
        let Start {
            identity,
            locks,
            runtime,
        } = start(Some(&session))?;
        let (sender, events) = channel();
        let answers = Answers::default();
        let peer = Arc::new(Mutex::new(None));
        let me = identity.public();
        let view_only = ViewOnly::default();
        let config = Config {
            identity: identity.clone(),
            name: name.to_owned(),
            approve: Some(approver(
                sender.clone(),
                Arc::clone(&wake),
                Arc::clone(&answers),
            )),
            notify: Some(notifier(
                sender.clone(),
                Arc::clone(&wake),
                Arc::clone(&view_only),
            )),
            engine: EngineVersion::this(),
        };
        let slot = Arc::clone(&peer);
        let announced = Announced::default();
        let told_analysis = Arc::clone(&announced);
        let (told, woken) = (sender.clone(), Arc::clone(&wake));
        runtime.spawn(async move {
            let started = async {
                let transport: Arc<dyn Transport> = Arc::new(
                    IrohTransport::bind(&identity.secret(), &options)
                        .await
                        .map_err(|e| e.to_string())?,
                );
                let (shared, mut ticket) = Peer::share_listing(session, transport, config, listed)
                    .await
                    .map_err(|e| e.to_string())?;
                if mode == Mode::Lan {
                    ticket.flags |= LAN_ONLY;
                }
                Ok::<_, String>((shared, ticket))
            };
            match started.await {
                Ok((shared, ticket)) => {
                    listen(&shared, sender.clone(), Arc::clone(&wake));
                    // Added before the ticket is out: their first link is
                    // let in.
                    for (text, role) in &members {
                        let added = parse_card(text).and_then(|(card, _)| {
                            shared
                                .add(&card, collab_role(*role))
                                .map_err(|e| e.to_string())
                        });
                        if let Err(why) = added {
                            tell(&sender, &wake, NetEvent::Failed(shown_name(&why)));
                        }
                    }
                    let shared = Arc::new(shared);
                    settle(&slot, &shared, &told_analysis);
                    tell(&sender, &wake, NetEvent::Ticket(ticket.to_string()));
                    tell(&sender, &wake, NetEvent::People);
                    tell(&sender, &wake, NetEvent::Members);
                    for (kind, wanted) in
                        [(Kind::Binary, sends.binary), (Kind::DebugFile, sends.debug)]
                    {
                        if wanted {
                            offer(&shared, kind, &sender, &wake).await;
                        }
                    }
                }
                Err(error) => {
                    tell(&sender, &wake, NetEvent::Ended(shown_name(&error)));
                }
            }
        });
        Ok(Self {
            runtime: Some(runtime),
            peer,
            events,
            answers,
            me,
            hosting: true,
            view_only,
            locks,
            deciding: Deciding::default(),
            announced,
            sender: told,
            wake: woken,
        })
    }

    /// Whether `ticket` asks for peers on the host's LAN only (`None`:
    /// not a ticket).
    pub fn lan_only(ticket: &str) -> Option<bool> {
        let ticket: JoinTicket = ticket.parse().ok()?;
        Some(ticket.lan_only())
    }

    /// Joins the project the host of `ticket` shares, as `name`,
    /// reaching it as `mode` says (its relay `relay`,
    /// the setting's), on a runtime of its own; `wake` after each event.
    /// The host is visited first (asked to
    /// admit this peer): if it
    /// sends a binary other than `session`'s (or there is none), the
    /// window is asked ([`NetEvent::Offer`]), the binary fetched
    /// ([`NetEvent::Fetched`]) and the session left to the window to open
    /// it and join again; else the session (on the same binary) joins.
    ///
    /// # Errors
    ///
    /// Not a ticket; no identity, the identity or the project held by
    /// another binbun, no runtime.
    pub fn join(
        session: Option<Arc<Session>>,
        name: &str,
        ticket: &str,
        mode: Mode,
        relay: &CollabRelay,
        wake: Wake,
    ) -> Result<Self, String> {
        let ticket: JoinTicket = ticket
            .parse()
            .map_err(|e: binbun_collab::Error| e.to_string())?;
        let options = mode.options(relay);
        let Start {
            identity,
            locks,
            runtime,
        } = start(session.as_deref())?;
        let (sender, events) = channel();
        let peer = Arc::new(Mutex::new(None));
        let me = identity.public();
        let view_only = ViewOnly::default();
        let config = Config {
            identity: identity.clone(),
            name: name.to_owned(),
            approve: None,
            notify: Some(notifier(
                sender.clone(),
                Arc::clone(&wake),
                Arc::clone(&view_only),
            )),
            engine: EngineVersion::this(),
        };
        let slot = Arc::clone(&peer);
        let deciding = Deciding::default();
        let asking = Arc::clone(&deciding);
        let announced = Announced::default();
        let told_analysis = Arc::clone(&announced);
        let (told, woken) = (sender.clone(), Arc::clone(&wake));
        runtime.spawn(async move {
            let joining = Joining {
                session,
                config,
                ticket,
                asking,
                sender: sender.clone(),
                wake: Arc::clone(&wake),
            };
            match joining.run(&identity, &options).await {
                Ok(Some(joined)) => {
                    listen(&joined, sender.clone(), Arc::clone(&wake));
                    settle(&slot, &Arc::new(joined), &told_analysis);
                    tell(
                        &sender,
                        &wake,
                        NetEvent::Said("Dialling the host".to_owned()),
                    );
                }
                Ok(None) => {}
                Err(error) => {
                    tell(&sender, &wake, NetEvent::Ended(shown_name(&error)));
                }
            }
        });
        Ok(Self {
            runtime: Some(runtime),
            peer,
            events,
            answers: Answers::default(),
            me,
            hosting: false,
            view_only,
            locks,
            deciding,
            announced,
            sender: told,
            wake: woken,
        })
    }

    /// Answers the offer asked ([`NetEvent::Offer`]).
    pub fn decide(&self, decision: Decision) {
        if let Some(answer) = self
            .deciding
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = answer.send(decision);
        }
    }

    /// Sends the binary (`debug`: the debug file the analysis read) to
    /// those who join from now (`on`), or no longer.
    pub fn send(&self, debug: bool, on: bool) {
        let (Some(peer), Some(runtime)) = (self.peer(), &self.runtime) else {
            return;
        };
        let kind = if debug { Kind::DebugFile } else { Kind::Binary };
        if !on {
            peer.withdraw(kind);
            tell(
                &self.sender,
                &self.wake,
                NetEvent::Said(format!("No longer sending the {kind}")),
            );
            return;
        }
        let (sender, wake) = (self.sender.clone(), Arc::clone(&self.wake));
        runtime.spawn(async move { offer(&peer, kind, &sender, &wake).await });
    }

    /// Fetches the debug file `from` analyses with, if they send it, into
    /// binbun's downloads folder ([`fetched_path`]): [`NetEvent::Fetched`],
    /// or [`NetEvent::FetchFailed`].
    pub fn fetch_debug(&self, from: PublicKey) {
        let (Some(peer), Some(runtime)) = (self.peer(), &self.runtime) else {
            return;
        };
        let (sender, wake) = (self.sender.clone(), Arc::clone(&self.wake));
        runtime.spawn(async move {
            let fetched = async {
                let offers = peer.offers(from).await.map_err(|e| e.to_string())?;
                let offer = offers
                    .into_iter()
                    .find(|offer| offer.kind == Kind::DebugFile)
                    .ok_or("they do not send their debug file (they share without it)")?;
                let to = fetched_path(&offer)?;
                let cache = Fetches::new().map_err(|e| e.to_string())?;
                let told = progress(&sender, &wake, &offer, from);
                peer.fetch(from, &offer, &cache, &to, Some(told))
                    .await
                    .map(|fetched| fetched.path)
                    .map_err(|e| e.to_string())
            };
            let event = match fetched.await {
                Ok(path) => NetEvent::Fetched {
                    debug: true,
                    path,
                    arch: None,
                    project: None,
                },
                Err(why) => NetEvent::FetchFailed(shown_name(&why)),
            };
            tell(&sender, &wake, event);
        });
    }

    /// The peer, once started.
    fn peer(&self) -> Option<Arc<Peer>> {
        self.peer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The events since the last poll.
    pub fn poll(&self) -> Vec<NetEvent> {
        self.events.take()
    }

    /// This install's identity key.
    pub fn me(&self) -> PublicKey {
        self.me
    }

    /// Whether this peer shares (else it joined).
    pub fn hosting(&self) -> bool {
        self.hosting
    }

    /// The shared project's id (its membership chain's), once known.
    pub fn project(&self) -> Option<String> {
        Some(self.peer()?.membership().project().to_string())
    }

    /// This peer's role, as the membership chain says.
    pub fn role(&self) -> Option<Role> {
        self.peer()?.role().map(shown_role)
    }

    /// The shared project's members in the order its membership chain
    /// admitted them (removed ones too): the same on every peer.
    pub fn admitted(&self) -> Vec<PublicKey> {
        self.peer()
            .map(|peer| peer.membership().admitted().to_vec())
            .unwrap_or_default()
    }

    /// The shared project's members now, in the order admitted, with
    /// their roles (the Members row's).
    pub fn members(&self) -> Vec<(PublicKey, Role)> {
        let Some(peer) = self.peer() else {
            return Vec::new();
        };
        let membership = peer.membership();
        let admitted: Vec<(PublicKey, Option<Role>)> = membership
            .admitted()
            .iter()
            .map(|&key| (key, membership.role(key).map(shown_role)))
            .collect();
        listed_members(&admitted)
    }

    /// Adds the member whose identity card is `text` as `role` (the
    /// owner's only; one removed is admitted again): their key and the
    /// card's name.
    ///
    /// # Errors
    ///
    /// Not an identity card, or not signed by its key; one's own; a
    /// member already; not the owner; not connected yet.
    pub fn add_card(&self, text: &str, role: Role) -> Result<(PublicKey, String), String> {
        let (card, name) = parse_card(text)?;
        let peer = self.peer().ok_or("Not connected yet")?;
        match card_refused(card.key, self.me, &self.members()) {
            Some(CardRefused::Own) => return Err("Your own identity card".to_owned()),
            Some(CardRefused::Member) => {
                return Err(format!("{} is a member already", shown_name(&name)));
            }
            None => {}
        }
        peer.add(&card, collab_role(role))
            .map_err(|e| e.to_string())?;
        Ok((card.key, name))
    }

    /// The share's owner, once the peer is up (a joiner knows them from
    /// the ticket before the first record comes).
    pub fn owner(&self) -> Option<PublicKey> {
        Some(self.peer()?.membership().owner())
    }

    /// Whether this window is joining: visiting the host, or joined with a
    /// session whose journal is not the share's yet. It takes no edits.
    pub fn joining(&self) -> bool {
        !self.hosting && self.peer().is_none_or(|peer| peer.session().joining())
    }

    /// Why this peer is view-only in the session, if it is: a viewer, or
    /// another build than the host's.
    pub fn read_only(&self) -> Option<String> {
        let peer = self.peer()?;
        if let Some(why) = peer.view_only() {
            return Some(why);
        }
        (peer.role() == Some(CollabRole::Viewer)).then(|| "you are a viewer".to_owned())
    }

    /// The others in the session, with their roles and links.
    pub fn people(&self) -> Vec<Person> {
        let Some(peer) = self.peer() else {
            return Vec::new();
        };
        let membership = peer.membership();
        let links: HashMap<PublicKey, String> = peer.links().into_iter().collect();
        let view_only = self
            .view_only
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let now = std::time::Instant::now();
        peer.participants()
            .into_iter()
            .map(|p| Person {
                key: p.card.key,
                name: p.card.name.to_string(),
                engine: p.engine.clone(),
                analysis: p.analysis.as_ref().map(|a| Analysis {
                    fingerprint: a.fingerprint,
                    debug: a.debug.as_ref().map(|d| (d.name.to_string(), d.sha256)),
                }),
                cursor: p.live_cursor(now).map(shown_cursor),
                following: p.following,
                role: membership.role(p.card.key).map(shown_role),
                path: links.get(&p.card.key).cloned(),
                view_only: view_only.get(&p.card.key).cloned(),
                agent: p.agent.map(|agent| Agent {
                    version: agent.version.map(Text::into_string),
                }),
            })
            .collect()
    }

    /// Sends `text` to the chat with the places it names and whom it
    /// mentions.
    ///
    /// # Errors
    ///
    /// Not started, too long, too fast, not admitted yet.
    pub fn chat(
        &self,
        text: &str,
        links: &[ChatLink],
        mentions: &[PublicKey],
    ) -> Result<(), String> {
        let peer = self.peer().ok_or("not connected yet")?;
        let links: Vec<LiveLink> = links
            .iter()
            .filter_map(|link| {
                Some(LiveLink {
                    start: u32::try_from(link.range.start).ok()?,
                    end: u32::try_from(link.range.end).ok()?,
                    address: link.address,
                    word: link.word,
                })
            })
            .collect();
        peer.chat(text, &links, mentions)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Removes chat message `id` for everyone (the owner's moderation).
    ///
    /// # Errors
    ///
    /// Not connected; this peer is not the owner.
    pub fn remove_chat(&self, id: u64) -> Result<(), String> {
        let peer = self.peer().ok_or("not connected yet")?;
        peer.remove_chat(id).map_err(|e| e.to_string())
    }

    /// Says where this window's cursor is.
    pub fn set_cursor(&self, cursor: Cursor) {
        if let Some(peer) = self.peer() {
            peer.set_cursor(live_cursor(cursor));
        }
    }

    /// Speaks for the agents connected to this window now (`agents`: each
    /// one's identity and how this window shows it), those that are
    /// members: the others see them as participants.
    pub fn host_agents(&self, agents: &[(Identity, Person)]) {
        let Some(peer) = self.peer() else {
            return;
        };
        peer.host_agents(
            agents
                .iter()
                .map(|(identity, person)| HostedAgent {
                    identity: identity.clone(),
                    name: person.name.clone(),
                    agent: LiveAgent {
                        version: person
                            .agent
                            .as_ref()
                            .and_then(|a| a.version.as_deref().map(Text::truncated)),
                    },
                    cursor: person.cursor.map(live_cursor),
                })
                .collect(),
        );
    }

    /// Says whom this window follows.
    pub fn follow(&self, leader: Option<PublicKey>) {
        if let Some(peer) = self.peer() {
            peer.follow(leader);
        }
    }

    /// Tells the others this window's analysis (once the peer is up, if
    /// it is not yet).
    pub fn announce(&self, analysis: Option<&Analysis>) {
        let analysis = analysis.map(|a| LiveAnalysis {
            fingerprint: a.fingerprint,
            debug: a.debug.as_ref().map(|(name, sha256)| DebugRef {
                name: Text::truncated(name),
                sha256: *sha256,
            }),
        });
        analysis.clone_into(
            &mut self
                .announced
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        if let Some(peer) = self.peer() {
            peer.announce(analysis);
        }
    }

    /// Answers request `id`: admitted as `role`, or not (`None`).
    pub fn answer(&self, id: u64, role: Option<Role>) {
        let role = role.and_then(|role| match role {
            Role::Editor => Some(CollabRole::Editor),
            Role::Viewer => Some(CollabRole::Viewer),
            Role::Agent => Some(CollabRole::Agent),
            Role::Owner | Role::Store => None,
        });
        if let Some(answer) = self
            .answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id)
        {
            let _ = answer.send(role);
        }
    }

    /// Makes `member` an editor, a viewer or an agent (the owner's only).
    ///
    /// # Errors
    ///
    /// Not the owner; not a member; another role.
    pub fn set_role(&self, member: PublicKey, role: Role) -> Result<(), String> {
        let peer = self.peer().ok_or("not connected yet")?;
        let role = match role {
            Role::Editor => CollabRole::Editor,
            Role::Viewer => CollabRole::Viewer,
            Role::Agent => CollabRole::Agent,
            Role::Owner | Role::Store => {
                return Err("only editor, viewer or agent".to_owned());
            }
        };
        peer.set_role(member, role).map_err(|e| e.to_string())
    }

    /// Adds the agent of `identity` named `name` as a member with the
    /// agent's role (the owner's only), by the card its identity makes.
    ///
    /// # Errors
    ///
    /// Not the owner; a member already; not connected yet.
    pub fn add_agent(&self, identity: &Identity, name: &str) -> Result<(), String> {
        let peer = self.peer().ok_or("Not connected yet")?;
        peer.add(&Card::new(identity, name), CollabRole::Agent)
            .map_err(|e| e.to_string())
    }

    /// Removes `member` (the owner's only): a new epoch they never get.
    ///
    /// # Errors
    ///
    /// Not the owner; not a member.
    pub fn remove(&self, member: PublicKey) -> Result<(), String> {
        let peer = self.peer().ok_or("not connected yet")?;
        peer.remove(member).map(|_| ()).map_err(|e| e.to_string())
    }

    /// The changes refused, by this peer's checks and the session's.
    pub fn refused(&self) -> Vec<Refused> {
        self.peer().map(|peer| peer.refused()).unwrap_or_default()
    }

    /// Goes on with `session` (a newer analysis of the binary).
    pub fn set_session(&self, session: Arc<Session>) {
        if let Some(peer) = self.peer() {
            peer.set_session(session);
        }
    }

    /// Stops: this peer's changes flushed to those linked ([`FLUSH`] at
    /// most), what came of it given to `report` (those who said they hold
    /// them, those who had not when the wait ran out, those who went
    /// first), the links closed, waiting for that at most `wait` (the rest
    /// goes on in the background, unless the process ends).
    pub fn stop(mut self, wait: Duration, report: Option<Report>) {
        for (_, answer) in self
            .answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
        {
            let _ = answer.send(None);
        }
        let peer = self
            .peer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let (done, finished) = mpsc::channel();
        let locks = std::mem::take(&mut self.locks);
        let stopping = std::thread::Builder::new()
            .name("binbun-collab-stop".to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    let flushed = match peer {
                        Some(peer) => {
                            let flushed = peer.flush(FLUSH).await;
                            if let Ok(peer) = Arc::try_unwrap(peer) {
                                peer.close().await;
                            }
                            flushed
                        }
                        None => Flushed::default(),
                    };
                    if let Some(report) = report {
                        report([
                            flushed.acknowledged,
                            flushed.unacknowledged,
                            flushed.disconnected,
                        ]);
                    }
                });
                drop(locks);
                let _ = done.send(());
                runtime.shutdown_timeout(Duration::from_secs(1));
            });
        if stopping.is_ok() {
            let _ = finished.recv_timeout(wait);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    use binbun_collab::ticket::Card;
    use binbun_collab::transport::BoxFuture;
    use binbun_collab::{Notice, Request};
    use binbun_gui_view::collab::{Cursor, Fetching, Place};
    use binbun_gui_view::session::Wake;
    use binbun_session::identity::Identity;
    use binbun_session::journal::{EngineVersion, PublicKey};

    use super::{
        ASKED, Answers, Asked, CURSORS, EVENTS, NetEvent, Queued, approver, channel, notice_event,
        tell,
    };

    /// A wake that counts how often it woke.
    fn counted() -> (Wake, Arc<AtomicUsize>) {
        let wakes = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&wakes);
        let wake: Wake = Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        (wake, wakes)
    }

    /// Key number `n`.
    fn key(n: usize) -> PublicKey {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(n as u64).to_le_bytes());
        PublicKey(key)
    }

    /// Request to join `id`.
    fn asked(id: u64) -> NetEvent {
        NetEvent::Asked(Asked {
            id,
            key: key(1),
            name: "Ann".to_owned(),
            path: "direct".to_owned(),
            engine: EngineVersion::this(),
        })
    }

    /// A fetch `done` bytes of 100 along.
    fn fetching(done: u64) -> NetEvent {
        NetEvent::Fetching(Fetching {
            name: "bash".to_owned(),
            from: key(1),
            debug: false,
            opening: false,
            done,
            total: 100,
        })
    }

    /// `n`'s cursor at `address`.
    fn cursor(n: usize, address: u64) -> NetEvent {
        let at = Cursor {
            place: Place::Listing,
            address,
            column: 0,
            selection: None,
        };
        NetEvent::Cursor(key(n), at)
    }

    #[test]
    fn every_kind_waiting_for_the_window_is_bounded_and_only_a_new_event_wakes_it() {
        let (sender, events) = channel();
        let (wake, wakes) = counted();
        let woken = || wakes.load(Ordering::SeqCst);
        // Status lines past the bound: dropped, and no wake for them.
        for n in 0..EVENTS * 2 {
            tell(&sender, &wake, NetEvent::Said(n.to_string()));
        }
        assert_eq!(woken(), EVENTS);
        // Progress: the last kept, the window woken once.
        for done in 0..100 {
            tell(&sender, &wake, fetching(done));
        }
        assert_eq!(woken(), EVENTS + 1);
        // Cursors: the last of each participant, of [`CURSORS`] at most.
        for n in 0..CURSORS * 2 {
            tell(&sender, &wake, cursor(n, 1));
            assert_ne!(tell(&sender, &wake, cursor(n, 2)), Queued::Added);
        }
        assert_eq!(woken(), EVENTS + 1 + CURSORS);
        // A session's end: the first kept.
        tell(&sender, &wake, NetEvent::Ended("first".to_owned()));
        let second = NetEvent::Ended("second".to_owned());
        assert_eq!(tell(&sender, &wake, second), Queued::Dropped);
        assert_eq!(woken(), EVENTS + 2 + CURSORS);

        let taken = events.take();
        assert_eq!(taken.len(), EVENTS + 2 + CURSORS);
        assert!(matches!(&taken[EVENTS], NetEvent::Fetching(f) if f.done == 99));
        let last = |q: &NetEvent| matches!(q, NetEvent::Cursor(_, at) if at.address == 2);
        assert_eq!(taken.iter().filter(|q| last(q)).count(), CURSORS);
        assert!(matches!(taken.last(), Some(NetEvent::Ended(why)) if why == "first"));
        // Taken: the next is queued anew, and wakes.
        assert_eq!(tell(&sender, &wake, fetching(100)), Queued::Added);
        // The window gone: nothing kept, nothing woken.
        drop(events);
        assert_eq!(tell(&sender, &wake, fetching(100)), Queued::Dropped);
        assert_eq!(woken(), EVENTS + 3 + CURSORS);
    }

    #[test]
    fn a_request_withdrawn_before_the_window_takes_it_leaves_the_queue_without_a_wake() {
        let (sender, events) = channel();
        let (wake, wakes) = counted();
        tell(&sender, &wake, asked(1));
        tell(&sender, &wake, asked(2));
        assert_eq!(tell(&sender, &wake, NetEvent::Withdrawn(1)), Queued::Merged);
        assert_eq!(wakes.load(Ordering::SeqCst), 2);
        let taken = events.take();
        assert!(matches!(taken.as_slice(), [NetEvent::Asked(a)] if a.id == 2));
        // Taken by the window: its withdrawal is told.
        assert_eq!(tell(&sender, &wake, NetEvent::Withdrawn(2)), Queued::Added);
        assert!(matches!(events.take().as_slice(), [NetEvent::Withdrawn(2)]));
    }

    /// A request to join from someone new.
    fn request() -> Request {
        Request {
            card: Card::new(&Identity::ephemeral().unwrap(), "Ann"),
            path: "direct".to_owned(),
            engine: EngineVersion::this(),
        }
    }

    /// What `asked` comes to at once: answered, or still waiting.
    fn at_once<T>(mut asked: BoxFuture<'static, T>) -> Poll<T> {
        asked.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn past_the_requests_waiting_or_with_the_window_gone_one_is_turned_away_unasked() {
        let (sender, events) = channel();
        let (wake, wakes) = counted();
        let answers = Answers::default();
        let approve = approver(sender, wake, Arc::clone(&answers));
        let waiting: Vec<_> = (0..ASKED).map(|_| approve(request())).collect();
        assert!(matches!(at_once(approve(request())), Poll::Ready(None)));
        assert_eq!(events.take().len(), ASKED);
        assert_eq!(wakes.load(Ordering::SeqCst), ASKED);
        // Withdrawn (their askers gone): room for another.
        drop(waiting);
        assert_eq!(events.take().len(), ASKED);
        assert!(matches!(at_once(approve(request())), Poll::Pending));
        // The window gone: asked of no one.
        drop(events);
        assert!(matches!(at_once(approve(request())), Poll::Ready(None)));
    }

    #[test]
    fn a_status_line_holds_what_a_peer_wrote_escaped() {
        let kicked = Notice::Kicked("bye\n[ 1.0] Admitted \u{202e}x".to_owned());
        let NetEvent::Ended(said) = notice_event(&kicked) else {
            panic!("not the end of the session");
        };
        assert_eq!(said, "Put out: bye\\u{a}[ 1.0] Admitted \\u{202e}x");
        let unlinked = Notice::Unlinked {
            peer: key(2),
            why: "gone\r\nLinked to someone".to_owned(),
        };
        let NetEvent::Said(said) = notice_event(&unlinked) else {
            panic!("not a status line");
        };
        assert!(said.ends_with("down: gone\\u{d}\\u{a}Linked to someone"));
    }
}
