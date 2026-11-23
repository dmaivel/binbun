//! A peer's links: a dialler opens the control lane and says hello; the
//! host lets in at once a key the membership chain names a member (the
//! transport proved the key: a card or a ticket proves nothing of it),
//! asks its approver about those holding this share's invite if live
//! approval is on (the owner admits them: a membership record, the epoch
//! key wrapped to them), and turns everyone else away before anyone is
//! asked. Once in, the dialler opens the sync lane, on which the sync
//! machine ([`binbun_sync::Machine`]) runs: Bootstrap (membership records
//! and `Ready` only), then Reader (tips, pulls, forks), the live and blob
//! lanes opening only then.
//!
//! What strangers cost the host is bounded ([`crate::budgets`]): each
//! holds a place in the stranger pool until let in or turned away
//! (members are told apart by their key before they say anything, and
//! never wait for a place), says a hello of
//! [`CONTROL_FRAME`](crate::wire::CONTROL_FRAME) bytes at most, and is
//! told everything it is told by its stage's deadline; requests waiting
//! for the approver are bounded, one per key, each withdrawn when its link
//! closes or the invite is forgotten, and refused once its time is up;
//! each key asks a few times a while, counted past reconnects. Links are
//! bounded per process, each numbered by a generation, which is the
//! machine's link id: a link never takes the place of a newer one to the
//! same peer, and its cleanup never removes its successor.
//!
//! On the sync lane, each frame's length is checked against its phase's
//! limit and its bytes reserved before its body is read; whatever the
//! machine says to write carries the generation it was made for and is
//! written only if the link is still of it when the writer takes it up;
//! a page (changes, records, a change just applied) is built only then,
//! holding a page permit.
//!
//! Each item is written whole within [`DEADLINE`] (a page's from the
//! taking of its permit): building, encoding, the rate's wait and the
//! write itself. A link that does not take it in time is closed, as is
//! one whose other side is revoked meanwhile; either way what was in hand
//! is dropped and its permits given back at once. A page is checked again
//! after the rate's wait, at its use: its link still of its generation
//! and its other side still served, and none of its changes at or past
//! a freeze of their chain made meanwhile (those are left out). Replies
//! to the other side's requests are bounded by [`REQUESTS`] until
//! written: one more closes the link.

use std::fmt;
#[cfg(test)]
use std::sync::PoisonError;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use binbun_bounded::{Bounded, Text};
use binbun_session::journal::PublicKey;
use binbun_sync::envelope::Envelope;
use binbun_sync::machine::{DEADLINE, REQUESTS};
use binbun_sync::wire::{BOOTSTRAP_FRAME, EnvelopeBytes, FRAME};
use binbun_sync::{Job, LinkId, Local, Page, Phase, Send as Outgoing, Sync};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};

use crate::Error;
use crate::budgets::{Asking, Charge, Deadline, FRAMES, LinkBudget, Stranger};
use crate::live::plain_engine;
use crate::membership::{Membership, Role};
use crate::peer::{After, Inner, Notice, Request, State};
use crate::ticket::PeerAddr;
use crate::transport::{
    Lane, Link, RecvStream, SendStream, read_bytes, read_frame, read_frame_length, write_bytes,
    write_frame,
};
use crate::wire::{Answer, Control, Engine, FEATURES, Hello, LOG, PROTOCOL};

/// How long a member has to open a lane or say hello, or a link to
/// close once told why it ends.
const HANDSHAKE: Duration = Duration::from_secs(30);

/// How long a joiner waits to dial again after its link is lost.
const REDIAL: Duration = Duration::from_secs(2);

/// A lane's streams.
type Streams = (SendStream, RecvStream);

/// How a synced link ended.
pub(crate) enum Ended {
    /// Put out by the host.
    Kicked(String),
    /// Lost, or closed.
    Lost(String),
    /// Not to sync: the chain names another binary than the session's.
    Refused(String),
}

/// Whom a peer dials: a host.
#[derive(Clone)]
pub(crate) struct Dial {
    /// Where it is reached.
    pub(crate) addr: PeerAddr,
    /// The ticket's invite.
    pub(crate) invite: [u8; 16],
}

/// Without the invite: debug output carries no way in.
impl fmt::Debug for Dial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dial")
            .field("addr", &self.addr)
            .field("invite", &"…")
            .finish()
    }
}

/// What the host makes of a hello.
enum Verdict {
    /// A member: in at once, as this.
    Member(Role),
    /// Holding this share's invite, with live approval on: the approver
    /// decides.
    Ask,
    /// Turned away, and why.
    Deny(String),
}

/// What a link's sync lane writes next.
pub(crate) enum Out {
    /// A message the machine made.
    Send(Outgoing),
    /// A page to build once a page permit is held.
    Job(Job),
}

/// The most items a link's sync lane holds unwritten (messages and jobs).
const OUT_QUEUE: usize = 4096;

/// What each item in a link's sync queue is charged besides its bytes: its
/// place in the queue.
const OUT_ITEM: usize = 64;

/// An item of a link's sync queue, with its charge of the link's
/// `sync.link` (and, a reply's, its place among [`REQUESTS`]) held until
/// it is written or dropped.
enum Queued {
    /// A message, encoded, for the generation it was made for.
    Send {
        generation: u64,
        bytes: Vec<u8>,
        _charge: Charge,
        _reply: Option<OwnedSemaphorePermit>,
    },
    /// A page to build.
    Job {
        job: Job,
        _charge: Charge,
        _reply: Option<OwnedSemaphorePermit>,
    },
}

/// What a link's sync lane writes, bounded (audit 4, H6): at most
/// [`OUT_QUEUE`] items, each message's bytes (and every item's place)
/// charged to the link's `sync.link` until written, so that the link's
/// ceiling and the process's hold for what waits to be written, a reply
/// made at once (a `HeadsRun`) as much as any. A link whose queue is full
/// or whose charge is refused (its other side not reading) is closed, the
/// item dropped. So is one whose other side has more than [`REQUESTS`]
/// requests unanswered: a reply, made at once or a page to build, holds
/// one of the link's places until its last byte is written (sync §3.1,
/// I12: an honest side has no more out, a reply counting against it
/// until read).
pub(crate) struct Outbox {
    queue: mpsc::Sender<Queued>,
    budget: Arc<LinkBudget>,
    link: Arc<dyn Link>,
    closed: Arc<OnceLock<String>>,
    /// The places of replies not yet written ([`REQUESTS`]).
    replies: Arc<Semaphore>,
    /// Told when the link is closed or revoked: the writer drops what it
    /// has in hand.
    stop: Arc<Notify>,
}

impl Outbox {
    /// The outbox of `link` (of `budget`) writing to `queue`, `closed`
    /// set when this side closes it.
    fn new(
        queue: mpsc::Sender<Queued>,
        budget: Arc<LinkBudget>,
        link: Arc<dyn Link>,
        closed: Arc<OnceLock<String>>,
    ) -> Self {
        Self {
            queue,
            budget,
            link,
            closed,
            replies: Arc::new(Semaphore::new(REQUESTS)),
            stop: Arc::new(Notify::new()),
        }
    }

    /// Puts `out` in the queue (a message encoded now); whether it is
    /// there. Not if the link is closed for it.
    pub(crate) fn send(&self, out: Out) -> bool {
        let reply = match &out {
            Out::Send(send) => send.message.reply().is_some(),
            Out::Job(job) => matches!(job.page, Page::Changes { .. } | Page::Records { .. }),
        };
        let reply = if reply {
            let Ok(place) = Arc::clone(&self.replies).try_acquire_owned() else {
                self.close("more requests outstanding than allowed");
                return false;
            };
            Some(place)
        } else {
            None
        };
        let queued = match out {
            Out::Send(send) => {
                let Ok(bytes) = send.message.encode() else {
                    self.close("a message past its bounds");
                    return false;
                };
                let Some(charge) = self.budget.charge(bytes.len().saturating_add(OUT_ITEM)) else {
                    self.close("not reading what it is sent");
                    return false;
                };
                Queued::Send {
                    generation: send.generation,
                    bytes,
                    _charge: charge,
                    _reply: reply,
                }
            }
            Out::Job(job) => {
                let Some(charge) = self.budget.charge(OUT_ITEM) else {
                    self.close("not reading what it is sent");
                    return false;
                };
                Queued::Job {
                    job,
                    _charge: charge,
                    _reply: reply,
                }
            }
        };
        match self.queue.try_send(queued) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.close("not reading what it is sent");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Closes the link, saying `why`.
    fn close(&self, why: &str) {
        let _ = self.closed.set(why.to_owned());
        self.stop();
        self.link.close(why);
    }

    /// Stops the writer: what it has in hand is dropped, its permits
    /// given back, and nothing more is written (the link closed or
    /// revoked).
    pub(crate) fn stop(&self) {
        self.stop.notify_one();
    }
}

/// One link's state.
pub(crate) struct LinkState {
    pub(crate) link: Arc<dyn Link>,
    /// Its place and ceilings.
    pub(crate) budget: Arc<LinkBudget>,
    /// Its id in the sync machine: its generation.
    pub(crate) id: LinkId,
    /// What its sync lane writes.
    pub(crate) out: Outbox,
    /// The one message for its control lane (a kick).
    pub(crate) control: mpsc::Sender<Control>,
    /// Why the peer is view-only in this session (another build), if it
    /// is: its changes of another build are not taken while it is linked.
    pub(crate) view_only: Option<String>,
    /// Whether it is a reader's: its live and blob lanes open.
    pub(crate) reader: watch::Sender<bool>,
    /// Why this side closed it, if it did.
    pub(crate) closed: Arc<OnceLock<String>>,
}

impl LinkState {
    /// Whether it is a reader's.
    pub(crate) fn is_reader(&self) -> bool {
        *self.reader.borrow()
    }
}

/// The kick for `removed`, saying `why`: a page of `membership`'s
/// records after `theirs`, the head they say they hold if this chain
/// holds that record there (else after none), through their removal and
/// none after it (sync §3.6): what they learn is that they were removed,
/// not who came or went since.
pub(crate) fn kick(
    membership: &Membership,
    removed: PublicKey,
    theirs: (u64, [u8; 32]),
    why: &str,
) -> Control {
    let (seq, hash) = theirs;
    let from = if membership.record_hash(seq) == Some(hash) {
        seq
    } else {
        0
    };
    let through = membership.removal(removed).unwrap_or(0);
    let count = usize::try_from(through.saturating_sub(from)).unwrap_or(usize::MAX);
    let records = membership.since(from);
    Control::kick(why, records.get(..count).unwrap_or(records))
}

impl Inner {
    /// Accepts links until the transport closes, each on a task of the
    /// process's: a stranger (no member) only with a place in the
    /// stranger pool, the one the transport took for its handshake if it
    /// took one ([`Link::stranger`]), so one place is held from the
    /// accepting of the connection through the admission decision.
    pub(crate) async fn accept_links(self: Arc<Self>) {
        while let Some(link) = self.transport.accept().await {
            let handshaken = link.stranger();
            let Some(task) = self.budgets.task() else {
                link.close("too busy: dial again later");
                continue;
            };
            if self.state().recovery.is_some() {
                link.close("recovering its membership chain: dial again later");
                continue;
            }
            let member = self.state().membership.role(link.remote()).is_some();
            let stranger = if member {
                None
            } else if let Some(mut stranger) = handshaken {
                stranger.next_stage();
                Some(stranger)
            } else if let Some(stranger) = self.budgets.stranger() {
                Some(stranger)
            } else {
                link.close("too many waiting to be let in: dial again later");
                continue;
            };
            let inner = Arc::clone(&self);
            self.spawn(async move {
                let _task = task;
                inner.incoming(link, stranger).await;
            });
        }
    }

    /// One dialler: heard, let in, asked about or turned away; then
    /// synced. A stranger holds `stranger` until let in or turned away,
    /// everything said to them said by its deadline.
    async fn incoming(self: Arc<Self>, link: Arc<dyn Link>, mut stranger: Option<Stranger>) {
        let remote = link.remote();
        let by = |stranger: &Option<Stranger>| {
            stranger
                .as_ref()
                .map_or_else(|| Deadline::after(HANDSHAKE), Stranger::deadline)
        };
        let hello_by = by(&stranger);
        let hello = async {
            let (lane, send, mut recv) = link.accept().await?;
            if lane != Lane::Control {
                return Err(Error::new("a link not opened with its control lane"));
            }
            match read_frame::<Control>(&mut *recv).await? {
                Some(Control::Hello(hello)) => Ok((send, recv, *hello)),
                Some(
                    Control::Pending
                    | Control::Welcome { .. }
                    | Control::Denied { .. }
                    | Control::Kick { .. },
                )
                | None => Err(Error::new("no hello")),
            }
        };
        let (mut send, recv, hello) = match hello_by.within(hello).await {
            Ok(Ok(heard)) => heard,
            Ok(Err(error)) => return self.turn(&link, None, &error.to_string()).await,
            Err(_) => return self.turn(&link, None, "no hello in time").await,
        };
        let view_only = self.view_only(&hello.engine);
        let verdict = self.verdict(&self.state(), remote, &hello);
        let role = match verdict {
            Verdict::Member(role) => role,
            Verdict::Deny(why) if self.state().membership.removed(remote) => {
                return self
                    .kick_removed(&link, send, hello_by, &why, hello.membership)
                    .await;
            }
            Verdict::Deny(why) => return self.turn(&link, Some((send, hello_by)), &why).await,
            Verdict::Ask => {
                let Some(waiting) = stranger.as_mut() else {
                    let why = "no place to wait to be let in";
                    return self.turn(&link, Some((send, hello_by)), why).await;
                };
                let asking = match self.budgets.ask(waiting, remote) {
                    Ok(asking) => asking,
                    Err(refused) => {
                        let why = refused.to_string();
                        return self.turn(&link, Some((send, hello_by)), &why).await;
                    }
                };
                let asked_by = waiting.deadline();
                let pending = asked_by.within(write_frame(&mut *send, &Control::Pending));
                if !matches!(pending.await, Ok(Ok(()))) {
                    return;
                }
                match self.ask(&link, &hello, asking).await {
                    Ok(role) => role,
                    Err(why) => return self.turn(&link, Some((send, asked_by)), &why).await,
                }
            }
        };
        let welcome = Control::Welcome {
            role,
            view_only: view_only.as_deref().map(Text::truncated),
            features: FEATURES,
        };
        let welcomed = by(&stranger).within(write_frame(&mut *send, &welcome));
        if !matches!(welcomed.await, Ok(Ok(()))) {
            return;
        }
        drop(stranger);
        let sync = async {
            match link.accept().await? {
                (Lane::Sync, send, recv) => Ok((send, recv)),
                (Lane::Control | Lane::Live | Lane::Blob, ..) => Err(Error::new("no sync lane")),
            }
        };
        match tokio::time::timeout(HANDSHAKE, sync).await {
            Ok(Ok(sync)) => {
                let (Ended::Kicked(why) | Ended::Lost(why) | Ended::Refused(why)) =
                    Arc::clone(&self)
                        .synced(&link, (send, recv), sync, view_only, true)
                        .await;
                self.tell(&Notice::Unlinked { peer: remote, why });
            }
            Ok(Err(error)) => link.close(&error.to_string()),
            Err(_) => link.close("no sync lane in time"),
        }
    }

    /// Puts out `link`'s removed member, saying why (`why`) with the
    /// membership records after the head it holds, `theirs`, through its
    /// removal ([`kick`]), on its control lane `send` by `by`: taking them
    /// takes what it wrote past its cut out of its projection on its side
    /// too (sync §4.5).
    async fn kick_removed(
        &self,
        link: &Arc<dyn Link>,
        mut send: SendStream,
        by: Deadline,
        why: &str,
        theirs: (u64, [u8; 32]),
    ) {
        let kick = Answer(kick(&self.state().membership, link.remote(), theirs, why));
        let said = async {
            if write_frame(&mut *send, &kick).await.is_ok() {
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut send).await;
                // Let the dialler read it and close first.
                link.closed().await;
            }
        };
        let _ = by.within(said).await;
        self.turn(link, None, why).await;
    }

    /// Turns `link` away, saying why on its control lane if open (`reply`)
    /// by the deadline given with it.
    async fn turn(&self, link: &Arc<dyn Link>, reply: Option<(SendStream, Deadline)>, why: &str) {
        self.tell(&Notice::Turned {
            peer: link.remote(),
            why: why.to_owned(),
        });
        if let Some((mut send, by)) = reply {
            let denied = Control::Denied {
                reason: Text::truncated(why),
            };
            let said = async {
                if write_frame(&mut *send, &denied).await.is_ok() {
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut send).await;
                    // Let the dialler read it and close first.
                    link.closed().await;
                }
            };
            let _ = by.within(said).await;
        }
        link.close(why);
    }

    /// Why a peer running `engine` is view-only here, if it is: it runs
    /// another release or build than this peer.
    fn view_only(&self, engine: &Engine) -> Option<String> {
        (*engine != Engine::of(&self.engine)).then(|| {
            format!(
                "it runs binbun {} (build {}), the host {} (build {}): a peer on another build \
                 is view-only, its changes not taken while it is linked here",
                engine.release, engine.build, self.engine.release, self.engine.build
            )
        })
    }

    /// What to make of `hello` from `remote`, as `state` stands.
    fn verdict(&self, state: &State, remote: PublicKey, hello: &Hello) -> Verdict {
        let Hello {
            protocol,
            log,
            project,
            invite,
            card,
            ..
        } = hello;
        if *log != LOG {
            return Verdict::Deny(format!(
                "this host keeps change log {LOG}, and you log {log}: another log major cannot \
                 join; run a binbun of log {LOG}"
            ));
        }
        if *protocol != PROTOCOL {
            return Verdict::Deny(format!(
                "this host speaks protocol {PROTOCOL}, and you {protocol}: run a binbun of \
                 protocol {PROTOCOL}"
            ));
        }
        if *project != state.membership.project() {
            return Verdict::Deny("this host shares another project".to_owned());
        }
        if card.key != remote || !card.verifies() {
            return Verdict::Deny("an identity card not of the key that dialled".to_owned());
        }
        if !plain_engine(&hello.engine) {
            return Verdict::Deny("a binbun release or build that is not plain text".to_owned());
        }
        if state.membership.removed(remote) {
            return Verdict::Deny("removed from the project".to_owned());
        }
        match state.membership.role(remote) {
            Some(Role::Store) => {
                return Verdict::Deny(
                    "a member of role store: this binbun links with none".to_owned(),
                );
            }
            Some(role) => return Verdict::Member(role),
            None => {}
        }
        if self.approve.is_none() {
            return Verdict::Deny(
                "not a member of this project: its owner adds you by your identity card (binbun \
                 id), then you join"
                    .to_owned(),
            );
        }
        if state.invite.is_none() || *invite != state.invite {
            return Verdict::Deny("not invited: the ticket is not this share's".to_owned());
        }
        if state.membership.signer() != self.me {
            return Verdict::Deny("only the project's owner admits members".to_owned());
        }
        Verdict::Ask
    }

    /// Asks the approver about the dialler of `link` (`hello`), their
    /// request listed (`asking`) until answered, and admits them as the
    /// role it gives: withdrawn if their link closes or the invite is
    /// forgotten first, refused if not answered by its time
    /// ([`Asking::answer_by`]); checked again as the record is signed
    /// (the invite still this share's, they no member, nor removed,
    /// since).
    async fn ask(
        self: &Arc<Self>,
        link: &Arc<dyn Link>,
        hello: &Hello,
        asking: Asking,
    ) -> Result<Role, String> {
        let Some(approve) = self.approve.clone() else {
            return Err("this host admits no one".to_owned());
        };
        let remote = link.remote();
        let request = Request {
            card: hello.card.clone(),
            path: link.path(),
            engine: hello.engine.version(),
        };
        // Subscribed before the invite is looked at: forgotten after,
        // it is told.
        let mut uninvited = self.uninvited.subscribe();
        let invited = async {
            loop {
                let invite = self.state().invite;
                if invite != hello.invite {
                    return;
                }
                if uninvited.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        };
        let role = tokio::select! {
            role = approve(request) => role.ok_or_else(|| "refused by the host".to_owned())?,
            () = link.closed() => return Err("gone before the host answered".to_owned()),
            () = invited => {
                return Err("the invite was withdrawn before the host answered".to_owned());
            }
            () = asking.answer_by().passed() => {
                return Err("not answered in time: ask again later".to_owned());
            }
        };
        let state = self.state();
        match self.verdict(&state, remote, hello) {
            Verdict::Ask => {}
            Verdict::Member(role) => return Ok(role),
            Verdict::Deny(why) => return Err(why),
        }
        self.admit_in(state, &hello.card, role)
            .map_err(|error| error.to_string())?;
        Ok(role)
    }

    /// Dials the host of `to` until refused, again whenever the link is
    /// lost.
    pub(crate) async fn dial(self: Arc<Self>, to: Dial) {
        let host = to.addr.id;
        loop {
            match Arc::clone(&self).visit(&to).await {
                Ok(Ended::Kicked(why)) => self.tell(&Notice::Kicked(why)),
                Ok(Ended::Lost(why)) => self.tell(&Notice::Unlinked { peer: host, why }),
                Ok(Ended::Refused(why)) | Err(Refusal::Denied(why)) => {
                    self.tell(&Notice::Denied(why));
                    return;
                }
                Err(Refusal::Failed(error)) => self.tell(&Notice::Unlinked {
                    peer: host,
                    why: error.to_string(),
                }),
            }
            tokio::time::sleep(REDIAL).await;
        }
    }

    /// One visit to the host of `to`: dialled, let in, synced until the
    /// link ends. None while the share is in recovery.
    async fn visit(self: Arc<Self>, to: &Dial) -> Result<Ended, Refusal> {
        if !self.recovered(&mut self.state()) {
            return Err(Refusal::Failed(Error::new(
                "recovering the membership chain: a record is not written whole",
            )));
        }
        let link = self.transport.connect(&to.addr).await?;
        if link.remote() != to.addr.id {
            link.close("not the host");
            return Err(Refusal::Failed(Error::new(
                "the host's key is not the ticket's",
            )));
        }
        let (mut send, mut recv) = link.open(Lane::Control).await?;
        let (project, membership) = {
            let state = self.state();
            (state.membership.project(), state.membership.head())
        };
        let hello = Control::Hello(Box::new(Hello {
            protocol: PROTOCOL,
            log: LOG,
            engine: Engine::of(&self.engine),
            project,
            invite: Some(to.invite),
            card: self.card.clone(),
            membership,
            features: FEATURES,
        }));
        write_frame(&mut *send, &hello).await?;
        loop {
            match read_frame::<Answer>(&mut *recv)
                .await?
                .map(|Answer(answer)| answer)
            {
                Some(Control::Pending) => self.tell(&Notice::Waiting),
                Some(Control::Welcome { view_only, .. }) => {
                    let view_only = view_only.map(Text::into_string);
                    self.state().view_only.clone_from(&view_only);
                    if let Some(why) = view_only {
                        self.tell(&Notice::ViewOnly(why));
                    }
                    break;
                }
                Some(Control::Denied { reason }) => {
                    link.close("denied");
                    return Err(Refusal::Denied(reason.into_string()));
                }
                Some(Control::Kick { reason, records }) => {
                    self.take_kick(&records.items);
                    link.close("kicked");
                    return Ok(Ended::Kicked(reason.into_string()));
                }
                Some(Control::Hello(_)) | None => {
                    link.close("no answer");
                    return Err(Refusal::Failed(Error::new("the host did not answer")));
                }
            }
        }
        let sync = link.open(Lane::Sync).await?;
        Ok(self.synced(&link, (send, recv), sync, None, false).await)
    }

    /// Syncs over `link` until it ends: the sync machine runs on its sync
    /// lane, the live and blob lanes beside it once it is a reader's. The
    /// peer's changes of another build are not taken while it is linked
    /// if it is `view_only` (why). A chain that comes naming another
    /// binary than the session's ends it. The link holds a place among
    /// the process's links while it lasts; none free, it ends. This side
    /// `hosts` it if the other dialled.
    async fn synced(
        self: Arc<Self>,
        link: &Arc<dyn Link>,
        control: Streams,
        sync: Streams,
        view_only: Option<String>,
        hosts: bool,
    ) -> Ended {
        let remote = link.remote();
        let Some(budget) = self.budgets.link(remote) else {
            link.close("too many links: dial again later");
            return Ended::Lost("too many links".to_owned());
        };
        let budget = Arc::new(budget);
        let id = LinkId(budget.generation());
        let (out, mut queue) = mpsc::channel(OUT_QUEUE);
        let (control_out, mut control_queue) = mpsc::channel(1);
        let (reader, reader_up) = watch::channel(false);
        let closed = Arc::new(OnceLock::new());
        let out = Outbox::new(
            out,
            Arc::clone(&budget),
            Arc::clone(link),
            Arc::clone(&closed),
        );
        let stop = Arc::clone(&out.stop);
        let linked = LinkState {
            link: Arc::clone(link),
            budget: Arc::clone(&budget),
            id,
            out,
            control: control_out,
            view_only: view_only.clone(),
            reader,
            closed: Arc::clone(&closed),
        };
        #[cfg(test)]
        self.held_linking().await;
        if let Err(ended) = self.link_up(linked, hosts) {
            link.close(match ended {
                Ended::Refused(_) => "another binary",
                Ended::Kicked(_) | Ended::Lost(_) => "not linked",
            });
            return ended;
        }
        let role = self.state().membership.role(remote);
        self.tell(&Notice::Linked {
            peer: remote,
            role,
            path: link.path(),
            view_only,
        });
        let (mut control_send, mut control_recv) = control;
        let (sync_send, sync_recv) = sync;
        let writer = self.write_sync(remote, id, &budget, (&mut queue, &stop), sync_send);
        let reader = self.read_sync(remote, id, sync_recv);
        let kicker = async {
            // A word for the peer (a kick) or, with no word, the link put
            // out of this peer's links (replaced, or the peer closing).
            if let Some(message) = control_queue.recv().await {
                let _ = write_frame(&mut *control_send, &Answer(message)).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut control_send).await;
                let _ = tokio::time::timeout(HANDSHAKE, link.closed()).await;
            }
        };
        let told = async {
            loop {
                match read_frame::<Answer>(&mut *control_recv).await {
                    Ok(Some(Answer(Control::Kick { reason, records }))) => {
                        self.take_kick(&records.items);
                        return Ended::Kicked(reason.into_string());
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => std::future::pending::<()>().await,
                    Err(error) => return Ended::Lost(error.to_string()),
                }
            }
        };
        let lanes = Arc::clone(&self).live(Arc::clone(link), Arc::clone(&budget), reader_up);
        let ended = tokio::select! {
            result = writer => Ended::Lost(result.err().map_or_else(|| "closed".to_owned(), |e| e.to_string())),
            result = reader => match result {
                Ok(Some(why)) => Ended::Refused(why),
                Ok(None) => Ended::Lost("closed".to_owned()),
                Err(error) => Ended::Lost(error.to_string()),
            },
            () = kicker => Ended::Lost("put out of this peer's links".to_owned()),
            ended = told => ended,
            () = lanes => Ended::Lost("the live session ended".to_owned()),
            () = link.closed() => Ended::Lost(closed.get().map_or_else(
                || "the link closed".to_owned(),
                |why| format!("the link closed: {why}"),
            )),
        };
        link.close(match ended {
            Ended::Refused(_) => "another binary",
            Ended::Kicked(_) | Ended::Lost(_) => "done",
        });
        self.link_down(remote, id);
        ended
    }

    /// Writes what the machine says to link `id` (to `remote`, of
    /// `budget`) on its sync lane, `send`, from `queue`: each message if
    /// the link is still of the generation it was made for, each page
    /// built once a page permit is held, the permit kept until its bytes
    /// are written (the rate's wait included), as each item's charge is.
    /// Told to `stop` (the link closed or revoked), it drops what it has
    /// in hand and writes nothing more. Ends only with an error (an item
    /// not written within [`DEADLINE`] among them): the queue closes with
    /// the link.
    async fn write_sync(
        &self,
        remote: PublicKey,
        id: LinkId,
        budget: &LinkBudget,
        (queue, stop): (&mut mpsc::Receiver<Queued>, &Notify),
        mut send: SendStream,
    ) -> Result<(), Error> {
        while let Some(item) = queue.recv().await {
            let written = tokio::select! {
                written = self.write_item(remote, id, budget, item, &mut send) => Some(written),
                () = stop.notified() => None,
            };
            match written {
                Some(written) => written?,
                None => break,
            }
        }
        std::future::pending().await
    }

    /// Writes `item` of link `id` (to `remote`, of `budget`) on `send`,
    /// whole within [`DEADLINE`]: a message from the moment it is taken
    /// up, a page from the taking of its permit. Its charge, its place
    /// among the replies and its page permit are given back when it is
    /// written or dropped.
    async fn write_item(
        &self,
        remote: PublicKey,
        id: LinkId,
        budget: &LinkBudget,
        item: Queued,
        send: &mut SendStream,
    ) -> Result<(), Error> {
        match item {
            Queued::Send {
                generation, bytes, ..
            } => {
                if !self.current(id, generation) {
                    return Ok(());
                }
                in_time(async {
                    self.rate(remote, bytes.len()).await;
                    write_bytes(&mut **send, &bytes).await?;
                    Ok(())
                })
                .await
            }
            Queued::Job { job, .. } => {
                let permit = match job.page {
                    Page::Records { .. } => self.records.records_page().await,
                    Page::Changes { .. } | Page::Fresh { .. } => budget.page().await,
                };
                let Some(_permit) = permit else {
                    return Ok(());
                };
                in_time(async {
                    let Some(page) = self.serve_job(&job) else {
                        return Ok(());
                    };
                    let bytes = page.message.encode()?;
                    self.rate(remote, bytes.len()).await;
                    let Some(bytes) = self.at_use(remote, &job, page.message, bytes)? else {
                        return Ok(());
                    };
                    write_bytes(&mut **send, &bytes).await?;
                    Ok(())
                })
                .await
            }
        }
    }

    /// Waits until `bytes` to `remote` are within its rate
    /// ([`crate::budgets::SYNC_BYTES`]), and takes them from it.
    async fn rate(&self, remote: PublicKey, bytes: usize) {
        loop {
            let wait = self.budgets.sync_out(remote, bytes);
            if wait.is_zero() {
                return;
            }
            tokio::time::sleep(wait).await;
        }
    }

    /// What of `message` (built for `job`, to `remote`, encoded as
    /// `bytes`) may still be written, checked at its use (sync §3.6):
    /// nothing if its link is no longer of the job's generation or its
    /// other side no longer served; changes at or past their chain's
    /// freeze left out (a cut or a fork proof taken while the page waited
    /// for its rate), and a page of changes left with none of them
    /// dropped if it was pushed.
    fn at_use(
        &self,
        remote: PublicKey,
        job: &Job,
        message: Sync,
        bytes: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Error> {
        if !self.current(job.link, job.generation) || self.serving(remote, job.link).is_none() {
            return Ok(None);
        }
        let session = self.session();
        // The envelopes before the first at or past its chain's freeze.
        let unfrozen = |envelopes: &[EnvelopeBytes]| {
            envelopes
                .iter()
                .take_while(|envelope| {
                    Envelope::parse(envelope).is_some_and(|envelope| {
                        session
                            .frozen_from(envelope.chain())
                            .is_none_or(|from| envelope.seq() < from)
                    })
                })
                .count()
        };
        let message = if let Sync::Changes {
            id, chain, changes, ..
        } = message
        {
            let kept = unfrozen(&changes);
            if kept == changes.len() {
                return Ok(Some(bytes));
            }
            Sync::Changes {
                id,
                chain,
                changes: Bounded::truncated(changes.iter().take(kept).cloned().collect()),
                more: false,
            }
        } else if let Sync::Fresh { changes } = message {
            let kept = unfrozen(&changes);
            if kept == changes.len() {
                return Ok(Some(bytes));
            }
            if kept == 0 {
                return Ok(None);
            }
            Sync::Fresh {
                changes: Bounded::truncated(changes.iter().take(kept).cloned().collect()),
            }
        } else {
            return Ok(Some(bytes));
        };
        Ok(Some(message.encode()?))
    }

    /// Reads link `id`'s sync lane (from `remote`), `recv`, into the
    /// machine: each frame's length checked against its phase's limit and
    /// its bytes reserved before its body is read, within the deadline.
    /// Why it ends: the lane's end, or the chain naming another binary.
    async fn read_sync(
        self: &Arc<Self>,
        remote: PublicKey,
        id: LinkId,
        mut recv: RecvStream,
    ) -> Result<Option<String>, Error> {
        loop {
            let bootstrap = self.phase(id) == Some(Phase::Bootstrap);
            let limit = if bootstrap { BOOTSTRAP_FRAME } else { FRAME };
            let Some(length) = read_frame_length(&mut *recv, limit).await? else {
                return Ok(None);
            };
            // A page of changes holds, while it is taken, its opened and
            // decoded forms beside it.
            let reserve = if bootstrap {
                length
            } else {
                length.saturating_mul(3).min(FRAMES)
            };
            let Some(_frame) = self.budgets.frame(reserve).await else {
                return Err(Error::new("a frame past the frames' ceiling"));
            };
            let bytes = tokio::time::timeout(DEADLINE, read_bytes(&mut *recv, length))
                .await
                .map_err(|_| Error::new("a frame's body not read in time"))??;
            let wait = self.budgets.sync_in(remote, length);
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            self.drive(|machine, view, charges, now| {
                machine.on_message(view, charges, now, id, &bytes)
            });
            self.tell_took();
            if let Some(why) = self.state().foreign.clone() {
                return Ok(Some(why));
            }
        }
    }

    /// Puts `linked` among this peer's links in place of an older one to
    /// the same peer, and tells the machine, in one hold. Not if the chain
    /// names another binary ([`Ended::Refused`]), the share is in
    /// recovery, a newer link to the peer is up, or the chain, read again
    /// in this hold, no longer lets the peer in: removed, or, if this side
    /// `hosts` the link, not a member ([`Ended::Lost`]).
    fn link_up(self: &Arc<Self>, linked: LinkState, hosts: bool) -> Result<(), Ended> {
        let remote = linked.link.remote();
        let id = linked.id;
        let mut driver = self.driver();
        let mut state = self.state();
        if let Some(why) = state.foreign.clone() {
            return Err(Ended::Refused(why));
        }
        if state.recovery.is_some() {
            return Err(Ended::Lost(
                "recovering the membership chain: a record is not written whole".to_owned(),
            ));
        }
        let member = state
            .membership
            .role(remote)
            .is_some_and(|role| role != Role::Store);
        if state.membership.removed(remote) || (hosts && !member) {
            return Err(Ended::Lost("no longer a member".to_owned()));
        }
        if state
            .links
            .get(&remote)
            .is_some_and(|newer| newer.budget.generation() > linked.budget.generation())
        {
            return Err(Ended::Lost("a newer link to the peer is up".to_owned()));
        }
        self.judge.set_view_only(remote, linked.view_only.is_some());
        driver.budgets.insert(linked.id, Arc::clone(&linked.budget));
        if let Some(old) = state.links.insert(remote, linked) {
            old.link.close("linked again");
        }
        let mut after = After::default();
        self.drive_held(
            &mut driver,
            &mut state,
            |machine, view, charges, now| {
                machine.on_local(view, charges, now, Local::Linked { link: id, remote })
            },
            &mut after,
        );
        drop((driver, state));
        self.finish(&after);
        Ok(())
    }

    /// Holds a link coming up where a test set it to
    /// ([`Inner::linking`]): says it got there, then waits for the word.
    #[cfg(test)]
    async fn held_linking(&self) {
        let gate = self
            .linking
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some((reached, go)) = gate {
            let _ = reached.send(());
            let _ = go.await;
        }
    }

    /// Takes link `id` to `remote` out: the machine told, its budget
    /// dropped, and its place among the links if it still holds it.
    fn link_down(self: &Arc<Self>, remote: PublicKey, id: LinkId) {
        self.drive(|machine, view, charges, now| {
            machine.on_local(view, charges, now, Local::Unlinked(id))
        });
        let mut driver = self.driver();
        driver.budgets.remove(&id);
        let mut state = self.state();
        if state.links.get(&remote).is_some_and(|known| known.id == id) {
            state.links.remove(&remote);
            self.judge.set_view_only(remote, false);
        }
        self.readers_changed(&state);
    }
}

/// Why a visit to the host failed.
enum Refusal {
    /// The host refused: final.
    Denied(String),
    /// The link failed: to dial again.
    Failed(Error),
}

impl From<Error> for Refusal {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// `write` (a link's item, sync lane), done within [`DEADLINE`]; an error
/// if not, which closes the link.
async fn in_time(write: impl Future<Output = Result<(), Error>>) -> Result<(), Error> {
    tokio::time::timeout(DEADLINE, write)
        .await
        .map_err(|_| Error::new("a write not finished in time"))?
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::{env, fs};

    use binbun_bounded::Bounded;
    use binbun_session::identity::Identity;
    use binbun_session::journal::{ChainId, ChangeHash, ChangeId, EngineVersion, ProjectId, Tip};
    use binbun_session::{Options, Session, Stage};
    use binbun_sync::budget::PER_CHAIN;
    use binbun_sync::{Report, Sync};
    use tokio::sync::oneshot;

    use super::*;
    use crate::budgets::{Budgets, SYNC_LINK, SYNC_LINK_BASE, SYNC_LINK_PER_LINK};
    use crate::mem::MemNet;
    use crate::ticket::Card;
    use crate::transport::{BoxFuture, Transport as _};
    use crate::{Config, Peer};

    /// A link whose other side reads nothing; why it was closed, if it
    /// was.
    struct Deaf {
        remote: PublicKey,
        closed: Mutex<Option<String>>,
    }

    impl Link for Deaf {
        fn remote(&self) -> PublicKey {
            self.remote
        }

        fn open(&self, _: Lane) -> BoxFuture<'_, Result<(SendStream, RecvStream), Error>> {
            Box::pin(std::future::pending())
        }

        fn accept(&self) -> BoxFuture<'_, Result<(Lane, SendStream, RecvStream), Error>> {
            Box::pin(std::future::pending())
        }

        fn path(&self) -> String {
            "deaf".to_owned()
        }

        fn close(&self, reason: &str) {
            *self.closed.lock().unwrap() = Some(reason.to_owned());
        }

        fn closed(&self) -> BoxFuture<'_, ()> {
            Box::pin(std::future::pending())
        }

        fn send_datagram(&self, _: Vec<u8>) -> Result<(), Error> {
            Err(Error::new("deaf"))
        }

        fn recv_datagram(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
            Box::pin(std::future::pending())
        }
    }

    /// A link of `budgets` to the peer of key `seed`, whose other side
    /// reads nothing: its outbox, its queue (never read), and the link.
    fn deaf(budgets: &Budgets, seed: u8) -> (Outbox, mpsc::Receiver<Queued>, Arc<Deaf>) {
        let remote = PublicKey([seed; 32]);
        let link = Arc::new(Deaf {
            remote,
            closed: Mutex::new(None),
        });
        let (queue, queued) = mpsc::channel(OUT_QUEUE);
        let outbox = Outbox::new(
            queue,
            Arc::new(budgets.link(remote).unwrap()),
            Arc::clone(&link) as Arc<dyn Link>,
            Arc::new(OnceLock::new()),
        );
        (outbox, queued, link)
    }

    /// A change pushed (no reply: replies are bounded apart, by their
    /// count), 40 kB, as a message to write.
    fn page() -> Out {
        let envelope = EnvelopeBytes::try_from(vec![0; 40_000]).unwrap();
        Out::Send(Outgoing {
            link: LinkId(0),
            generation: 0,
            message: Sync::Fresh {
                changes: Bounded::truncated(vec![envelope]),
            },
        })
    }

    /// The bytes `queued` holds charged, and how many items.
    fn held(queued: &mut mpsc::Receiver<Queued>) -> (usize, usize) {
        let (mut bytes, mut items) = (0, 0);
        while let Ok(item) = queued.try_recv() {
            items += 1;
            bytes += OUT_ITEM;
            if let Queued::Send { bytes: written, .. } = item {
                bytes += written.len();
            }
        }
        (bytes, items)
    }

    #[tokio::test]
    async fn links_that_stop_reading_hold_their_bounds_and_the_process_its_own() {
        let budgets = Budgets::default();
        let mut links: Vec<_> = (0..16).map(|seed| deaf(&budgets, seed)).collect();
        for (outbox, _, _) in &links {
            let mut sent = 0;
            while outbox.send(page()) {
                sent += 1;
            }
            assert!(sent < OUT_QUEUE, "{sent}");
        }
        let mut total = 0;
        for (_, queued, link) in &mut links {
            // Closed once it could hold no more.
            assert_eq!(
                link.closed.lock().unwrap().as_deref(),
                Some("not reading what it is sent")
            );
            let (bytes, _) = held(queued);
            assert!(bytes <= SYNC_LINK_PER_LINK - SYNC_LINK_BASE, "{bytes}");
            total += bytes + SYNC_LINK_BASE;
        }
        assert!(total <= SYNC_LINK, "{total}");
        // The process's ceiling, not each link's, stopped the later ones.
        assert!(total > SYNC_LINK - SYNC_LINK_PER_LINK, "{total}");
    }

    #[tokio::test]
    async fn a_queue_of_jobs_is_bounded_by_its_count() {
        let budgets = Budgets::default();
        let (outbox, mut queued, link) = deaf(&budgets, 1);
        let job = || {
            Out::Job(Job {
                link: LinkId(0),
                generation: 0,
                page: Page::Fresh {
                    change: ChangeId {
                        chain: ChainId([0; 16]),
                        seq: 1,
                    },
                },
            })
        };
        let mut sent = 0;
        while outbox.send(job()) {
            sent += 1;
        }
        assert_eq!(sent, OUT_QUEUE);
        assert!(link.closed.lock().unwrap().is_some());
        assert_eq!(held(&mut queued).1, OUT_QUEUE);
        // What a queue held is given back with it.
        drop((outbox, queued));
        let (again, _queued, _) = deaf(&budgets, 1);
        assert!(again.send(job()));
    }

    #[tokio::test]
    async fn replies_not_yet_written_past_the_requests_close_the_link() {
        let budgets = Budgets::default();
        let (outbox, mut queued, link) = deaf(&budgets, 1);
        let tips = |id| {
            Out::Send(Outgoing {
                link: LinkId(0),
                generation: 0,
                message: Sync::TipsPage {
                    id,
                    tips: Bounded::new(),
                    next: None,
                },
            })
        };
        let page = |id| {
            Out::Job(Job {
                link: LinkId(0),
                generation: 0,
                page: Page::Changes {
                    id,
                    chain: ChainId([0; 16]),
                    after: 0,
                    at: ChangeHash([0; 32]),
                    most: 1,
                },
            })
        };
        let pushed = || {
            Out::Send(Outgoing {
                link: LinkId(0),
                generation: 0,
                message: Sync::Tips {
                    tips: Bounded::new(),
                },
            })
        };
        // Pushes hold no place; replies made at once and pages to build
        // each hold one until written.
        for _ in 0..2 * REQUESTS {
            assert!(outbox.send(pushed()));
        }
        for id in 0..REQUESTS - 1 {
            assert!(outbox.send(tips(u32::try_from(id).unwrap())));
        }
        assert!(outbox.send(page(100)));
        assert_eq!(*link.closed.lock().unwrap(), None);
        // One reply written (taken from the queue): room for one more.
        while let Ok(item) = queued.try_recv() {
            if matches!(
                item,
                Queued::Send {
                    _reply: Some(_),
                    ..
                }
            ) {
                break;
            }
        }
        assert!(outbox.send(tips(200)));
        assert_eq!(*link.closed.lock().unwrap(), None);
        // A ninth unanswered: the link is closed.
        assert!(!outbox.send(page(201)));
        assert_eq!(
            link.closed.lock().unwrap().as_deref(),
            Some("more requests outstanding than allowed")
        );
    }

    /// The owner's session, on the fixture, in a directory of its own.
    fn session(test: &str) -> (Arc<Session>, Identity, PathBuf) {
        let home = env::temp_dir().join(format!("binbun-link-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let identity = Identity::load_or_create(&home.join("identity")).unwrap();
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
        (Arc::new(session), identity, home)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_member_the_owner_removes_while_its_link_comes_up_is_never_linked() {
        let (session, owner, home) = session("removed-linking");
        let net = MemNet::new();
        let config = Config {
            identity: owner.clone(),
            name: "ann".to_owned(),
            approve: None,
            notify: None,
            engine: EngineVersion::this(),
        };
        let (peer, ticket) = Peer::share(session, Arc::new(net.endpoint(owner.public())), config)
            .await
            .unwrap();
        let xan = Identity::ephemeral().unwrap();
        peer.add(&Card::new(&xan, "xan"), Role::Viewer).unwrap();
        // Xan is welcomed as a member.
        let link = net
            .endpoint(xan.public())
            .connect(&ticket.host)
            .await
            .unwrap();
        let (mut send, mut recv) = link.open(Lane::Control).await.unwrap();
        let hello = Hello {
            protocol: PROTOCOL,
            log: LOG,
            engine: Engine::of(&EngineVersion::this()),
            project: ticket.project,
            invite: None,
            card: Card::new(&xan, "xan"),
            membership: (0, [0; 32]),
            features: FEATURES,
        };
        write_frame(&mut *send, &Control::Hello(Box::new(hello)))
            .await
            .unwrap();
        let welcome = read_frame::<Control>(&mut *recv).await.unwrap();
        assert!(matches!(welcome, Some(Control::Welcome { .. })));
        // His link held where it is put up, the owner removes him; then
        // it goes on.
        let (reached, at) = oneshot::channel();
        let (go, held) = oneshot::channel();
        *peer.inner().linking.lock().unwrap() = Some((reached, held));
        let (_sync, mut lane) = link.open(Lane::Sync).await.unwrap();
        at.await.unwrap();
        peer.remove(xan.public()).unwrap();
        go.send(()).unwrap();
        // It is not put up: nothing comes on its lane, and it is never
        // among the links.
        let first = tokio::time::timeout(
            Duration::from_secs(10),
            read_frame_length(&mut *lane, FRAME),
        )
        .await
        .expect("the lane ends in time");
        assert!(matches!(first, Ok(None) | Err(_)), "{first:?}");
        assert_eq!(peer.links(), Vec::new());
        assert_eq!(peer.readers(), Vec::new());
        peer.close().await;
        let _ = fs::remove_dir_all(home);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gone_links_report_keeps_this_peers_own_chains_charged_and_the_newest_link() {
        let (session, owner, home) = session("kept-report");
        let budgets = Budgets::default();
        let net = MemNet::new();
        let config = Config {
            identity: owner.clone(),
            name: "ann".to_owned(),
            approve: None,
            notify: None,
            engine: EngineVersion::this(),
        };
        let transport = net.endpoint_within(owner.public(), budgets.clone());
        let (peer, _) = Peer::share(Arc::clone(&session), Arc::new(transport), config)
            .await
            .unwrap();
        let entry = session
            .database()
            .unwrap()
            .functions()
            .next()
            .unwrap()
            .1
            .entry;
        session.comment(entry, Some("mine")).unwrap();
        // Its chain, begun by the change (pending, with no reader linked).
        let own = Tip {
            chain: session.chain(),
            project: ProjectId([1; 16]),
            seq: 1,
            hash: ChangeHash([2; 32]),
            fork: 0,
        };
        assert!(session.chain_origin(own.chain).is_some());
        let foreign = Tip {
            chain: ChainId([9; 16]),
            ..own
        };
        let report = |tips: &[Tip]| Report {
            tips: tips.iter().map(|tip| (tip.chain, *tip)).collect(),
            membership: Some((1, [0; 32])),
        };
        let remote = PublicKey([5; 32]);
        let inner = peer.inner();
        // Only the peer's own chain is kept, and charged with the report.
        inner.keep_report(
            &mut inner.state(),
            (remote, LinkId(7)),
            report(&[own, foreign]),
        );
        {
            let state = inner.state();
            let kept = &state.reports[&remote];
            assert_eq!(kept.link, LinkId(7));
            assert_eq!(kept.report.tips.keys().collect::<Vec<_>>(), [&own.chain]);
        }
        assert!(budgets.retain(SYNC_LINK - 2 * PER_CHAIN + 1).is_none());
        assert!(budgets.retain(SYNC_LINK - 2 * PER_CHAIN).is_some());
        // An older link's, gone after it, does not take its place.
        inner.keep_report(&mut inner.state(), (remote, LinkId(5)), report(&[]));
        assert_eq!(inner.state().reports[&remote].link, LinkId(7));
        // A newer one's does, the older's charge given back.
        inner.keep_report(&mut inner.state(), (remote, LinkId(9)), report(&[]));
        assert_eq!(inner.state().reports[&remote].link, LinkId(9));
        assert!(budgets.retain(SYNC_LINK - PER_CHAIN + 1).is_none());
        assert!(budgets.retain(SYNC_LINK - PER_CHAIN).is_some());
        peer.close().await;
        let _ = fs::remove_dir_all(home);
    }
}
