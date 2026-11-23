#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Who is let in, and what strangers and members cost a host, over
//! [`MemNet`]: a key the owner added is let in at once, no one asked; a
//! stranger without a grant is denied and given nothing; a stranger's
//! oversized hello is turned away at once; strangers waiting to be let in
//! are bounded, members never wait for a place; one request per key, each
//! withdrawn when its asker goes or the invite is forgotten, and checked
//! again before it is signed; a member's asks and refusals neither queue
//! history without bound nor are kept without bound.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use binbun_collab::bounded::{Bounded, Bytes};
use binbun_collab::mem::MemNet;
use binbun_collab::membership::Role;
use binbun_collab::ticket::{Card, JoinTicket};
use binbun_collab::transport::{
    Lane, Link, RecvStream, SendStream, read_bytes, read_frame, read_frame_length, write_bytes,
    write_frame,
};
use binbun_collab::wire::{Control, Engine, FEATURES, Hello, LOG, PROTOCOL};
use binbun_collab::{Approver, Config, Notice, Peer, Request, Transport};
use binbun_session::identity::Identity;
use binbun_session::journal::{ChangeHash, ChangeId, EngineVersion, PublicKey};
use binbun_session::{Options, Session, Stage};
use binbun_sync::Sync;
use binbun_sync::machine::WANTS;
use binbun_sync::wire::{CHANGES, FRAME, REFUSED, WHY};

/// `tests/fixtures/<name>`.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// A fresh directory for `name`, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("collab-admission-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One person: their identity and session on `file` (under `dir`), and
/// what their peer tells.
struct Person {
    identity: Identity,
    session: Arc<Session>,
    heard: Arc<Mutex<Vec<Notice>>>,
}

impl Person {
    fn new(dir: &Scratch, name: &str, file: &str) -> Self {
        let home = dir.0.join(name);
        let identity = Identity::load_or_create(&home.join("identity")).unwrap();
        let session = Session::open(
            fixture(file),
            Options {
                project: Some(home.join("project")),
                identity: Some(home.join("identity")),
                warm: false,
                ..Options::default()
            },
        )
        .unwrap();
        session.wait(Stage::Analysed, None);
        Self {
            identity,
            session: Arc::new(session),
            heard: Arc::default(),
        }
    }

    fn key(&self) -> PublicKey {
        self.identity.public()
    }

    fn config(&self, approve: Option<Approver>) -> Config {
        let heard = Arc::clone(&self.heard);
        Config {
            identity: self.identity.clone(),
            name: "someone".to_owned(),
            approve,
            notify: Some(Arc::new(move |notice: &Notice| {
                heard.lock().unwrap().push(notice.clone());
            })),
            engine: EngineVersion::this(),
        }
    }

    fn transport(&self, net: &MemNet) -> Arc<dyn Transport> {
        Arc::new(net.endpoint(self.key()))
    }

    /// Shares their project over `net`, ticket holders let in by
    /// `approve`.
    async fn share(&self, net: &MemNet, approve: Approver) -> (Peer, JoinTicket) {
        Peer::share(
            Arc::clone(&self.session),
            self.transport(net),
            self.config(Some(approve)),
        )
        .await
        .unwrap()
    }

    /// Shares their project over `net`, only members let in.
    async fn host(&self, net: &MemNet) -> (Peer, JoinTicket) {
        Peer::share(
            Arc::clone(&self.session),
            self.transport(net),
            self.config(None),
        )
        .await
        .unwrap()
    }

    async fn join(&self, net: &MemNet, ticket: &JoinTicket) -> Peer {
        Peer::join(
            Arc::clone(&self.session),
            self.transport(net),
            self.config(None),
            ticket,
        )
        .await
        .unwrap()
    }

    /// Renames the function at `entry` to `name`.
    fn rename(&self, entry: u64, name: &str) {
        self.session.rename_function(entry, Some(name)).unwrap();
    }

    /// Some function's entry.
    fn a_function(&self) -> u64 {
        let database = self.session.database().unwrap();
        database.functions().next().map(|(_, f)| f.entry).unwrap()
    }

    /// Whether this session holds a change by `author`.
    fn has_from(&self, author: PublicKey) -> bool {
        self.session
            .history()
            .iter()
            .any(|entry| entry.author == author)
    }

    /// Whether their peer told a notice `matching`.
    fn heard(&self, matching: impl Fn(&Notice) -> bool) -> bool {
        self.heard.lock().unwrap().iter().any(matching)
    }
}

/// Waits (up to 30 s) until `done`.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(30), "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// An approver admitting everyone as `role`, counting whom it was asked
/// about.
fn admitting(role: Role, asked: &Arc<AtomicUsize>) -> Approver {
    let asked = Arc::clone(asked);
    Arc::new(move |_| {
        asked.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Some(role) })
    })
}

/// Counts one when dropped.
struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// `who` dialling `ticket`'s host by hand: its control lane, a hello
/// sent (with the ticket's invite if `invited`).
async fn say_hello(
    net: &MemNet,
    who: &Identity,
    ticket: &JoinTicket,
    invited: bool,
) -> (Arc<dyn Link>, SendStream, RecvStream) {
    say_hello_running(net, who, ticket, invited, &EngineVersion::this()).await
}

/// `who` dialling `ticket`'s host by hand, saying it runs `engine`.
async fn say_hello_running(
    net: &MemNet,
    who: &Identity,
    ticket: &JoinTicket,
    invited: bool,
    engine: &EngineVersion,
) -> (Arc<dyn Link>, SendStream, RecvStream) {
    let link = net
        .endpoint(who.public())
        .connect(&ticket.host)
        .await
        .unwrap();
    let (mut send, recv) = link.open(Lane::Control).await.unwrap();
    let hello = Hello {
        protocol: PROTOCOL,
        log: LOG,
        engine: Engine::of(engine),
        project: ticket.project,
        invite: invited.then_some(ticket.invite),
        card: Card::new(who, "cat"),
        membership: (0, [0; 32]),
        features: FEATURES,
    };
    write_frame(&mut *send, &Control::Hello(Box::new(hello)))
        .await
        .unwrap();
    (link, send, recv)
}

/// The host's next word on a control lane.
async fn answer(recv: &mut RecvStream) -> Control {
    tokio::time::timeout(Duration::from_secs(10), read_frame::<Control>(&mut **recv))
        .await
        .expect("an answer in time")
        .unwrap()
        .expect("an answer")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_the_owner_adds_is_let_in_with_no_one_asked() {
    let dir = Scratch::new("added");
    let ann = Person::new(&dir, "ann", "program-x86_64.elf");
    let bob = Person::new(&dir, "bob", "program-x86_64.elf");
    let entry = ann.a_function();
    ann.rename(entry, "anns");
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    a.add(&Card::new(&bob.identity, "bob"), Role::Editor)
        .unwrap();
    let b = bob.join(&net, &ticket).await;
    until("Bob is in, a reader, with Ann's edit", || {
        b.role() == Some(Role::Editor)
            && b.readers() == [ann.key()]
            && bob.session.name(entry).as_deref() == Some("anns")
    })
    .await;
    // Let in at once: he waited for no one.
    assert!(!bob.heard(|n| matches!(n, Notice::Waiting)));
    assert!(!ann.heard(|n| matches!(n, Notice::Turned { .. })));
    assert_eq!(b.epochs(), [0]);
    bob.rename(entry, "bobs");
    until("Ann takes Bob's edit", || {
        ann.session.name(entry).as_deref() == Some("bobs")
    })
    .await;
    a.close().await;
    b.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_without_a_grant_is_denied_and_given_nothing() {
    let dir = Scratch::new("stranger");
    let ann = Person::new(&dir, "ann", "program-x86_64.elf");
    let cat = Person::new(&dir, "cat", "program-x86_64.elf");
    let entry = ann.a_function();
    ann.rename(entry, "anns");
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    // The ticket alone: no one added her, no one to ask.
    let c = cat.join(&net, &ticket).await;
    until("Cat is denied", || {
        cat.heard(|n| matches!(n, Notice::Denied(why) if why.contains("not a member")))
    })
    .await;
    assert!(ann.heard(|n| matches!(n, Notice::Turned { peer, .. } if *peer == cat.key())));
    // She holds nothing of the share: no record, no key, no change.
    assert_eq!(c.membership().seq(), 0);
    assert_eq!(c.epochs(), Vec::<u32>::new());
    assert!(c.readers().is_empty() && a.readers().is_empty());
    assert_eq!(cat.session.genesis(), None);
    assert_eq!(cat.session.tips_after(None, usize::MAX), Vec::new());
    assert!(!cat.has_from(ann.key()));
    assert_ne!(cat.session.name(entry).as_deref(), Some("anns"));
    assert_eq!(a.membership().role(cat.key()), None);
    a.close().await;
    c.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strangers_cost_the_host_little_and_members_never_wait_for_them() {
    let dir = Scratch::new("strangers");
    let ann = Person::new(&dir, "ann", "program-x86_64.elf");
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, admitting(Role::Editor, &asked)).await;
    let bob = Identity::ephemeral().unwrap();
    a.add(&Card::new(&bob, "bob"), Role::Editor).unwrap();

    // A first frame that claims a megabyte and sends none of it: turned
    // away at once, not waited for.
    let cat = Identity::ephemeral().unwrap();
    let link = net
        .endpoint(cat.public())
        .connect(&ticket.host)
        .await
        .unwrap();
    let (mut send, _recv) = link.open(Lane::Control).await.unwrap();
    let mut claim = Vec::new();
    let mut length = 1usize << 20;
    while length >= 0x80 {
        claim.push(u8::try_from(length & 0x7f).unwrap() | 0x80);
        length >>= 7;
    }
    claim.push(u8::try_from(length).unwrap());
    tokio::io::AsyncWriteExt::write_all(&mut send, &claim)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), link.closed())
        .await
        .expect("an oversized hello is turned away at once");

    // Strangers that say nothing: past a bound, closed at once (maybe
    // before their control lane opens: counted as closed all the same).
    let mut silent = Vec::new();
    for _ in 0..100 {
        let who = Identity::ephemeral().unwrap();
        let link = net
            .endpoint(who.public())
            .connect(&ticket.host)
            .await
            .unwrap();
        let lane = link.open(Lane::Control).await.ok();
        silent.push((link, lane));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut closed = 0;
    for (link, _) in &silent {
        if tokio::time::timeout(Duration::from_millis(10), link.closed())
            .await
            .is_ok()
        {
            closed += 1;
        }
    }
    assert!(closed >= 30, "{closed} of 100 silent strangers turned away");

    // A member is let in all the same.
    let (_link, _send, mut recv) = say_hello(&net, &bob, &ticket, false).await;
    assert!(matches!(answer(&mut recv).await, Control::Welcome { .. }));
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    drop(silent);
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_request_per_key_withdrawn_when_its_asker_goes_or_the_invite_is_forgotten() {
    let dir = Scratch::new("withdrawn");
    let ann = Person::new(&dir, "ann", "program-x86_64.elf");
    let net = MemNet::new();
    let requests: Arc<Mutex<Vec<Request>>> = Arc::default();
    let withdrawn = Arc::new(AtomicUsize::new(0));
    let approve: Approver = {
        let (requests, withdrawn) = (Arc::clone(&requests), Arc::clone(&withdrawn));
        Arc::new(move |request| {
            requests.lock().unwrap().push(request);
            let dropped = Dropped(Arc::clone(&withdrawn));
            Box::pin(async move {
                let _dropped = dropped;
                std::future::pending::<Option<Role>>().await
            })
        })
    };
    let (a, ticket) = ann.share(&net, approve).await;
    let cat = Identity::ephemeral().unwrap();

    // Asked about once, by the key the link proved.
    let (first, _send, mut recv) = say_hello(&net, &cat, &ticket, true).await;
    assert_eq!(answer(&mut recv).await, Control::Pending);
    until("the approver is asked", || {
        requests.lock().unwrap().len() == 1
    })
    .await;
    assert_eq!(requests.lock().unwrap()[0].card.key, cat.public());
    // A second request of the same key, while the first waits: turned
    // away, the approver not asked again.
    let (_second, _send2, mut recv2) = say_hello(&net, &cat, &ticket, true).await;
    assert!(matches!(answer(&mut recv2).await, Control::Denied { .. }));
    assert_eq!(requests.lock().unwrap().len(), 1);

    // The asker goes: the request is withdrawn, and they may ask again.
    first.close("gone");
    until("the request is withdrawn", || {
        withdrawn.load(Ordering::SeqCst) == 1
    })
    .await;
    let (_third, _send3, mut recv3) = say_hello(&net, &cat, &ticket, true).await;
    assert_eq!(answer(&mut recv3).await, Control::Pending);
    until("asked again", || requests.lock().unwrap().len() == 2).await;

    // The invite forgotten: the request is withdrawn, the asker told.
    a.stop_inviting();
    until("the request is withdrawn", || {
        withdrawn.load(Ordering::SeqCst) == 2
    })
    .await;
    assert!(matches!(answer(&mut recv3).await, Control::Denied { .. }));
    assert_eq!(a.membership().role(cat.public()), None);
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approval_that_comes_after_the_invite_is_forgotten_admits_no_one() {
    let dir = Scratch::new("recheck");
    let ann = Person::new(&dir, "ann", "program-x86_64.elf");
    let net = MemNet::new();
    // The approver forgets the invite as it admits (the share closing
    // while the owner clicks).
    let slot: Arc<OnceLock<Weak<Peer>>> = Arc::default();
    let approve: Approver = {
        let slot = Arc::clone(&slot);
        Arc::new(move |_| {
            if let Some(peer) = slot.get().and_then(Weak::upgrade) {
                peer.stop_inviting();
            }
            Box::pin(async { Some(Role::Editor) })
        })
    };
    let (a, ticket) = ann.share(&net, approve).await;
    let a = Arc::new(a);
    slot.set(Arc::downgrade(&a)).unwrap();
    let cat = Identity::ephemeral().unwrap();
    let (_link, _send, mut recv) = say_hello(&net, &cat, &ticket, true).await;
    assert_eq!(answer(&mut recv).await, Control::Pending);
    assert!(matches!(answer(&mut recv).await, Control::Denied { .. }));
    assert_eq!(a.membership().role(cat.public()), None);
    Arc::try_unwrap(a).unwrap().close().await;
}

/// A member's binbun spoken by hand over its sync lane, from Reader on.
struct Hand {
    link: Arc<dyn Link>,
    _control: (SendStream, RecvStream),
    send: SendStream,
    recv: RecvStream,
}

impl Hand {
    /// `who`, a member, linked to `ticket`'s host: hello, welcome, the
    /// sync lane; the host's membership head said back, its `Ready`
    /// answered.
    async fn reader(net: &MemNet, who: &Identity, ticket: &JoinTicket) -> Self {
        let (link, send, mut recv) = say_hello(net, who, ticket, false).await;
        assert!(matches!(answer(&mut recv).await, Control::Welcome { .. }));
        let (sync_send, sync_recv) = link.open(Lane::Sync).await.unwrap();
        let mut hand = Self {
            link,
            _control: (send, recv),
            send: sync_send,
            recv: sync_recv,
        };
        let Some(Sync::MembershipHead { membership }) = hand.next().await else {
            panic!("no membership head first");
        };
        hand.say(&Sync::MembershipHead { membership }).await;
        loop {
            if let Some(Sync::Ready {
                genesis,
                membership,
            }) = hand.next().await
            {
                hand.say(&Sync::Ready {
                    genesis,
                    membership,
                })
                .await;
                return hand;
            }
        }
    }

    async fn say(&mut self, message: &Sync) {
        write_bytes(&mut *self.send, &message.encode().unwrap())
            .await
            .unwrap();
    }

    /// The host's next message; `None` once the lane ends.
    async fn next(&mut self) -> Option<Sync> {
        let length = read_frame_length(&mut *self.recv, FRAME).await.ok()??;
        let bytes = read_bytes(&mut *self.recv, length).await.ok()?;
        Some(Sync::decode(&bytes).unwrap())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_members_asks_and_refusals_neither_queue_nor_keep_without_bound() {
    let dir = Scratch::new("member");
    let ann = Person::new(&dir, "ann", "program-x86_64.elf");
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    // A history whose envelopes outgrow a link's buffer.
    let entry = ann.a_function();
    for i in 0..300 {
        ann.rename(entry, &format!("{i}_{}", "n".repeat(250)));
    }
    let chain = ann.session.chain();
    let cat = Identity::ephemeral().unwrap();
    a.add(&Card::new(&cat, "cat"), Role::Viewer).unwrap();
    let mut hand = Hand::reader(&net, &cat, &ticket).await;

    // The whole chain asked for 50 times, nothing read meanwhile: the
    // host serves what its stream takes and closes the link past the
    // asks it lets wait, queuing no more.
    for id in 0..50 {
        let want = Sync::Want {
            id,
            chain,
            after: 0,
            at: ChangeHash::ZERO,
            most: u16::try_from(CHANGES).unwrap(),
        };
        hand.say(&want).await;
    }
    tokio::time::timeout(Duration::from_secs(10), hand.link.closed())
        .await
        .expect("asks past the bound close the link");
    let mut envelopes = 0;
    while let Ok(Some(message)) =
        tokio::time::timeout(Duration::from_millis(500), hand.next()).await
    {
        if let Sync::Changes { changes, .. } = message {
            envelopes += changes.len();
        }
    }
    assert!(
        envelopes <= (WANTS + 1) * CHANGES,
        "{envelopes} envelopes served"
    );

    // Refusals of changes Ann never made, and of one she did, said many
    // times with ever other reasons: only hers is kept, once.
    let mut hand = Hand::reader(&net, &cat, &ticket).await;
    let hers = ChangeId { chain, seq: 2 };
    let by_cat = |peer: &Peer| -> Vec<_> {
        peer.refused()
            .into_iter()
            .filter(|refused| refused.why.starts_with("refused by"))
            .collect()
    };
    for round in 0..100u64 {
        let mut refused: Vec<(ChangeId, Bytes<WHY>)> = (0..3)
            .map(|i| {
                let why = format!("{round}.{i}{}", "y".repeat(WHY - 10));
                (hers, Bytes::try_from(why.into_bytes()).unwrap())
            })
            .collect();
        refused.extend((0..REFUSED as u64 - 3).map(|seq| {
            let invented = ChangeId {
                chain,
                seq: 1_000_000 + round * 100 + seq,
            };
            (invented, Bytes::try_from(b"x".repeat(100)).unwrap())
        }));
        hand.say(&Sync::Refused {
            changes: Bounded::truncated(refused),
        })
        .await;
    }
    until("Cat's refusal of Ann's change is listed", || {
        !by_cat(&a).is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let listed = by_cat(&a);
    assert_eq!(listed.len(), 1, "{} refusals kept", listed.len());
    let kept = &listed[0];
    assert_eq!(kept.change, Some(hers));
    assert!(kept.why.len() <= WHY + 100, "{} bytes kept", kept.why.len());
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hello_whose_binbun_is_not_plain_text_is_turned_away() {
    let dir = Scratch::new("labels");
    let ann = Person::new(&dir, "ann", "program-x86_64.elf");
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, admitting(Role::Editor, &asked)).await;
    let bob = Identity::ephemeral().unwrap();
    a.add(&Card::new(&bob, "bob"), Role::Editor).unwrap();
    let this = EngineVersion::this();
    let cleared = EngineVersion {
        release: format!("{}\u{1b}[2J", this.release),
        ..this.clone()
    };
    let reversed = EngineVersion {
        build: format!("\u{202e}{}", this.build),
        ..this.clone()
    };

    // An invited stranger and a member alike, before anyone is asked.
    for engine in [cleared, reversed] {
        let stranger = Identity::ephemeral().unwrap();
        for who in [&stranger, &bob] {
            let (_link, _send, mut recv) =
                say_hello_running(&net, who, &ticket, true, &engine).await;
            let said = answer(&mut recv).await;
            assert!(matches!(said, Control::Denied { .. }), "{said:?}");
        }
    }
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    assert_eq!(a.membership().members().len(), 2);
    a.close().await;
}

#[tokio::test]
async fn a_request_not_answered_in_time_is_refused_and_each_key_asks_a_few_times_a_while() {
    let dir = Scratch::new("expiry");
    let ann = Person::new(&dir, "ann", "program-x86_64.elf");
    let net = MemNet::new();
    let requests = Arc::new(AtomicUsize::new(0));
    let withdrawn = Arc::new(AtomicUsize::new(0));
    let approve: Approver = {
        let (requests, withdrawn) = (Arc::clone(&requests), Arc::clone(&withdrawn));
        Arc::new(move |_| {
            requests.fetch_add(1, Ordering::SeqCst);
            let dropped = Dropped(Arc::clone(&withdrawn));
            Box::pin(async move {
                let _dropped = dropped;
                std::future::pending::<Option<Role>>().await
            })
        })
    };
    let (a, ticket) = ann.share(&net, approve).await;
    // The host's clock runs as fast as its timers fire from here.
    tokio::time::pause();
    let cat = Identity::ephemeral().unwrap();

    // Never answered: refused once its time is up, the approver's future
    // dropped.
    let (_first, _send, mut recv) = say_hello(&net, &cat, &ticket, true).await;
    assert_eq!(answer(&mut recv).await, Control::Pending);
    let late = tokio::time::timeout(Duration::from_secs(3600), read_frame::<Control>(&mut *recv))
        .await
        .expect("refused within the hour")
        .unwrap();
    assert!(matches!(late, Some(Control::Denied { .. })), "{late:?}");
    assert_eq!(withdrawn.load(Ordering::SeqCst), 1);
    assert_eq!(a.membership().role(cat.public()), None);

    // Asked twice more, each withdrawn: a fourth request of the key is
    // turned away before the approver is asked.
    for asked in 2..=3 {
        let (link, _send, mut recv) = say_hello(&net, &cat, &ticket, true).await;
        assert_eq!(answer(&mut recv).await, Control::Pending);
        link.close("gone");
        while withdrawn.load(Ordering::SeqCst) < asked {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let (_fourth, _send, mut recv) = say_hello(&net, &cat, &ticket, true).await;
    assert!(matches!(answer(&mut recv).await, Control::Denied { .. }));
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    // Another key is asked about all the same; and a while later, this one
    // again.
    let dan = Identity::ephemeral().unwrap();
    let (_dan, _send, mut recv) = say_hello(&net, &dan, &ticket, true).await;
    assert_eq!(answer(&mut recv).await, Control::Pending);
    tokio::time::advance(Duration::from_mins(20)).await;
    let (_fifth, _send, mut recv) = say_hello(&net, &cat, &ticket, true).await;
    assert_eq!(answer(&mut recv).await, Control::Pending);
    assert_eq!(requests.load(Ordering::SeqCst), 5);
    a.close().await;
}
