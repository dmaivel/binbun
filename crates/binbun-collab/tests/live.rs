#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The live session over [`MemTransport`]s: presence while dragging stays
//! at 20 datagrams a
//! second at most, each [`MAX_DATAGRAM`] bytes at most, the latest cursor
//! arriving;
//! nothing of it is written under the project; a third peer sees the
//! others through the host; chat reaches everyone, late joiners get the
//! backlog, and bursts are limited; an agent connected to the host's
//! window is a participant for the others while it is connected and a
//! member, its cursor with it.
//!
//! Every joiner is added by the owner before it connects.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use binbun_collab::bounded::Text;
use binbun_collab::budgets::Budgets;
use binbun_collab::live::{Agent, ChatLink, Cursor, HostedAgent, MAX_DATAGRAM, Place, Selection};
use binbun_collab::mem::{MemNet, MemTransport};
use binbun_collab::membership::Role;
use binbun_collab::ticket::{Card, JoinTicket, PeerAddr};
use binbun_collab::transport::{BoxFuture, Lane, Link, RecvStream, SendStream, Transport};
use binbun_collab::{Config, Error, Peer};
use binbun_session::identity::Identity;
use binbun_session::journal::{EngineVersion, PublicKey};
use binbun_session::{Options, Session, Stage};

/// `tests/fixtures/program-x86_64.elf`.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A fresh directory for `name`.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-live-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Datagrams sent, by sender: when, how many bytes.
type Sent = Arc<Mutex<BTreeMap<PublicKey, Vec<(Instant, usize)>>>>;

/// Where the drag goes: addresses no project holds.
const BASE: u64 = 0x5eed_c0de_0000_0000;

/// A link that counts the datagrams sent on it.
struct Counted {
    link: Arc<dyn Link>,
    me: PublicKey,
    sent: Sent,
}

impl Link for Counted {
    fn remote(&self) -> PublicKey {
        self.link.remote()
    }
    fn open(&self, lane: Lane) -> BoxFuture<'_, Result<(SendStream, RecvStream), Error>> {
        self.link.open(lane)
    }
    fn accept(&self) -> BoxFuture<'_, Result<(Lane, SendStream, RecvStream), Error>> {
        self.link.accept()
    }
    fn path(&self) -> String {
        self.link.path()
    }
    fn close(&self, reason: &str) {
        self.link.close(reason);
    }
    fn closed(&self) -> BoxFuture<'_, ()> {
        self.link.closed()
    }
    fn send_datagram(&self, bytes: Vec<u8>) -> Result<(), Error> {
        self.sent
            .lock()
            .unwrap()
            .entry(self.me)
            .or_default()
            .push((Instant::now(), bytes.len()));
        self.link.send_datagram(bytes)
    }
    fn recv_datagram(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        self.link.recv_datagram()
    }
}

/// A transport whose links count the datagrams sent.
struct Counting {
    inner: MemTransport,
    sent: Sent,
}

impl Counting {
    fn wrap(&self, link: Arc<dyn Link>) -> Arc<dyn Link> {
        Arc::new(Counted {
            link,
            me: self.inner.id(),
            sent: Arc::clone(&self.sent),
        })
    }
}

impl Transport for Counting {
    fn id(&self) -> PublicKey {
        self.inner.id()
    }
    fn addr(&self) -> PeerAddr {
        self.inner.addr()
    }
    fn connect<'a>(&'a self, to: &'a PeerAddr) -> BoxFuture<'a, Result<Arc<dyn Link>, Error>> {
        Box::pin(async move { Ok(self.wrap(self.inner.connect(to).await?)) })
    }
    fn accept(&self) -> BoxFuture<'_, Option<Arc<dyn Link>>> {
        Box::pin(async move { Some(self.wrap(self.inner.accept().await?)) })
    }
    fn close(&self) -> BoxFuture<'_, ()> {
        self.inner.close()
    }
    fn budgets(&self) -> &Budgets {
        self.inner.budgets()
    }
}

/// One person: identity and session on the fixture in `dir/name`.
struct Person {
    name: &'static str,
    identity: Identity,
    session: Arc<Session>,
    project: PathBuf,
}

impl Person {
    fn new(dir: &Path, name: &'static str) -> Self {
        let home = dir.join(name.to_lowercase());
        let identity = Identity::load_or_create(&home.join("identity")).unwrap();
        let session = Session::open(
            fixture(),
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
            name,
            identity,
            session: Arc::new(session),
            project: home.join("project"),
        }
    }

    fn config(&self) -> Config {
        Config {
            identity: self.identity.clone(),
            name: self.name.to_owned(),
            approve: None,
            notify: None,
            engine: EngineVersion::this(),
        }
    }

    /// Their identity card, as the owner adds them by.
    fn card(&self) -> Card {
        Card::new(&self.identity, self.name)
    }

    fn transport(&self, net: &MemNet, sent: &Sent) -> Arc<dyn Transport> {
        Arc::new(Counting {
            inner: net.endpoint(self.identity.public()),
            sent: Arc::clone(sent),
        })
    }

    /// Shares their session over `net`.
    async fn share(&self, net: &MemNet, sent: &Sent) -> (Peer, JoinTicket) {
        Peer::share(
            Arc::clone(&self.session),
            self.transport(net, sent),
            self.config(),
        )
        .await
        .unwrap()
    }

    /// Joins `ticket`'s share over `net`, added by its owner (`host`) as
    /// an editor first.
    async fn join(&self, host: &Peer, net: &MemNet, sent: &Sent, ticket: &JoinTicket) -> Peer {
        host.add(&self.card(), Role::Editor).unwrap();
        Peer::join(
            Arc::clone(&self.session),
            self.transport(net, sent),
            self.config(),
            ticket,
        )
        .await
        .unwrap()
    }
}

/// Waits (up to 30 s) until `done`.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(30), "never: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Every file under `dir` and its bytes.
fn files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut todo = vec![dir.to_owned()];
    while let Some(dir) = todo.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                todo.push(path);
            } else {
                found.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    found
}

/// The most of `times` within any one second.
fn busiest_second(times: &[Instant]) -> usize {
    times
        .iter()
        .map(|start| {
            times
                .iter()
                .filter(|t| **t >= *start && t.duration_since(*start) < Duration::from_secs(1))
                .count()
        })
        .max()
        .unwrap_or(0)
}

/// `value`'s postcard (LEB128) bytes.
fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let low = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value == 0 {
            bytes.push(low);
            return bytes;
        }
        bytes.push(low | 0x80);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn presence_while_dragging_is_rate_limited_small_and_never_kept() {
    let dir = scratch("drag");
    let (ann, bob) = (Person::new(&dir, "Ann"), Person::new(&dir, "Bob"));
    let net = MemNet::new();
    let sent = Sent::default();
    let (a, ticket) = ann.share(&net, &sent).await;
    let b = bob.join(&a, &net, &sent, &ticket).await;
    until("each sees the other", || {
        a.participants().len() == 1 && b.participants().len() == 1 && b.role().is_some()
    })
    .await;
    assert_eq!(b.participants()[0].card.name, "Ann");
    assert_eq!(a.participants()[0].card.name, "Bob");
    let history = ann.session.history().len();
    let kept = (files(&ann.project), files(&bob.project));
    sent.lock().unwrap().clear();

    // Ann drags for two seconds: a cursor every millisecond, at addresses
    // no project holds.
    let start = Instant::now();
    let mut last = BASE;
    while start.elapsed() < Duration::from_secs(2) {
        last += 1;
        a.set_cursor(Cursor {
            place: Place::Listing,
            address: last,
            column: 40,
            selection: Some(Selection::Addresses { first: BASE, last }),
        });
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let bob_sees = |address| {
        b.participants()
            .first()
            .and_then(|ann| ann.cursor)
            .is_some_and(|cursor| cursor.address == address)
    };
    until("Bob sees where Ann stopped", || bob_sees(last)).await;

    let sent = sent.lock().unwrap().clone();
    let anns: Vec<(Instant, usize)> = sent[&ann.identity.public()].clone();
    let times: Vec<Instant> = anns.iter().map(|(time, _)| *time).collect();
    let busiest = busiest_second(&times);
    let largest = anns.iter().map(|(_, size)| *size).max().unwrap();
    println!(
        "presence: {} datagrams in {:.2} s of dragging, at most {busiest} in one second, \
         the largest {largest} bytes",
        anns.len(),
        start.elapsed().as_secs_f64()
    );
    assert!(busiest <= 20, "{busiest} datagrams in one second");
    // Coalesced, not dropped: about one every 50 ms went.
    assert!(anns.len() >= 30, "only {} datagrams", anns.len());
    assert!(largest <= MAX_DATAGRAM, "a datagram of {largest} bytes");

    a.close().await;
    b.close().await;
    // Nothing of the session was written: the projects' files are as they
    // were, the history too, and no address dragged over is in any file.
    assert_eq!(ann.session.history().len(), history);
    let after = (files(&ann.project), files(&bob.project));
    assert_eq!(after, kept);
    for (path, bytes) in after.0.iter().chain(after.1.iter()) {
        for needle in [varint(last), last.to_le_bytes().to_vec()] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{} holds presence",
                path.display()
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_third_peer_sees_the_others_through_the_host_and_chat_reaches_everyone() {
    let dir = scratch("three");
    let (ann, bob, cat) = (
        Person::new(&dir, "Ann"),
        Person::new(&dir, "Bob"),
        Person::new(&dir, "Cat"),
    );
    let net = MemNet::new();
    let sent = Sent::default();
    let (a, ticket) = ann.share(&net, &sent).await;
    let b = bob.join(&a, &net, &sent, &ticket).await;
    until("Bob is in", || {
        b.role().is_some() && a.participants().len() == 1
    })
    .await;
    // A burst of five goes; a sixth at once is refused.
    for n in 0..5 {
        a.chat(&format!("message {n}"), &[], &[]).unwrap();
    }
    assert!(a.chat("one too many", &[], &[]).is_err());
    until("Bob has the five", || b.chat_log().len() == 5).await;
    let texts: Vec<String> = b.chat_log().into_iter().map(|m| m.text.into()).collect();
    assert_eq!(
        texts,
        (0..5).map(|n| format!("message {n}")).collect::<Vec<_>>()
    );
    assert!(b.chat_log().iter().all(|m| m.from == ann.identity.public()));

    // Cat comes late: the backlog, both others, and Bob's cursor through
    // Ann.
    let c = cat.join(&a, &net, &sent, &ticket).await;
    until("Cat knows both", || c.participants().len() == 2).await;
    until("Cat has the backlog", || c.chat_log().len() == 5).await;
    until("Bob knows Cat", || b.participants().len() == 2).await;
    let spot = Cursor {
        place: Place::C {
            function: 0x1130,
            reading: true,
            line: 7,
        },
        address: 0x1139,
        column: 12,
        selection: None,
    };
    b.set_cursor(spot);
    b.follow(Some(ann.identity.public()));
    until("Cat sees Bob's cursor and whom he follows", || {
        c.participants().iter().any(|p| {
            p.card.key == bob.identity.public()
                && p.cursor == Some(spot)
                && p.following == Some(ann.identity.public())
        })
    })
    .await;
    // Cat's message reaches Bob through Ann, its link moved with the
    // trimmed text, the one past it dropped, its mention kept.
    let link = |start: u32, end: u32| ChatLink {
        start,
        end,
        address: 0x1130,
        word: false,
    };
    c.chat(
        "  hello from Cat at `main` ",
        &[link(21, 25), link(30, 34)],
        &[bob.identity.public()],
    )
    .unwrap();
    until("Bob has Cat's message", || {
        b.chat_log().iter().any(|m| {
            m.text == "hello from Cat at `main`"
                && m.from == cat.identity.public()
                && m.links == [link(19, 23)]
                && m.text.get(19..23) == Some("main")
                && m.mentions == [bob.identity.public()]
        })
    })
    .await;
    // Bob leaves: Cat hears it from Ann.
    b.close().await;
    until("Cat forgets Bob", || {
        c.participants()
            .iter()
            .all(|p| p.card.key != bob.identity.public())
    })
    .await;
    a.close().await;
    c.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_on_the_hosts_window_is_a_participant_for_the_others() {
    let dir = scratch("agent");
    let (ann, bob, cat) = (
        Person::new(&dir, "Ann"),
        Person::new(&dir, "Bob"),
        Person::new(&dir, "Cat"),
    );
    let net = MemNet::new();
    let sent = Sent::default();
    let (a, ticket) = ann.share(&net, &sent).await;
    let b = bob.join(&a, &net, &sent, &ticket).await;
    until("Bob is in", || {
        b.role().is_some() && a.participants().len() == 1 && b.participants().len() == 1
    })
    .await;

    // Codex connects to Ann's window: its identity is hers to sign with.
    let codex = Identity::ephemeral().unwrap();
    let key = codex.public();
    let at = |address: u64| Cursor {
        place: Place::Listing,
        address,
        column: 0,
        selection: None,
    };
    let hosted = |cursor: Option<Cursor>| HostedAgent {
        identity: codex.clone(),
        name: "Codex".to_owned(),
        agent: Agent {
            version: Some(Text::truncated("0.42")),
        },
        cursor,
    };
    let agent_of = |peer: &Peer| peer.participants().into_iter().find(|p| p.card.key == key);

    // Not a member yet: no participant. The lane keeps its order, so a
    // chat message said after reaches Bob after any Hi would have.
    a.host_agents(vec![hosted(Some(at(0x1130)))]);
    a.chat("before Codex is a member", &[], &[]).unwrap();
    until("Bob has the message", || b.chat_log().len() == 1).await;
    assert!(
        agent_of(&b).is_none(),
        "a non-member agent is a participant"
    );

    // A member with the agent's role: Bob sees it join, as an agent, where
    // its code works.
    a.add(&Card::new(&codex, "Codex"), Role::Agent).unwrap();
    a.host_agents(vec![hosted(Some(at(0x1130)))]);
    until("Bob sees Codex join at 0x1130", || {
        agent_of(&b).is_some_and(|p| {
            p.card.name == "Codex"
                && p.via == ann.identity.public()
                && p.agent.as_ref().and_then(|a| a.version.as_deref()) == Some("0.42")
                && p.cursor == Some(at(0x1130))
        })
    })
    .await;
    // Ann's window shows its own agents: it is none of her participants.
    assert!(agent_of(&a).is_none());

    // Its code moves on: the cursor reaches Bob.
    a.host_agents(vec![hosted(Some(at(0x1139)))]);
    until("Bob sees Codex's cursor move", || {
        agent_of(&b).is_some_and(|p| p.live_cursor(Instant::now()) == Some(at(0x1139)))
    })
    .await;

    // Cat joins late: Ann's greeting brings Codex and its cursor.
    let c = cat.join(&a, &net, &sent, &ticket).await;
    until("Cat sees Codex at 0x1139", || {
        agent_of(&c).is_some_and(|p| p.agent.is_some() && p.cursor == Some(at(0x1139)))
    })
    .await;

    // Codex disconnects: gone for both.
    a.host_agents(Vec::new());
    until("Bob and Cat see Codex leave", || {
        agent_of(&b).is_none() && agent_of(&c).is_none()
    })
    .await;

    // Back, then removed by the owner: gone again, and not back while
    // still connected.
    a.host_agents(vec![hosted(None)]);
    until("Bob sees Codex back", || agent_of(&b).is_some()).await;
    a.remove(key).unwrap();
    until("Bob sees Codex removed", || agent_of(&b).is_none()).await;
    a.host_agents(vec![hosted(Some(at(0x1140)))]);
    a.chat("after Codex is removed", &[], &[]).unwrap();
    until("Bob has the second message", || b.chat_log().len() == 2).await;
    assert!(agent_of(&b).is_none(), "a removed agent is a participant");

    a.close().await;
    b.close().await;
    c.close().await;
}
