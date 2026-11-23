#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Peers over iroh ([`IrohTransport`]) on this machine:
//!
//! - on the loopback interface, no relay: the identity key is the
//!   endpoint's, the joiner is admitted, edits made on each side reach the
//!   other;
//! - the same with every byte binbun hands the transport, both ways,
//!   captured: none of the plaintext a session holds (names, comments, the
//!   binary's name and hash, the host's name) is in it; the joiner's
//!   name, in its hello, is the only name; the binary the host sends
//!   crosses as a blob, none of
//!   its bytes, name or hash in plaintext on the wire or in the blob the
//!   host keeps;
//! - through a relay only, the joiner having no direct transport at all
//!   (no UDP socket): the session works over the relay path alone.
//! - three joiners on one host, each its own endpoint on this machine:
//!   all admitted and linked, every one's edit reaches every other;
//! - a joiner closed while it dials a host that does not answer says
//!   nothing of the host being unreachable (the dial is ended, not
//!   failed by its endpoint closing).
//!
//! Every joiner is added by the owner, by its identity card, before it
//! connects.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use binbun_collab::blobs::Kind;
use binbun_collab::bounded::Bounded;
use binbun_collab::budgets::{Budgets, Stranger};
use binbun_collab::fetches::Fetches;
use binbun_collab::membership::Role;
use binbun_collab::net::{IrohTransport, NetOptions, Relay};
use binbun_collab::ticket::{Card, JoinTicket, PeerAddr};
use binbun_collab::transport::{BoxFuture, Lane, Link, RecvStream, SendStream};
use binbun_collab::wire::ALPN;
use binbun_collab::{Config, Error, Notice, Peer, Transport};
use binbun_session::identity::Identity;
use binbun_session::journal::{EngineVersion, PublicKey};
use binbun_session::{Options, Session, Stage};
use iroh::endpoint::presets;
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, RelayMode, SecretKey};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The host's name on her card.
const ANN: &str = "Ann Hostname";

/// The joiner's name on his card.
const BOB: &str = "Bob Joinerson";

/// The fixture.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A session on the fixture, its project and identity under `dir`.
fn person(dir: &Path) -> (Identity, Arc<Session>) {
    let _ = fs::remove_dir_all(dir);
    let identity = Identity::load_or_create(&dir.join("identity")).unwrap();
    let session = Session::open(
        fixture(),
        Options {
            project: Some(dir.join("project")),
            identity: Some(dir.join("identity")),
            warm: false,
            ..Options::default()
        },
    )
    .unwrap();
    session.wait(Stage::Analysed, None);
    (identity, Arc::new(session))
}

/// A peer's configuration: `identity` named `name`.
fn config(identity: &Identity, name: &str) -> Config {
    Config {
        identity: identity.clone(),
        name: name.to_owned(),
        approve: None,
        notify: None,
        engine: EngineVersion::this(),
    }
}

/// An endpoint keyed by `identity` on the loopback interface, no relay.
async fn endpoint(identity: &Identity) -> Arc<dyn Transport> {
    let options = NetOptions {
        relay: Relay::Disabled,
        mdns: false,
        portmap: false,
        bind: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    };
    Arc::new(
        IrohTransport::bind(&identity.secret(), &options)
            .await
            .unwrap(),
    )
}

/// The entry of the function `name` in `session`.
fn entry(session: &Session, name: &str) -> u64 {
    let database = session.database().unwrap();
    database
        .functions()
        .find(|(_, f)| session.name(f.entry).as_deref() == Some(name))
        .map(|(_, f)| f.entry)
        .unwrap()
}

/// Waits (up to 30 s) until `done`.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(30), "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `identity`, named `name`, joins `ticket`'s share over `transport`,
/// added by its owner (`host`) as an editor first; once its link syncs
/// (its journal the share's: what it writes before is kept apart).
async fn join(
    host: &Peer,
    (identity, session): &(Identity, Arc<Session>),
    name: &str,
    transport: Arc<dyn Transport>,
    ticket: &JoinTicket,
) -> Peer {
    host.add(&Card::new(identity, name), Role::Editor).unwrap();
    let peer = Peer::join(
        Arc::clone(session),
        transport,
        config(identity, name),
        ticket,
    )
    .await
    .unwrap();
    until("the link syncs", || !peer.readers().is_empty()).await;
    peer
}

/// Ann shares over `host`, Bob joins over `guest`; each renames a
/// function; both see both. The peers and the ticket.
async fn rename_both_ways(
    (ann, ann_session): &(Identity, Arc<Session>),
    bob: &(Identity, Arc<Session>),
    host: Arc<dyn Transport>,
    guest: Arc<dyn Transport>,
) -> (Peer, Peer, JoinTicket) {
    let (classify, checked) = (
        entry(ann_session, "classify"),
        entry(ann_session, "checked"),
    );
    let (a, ticket) = Peer::share(Arc::clone(ann_session), host, config(ann, ANN))
        .await
        .unwrap();
    let ticket: JoinTicket = ticket.to_string().parse().unwrap();
    let b = join(&a, bob, BOB, guest, &ticket).await;
    let bob_session = &bob.1;
    ann_session.rename_function(classify, Some("sort")).unwrap();
    bob_session.rename_function(checked, Some("guard")).unwrap();
    until("the edits cross", || {
        ann_session.name(checked).as_deref() == Some("guard")
            && bob_session.name(classify).as_deref() == Some("sort")
    })
    .await;
    assert_eq!(b.role(), Some(Role::Editor));
    (a, b, ticket)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_peers_sync_over_iroh_on_loopback() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("collab-iroh");
    let (ann, bob) = (person(&dir.join("ann")), person(&dir.join("bob")));
    let host = endpoint(&ann.0).await;
    assert_eq!(host.id(), ann.0.public());
    let guest = endpoint(&bob.0).await;
    let (a, b, ticket) = rename_both_ways(&ann, &bob, host, guest).await;
    assert!(
        ticket
            .host
            .direct
            .iter()
            .all(|addr| addr.ip().is_loopback())
    );
    assert_eq!(ticket.host.relay, None);
    let links = a.links();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].0, bob.0.public());
    assert!(links[0].1.contains("direct 127.0.0.1"), "{}", links[0].1);
    a.close().await;
    b.close().await;
}

/// What a capture holds: per stream (sender, receiver, lane), its bytes.
type Streams = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// A transport whose streams' bytes, both ways, are kept.
struct Capture {
    inner: Arc<dyn Transport>,
    streams: Streams,
}

/// A link of a [`Capture`].
struct CaptureLink {
    inner: Arc<dyn Link>,
    me: PublicKey,
    streams: Streams,
}

/// One direction of a stream, kept at `index` of the capture.
struct Tee<T> {
    inner: T,
    streams: Streams,
    index: usize,
}

impl<T> Tee<T> {
    fn keep(&self, bytes: &[u8]) {
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        streams[self.index].1.extend_from_slice(bytes);
    }
}

impl AsyncWrite for Tee<SendStream> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let written = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = written {
            self.keep(&buf[..n]);
        }
        written
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for Tee<RecvStream> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let read = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = read {
            let bytes = buf.filled()[before..].to_vec();
            self.keep(&bytes);
        }
        read
    }
}

impl CaptureLink {
    /// Keeps a datagram sent (`out`) or received.
    fn keep_datagram(&self, out: bool, bytes: &[u8]) {
        let remote = self.inner.remote();
        let name = if out {
            format!("{} -> {remote} datagrams", self.me)
        } else {
            format!("{remote} -> {} datagrams", self.me)
        };
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        match streams.iter_mut().find(|(n, _)| *n == name) {
            Some((_, kept)) => kept.extend_from_slice(bytes),
            None => streams.push((name, bytes.to_vec())),
        }
    }

    /// `(send, recv)` of `lane` kept.
    fn tee(&self, lane: Lane, send: SendStream, recv: RecvStream) -> (SendStream, RecvStream) {
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        let remote = self.inner.remote();
        streams.push((format!("{} -> {} {lane:?}", self.me, remote), Vec::new()));
        streams.push((format!("{} -> {} {lane:?}", remote, self.me), Vec::new()));
        let index = streams.len() - 2;
        let send = Tee {
            inner: send,
            streams: Arc::clone(&self.streams),
            index,
        };
        let recv = Tee {
            inner: recv,
            streams: Arc::clone(&self.streams),
            index: index + 1,
        };
        (Box::new(send), Box::new(recv))
    }
}

impl Link for CaptureLink {
    fn remote(&self) -> PublicKey {
        self.inner.remote()
    }

    fn open(&self, lane: Lane) -> BoxFuture<'_, Result<(SendStream, RecvStream), Error>> {
        Box::pin(async move {
            let (send, recv) = self.inner.open(lane).await?;
            Ok(self.tee(lane, send, recv))
        })
    }

    fn accept(&self) -> BoxFuture<'_, Result<(Lane, SendStream, RecvStream), Error>> {
        Box::pin(async move {
            let (lane, send, recv) = self.inner.accept().await?;
            let (send, recv) = self.tee(lane, send, recv);
            Ok((lane, send, recv))
        })
    }

    fn path(&self) -> String {
        self.inner.path()
    }

    fn close(&self, reason: &str) {
        self.inner.close(reason);
    }

    fn closed(&self) -> BoxFuture<'_, ()> {
        self.inner.closed()
    }

    fn stranger(&self) -> Option<Stranger> {
        self.inner.stranger()
    }

    // Datagrams (presence) are on the wire too: kept as a stream of their
    // own per direction.
    fn send_datagram(&self, bytes: Vec<u8>) -> Result<(), Error> {
        self.keep_datagram(true, &bytes);
        self.inner.send_datagram(bytes)
    }

    fn recv_datagram(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let bytes = self.inner.recv_datagram().await?;
            self.keep_datagram(false, &bytes);
            Ok(bytes)
        })
    }
}

impl Capture {
    fn wrap(&self, link: Arc<dyn Link>) -> Arc<dyn Link> {
        Arc::new(CaptureLink {
            inner: link,
            me: self.inner.id(),
            streams: Arc::clone(&self.streams),
        })
    }
}

impl Transport for Capture {
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

/// Whether `needle` is anywhere in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_wire_carries_no_plaintext_but_the_joiners_name_in_its_hello() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("collab-wire");
    let (ann, bob) = (person(&dir.join("ann")), person(&dir.join("bob")));
    let streams: Streams = Arc::default();
    let capture = |inner: Arc<dyn Transport>| -> Arc<dyn Transport> {
        Arc::new(Capture {
            inner,
            streams: Arc::clone(&streams),
        })
    };
    let host = capture(endpoint(&ann.0).await);
    let guest = capture(endpoint(&bob.0).await);
    let (a, b, _) = rename_both_ways(&ann, &bob, host, guest).await;
    // More plaintext to keep off the wire: a comment, two more names.
    let loop_sum = entry(&ann.1, "loop_sum");
    ann.1
        .comment(loop_sum, Some("the key schedule lives here"))
        .unwrap();
    bob.1
        .rename_function(loop_sum, Some("expand_key_schedule"))
        .unwrap();
    until("the comment and the name cross", || {
        bob.1.edits() == ann.1.edits()
            && ann.1.name(loop_sum).as_deref() == Some("expand_key_schedule")
    })
    .await;
    // The binary, sent: Ann offers it, Bob fetches it where he chose, its
    // blob in his cache meanwhile.
    let offer = a.offer(Kind::Binary).await.unwrap().offer;
    let [offered] = b.offers(ann.0.public()).await.unwrap().try_into().unwrap();
    assert_eq!(offered, offer);
    let fetched = dir.join("bob").join("fetched");
    let cache = Fetches::at(dir.join("bob").join("cache")).unwrap();
    b.fetch(ann.0.public(), &offer, &cache, &fetched, None)
        .await
        .unwrap();
    assert_eq!(fs::read(&fetched).unwrap(), fs::read(fixture()).unwrap());
    a.close().await;
    b.close().await;
    let key = binbun_session::project::Key::of_file(&fixture()).unwrap();
    let secrets: Vec<(&str, Vec<u8>)> = vec![
        ("a function name", b"sort".to_vec()),
        ("a function name", b"guard".to_vec()),
        ("a function name", b"expand_key_schedule".to_vec()),
        ("the comment", b"the key schedule lives here".to_vec()),
        ("the binary's name", b"program-x86_64.elf".to_vec()),
        ("the binary's SHA-256", key.hex().into_bytes()),
        ("the binary's SHA-256", key.sha256().to_vec()),
        ("the host's name", ANN.as_bytes().to_vec()),
    ];
    let streams = streams.lock().unwrap_or_else(PoisonError::into_inner);
    let total: usize = streams.iter().map(|(_, bytes)| bytes.len()).sum();
    assert!(total > 1000, "a capture of {total} bytes");
    // The binary's distinctive runs: 32 bytes of at least 16 values.
    let binary = fs::read(fixture()).unwrap();
    let runs: Vec<&[u8]> = binary
        .windows(32)
        .step_by(61)
        .filter(|run| run.iter().collect::<std::collections::BTreeSet<_>>().len() >= 16)
        .collect();
    assert!(runs.len() > 20, "{} runs", runs.len());
    let blob_lane = format!("{} -> {} Blob", ann.0.public(), bob.0.public());
    let sent: usize = streams
        .iter()
        .filter(|(stream, _)| *stream == blob_lane)
        .map(|(_, bytes)| bytes.len())
        .sum();
    assert!(sent as u64 > offer.sealed(), "{sent} bytes of blob");
    for (stream, bytes) in streams.iter() {
        for (what, secret) in &secrets {
            assert!(
                !contains(bytes, secret),
                "{what} {:?} in {stream}",
                String::from_utf8_lossy(secret)
            );
        }
        for run in &runs {
            assert!(!contains(bytes, run), "the binary's bytes in {stream}");
        }
    }
    // The capture would have shown a name: Bob's is in his hello, on the
    // control lane from him to Ann, and nowhere else.
    let bob_to_ann = format!("{} -> {} Control", bob.0.public(), ann.0.public());
    let with_bob: Vec<&str> = streams
        .iter()
        .filter(|(_, bytes)| contains(bytes, BOB.as_bytes()))
        .map(|(stream, _)| stream.as_str())
        .collect();
    assert!(
        !with_bob.is_empty() && with_bob.iter().all(|stream| *stream == bob_to_ann),
        "{with_bob:?}"
    );
    // Nor does either peer keep any of it beside the project: the
    // membership chain holds keys, roles and wraps only; the blobs, the
    // binary sealed.
    let secrets: Vec<(&str, Vec<u8>)> = secrets
        .into_iter()
        .chain([("Bob's name", BOB.as_bytes().to_vec())])
        .collect();
    for side in ["ann", "bob"] {
        let files = kept(
            &dir.join(side).join("project").join("collab"),
            &secrets,
            &runs,
        );
        let stored = files
            .iter()
            .any(|file| fs::metadata(file).is_ok_and(|m| m.len() == offer.sealed()));
        assert_eq!(stored, side == "ann", "the blob, at Ann's only: {files:?}");
    }
}

/// The files under `collab` (a membership chain among them), none of
/// which holds any of `secrets` or the binary's `runs`.
fn kept(collab: &Path, secrets: &[(&str, Vec<u8>)], runs: &[&[u8]]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut todo = vec![collab.to_path_buf()];
    while let Some(path) = todo.pop() {
        match fs::read_dir(&path) {
            Ok(entries) => todo.extend(entries.flatten().map(|entry| entry.path())),
            Err(_) => files.push(path),
        }
    }
    assert!(
        files.iter().any(|file| file.ends_with("membership.log")),
        "{files:?}"
    );
    for file in &files {
        let bytes = fs::read(file).unwrap_or_default();
        for (what, secret) in secrets {
            assert!(!contains(&bytes, secret), "{what} in {}", file.display());
        }
        for run in runs {
            assert!(
                !contains(&bytes, run),
                "the binary's bytes in {}",
                file.display()
            );
        }
    }
    files
}

/// An endpoint keyed by `identity` whose only relay is `relays` (trusted
/// unchecked), with direct transports on the loopback interface if
/// `direct`, else none at all: no UDP socket, the relay its only path.
async fn relayed(identity: &Identity, relays: &iroh::RelayMap, direct: bool) -> Arc<dyn Transport> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&identity.secret()))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Custom(relays.clone()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .clear_ip_transports();
    if direct {
        builder = builder
            .bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
    }
    let endpoint = builder.bind().await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), endpoint.online())
        .await
        .unwrap();
    Arc::new(IrohTransport::from_endpoint(endpoint))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_with_no_direct_path_syncs_through_a_relay() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("collab-relay");
    let (ann, bob) = (person(&dir.join("ann")), person(&dir.join("bob")));
    let (relays, url, _server) = iroh::test_utils::run_relay_server_with(false)
        .await
        .unwrap();
    let host = relayed(&ann.0, &relays, true).await;
    let guest = relayed(&bob.0, &relays, false).await;
    // Bob has no address but the relay's.
    assert_eq!(guest.addr().direct, Vec::<SocketAddr>::new());
    assert_eq!(
        guest.addr().relay.as_deref(),
        Some(url.to_string().as_str())
    );
    let (a, b, ticket) = rename_both_ways(&ann, &bob, host, guest).await;
    assert_eq!(ticket.host.relay.as_deref(), Some(url.to_string().as_str()));
    for (peer, other) in [(&a, bob.0.public()), (&b, ann.0.public())] {
        let links = peer.links();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].0, other);
        let path = &links[0].1;
        assert!(
            path.contains("relay ") && !path.contains("direct"),
            "{path}"
        );
    }
    a.close().await;
    b.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_joiners_on_one_host_over_iroh_on_loopback_all_sync() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-iroh-three-{}", std::process::id()));
    let ann = person(&dir.join("ann"));
    let (a, ticket) = Peer::share(
        Arc::clone(&ann.1),
        endpoint(&ann.0).await,
        config(&ann.0, ANN),
    )
    .await
    .unwrap();
    let ticket: JoinTicket = ticket.to_string().parse().unwrap();
    // Each joiner renames a function of its own, once all are in.
    let renames = [
        ("Bob", "classify", "sort"),
        ("Cy", "checked", "guard"),
        ("Di", "loop_sum", "total"),
    ];
    let mut joiners = Vec::new();
    for (name, _, _) in renames {
        let joiner = person(&dir.join(name));
        let transport = endpoint(&joiner.0).await;
        let peer = join(&a, &joiner, name, transport, &ticket).await;
        let (identity, session) = joiner;
        joiners.push((identity, session, peer));
    }
    until("all three are linked to the host", || a.links().len() == 3).await;
    for (_, _, peer) in &joiners {
        until("each is admitted", || peer.role() == Some(Role::Editor)).await;
    }
    let wanted: Vec<(u64, &str)> = renames
        .iter()
        .map(|(_, old, new)| (entry(&ann.1, old), *new))
        .collect();
    for ((_, session, _), (at, new)) in joiners.iter().zip(&wanted) {
        session.rename_function(*at, Some(new)).unwrap();
    }
    let sessions: Vec<&Arc<Session>> = std::iter::once(&ann.1)
        .chain(joiners.iter().map(|(_, session, _)| session))
        .collect();
    until("every rename reaches every peer", || {
        sessions.iter().all(|session| {
            wanted
                .iter()
                .all(|(at, new)| session.name(*at).as_deref() == Some(*new))
        })
    })
    .await;
    let mut linked: Vec<PublicKey> = a.links().into_iter().map(|(key, _)| key).collect();
    let mut expected: Vec<PublicKey> = joiners.iter().map(|(id, _, _)| id.public()).collect();
    linked.sort_by_key(|key| key.0);
    expected.sort_by_key(|key| key.0);
    assert_eq!(linked, expected);
    for (_, _, peer) in joiners {
        peer.close().await;
    }
    a.close().await;
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_closed_while_dialling_says_nothing_of_the_host() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-iroh-closed-{}", std::process::id()));
    let (ann, ann_session) = person(&dir.join("ann"));
    let (bob, bob_session) = person(&dir.join("bob"));
    // Ann's ticket, her address made a loopback port nobody answers on.
    let (a, ticket) = Peer::share(ann_session, endpoint(&ann).await, config(&ann, ANN))
        .await
        .unwrap();
    a.close().await;
    let silent = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ticket = JoinTicket {
        host: PeerAddr {
            direct: Bounded::truncated(vec![silent.local_addr().unwrap()]),
            ..ticket.host
        },
        ..ticket
    };
    let heard: Arc<Mutex<Vec<Notice>>> = Arc::default();
    let notices = Arc::clone(&heard);
    let config = Config {
        notify: Some(Arc::new(move |notice: &Notice| {
            notices.lock().unwrap().push(notice.clone());
        })),
        ..config(&bob, BOB)
    };
    let b = Peer::join(bob_session, endpoint(&bob).await, config, &ticket)
        .await
        .unwrap();
    // The dial is under way (the host's silence makes it wait).
    tokio::time::sleep(Duration::from_millis(300)).await;
    b.close().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let heard = heard.lock().unwrap().clone();
    assert!(
        !heard
            .iter()
            .any(|notice| matches!(notice, Notice::Unlinked { .. })),
        "{heard:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}
