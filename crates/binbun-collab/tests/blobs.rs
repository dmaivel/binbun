#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Files by hash:
//!
//! - a binary the host offers crosses to a joiner who lacks it, sealed,
//!   over iroh on the loopback interface: a fetch cut short goes on where
//!   it stopped, a range tampered with on the way is refused and nothing
//!   past it kept, the file opened is the host's (SHA-256); the blob the
//!   host keeps is the Padmé size of the file's and holds none of its
//!   plaintext; the joiner then joins with it, its changes taken. The
//!   binary is the units fixture grown by `BINBUN_BLOB_MB` megabytes (64
//!   by default; 940 for the acceptance run) of data no two chunks of
//!   which are alike;
//! - a debug file fetched from the peer whose analysis read it makes the
//!   two analyses' fingerprints match again; one who visits without
//!   joining is offered the binary the share names and nothing else, and
//!   is not served the debug file;
//! - an offer whose blob is larger than it says is refused within its
//!   size, and one that does not open into the file offered is refused;
//!   neither leaves anything fetched;
//! - a file fetched never replaces another at the name asked for: it goes
//!   beside it, unless that holds the same bytes; nor one by the name a
//!   fetch once wrote until whole; a second fetch of a blob while one
//!   works is refused, and the first writes it whole;
//! - a fetch keeps its blob in the cache alone, its file only where it
//!   was asked to go, whatever name it was offered under (`project.toml`,
//!   `../x`); a directory named as fetches once named theirs stays;
//! - a frame claiming many bytes and sending few is read into room for
//!   those few.
//!
//! Every joiner and visitor is added by the owner before it connects.

use std::fs;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use binbun_collab::blob;
use binbun_collab::blobs::{Fetched, Kind, Offer, OnProgress, Step, Visit};
use binbun_collab::bounded::Text;
use binbun_collab::budgets::Budgets;
use binbun_collab::fetches::Fetches;
use binbun_collab::mem::MemNet;
use binbun_collab::membership::Role;
use binbun_collab::net::{IrohTransport, NetOptions, Relay};
use binbun_collab::ticket::{Card, JoinTicket, PeerAddr};
use binbun_collab::transport::{
    BoxFuture, Lane, Link, RecvStream, SendStream, read_bytes, read_frame_length,
};
use binbun_collab::{Config, Error, Peer, Transport};
use binbun_session::identity::Identity;
use binbun_session::journal::{EngineVersion, PublicKey};
use binbun_session::{DebugSource, Options, Session, Stage, Waited};
use binbun_sync::wire::FRAME;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A fixture.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// A directory of the test's own, empty.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-blobs-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A session on `file` (its project and identity under `home`) reading
/// debug information as `debug` says, once analysed.
fn open(home: &Path, file: &Path, debug: DebugSource) -> (Identity, Arc<Session>) {
    let identity = Identity::load_or_create(&home.join("identity")).unwrap();
    let session = Session::open(
        file,
        Options {
            project: Some(home.join("project")),
            identity: Some(home.join("identity")),
            warm: false,
            debug,
            ..Options::default()
        },
    )
    .unwrap();
    match session.wait(Stage::Analysed, None) {
        Waited::Reached(_) => {}
        other @ (Waited::Stopped { .. } | Waited::TimedOut(_)) => {
            panic!("{}: {other:?}", file.display())
        }
    }
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

/// Waits (up to 60 s) until `done`.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(60), "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The next of a stream of numbers no run of which repeats (xorshift).
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// The units fixture grown by `megabytes` of data no two chunks of
/// which are alike, at `path`: an executable still (its loader ignores
/// what follows its segments).
fn grown(path: &Path, megabytes: u64) {
    let mut file = std::io::BufWriter::new(fs::File::create(path).unwrap());
    file.write_all(&fs::read(fixture("units-x86_64.elf")).unwrap())
        .unwrap();
    let mut state = 0x2545_f491_4f6c_dd1d;
    let mut buffer = vec![0u8; 1 << 20];
    for _ in 0..megabytes {
        for word in buffer.as_chunks_mut::<8>().0 {
            word.copy_from_slice(&next(&mut state).to_le_bytes());
        }
        file.write_all(&buffer).unwrap();
    }
    file.flush().unwrap();
}

/// The file's SHA-256.
fn sha256(path: &Path) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, &fs::read(path).unwrap());
    digest.as_ref().try_into().unwrap()
}

/// Every file under `dir`.
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(path) = todo.pop() {
        match fs::read_dir(&path) {
            Ok(entries) => todo.extend(entries.flatten().map(|entry| entry.path())),
            Err(_) => found.push(path),
        }
    }
    found
}

/// The blobs' directories left in `cache` (each fetch's lock file
/// stays beside them).
fn left(cache: &Fetches) -> Vec<PathBuf> {
    fs::read_dir(cache.root())
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect()
}

/// Whether any of the 32-byte `runs` is anywhere in `haystack` (each
/// offset looked at once, by the runs' first eight bytes).
fn holds_any(haystack: &[u8], runs: &[[u8; 32]]) -> bool {
    let starts: std::collections::HashSet<u64> = runs
        .iter()
        .map(|run| u64::from_le_bytes(run[..8].try_into().unwrap()))
        .collect();
    haystack.windows(32).any(|window| {
        starts.contains(&u64::from_le_bytes(window[..8].try_into().unwrap()))
            && runs.iter().any(|run| run == window)
    })
}

/// The host's side of blob streams, counted (bytes sent to joiners), one
/// byte flipped at an offset of the next one when armed, the next one
/// paced (bytes a second) when asked.
#[derive(Clone, Default)]
struct Wire {
    sent: Arc<AtomicU64>,
    flip_at: Arc<Mutex<Option<u64>>>,
    pace: Arc<AtomicU64>,
}

/// A transport whose links' blob streams go through a [`Wire`].
struct Watched {
    inner: Arc<dyn Transport>,
    wire: Wire,
}

/// A link of a [`Watched`] transport.
struct WatchedLink {
    inner: Arc<dyn Link>,
    wire: Wire,
}

/// The sending half of a blob stream the host serves.
struct Served {
    inner: SendStream,
    wire: Wire,
    /// This stream's bytes so far.
    written: u64,
    /// Where this stream flips a byte, if it does.
    flip_at: Option<u64>,
    /// Its bytes a second at most (0: as fast as it goes).
    pace: u64,
    began: Instant,
    waiting: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl AsyncWrite for Served {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(micros) = (self.written * 1_000_000).checked_div(self.pace) {
            let due = self.began + Duration::from_micros(micros);
            if Instant::now() < due {
                let waiting = self
                    .waiting
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(due.into())));
                if waiting.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
            }
            self.waiting = None;
        }
        let mut bytes = buf.to_vec();
        if let Some(at) = self.flip_at
            && at >= self.written
            && at < self.written + bytes.len() as u64
        {
            bytes[usize::try_from(at - self.written).unwrap()] ^= 0x40;
        }
        let written = Pin::new(&mut self.inner).poll_write(cx, &bytes);
        if let Poll::Ready(Ok(n)) = written {
            if self.flip_at.is_some_and(|at| at < self.written + n as u64) {
                self.flip_at = None;
            }
            self.written += n as u64;
            self.wire.sent.fetch_add(n as u64, Ordering::Relaxed);
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

impl Link for WatchedLink {
    fn remote(&self) -> PublicKey {
        self.inner.remote()
    }

    fn open(&self, lane: Lane) -> BoxFuture<'_, Result<(SendStream, RecvStream), Error>> {
        self.inner.open(lane)
    }

    fn accept(&self) -> BoxFuture<'_, Result<(Lane, SendStream, RecvStream), Error>> {
        Box::pin(async move {
            let (lane, send, recv) = self.inner.accept().await?;
            if lane != Lane::Blob {
                return Ok((lane, send, recv));
            }
            let flip_at = self
                .wire
                .flip_at
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let served = Served {
                inner: send,
                wire: self.wire.clone(),
                written: 0,
                flip_at,
                pace: self.wire.pace.swap(0, Ordering::Relaxed),
                began: Instant::now(),
                waiting: None,
            };
            Ok((lane, Box::new(served) as SendStream, recv))
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

    fn send_datagram(&self, bytes: Vec<u8>) -> Result<(), Error> {
        self.inner.send_datagram(bytes)
    }

    fn recv_datagram(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        self.inner.recv_datagram()
    }
}

impl Transport for Watched {
    fn id(&self) -> PublicKey {
        self.inner.id()
    }

    fn addr(&self) -> PeerAddr {
        self.inner.addr()
    }

    fn connect<'a>(&'a self, to: &'a PeerAddr) -> BoxFuture<'a, Result<Arc<dyn Link>, Error>> {
        self.inner.connect(to)
    }

    fn accept(&self) -> BoxFuture<'_, Option<Arc<dyn Link>>> {
        Box::pin(async move {
            let link = self.inner.accept().await?;
            Some(Arc::new(WatchedLink {
                inner: link,
                wire: self.wire.clone(),
            }) as Arc<dyn Link>)
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        self.inner.close()
    }

    fn budgets(&self) -> &Budgets {
        self.inner.budgets()
    }
}

/// Megabytes per second.
fn rate(bytes: u64, time: Duration) -> f64 {
    f64::from(u32::try_from(bytes / 1000).unwrap()) / 1e3 / time.as_secs_f64()
}

/// Checks the blob kept beside the project under `collab` for `offer` of
/// the file `binary`: the Padmé size of the file's, once, none of the
/// file's bytes in it nor in any other file there.
fn kept_sealed(collab: &Path, binary: &Path, offer: &Offer) {
    let length = fs::metadata(binary).unwrap().len();
    let padded = blob::padme(length);
    assert_eq!(
        offer.sealed(),
        blob::HEADER as u64 + padded + 16 * padded.div_ceil(blob::CHUNK as u64)
    );
    let plain = fs::read(binary).unwrap();
    let mut state = 7;
    let runs: Vec<[u8; 32]> = (0..64)
        .map(|_| {
            let at = usize::try_from(next(&mut state) % (length - 32)).unwrap();
            plain[at..at + 32].try_into().unwrap()
        })
        .chain([plain[..32].try_into().unwrap()])
        .collect();
    drop(plain);
    let kept = files(collab);
    let stored: Vec<&PathBuf> = kept
        .iter()
        .filter(|file| fs::metadata(file).unwrap().len() == offer.sealed())
        .collect();
    assert_eq!(stored.len(), 1, "the blob, once: {kept:?}");
    for file in &kept {
        assert!(
            !holds_any(&fs::read(file).unwrap(), &runs),
            "plaintext in {}",
            file.display()
        );
    }
}

/// Fetches `offer` on `visit` into `to` (the blob in `cache` meanwhile)
/// three times over the host's `wire`: cut short at 40 %, then refused at
/// 70 % (a byte flipped on the way), then whole; what the last came to.
async fn fetched_after_a_cut_and_a_tamper(
    visit: &Visit,
    offer: &Offer,
    wire: &Wire,
    cache: &Fetches,
    to: &Path,
) -> Fetched {
    // Cut short at 40 %, two seconds in: the fetch dropped, as a receiver
    // killed (what a store took in its last half second is lost then).
    wire.pace.store(offer.sealed() / 5, Ordering::Relaxed);
    let cut = Arc::new(tokio::sync::Notify::new());
    let progress: OnProgress = {
        let cut = Arc::clone(&cut);
        let total = offer.sealed();
        Arc::new(move |progress| {
            if progress.step == Step::Fetching && progress.done * 10 >= total * 4 {
                cut.notify_one();
            }
        })
    };
    let started = Instant::now();
    tokio::select! {
        fetched = visit.fetch(offer, cache, to, Some(progress)) => panic!("not cut: {fetched:?}"),
        () = cut.notified() => {}
    }
    let first = wire.sent.swap(0, Ordering::Relaxed);
    eprintln!(
        "cut after {first} bytes sent in {:.2?} ({:.0} MB/s)",
        started.elapsed(),
        rate(first, started.elapsed())
    );
    assert!(!to.exists());

    // Going on, a byte flipped on the way at 70 %: refused there, and what
    // came before it kept.
    let flip = offer.sealed() * 7 / 10 - first;
    *wire.flip_at.lock().unwrap() = Some(flip);
    let refused = visit.fetch(offer, cache, to, None).await.unwrap_err();
    let second = wire.sent.swap(0, Ordering::Relaxed);
    eprintln!("refused after {second} more bytes: {refused}");
    let why = refused.to_string();
    assert!(
        why.starts_with("the binary from ") && why.contains("does not match the blob's hash"),
        "{why}"
    );
    assert!(second < offer.sealed() * 4 / 10, "{second}");
    assert!(!to.exists());

    // Going on again: the rest only, and the file is Ann's.
    let fetched = visit.fetch(offer, cache, to, None).await.unwrap();
    let third = wire.sent.swap(0, Ordering::Relaxed);
    eprintln!(
        "fetched: {} bytes here before, {} received ({third} sent with the protocol's) in \
         {:.2?} ({:.0} MB/s); opened in {:.2?} ({:.0} MB/s), AEAD {:.2?}",
        fetched.had,
        fetched.received,
        fetched.fetching,
        rate(fetched.received, fetched.fetching),
        fetched.opening,
        rate(offer.length, fetched.opening),
        fetched.crypto
    );
    assert!(fetched.had >= offer.sealed() * 65 / 100, "{}", fetched.had);
    assert!(third < offer.sealed() * 35 / 100, "re-sent {third}");
    assert_eq!(fetched.had + fetched.received, offer.sealed());
    fetched
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_binary_crosses_sealed_goes_on_after_a_cut_and_refuses_a_range_tampered_with() {
    let megabytes: u64 = std::env::var("BINBUN_BLOB_MB")
        .ok()
        .and_then(|mb| mb.parse().ok())
        .unwrap_or(64);
    let dir = scratch("binary");
    let binary = dir.join("ann").join("big-units");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    grown(&binary, megabytes);
    let (ann, ann_session) = open(&dir.join("ann"), &binary, DebugSource::Without);
    let wire = Wire::default();
    let host: Arc<dyn Transport> = Arc::new(Watched {
        inner: endpoint(&ann).await,
        wire: wire.clone(),
    });
    let (a, ticket) = Peer::share(Arc::clone(&ann_session), host, config(&ann, "Ann"))
        .await
        .unwrap();
    let prepared = a.offer(Kind::Binary).await.unwrap();
    assert!(!prepared.kept);
    let offer = prepared.offer;
    eprintln!(
        "sealed {} bytes in {:.2?} ({:.0} MB/s), AEAD {:.2?} ({:.0} MB/s)",
        offer.length,
        prepared.sealing,
        rate(offer.length, prepared.sealing),
        prepared.crypto,
        rate(offer.length, prepared.crypto)
    );
    // Offering it again offers the same blob, kept.
    let again = a.offer(Kind::Binary).await.unwrap();
    assert!(again.kept && again.offer == offer);

    // Bob, who lacks the binary, added by Ann, visits: the chain names
    // Ann's binary, and she offers it.
    let bob_home = dir.join("bob");
    let bob = Identity::load_or_create(&bob_home.join("identity")).unwrap();
    a.add(&Card::new(&bob, "Bob"), Role::Editor).unwrap();
    let guest = endpoint(&bob).await;
    let visit = Visit::new(&guest, &config(&bob, "Bob"), &ticket)
        .await
        .unwrap();
    assert_eq!(
        visit.binary().map(|named| named.sha256),
        Some(sha256(&binary))
    );
    assert_eq!(visit.offers().await.unwrap(), vec![offer.clone()]);
    let cache = Fetches::at(bob_home.join("cache")).unwrap();
    let to = bob_home.join("big-units");
    fetched_after_a_cut_and_a_tamper(&visit, &offer, &wire, &cache, &to).await;
    assert_eq!(sha256(&to), sha256(&binary));
    assert_eq!(
        left(&cache),
        Vec::<PathBuf>::new(),
        "the fetched blob is dropped once opened"
    );
    visit.close();

    // Bob joins with the binary fetched, as a member at once; once his
    // link syncs his journal is the share's, so his edits are taken.
    let (_, bob_session) = open(&bob_home, &to, DebugSource::Without);
    let b = Peer::join(
        Arc::clone(&bob_session),
        guest,
        config(&bob, "Bob"),
        &ticket,
    )
    .await
    .unwrap();
    until("Bob's link syncs", || !b.readers().is_empty()).await;
    let entry = bob_session
        .database()
        .unwrap()
        .functions()
        .map(|(_, f)| f.entry)
        .next()
        .unwrap();
    bob_session
        .rename_function(entry, Some("fetched_then_named"))
        .unwrap();
    until("Bob's rename reaches Ann", || {
        ann_session.name(entry).as_deref() == Some("fetched_then_named")
    })
    .await;
    a.close().await;
    b.close().await;
    drop((ann_session, bob_session));
    // What Ann keeps is read once her store is closed: its database is
    // locked while open, which Windows enforces on reads too.
    kept_sealed(
        &dir.join("ann").join("project").join("collab"),
        &binary,
        &offer,
    );
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_being_served_stops_within_a_mebibyte_of_its_fetchers_removal() {
    let dir = scratch("fenced");
    let binary = dir.join("ann").join("big-units");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    grown(&binary, 16);
    let (ann, ann_session) = open(&dir.join("ann"), &binary, DebugSource::Without);
    let wire = Wire::default();
    let host: Arc<dyn Transport> = Arc::new(Watched {
        inner: endpoint(&ann).await,
        wire: wire.clone(),
    });
    let (a, ticket) = Peer::share(Arc::clone(&ann_session), host, config(&ann, "Ann"))
        .await
        .unwrap();
    let offer = a.offer(Kind::Binary).await.unwrap().offer;
    // Bob, added, visits for the binary; his visit reads nothing on its
    // control lane, so a kick there does not end the link.
    let bob_home = dir.join("bob");
    let bob = Identity::load_or_create(&bob_home.join("identity")).unwrap();
    a.add(&Card::new(&bob, "Bob"), Role::Editor).unwrap();
    let visit = Visit::new(&endpoint(&bob).await, &config(&bob, "Bob"), &ticket)
        .await
        .unwrap();
    let cache = Fetches::at(bob_home.join("cache")).unwrap();
    let to = bob_home.join("big-units");
    // Served at 4 MB a second; Bob removed once 2 MiB have come.
    wire.pace.store(4_000_000, Ordering::Relaxed);
    let begun = Arc::new(tokio::sync::Notify::new());
    let progress: OnProgress = {
        let begun = Arc::clone(&begun);
        Arc::new(move |progress| {
            if progress.step == Step::Fetching && progress.done >= 2 << 20 {
                begun.notify_one();
            }
        })
    };
    let (fetched, removed) = {
        let fetch = visit.fetch(&offer, &cache, &to, Some(progress));
        tokio::pin!(fetch);
        tokio::select! {
            fetched = &mut fetch => panic!("not removed in time: {fetched:?}"),
            () = begun.notified() => {}
        }
        a.remove(bob.public()).unwrap();
        let removed = wire.sent.load(Ordering::Relaxed);
        let fetched = tokio::time::timeout(Duration::from_secs(20), fetch)
            .await
            .expect("the fetch ends");
        (fetched, removed)
    };
    assert!(fetched.is_err(), "{fetched:?}");
    let after = wire.sent.load(Ordering::Relaxed) - removed;
    assert!(after <= 1 << 20, "{after} bytes served past the removal");
    assert!(!to.exists());
    visit.close();
    a.close().await;
    drop(ann_session);
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_member_visiting_takes_the_records_of_its_removal() {
    let dir = scratch("visit-kick");
    let units = fixture("units-x86_64.elf");
    let (ann, ann_session) = open(&dir.join("ann"), &units, DebugSource::Without);
    let net = MemNet::new();
    let (a, ticket) = Peer::share(
        Arc::clone(&ann_session),
        Arc::new(net.endpoint(ann.public())),
        config(&ann, "Ann"),
    )
    .await
    .unwrap();
    let bob = Identity::ephemeral().unwrap();
    a.add(&Card::new(&bob, "Bob"), Role::Editor).unwrap();
    a.remove(bob.public()).unwrap();
    let removal = a.membership().seq();
    let dan = Identity::ephemeral().unwrap();
    a.add(&Card::new(&dan, "Dan"), Role::Editor).unwrap();
    // Put out, the visit verifies the records through his removal.
    let guest: Arc<dyn Transport> = Arc::new(net.endpoint(bob.public()));
    let refused = Visit::new(&guest, &config(&bob, "Bob"), &ticket)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        refused.ends_with(&format!("membership record {removal} says")),
        "{refused}"
    );
    a.close().await;
    drop(ann_session);
    let _ = fs::remove_dir_all(&dir);
}

/// One the owner of `host`'s share added, visiting by `ticket` over
/// `net` without joining (a cache in `home`), is offered nothing until
/// the binary the share names is offered, then that alone, and is not
/// served the debug file `debug` offered.
async fn visitor_is_offered_the_binary_alone(
    host: &Peer,
    net: &MemNet,
    ticket: &JoinTicket,
    debug: &Offer,
    home: &Path,
) {
    let cat = Identity::ephemeral().unwrap();
    host.add(&Card::new(&cat, "Cat"), Role::Editor).unwrap();
    let guest: Arc<dyn Transport> = Arc::new(net.endpoint(cat.public()));
    let visit = Visit::new(&guest, &config(&cat, "Cat"), ticket)
        .await
        .unwrap();
    assert_eq!(visit.offers().await.unwrap(), Vec::<Offer>::new());
    fs::create_dir_all(home).unwrap();
    let cache = Fetches::at(home.join("cache")).unwrap();
    let denied = home.join("units-x86_64.debug");
    let refused = visit.fetch(debug, &cache, &denied, None).await.unwrap_err();
    assert!(
        refused.to_string().contains("only the binary shared"),
        "{refused}"
    );
    assert!(!denied.exists());
    let binary = host.offer(Kind::Binary).await.unwrap().offer;
    assert_eq!(visit.offers().await.unwrap(), vec![binary]);
    host.withdraw(Kind::Binary);
    assert_eq!(visit.offers().await.unwrap(), Vec::<Offer>::new());
    visit.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_debug_file_fetched_from_a_peer_makes_the_fingerprints_match() {
    let dir = scratch("debug");
    let units = fixture("units-x86_64.elf");
    let (ann, ann_session) = open(
        &dir.join("ann"),
        &units,
        DebugSource::Path(fixture("units-x86_64.debug")),
    );
    let (bob, bob_session) = open(&dir.join("bob"), &units, DebugSource::Without);
    let (theirs, mine) = (
        ann_session.fingerprint().unwrap(),
        bob_session.fingerprint().unwrap(),
    );
    assert_ne!(theirs.analysis, mine.analysis);
    assert_eq!(mine.debug, None);
    let net = MemNet::new();
    let (a, ticket) = Peer::share(
        Arc::clone(&ann_session),
        Arc::new(net.endpoint(ann.public())),
        config(&ann, "Ann"),
    )
    .await
    .unwrap();
    a.add(&Card::new(&bob, "Bob"), Role::Editor).unwrap();
    let b = Peer::join(
        Arc::clone(&bob_session),
        Arc::new(net.endpoint(bob.public())),
        config(&bob, "Bob"),
        &ticket,
    )
    .await
    .unwrap();
    // In: his link syncs (before, only the binary the share names is
    // offered on it).
    until("Bob's link syncs", || !b.readers().is_empty()).await;
    // Not offered: neither listed nor served.
    assert_eq!(b.offers(ann.public()).await.unwrap(), Vec::<Offer>::new());
    a.offer(Kind::DebugFile).await.unwrap();
    let offers = b.offers(ann.public()).await.unwrap();
    let [offer] = offers.as_slice() else {
        panic!("{offers:?}")
    };
    assert_eq!(
        (offer.kind, &*offer.name, Some(offer.sha256)),
        (
            Kind::DebugFile,
            "units-x86_64.debug",
            theirs.debug.as_ref().map(|debug| debug.sha256)
        )
    );
    let to = dir.join("bob").join("units-x86_64.debug");
    let cache = Fetches::at(dir.join("bob").join("cache")).unwrap();
    let told = Arc::new(AtomicBool::new(false));
    let progress: OnProgress = {
        let told = Arc::clone(&told);
        Arc::new(move |progress| {
            if progress.step == Step::Opening && progress.done == progress.total {
                told.store(true, Ordering::Relaxed);
            }
        })
    };
    b.fetch(ann.public(), offer, &cache, &to, Some(progress))
        .await
        .unwrap();
    assert!(told.load(Ordering::Relaxed));
    assert_eq!(
        fs::read(&to).unwrap(),
        fs::read(fixture("units-x86_64.debug")).unwrap()
    );
    // Analysed again with it: the fingerprints match.
    let again = Arc::new(bob_session.with_debug(&to).unwrap());
    again.wait(Stage::Analysed, None);
    b.set_session(Arc::clone(&again));
    assert_eq!(again.fingerprint().unwrap(), theirs);
    visitor_is_offered_the_binary_alone(&a, &net, &ticket, offer, &dir.join("cat")).await;
    // Withdrawn: no longer offered, nor served.
    a.withdraw(Kind::DebugFile);
    assert_eq!(b.offers(ann.public()).await.unwrap(), Vec::<Offer>::new());
    let refused = b
        .fetch(
            ann.public(),
            offer,
            &cache,
            &dir.join("bob").join("again.debug"),
            None,
        )
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("not offered"), "{refused}");
    a.close().await;
    b.close().await;
    let _ = fs::remove_dir_all(&dir);
}

/// Ann sharing a binary she offers (the units fixture grown by a
/// megabyte), her blob streams through `wire`, and Bob visiting her.
struct Visited {
    dir: PathBuf,
    binary: PathBuf,
    ann: Peer,
    /// Keeps Bob's endpoint for the visit.
    _guest: Arc<dyn Transport>,
    visit: Visit,
    offer: Offer,
    wire: Wire,
}

/// [`Visited`], over a [`MemNet`], in a scratch directory `name`.
async fn visited(name: &str) -> Visited {
    let dir = scratch(name);
    let binary = dir.join("ann").join("grown");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    grown(&binary, 1);
    let (ann, session) = open(&dir.join("ann"), &binary, DebugSource::Without);
    let net = MemNet::new();
    let wire = Wire::default();
    let host: Arc<dyn Transport> = Arc::new(Watched {
        inner: Arc::new(net.endpoint(ann.public())),
        wire: wire.clone(),
    });
    let (a, ticket) = Peer::share(session, host, config(&ann, "Ann"))
        .await
        .unwrap();
    let offer = a.offer(Kind::Binary).await.unwrap().offer;
    let bob = Identity::load_or_create(&dir.join("bob").join("identity")).unwrap();
    a.add(&Card::new(&bob, "Bob"), Role::Editor).unwrap();
    let guest: Arc<dyn Transport> = Arc::new(net.endpoint(bob.public()));
    let visit = Visit::new(&guest, &config(&bob, "Bob"), &ticket)
        .await
        .unwrap();
    assert_eq!(visit.offers().await.unwrap(), vec![offer.clone()]);
    Visited {
        dir,
        binary,
        ann: a,
        _guest: guest,
        visit,
        offer,
        wire,
    }
}

/// The files a fetch writes in `dir` until whole (`.binbun-<random>.part`)
/// left there.
fn staged(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name.starts_with(".binbun-") && name.ends_with(".part")
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offer_smaller_than_its_blob_or_not_its_file_is_refused_and_nothing_kept() {
    let Visited {
        dir,
        binary,
        ann,
        _guest,
        visit,
        offer,
        wire,
    } = visited("refused").await;
    let cache = Fetches::at(dir.join("bob").join("cache")).unwrap();
    let to = dir.join("bob").join("grown");

    // An offer of a file of a few kilobytes naming a blob of a megabyte:
    // refused within the size it says, and nothing of it kept.
    let small = Offer {
        length: 4000,
        ..offer.clone()
    };
    assert!(offer.sealed() > 200 * small.sealed());
    wire.sent.store(0, Ordering::Relaxed);
    let refused = visit.fetch(&small, &cache, &to, None).await.unwrap_err();
    let sent = wire.sent.swap(0, Ordering::Relaxed);
    // Its size, the rest of the BLAKE3 chunk group it ends in (16 KiB),
    // the tree's hashes and the frames: no more.
    assert!(sent < small.sealed() + (32 << 10), "{sent} bytes sent");
    assert!(refused.to_string().contains("refused"), "{refused}");
    assert_eq!(left(&cache), Vec::<PathBuf>::new());
    assert!(!to.exists() && staged(&dir.join("bob")).is_empty());

    // An offer naming the blob but another file (its SHA-256): fetched,
    // refused once opened, and the blob dropped with the file.
    let other = Offer {
        sha256: [7; 32],
        ..offer.clone()
    };
    let refused = visit.fetch(&other, &cache, &to, None).await.unwrap_err();
    assert!(
        refused.to_string().contains("not the one offered"),
        "{refused}"
    );
    assert_eq!(left(&cache), Vec::<PathBuf>::new());
    assert!(!to.exists() && staged(&dir.join("bob")).is_empty());

    // The offer as it is: the file, whole.
    let fetched = visit.fetch(&offer, &cache, &to, None).await.unwrap();
    assert_eq!(fetched.path, to);
    assert_eq!(sha256(&to), sha256(&binary));
    assert!(left(&cache).is_empty() && staged(&dir.join("bob")).is_empty());
    visit.close();
    ann.close().await;
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_fetched_never_replaces_another_at_its_name() {
    let Visited {
        dir,
        binary,
        ann,
        _guest,
        visit,
        offer,
        wire: _,
    } = visited("beside").await;
    let bob = dir.join("bob");
    let cache = Fetches::at(bob.join("cache")).unwrap();

    // An earlier download of another file by that name stays; the file
    // fetched goes beside it.
    let to = bob.join("grown.elf");
    fs::write(&to, b"an earlier download").unwrap();
    let beside = bob.join("grown (2).elf");
    let fetched = visit.fetch(&offer, &cache, &to, None).await.unwrap();
    assert_eq!(fetched.path, beside);
    assert_eq!(fs::read(&to).unwrap(), b"an earlier download");
    assert_eq!(sha256(&beside), sha256(&binary));

    // Fetched again: the copy beside, of the same bytes, is the one; no
    // third.
    let again = visit.fetch(&offer, &cache, &to, None).await.unwrap();
    assert_eq!(again.path, beside);
    assert!(!bob.join("grown (3).elf").exists());
    assert_eq!(fs::read(&to).unwrap(), b"an earlier download");

    // At a name free, then fetched there again: in place both times.
    let free = bob.join("grown");
    for _ in 0..2 {
        let fetched = visit.fetch(&offer, &cache, &free, None).await.unwrap();
        assert_eq!(fetched.path, free);
        assert_eq!(sha256(&free), sha256(&binary));
    }
    assert!(!bob.join("grown (2)").exists());
    assert_eq!(staged(&bob), Vec::<PathBuf>::new());
    visit.close();
    ann.close().await;
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_leaves_the_files_beside_its_name_alone_and_fetches_of_a_blob_at_once_do_not_meet()
{
    let Visited {
        dir,
        binary,
        ann,
        _guest,
        visit,
        offer,
        wire: _,
    } = visited("staging").await;
    let bob = dir.join("bob");
    let cache = Fetches::at(bob.join("cache")).unwrap();

    // A file by the name a fetch once wrote until whole stays.
    let to = bob.join("grown");
    let mut beside = to.as_os_str().to_owned();
    beside.push(".binbun-part");
    let beside = PathBuf::from(beside);
    fs::write(&beside, b"an earlier download").unwrap();
    let fetched = visit.fetch(&offer, &cache, &to, None).await.unwrap();
    assert_eq!(fetched.path, to);
    assert_eq!(sha256(&to), sha256(&binary));
    assert_eq!(fs::read(&beside).unwrap(), b"an earlier download");

    // Two fetches of the blob at once: the second is refused while the
    // first works, which writes the file whole.
    let (one, two) = (bob.join("one"), bob.join("two"));
    let (first, second) = tokio::join!(
        visit.fetch(&offer, &cache, &one, None),
        visit.fetch(&offer, &cache, &two, None),
    );
    assert_eq!(sha256(&first.unwrap().path), sha256(&binary));
    assert!(second.is_err() && !two.exists());
    assert_eq!(left(&cache), Vec::<PathBuf>::new());
    assert_eq!(staged(&bob), Vec::<PathBuf>::new());
    visit.close();
    ann.close().await;
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_writes_in_the_cache_and_where_it_was_asked_alone_whatever_the_name_offered() {
    let Visited {
        dir,
        binary,
        ann,
        _guest,
        visit,
        offer,
        wire: _,
    } = visited("placed").await;
    let bob = dir.join("bob");
    let cache = Fetches::at(bob.join("cache")).unwrap();
    // Directories named as fetches once named theirs beside the file
    // (`.NAME.binbun-fetch`): someone's own.
    let theirs: Vec<PathBuf> = [".grown.binbun-fetch", ".project.toml.binbun-fetch"]
        .iter()
        .map(|name| bob.join(name))
        .collect();
    for dir in &theirs {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("keep"), b"someone's").unwrap();
    }
    let chosen = bob.join("chosen");
    fs::create_dir_all(&chosen).unwrap();
    let before = files(&bob);
    // The blob's directory in the cache (under a name of its own), seen
    // while the fetch works.
    let in_cache = Arc::new(AtomicBool::new(false));
    let root = cache.root().to_path_buf();
    for (name, to) in [
        ("project.toml", chosen.join("one")),
        ("../x", chosen.join("two")),
    ] {
        let named = Offer {
            name: Text::truncated(name),
            ..offer.clone()
        };
        let progress: OnProgress = {
            let (in_cache, root) = (Arc::clone(&in_cache), root.clone());
            Arc::new(move |_| {
                let mut staging = fs::read_dir(&root).into_iter().flatten().flatten();
                if staging.any(|entry| entry.path().join("store").is_dir()) {
                    in_cache.store(true, Ordering::Relaxed);
                }
            })
        };
        let fetched = visit
            .fetch(&named, &cache, &to, Some(progress))
            .await
            .unwrap();
        assert_eq!(fetched.path, to);
        assert_eq!(sha256(&to), sha256(&binary));
    }
    assert!(in_cache.load(Ordering::Relaxed));
    // New: the two files where they were asked to go, and the blob's lock
    // file in the cache; nothing else, nor above.
    let mut new: Vec<PathBuf> = files(&bob)
        .into_iter()
        .filter(|path| !before.contains(path))
        .collect();
    new.sort();
    let lock = cache.root().join(format!("{}.lock", blob_hex(&offer)));
    assert_eq!(new, vec![lock, chosen.join("one"), chosen.join("two")]);
    assert!(!dir.join("x").exists());
    for dir in &theirs {
        assert_eq!(fs::read(dir.join("keep")).unwrap(), b"someone's");
    }
    visit.close();
    ann.close().await;
    let _ = fs::remove_dir_all(&dir);
}

/// `offer`'s blob id in lower-case hexadecimal, as the cache names it.
fn blob_hex(offer: &Offer) -> String {
    offer
        .blob
        .0
        .iter()
        .fold(String::new(), |hex, byte| format!("{hex}{byte:02x}"))
}

/// A stream that sends `bytes`, then nothing more without ending, the
/// most room it was given to read into kept.
struct Stalled {
    bytes: Vec<u8>,
    sent: usize,
    room: usize,
}

impl AsyncRead for Stalled {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.room = self.room.max(buf.remaining());
        let rest = &self.bytes[self.sent..];
        if rest.is_empty() {
            return Poll::Pending;
        }
        let count = rest.len().min(buf.remaining());
        buf.put_slice(&rest[..count]);
        self.sent += count;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn a_frame_claiming_many_bytes_and_sending_few_is_read_into_little() {
    // The most a frame of the largest kind (the sync lane's) may claim,
    // then a kilobyte, then nothing.
    let mut bytes = Vec::new();
    let mut length = FRAME;
    while length >= 0x80 {
        bytes.push(u8::try_from(length & 0x7f).unwrap() | 0x80);
        length >>= 7;
    }
    bytes.push(u8::try_from(length).unwrap());
    bytes.extend(std::iter::repeat_n(7, 1000));
    let mut stalled = Stalled {
        bytes,
        sent: 0,
        room: 0,
    };
    let read = tokio::time::timeout(Duration::from_millis(200), async {
        let length = read_frame_length(&mut stalled, FRAME).await?.unwrap();
        assert_eq!(length, FRAME);
        read_bytes(&mut stalled, length).await
    })
    .await;
    assert!(read.is_err(), "the frame is not whole: still read");
    assert_eq!(stalled.sent, stalled.bytes.len());
    // The room read into grows with the bytes that came, not to the
    // length claimed.
    assert!(stalled.room < 64 << 10, "{} bytes of room", stalled.room);
}
