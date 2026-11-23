#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Bookmarks among three peers over [`MemTransport`]: each one's own in
//! their overlay, every other's under their key; a private
//! bookmark never leaves its peer (no change sent or kept in the log
//! holds it), one made private from shared is a removal the others see,
//! both kept locally across reopening; another's bookmark copied into
//! one's own is one's own everywhere.
//!
//! Every joiner is added by the owner before it connects.
//!
//! [`MemTransport`]: binbun_collab::mem::MemTransport

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun_collab::mem::MemNet;
use binbun_collab::membership::Role;
use binbun_collab::ticket::{Card, JoinTicket};
use binbun_collab::{Config, Peer, Transport};
use binbun_session::identity::Identity;
use binbun_session::journal::{EngineVersion, Key, PublicKey, Value};
use binbun_session::{Options, Session, Stage};

/// `tests/fixtures/program-x86_64.elf`.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A test's directory of its own (by process), removed when it ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("collab-bookmarks-{name}-{}", std::process::id()));
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

/// Options keeping the project in `home/project`, signing with the
/// identity in `home/identity`, no warming.
fn options(home: &Path) -> Options {
    Options {
        project: Some(home.join("project")),
        identity: Some(home.join("identity")),
        warm: false,
        ..Options::default()
    }
}

/// One person: identity and session on the fixture in `dir/name`.
struct Person {
    name: &'static str,
    home: PathBuf,
    identity: Identity,
    session: Arc<Session>,
}

impl Person {
    fn new(dir: &Scratch, name: &'static str) -> Self {
        let home = dir.0.join(name);
        let identity = Identity::load_or_create(&home.join("identity")).unwrap();
        let session = Session::open(fixture(), options(&home)).unwrap();
        session.wait(Stage::Callers, None);
        Self {
            name,
            home,
            identity,
            session: Arc::new(session),
        }
    }

    fn key(&self) -> PublicKey {
        self.identity.public()
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

    fn transport(&self, net: &MemNet) -> Arc<dyn Transport> {
        Arc::new(net.endpoint(self.key()))
    }

    async fn share(&self, net: &MemNet) -> (Peer, JoinTicket) {
        Peer::share(
            Arc::clone(&self.session),
            self.transport(net),
            self.config(),
        )
        .await
        .unwrap()
    }

    /// Joins `ticket`'s share, added by its owner (`host`) as an editor
    /// first; once its link syncs (its journal the share's: what it
    /// writes before is kept apart).
    async fn join(&self, host: &Peer, net: &MemNet, ticket: &JoinTicket) -> Peer {
        host.add(&Card::new(&self.identity, self.name), Role::Editor)
            .unwrap();
        let peer = Peer::join(
            Arc::clone(&self.session),
            self.transport(net),
            self.config(),
            ticket,
        )
        .await
        .unwrap();
        until("the link syncs", || !peer.readers().is_empty()).await;
        peer
    }
}

/// Waits (up to 30 s) until `done`.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(30), "never: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Whether every one of `sessions` tells the same tips.
fn converged(sessions: &[&Arc<Session>]) -> bool {
    let tips = |session: &Session| session.tips_after(None, usize::MAX);
    sessions
        .iter()
        .all(|session| tips(session) == tips(sessions[0]))
}

/// `(address, name)` as a bookmarks map.
fn marks(bookmarks: &[(u64, &str)]) -> BTreeMap<u64, String> {
    bookmarks
        .iter()
        .map(|&(address, name)| (address, name.to_owned()))
        .collect()
}

/// Whether `needle` is anywhere in `haystack`.
fn holds(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// The bytes of every file under `dir` but a `private.toml`, by path.
fn shared_files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut todo = vec![dir.to_owned()];
    while let Some(dir) = todo.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                todo.push(path);
            } else if path.file_name().is_some_and(|name| name != "private.toml") {
                found.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    found
}

/// Whether any change `session` has (every author's, its body as signed
/// and sealed) or any edit its history lists holds `name`.
fn carries(session: &Session, name: &str) -> bool {
    let sent = session.chains().into_iter().any(|(chain, ..)| {
        session
            .changes_after(chain, 0, usize::MAX, usize::MAX)
            .iter()
            .any(|change| holds(&change.body, name))
    });
    let edited = session.history().iter().any(|entry| {
        session.edits_of(entry.id).iter().any(|(_, value, before)| {
            [value, before]
                .iter()
                .any(|value| **value == Value::Text(Some(name.to_owned())))
        })
    });
    sent || edited
}

/// Each of `people` sees the others' bookmarks (`own`: each one's, by
/// key) under their keys, never its own there, and its own in its
/// overlay.
fn sees_the_others(people: [&Person; 3], own: &BTreeMap<PublicKey, BTreeMap<u64, String>>) {
    for person in people {
        let mut others = own.clone();
        let mine = others.remove(&person.key()).unwrap();
        assert_eq!(person.session.others_bookmarks(), others, "{}", person.name);
        assert_eq!(person.session.overlay().bookmarks, mine, "{}", person.name);
    }
}

/// `name` is in no change any of `people` has (every author's, as signed
/// and sent; the history's edits) and in no file of theirs but a
/// `private.toml`.
fn never_left(people: [&Person; 3], name: &str) {
    for person in people {
        assert!(!carries(&person.session, name), "{}", person.name);
        let files = shared_files(&person.home);
        let log = person.home.join("project").join("log");
        assert!(files.keys().any(|path| path.starts_with(&log)));
        assert!(
            files.values().all(|bytes| !holds(bytes, name)),
            "{}",
            person.name
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_sees_the_others_bookmarks_by_author_and_never_a_private_one() {
    // Names no change or file could hold by chance.
    const PRIVATE: &str = "bob-private-c4g-91d2";
    const MOVED: &str = "bob-moved-c4g-91d2";
    let dir = Scratch::new("authors");
    let (ann, bob, carol) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "carol"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    let (b, c) = (
        bob.join(&a, &net, &ticket).await,
        carol.join(&a, &net, &ticket).await,
    );
    ann.session.bookmark(0x1190, Some("ann's")).unwrap();
    bob.session.bookmark(0x1194, Some(MOVED)).unwrap();
    bob.session.bookmark(0x11d0, Some("bob's")).unwrap();
    carol.session.bookmark(0x11a3, Some("carol's")).unwrap();
    let all = [&ann.session, &bob.session, &carol.session];
    until("every bookmark everywhere", || {
        converged(&all)
            && all
                .iter()
                .all(|session| session.others_bookmarks().len() == 2)
    })
    .await;
    let own = BTreeMap::from([
        (ann.key(), marks(&[(0x1190, "ann's")])),
        (bob.key(), marks(&[(0x1194, MOVED), (0x11d0, "bob's")])),
        (carol.key(), marks(&[(0x11a3, "carol's")])),
    ]);
    sees_the_others([&ann, &bob, &carol], &own);

    // Bob's private bookmark, and his shared one made private.
    bob.session.bookmark_private(0x11b0, Some(PRIVATE)).unwrap();
    bob.session.set_bookmark_private(0x1194, true).unwrap();
    until("the removal everywhere", || {
        converged(&all)
            && [&ann, &carol].iter().all(|person| {
                person.session.others_bookmarks().get(&bob.key())
                    == Some(&marks(&[(0x11d0, "bob's")]))
            })
    })
    .await;
    assert_eq!(
        bob.session.private_bookmarks(),
        marks(&[(0x1194, MOVED), (0x11b0, PRIVATE)])
    );
    assert_eq!(bob.session.overlay().bookmarks, marks(&[(0x11d0, "bob's")]));
    // Seen as a removal: Bob's change writes the tombstone alone.
    for person in [&ann, &carol] {
        let history = person.session.history();
        let moved = history
            .iter()
            .find(|entry| entry.label == "Make bookmark private")
            .unwrap();
        assert_eq!(moved.author, bob.key());
        assert_eq!(
            person.session.edits_of(moved.id),
            vec![(
                Key::Bookmark(bob.key(), 0x1194),
                Value::Text(None),
                Value::Text(Some(MOVED.to_owned()))
            )]
        );
    }
    // Never sent, never kept but privately: in no change any peer has
    // (Bob's own as sent), no file of any peer's but Bob's
    // `private.toml`.
    never_left([&ann, &bob, &carol], PRIVATE);
    // The shared name was sent before it moved: the check sees names.
    assert!(carries(&ann.session, MOVED));

    // Carol copies Bob's into her own: hers, seen as hers by Ann.
    carol.session.bookmark(0x11d0, Some("bob's")).unwrap();
    assert_eq!(
        carol.session.overlay().bookmarks,
        marks(&[(0x11a3, "carol's"), (0x11d0, "bob's")])
    );
    until("Carol's copy reaches Ann", || {
        ann.session.others_bookmarks().get(&carol.key())
            == Some(&marks(&[(0x11a3, "carol's"), (0x11d0, "bob's")]))
    })
    .await;
    assert_eq!(
        ann.session.others_bookmarks().get(&bob.key()),
        Some(&marks(&[(0x11d0, "bob's")]))
    );

    for peer in [a, b, c] {
        peer.close().await;
    }
    // Bob's private ones are his still, reopened (his session gone first:
    // one session writes a project at a time).
    let home = bob.home.clone();
    drop(bob);
    let reopened = Session::open(fixture(), options(&home)).unwrap();
    reopened.wait(Stage::Callers, None);
    assert_eq!(
        reopened.private_bookmarks(),
        marks(&[(0x1194, MOVED), (0x11b0, PRIVATE)])
    );
    assert_eq!(reopened.overlay().bookmarks, marks(&[(0x11d0, "bob's")]));
    reopened.close();
}
