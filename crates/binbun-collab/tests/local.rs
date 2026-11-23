#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Local edits in a share (sync §4.5 rules 4 and 6, P20): a joiner's
//! edits before the share's journal exists are refused; edits made with
//! no link a reader's are pending, shown, and admitted at the first
//! reader; an edit the share refuses is in no projection, for a viewer, a
//! demoted editor and a removed member alike; a removed member's pending
//! edits past the cut move apart once the removal record is taken, and
//! later edits are refused at the source.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun_collab::mem::MemNet;
use binbun_collab::membership::Role;
use binbun_collab::ticket::{Card, JoinTicket};
use binbun_collab::{Config, Peer};
use binbun_session::identity::Identity;
use binbun_session::journal::{EngineVersion, Key, Value};
use binbun_session::{Error, Options, Session, Stage};

/// Addresses the test comments.
const A: u64 = 0x1190;
const B: u64 = 0x1194;

/// A fresh directory for this test, by process.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("binbun-local-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The identity kept in `home`.
fn identity(home: &Path) -> Identity {
    Identity::load_or_create(&home.join("identity")).unwrap()
}

/// A session on the fixture, its project and identity in `home`.
fn session(home: &Path) -> Arc<Session> {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf");
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

/// How a peer of `identity` is made.
fn config(identity: &Identity) -> Config {
    Config {
        identity: identity.clone(),
        name: "someone".to_owned(),
        approve: None,
        notify: None,
        engine: EngineVersion::this(),
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

/// `session`'s comment at `address`.
fn comment(session: &Session, address: u64) -> Option<String> {
    session.edits().comment(address).map(str::to_owned)
}

/// `home`'s session joined to `ticket` over `net`: linked and synced
/// (`synced`), or not (a net the host is not on).
async fn join(
    session: Arc<Session>,
    home: &Path,
    net: &MemNet,
    ticket: &JoinTicket,
    synced: bool,
) -> Peer {
    let me = identity(home);
    let peer = Peer::join(
        session,
        Arc::new(net.endpoint(me.public())),
        config(&me),
        ticket,
    )
    .await
    .unwrap();
    if synced {
        until("a link is a reader's", || !peer.readers().is_empty()).await;
    }
    peer
}

/// Whether `error` is the share's refusal at the source.
fn refused<T>(result: &Result<T, Error>) -> bool {
    matches!(result, Err(Error::Refused(_)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(clippy::too_many_lines, reason = "one scenario, every role in turn")]
async fn local_edits_are_pending_without_a_reader_and_a_refused_edit_is_never_shown() {
    let dir = scratch("p20");
    let (net, nowhere) = (MemNet::new(), MemNet::new());
    let ann_home = dir.join("ann");
    let ann_id = identity(&ann_home);
    let (ann, ticket) = Peer::share(
        session(&ann_home),
        Arc::new(net.endpoint(ann_id.public())),
        config(&ann_id),
    )
    .await
    .unwrap();
    let (bob_home, cat_home, dan_home) = (dir.join("bob"), dir.join("cat"), dir.join("dan"));
    for (home, role) in [
        (&bob_home, Role::Editor),
        (&cat_home, Role::Viewer),
        (&dan_home, Role::Editor),
    ] {
        ann.add(&Card::new(&identity(home), "someone"), role)
            .unwrap();
    }

    // Before the share's journal exists (the host out of reach), the
    // joining window takes no edit and shows none.
    let bob = join(session(&bob_home), &bob_home, &nowhere, &ticket, false).await;
    assert!(bob.session().joining());
    assert!(refused(&bob.session().comment(A, Some("early"))));
    assert_eq!(comment(&bob.session(), A), None);
    let bob_session = bob.session();
    bob.close().await;

    // Joined and synced, then out of reach: an edit is pending, shown,
    // told to no one; at the next reader link it is admitted and Ann
    // has it.
    let bob = join(Arc::clone(&bob_session), &bob_home, &net, &ticket, true).await;
    bob.close().await;
    let bob = join(
        Arc::clone(&bob_session),
        &bob_home,
        &nowhere,
        &ticket,
        false,
    )
    .await;
    assert!(!bob_session.joining());
    bob_session.comment(A, Some("offline")).unwrap();
    assert_eq!(comment(&bob_session, A).as_deref(), Some("offline"));
    let pending = bob_session.pending();
    assert!(
        pending.iter().any(|edit| edit
            .values
            .contains(&(Key::Comment(A), Value::Text(Some("offline".to_owned()))))),
        "{pending:?}"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(comment(&ann.session(), A), None);
    bob.close().await;
    let bob = join(Arc::clone(&bob_session), &bob_home, &net, &ticket, true).await;
    until("Ann has Bob's offline edit", || {
        comment(&ann.session(), A).as_deref() == Some("offline")
    })
    .await;
    until("nothing of Bob's pending", || {
        bob_session.pending().is_empty()
    })
    .await;

    // A viewer's edit with a reader link: refused at the source, not shown.
    let cat = join(session(&cat_home), &cat_home, &net, &ticket, true).await;
    assert!(refused(&cat.session().comment(B, Some("cat"))));
    assert_eq!(comment(&cat.session(), B), None);
    assert_eq!(cat.session().pending(), Vec::new());

    // An editor made a viewer: the same.
    ann.set_role(bob.id(), Role::Viewer).unwrap();
    until("Bob is a viewer", || bob.role() == Some(Role::Viewer)).await;
    assert!(refused(&bob_session.comment(B, Some("demoted"))));
    assert_eq!(comment(&bob_session, B), None);

    // A removed member's edits made unaware of the removal are pending
    // and shown; once the removal record is taken (with the kick, at the
    // next attempt to link) they move apart, listed with their values as
    // not in this project; later edits are refused at the source.
    let dan = join(session(&dan_home), &dan_home, &net, &ticket, true).await;
    let dan_session = dan.session();
    let dan_id = dan.id();
    dan.close().await;
    ann.remove(dan_id).unwrap();
    let dan = join(
        Arc::clone(&dan_session),
        &dan_home,
        &nowhere,
        &ticket,
        false,
    )
    .await;
    dan_session.comment(B, Some("unaware")).unwrap();
    assert_eq!(comment(&dan_session, B).as_deref(), Some("unaware"));
    dan.close().await;
    let dan = join(Arc::clone(&dan_session), &dan_home, &net, &ticket, false).await;
    until("Dan takes his removal", || dan.membership().removed(dan_id)).await;
    until("Dan's edit leaves his projection", || {
        comment(&dan_session, B).is_none()
    })
    .await;
    let apart = dan_session.not_in_project();
    assert!(
        apart.iter().any(|edit| edit
            .values
            .contains(&(Key::Comment(B), Value::Text(Some("unaware".to_owned()))))),
        "{apart:?}"
    );
    assert_eq!(dan_session.pending(), Vec::new());
    assert!(refused(&dan_session.comment(B, Some("after"))));
    assert_eq!(comment(&dan_session, B), None);
    assert_eq!(comment(&ann.session(), B), None);

    for peer in [ann, bob, cat, dan] {
        peer.close().await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}
