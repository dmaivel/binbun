#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The share's one admission operation, with real storage (sync §3.3,
//! §4.3, §4.4; tests P21 and P22): a chain the owner never saw, held by
//! one replica through its author's removal and readmission and first
//! seen by another after it, is admitted alike on both (its start only);
//! a raise leaves the chain of the earlier grant at its role, new rights
//! used on a new chain;
//! a listed prefix handed in from a file is taken only on the branch its
//! walk checked, never on another signed branch; an envelope that cannot
//! be opened here is declined where it came from and stops nothing.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun_collab::crypto::{self, EpochKey};
use binbun_collab::mem::MemNet;
use binbun_collab::membership::{Record, Role};
use binbun_collab::ticket::{Card, JoinTicket};
use binbun_collab::{Approver, Config, Peer, Transport, bounded};
use binbun_session::identity::Identity;
use binbun_session::journal::talk::Anchor;
use binbun_session::journal::{
    Body, ChainId, ChainOrigin, EngineVersion, Head, Hlc, SignedChange, SignedHead, Signer,
};
use binbun_session::{Options, Say, Session, Stage};
use ed25519_dalek::SigningKey;

/// `tests/fixtures/program-x86_64.elf`.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A test's directory of its own (by process), removed when it ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("collab-grants-{name}-{}", std::process::id()));
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

/// One person: their identity and their session on the fixture, in a
/// project of their own.
struct Person {
    name: &'static str,
    identity: Identity,
    session: Arc<Session>,
}

impl Person {
    fn new(dir: &Scratch, name: &'static str) -> Self {
        let home = dir.0.join(name);
        let identity = Identity::load_or_create(&home.join("identity")).unwrap();
        let session = Session::open(
            fixture(),
            Options {
                identity: Some(home.join("identity")),
                project: Some(home.join("project")),
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
        }
    }

    fn config(&self, approve: Option<Approver>) -> Config {
        Config {
            identity: self.identity.clone(),
            name: self.name.to_owned(),
            approve,
            notify: None,
            engine: EngineVersion::this(),
        }
    }

    fn transport(&self, net: &MemNet) -> Arc<dyn Transport> {
        Arc::new(net.endpoint(self.identity.public()))
    }

    /// Shares their project over `net`, ticket holders let in as editors.
    async fn share(&self, net: &MemNet) -> (Peer, JoinTicket) {
        let approve: Approver = Arc::new(|_| Box::pin(async { Some(Role::Editor) }));
        Peer::share(
            Arc::clone(&self.session),
            self.transport(net),
            self.config(Some(approve)),
        )
        .await
        .unwrap()
    }

    /// Joins `ticket`'s share over `net`, once its link is a reader's.
    async fn join(&self, net: &MemNet, ticket: &JoinTicket) -> Peer {
        let peer = self.dial(net, ticket).await;
        until(&format!("{} reads the share", self.name), || {
            !peer.readers().is_empty()
        })
        .await;
        peer
    }

    /// Joins `ticket`'s share as kept here, over a network its host is
    /// not on: the share attached to the session, nothing linked.
    async fn apart(&self, ticket: &JoinTicket) -> Peer {
        self.dial(&MemNet::new(), ticket).await
    }

    async fn dial(&self, net: &MemNet, ticket: &JoinTicket) -> Peer {
        Peer::join(
            Arc::clone(&self.session),
            self.transport(net),
            self.config(None),
            ticket,
        )
        .await
        .unwrap()
    }

    /// The entry of the function named `function`.
    fn entry(&self, function: &str) -> u64 {
        let database = self.session.database().unwrap();
        database
            .functions()
            .find(|(_, f)| self.session.name(f.entry).as_deref() == Some(function))
            .map(|(_, f)| f.entry)
            .unwrap()
    }

    fn rename(&self, function: &str, name: &str) {
        self.session
            .rename_function(self.entry(function), Some(name))
            .unwrap();
    }

    /// How far their session tells chain `chain` (0: not at all).
    fn seq(&self, chain: ChainId) -> u64 {
        self.session.tip(chain).map_or(0, |tip| tip.seq)
    }

    /// Chain `chain` as their session tells it, its start first.
    fn changes(&self, chain: ChainId) -> Vec<SignedChange> {
        self.session.changes_after(chain, 0, 64, usize::MAX)
    }

    /// The directory their share keeps its membership chain in.
    fn kept(&self, ticket: &JoinTicket) -> PathBuf {
        self.session
            .project()
            .unwrap()
            .dir()
            .join("collab")
            .join(ticket.project.to_string())
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

/// A change with head `head` (its commitment aside) and `like`'s body as
/// `edit` leaves it, a little later, signed by `by`.
fn signed(
    head: Head,
    like: &SignedChange,
    by: &Identity,
    edit: impl FnOnce(&mut Body),
) -> SignedChange {
    let mut body = Body::decode(&like.body).unwrap();
    body.hlc = Hlc(body.hlc.0 + 1);
    edit(&mut body);
    let bytes = body.encode().unwrap();
    let head = Head {
        body: Body::commitment(&bytes),
        ..head
    };
    SignedChange {
        head: SignedHead::sign(head, &Signer::from_seed(&by.secret())),
        body: bytes,
    }
}

/// The epoch now and its key, as `who`'s wrap in `peer`'s chain gives it.
fn epoch_key(peer: &Peer, who: &Identity) -> (u32, EpochKey) {
    let membership = peer.membership();
    let epoch = membership.epoch();
    let key = membership
        .since(0)
        .iter()
        .map(|signed| bounded::decode::<Record>(&signed.bytes).unwrap())
        .filter(|record| record.epoch == epoch)
        .flat_map(|record| record.wraps)
        .find(|(member, _)| *member == who.public())
        .map(|(_, wrap)| {
            crypto::unwrap(
                &wrap,
                membership.project(),
                epoch,
                who.public(),
                &who.agreement_secret(),
            )
            .unwrap()
        })
        .unwrap();
    (epoch, key)
}

/// `changes` sealed by member `who` in `peer`'s share, naming epoch
/// `epoch` (whose key it may not be): what a file of `who`'s holds.
fn sealed_as(peer: &Peer, who: &Identity, epoch: u32, changes: &[SignedChange]) -> Vec<Vec<u8>> {
    let (_, key) = epoch_key(peer, who);
    let membership = peer.membership();
    let (project, genesis) = (membership.project(), membership.genesis().unwrap());
    let sealer = SigningKey::from_bytes(&who.secret());
    changes
        .iter()
        .map(|change| {
            crypto::seal(&key.log(project), project, &genesis, epoch, change, &sealer).unwrap()
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_readmitted_authors_chain_the_owner_never_saw_is_judged_alike_everywhere() {
    let dir = Scratch::new("readmitted");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    bob.rename("classify", "bobs");
    let seen = bob.session.chain();
    until("Ann and Cat hold Bob's change", || {
        ann.seq(seen) == 2 && cat.seq(seen) == 2
    })
    .await;
    // A chain of Bob's under the same grant that the owner never sees: Cat
    // takes it while not linked, before the removal.
    let [start, edit] = [&bob.changes(seen)[0], &bob.changes(seen)[1]];
    let origin = ChainOrigin {
        salt: [9; 16],
        ..start.head.head.origin.unwrap()
    };
    let unseen = origin.chain();
    let unseen_start = signed(
        Head {
            chain: unseen,
            origin: Some(origin),
            ..start.head.head
        },
        start,
        &bob.identity,
        |_| {},
    );
    let unseen_edit = signed(
        Head {
            chain: unseen,
            seq: 2,
            prev: unseen_start.hash(),
            origin: None,
            ..edit.head.head
        },
        edit,
        &bob.identity,
        |body| "unseen".clone_into(&mut body.label),
    );
    let unseen_chain = vec![unseen_start.clone(), unseen_edit.clone()];
    c.close().await;
    let c = cat.apart(&ticket).await;
    let applied = cat.session.receive(unseen_chain.clone());
    assert_eq!(applied.taken.len(), 2, "{applied:?}");
    c.close().await;
    // Removed (the cut names only the chain Ann saw), then readmitted.
    a.remove(bob.identity.public()).unwrap();
    a.add(&Card::new(&bob.identity, "bob"), Role::Editor)
        .unwrap();
    // Cat, the early holder, takes both records; Ann, the late one, sees
    // the chain only now: each admits its start only.
    let c = cat.join(&net, &ticket).await;
    until("Cat holds Ann's records", || {
        c.membership().head() == a.membership().head()
    })
    .await;
    until("Cat keeps the unseen chain's start only", || {
        cat.seq(unseen) == 1
    })
    .await;
    let applied = ann.session.receive(unseen_chain);
    assert!(
        applied.taken.iter().all(|(id, _)| id.seq == 1),
        "{applied:?}"
    );
    until("Ann and Cat agree on it", || {
        ann.seq(unseen) == 1 && ann.session.tip(unseen) == cat.session.tip(unseen)
    })
    .await;
    for person in [&ann, &cat] {
        assert_eq!(
            person.session.frozen_from(unseen),
            Some(1),
            "{}",
            person.name
        );
        assert_eq!(person.seq(seen), 2, "{}", person.name);
    }
    for peer in [a, b, c] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_raised_member_edits_on_a_new_chain_and_the_old_one_keeps_its_role() {
    let dir = Scratch::new("raised");
    let (ann, bob) = (Person::new(&dir, "ann"), Person::new(&dir, "bob"));
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    a.add(&Card::new(&bob.identity, "bob"), Role::Viewer)
        .unwrap();
    let b = bob.join(&net, &ticket).await;
    // A viewer talks: a chain under his viewer's grant.
    let thread = bob
        .session
        .open_thread(Anchor::Function(bob.entry("classify")), "")
        .unwrap();
    let say = Say {
        body: "a question".to_owned(),
        ..Say::default()
    };
    bob.session.post(thread, say).unwrap();
    let talked = bob.session.chain();
    until("Ann holds what Bob said", || ann.seq(talked) == 3).await;
    // Raised: his edit goes on a new chain, under the new grant, and is
    // taken; the chain he talked on keeps a viewer's role.
    a.set_role(bob.identity.public(), Role::Editor).unwrap();
    until("Bob is an editor", || b.role() == Some(Role::Editor)).await;
    bob.rename("classify", "sort");
    let edited = bob.session.chain();
    assert_ne!(edited, talked);
    until("Ann takes Bob's edit", || ann.seq(edited) == 2).await;
    let past = signed(
        Head {
            seq: 4,
            prev: bob.changes(talked)[2].hash(),
            ..bob.changes(talked)[2].head.head
        },
        &bob.changes(edited)[1],
        &bob.identity,
        |_| {},
    );
    let applied = ann.session.receive(vec![past]);
    assert!(applied.taken.is_empty(), "{applied:?}");
    assert_eq!(ann.session.frozen_from(talked), Some(4));
    a.close().await;
    b.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listed_prefix_from_a_file_is_taken_only_on_the_branch_its_walk_checked() {
    let dir = Scratch::new("listed");
    let (ann, bob) = (Person::new(&dir, "ann"), Person::new(&dir, "bob"));
    // Ann's work from before the share: one chain the share lists to its
    // fourth change.
    ann.rename("classify", "sort");
    ann.rename("checked", "guard");
    ann.rename("loop_sum", "sum");
    let listed = ann.session.chain();
    let prefix = ann.changes(listed);
    assert_eq!(prefix.len(), 4);
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    assert_eq!(
        a.membership().before().get(&listed),
        Some(&(4, prefix[3].hash()))
    );
    // Bob added, his copy of the chain kept as Ann's: the share attached,
    // nothing linked, nothing walked.
    a.add(&Card::new(&bob.identity, "bob"), Role::Editor)
        .unwrap();
    let kept = bob.kept(&ticket);
    fs::create_dir_all(&kept).unwrap();
    fs::copy(
        ann.kept(&ticket).join("membership.log"),
        kept.join("membership.log"),
    )
    .unwrap();
    let b = bob.apart(&ticket).await;
    assert_eq!(b.membership().head(), a.membership().head());
    // Another branch signed by Ann, differing at number 3.
    let other = signed(prefix[2].head.head, &prefix[2], &ann.identity, |body| {
        "other".clone_into(&mut body.label);
    });
    let after = signed(
        Head {
            seq: 4,
            prev: other.hash(),
            ..prefix[3].head.head
        },
        &prefix[3],
        &ann.identity,
        |_| {},
    );
    let epoch = b.membership().epoch();
    let branches = [
        vec![prefix[0].clone(), prefix[1].clone(), other.clone(), after],
        vec![
            prefix[0].clone(),
            prefix[1].clone(),
            other,
            prefix[3].clone(),
        ],
        prefix.clone(),
    ];
    // From a file, with or without the listed end, the listed branch
    // too: nothing applied at any number before the walk.
    for branch in &branches {
        let received = b.receive(&sealed_as(&b, &bob.identity, epoch, branch));
        assert_eq!(received.taken, 0, "{received:?}");
        assert_eq!(bob.seq(listed), 0);
        assert!(bob.session.tip(listed).is_none());
    }
    // Linked, Bob walks from the listed hash and takes the listed branch.
    b.close().await;
    let b = bob.join(&net, &ticket).await;
    until("Bob takes the listed prefix", || bob.seq(listed) == 4).await;
    assert_eq!(bob.changes(listed), prefix);
    a.close().await;
    b.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_envelope_that_cannot_be_opened_stops_nothing_and_its_change_comes_by_a_link() {
    let dir = Scratch::new("unopened");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    ann.rename("classify", "sort");
    let chain = ann.session.chain();
    until("Bob holds Ann's chain", || bob.seq(chain) == 2).await;
    b.close().await;
    // Cat keeps Ann a reader's: her next change is admitted.
    ann.rename("checked", "guard");
    let guarded = ann.changes(chain)[2].clone();
    let b = bob.apart(&ticket).await;
    // Sealed by a member under an epoch that does not exist: declined
    // where it came from, kept nowhere, nothing stopped or frozen.
    let bad = sealed_as(&b, &bob.identity, 7, std::slice::from_ref(&guarded));
    let received = b.receive(&bad);
    assert_eq!(
        (received.taken, received.held, received.refused.len()),
        (0, 0, 1),
        "{received:?}"
    );
    assert!(bob.session.frozen().is_empty());
    // The same change from a link is taken.
    b.close().await;
    let b = bob.join(&net, &ticket).await;
    until("Bob takes Ann's change by the link", || bob.seq(chain) == 3).await;
    for peer in [a, b, c] {
        peer.close().await;
    }
}
