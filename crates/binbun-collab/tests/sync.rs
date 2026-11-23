#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Peers over [`MemNet`]:
//! two and three peers converge, concurrent edits surface as one
//! conflict everywhere and resolve everywhere; a viewer's writes are
//! taken by no peer; removing a member re-keys and cuts their later
//! changes on every peer, held ones included; a member added after a
//! removal reads the whole history from another member, the owner away;
//! forks freeze their chain on every peer that meets both sides;
//! tampered envelopes are refused; nothing naming a chain passes before
//! a link is a reader's; a ticket is worth nothing once its share closes;
//! a shared project exports without its share and imports unshared, its
//! edits and log whole; a library signature's match made by the host and
//! its rejection by a member cross between them. A page's permit is held
//! through its rate's wait and its write, and given back once written,
//! at its reader's removal or at the write's deadline; a member that
//! stops reading holds up no other share's membership catch-up; pages
//! waiting for their rate leave out what a cut took meanwhile, and none
//! is written to a member removed while it waited; a removed member
//! whose missed records span several kicks learns all of them through
//! its removal.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use binbun_collab::blobs::Kind;
use binbun_collab::bounded::{Bounded, Bytes};
use binbun_collab::budgets::{Budgets, Clock, FakeRelativeClock, SYNC_BYTES, SYNC_PAGES};
use binbun_collab::crypto;
use binbun_collab::mem::MemNet;
use binbun_collab::membership::{Op, Record, RecordCut, Role, SignedRecord};
use binbun_collab::ticket::{Card, JoinTicket};
use binbun_collab::transport::{
    Lane, Link, RecvStream, SendStream, read_bytes, read_frame, read_frame_length, write_bytes,
    write_frame,
};
use binbun_collab::wire::{
    Answer, Control, Engine, FEATURES, Hello, LIVE_FRAME, LOG, MAX_KICK_RECORDS, PROTOCOL,
};
use binbun_collab::{Approver, Config, Flushed, Notice, Peer, Transport};
use binbun_session::identity::Identity;
use binbun_session::journal::talk::Anchor;
use binbun_session::journal::{
    Body, ChainId, ChangeHash, EngineVersion, HEAD, Head, Hlc, Key, Origin, ProjectId, PublicKey,
    SIG, SignedChange, SignedHead, Signer, Tip, Value,
};
use binbun_session::project::{self, Bundle, Imported};
use binbun_session::signatures::{NameSource, Options as SignatureOptions};
use binbun_session::{Options, Session, Stage};
use binbun_sync::Sync;
use binbun_sync::envelope::Envelope;
use binbun_sync::machine::DEADLINE;
use binbun_sync::wire::{FRAME, RecordBytes};
use ed25519_dalek::{Signer as _, SigningKey};

/// Whether `person` heard a notice `matching`.
fn heard(person: &Person, matching: impl Fn(&Notice) -> bool) -> bool {
    person.heard.lock().unwrap().iter().any(matching)
}

/// Whether `person` was turned away or put out.
fn put_out(person: &Person) -> bool {
    heard(person, |n| {
        matches!(n, Notice::Denied(_) | Notice::Kicked(_))
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_on_another_build_is_view_only_and_another_log_major_cannot_join() {
    let dir = scratch("versions");
    let (ann, bob) = (Person::new(&dir, "ann"), Person::new(&dir, "bob"));
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let other = EngineVersion {
        build: "0123456789ab".to_owned(),
        ..EngineVersion::this()
    };
    let b = bob.join_as(&net, &ticket, other.clone()).await;
    // Admitted, and told it is view-only; the host shows it too. The
    // welcome (control lane) says view-only, and the notice follows it;
    // the role comes with the membership records (sync lane), after: in
    // no fixed order with either.
    until("Bob is in, an editor, told he is view-only", || {
        b.role() == Some(Role::Editor)
            && heard(
                &bob,
                |n| matches!(n, Notice::ViewOnly(why) if why.contains("another build")),
            )
    })
    .await;
    assert!(b.view_only().unwrap().contains("0123456789ab"));
    until("Ann shows Bob view-only", || {
        heard(&ann, |n| {
            matches!(
                n,
                Notice::Linked {
                    view_only: Some(_),
                    ..
                }
            )
        })
    })
    .await;
    // He sees Ann's edits.
    ann.rename("classify", "sort");
    until("Bob sees Ann's edit", || converged(&[&ann, &bob])).await;
    // A change of his made by this build is taken; one his build made is
    // not, while he is linked view-only.
    bob.rename("checked", "guard");
    until("Ann takes Bob's change of this build", || {
        has_from(&ann, bob.key())
    })
    .await;
    let mine = bob.last(bob.session.chain());
    let theirs = following(&mine, &bob.identity, |body| {
        body.engine = other.clone();
        body.label = "Rename function (another build)".to_owned();
    });
    let applied = ann.session.receive(vec![theirs.clone()]);
    assert!(applied.taken.is_empty(), "{applied:?}");
    assert_eq!(applied.stopped.len(), 1);
    // His link gone, it is taken when it comes again.
    b.close().await;
    until("Ann's link to Bob is down", || a.links().is_empty()).await;
    let applied = ann.session.receive(vec![theirs]);
    assert_eq!(applied.taken.len(), 1, "{applied:?}");
    // Another log major is turned away at its hello, saying so, before
    // anyone is asked.
    let cat = Identity::ephemeral().unwrap();
    let link = net
        .endpoint(cat.public())
        .connect(&ticket.host)
        .await
        .unwrap();
    let (mut send, mut recv) = link.open(Lane::Control).await.unwrap();
    let hello = Hello {
        protocol: PROTOCOL,
        log: LOG + 1,
        engine: Engine::of(&EngineVersion::this()),
        project: ticket.project,
        invite: Some(ticket.invite),
        card: Card::new(&cat, "cat"),
        membership: (0, [0; 32]),
        features: FEATURES,
    };
    write_frame(&mut *send, &Control::Hello(Box::new(hello)))
        .await
        .unwrap();
    match read_frame::<Control>(&mut *recv).await.unwrap() {
        Some(Control::Denied { reason }) => {
            assert!(reason.contains(&format!("log {LOG}")), "{reason}");
        }
        other => panic!("not denied: {other:?}"),
    }
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_admitted_again_writes_anew_and_what_they_wrote_while_removed_stays_refused() {
    let dir = scratch("readmit");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let (checked, loop_sum) = (ann.entry("checked"), ann.entry("loop_sum"));
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    bob.rename("classify", "bobs");
    until("all three converge", || converged(&[&ann, &bob, &cat])).await;
    let old_chain = bob.session.chain();
    let last = bob.last(old_chain);
    a.remove(bob.key()).unwrap();
    until("Bob is put out", || put_out(&bob)).await;
    // Written while removed: his own session, judged by the record, takes
    // it not.
    bob.rename_refused(checked, "meanwhile");
    b.close().await;
    // Admitted again (by his card): a new record, epoch 1's key wrapped
    // to him.
    a.add(&Card::new(&bob.identity, "bob"), Role::Editor)
        .unwrap();
    let b = bob.join(&net, &ticket).await;
    until("Bob is back with epoch 1's key", || {
        b.role() == Some(Role::Editor) && b.epochs().contains(&1)
    })
    .await;
    bob.rename("loop_sum", "after");
    assert_ne!(bob.session.chain(), old_chain);
    until("his new edit reaches Ann and Cat", || {
        [&ann, &cat]
            .iter()
            .all(|person| person.session.name(loop_sum).as_deref() == Some("after"))
    })
    .await;
    // What his key signs on the old chain past the removal (another
    // client of his, say) is refused by Ann and Cat alike.
    let meanwhile = following(&last, &bob.identity, |body| {
        body.label = "meanwhile".to_owned();
    });
    for person in [&ann, &cat] {
        let applied = person.session.receive(vec![meanwhile.clone()]);
        assert!(applied.taken.is_empty(), "{} took it", person.name);
        assert_eq!(
            person.session.name(checked).as_deref(),
            Some("checked"),
            "{}",
            person.name
        );
        assert_eq!(person.seq(old_chain), last.id().seq, "{}", person.name);
    }
    for peer in [a, b, c] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ownership_moves_to_a_member_who_alone_signs_after_and_a_third_peer_follows() {
    let dir = scratch("transfer");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    until("all three are in", || c.membership().seq() == 3).await;
    a.transfer(bob.key()).unwrap();
    until("Bob and Cat follow the transfer", || {
        b.membership().owner() == bob.key() && c.membership().owner() == bob.key()
    })
    .await;
    assert_eq!(a.role(), Some(Role::Editor));
    assert_eq!(c.membership().role(bob.key()), Some(Role::Owner));
    // Ann signs nothing now; a record she signs anyway is refused.
    assert!(a.remove(cat.key()).is_err());
    let chain = c.membership();
    let last = chain.since(0).last().unwrap();
    let record = Record {
        seq: chain.seq() + 1,
        prev: *blake3::hash(&last.bytes).as_bytes(),
        op: Op::SetRole {
            member: cat.key(),
            role: Role::Viewer,
            cut: RecordCut::new(),
        },
        epoch: chain.epoch(),
        wraps: Bounded::new(),
    };
    let bytes = Bytes::try_from(postcard::to_allocvec(&record).unwrap()).unwrap();
    let sign = |identity: &Identity| SignedRecord {
        sig: SigningKey::from_bytes(&identity.secret()).sign(&bytes),
        bytes: bytes.clone(),
    };
    assert!(chain.clone().take(&sign(&ann.identity)).is_err());
    assert!(chain.clone().take(&sign(&bob.identity)).is_ok());
    // Bob's own, live: Cat follows it.
    b.set_role(cat.key(), Role::Viewer).unwrap();
    until("Cat is a viewer, by Bob's record", || {
        c.role() == Some(Role::Viewer)
    })
    .await;
    // Ann still edits, as an editor.
    ann.rename("classify", "sort");
    until("Ann's edit reaches Cat", || converged(&[&ann, &cat])).await;
    for peer in [a, b, c] {
        peer.close().await;
    }
}

/// `tests/fixtures/program-x86_64.elf`.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A fresh directory for `name`.
fn scratch(name: &str) -> Scratch {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// A test's directory, its own even with copies of the test running at
/// once (by process), removed when the test ends.
struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One person: their identity, their session on the fixture (its project
/// and identity in `dir`), and what their peer tells.
struct Person {
    name: &'static str,
    identity: Identity,
    session: Arc<Session>,
    heard: Arc<Mutex<Vec<Notice>>>,
}

impl Person {
    fn new(dir: &Path, name: &'static str) -> Self {
        let home = dir.join(name);
        let project = Some(home.join("project"));
        Self::open(
            name,
            &home,
            Options {
                project,
                ..Options::default()
            },
        )
    }

    /// `name`, their identity in `home`, their session on the fixture
    /// opened with `options` (that identity, no warming).
    fn open(name: &'static str, home: &Path, options: Options) -> Self {
        Self::open_file(name, home, &fixture(), options)
    }

    /// `name`, their identity in `home`, their session on `file` opened
    /// with `options` (that identity, no warming).
    fn open_file(name: &'static str, home: &Path, file: &Path, options: Options) -> Self {
        let identity = Identity::load_or_create(&home.join("identity")).unwrap();
        let session = Session::open(
            file,
            Options {
                identity: Some(home.join("identity")),
                warm: false,
                ..options
            },
        )
        .unwrap();
        session.wait(Stage::Analysed, None);
        Self {
            name,
            identity,
            session: Arc::new(session),
            heard: Arc::default(),
        }
    }

    fn key(&self) -> PublicKey {
        self.identity.public()
    }

    /// Their peer's configuration, admitting with `approve`.
    fn config(&self, approve: Option<Approver>) -> Config {
        let heard = Arc::clone(&self.heard);
        Config {
            identity: self.identity.clone(),
            name: self.name.to_owned(),
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
        self.share_with(net, Some(approve)).await
    }

    /// Shares their project over `net`, only members let in.
    async fn host(&self, net: &MemNet) -> (Peer, JoinTicket) {
        self.share_with(net, None).await
    }

    async fn share_with(&self, net: &MemNet, approve: Option<Approver>) -> (Peer, JoinTicket) {
        Peer::share(
            Arc::clone(&self.session),
            self.transport(net),
            self.config(approve),
        )
        .await
        .unwrap()
    }

    /// Shares their project over `net` from a process whose budgets are
    /// `budgets` (another share's there too, say), ticket holders let in
    /// by `approve`.
    async fn share_within(
        &self,
        net: &MemNet,
        budgets: &Budgets,
        approve: Option<Approver>,
    ) -> (Peer, JoinTicket) {
        Peer::share(
            Arc::clone(&self.session),
            Arc::new(net.endpoint_within(self.key(), budgets.clone())),
            self.config(approve),
        )
        .await
        .unwrap()
    }

    async fn join(&self, net: &MemNet, ticket: &JoinTicket) -> Peer {
        self.join_as(net, ticket, EngineVersion::this()).await
    }

    /// Joins `ticket`'s share over a network its host is not on: the
    /// share attached to the session (what it writes judged and admitted
    /// as when linked), nothing linked.
    async fn apart(&self, ticket: &JoinTicket) -> Peer {
        self.dial(&MemNet::new(), ticket, EngineVersion::this())
            .await
    }

    /// Hosts their session's share again on a network of its own, where
    /// `member`'s binbun, spoken by hand, reaches Reader and takes
    /// nothing: what they write from then on is admitted and sealable,
    /// and reaches no other peer.
    async fn alone_with(&self, member: &Identity) -> (Peer, Hand) {
        let side = MemNet::new();
        let (peer, ticket) = self.host(&side).await;
        let hand = Hand::reader(&side, member, &ticket).await;
        until(&format!("{} has a reader", self.name), || {
            peer.readers() == [member.public()]
        })
        .await;
        (peer, hand)
    }

    /// Joins speaking for `engine` (another build, say), once its link is
    /// a reader's: what the session writes from then on is the share's.
    async fn join_as(&self, net: &MemNet, ticket: &JoinTicket, engine: EngineVersion) -> Peer {
        let peer = self.dial(net, ticket, engine).await;
        until(&format!("{} reads the share", self.name), || {
            !peer.readers().is_empty()
        })
        .await;
        peer
    }

    /// Starts joining speaking for `engine`, whatever comes of it.
    async fn dial(&self, net: &MemNet, ticket: &JoinTicket, engine: EngineVersion) -> Peer {
        let mut config = self.config(None);
        config.engine = engine;
        Peer::join(
            Arc::clone(&self.session),
            self.transport(net),
            config,
            ticket,
        )
        .await
        .unwrap()
    }

    /// The entry of the function named `name` (the user's name, else its
    /// symbol).
    fn entry(&self, name: &str) -> u64 {
        let database = self.session.database().unwrap();
        database
            .functions()
            .find(|(_, f)| self.session.name(f.entry).as_deref() == Some(name))
            .map(|(_, f)| f.entry)
            .unwrap()
    }

    fn rename(&self, function: &str, name: &str) {
        self.session
            .rename_function(self.entry(function), Some(name))
            .unwrap();
    }

    /// Renames the function at `function` to `name` where the share takes
    /// not their edits: refused at the source, neither shown nor told (the
    /// session's tips stay as they were).
    fn rename_refused(&self, function: u64, name: &str) {
        let (tips, shown) = (self.tips(), self.session.name(function));
        let refused = self.session.rename_function(function, Some(name));
        assert!(
            matches!(refused, Err(binbun_session::Error::Refused(_))),
            "{}: {refused:?}",
            self.name
        );
        assert_eq!(self.session.name(function), shown, "{} shows it", self.name);
        assert_eq!(self.tips(), tips, "{} tells it", self.name);
    }

    fn project_file(&self) -> Vec<u8> {
        fs::read(self.session.project().unwrap().edits()).unwrap_or_default()
    }

    /// The tips their session tells.
    fn tips(&self) -> Vec<Tip> {
        self.session.tips_after(None, usize::MAX)
    }

    /// How far their session tells chain `chain` (0: not at all).
    fn seq(&self, chain: ChainId) -> u64 {
        self.session.tip(chain).map_or(0, |tip| tip.seq)
    }

    /// The last change their session tells of chain `chain`, as signed.
    fn last(&self, chain: ChainId) -> SignedChange {
        let seq = self.seq(chain);
        self.session.changes_after(chain, seq - 1, 1, usize::MAX)[0].clone()
    }

    /// The chain their session writes on.
    fn chain(&self) -> ChainId {
        self.session.chain()
    }
}

/// An approver admitting everyone as `role`, counting whom it was asked
/// about.
fn approver(role: Role, asked: &Arc<AtomicUsize>) -> Approver {
    let asked = Arc::clone(asked);
    Arc::new(move |_| {
        asked.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Some(role) })
    })
}

/// Waits (up to 30 s) until `done`.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(30), "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Whether every peer of `people` tells the same tips and has the same
/// project file.
fn converged(people: &[&Person]) -> bool {
    let first = people[0];
    people.iter().all(|person| {
        person.tips() == first.tips() && person.project_file() == first.project_file()
    })
}

/// A change with head `head` (its body's commitment aside) and the body
/// of `like` as `edit` leaves it, its time a little later, signed by
/// `by`: what a client holding `by`'s key writes.
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

/// The change after `last` on its chain (linked to it), its body
/// `last`'s as `edit` leaves it, signed by `by`.
fn following(last: &SignedChange, by: &Identity, edit: impl FnOnce(&mut Body)) -> SignedChange {
    let head = last.head.head;
    let next = Head {
        seq: head.seq + 1,
        prev: last.hash(),
        origin: None,
        ..head
    };
    signed(next, last, by, edit)
}

/// Another change at `change`'s place (its number, after the same
/// change), labelled `label`, signed by `by`: with `change`, a fork of
/// its chain.
fn beside(change: &SignedChange, label: &str, by: &Identity) -> SignedChange {
    signed(change.head.head, change, by, |body| {
        label.clone_into(&mut body.label);
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_peers_converge_with_edits_made_on_each_side() {
    let dir = scratch("both-ways");
    let (ann, bob) = (Person::new(&dir, "ann"), Person::new(&dir, "bob"));
    let functions = ["classify", "checked", "loop_sum"].map(|name| ann.entry(name));
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    a.add(&Card::new(&bob.identity, "bob"), Role::Editor)
        .unwrap();
    let b = bob.join(&net, &ticket).await;
    until("Bob's link is a reader's", || b.readers() == [ann.key()]).await;
    ann.rename("classify", "sort");
    bob.rename("checked", "guard");
    bob.session
        .comment(functions[2], Some("Bob was here"))
        .unwrap();
    until("both have both people's edits", || {
        converged(&[&ann, &bob])
            && [&ann, &bob].iter().all(|person| {
                person.session.name(functions[0]).as_deref() == Some("sort")
                    && person.session.name(functions[1]).as_deref() == Some("guard")
                    && person.session.edits().comment(functions[2]) == Some("Bob was here")
            })
    })
    .await;
    assert!(has_from(&ann, bob.key()) && has_from(&bob, ann.key()));
    for peer in [a, b] {
        assert!(peer.refused().is_empty(), "{:?}", peer.refused());
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_and_three_peers_converge_and_a_conflict_is_one_everywhere() {
    let dir = scratch("converge");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let classify = ann.entry("classify");
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &ticket).await;
    until("Bob is in", || b.readers() == [ann.key()]).await;
    b.close().await;
    // Apart, both name `classify`, concurrently; Bob's work waits for
    // his next link.
    ann.rename("classify", "sort");
    bob.rename("classify", "order");
    bob.session
        .comment(bob.entry("checked"), Some("Bob was here"))
        .unwrap();
    let b = bob.join(&net, &ticket).await;
    until("Ann and Bob converge", || {
        converged(&[&ann, &bob]) && has_from(&ann, bob.key())
    })
    .await;
    assert_eq!(b.role(), Some(Role::Editor));
    // One conflict, both names, on both.
    for person in [&ann, &bob] {
        let conflicts = person.session.conflicts();
        assert_eq!(conflicts.len(), 1, "{}", person.name);
        assert_eq!(conflicts[0].key, Key::FunctionName(classify));
        let mut names: Vec<_> = conflicts[0]
            .leaves
            .iter()
            .map(|leaf| leaf.value.clone())
            .collect();
        names.sort_by_key(|value| format!("{value:?}"));
        assert_eq!(
            names,
            [
                Value::Text(Some("order".to_owned())),
                Value::Text(Some("sort".to_owned()))
            ]
        );
    }
    let c = cat.join(&net, &ticket).await;
    until("Cat is in", || c.readers() == [ann.key()]).await;
    ann.rename("loop_sum", "sum");
    cat.rename("checked", "guard");
    until("three converge", || {
        converged(&[&ann, &bob, &cat]) && has_from(&bob, cat.key())
    })
    .await;
    assert_eq!(asked.load(Ordering::SeqCst), 2);
    assert_eq!(cat.session.conflicts().len(), 1);
    assert_eq!(cat.session.edits(), ann.session.edits());
    // Bob resolves; the conflict is gone everywhere.
    let key = bob.session.conflicts()[0].key.clone();
    bob.session
        .resolve(key, Value::Text(Some("order".to_owned())))
        .unwrap();
    until("the resolution reaches everyone", || {
        converged(&[&ann, &bob, &cat])
            && [&ann, &bob, &cat]
                .iter()
                .all(|person| person.session.conflicts().is_empty())
    })
    .await;
    assert_eq!(cat.session.name(classify).as_deref(), Some("order"));
    for peer in [a, b, c] {
        assert!(peer.refused().is_empty(), "{:?}", peer.refused());
        peer.close().await;
    }
}

/// `tests/fixtures/sigs-app-gcc.elf` (stripped) and its `exit`'s entry.
fn sigs_app() -> (PathBuf, u64) {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    (fixtures.join("sigs-app-gcc.elf"), 0x40_1360)
}

/// A pack of the library `sigs-app-gcc.elf` links (`sigs-1@1`), written
/// to `file`.
fn sigs_pack(file: &Path) {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let input = |name: &str| (name.to_owned(), fs::read(fixtures.join(name)).unwrap());
    let pack = binbun::signatures::make(
        &[input("sigs-gcc.a"), input("sigs-exit-gcc.o")],
        &binbun::signatures::MakeOptions {
            library: "sigs".into(),
            version: "1".into(),
            licence: "MIT".into(),
            build: "gcc-O2".into(),
            separators: true,
            ..binbun::signatures::MakeOptions::default()
        },
    )
    .unwrap();
    fs::write(file, pack.write().unwrap()).unwrap();
}

/// Ann's session names `exit` by a library signature as it opens (one
/// change by `sig:sigs-1@1`); Bob reads no packs, joins, and has the name
/// from that signature with its record; his rejection reaches Ann: the
/// name is gone there too, the record kept as rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signatures_match_by_the_host_and_its_rejection_by_a_member_cross() {
    let dir = scratch("signatures");
    let pack = dir.join("sigs.jsonl");
    sigs_pack(&pack);
    let (app, exit) = sigs_app();
    let open = |name: &'static str, signatures: SignatureOptions| {
        let home = dir.join(name);
        Person::open_file(
            name,
            &home,
            &app,
            Options {
                project: Some(home.join("project")),
                signatures,
                ..Options::default()
            },
        )
    };
    // Identity alone: no background run to race the test's changes.
    let ann = open(
        "ann",
        SignatureOptions {
            packs: Some(vec![pack]),
            behaviour: false,
            ..SignatureOptions::default()
        },
    );
    let bob = open(
        "bob",
        SignatureOptions {
            enabled: false,
            ..SignatureOptions::default()
        },
    );
    ann.session.wait(Stage::Signatures, None);
    bob.session.wait(Stage::Signatures, None);
    assert_eq!(ann.session.name(exit).as_deref(), Some("exit"));
    assert_eq!(bob.session.name(exit), None);
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &ticket).await;
    until("the match reaches Bob", || {
        converged(&[&ann, &bob]) && bob.session.name(exit).is_some()
    })
    .await;
    assert_eq!(bob.session.name(exit).as_deref(), Some("exit"));
    assert_eq!(bob.session.name_source(exit), Some(NameSource::Signature));
    let identified = bob.session.signature(exit).unwrap();
    assert_eq!(
        (identified.pack.as_str(), identified.name.as_str()),
        ("sigs-1@1", "exit")
    );
    assert!(identified.no_return && !identified.rejected);
    // Ann's change by the signature, not one Bob made again.
    let by = Origin::Signature("sigs-1@1".to_owned());
    let made: Vec<PublicKey> = bob
        .session
        .history()
        .iter()
        .filter(|entry| entry.origin == by)
        .map(|entry| entry.author)
        .collect();
    assert_eq!(made, [ann.key()]);
    // Bob rejects it; Ann's name goes, her record says rejected.
    bob.session.reject_signature(exit).unwrap();
    until("the rejection reaches Ann", || {
        converged(&[&ann, &bob])
            && ann
                .session
                .signature(exit)
                .is_some_and(|identified| identified.rejected)
    })
    .await;
    assert_eq!(ann.session.name(exit), None);
    assert_eq!(ann.session.name_source(exit), None);
    for peer in [a, b] {
        assert!(peer.refused().is_empty(), "{:?}", peer.refused());
        peer.close().await;
    }
}

/// Whether `person`'s session has any change by `author`.
fn has_from(person: &Person, author: PublicKey) -> bool {
    person
        .session
        .history()
        .iter()
        .any(|entry| entry.author == author)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_viewers_writes_are_taken_by_no_peer() {
    let dir = scratch("viewer");
    let (ann, bob, vic) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "vic"),
    );
    let checked = ann.entry("checked");
    let net = MemNet::new();
    let vic_key = vic.key();
    let approve: Approver = Arc::new(move |request| {
        let role = if request.card.key == vic_key {
            Role::Viewer
        } else {
            Role::Editor
        };
        Box::pin(async move { Some(role) })
    });
    let (a, ticket) = ann.share(&net, approve).await;
    let b = bob.join(&net, &ticket).await;
    let v = vic.join(&net, &ticket).await;
    ann.rename("classify", "sort");
    until("all three converge", || {
        converged(&[&ann, &bob, &vic]) && vic.session.name(ann.entry("sort")).is_some()
    })
    .await;
    assert_eq!(v.role(), Some(Role::Viewer));
    // A viewer talks: his thread reaches everyone.
    vic.session
        .open_thread(Anchor::Function(checked), "checked")
        .unwrap();
    until("Vic's thread reaches Ann and Bob", || {
        has_from(&ann, vic_key) && has_from(&bob, vic_key)
    })
    .await;
    // His edit his own session takes not.
    vic.rename_refused(checked, "mine");
    // One his key signs anyway (another client of his): taken by no
    // peer, his role not one that edits.
    let thread = vic.last(vic.chain());
    let ann_edit = ann.last(ann.chain());
    let edit = following(&thread, &vic.identity, |body| {
        *body = Body {
            hlc: body.hlc,
            ..Body::decode(&ann_edit.body).unwrap()
        };
    });
    for person in [&ann, &bob] {
        let applied = person.session.receive(vec![edit.clone()]);
        assert!(applied.taken.is_empty(), "{} took Vic's edit", person.name);
        assert_eq!(
            person.session.name(checked).as_deref(),
            Some("checked"),
            "{}",
            person.name
        );
    }
    ann.rename("loop_sum", "sum");
    until("Ann's next edit reaches Bob and Vic", || {
        converged(&[&ann, &bob, &vic])
    })
    .await;
    for person in [&ann, &bob, &vic] {
        assert_eq!(person.seq(vic.chain()), thread.id().seq, "{}", person.name);
    }
    for peer in [a, b, v] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_member_rekeys_and_refuses_their_later_changes_everywhere() {
    let dir = scratch("remove");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let (classify, checked, loop_sum) = (
        ann.entry("classify"),
        ann.entry("checked"),
        ann.entry("loop_sum"),
    );
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    ann.rename("main", "start");
    bob.rename("classify", "bobs");
    until("all three converge", || {
        converged(&[&ann, &bob, &cat]) && has_from(&cat, bob.key()) && has_from(&cat, ann.key())
    })
    .await;
    let before = ann.seq(ann.chain());
    let last = bob.last(bob.chain());
    // Ann's chain as sealed in epoch 0, whose key Bob holds.
    let opened = a.seal_after(ann.chain(), 0).unwrap();
    let epoch = a.remove(bob.key()).unwrap();
    assert_eq!(epoch, 1);
    until("Cat holds epoch 1's key and Bob is put out", || {
        c.epochs().contains(&1) && put_out(&bob)
    })
    .await;
    assert_eq!(b.epochs(), [0]);
    // Put out with the record of it: Bob knows he was removed.
    assert_eq!(b.role(), None);
    assert_eq!(b.membership().epoch(), 1);
    // Ann's change after the removal: Cat takes it; Bob cannot open it:
    // declined where it came from, nothing stopped or kept for it.
    ann.rename("loop_sum", "sum");
    until("Cat takes Ann's change", || converged(&[&ann, &cat])).await;
    let after = a.seal_after(ann.chain(), before).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(Envelope::parse(&after[0]).unwrap().epoch(), 1);
    let received = b.receive(&after);
    assert_eq!(
        (received.taken, received.held, received.refused.len()),
        (0, 0, 1),
        "{received:?}"
    );
    assert_eq!(bob.session.name(loop_sum).as_deref(), Some("loop_sum"));
    // Nor is anything handed to him taken that he could open: the key
    // sealing the share's binary since his removal is not his, so the
    // binary open is not known to be the share's.
    let received = b.receive(&opened);
    assert_eq!(
        (received.taken, received.held, received.refused.len()),
        (0, 0, opened.len()),
        "{received:?}"
    );
    // Bob's change after the removal: his own session takes it not; one
    // his key signs anyway is refused by Ann and Cat alike.
    bob.rename_refused(checked, "late");
    let late = following(&last, &bob.identity, |body| {
        body.label = "late".to_owned();
    });
    for person in [&ann, &cat] {
        let applied = person.session.receive(vec![late.clone()]);
        assert!(
            applied.taken.is_empty(),
            "{} took Bob's late change",
            person.name
        );
        assert_eq!(person.seq(bob.chain()), last.id().seq);
        assert_eq!(person.tips(), ann.tips());
    }
    // What Bob had up to the cut stays his.
    assert_eq!(bob.session.name(classify).as_deref(), Some("bobs"));
    assert_eq!(ann.session.name(classify).as_deref(), Some("bobs"));
    for peer in [a, b, c] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_cuts_a_members_later_changes_on_every_peer_held_ones_included() {
    let dir = scratch("remove-held");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let checked = ann.entry("checked");
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    for person in [&bob, &cat] {
        a.add(&Card::new(&person.identity, person.name), Role::Editor)
            .unwrap();
    }
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    bob.rename("classify", "early");
    until("all three have Bob's early name", || {
        converged(&[&ann, &bob, &cat]) && has_from(&cat, bob.key())
    })
    .await;
    let chain = bob.chain();
    let kept = bob.seq(chain);
    // Cat goes on apart; Ann names `checked`, and Bob takes it.
    c.close().await;
    let c = cat.apart(&ticket).await;
    ann.session
        .rename_function(checked, Some("ann_checked"))
        .unwrap();
    until("Bob takes Ann's name", || {
        bob.session.name(checked).as_deref() == Some("ann_checked")
    })
    .await;
    // Bob goes on alone with a reader that takes nothing, and names it
    // again: his change, admitted, follows Ann's and reaches no one.
    b.close().await;
    let (b, _reader) = bob.alone_with(&ann.identity).await;
    bob.session.rename_function(checked, Some("b1")).unwrap();
    assert_eq!(bob.seq(chain), kept + 1);
    let later = bob.session.changes_after(chain, kept, 8, usize::MAX);
    assert_eq!(later.len(), 1);
    let sealed = b.seal_after(chain, kept).unwrap();
    assert_eq!(sealed.len(), 1);
    // Cat, without Ann's, holds it, waiting for hers.
    let applied = cat.session.receive(later.clone());
    assert_eq!((applied.taken.len(), applied.held), (0, 1), "{applied:?}");
    // Ann removes Bob at what she has of him. Cat links again: the
    // removal comes, and Ann's change the one held waits for.
    a.remove(bob.key()).unwrap();
    c.close().await;
    let c = cat.join(&net, &ticket).await;
    until("Cat takes the removal and Ann's name", || {
        c.membership().epoch() == 1 && cat.session.name(checked).as_deref() == Some("ann_checked")
    })
    .await;
    // Handed again, by the session and sealed, it is taken nowhere.
    for (person, peer) in [(&ann, &a), (&cat, &c)] {
        let applied = person.session.receive(later.clone());
        assert!(applied.taken.is_empty(), "{}: {applied:?}", person.name);
        let received = peer.receive(&sealed);
        assert_eq!(received.taken, 0, "{}: {received:?}", person.name);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    for person in [&ann, &cat] {
        assert_eq!(person.seq(chain), kept, "{}", person.name);
        assert_eq!(
            person.session.name(checked).as_deref(),
            Some("ann_checked"),
            "{}",
            person.name
        );
        assert!(
            person
                .session
                .history()
                .iter()
                .all(|entry| entry.id.chain != chain || entry.id.seq <= kept),
            "{} lists a change of Bob's past the cut",
            person.name
        );
    }
    assert_eq!(ann.tips(), cat.tips());
    for peer in [a, b, c] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_added_after_a_removal_reads_the_whole_history_from_another_member_the_owner_away()
{
    let dir = scratch("history");
    let (ann, bob, cat, dan, eve) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
        Person::new(&dir, "dan"),
        Person::new(&dir, "eve"),
    );
    let [classify, checked, loop_sum, main] =
        ["classify", "checked", "loop_sum", "main"].map(|name| ann.entry(name));
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    for person in [&bob, &cat, &eve] {
        a.add(&Card::new(&person.identity, person.name), Role::Editor)
            .unwrap();
    }
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    let eves_peer = eve.join(&net, &ticket).await;
    // Epoch 0: Ann and Bob write.
    ann.rename("checked", "ann_checked");
    bob.rename("classify", "bob_classify");
    until("all four have both names", || {
        converged(&[&ann, &bob, &cat, &eve])
            && has_from(&cat, bob.key())
            && has_from(&eve, bob.key())
    })
    .await;
    // Eve goes on alone in epoch 0, with a reader that takes nothing:
    // her change reaches no one, sealed under epoch 0's key.
    eves_peer.close().await;
    let (eves_peer, reader) = eve.alone_with(&cat.identity).await;
    eve.rename("main", "eve_main");
    let eves = eves_peer.seal_after(eve.chain(), 0).unwrap();
    assert_eq!(eves.len(), 2);
    assert!(
        eves.iter()
            .all(|envelope| Envelope::parse(envelope).unwrap().epoch() == 0)
    );
    eves_peer.close().await;
    drop(reader);
    // Epoch 1: Bob removed, Ann writes, Dan added.
    a.remove(bob.key()).unwrap();
    ann.rename("loop_sum", "ann_loop");
    a.add(&Card::new(&dan.identity, "dan"), Role::Editor)
        .unwrap();
    until("Cat has it all", || {
        converged(&[&ann, &cat]) && c.membership().seq() == a.membership().seq()
    })
    .await;
    a.close().await;
    b.close().await;
    // Ann away, Cat hosts; Dan joins her.
    let mesh = MemNet::new();
    let (c, by_cat) = cat.host(&mesh).await;
    let dans_peer = dan.join(&mesh, &by_cat).await;
    until("Dan has what Cat has", || {
        converged(&[&cat, &dan]) && has_from(&dan, bob.key())
    })
    .await;
    assert_eq!(dans_peer.epochs(), [1]);
    for (function, name) in [
        (classify, "bob_classify"),
        (checked, "ann_checked"),
        (loop_sum, "ann_loop"),
    ] {
        assert_eq!(dan.session.name(function).as_deref(), Some(name));
    }
    // Eve's, sealed in epoch 0, opens for him through the history the
    // records carry.
    let received = dans_peer.receive(&eves);
    assert_eq!(received.taken, eves.len(), "{received:?}");
    assert_eq!(dan.session.name(main).as_deref(), Some("eve_main"));
    for peer in [c, dans_peer] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_envelopes_are_refused() {
    let dir = scratch("tamper");
    let (ann, bob) = (Person::new(&dir, "ann"), Person::new(&dir, "bob"));
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &ticket).await;
    ann.rename("classify", "sort");
    until("Bob has Ann's chain", || converged(&[&ann, &bob])).await;
    // Bob stops syncing, so only what is handed to him arrives; a reader
    // that takes nothing stays linked to Ann, so her next change is
    // admitted.
    let _reader = Hand::idle(&a, &net, &ticket).await;
    let chain = ann.chain();
    let before = ann.seq(chain);
    b.close().await;
    let bob_peer = bob.apart(&ticket).await;
    ann.rename("checked", "guard");
    let sealed = a.seal_after(chain, before).unwrap();
    assert_eq!(sealed.len(), 1);
    let envelope = &sealed[0];
    let hash = ann.last(chain).hash();
    // project ‖ head ‖ author's signature ‖ epoch ‖ nonce ‖ ciphertext and
    // tag ‖ sealer ‖ seal's signature.
    let epoch = 16 + HEAD + SIG;
    let seal_at = envelope.len() - 32 - SIG;
    let flipped = |at: usize| {
        let mut tampered = envelope.clone();
        tampered[at] ^= 0x20;
        tampered
    };
    for (what, tampered) in [
        ("project", flipped(0)),
        ("head", flipped(16 + HEAD - 1)),
        ("author's signature", flipped(16 + HEAD + 3)),
        ("nonce", flipped(epoch + 4 + 3)),
        ("ciphertext", flipped(epoch + 28 + 3)),
        ("tag", flipped(seal_at - 1)),
        ("cut short", envelope[..envelope.len() - 1].to_vec()),
    ] {
        let received = bob_peer.receive(&[tampered]);
        assert_eq!(
            (received.taken, received.refused.len()),
            (0, 1),
            "{what}: {received:?}"
        );
    }
    // Another epoch's, whose key Bob has not: declined, not held, and no
    // stop of the chain.
    let received = bob_peer.receive(&[flipped(epoch + 3)]);
    assert_eq!(
        (received.taken, received.held, received.refused.len()),
        (0, 0, 1),
        "{received:?}"
    );
    // A bad sealing is no fork: nothing frozen.
    assert!(bob.session.frozen().is_empty());
    assert_ne!(
        bob.session.name(ann.entry("guard")).as_deref(),
        Some("guard")
    );
    // The seal names its sealer only as sealed.
    let genesis = a.membership().genesis().unwrap();
    let named = |bytes: &[u8]| crypto::sealer(&Envelope::parse(bytes).unwrap(), &genesis, hash);
    assert_eq!(named(envelope), Some(ann.key()));
    assert_eq!(named(&flipped(seal_at + 3)), None);
    assert_eq!(named(&flipped(envelope.len() - 1)), None);
    // The envelope itself is taken.
    assert_eq!(bob_peer.receive(&sealed).taken, 1);
    assert_eq!(
        bob.session.name(ann.entry("guard")).as_deref(),
        Some("guard")
    );
    a.close().await;
    bob_peer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ticket_replayed_after_its_share_closes_is_refused_before_anyone_is_asked() {
    let dir = scratch("replay");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, old) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &old).await;
    until("Bob is in", || b.role() == Some(Role::Editor)).await;
    a.close().await;
    // Shared again: the chain read back, a new invite.
    let (again, new) = ann.share(&net, approver(Role::Editor, &asked)).await;
    assert_eq!(again.membership().seq(), 2);
    assert_ne!(new.invite, old.invite);
    assert_eq!((new.project, new.owner), (old.project, old.owner));
    let c = cat.dial(&net, &old, EngineVersion::this()).await;
    until("Cat is turned away", || {
        heard(&cat, |n| matches!(n, Notice::Denied(_)))
    })
    .await;
    assert_eq!(asked.load(Ordering::SeqCst), 1, "Cat reached the approver");
    assert_eq!(c.role(), None);
    // Bob, a member, needs no invite: the old ticket links him again.
    ann.rename("classify", "sort");
    until("Bob syncs with the new share", || {
        converged(&[&ann, &bob]) && has_from(&bob, ann.key())
    })
    .await;
    for peer in [again, b, c] {
        peer.close().await;
    }
}

/// A member's binbun spoken by hand over its link: one that reaches
/// Reader, answers the host's ask for its tips with none, and then tells
/// nothing of what it holds.
struct Hand {
    link: Arc<dyn Link>,
    control: (SendStream, RecvStream),
    send: SendStream,
    recv: RecvStream,
}

impl Hand {
    /// A member `owner` (sharing over `net`, by `ticket`) adds, linked by
    /// hand up to Reader: the owner's edits are admitted while no one
    /// else is linked, and reach no one.
    async fn idle(owner: &Peer, net: &MemNet, ticket: &JoinTicket) -> Self {
        let who = Identity::ephemeral().unwrap();
        owner.add(&Card::new(&who, "dan"), Role::Viewer).unwrap();
        let hand = Self::reader(net, &who, ticket).await;
        until("the idle reader is linked", || {
            owner.readers().contains(&who.public())
        })
        .await;
        hand
    }

    /// `who`, a member, linked to `ticket`'s host: hello, welcome, the
    /// sync lane; the host's membership head said back, its `Ready`
    /// answered.
    async fn reader(net: &MemNet, who: &Identity, ticket: &JoinTicket) -> Self {
        let link = net
            .endpoint(who.public())
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
            card: Card::new(who, "dan"),
            membership: (0, [0; 32]),
            features: FEATURES,
        };
        write_frame(&mut *send, &Control::Hello(Box::new(hello)))
            .await
            .unwrap();
        let welcome = read_frame::<Control>(&mut *recv).await.unwrap();
        assert!(
            matches!(welcome, Some(Control::Welcome { .. })),
            "{welcome:?}"
        );
        let (sync_send, sync_recv) = link.open(Lane::Sync).await.unwrap();
        let mut hand = Self {
            link,
            control: (send, recv),
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
                // The host's one request at Reader answered (no tips), so
                // no request of its stays unanswered past its deadline.
                let asked = hand
                    .first(Duration::from_secs(10), |m| {
                        matches!(m, Sync::TipsAsk { .. })
                    })
                    .await;
                let Some(Sync::TipsAsk { id, .. }) = asked else {
                    panic!("no tips asked at Reader: {asked:?}");
                };
                hand.say(&Sync::TipsPage {
                    id,
                    tips: Bounded::new(),
                    next: None,
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

    /// The host's first message `matching` within `wait`, those before it
    /// read; none if none comes (or the lane ends).
    async fn first(&mut self, wait: Duration, matching: impl Fn(&Sync) -> bool) -> Option<Sync> {
        tokio::time::timeout(wait, async {
            loop {
                let message = self.next().await?;
                if matching(&message) {
                    return Some(message);
                }
            }
        })
        .await
        .ok()
        .flatten()
    }

    /// The kick on the control lane, within 10 s: its records.
    async fn kicked(&mut self) -> Vec<SignedRecord> {
        let kick = tokio::time::timeout(
            Duration::from_secs(10),
            read_frame::<Answer>(&mut *self.control.1),
        )
        .await
        .expect("a kick in time")
        .unwrap();
        let Some(Answer(Control::Kick { records, .. })) = kick else {
            panic!("not a kick: {kick:?}");
        };
        assert!(!records.more);
        records.items.to_vec()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_whose_third_record_fails_keeps_the_first_two_and_puts_out_whom_they_removed() {
    let dir = scratch("page-fails");
    let (ann, cat) = (Person::new(&dir, "ann"), Person::new(&dir, "cat"));
    let (xan, yan) = (
        Identity::ephemeral().unwrap(),
        Identity::ephemeral().unwrap(),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    a.add(&Card::new(&cat.identity, "cat"), Role::Editor)
        .unwrap();
    for (who, name) in [(&xan, "xan"), (&yan, "yan")] {
        a.add(&Card::new(who, name), Role::Viewer).unwrap();
    }
    let c = cat.join(&net, &ticket).await;
    until("Cat holds the chain", || {
        c.membership().seq() == a.membership().seq()
    })
    .await;
    c.close().await;
    // Cat hosts on her own; Xan and Yan read from her.
    let mesh = MemNet::new();
    let (c, by_cat) = cat.host(&mesh).await;
    let mut xans = Hand::reader(&mesh, &xan, &by_cat).await;
    let mut yans = Hand::reader(&mesh, &yan, &by_cat).await;
    until("both read from Cat", || c.readers().len() == 2).await;
    // Out of Cat's sight, Ann removes Xan and adds two more.
    let held = c.membership().seq();
    a.remove(xan.public()).unwrap();
    for name in ["dan", "eve"] {
        let who = Identity::ephemeral().unwrap();
        a.add(&Card::new(&who, name), Role::Viewer).unwrap();
    }
    let records = a.membership().since(held).to_vec();
    assert_eq!(records.len(), 3);
    // Yan pushes the three, the third's signature not the owner's.
    let mut broken = records[2].clone();
    broken.sig = SigningKey::from_bytes(&yan.secret()).sign(&broken.bytes);
    let page: Vec<RecordBytes> = [&records[0], &records[1], &broken]
        .iter()
        .map(|signed| RecordBytes::try_from(postcard::to_allocvec(signed).unwrap()).unwrap())
        .collect();
    yans.say(&Sync::Records {
        id: None,
        records: Bounded::truncated(page),
        more: false,
    })
    .await;
    // The two before it taken, and Xan put out at once with the records
    // through his removal, none after it.
    until("Cat takes the two", || c.membership().seq() == held + 2).await;
    assert_eq!(xans.kicked().await, records[..1]);
    assert!(c.membership().removed(xan.public()));
    assert_eq!(c.membership().seq(), held + 2);
    for peer in [a, c] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_member_dialling_again_learns_of_its_removal_and_nothing_after() {
    let dir = scratch("kick-prefix");
    let (ann, bob) = (Person::new(&dir, "ann"), Person::new(&dir, "bob"));
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    a.add(&Card::new(&bob.identity, "bob"), Role::Editor)
        .unwrap();
    let b = bob.join(&net, &ticket).await;
    until("Bob holds the chain", || {
        b.membership().seq() == a.membership().seq()
    })
    .await;
    b.close().await;
    // Removed while away; someone added after.
    a.remove(bob.key()).unwrap();
    let removal = a.membership().seq();
    let dan = Identity::ephemeral().unwrap();
    a.add(&Card::new(&dan, "dan"), Role::Editor).unwrap();
    let b = bob.dial(&net, &ticket, EngineVersion::this()).await;
    until("Bob is put out", || put_out(&bob)).await;
    let chain = b.membership();
    assert!(chain.removed(bob.key()));
    assert_eq!(chain.seq(), removal);
    assert_eq!(chain.role(dan.public()), None);
    for peer in [a, b] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flush_hears_only_the_link_each_member_had_when_it_began() {
    let dir = scratch("flush-link");
    let ann = Person::new(&dir, "ann");
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    ann.rename("main", "ann_main");
    let xan = Identity::ephemeral().unwrap();
    a.add(&Card::new(&xan, "xan"), Role::Viewer).unwrap();
    let first = Hand::reader(&net, &xan, &ticket).await;
    until("Xan reads", || a.readers().contains(&xan.public())).await;
    // Xan links again while the flush runs, and on the new link tells he
    // holds Ann's change: the link the flush began with told nothing, and
    // went.
    let tip = ann.session.tip(ann.chain()).unwrap();
    let again = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut second = Hand::reader(&net, &xan, &ticket).await;
        second
            .say(&Sync::Tips {
                tips: Bounded::truncated(vec![tip]),
            })
            .await;
        second
    };
    let (flushed, second) = tokio::join!(a.flush(Duration::from_secs(10)), again);
    assert_eq!(flushed.acknowledged, Vec::<PublicKey>::new());
    assert_eq!(flushed.disconnected, vec![xan.public()]);
    // A flush begun on the new link hears it.
    let flushed = a.flush(Duration::from_secs(10)).await;
    assert_eq!(flushed.acknowledged, vec![xan.public()]);
    drop((first, second));
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_removed_between_welcome_and_sync_is_never_linked() {
    let dir = scratch("late-removal");
    let ann = Person::new(&dir, "ann");
    let xan = Identity::ephemeral().unwrap();
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    a.add(&Card::new(&xan, "xan"), Role::Viewer).unwrap();
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
    assert!(
        matches!(welcome, Some(Control::Welcome { .. })),
        "{welcome:?}"
    );
    // Removed once welcomed, before the sync lane opens: the link is
    // not put up, and nothing comes on the lane.
    a.remove(xan.public()).unwrap();
    let (_sync, mut lane) = link.open(Lane::Sync).await.unwrap();
    let first = tokio::time::timeout(
        Duration::from_secs(10),
        read_frame_length(&mut *lane, FRAME),
    )
    .await
    .expect("the lane ends in time");
    assert!(matches!(first, Ok(None) | Err(_)), "{first:?}");
    assert_eq!(a.links(), Vec::<(PublicKey, String)>::new());
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_members_live_lane_is_written_nothing_more() {
    let dir = scratch("live-fence");
    let ann = Person::new(&dir, "ann");
    let xan = Identity::ephemeral().unwrap();
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    a.add(&Card::new(&xan, "xan"), Role::Viewer).unwrap();
    // Xan, by hand, reads nothing on his control lane: a kick does not
    // end his link.
    let hand = Hand::reader(&net, &xan, &ticket).await;
    let (lane, _, mut live) = tokio::time::timeout(Duration::from_secs(10), hand.link.accept())
        .await
        .expect("a live lane in time")
        .unwrap();
    assert_eq!(lane, Lane::Live);
    // The frame on it within `wait`, if one comes.
    let frame = async |live: &mut RecvStream, wait: Duration| {
        tokio::time::timeout(wait, read_frame_length(&mut **live, LIVE_FRAME))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
    };
    // Ann's greeting comes, then nothing for a while.
    let mut greeting = frame(&mut live, Duration::from_secs(10)).await;
    assert!(greeting.is_some());
    while let Some(length) = greeting {
        read_bytes(&mut *live, length).await.unwrap();
        greeting = frame(&mut live, Duration::from_millis(500)).await;
    }
    // Removed, then Ann says something: none of it is written to him.
    a.remove(xan.public()).unwrap();
    a.chat("said after the removal", &[], &[]).unwrap();
    assert_eq!(frame(&mut live, Duration::from_secs(2)).await, None);
    drop(hand);
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flush_returns_once_every_member_linked_has_this_peers_changes() {
    let dir = scratch("flush");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let classify = ann.entry("classify");
    let dan = Identity::ephemeral().unwrap();
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    for (identity, name) in [
        (&bob.identity, "bob"),
        (&cat.identity, "cat"),
        (&dan, "dan"),
    ] {
        a.add(&Card::new(identity, name), Role::Editor).unwrap();
    }
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    // Each side's link is its own: Bob flushes to those he has linked.
    until("both are readers", || {
        a.readers().len() == 2 && b.readers().len() == 1 && c.readers().len() == 1
    })
    .await;
    // Bob edits and closes at once: the flush is what carries the edit.
    bob.rename("classify", "sort");
    let flushed = b.flush(Duration::from_secs(5)).await;
    assert_eq!(
        flushed,
        Flushed {
            acknowledged: vec![ann.key()],
            unacknowledged: vec![],
            disconnected: vec![],
        }
    );
    b.close().await;
    assert_eq!(ann.session.name(classify).as_deref(), Some("sort"));
    until("Ann's link to Bob is down", || {
        a.links().iter().all(|(key, _)| *key != bob.key())
    })
    .await;
    // Dan's binbun reaches Reader and tells nothing: Ann's flush waits
    // for him to the end, Cat telling she has it.
    let mut hand = Hand::reader(&net, &dan, &ticket).await;
    until("Dan is a reader", || a.readers().contains(&dan.public())).await;
    ann.rename("checked", "guard");
    let flushed = a.flush(Duration::from_millis(500)).await;
    assert_eq!(
        flushed,
        Flushed {
            acknowledged: vec![cat.key()],
            unacknowledged: vec![dan.public()],
            disconnected: vec![],
        }
    );
    assert_eq!(
        cat.session.name(cat.entry("guard")).as_deref(),
        Some("guard")
    );
    assert_eq!(cat.session.name(classify).as_deref(), Some("sort"));
    // His link goes during the next: he is told apart.
    ann.rename("loop_sum", "sum");
    let (flushed, ()) = tokio::join!(a.flush(Duration::from_secs(5)), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        hand.link.close("gone");
        while hand.next().await.is_some() {}
    });
    assert_eq!(
        flushed,
        Flushed {
            acknowledged: vec![cat.key()],
            unacknowledged: vec![],
            disconnected: vec![dan.public()],
        }
    );
    for peer in [a, c] {
        peer.close().await;
    }
}

/// A mesh where an editor hosts, cut short: Ann (the owner), Bob and Cat
/// are members; Bob names `classify` early (all three have it). Then
/// Ann is away while Cat hosts and Bob joins her: Ann named `checked`
/// before, Bob names it again (over Ann's) and names `loop_sum`, and Cat
/// names `loop_sum` after Bob. Away, Ann cuts Bob (`lower`: makes him a
/// viewer; else removes him) at what she has of him, the early name
/// only; then she joins Cat, whose peer takes the cut after Bob's names.
/// The people, their peers (Ann's, Bob's, Cat's), the functions
/// (`classify`, `checked`, `loop_sum`), and Bob's chain and the change
/// the cut keeps.
async fn cut_in_a_mesh(
    dir: &Path,
    lower: bool,
) -> ([Person; 3], [Peer; 3], [u64; 3], (ChainId, u64)) {
    let (ann, bob, cat) = (
        Person::new(dir, "ann"),
        Person::new(dir, "bob"),
        Person::new(dir, "cat"),
    );
    let functions = ["classify", "checked", "loop_sum"].map(|name| ann.entry(name));
    let [classify, checked, loop_sum] = functions;
    let asked = Arc::new(AtomicUsize::new(0));
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    ann.session
        .rename_function(checked, Some("ann_checked"))
        .unwrap();
    bob.session
        .rename_function(classify, Some("bob_early"))
        .unwrap();
    until("all three have both names", || {
        converged(&[&ann, &bob, &cat]) && has_from(&cat, ann.key()) && has_from(&cat, bob.key())
    })
    .await;
    let kept = (bob.chain(), bob.seq(bob.chain()));
    for peer in [a, b, c] {
        peer.close().await;
    }
    // Cat hosts (an editor: she lets members in, admits no one); Bob
    // joins her. Ann is away.
    let mesh = MemNet::new();
    let (c, by_cat) = cat.share(&mesh, approver(Role::Editor, &asked)).await;
    assert_eq!(by_cat.owner, ann.key());
    let b = bob.join(&mesh, &by_cat).await;
    bob.session
        .rename_function(checked, Some("bob_checked"))
        .unwrap();
    bob.session
        .rename_function(loop_sum, Some("bob_loop"))
        .unwrap();
    until("Cat takes Bob's names", || {
        cat.session.name(checked).as_deref() == Some("bob_checked")
            && cat.session.name(loop_sum).as_deref() == Some("bob_loop")
    })
    .await;
    cat.session
        .rename_function(loop_sum, Some("cat_loop"))
        .unwrap();
    until("Bob takes Cat's", || {
        bob.session.name(loop_sum).as_deref() == Some("cat_loop")
    })
    .await;
    // Away, Ann cuts Bob at what she has of him.
    let away = MemNet::new();
    let (a, _) = ann.share(&away, approver(Role::Editor, &asked)).await;
    if lower {
        a.set_role(bob.key(), Role::Viewer).unwrap();
    } else {
        a.remove(bob.key()).unwrap();
    }
    a.close().await;
    let a = ann.join(&mesh, &by_cat).await;
    ([ann, bob, cat], [a, b, c], functions, kept)
}

/// What a frozen chain leaves, on every peer: `checked` back to Ann's
/// name (the writer before Bob's), `loop_sum` Cat's (written after Bob's:
/// last writer wins), `classify` Bob's early name (within the cut); none
/// of Bob's changes past the cut in the history, each listed refused.
async fn frozen_everywhere(
    people: &[Person; 3],
    peers: &[Peer; 3],
    functions: [u64; 3],
    kept: (ChainId, u64),
) {
    let [ann, bob, cat] = people;
    let [classify, checked, loop_sum] = functions;
    let (chain, cut) = kept;
    until("Cat drops Bob's names past the cut", || {
        cat.session.name(checked).as_deref() == Some("ann_checked")
    })
    .await;
    until("Ann and Cat converge", || converged(&[ann, cat])).await;
    until("Bob drops them too", || {
        bob.session.name(checked).as_deref() == Some("ann_checked")
    })
    .await;
    for person in people {
        let session = &person.session;
        assert_eq!(
            session.name(classify).as_deref(),
            Some("bob_early"),
            "{}",
            person.name
        );
        assert_eq!(
            session.name(checked).as_deref(),
            Some("ann_checked"),
            "{}",
            person.name
        );
        assert_eq!(
            session.name(loop_sum).as_deref(),
            Some("cat_loop"),
            "{}",
            person.name
        );
        assert!(session.conflicts().is_empty(), "{}", person.name);
        assert_eq!(
            session.frozen().get(&chain),
            Some(&(cut + 1)),
            "{}",
            person.name
        );
        assert!(
            session
                .history()
                .iter()
                .all(|entry| entry.id.chain != chain || entry.id.seq <= cut),
            "{} still lists a change of Bob's past the cut",
            person.name
        );
    }
    assert_eq!(cat.project_file(), bob.project_file());
    // Cat lists the two she dropped; Bob's session lists his.
    let past = |peer: &Peer| {
        peer.refused()
            .iter()
            .filter_map(|refused| refused.change)
            .filter(|id| id.chain == chain && id.seq > cut)
            .collect::<BTreeSet<_>>()
            .len()
    };
    assert_eq!(past(&peers[2]), 2, "{:?}", peers[2].refused());
    until("Bob's lists his", || past(&peers[1]) >= 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_arriving_late_freezes_what_was_taken_past_its_cut() {
    let dir = scratch("freeze-remove");
    let (people, peers, functions, kept) = cut_in_a_mesh(&dir, false).await;
    frozen_everywhere(&people, &peers, functions, kept).await;
    let [_, bob, cat] = &people;
    // His undo, of his early name, is refused: his writing is cut.
    let tips = bob.tips();
    let undone = bob.session.undo();
    assert!(
        matches!(undone, Err(binbun_session::Error::Refused(_))),
        "{undone:?}"
    );
    assert_eq!(bob.tips(), tips);
    // Bob is out; what he writes now his own session takes not, and what
    // his key signs anyway Cat refuses.
    until("Bob is put out", || put_out(bob)).await;
    let main = cat.entry("main");
    bob.rename_refused(main, "late");
    let last = bob.last(kept.0);
    let late = following(&last, &bob.identity, |body| {
        body.label = "late".to_owned();
    });
    assert_eq!(cat.session.receive(vec![late]).taken, Vec::new());
    assert_ne!(cat.session.name(main).as_deref(), Some("late"));
    for peer in peers {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_role_lowered_late_freezes_what_was_taken_past_its_cut() {
    let dir = scratch("freeze-lower");
    let (people, peers, functions, kept) = cut_in_a_mesh(&dir, true).await;
    frozen_everywhere(&people, &peers, functions, kept).await;
    let [_, bob, cat] = &people;
    // A viewer now, still linked: what he edits his own session takes
    // not; what his key signs anyway Cat takes not.
    until("Bob is a viewer", || peers[1].role() == Some(Role::Viewer)).await;
    // Nor is his undo taken.
    let tips = bob.tips();
    assert!(bob.session.undo().is_err());
    assert_eq!(bob.tips(), tips);
    let main = cat.entry("main");
    bob.rename_refused(main, "late");
    let last = bob.last(kept.0);
    let late = following(&last, &bob.identity, |body| {
        body.label = "late".to_owned();
    });
    assert_eq!(cat.session.receive(vec![late]).taken, Vec::new());
    assert_ne!(cat.session.name(main).as_deref(), Some("late"));
    for peer in peers {
        peer.close().await;
    }
}

/// Every file under `dir`, by its path there (`/`-separated), with its
/// bytes.
fn files_under(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let name = path.strip_prefix(dir).unwrap().to_string_lossy();
                files.push((name.replace('\\', "/"), fs::read(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_project_exports_without_its_share_and_imports_unshared() {
    let dir = scratch("export");
    let (ann, bob) = (Person::new(&dir, "ann"), Person::new(&dir, "bob"));
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &ticket).await;
    ann.rename("classify", "sort");
    bob.rename("checked", "guard");
    until("Ann and Bob converge", || {
        converged(&[&ann, &bob]) && has_from(&ann, bob.key()) && has_from(&bob, ann.key())
    })
    .await;
    // The binary offered: sealed blobs and offers kept in the share too.
    a.offer(Kind::Binary).await.unwrap();
    ann.session.save().unwrap();
    let mine = ann.session.project().unwrap().clone();
    let share = mine.dir().join("collab").join(ticket.project.to_string());
    assert!(share.join("membership.log").is_file());
    assert!(share.join("blobs").is_dir());

    let key = project::Key::of_file(&fixture()).unwrap();
    let file = dir.join("shared.binbun");
    project::export(&mine, &key, &file).unwrap();
    let bundle = Bundle::read(&file).unwrap();
    let paths = bundle.files().iter().map(|(path, _)| path);
    let logs = bundle.logs().iter().map(|(path, _)| path);
    for path in paths.chain(logs) {
        assert!(!path.starts_with("collab/"), "{path}");
    }

    // Carl, elsewhere, imports it: no share with it, the log byte for
    // byte (Ann's chain and Bob's) but the share's marks of what it
    // admitted.
    let carl_home = dir.join("carl");
    let root = carl_home.join("projects");
    let Imported::Installed(theirs) = project::import(&bundle, &root, false).unwrap() else {
        panic!("not installed");
    };
    assert!(!theirs.dir().join("collab").exists());
    let log = files_under(&theirs.dir().join("log"));
    let kept = files_under(&mine.dir().join("log"));
    for file in &log {
        assert!(kept.contains(file), "{} is not Ann's", file.0);
    }
    assert!(kept.iter().any(|(path, _)| path == "admitted"));
    assert!(log.iter().all(|(path, _)| path != "admitted"));
    let chains = |files: &[(String, Vec<u8>)]| -> Vec<(String, Vec<u8>)> {
        files
            .iter()
            .filter(|(path, _)| path.starts_with("chains/"))
            .cloned()
            .collect()
    };
    assert_eq!(chains(&log), chains(&kept));
    assert_eq!(chains(&log).len(), 2);

    let carl = Person::open(
        "carl",
        &carl_home,
        Options {
            project: Some(theirs.dir().to_owned()),
            ..Options::default()
        },
    );
    // Both people's edits, as Ann has them.
    assert_eq!(carl.entry("sort"), ann.entry("sort"));
    assert_eq!(carl.entry("guard"), ann.entry("guard"));
    let authors: Vec<PublicKey> = carl
        .session
        .history()
        .iter()
        .map(|entry| entry.author)
        .collect();
    assert!(authors.contains(&ann.key()) && authors.contains(&bob.key()));

    // Unshared: sharing it makes Carl the owner of a new membership, not
    // a member of Ann's.
    let elsewhere = MemNet::new();
    let (c, again) = carl.share(&elsewhere, approver(Role::Editor, &asked)).await;
    assert_eq!(again.owner, carl.key());
    assert_eq!(c.membership().seq(), 1);
    for peer in [a, b, c] {
        peer.close().await;
    }
}

/// Ann, her identity in `home` and her project kept in `root` as binbun
/// keeps projects (by the binary's contents), sharing it over `net`.
async fn sharing_in(home: &Path, root: &Path, net: &MemNet) -> (Person, Peer, JoinTicket) {
    let ann = Person::open(
        "ann",
        home,
        Options {
            projects: Some(root.to_owned()),
            ..Options::default()
        },
    );
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(net, approver(Role::Editor, &asked)).await;
    (ann, a, ticket)
}

/// `person`'s project exported to `file`, their changes saved first.
fn exported(person: &Person, file: &Path) -> Bundle {
    person.session.save().unwrap();
    let key = project::Key::of_file(&fixture()).unwrap();
    project::export(person.session.project().unwrap(), &key, file).unwrap();
    Bundle::read(file).unwrap()
}

/// The id of `person`'s log (what sharing it anew names the share).
fn log_id(person: &Person) -> ProjectId {
    let hex = person.session.project_id();
    let mut id = [0; 16];
    for (at, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).unwrap();
    }
    ProjectId(id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_project_replaced_by_its_own_export_keeps_its_share() {
    let dir = scratch("replace-same");
    let (home, root) = (dir.join("ann"), dir.join("ann").join("projects"));
    let net = MemNet::new();
    let (ann, a, ticket) = sharing_in(&home, &root, &net).await;
    let bob = Person::new(&dir, "bob");
    let b = bob.join(&net, &ticket).await;
    ann.rename("classify", "sort");
    until("Ann and Bob converge", || {
        converged(&[&ann, &bob]) && has_from(&bob, ann.key())
    })
    .await;
    a.offer(Kind::Binary).await.unwrap();
    let bundle = exported(&ann, &dir.join("ann.binbun"));
    let mine = ann.session.project().unwrap().clone();
    a.close().await;
    b.close().await;
    drop(ann);
    let collab = mine.dir().join("collab");
    let share = collab.join(ticket.project.to_string());
    let membership = fs::read(share.join("membership.log")).unwrap();
    let offers = fs::read(share.join("blobs").join("offers.bin")).unwrap();

    // Taken back over the project: the same log, so the share stays.
    assert_eq!(
        project::import(&bundle, &root, true).unwrap(),
        Imported::Installed(mine.clone())
    );
    assert_eq!(fs::read(share.join("membership.log")).unwrap(), membership);
    assert_eq!(
        fs::read(share.join("blobs").join("offers.bin")).unwrap(),
        offers
    );
    assert!(mine.lock().is_file());

    // Shared again: the same share, Ann its owner, Bob still a member
    // (the old ticket links him again).
    let net = MemNet::new();
    let (ann, a, again) = sharing_in(&home, &root, &net).await;
    assert_eq!((again.project, again.owner), (ticket.project, ann.key()));
    assert_eq!(a.membership().seq(), 2);
    let b = bob.join(&net, &ticket).await;
    until("Bob is in again", || b.role() == Some(Role::Editor)).await;
    ann.rename("loop_sum", "sum");
    until("Bob takes Ann's next edit", || {
        converged(&[&ann, &bob]) && bob.session.name(ann.entry("sum")).is_some()
    })
    .await;
    for peer in [a, b] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_project_replaced_by_another_projects_export_drops_that_share() {
    let dir = scratch("replace-other");
    let (home, root) = (dir.join("ann"), dir.join("ann").join("projects"));
    let (ann, a, ticket) = sharing_in(&home, &root, &MemNet::new()).await;
    let mine = ann.session.project().unwrap().clone();
    a.close().await;
    drop(ann);
    // Cat's project of the same binary: another log.
    let cat = Person::new(&dir, "cat");
    cat.rename("classify", "cats");
    let bundle = exported(&cat, &dir.join("cat.binbun"));
    let theirs = log_id(&cat);
    assert_ne!(theirs, ticket.project);

    assert_eq!(
        project::import(&bundle, &root, true).unwrap(),
        Imported::Installed(mine.clone())
    );
    // Ann's share was of the log replaced: gone with it; the lock stays.
    let collab = mine.dir().join("collab");
    assert!(!collab.join(ticket.project.to_string()).exists());
    assert!(mine.lock().is_file());

    // Opened, it has Cat's edits.
    let opened = Person::open(
        "ann",
        &home,
        Options {
            projects: Some(root.clone()),
            ..Options::default()
        },
    );
    assert_eq!(opened.entry("cats"), cat.entry("cats"));
    drop(opened);
    // Sharing it now shares Cat's log anew, Ann its owner: Cat's chain,
    // not Ann's own, kept apart.
    let (ann, a, again) = sharing_in(&home, &root, &MemNet::new()).await;
    assert_eq!((again.project, again.owner), (theirs, ann.key()));
    assert_eq!(a.membership().seq(), 1);
    assert!(ann.tips().is_empty(), "{:?}", ann.tips());
    assert!(!has_from(&ann, cat.key()));
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_peers_holding_another_last_change_of_one_chain_both_freeze_it_once_linked() {
    let dir = scratch("fork");
    let (ann, bob) = (Person::new(&dir, "ann"), Person::new(&dir, "bob"));
    let net = MemNet::new();
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    let b = bob.join(&net, &ticket).await;
    ann.rename("classify", "sort");
    until("both converge", || {
        converged(&[&ann, &bob]) && has_from(&bob, ann.key())
    })
    .await;
    let _reader = Hand::idle(&a, &net, &ticket).await;
    b.close().await;
    // Apart (Ann's change admitted for a reader that takes nothing), her
    // client signs her next change, and another at its place, which Bob's
    // session takes: one chain, as long on each side, its last change
    // another.
    let b = bob.apart(&ticket).await;
    let chain = ann.chain();
    ann.rename("sort", "order");
    let place = ann.seq(chain);
    let fork = beside(&ann.last(chain), "fork", &ann.identity);
    assert_eq!(bob.session.receive(vec![fork]).taken.len(), 1);
    assert_eq!(bob.seq(chain), place);
    assert_ne!(bob.last(chain).hash(), ann.last(chain).hash());
    b.close().await;

    let b = bob.join(&net, &ticket).await;
    // The freeze marks at once; its changes leave the names a batch at a
    // time after (sync §4.3).
    until("both freeze Ann's chain at that place", || {
        [&ann, &bob].iter().all(|person| {
            person.session.frozen().get(&chain) == Some(&place) && person.session.settled()
        })
    })
    .await;
    for person in [&ann, &bob] {
        assert!(person.session.evidence(chain).is_some(), "{}", person.name);
        assert_eq!(person.session.tip(chain).unwrap().fork, place);
        assert_eq!(
            person.session.name(person.entry("sort")).as_deref(),
            Some("sort")
        );
    }
    a.close().await;
    b.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fork_found_on_a_link_freezes_its_chain_on_both_sides() {
    let dir = scratch("fork-linked");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    for person in [&bob, &cat] {
        a.add(&Card::new(&person.identity, person.name), Role::Editor)
            .unwrap();
    }
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    ann.rename("classify", "sort");
    until("all three have Ann's chain", || {
        converged(&[&ann, &bob, &cat]) && has_from(&cat, ann.key())
    })
    .await;
    // Cat apart; Ann's next change reaches Bob, and another at its place,
    // signed by her key, reaches Cat.
    c.close().await;
    let c = cat.apart(&ticket).await;
    let chain = ann.chain();
    ann.rename("checked", "guard");
    let place = ann.seq(chain);
    until("Bob takes it", || bob.seq(chain) == place).await;
    let fork = beside(&ann.last(chain), "fork", &ann.identity);
    assert_eq!(cat.session.receive(vec![fork]).taken.len(), 1);
    let sealed = c.seal_after(chain, place - 1).unwrap();
    // Handed to Bob, linked to Ann: both freeze the chain there.
    let received = b.receive(&sealed);
    assert_eq!(received.taken, 0, "{received:?}");
    // Marked at once; taken out of the names a batch at a time after.
    until("Ann and Bob freeze Ann's chain at that place", || {
        [&ann, &bob].iter().all(|person| {
            person.session.frozen().get(&chain) == Some(&place) && person.session.settled()
        })
    })
    .await;
    for person in [&ann, &bob] {
        assert!(person.session.evidence(chain).is_some(), "{}", person.name);
        assert_ne!(
            person.session.name(person.entry("checked")).as_deref(),
            Some("guard"),
            "{}",
            person.name
        );
    }
    for peer in [a, b, c] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_names_none_of_its_chains_before_its_link_is_a_readers() {
    let dir = scratch("unbound");
    let bob = Person::new(&dir, "bob");
    bob.rename("classify", "mine");
    assert!(
        bob.session
            .chains()
            .iter()
            .any(|(_, author, seq)| *author == bob.key() && *seq > 1)
    );
    // A host of the test's own, which lets Bob in and says nothing past
    // its membership head.
    let net = MemNet::new();
    let host = Identity::ephemeral().unwrap();
    let end = net.endpoint(host.public());
    let ticket = JoinTicket {
        v: 1,
        host: end.addr(),
        owner: host.public(),
        project: ProjectId([9; 16]),
        invite: [1; 16],
        flags: 0,
        arch: None,
    };
    let b = bob.dial(&net, &ticket, EngineVersion::this()).await;
    let link = end.accept().await.unwrap();
    let (_, mut control_send, mut control_recv) = link.accept().await.unwrap();
    assert!(matches!(
        read_frame::<Control>(&mut *control_recv).await.unwrap(),
        Some(Control::Hello(_))
    ));
    let welcome = Control::Welcome {
        role: Role::Editor,
        view_only: None,
        features: FEATURES,
    };
    write_frame(&mut *control_send, &welcome).await.unwrap();
    let (lane, mut send, mut recv) = link.accept().await.unwrap();
    assert!(matches!(lane, Lane::Sync));
    // A while: only Bootstrap's messages come.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut said = Vec::new();
    while let Ok(Ok(Some(length))) =
        tokio::time::timeout_at(deadline, read_frame_length(&mut *recv, FRAME)).await
    {
        let bytes = read_bytes(&mut *recv, length).await.unwrap();
        said.push(Sync::decode(&bytes).unwrap());
    }
    assert!(
        matches!(said.first(), Some(Sync::MembershipHead { .. })),
        "{said:?}"
    );
    for message in &said {
        assert!(message.in_bootstrap(), "said before Reader: {message:?}");
    }
    assert_eq!(b.readers(), Vec::new());
    // A tip told before Reader closes the link.
    let tip = Sync::Tips {
        tips: Bounded::truncated(vec![Tip {
            chain: ChainId([7; 16]),
            project: ProjectId([9; 16]),
            seq: 3,
            hash: ChangeHash([7; 32]),
            fork: 0,
        }]),
    };
    write_bytes(&mut *send, &tip.encode().unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), link.closed())
        .await
        .expect("a tip before Reader closes the link");
    assert!(bob.session.tip(ChainId([7; 16])).is_none());
    b.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_on_another_binary_never_reaches_reader_and_nothing_crosses() {
    // Ann's share names her binary; Cat, on another, is let in and never
    // reaches Reader: nothing crosses either way.
    let dir = scratch("other-binary");
    let ann = Person::new(&dir, "ann");
    let cat = Person::open_file(
        "cat",
        &dir.join("cat"),
        &fixture().with_file_name("globals-x86_64.elf"),
        Options {
            project: Some(dir.join("cat").join("project")),
            ..Options::default()
        },
    );
    ann.rename("classify", "anns");
    let entry = {
        let database = cat.session.database().unwrap();
        database.functions().next().map(|(_, f)| f.entry).unwrap()
    };
    cat.session.rename_function(entry, Some("cats")).unwrap();
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    a.add(&Card::new(&cat.identity, "cat"), Role::Editor)
        .unwrap();
    let c = cat.dial(&net, &ticket, EngineVersion::this()).await;
    let start = Instant::now();
    while !heard(
        &cat,
        |n| matches!(n, Notice::Denied(why) if why.contains("another binary")),
    ) {
        assert!(a.readers().is_empty() && c.readers().is_empty());
        assert!(start.elapsed() < Duration::from_secs(30), "never told");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(a.readers().is_empty() && c.readers().is_empty());
    assert!(!has_from(&ann, cat.key()));
    assert!(!has_from(&cat, ann.key()));
    assert!(
        cat.session
            .chains()
            .iter()
            .all(|(_, author, _)| *author == cat.key())
    );
    a.close().await;
    c.close().await;
}

/// Budgets whose rates run on a clock that stands still until moved, and
/// the clock.
fn faked() -> (Budgets, FakeRelativeClock) {
    let clock = FakeRelativeClock::default();
    (Budgets::new(Clock::fake(clock.clone())), clock)
}

/// Spends the sync bytes `budgets` lets `to` be sent, then lets `left`
/// come again: what is longer waits for the clock to move.
fn spend(budgets: &Budgets, clock: &FakeRelativeClock, to: PublicKey, left: u32) {
    for chunk in [1 << 20, 1 << 10, 1] {
        while budgets.sync_out(to, chunk).is_zero() {}
    }
    clock.advance(SYNC_BYTES.over / SYNC_BYTES.burst * left);
}

/// Checks for `wait` that one page of changes stays in hand in `budgets`.
async fn held_for(budgets: &Budgets, wait: Duration) {
    let start = Instant::now();
    while start.elapsed() < wait {
        assert_eq!(budgets.pages_free(), SYNC_PAGES - 1);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A `Want` of all of `chain` from its start.
fn want_all(id: u32, chain: ChainId) -> Sync {
    Sync::Want {
        id,
        chain,
        after: 0,
        at: ChangeHash::ZERO,
        most: 256,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_permit_is_held_through_its_rate_and_write_and_given_back_at_revocation_or_deadline()
{
    let dir = scratch("page-permit");
    let ann = Person::new(&dir, "ann");
    let (budgets, clock) = faked();
    let net = MemNet::new();
    let (a, ticket) = ann.share_within(&net, &budgets, None).await;
    // More of Ann's changes than a stream holds unread.
    let main = ann.entry("main");
    for n in 0..3 {
        ann.session
            .comment(main + n, Some(&"a".repeat(40_000)))
            .unwrap();
    }
    let (xan, yan) = (
        Identity::ephemeral().unwrap(),
        Identity::ephemeral().unwrap(),
    );
    a.add(&Card::new(&xan, "xan"), Role::Viewer).unwrap();
    let mut xans = Hand::reader(&net, &xan, &ticket).await;
    until("Xan reads", || a.readers().contains(&xan.public())).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(budgets.pages_free(), SYNC_PAGES);
    // The rate's wait: Xan's bytes all but spent, the clock standing
    // still. The page is built and its permit held while it waits.
    spend(&budgets, &clock, xan.public(), 16 << 10);
    xans.say(&want_all(1, ann.chain())).await;
    until("the page is in hand", || {
        budgets.pages_free() == SYNC_PAGES - 1
    })
    .await;
    held_for(&budgets, Duration::from_secs(1)).await;
    // The write: the clock moves, Xan reads nothing, and the page is
    // more than his stream holds. Still held.
    clock.advance(Duration::from_secs(60));
    held_for(&budgets, Duration::from_secs(1)).await;
    // He reads: the write ends, and the permit is given back with it.
    let changes = xans
        .first(Duration::from_secs(10), |m| {
            matches!(m, Sync::Changes { id: 1, .. })
        })
        .await;
    assert!(
        matches!(&changes, Some(Sync::Changes { changes, .. }) if changes.len() >= 3),
        "{changes:?}"
    );
    until("the permit is given back once written", || {
        budgets.pages_free() == SYNC_PAGES
    })
    .await;
    // Stalled again, Xan is removed: given back at once, long before the
    // deadline.
    xans.say(&want_all(2, ann.chain())).await;
    until("the page is in hand again", || {
        budgets.pages_free() == SYNC_PAGES - 1
    })
    .await;
    held_for(&budgets, Duration::from_millis(500)).await;
    let start = Instant::now();
    a.remove(xan.public()).unwrap();
    until("given back at the revocation", || {
        budgets.pages_free() == SYNC_PAGES
    })
    .await;
    assert!(start.elapsed() < DEADLINE / 3, "{:?}", start.elapsed());
    // Yan's write stalls the same way, and nothing ends it but the
    // deadline: then his link is closed and the permit given back.
    a.add(&Card::new(&yan, "yan"), Role::Viewer).unwrap();
    let mut yans = Hand::reader(&net, &yan, &ticket).await;
    until("Yan reads", || a.readers().contains(&yan.public())).await;
    yans.say(&want_all(1, ann.chain())).await;
    until("Yan's page is in hand", || {
        budgets.pages_free() == SYNC_PAGES - 1
    })
    .await;
    let start = Instant::now();
    while budgets.pages_free() != SYNC_PAGES {
        assert!(start.elapsed() < DEADLINE + Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        start.elapsed() + Duration::from_secs(2) > DEADLINE,
        "{:?}",
        start.elapsed()
    );
    until("Yan's link is closed", || {
        a.links().iter().all(|(key, _)| *key != yan.public())
    })
    .await;
    drop((xans, yans));
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_not_reading_holds_up_no_other_shares_membership_catch_up() {
    let dir = scratch("records-page");
    let (ann, cat, dan) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "cat"),
        Person::new(&dir, "dan"),
    );
    let (budgets, clock) = faked();
    // Ann and Cat each share their own project from one process.
    let net = MemNet::new();
    let (a, by_ann) = ann.share_within(&net, &budgets, None).await;
    let (c, by_cat) = cat.share_within(&net, &budgets, None).await;
    let (xan, yan) = (
        Identity::ephemeral().unwrap(),
        Identity::ephemeral().unwrap(),
    );
    a.add(&Card::new(&xan, "xan"), Role::Viewer).unwrap();
    a.add(&Card::new(&yan, "yan"), Role::Viewer).unwrap();
    // Records enough that a page of them is more than a few messages.
    for name in ["eve", "fay", "gus", "hal", "ivy", "jon"] {
        let who = Identity::ephemeral().unwrap();
        a.add(&Card::new(&who, name), Role::Viewer).unwrap();
    }
    let mut xans = Hand::reader(&net, &xan, &by_ann).await;
    let mut yans = Hand::reader(&net, &yan, &by_ann).await;
    until("both read from Ann", || a.readers().len() == 2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Xan's link holds Ann's share's page for records and does not take
    // it: his rate spent, on a clock that stands still.
    spend(&budgets, &clock, xan.public(), 512);
    let ask = Sync::RecordsAsk {
        id: 1,
        after: 0,
        at: [0; 32],
    };
    xans.say(&ask).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    yans.say(&ask).await;
    // Cat's share is another: Dan joins it and catches up with its
    // membership chain at once.
    c.add(&Card::new(&dan.identity, "dan"), Role::Editor)
        .unwrap();
    let start = Instant::now();
    let d = dan.join(&net, &by_cat).await;
    until("Dan holds Cat's chain", || {
        d.membership().seq() == c.membership().seq()
    })
    .await;
    assert!(start.elapsed() < DEADLINE / 3, "{:?}", start.elapsed());
    // Yan, in Ann's share, waits for the page Xan's link holds...
    let records = |m: &Sync| matches!(m, Sync::Records { id: Some(1), .. });
    assert_eq!(yans.first(Duration::from_secs(1), records).await, None);
    // ...until Xan's write passes its deadline: his link is closed and
    // the page given back.
    assert!(
        yans.first(DEADLINE + Duration::from_secs(10), records)
            .await
            .is_some()
    );
    assert!(start.elapsed() > DEADLINE / 2, "{:?}", start.elapsed());
    until("Xan's link is closed", || {
        a.links().iter().all(|(key, _)| *key != xan.public())
    })
    .await;
    drop((xans, yans));
    for peer in [a, c, d] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pages_waiting_for_their_rate_leave_out_what_a_removal_cut_meanwhile() {
    let dir = scratch("paused-cut");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let [classify, main, checked] = ["classify", "main", "checked"].map(|name| ann.entry(name));
    let (xan, yan) = (
        Identity::ephemeral().unwrap(),
        Identity::ephemeral().unwrap(),
    );
    let asked = Arc::new(AtomicUsize::new(0));
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net, approver(Role::Editor, &asked)).await;
    for (who, name) in [(&xan, "xan"), (&yan, "yan")] {
        a.add(&Card::new(who, name), Role::Viewer).unwrap();
    }
    let b = bob.join(&net, &ticket).await;
    let c = cat.join(&net, &ticket).await;
    bob.session
        .rename_function(classify, Some("bob_early"))
        .unwrap();
    let chain = bob.chain();
    let cut = bob.seq(chain);
    until("Cat has Bob's change and the chain", || {
        cat.seq(chain) == cut && c.membership().seq() == a.membership().seq()
    })
    .await;
    let at = bob.last(chain).hash();
    for peer in [a, b, c] {
        peer.close().await;
    }
    // Cat hosts, Ann away; Bob writes past what Ann has of him.
    let (budgets, clock) = faked();
    let mesh = MemNet::new();
    let (c, by_cat) = cat
        .share_within(&mesh, &budgets, Some(approver(Role::Editor, &asked)))
        .await;
    let b = bob.join(&mesh, &by_cat).await;
    let big = "b".repeat(40_000);
    bob.session.comment(main, Some(&big)).unwrap();
    until("Cat takes it", || cat.seq(chain) == cut + 1).await;
    // Xan and Yan read from Cat; Yan says he holds Bob's chain as far, so
    // Bob's next is pushed to him.
    let mut xans = Hand::reader(&mesh, &xan, &by_cat).await;
    let mut yans = Hand::reader(&mesh, &yan, &by_cat).await;
    until("both read from Cat", || c.readers().len() == 3).await;
    yans.say(&Sync::Tips {
        tips: Bounded::truncated(vec![cat.session.tip(chain).unwrap()]),
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Their rates spent, the clock standing still: a page for each is
    // built and waits.
    spend(&budgets, &clock, xan.public(), 8 << 10);
    spend(&budgets, &clock, yan.public(), 8 << 10);
    xans.say(&Sync::Want {
        id: 1,
        chain,
        after: cut,
        at,
        most: 256,
    })
    .await;
    bob.session.comment(checked, Some(&big)).unwrap();
    until("both pages are in hand", || {
        cat.seq(chain) == cut + 2 && budgets.pages_free() == SYNC_PAGES - 2
    })
    .await;
    // Ann, away, removed Bob at what she had of him; she brings it to Cat,
    // who freezes Bob's chain past the cut.
    let away = MemNet::new();
    let (a, _) = ann.share(&away, approver(Role::Editor, &asked)).await;
    a.remove(bob.key()).unwrap();
    a.close().await;
    let a = ann.join(&mesh, &by_cat).await;
    until("Cat freezes Bob's chain past the cut", || {
        cat.session.frozen().get(&chain) == Some(&(cut + 1))
    })
    .await;
    // The rates come again: neither page holds a change past the cut.
    clock.advance(Duration::from_secs(60));
    let reply = xans
        .first(Duration::from_secs(10), |m| {
            matches!(m, Sync::Changes { id: 1, .. })
        })
        .await;
    assert!(
        matches!(&reply, Some(Sync::Changes { changes, more: false, .. }) if changes.is_empty()),
        "{reply:?}"
    );
    let pushed = yans
        .first(Duration::from_secs(3), |m| matches!(m, Sync::Fresh { .. }))
        .await;
    assert_eq!(pushed, None);
    until("both permits are given back", || {
        budgets.pages_free() == SYNC_PAGES
    })
    .await;
    drop((xans, yans));
    for peer in [a, b, c] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_waiting_for_its_rate_is_never_written_once_its_reader_is_removed() {
    let dir = scratch("paused-removal");
    let ann = Person::new(&dir, "ann");
    let (budgets, clock) = faked();
    let net = MemNet::new();
    let (a, ticket) = ann.share_within(&net, &budgets, None).await;
    ann.session
        .comment(ann.entry("main"), Some(&"a".repeat(40_000)))
        .unwrap();
    let xan = Identity::ephemeral().unwrap();
    a.add(&Card::new(&xan, "xan"), Role::Viewer).unwrap();
    let mut xans = Hand::reader(&net, &xan, &ticket).await;
    until("Xan reads", || a.readers().contains(&xan.public())).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    // The page made for Xan, its rate's wait in hand when the owner
    // removes him here: in the hold that takes the record, his link is
    // revoked and the page dropped; once the rate comes again nothing of
    // it is written, though his link may still be up.
    spend(&budgets, &clock, xan.public(), 8 << 10);
    xans.say(&want_all(1, ann.chain())).await;
    until("the page is in hand", || {
        budgets.pages_free() == SYNC_PAGES - 1
    })
    .await;
    a.remove(xan.public()).unwrap();
    let start = Instant::now();
    clock.advance(Duration::from_secs(60));
    let reply = xans
        .first(Duration::from_secs(3), |m| {
            matches!(m, Sync::Changes { .. })
        })
        .await;
    assert_eq!(reply, None);
    until("the page is dropped", || budgets.pages_free() == SYNC_PAGES).await;
    assert!(start.elapsed() < DEADLINE / 3, "{:?}", start.elapsed());
    drop(xans);
    a.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_member_whose_missed_records_span_several_kicks_learns_all_through_its_removal() {
    let dir = scratch("kick-pages");
    let (ann, bob) = (Person::new(&dir, "ann"), Person::new(&dir, "bob"));
    let net = MemNet::new();
    let (a, ticket) = ann.host(&net).await;
    a.add(&Card::new(&bob.identity, "bob"), Role::Editor)
        .unwrap();
    let b = bob.join(&net, &ticket).await;
    until("Bob holds the chain", || {
        b.membership().seq() == a.membership().seq()
    })
    .await;
    b.close().await;
    // While he is away, more records than one kick carries, then his
    // removal, then one more.
    let held = a.membership().seq();
    for n in 0..MAX_KICK_RECORDS + 6 {
        let who = Identity::ephemeral().unwrap();
        a.add(&Card::new(&who, &format!("m{n}")), Role::Viewer)
            .unwrap();
    }
    a.remove(bob.key()).unwrap();
    let removal = a.membership().seq();
    assert!(removal - held > MAX_KICK_RECORDS as u64);
    let dan = Identity::ephemeral().unwrap();
    a.add(&Card::new(&dan, "dan"), Role::Editor).unwrap();
    // He dials again: kick after kick, each from the head he reached, until
    // he holds his removal, and nothing after it.
    let b = bob.dial(&net, &ticket, EngineVersion::this()).await;
    until("Bob learns of his removal", || {
        b.membership().removed(bob.key())
    })
    .await;
    let kicks = bob
        .heard
        .lock()
        .unwrap()
        .iter()
        .filter(|n| matches!(n, Notice::Kicked(_)))
        .count();
    assert!(kicks >= 2, "{kicks}");
    let chain = b.membership();
    assert_eq!(chain.seq(), removal);
    assert_eq!(
        chain.since(held).to_vec(),
        a.membership().since(held)[..usize::try_from(removal - held).unwrap()].to_vec()
    );
    assert_eq!(chain.role(dan.public()), None);
    for peer in [a, b] {
        peer.close().await;
    }
}
