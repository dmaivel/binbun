#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Conversation among three peers over [`MemTransport`]: a thread on a C line
//! follows its address on every peer across a re-analysis that renumbers
//! functions; a post's deletion wins over a concurrent edit everywhere,
//! and an edit of it by anyone but its author, taken by every peer,
//! changes nothing shown; the owner removes a post and a chat message,
//! gone on every peer (a late joiner's too), "removed by the owner"; an
//! agent edits as an editor does, a person accepts part of its
//! suggestion, history naming both, and once the owner makes it a viewer
//! a change of its chain past then is refused by every peer.
//! A peer's checks before the session's: a signed fork of a change it
//! holds, or two at one place in one delivery, freeze the chain there on
//! every peer; a reader's first change of another's chain naming itself
//! is refused, the chain staying its author's; an author linked
//! view-only has their other build's changes taken by no route while
//! that link lasts, and from another member once it ends; changes of a
//! chain whose first change never came are not held, and the refusals
//! listed are bounded.
//!
//! Every joiner is added by the owner before it connects, and edits once
//! its link syncs.
//!
//! [`MemTransport`]: binbun_collab::mem::MemTransport

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use binbun_collab::crypto::{self, EpochKey};
use binbun_collab::mem::MemNet;
use binbun_collab::membership::{Record, Role};
use binbun_collab::ticket::{Card, JoinTicket};
use binbun_collab::{Config, Peer, Received, Transport, bounded};
use binbun_session::identity::Identity;
use binbun_session::journal::talk::{Anchor, Deleted, PostOp, SuggestionState};
use binbun_session::journal::{
    Body, Bound, ChainId, ChainOrigin, ChangeHash, EngineVersion, Head, Hlc, Key, Op, OpId, Origin,
    PublicKey, SignedChange, SignedHead, Signer, Under, Value,
};
use binbun_session::{
    Bounds, Corrections, Error, Located, Options, Say, Session, Stage, Suggesting, View,
};
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
            .join(format!("collab-talk-{name}-{}", std::process::id()));
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

/// One person: identity and session on the fixture in `dir/name`.
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
                project: Some(home.join("project")),
                identity: Some(home.join("identity")),
                warm: false,
                ..Options::default()
            },
        )
        .unwrap();
        session.wait(Stage::Callers, None);
        Self {
            name,
            identity,
            session: Arc::new(session),
        }
    }

    fn key(&self) -> PublicKey {
        self.identity.public()
    }

    /// Its config as a peer speaking for `engine`.
    fn config_as(&self, engine: EngineVersion) -> Config {
        Config {
            identity: self.identity.clone(),
            name: self.name.to_owned(),
            approve: None,
            notify: None,
            engine,
        }
    }

    fn transport(&self, net: &MemNet) -> Arc<dyn Transport> {
        Arc::new(net.endpoint(self.key()))
    }

    async fn share(&self, net: &MemNet) -> (Peer, JoinTicket) {
        self.share_as(net, EngineVersion::this()).await
    }

    /// Shares, speaking for `engine`.
    async fn share_as(&self, net: &MemNet, engine: EngineVersion) -> (Peer, JoinTicket) {
        Peer::share(
            Arc::clone(&self.session),
            self.transport(net),
            self.config_as(engine),
        )
        .await
        .unwrap()
    }

    async fn join(&self, host: &Peer, net: &MemNet, ticket: &JoinTicket) -> Peer {
        self.join_as(host, net, ticket, EngineVersion::this()).await
    }

    /// Joins, speaking for `engine`: added by the owner (`host`) first,
    /// `cat` as an agent and everyone else as an editor; once its link
    /// syncs (its journal the share's: what it writes before is kept
    /// apart).
    async fn join_as(
        &self,
        host: &Peer,
        net: &MemNet,
        ticket: &JoinTicket,
        engine: EngineVersion,
    ) -> Peer {
        let role = if self.name == "cat" {
            Role::Agent
        } else {
            Role::Editor
        };
        host.add(&Card::new(&self.identity, self.name), role)
            .unwrap();
        let peer = Peer::join(
            Arc::clone(&self.session),
            self.transport(net),
            self.config_as(engine),
            ticket,
        )
        .await
        .unwrap();
        until("the link syncs", || !peer.readers().is_empty()).await;
        peer
    }

    fn entry(&self, name: &str) -> u64 {
        let database = self.session.database().unwrap();
        database
            .functions()
            .find(|(_, f)| self.session.name(f.entry).as_deref() == Some(name))
            .map(|(_, f)| f.entry)
            .unwrap()
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

/// Why `peer` refused changes of chain `chain`, each.
fn refusals(peer: &Peer, chain: ChainId) -> Vec<String> {
    peer.refused()
        .into_iter()
        .filter(|refused| refused.change.is_some_and(|id| id.chain == chain))
        .map(|refused| refused.why)
        .collect()
}

/// Posts `body` in a new thread on `anchor`; the thread and post.
fn open(session: &Session, anchor: Anchor, body: &str) -> (OpId, OpId) {
    let thread = session.open_thread(anchor, "").unwrap();
    let say = Say {
        body: body.to_owned(),
        ..Say::default()
    };
    (thread, session.post(thread, say).unwrap())
}

/// A body doing `ops`, labelled `label`, made now by a person.
fn body(label: &str, ops: Vec<Op>) -> Body {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Body {
        bound: None,
        hlc: Hlc::new(u64::try_from(now.as_millis()).unwrap(), 0),
        membership: 0,
        engine: EngineVersion::this(),
        origin: Origin::User,
        label: label.to_owned(),
        undoes: None,
        group: None,
        ops,
        blind: [0x5a; 16],
    }
}

/// An op writing `value` at `key`, having seen nothing there.
fn op(key: Key, value: Value) -> Op {
    Op {
        key,
        value,
        prev: Vec::new(),
    }
}

/// `body` as change `seq` of chain `chain` after the change of hash
/// `prev` (a first change carrying `origin`), signed by `author`: what
/// a client makes.
fn signed(
    author: &Identity,
    chain: ChainId,
    seq: u64,
    prev: ChangeHash,
    origin: Option<ChainOrigin>,
    body: &Body,
) -> SignedChange {
    let body = body.encode().unwrap();
    let head = Head {
        chain,
        seq,
        prev,
        body: Body::commitment(&body),
        origin,
    };
    SignedChange {
        head: SignedHead::sign(head, &Signer::from_seed(&author.secret())),
        body,
    }
}

/// The start of a chain of `origin`'s in `peer`'s share, signed by
/// `author`, under the grant the share gives them now.
fn start(author: &Identity, peer: &Peer, origin: ChainOrigin) -> SignedChange {
    let session = peer.session();
    let grant = peer.membership().grant(author.public()).unwrap_or(0);
    let bound = Some(Bound {
        share: session.genesis().map(|genesis| Under { genesis, grant }),
        of: session.binding(),
    });
    let first = Body {
        bound,
        ..body("", Vec::new())
    };
    signed(
        author,
        origin.chain(),
        1,
        ChangeHash::ZERO,
        Some(origin),
        &first,
    )
}

/// The change after chain `chain`'s tip in `session`, by `author`,
/// labelled `label`, doing `ops`.
fn next(
    author: &Identity,
    session: &Session,
    chain: ChainId,
    label: &str,
    ops: Vec<Op>,
) -> SignedChange {
    let tip = session.tip(chain).unwrap();
    signed(
        author,
        chain,
        tip.seq + 1,
        tip.hash,
        None,
        &body(label, ops),
    )
}

/// The key of the epoch now as `peer` has the membership chain, unwrapped
/// by member `who`: what a member's client holds.
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

/// `changes` sealed by member `who` under the key of the epoch now as
/// `peer` has the membership chain: what `who`'s client sends.
fn sealed(peer: &Peer, who: &Identity, changes: &[SignedChange]) -> Vec<Vec<u8>> {
    let (epoch, key) = epoch_key(peer, who);
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
async fn a_thread_on_a_c_line_follows_its_address_on_every_peer_across_a_renumbering() {
    let dir = Scratch::new("renumbered");
    let (ann, bob, dan) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "dan"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    let (b, d) = (
        bob.join(&a, &net, &ticket).await,
        dan.join(&a, &net, &ticket).await,
    );
    // Ann's thread on the last line of `checked` made from an instruction.
    let checked = ann.entry("checked");
    let before = ann
        .session
        .database()
        .unwrap()
        .function_at(checked)
        .unwrap();
    let document = ann.session.document_view(before, View::Exact).unwrap();
    let address = (0..document.lines().len())
        .rev()
        .find_map(|n| document.provenance.addresses_of(n).first().copied())
        .unwrap();
    let anchor = Anchor::Line {
        function: checked,
        reading: false,
        address,
    };
    let (thread, _) = open(&ann.session, anchor.clone(), "Checked twice?");
    // Bob makes a function in `classify`'s padding: every function after
    // it is numbered anew on every peer's next analysis.
    let mut made = Corrections::default();
    made.set_bounds(0x11a3, Some(Bounds::Function { end: None }));
    until("the thread reaches Bob", || {
        bob.session.thread(thread).is_some()
    })
    .await;
    bob.session.set_corrections(&made).unwrap();
    let all = [&ann.session, &bob.session, &dan.session];
    until("all three have both", || {
        converged(&all) && dan.session.corrections() == made
    })
    .await;
    for (person, peer) in [(&ann, &a), (&bob, &b), (&dan, &d)] {
        let now = Arc::new(person.session.reanalysed().unwrap());
        now.wait(Stage::Analysed, None);
        peer.set_session(Arc::clone(&now));
        let after = now.database().unwrap().function_at(checked).unwrap();
        assert_ne!(after, before, "{}: renumbered", person.name);
        let found = now.threads_at(address);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].posts[0].body, "Checked twice?");
        let Located::Line {
            function,
            line: Some(line),
            ..
        } = now.locate(&anchor)
        else {
            panic!("{}: not on a line", person.name);
        };
        assert_eq!(function, after);
        let document = now.document_view(after, View::Exact).unwrap();
        assert!(document.provenance.addresses_of(line).contains(&address));
    }
    for peer in [a, b, d] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deletion_wins_over_a_concurrent_edit_and_an_edit_by_another_changes_nothing_shown() {
    let dir = Scratch::new("delete-wins");
    let (ann, bob, dan) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "dan"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    let (b, d) = (
        bob.join(&a, &net, &ticket).await,
        dan.join(&a, &net, &ticket).await,
    );
    let (_, post) = open(
        &bob.session,
        Anchor::Function(bob.entry("classify")),
        "mine",
    );
    let all = [&ann.session, &bob.session, &dan.session];
    until("the post is everywhere", || {
        converged(&all) && dan.session.post_of(post).is_some()
    })
    .await;
    // Dan may not edit Bob's post (his client says so) ...
    let refused = dan.session.edit_post(post, "hijacked").unwrap_err();
    assert!(matches!(refused, Error::Conversation(_)), "{refused:?}");
    // ... and a forger's change doing it, on a chain of Dan's own handed
    // to Ann, is taken by every peer and changes nothing shown.
    let origin = ChainOrigin {
        author: dan.key(),
        project: d.membership().project(),
        salt: [0x5a; 16],
    };
    let first = start(&dan.identity, &d, origin);
    let chain = origin.chain();
    let edit = op(
        Key::Post(post),
        Value::Post(PostOp::Edit("hijacked".to_owned())),
    );
    let forged = signed(
        &dan.identity,
        chain,
        2,
        first.hash(),
        None,
        &body("Edit post", vec![edit]),
    );
    let received = a.receive(&sealed(&d, &dan.identity, &[first, forged]));
    assert_eq!(
        received,
        Received {
            taken: 2,
            ..Received::default()
        }
    );
    until("the forger's chain everywhere", || {
        converged(&all) && dan.session.tip(chain).is_some_and(|tip| tip.seq == 2)
    })
    .await;
    for (person, peer) in [(&ann, &a), (&bob, &b), (&dan, &d)] {
        assert_eq!(
            refusals(peer, chain),
            Vec::<String>::new(),
            "{}",
            person.name
        );
        assert_eq!(person.session.post_of(post).unwrap().body, "mine");
    }
    // Bob edits while Ann (the owner) removes it: deleted on every peer.
    bob.session.edit_post(post, "mine, edited").unwrap();
    ann.session.delete_post(post).unwrap();
    let removed = Some(Deleted {
        by: ann.key(),
        origin: Origin::User,
        by_owner: true,
    });
    until("deleted everywhere", || {
        converged(&all)
            && all
                .iter()
                .all(|session| session.post_of(post).unwrap().deleted == removed)
    })
    .await;
    for session in all {
        let shown = session.post_of(post).unwrap();
        assert_eq!(shown.body, "");
        assert!(shown.edited.is_some(), "the edit was taken, and lost");
    }
    for peer in [a, b, d] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_removes_a_post_and_a_chat_message_gone_on_every_peer_and_a_late_joiners() {
    let dir = Scratch::new("moderation");
    let (ann, bob, dan, eve) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "dan"),
        Person::new(&dir, "eve"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    let (b, d) = (
        bob.join(&a, &net, &ticket).await,
        dan.join(&a, &net, &ticket).await,
    );
    let (_, post) = open(
        &bob.session,
        Anchor::Instruction(0x1190),
        "spam in a thread",
    );
    let peers = [&a, &b, &d];
    // Chat once admitted (the live key comes with the membership).
    let mut sent = None;
    until("Bob chats", || {
        sent = b.chat("spam in the chat", &[], &[]).ok();
        sent.is_some()
    })
    .await;
    let spam = sent.unwrap();
    until("both everywhere", || {
        peers
            .iter()
            .all(|peer| peer.chat_log().iter().any(|m| m.id == spam.id))
            && dan.session.post_of(post).is_some()
    })
    .await;
    // Only the owner moderates.
    assert!(d.remove_chat(spam.id).is_err());
    assert!(matches!(
        dan.session.delete_post(post),
        Err(Error::Conversation(_))
    ));
    a.remove_chat(spam.id).unwrap();
    ann.session.delete_post(post).unwrap();
    let gone = |peer: &Peer, session: &Session| {
        let chat = peer.chat_log();
        let message = chat.iter().find(|m| m.id == spam.id);
        let shown = session.post_of(post);
        message.is_some_and(|m| m.removed && m.text.is_empty())
            && shown.is_some_and(|p| {
                p.body.is_empty()
                    && p.deleted
                        == Some(Deleted {
                            by: ann.key(),
                            origin: Origin::User,
                            by_owner: true,
                        })
            })
    };
    until("removed on every peer", || {
        gone(&a, &ann.session) && gone(&b, &bob.session) && gone(&d, &dan.session)
    })
    .await;
    // A late joiner sees both removed.
    let e = eve.join(&a, &net, &ticket).await;
    until("removed for the late joiner", || gone(&e, &eve.session)).await;
    for peer in [a, b, d, e] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_edits_until_made_a_viewer_and_a_person_accepts_part_of_its_suggestion() {
    let dir = Scratch::new("agent");
    let (ann, bob, cat) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "cat"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    let (b, c) = (
        bob.join(&a, &net, &ticket).await,
        cat.join(&a, &net, &ticket).await,
    );
    assert_eq!(c.role(), Some(Role::Agent));
    let classify = cat.entry("classify");
    // Its suggestion is taken.
    cat.session.begin("Suggest", Origin::Agent);
    let id = cat
        .session
        .suggest(Suggesting {
            label: "Name classify".to_owned(),
            edits: vec![
                (
                    Key::FunctionName(classify),
                    Value::Text(Some("sign_of".into())),
                ),
                (Key::Comment(classify), Value::Text(Some("-1, 0, 1".into()))),
            ],
            rationale: "Returns the sign.".to_owned(),
            ..Suggesting::default()
        })
        .unwrap();
    cat.session.commit().unwrap();
    until("Bob has it", || bob.session.suggestion(id).is_some()).await;
    // The agent's own edit is taken by every peer, as an editor's.
    let helper = cat.entry("checked");
    cat.session
        .rename_function(helper, Some("agent_name"))
        .unwrap();
    until("the agent's rename everywhere", || {
        [&ann.session, &bob.session]
            .iter()
            .all(|session| session.name(helper).as_deref() == Some("agent_name"))
    })
    .await;
    let chain = cat.session.chain();
    assert_eq!(refusals(&a, chain), Vec::<String>::new());
    assert_eq!(refusals(&b, chain), Vec::<String>::new());
    // Bob accepts the name only: one change of his, naming the agent.
    let entry = bob.session.accept(id, &[0]).unwrap().unwrap();
    let all = [&ann.session, &bob.session, &cat.session];
    until("accepted everywhere", || {
        all.iter().all(|session| {
            session
                .suggestion(id)
                .is_some_and(|s| s.state == SuggestionState::Accepted(vec![0]))
        })
    })
    .await;
    let history = ann.session.history();
    let accepted = history.iter().find(|e| e.id == entry.id).unwrap();
    assert_eq!(accepted.author, bob.key());
    assert_eq!(accepted.origin, Origin::Accept(id));
    let by = accepted.suggested_by.as_ref().unwrap();
    assert_eq!((by.key, &by.origin), (cat.key(), &Origin::Agent));
    assert_eq!(ann.session.name(classify).as_deref(), Some("sign_of"));
    assert_eq!(ann.session.edits().comment(classify), None);
    // Made a viewer by the owner: its chain is cut there, frozen past it,
    // so the next change of it, signed and sealed by its client, is
    // refused by every peer it is handed to.
    a.set_role(cat.key(), Role::Viewer).unwrap();
    until("Cat and Bob have the role", || {
        c.role() == Some(Role::Viewer) && b.membership().role(cat.key()) == Some(Role::Viewer)
    })
    .await;
    let rename = op(
        Key::FunctionName(helper),
        Value::Text(Some("viewer_name".to_owned())),
    );
    let past = next(
        &cat.identity,
        &ann.session,
        chain,
        "Rename function",
        vec![rename],
    );
    let seq = past.id().seq;
    let envelopes = sealed(&c, &cat.identity, &[past]);
    for peer in [&a, &b] {
        let received = peer.receive(&envelopes);
        assert_eq!((received.taken, received.refused.len()), (0, 1));
        assert!(
            received.refused[0].why.contains("frozen"),
            "{:?}",
            received.refused
        );
        assert_eq!(peer.session().frozen_from(chain), Some(seq));
        assert_eq!(peer.session().name(helper).as_deref(), Some("agent_name"));
    }
    for peer in [a, b, c] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signed_fork_of_a_change_held_or_beside_it_freezes_its_chain_everywhere() {
    let dir = Scratch::new("fork");
    let (ann, bob, dan) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "dan"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    let (b, d) = (
        bob.join(&a, &net, &ticket).await,
        dan.join(&a, &net, &ticket).await,
    );
    ann.session.comment(0x1190, Some("ann")).unwrap();
    let all = [&ann.session, &bob.session, &dan.session];
    until("Ann's comment everywhere", || {
        converged(&all) && dan.session.edits().comment(0x1190) == Some("ann")
    })
    .await;
    // Ann's client signs another second change of her chain: Bob, who
    // holds the one she made, freezes the chain from there, and so does
    // every peer the proof reaches.
    let chain = ann.session.chain();
    let first = ann.session.chain_start(chain).unwrap();
    let held = ann.session.head_at(chain, 2).unwrap();
    let other = body("Comment", vec![op(Key::Comment(0x1190), text("fork"))]);
    let fork = signed(&ann.identity, chain, 2, first.hash(), None, &other);
    assert_ne!(fork.hash(), held.hash());
    let received = b.receive(&sealed(&b, &ann.identity, &[fork]));
    assert_eq!((received.taken, received.refused.len()), (0, 1));
    assert!(received.refused[0].why.contains("forked"), "{received:?}");
    until("Ann's chain frozen everywhere", || {
        all.iter().all(|session| {
            session.frozen_from(chain) == Some(2) && session.edits().comment(0x1190).is_none()
        })
    })
    .await;
    // Two third changes of Bob's chain in one delivery, to Dan, who has
    // neither: the same, from the third.
    bob.session.comment(0x1194, Some("bob")).unwrap();
    until("Bob's comment everywhere", || {
        converged(&all) && dan.session.edits().comment(0x1194) == Some("bob")
    })
    .await;
    let bobs = bob.session.chain();
    let two: Vec<SignedChange> = ["one", "another"]
        .into_iter()
        .map(|said| {
            let ops = vec![op(Key::Comment(0x1198), text(said))];
            next(&bob.identity, &bob.session, bobs, "Comment", ops)
        })
        .collect();
    let received = d.receive(&sealed(&d, &bob.identity, &two));
    assert_eq!((received.taken, received.refused.len()), (1, 1));
    assert!(received.refused[0].why.contains("forked"), "{received:?}");
    until("Bob's chain frozen everywhere", || {
        all.iter().all(|session| {
            session.frozen_from(bobs) == Some(3)
                && session.edits().comment(0x1194) == Some("bob")
                && session.edits().comment(0x1198).is_none()
        })
    })
    .await;
    for peer in [a, b, d] {
        peer.close().await;
    }
}

/// A comment's value: `said`.
fn text(said: &str) -> Value {
    Value::Text(Some(said.to_owned()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_cannot_claim_anothers_chain_with_a_first_change_naming_itself() {
    let dir = Scratch::new("claimed");
    let (ann, bob, dan) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "dan"),
    );
    let net = MemNet::new();
    let (a, ticket) = ann.share(&net).await;
    let (b, d) = (
        bob.join(&a, &net, &ticket).await,
        dan.join(&a, &net, &ticket).await,
    );
    a.set_role(dan.key(), Role::Viewer).unwrap();
    until("Dan reads only", || d.role() == Some(Role::Viewer)).await;
    // Bob's chain, nothing of it sent yet: Dan knows its id.
    let chain = bob.session.chain();
    assert_eq!(ann.session.tip(chain), None);
    // Dan's client makes a first change of it naming him, signed by him,
    // sealed under the epoch's key he holds, and hands it to Ann: refused.
    let claim = ChainOrigin {
        author: dan.key(),
        project: d.membership().project(),
        salt: [1; 16],
    };
    let mut forged = start(&dan.identity, &d, claim);
    let head = Head {
        chain,
        ..forged.head.head
    };
    forged.head = SignedHead::sign(head, &Signer::from_seed(&dan.identity.secret()));
    let received = a.receive(&sealed(&d, &dan.identity, &[forged]));
    assert_eq!((received.taken, received.refused.len()), (0, 1));
    assert_eq!(ann.session.tip(chain), None);
    // Bob's changes are still his on Ann's peer.
    bob.session.comment(0x1190, Some("bob")).unwrap();
    bob.session.comment(0x1194, Some("bob again")).unwrap();
    assert_eq!(bob.session.chain(), chain);
    until("Ann takes Bob's changes", || {
        ann.session.edits().comment(0x1194) == Some("bob again")
    })
    .await;
    assert_eq!(
        ann.session.chain_origin(chain).map(|origin| origin.author),
        Some(bob.key())
    );
    let history = ann.session.history();
    let of_chain: Vec<_> = history
        .iter()
        .filter(|entry| entry.id.chain == chain)
        .collect();
    assert_eq!(of_chain.len(), 2);
    assert!(of_chain.iter().all(|entry| entry.author == bob.key()));
    for peer in [a, b, d] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_author_linked_view_only_has_their_builds_changes_taken_by_no_route_while_linked() {
    let dir = Scratch::new("view-only");
    let (ann, bob, vic) = (
        Person::new(&dir, "ann"),
        Person::new(&dir, "bob"),
        Person::new(&dir, "vic"),
    );
    // Ann and Bob speak for another build than the one their sessions
    // (and Vic's) stamp their changes with.
    let other = EngineVersion {
        release: "0.0.0".to_owned(),
        build: "other".to_owned(),
    };
    let net = MemNet::new();
    let (a, ticket) = ann.share_as(&net, other.clone()).await;
    let b = bob.join_as(&a, &net, &ticket, other).await;
    let v = vic.join_as(&a, &net, &ticket, EngineVersion::this()).await;
    until("Vic is view-only", || v.view_only().is_some()).await;
    assert_eq!(b.view_only(), None);
    // Vic's change, sent to Ann directly: not taken.
    vic.session.comment(0x1190, Some("vic")).unwrap();
    let chain = vic.session.chain();
    until("Vic's change is his", || {
        vic.session.tip(chain).is_some_and(|tip| tip.seq == 2)
    })
    .await;
    // Handed to Bob, who has no link to Vic: taken, and sent on to Ann,
    // who does not take it either.
    let received = b.receive(&v.seal_after(chain, 0).unwrap());
    assert_eq!((received.taken, received.refused), (2, Vec::new()));
    bob.session.comment(0x1194, Some("bob")).unwrap();
    until("Bob's comment reaches Ann", || {
        ann.session.edits().comment(0x1194) == Some("bob")
    })
    .await;
    assert!(
        ann.session
            .history()
            .iter()
            .all(|entry| entry.author != vic.key())
    );
    assert_eq!(ann.session.edits().comment(0x1190), None);
    // Vic's link ends: his change, from Bob, is taken.
    v.close().await;
    until("Ann takes Vic's change", || {
        ann.session.edits().comment(0x1190) == Some("vic")
    })
    .await;
    for peer in [a, b] {
        peer.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changes_of_a_chain_whose_first_never_came_are_not_held_and_refusals_listed_are_bounded() {
    let dir = Scratch::new("bounded");
    let ann = Person::new(&dir, "ann");
    let net = MemNet::new();
    let (a, _) = ann.share(&net).await;
    // Changes 2 to 1101 of a stranger's chain, sealed under the epoch's
    // key: its first change never came, so none is held waiting for it.
    let stranger = Identity::ephemeral().unwrap();
    let origin = ChainOrigin {
        author: stranger.public(),
        project: a.membership().project(),
        salt: [0x4b; 16],
    };
    let chain = origin.chain();
    let mut prev = start(&stranger, &a, origin).hash();
    let changes: Vec<SignedChange> = (2..=1101)
        .map(|seq| {
            let said = body(
                "Comment",
                vec![op(Key::Comment(0x9000_0000 + seq), text("x"))],
            );
            let change = signed(&stranger, chain, seq, prev, None, &said);
            prev = change.hash();
            change
        })
        .collect();
    let received = a.receive(&sealed(&a, &ann.identity, &changes));
    assert_eq!((received.taken, received.held), (0, 0));
    assert_eq!(received.refused.len(), 1100);
    // Refusals listed: the latest 1024.
    let listed: Vec<u64> = a
        .refused()
        .iter()
        .filter_map(|refused| refused.change.filter(|id| id.chain == chain))
        .map(|id| id.seq)
        .collect();
    assert_eq!(listed, (78..=1101).collect::<Vec<_>>());
    a.close().await;
}
