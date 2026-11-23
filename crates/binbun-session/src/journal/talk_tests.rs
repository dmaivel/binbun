//! Conversation's merge rules:
//! a post's deletion wins over a concurrent edit in every delivery order;
//! an edit by anyone but a post's author counts for nothing, and a post in
//! no thread is not shown; a deletion counts from the author or an owner
//! only; a post that comes before its thread waits for it; a thread named
//! for another change is refused for good; mentions are told to the
//! identity mentioned, never for its own posts; an agent's post is named
//! on the agent's chain, apart from the install's, and a mention of an
//! agent the install signs for is told there; conversation is never an
//! undo step, a suggestion's acceptance is; a suggestion superseded by
//! anyone but its author is not superseded.

use std::collections::BTreeSet;

use super::talk::{
    Anchor, Deleted, EditValue, Evidence, Mention, Opening, PostOp, Posting, Proposed, Suggest,
    SuggestionOp, SuggestionState, ThreadOp,
};
use super::tests::{author, body, forge_bytes, sealed, settled};
use super::{ChangeId, Journal, Key, OpId, Origin, PublicKey, SignedChange, Value};
use crate::edits::Edits;
use crate::identity::Identity;

/// One change by `origin` of what `write` writes; what it returned and
/// the changes made (its chain's start first, if it began the chain).
fn change<T>(
    journal: &mut Journal,
    edits: &mut Edits,
    origin: Origin,
    write: impl FnOnce(&mut Journal, &mut Edits) -> T,
) -> (T, Vec<SignedChange>) {
    journal.begin("talk", origin);
    let made = write(journal, edits);
    (made, sealed(journal.commit(edits).unwrap()))
}

/// Opens a thread on the function at `0x1000` and posts `body` in it,
/// mentioning `mentions`, in one change by `origin`.
fn thread(
    journal: &mut Journal,
    edits: &mut Edits,
    origin: Origin,
    body: &str,
    mentions: Vec<Mention>,
) -> ((OpId, OpId), Vec<SignedChange>) {
    change(journal, edits, origin, |journal, edits| {
        let thread = journal.next_talk().unwrap();
        let opening = Opening {
            anchor: Anchor::Function(0x1000),
            quote: "int f(void)".to_owned(),
        };
        journal.write(
            &Key::Thread(thread),
            Value::Thread(ThreadOp::Open(Box::new(opening))),
            edits,
        );
        let post = journal.next_talk().unwrap();
        let posting = Posting {
            thread,
            reply_to: None,
            body: body.to_owned(),
            mentions,
            evidence: None,
        };
        journal.write(
            &Key::Post(post),
            Value::Post(PostOp::New(Box::new(posting))),
            edits,
        );
        (thread, post)
    })
}

/// `op` on post `post`, as a change of its own (no check: as a forger
/// could write it).
fn on_post(journal: &mut Journal, edits: &mut Edits, post: OpId, op: PostOp) -> Vec<SignedChange> {
    change(journal, edits, Origin::User, |journal, edits| {
        journal.write(&Key::Post(post), Value::Post(op), edits);
    })
    .1
}

/// Takes `changes`, in order; the refusals.
fn deliver(journal: &mut Journal, edits: &mut Edits, changes: &[SignedChange]) -> Vec<String> {
    let mut refused = Vec::new();
    for change in changes {
        let (applied, _) = journal.receive(vec![change.clone()], edits);
        let applied = settled(journal, edits, applied);
        refused.extend(applied.refused.into_iter().map(|r| r.why));
    }
    refused
}

/// Takes `changes`, in order, none refused.
fn take(journal: &mut Journal, edits: &mut Edits, changes: &[SignedChange]) {
    assert_eq!(deliver(journal, edits, changes), Vec::<String>::new());
}

#[test]
fn a_deletion_wins_over_a_concurrent_edit_in_every_order_on_every_peer() {
    let (mut ann, mut ann_edits) = author(1);
    let (mut cat, mut cat_edits) = author(3);
    let owners = BTreeSet::from([cat.author()]);
    ann.set_owners(owners.clone());
    cat.set_owners(owners.clone());
    let ((_, post), first) = thread(&mut ann, &mut ann_edits, Origin::User, "aes?", vec![]);
    deliver(&mut cat, &mut cat_edits, &first);
    // Concurrently: Ann edits her post, Cat (the owner) removes it.
    let edit = on_post(
        &mut ann,
        &mut ann_edits,
        post,
        PostOp::Edit("aes key setup".into()),
    );
    let delete = on_post(&mut cat, &mut cat_edits, post, PostOp::Delete);
    take(&mut ann, &mut ann_edits, &delete);
    take(&mut cat, &mut cat_edits, &edit);
    // Ann edits again having seen the deletion: still deleted.
    let later = on_post(&mut ann, &mut ann_edits, post, PostOp::Edit("again".into()));
    deliver(&mut cat, &mut cat_edits, &later);
    let removed = Some(Deleted {
        by: cat.author(),
        origin: Origin::User,
        by_owner: true,
    });
    let mut seen = vec![ann.find_post(post).unwrap(), cat.find_post(post).unwrap()];
    // A third peer, in every order of the three after the first that
    // keeps Ann's chain in its order (as it is pulled).
    let orders = [
        [&edit, &delete, &later],
        [&delete, &edit, &later],
        [&edit, &later, &delete],
    ];
    for order in orders {
        let (mut bob, mut bob_edits) = author(2);
        bob.set_owners(owners.clone());
        let mut all = first.clone();
        all.extend(order.into_iter().flatten().cloned());
        take(&mut bob, &mut bob_edits, &all);
        seen.push(bob.find_post(post).unwrap());
    }
    for post in &seen {
        assert_eq!(post.deleted, removed);
        assert_eq!(post.body, "");
        assert!(post.mentions.is_empty() && post.evidence.is_none());
    }
    assert!(seen.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn an_edit_by_anyone_but_the_author_counts_for_nothing_and_a_deletion_only_from_an_owner() {
    let (mut ann, mut ann_edits) = author(1);
    let (mut bob, mut bob_edits) = author(2);
    let ((_, post), first) = thread(&mut ann, &mut ann_edits, Origin::User, "mine", vec![]);
    deliver(&mut bob, &mut bob_edits, &first);
    // Bob's client would never write it; a forger's does. It is taken (a
    // rule about another's change is no refusal), and counts for nothing.
    let forged = on_post(
        &mut bob,
        &mut bob_edits,
        post,
        PostOp::Edit("hijacked".into()),
    );
    take(&mut ann, &mut ann_edits, &forged);
    let shown = ann.find_post(post).unwrap();
    assert_eq!((shown.body.as_str(), shown.edited), ("mine", None));
    assert!(bob.frozen.is_empty() && ann.frozen.is_empty());
    // Dan's script deleting Ann's post: taken, but no deletion while he
    // owns nothing; once he is an owner, it is one, as the script.
    let (mut cat, mut cat_edits) = author(3);
    deliver(&mut cat, &mut cat_edits, &first);
    let (mut dan, mut dan_edits) = author(4);
    deliver(&mut dan, &mut dan_edits, &first);
    let tidy = Origin::Script("tidy".to_owned());
    let ((), delete) = change(&mut dan, &mut dan_edits, tidy.clone(), |journal, edits| {
        journal.write(&Key::Post(post), Value::Post(PostOp::Delete), edits);
    });
    take(&mut cat, &mut cat_edits, &delete);
    assert_eq!(cat.find_post(post).unwrap().deleted, None);
    assert!(cat.set_owners(BTreeSet::from([dan.author()])));
    assert_eq!(
        cat.find_post(post).unwrap().deleted,
        Some(Deleted {
            by: dan.author(),
            origin: tidy,
            by_owner: true,
        })
    );
}

#[test]
fn a_post_waits_for_its_thread_and_a_post_in_no_thread_is_not_shown() {
    let (mut ann, mut ann_edits) = author(1);
    let (mut bob, mut bob_edits) = author(2);
    let ((thread_id, _), first) = thread(&mut ann, &mut ann_edits, Origin::User, "one", vec![]);
    deliver(&mut bob, &mut bob_edits, &first);
    let dan_key = super::Signer::from_seed(&[5; 32]).public();
    let reply = |thread| {
        move |journal: &mut Journal, edits: &mut Edits| {
            let id = journal.next_talk().unwrap();
            let posting = Posting {
                thread,
                reply_to: None,
                body: "two".to_owned(),
                mentions: vec![Mention {
                    key: dan_key,
                    agent: None,
                }],
                evidence: None,
            };
            journal.write(
                &Key::Post(id),
                Value::Post(PostOp::New(Box::new(posting))),
                edits,
            );
            id
        }
    };
    let (answer, second) = change(&mut bob, &mut bob_edits, Origin::User, reply(thread_id));
    // Bob's reply before Ann's thread: it waits for it.
    let (mut carl, mut carl_edits) = author(3);
    let (held, _) = carl.receive(second.clone(), &mut carl_edits);
    assert_eq!(held.held, 1);
    assert_eq!(carl.threads().len(), 0);
    let (taken, _) = carl.receive(first.clone(), &mut carl_edits);
    assert_eq!(taken.changes.len(), 2);
    let threads = carl.threads();
    assert_eq!(threads.len(), 1);
    let bodies: Vec<&str> = threads[0].posts.iter().map(|p| p.body.as_str()).collect();
    assert_eq!(bodies, ["one", "two"]);
    assert_eq!(threads[0].posts[1].id, answer);
    // A post naming as its thread an op of a change that opened none: the
    // change is taken, the post shown nowhere and told to no one.
    let nowhere = OpId {
        change: ChangeId {
            chain: thread_id.change.chain,
            seq: thread_id.change.seq,
        },
        index: 7,
    };
    let (stray, third) = change(&mut bob, &mut bob_edits, Origin::User, reply(nowhere));
    let mut dan = Journal::new(
        super::ProjectId([7; 16]),
        super::tests::of(),
        super::Signer::from_seed(&[5; 32]),
    )
    .unwrap();
    let mut dan_edits = Edits::default();
    take(&mut dan, &mut dan_edits, &[first, second].concat());
    let _ = dan.talked();
    take(&mut dan, &mut dan_edits, &third);
    assert_eq!(dan.find_post(stray), None);
    assert_eq!(dan.threads()[0].posts.len(), 2);
    assert!(dan.talked().is_none_or(|(_, mentions)| mentions.is_empty()));
}

#[test]
fn a_thread_named_for_another_change_is_refused_for_good() {
    let (mut ann, mut ann_edits) = author(1);
    let ((), forged) = change(&mut ann, &mut ann_edits, Origin::User, |journal, edits| {
        let opening = Opening {
            anchor: Anchor::Instruction(0x1004),
            quote: String::new(),
        };
        let mut id = journal.next_talk().unwrap();
        id.change.seq += 7;
        journal.write(
            &Key::Thread(id),
            Value::Thread(ThreadOp::Open(Box::new(opening))),
            edits,
        );
    });
    let (mut bob, mut bob_edits) = author(2);
    let refused = deliver(&mut bob, &mut bob_edits, &forged);
    assert!(
        refused[0].contains("not named for the change"),
        "{refused:?}"
    );
    assert_eq!(bob.frozen_from(ann.chain), Some(2));
}

#[test]
fn mentions_are_told_to_the_identity_mentioned_but_never_of_its_own_posts() {
    let (mut ann, mut ann_edits) = author(1);
    let (mut bob, mut bob_edits) = author(2);
    let helper = Mention {
        key: bob.author(),
        agent: Some("script:helper".to_owned()),
    };
    let person = Mention {
        key: bob.author(),
        agent: None,
    };
    let ((thread_id, post), first) = thread(
        &mut ann,
        &mut ann_edits,
        Origin::User,
        "@helper why size_t?",
        vec![helper.clone(), person.clone()],
    );
    let (_, mentions) = ann.talked().unwrap();
    assert!(mentions.is_empty(), "Ann is not mentioned");
    deliver(&mut bob, &mut bob_edits, &first);
    let (talked, mentions) = bob.talked().unwrap();
    assert_eq!(talked.threads, [thread_id]);
    let told: Vec<&Mention> = mentions.iter().map(|m| &m.mention).collect();
    assert_eq!(told, [&helper, &person]);
    assert!(
        mentions
            .iter()
            .all(|m| m.post == post && m.by.key == ann.author())
    );
    // The helper answering, mentioning itself: nothing told for that one.
    change(
        &mut bob,
        &mut bob_edits,
        Origin::Script("helper".into()),
        |journal, edits| {
            let id = journal.next_talk().unwrap();
            let posting = Posting {
                thread: thread_id,
                reply_to: Some(post),
                body: "@helper looked: size_t".to_owned(),
                mentions: vec![helper.clone()],
                evidence: None,
            };
            journal.write(
                &Key::Post(id),
                Value::Post(PostOp::New(Box::new(posting))),
                edits,
            );
        },
    );
    let (_, mentions) = bob.talked().unwrap();
    assert_eq!(mentions.len(), 0);
    // Conversation alone is never an undo step.
    assert!(!bob.can_undo() && !ann.can_undo());
}

/// A post `body` in `thread` mentioning `mentions`, as a change of its
/// own by `origin`, signed by agent `by` (none: the install); its id and
/// the changes made.
fn post(
    journal: &mut Journal,
    edits: &mut Edits,
    (origin, by): (Origin, Option<PublicKey>),
    thread: OpId,
    body: &str,
    mentions: Vec<Mention>,
) -> (OpId, Vec<SignedChange>) {
    journal.begin_as("talk", origin, by);
    let id = journal.next_talk().unwrap();
    let posting = Posting {
        thread,
        reply_to: None,
        body: body.to_owned(),
        mentions,
        evidence: None,
    };
    journal.write(
        &Key::Post(id),
        Value::Post(PostOp::New(Box::new(posting))),
        edits,
    );
    let made = sealed(journal.commit(edits).unwrap());
    assert_eq!(
        made.last().unwrap().id(),
        id.change,
        "named for its own change"
    );
    (id, made)
}

#[test]
fn an_agents_post_and_the_installs_reply_are_two_posts_and_a_mention_of_the_agent_is_told() {
    let (mut ann, mut ann_edits) = author(1);
    let codex = ann
        .add_agent(Identity::ephemeral().unwrap(), "Codex")
        .unwrap();
    let ((thread_id, _), first) = thread(&mut ann, &mut ann_edits, Origin::User, "loop?", vec![]);
    let _ = ann.talked();
    let person = Mention {
        key: ann.author(),
        agent: None,
    };
    let agent = Mention {
        key: codex,
        agent: None,
    };
    let (asked, by_agent) = post(
        &mut ann,
        &mut ann_edits,
        (Origin::Agent, Some(codex)),
        thread_id,
        "A loop?",
        vec![person.clone()],
    );
    let (answer, by_ann) = post(
        &mut ann,
        &mut ann_edits,
        (Origin::User, None),
        thread_id,
        "It sums.",
        vec![agent.clone()],
    );
    assert_ne!(asked, answer);
    assert_ne!(asked.change.chain, answer.change.chain);
    let (_, mentions) = ann.talked().unwrap();
    let told: Vec<(OpId, &Mention, PublicKey)> = mentions
        .iter()
        .map(|m| (m.post, &m.mention, m.by.key))
        .collect();
    assert_eq!(
        told,
        [(asked, &person, codex), (answer, &agent, ann.author())]
    );
    // Both kept, here and on a peer taking the changes.
    let (mut bob, mut bob_edits) = author(2);
    take(
        &mut bob,
        &mut bob_edits,
        &[first, by_agent, by_ann].concat(),
    );
    for journal in [&ann, &bob] {
        let threads = journal.threads();
        let posts: Vec<(OpId, &str)> = threads[0]
            .posts
            .iter()
            .map(|p| (p.id, p.body.as_str()))
            .collect();
        assert_eq!(posts[1..], [(asked, "A loop?"), (answer, "It sums.")]);
    }
    // Bob signs for no agent: the mention of Codex is none of his.
    let (_, mentions) = bob.talked().unwrap();
    assert!(mentions.is_empty(), "{mentions:?}");
}

/// A suggestion by `origin` of a name for the function at `0x1000`.
fn suggestion(
    journal: &mut Journal,
    edits: &mut Edits,
    origin: Origin,
    supersedes: Option<OpId>,
) -> (OpId, Vec<SignedChange>) {
    change(journal, edits, origin, |journal, edits| {
        let id = journal.next_talk().unwrap();
        let key = Key::FunctionName(0x1000);
        let suggest = Suggest {
            label: "Name it".to_owned(),
            edits: vec![Proposed {
                prev: journal.leaves_of(&key),
                key,
                value: EditValue::Text(Some("aes_init".to_owned())),
            }],
            rationale: "S-box".to_owned(),
            evidence: Evidence::default(),
            thread: None,
            supersedes,
        };
        journal.write(
            &Key::Suggestion(id),
            Value::Suggestion(SuggestionOp::New(Box::new(suggest))),
            edits,
        );
        if let Some(old) = supersedes {
            journal.write(
                &Key::Suggestion(old),
                Value::Suggestion(SuggestionOp::State(SuggestionState::Superseded(id))),
                edits,
            );
        }
        id
    })
}

#[test]
fn only_its_author_supersedes_a_suggestion_and_an_accepted_one_is_pending_once_undone() {
    let (mut agent, mut agent_edits) = author(4);
    let (mut ann, mut ann_edits) = author(1);
    let (first, made) = suggestion(&mut agent, &mut agent_edits, Origin::Agent, None);
    deliver(&mut ann, &mut ann_edits, &made);
    // Ann superseding the agent's suggestion: taken, and superseding
    // nothing anywhere; nor does her suggestion claim to replace it.
    let (hers, forged) = suggestion(&mut ann, &mut ann_edits, Origin::User, Some(first));
    take(&mut agent, &mut agent_edits, &forged);
    for journal in [&agent, &ann] {
        assert_eq!(
            journal.find_suggestion(first).unwrap().state,
            SuggestionState::Pending
        );
        assert_eq!(journal.find_suggestion(hers).unwrap().supersedes, None);
    }
    // The agent's own next version (having seen Ann's, which it names):
    // taken, and it supersedes.
    let (second, next) = suggestion(&mut agent, &mut agent_edits, Origin::Agent, Some(first));
    let (mut cat, mut cat_edits) = author(3);
    take(&mut cat, &mut cat_edits, &[made, forged, next].concat());
    let old = cat.find_suggestion(first).unwrap();
    assert_eq!(old.state, SuggestionState::Superseded(second));
    let new = cat.find_suggestion(second).unwrap();
    assert_eq!(new.supersedes, Some(first));
    assert_eq!(new.author.origin, Origin::Agent);
    assert!(!new.edits[0].moved);
    // Accepted by Cat: the name and the state in one change; undone, the
    // name goes and the suggestion is pending again.
    let key = Key::FunctionName(0x1000);
    let ((), accepted) = change(
        &mut cat,
        &mut cat_edits,
        Origin::Accept(second),
        |journal, edits| {
            journal.write(&key, Value::Text(Some("aes_init".into())), edits);
            journal.write(
                &Key::Suggestion(second),
                Value::Suggestion(SuggestionOp::State(SuggestionState::Accepted(vec![0]))),
                edits,
            );
        },
    );
    assert_eq!(cat_edits.name(0x1000), Some("aes_init"));
    let entry = cat.history().into_iter().next().unwrap();
    let by = entry.suggested_by.unwrap();
    assert_eq!((by.key, by.origin), (agent.author(), Origin::Agent));
    assert_eq!(entry.author, cat.author());
    let plan = cat.plan_undo().unwrap();
    assert_eq!(plan.skipped.len(), 0);
    let undo = change(
        &mut cat,
        &mut cat_edits,
        plan.origin.clone(),
        |journal, edits| {
            for (key, value) in &plan.ops {
                journal.write(key, value.clone(), edits);
            }
        },
    );
    assert_eq!(cat_edits.name(0x1000), None);
    assert_eq!(
        cat.find_suggestion(second).unwrap().state,
        SuggestionState::Pending
    );
    // The agent sees the same.
    take(&mut agent, &mut agent_edits, &[accepted, undo.1].concat());
    assert_eq!(
        agent.find_suggestion(second).unwrap().state,
        SuggestionState::Pending
    );
}

/// Ann's first changes, suggesting `0x55`'s comment be cleared, signed,
/// with the suggestion nested `depth` deep: the edit it proposes is again
/// the suggestion, as many times (1: the suggestion itself).
fn nested_suggestion(depth: usize) -> Vec<SignedChange> {
    let (mut ann, mut ann_edits) = author(1);
    let key = Key::Comment(0x55);
    let suggest = |value: EditValue| Suggest {
        label: String::new(),
        edits: vec![Proposed {
            key: key.clone(),
            value,
            prev: Vec::new(),
        }],
        rationale: String::new(),
        evidence: Evidence::default(),
        thread: None,
        supersedes: None,
    };
    let made = Value::Suggestion(SuggestionOp::New(Box::new(suggest(EditValue::Text(None)))));
    let ((), mut signed) = change(&mut ann, &mut ann_edits, Origin::Agent, |journal, edits| {
        let id = journal.next_talk().unwrap();
        journal.write(&Key::Suggestion(id), made.clone(), edits);
    });
    // The value's bytes: those before its edit's value, that value (a
    // text's tombstone, as a value or an edit's value), those after.
    let whole = postcard::to_stdvec(&made).unwrap();
    let inner = postcard::to_stdvec(&EditValue::Text(None)).unwrap();
    assert_eq!(inner, postcard::to_stdvec(&Value::Text(None)).unwrap());
    let mut cut = postcard::to_stdvec(&key).unwrap();
    cut.extend_from_slice(&inner);
    let at = whole
        .windows(cut.len())
        .position(|window| window == cut.as_slice())
        .unwrap()
        + cut.len()
        - inner.len();
    let (before, after) = (&whole[..at], &whole[at + inner.len()..]);
    let mut nested = Vec::with_capacity(whole.len() * depth);
    for _ in 0..depth {
        nested.extend_from_slice(before);
    }
    nested.extend_from_slice(&inner);
    for _ in 0..depth {
        nested.extend_from_slice(after);
    }
    let edit = signed.pop().unwrap();
    let bytes = postcard::to_stdvec(&body(&edit)).unwrap();
    let at = bytes
        .windows(whole.len())
        .position(|window| window == whole.as_slice())
        .unwrap();
    let mut forged = bytes[..at].to_vec();
    forged.extend_from_slice(&nested);
    forged.extend_from_slice(&bytes[at + whole.len()..]);
    signed.push(forge_bytes(&edit, forged, 1));
    signed
}

#[test]
fn a_suggestion_proposing_a_suggestion_does_not_read_however_deep() {
    let (mut bob, mut bob_edits) = author(2);
    // Once: the suggestion as made, taken.
    take(&mut bob, &mut bob_edits, &nested_suggestion(1));
    let proposed: Vec<Key> = bob
        .suggestions()
        .into_iter()
        .flat_map(|suggestion| suggestion.edits)
        .map(|edit| edit.key)
        .collect();
    assert_eq!(proposed, [Key::Comment(0x55)]);
    // Proposing itself, a thousand deep and past a body's bound: does not
    // read, the reader's stack intact; its author signed it, so its chain
    // freezes there.
    for depth in [1000, 100_000] {
        let (mut cat, mut cat_edits) = author(3);
        let made = nested_suggestion(depth);
        let (applied, _) = cat.receive(made.clone(), &mut cat_edits);
        assert_eq!(applied.frozen, [(made[1].id().chain, 2)], "{depth}");
        assert_eq!(applied.changes, Vec::new());
        assert_eq!(cat.suggestions(), Vec::new());
    }
}
