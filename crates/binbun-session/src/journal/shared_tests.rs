//! A share's journal: rights judged when a change is applied, releases
//! included (sync §4.2; P2); what is admitted, pending and apart kept
//! apart on disk and in every state derived from them, through crashes
//! and restarts (sync §4.5; P10, P15, Astra's case B); freezes and
//! evidence written before they take effect; a chain bound elsewhere
//! turned away; the owner's work from before the share taken only as far
//! as its first record lists it; Bring a publication of chosen values.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::store::{self, crash};
use super::talk::{Anchor, Opening, ThreadOp};
use super::tests::{author, change, of, sealed, settled};
use super::{
    Authority, Body, Cause, ChainId, ChangeHash, ChangeId, Evidence, FrozenBy, Head, Intent,
    Journal, Key, Origin, PublicKey, SignedChange, Stopped, Under, Value, Verdict, Why,
};
use crate::edits::Edits;
use crate::identity::Identity;
use crate::project::{self, Bundle, Project};

/// The share's genesis in these tests.
const GENESIS: [u8; 32] = [0x6e; 32];

/// What a membership chain says, as a test sets it: per change, then per
/// author (of a change past its chain's start), what `admit` says (else
/// admit); who it names, each under grant 1.
#[derive(Default)]
struct Rules {
    changes: Mutex<BTreeMap<ChangeId, Verdict>>,
    authors: Mutex<BTreeMap<PublicKey, Verdict>>,
    members: Mutex<BTreeSet<PublicKey>>,
    asked: AtomicUsize,
    /// No link a reader's: own commits pending unless final.
    offline: std::sync::atomic::AtomicBool,
}

impl Rules {
    /// Naming `seeds`' keys members.
    fn of(seeds: &[u8]) -> Arc<Self> {
        let rules = Self::default();
        rules
            .members
            .lock()
            .unwrap()
            .extend(seeds.iter().map(|&seed| key(seed)));
        Arc::new(rules)
    }

    /// `author`'s changes judged `verdict` from now on (none: admitted).
    fn judge(&self, author: PublicKey, verdict: Option<Verdict>) {
        let mut authors = self.authors.lock().unwrap();
        match verdict {
            Some(verdict) => authors.insert(author, verdict),
            None => authors.remove(&author),
        };
    }
}

impl Authority for Rules {
    fn admit(&self, author: PublicKey, _: u64, head: &Head, _: &Body) -> Verdict {
        self.asked.fetch_add(1, Ordering::Relaxed);
        if let Some(verdict) = self.changes.lock().unwrap().get(&head.id()) {
            return verdict.clone();
        }
        if head.seq == 1 {
            return Verdict::Admit;
        }
        self.authors
            .lock()
            .unwrap()
            .get(&author)
            .cloned()
            .unwrap_or(Verdict::Admit)
    }

    fn knows(&self, author: PublicKey) -> bool {
        self.members.lock().unwrap().contains(&author)
    }

    fn grant(&self, author: PublicKey) -> Option<u64> {
        self.knows(author).then_some(1)
    }

    fn reader(&self) -> bool {
        !self.offline.load(Ordering::Relaxed)
    }
}

/// The key of seed `seed`.
fn key(seed: u8) -> PublicKey {
    super::Signer::from_seed(&[seed; 32]).public()
}

/// `rules` as the authority to attach.
#[expect(
    clippy::unnecessary_wraps,
    reason = "what `Journal::attach` takes: none detaches"
)]
fn judged(rules: &Arc<Rules>) -> Option<Arc<dyn Authority>> {
    Some(Arc::clone(rules) as Arc<dyn Authority>)
}

/// A member's journal (identity `seed`), in memory, of the share.
fn member(seed: u8, rules: &Arc<Rules>) -> (Journal, Edits) {
    let (mut journal, edits) = author(seed);
    journal.attach(judged(rules));
    let mut touched = BTreeSet::new();
    journal
        .share(GENESIS, of(), &BTreeMap::new(), &mut touched)
        .unwrap();
    (journal, edits)
}

fn name(text: &str) -> Value {
    Value::Text(Some(text.to_owned()))
}

/// Takes `changes` into `journal`; what it came to.
fn deliver(journal: &mut Journal, edits: &mut Edits, changes: &[SignedChange]) -> super::Applied {
    let applied = journal.receive(changes.to_vec(), edits).0;
    settled(journal, edits, applied)
}

/// A fresh directory of this process's, for test `name`.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("binbun-shared-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// The journal of the project in `dir`, `identity` writing.
fn open(dir: &Path, identity: &Identity) -> Result<(Edits, Journal), String> {
    super::open(&Project::new(dir), identity, of())
}

/// Every tip, by chain.
fn tips(journal: &Journal) -> BTreeMap<ChainId, (u64, ChangeHash)> {
    journal
        .tips_after(None, usize::MAX)
        .into_iter()
        .map(|tip| (tip.chain, (tip.seq, tip.hash)))
        .collect()
}

/// A cut by membership record 2.
const CUT: FrozenBy = FrozenBy::Cut {
    record: 2,
    hash: [2; 32],
};

#[test]
fn a_change_held_past_a_cut_is_never_admitted_in_any_order() {
    let rules = Rules::of(&[1, 2, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let (mut bob, mut bob_edits) = member(2, &rules);
    let a = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("ann"))]);
    deliver(&mut bob, &mut bob_edits, &a);
    // Bob's edits name Ann's: they wait for it where it has not come.
    let mut b = change(&mut bob, &mut bob_edits, &[(Key::Comment(1), name("bob"))]);
    b.extend(change(
        &mut bob,
        &mut bob_edits,
        &[(Key::Comment(2), name("more"))],
    ));
    let bob_chain = bob.chain;
    // Every order of Ann's changes, Bob's, and Bob's cut from 2.
    let events = ["a", "b", "cut"];
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for order in orders {
        let (mut carl, mut carl_edits) = member(3, &rules);
        for at in order {
            match events[at] {
                "a" => {
                    deliver(&mut carl, &mut carl_edits, &a);
                }
                "b" => {
                    deliver(&mut carl, &mut carl_edits, &b);
                }
                _ => {
                    let frozen = carl
                        .freeze_and_keep(&[(bob_chain, 2, CUT)], &mut carl_edits)
                        .unwrap()
                        .0;
                    settled(&mut carl, &mut carl_edits, frozen);
                }
            }
            // From the cut on, nothing of Bob's past it is admitted.
            let cut = order.iter().position(|&e| e == 2).unwrap();
            if order.iter().position(|&e| e == at).unwrap() >= cut {
                assert!(
                    carl.records
                        .keys()
                        .all(|id| id.chain != bob_chain || id.seq < 2),
                    "{order:?}"
                );
            }
        }
        assert_eq!(carl.tip(bob_chain).map(|tip| tip.seq), Some(1), "{order:?}");
        assert_eq!(carl.holding, 0, "{order:?}");
        assert_eq!(carl_edits.comment(1), Some("ann"), "{order:?}");
        assert_eq!(carl_edits.comment(2), None, "{order:?}");
    }
}

#[test]
fn a_change_released_is_judged_again_and_held_changes_need_a_known_chain() {
    let rules = Rules::of(&[1, 2, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let (mut bob, mut bob_edits) = member(2, &rules);
    let a = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("ann"))]);
    deliver(&mut bob, &mut bob_edits, &a);
    let b = change(&mut bob, &mut bob_edits, &[(Key::Comment(1), name("bob"))]);
    // Not its chain's start first: nothing held, its chain unknown.
    let (mut carl, mut carl_edits) = member(3, &rules);
    let applied = deliver(&mut carl, &mut carl_edits, &b[1..]);
    assert_eq!(applied.stopped[0].why, Stopped::Unknown);
    assert_eq!(applied.held, 0);
    // Held for Ann's; Bob made a viewer meanwhile: judged again when let
    // go, immediately before it would be taken, and not taken.
    let applied = deliver(&mut carl, &mut carl_edits, &b);
    assert_eq!(applied.held, 1);
    rules.judge(key(2), Some(Verdict::NotYet(Cause::ViewOnly(key(2)))));
    let rechecked = carl.recheck_held();
    let rechecked = settled(&mut carl, &mut carl_edits, rechecked);
    assert_eq!(rechecked.held, 1, "still waiting for Ann's");
    let before = rules.asked.load(Ordering::Relaxed);
    let applied = deliver(&mut carl, &mut carl_edits, &a);
    assert!(rules.asked.load(Ordering::Relaxed) > before);
    assert!(
        applied.stopped.iter().any(
            |stop| stop.id == b[1].id() && stop.why == Stopped::NotYet(Cause::ViewOnly(key(2)))
        ),
        "{applied:?}"
    );
    assert_eq!(carl_edits.comment(1), Some("ann"));
    assert_eq!(carl.tip(bob.chain).unwrap().seq, 1);
    // Detached, a share's journal takes nothing from outside.
    carl.attach(None);
    let applied = deliver(&mut carl, &mut carl_edits, &b[1..]);
    assert_eq!(applied.stopped[0].why, Stopped::Detached);
}

#[test]
fn a_chain_of_another_share_or_of_none_is_turned_away_and_a_listed_prefix_taken_so_far() {
    let rules = Rules::of(&[1, 2, 3, 5]);
    // Ann's work from before the share, on a chain of no share.
    let (mut ann, mut ann_edits) = author(1);
    let old = change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(1), name("before"))],
    );
    let past = change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(2), name("later"))],
    );
    let listed = BTreeMap::from([(ann.chain, (2, old[1].hash()))]);
    // Another share's chain.
    let (mut eve, mut eve_edits) = author(5);
    eve.attach(judged(&rules));
    eve.share([9; 32], of(), &BTreeMap::new(), &mut BTreeSet::new())
        .unwrap();
    let elsewhere = change(
        &mut eve,
        &mut eve_edits,
        &[(Key::Comment(3), name("other"))],
    );
    // A chain of no share that is not listed.
    let (mut dan, mut dan_edits) = author(4);
    let unlisted = change(
        &mut dan,
        &mut dan_edits,
        &[(Key::Comment(4), name("private"))],
    );
    let (mut bob, mut bob_edits) = author(2);
    bob.attach(judged(&rules));
    bob.share(GENESIS, of(), &listed, &mut BTreeSet::new())
        .unwrap();
    for turned in [&elsewhere, &unlisted] {
        let applied = deliver(&mut bob, &mut bob_edits, turned);
        assert!(
            matches!(applied.stopped[0].why, Stopped::Turned(_)),
            "{applied:?}"
        );
        assert_eq!(applied.known, []);
    }
    assert!(bob.chains.is_empty() && bob.records.is_empty());
    // The listed prefix: taken; past it, of neither.
    let applied = deliver(&mut bob, &mut bob_edits, &[old.clone(), past].concat());
    assert_eq!(applied.taken.len(), 2);
    assert!(matches!(applied.stopped[0].why, Stopped::Turned(_)));
    assert_eq!(bob_edits.comment(1), Some("before"));
    assert_eq!(bob_edits.comment(2), None);
    // Another branch at the listed number, by the same author: not it.
    let mut branch = super::tests::body(&old[1]);
    branch.ops[0].value = name("branch");
    let other = super::tests::forge(&old[1], &branch, 1);
    let (mut cat, mut cat_edits) = author(3);
    cat.attach(judged(&rules));
    cat.share(GENESIS, of(), &listed, &mut BTreeSet::new())
        .unwrap();
    let applied = deliver(&mut cat, &mut cat_edits, &[old[0].clone(), other]);
    assert!(matches!(applied.stopped[0].why, Stopped::Turned(_)));
    assert_eq!(cat_edits.comment(1), None);
}

#[test]
fn a_listed_prefix_is_of_the_share_by_its_listing_and_no_fork_or_cut_reaches_it() {
    // Ann's agent's work from before the share; the agent is no member.
    let rules = Rules::of(&[2]);
    let (mut ann, mut ann_edits) = author(1);
    let old = change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(1), name("before"))],
    );
    let listed = BTreeMap::from([(ann.chain, (2, old[1].hash()))]);
    let (mut bob, mut bob_edits) = author(2);
    bob.attach(judged(&rules));
    bob.share(GENESIS, of(), &listed, &mut BTreeSet::new())
        .unwrap();
    let applied = deliver(&mut bob, &mut bob_edits, &old);
    assert_eq!(applied.taken.len(), 2, "{applied:?}");
    // Another change at the listed number: not of the share, no proof.
    let mut branch = super::tests::body(&old[1]);
    branch.ops[0].value = name("branch");
    let other = super::tests::forge(&old[1], &branch, 1);
    let applied = deliver(&mut bob, &mut bob_edits, &[other]);
    assert!(
        matches!(applied.stopped[0].why, Stopped::Turned(_)),
        "{applied:?}"
    );
    assert_eq!((applied.forks.len(), bob.evidence(ann.chain)), (0, None));
    // A cut from 1 reaches no further than past the prefix.
    let frozen = bob
        .freeze_and_keep(&[(ann.chain, 1, CUT)], &mut bob_edits)
        .unwrap()
        .0;
    settled(&mut bob, &mut bob_edits, frozen);
    assert_eq!(bob.frozen_from(ann.chain), Some(3));
    assert_eq!(bob.tip(ann.chain).unwrap().seq, 2);
    assert_eq!(bob_edits.comment(1), Some("before"));
}

#[test]
fn an_owner_shares_the_chains_listed_and_keeps_the_rest_apart() {
    let rules = Rules::of(&[1]);
    let (mut ann, mut ann_edits) = author(1);
    let mine = change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(1), name("listed"))],
    );
    let old_chain = ann.chain;
    ann.new_chain().unwrap();
    change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(2), name("not listed"))],
    );
    let unlisted = ann.chain;
    ann.attach(judged(&rules));
    let listed = BTreeMap::from([(old_chain, (2, mine[1].hash()))]);
    let mut touched = BTreeSet::new();
    ann.share(GENESIS, of(), &listed, &mut touched).unwrap();
    let (_, keys) = ann.settle(super::Applied::default(), touched, &mut ann_edits);
    assert!(keys.contains(&Key::Comment(2)));
    assert_eq!(ann_edits.comment(1), Some("listed"));
    assert_eq!(ann_edits.comment(2), None);
    assert_eq!(
        tips(&ann),
        BTreeMap::from([(old_chain, (2, mine[1].hash()))])
    );
    assert!(ann.share.as_ref().unwrap().apart.contains(&unlisted));
    // New work names the share, on a new chain.
    let next = change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(3), name("shared"))],
    );
    assert!(next[0].id().chain != old_chain && next[0].id().chain != unlisted);
    assert_eq!(
        super::tests::body(&next[0]).bound.unwrap().share,
        Some(Under {
            genesis: GENESIS,
            grant: 1
        })
    );
    // Sharing again in the same share does nothing; in another, refused.
    let mut touched = BTreeSet::new();
    assert!(ann.share(GENESIS, of(), &listed, &mut touched).is_ok());
    assert!(ann.share([1; 32], of(), &listed, &mut touched).is_err());
}

#[test]
fn an_own_commit_attached_is_judged_and_one_not_taken_is_not_written() {
    let rules = Rules::of(&[1]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let made = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    assert_eq!(tips(&ann)[&ann.chain], (2, made[1].hash()));
    rules.judge(key(1), Some(Verdict::Never(Why::new("a viewer's edit"))));
    ann.begin("edit", Origin::User);
    ann.write(&Key::Comment(2), name("two"), &mut ann_edits);
    assert!(ann.commit(&mut ann_edits).is_err());
    assert_eq!(ann_edits.comment(2), None);
    assert!(ann.records.keys().all(|id| id.seq <= 2));
    // A Bring the share does not take writes nothing either.
    let (mut dan, mut dan_edits) = author(1);
    change(
        &mut dan,
        &mut dan_edits,
        &[(Key::Comment(7), name("private"))],
    );
    let values = dan.bringable();
    assert!(ann.bring(&values, "Bring", &mut ann_edits).is_err());
    assert_eq!(ann_edits.comment(7), None);
    // Taken, it is one change of Ann's, naming nothing of where it came
    // from, labelled as brought.
    rules.judge(key(1), None);
    let brought = sealed(ann.bring(&values, "My analysis", &mut ann_edits).unwrap());
    assert_eq!(brought.len(), 1);
    let body = super::tests::body(&brought[0]);
    assert_eq!(
        body.origin,
        Origin::Import("brought: My analysis".to_owned())
    );
    assert_eq!(body.ops.len(), 1);
    assert_eq!(body.ops[0].prev, []);
    assert_eq!(ann_edits.comment(7), Some("private"));
    assert_eq!(values[0].writer, dan.author());
}

#[test]
fn a_never_freezes_its_chain_after_its_evidence_and_freeze_are_written() {
    let rules = Rules::of(&[1, 2, 3]);
    let dir = scratch("never");
    let carl_id = Identity::ephemeral().unwrap();
    let (mut carl_edits, mut carl) = open(&dir, &carl_id).unwrap();
    carl.attach(judged(&rules));
    carl.share(GENESIS, of(), &BTreeMap::new(), &mut BTreeSet::new())
        .unwrap();
    let (mut bob, mut bob_edits) = member(2, &rules);
    let b = change(&mut bob, &mut bob_edits, &[(Key::Comment(1), name("one"))]);
    let more = change(&mut bob, &mut bob_edits, &[(Key::Comment(2), name("two"))]);
    rules
        .changes
        .lock()
        .unwrap()
        .insert(more[0].id(), Verdict::Never(Why::new("a viewer's edit")));
    let applied = deliver(&mut carl, &mut carl_edits, &[b, more.clone()].concat());
    assert_eq!(applied.frozen, [(bob.chain, 3)]);
    let log = dir.join("log");
    let evidence = fs::read_to_string(log.join("evidence")).unwrap();
    let frozen = fs::read_to_string(log.join("frozen")).unwrap();
    assert!(evidence.contains(&format!("{} refused", bob.chain)));
    assert!(frozen.contains(&format!("{} 3 never", bob.chain)));
    // Opened again, judged by nothing: the freeze, its evidence and the
    // admitted state as they were; nothing asked.
    drop(carl);
    let asked = rules.asked.load(Ordering::Relaxed);
    let (edits, again) = open(&dir, &carl_id).unwrap();
    assert_eq!(rules.asked.load(Ordering::Relaxed), asked);
    assert_eq!(again.frozen_from(bob.chain), Some(3));
    assert!(
        matches!(again.evidence(bob.chain), Some(Evidence::Refused(head)) if head.id() == more[0].id())
    );
    assert_eq!(again.tip(bob.chain).unwrap().seq, 2);
    assert_eq!(edits.comment(1), Some("one"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn marks_that_do_not_match_the_log_keep_it_from_opening_as_shared() {
    let rules = Rules::of(&[1, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let fork = (ann.clone(), ann_edits.clone());
    let a = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    let (mut fork, mut fork_edits) = fork;
    let other = change(
        &mut fork,
        &mut fork_edits,
        &[(Key::Comment(1), name("other"))],
    );
    let dir = scratch("marks");
    let carl_id = Identity::ephemeral().unwrap();
    {
        let (mut edits, mut carl) = open(&dir, &carl_id).unwrap();
        carl.attach(judged(&rules));
        carl.share(GENESIS, of(), &BTreeMap::new(), &mut BTreeSet::new())
            .unwrap();
        deliver(&mut carl, &mut edits, &a);
    }
    let log = dir.join("log");
    let copy = scratch("marks-copy");
    let reset = || {
        let _ = fs::remove_dir_all(copy.join("log"));
        // No project file a test's opening wrote: what opens is the log's.
        let _ = fs::remove_file(Project::new(&copy).edits());
        copy_dir(&log, &copy.join("log"));
    };
    let opens = || open(&copy, &carl_id).map(|_| ());
    reset();
    assert!(opens().is_ok());
    // Refilled: another change at the marked number.
    reset();
    let mut store = store::Store::new(copy.join("log"));
    store.cut(ann.chain, 2).unwrap();
    store.append(ann.chain, &[&other[1]]).unwrap();
    assert!(opens().unwrap_err().contains("mark"));
    // The mark past the end of its chain.
    reset();
    store::Store::new(copy.join("log"))
        .cut(ann.chain, 2)
        .unwrap();
    assert!(opens().unwrap_err().contains("mark"));
    // The marked chain's file gone: not opened, never taken as no chain.
    reset();
    let file = copy.join("log/chains").join(format!("{}.log", ann.chain));
    fs::remove_file(&file).unwrap();
    assert!(opens().is_err());
    // The marked chain's file does not read: its mark cannot be checked.
    reset();
    let mut bytes = fs::read(&file).unwrap();
    // Its start numbered 0, past the file's first line.
    let seq = b"binbun log 1\n".len() + 16;
    bytes[seq..seq + 8].copy_from_slice(&0u64.to_be_bytes());
    assert!(store::decode(&bytes).is_err());
    fs::write(&file, bytes).unwrap();
    assert!(opens().is_err());
    // Marks of another share than the log's.
    reset();
    fs::write(copy.join("log/share"), format!("{}\n", "11".repeat(32))).unwrap();
    assert!(opens().is_err());
    // No freezes, or no evidence: not opened, never taken as none.
    for gone in ["frozen", "evidence", "admitted"] {
        reset();
        fs::remove_file(copy.join("log").join(gone)).unwrap();
        assert!(opens().is_err(), "{gone}");
    }
    // A bundle of the project carries no marks, nor the share.
    reset();
    let key = labelled(&copy);
    let bundle = Bundle::of(&Project::new(&copy), &key).unwrap();
    let paths: Vec<&str> = bundle
        .logs()
        .iter()
        .map(|(path, _)| path.as_str())
        .collect();
    assert!(paths.contains(&"log/frozen"));
    for local in ["log/admitted", "log/share", "log/local"] {
        assert!(!paths.contains(&local), "{paths:?}");
    }
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&copy);
}

/// Copies directory `from` to `to`, whole.
fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            copy_dir(&path, &to.join(entry.file_name()));
        } else {
            fs::copy(&path, to.join(entry.file_name())).unwrap();
        }
    }
}

/// Carl's pending work, refused (a viewer) and moved apart with a crash
/// at write `at` (none: none); then the process starts again, Carl is
/// made an editor and his pending work judged again. Whether the crash
/// came, and the chain the work was on.
fn refused_then_promoted(dir: &Path, at: Option<usize>) -> bool {
    let rules = Rules::of(&[3]);
    let carl_id = Identity::ephemeral().unwrap();
    let carl_key = carl_id.public();
    rules.members.lock().unwrap().insert(carl_key);
    let (old, work, crashed) = {
        let (mut edits, mut carl) = open(dir, &carl_id).unwrap();
        carl.attach(judged(&rules));
        carl.share(GENESIS, of(), &BTreeMap::new(), &mut BTreeSet::new())
            .unwrap();
        // Made while collaboration is not attached: pending.
        carl.attach(None);
        let mut work = change(&mut carl, &mut edits, &[(Key::Comment(1), name("one"))]);
        work.extend(change(
            &mut carl,
            &mut edits,
            &[(Key::Comment(2), name("two"))],
        ));
        carl.flush().unwrap();
        assert!(
            carl.tip(carl.chain).is_none(),
            "pending work is told nothing"
        );
        let old = carl.chain;
        // Attached as a viewer: refused, moved apart.
        rules.judge(carl_key, Some(Verdict::Never(Why::new("a viewer's edit"))));
        carl.attach(judged(&rules));
        crash::arm(at);
        let promoted = carl.promote(true, &mut BTreeSet::new());
        let crashed = crash::crashed();
        crash::arm(None);
        if !crashed {
            let applied = promoted.unwrap();
            assert_eq!(applied.refused.len(), 2, "{applied:?}");
            assert_ne!(carl.chain, old);
        }
        (old, work, crashed)
    };
    let apart = dir.join("log/apart").join(format!("{old}.log"));
    let refused_durably = fs::read(&apart)
        .ok()
        .and_then(|bytes| store::decode(&bytes).ok())
        .is_some_and(|(kept, _)| kept.iter().any(|change| change.id() == work[1].id()));
    // Started again, made an editor, judged again.
    let (mut edits, mut carl) = open(dir, &carl_id).unwrap();
    rules.judge(carl_key, None);
    carl.attach(judged(&rules));
    let mut touched = BTreeSet::new();
    let applied = carl.promote(true, &mut touched).unwrap();
    carl.settle(applied, touched, &mut edits);
    let told = carl.changes_after(old, 1, usize::MAX, usize::MAX);
    if refused_durably {
        // Refused once is refused for good: never told, never shown.
        assert_eq!(told, [], "{at:?}");
        assert!(carl.records.keys().all(|id| id.chain != old || id.seq == 1));
        assert_eq!((edits.comment(1), edits.comment(2)), (None, None), "{at:?}");
        assert_ne!(carl.chain, old);
    } else {
        // Never refused where it counts: judged now, and taken.
        assert_eq!(told, work[1..], "{at:?}");
        assert_eq!(edits.comment(2), Some("two"));
    }
    // New work is taken, on a chain that can go on.
    let next = change(&mut carl, &mut edits, &[(Key::Comment(3), name("three"))]);
    assert!(
        next.iter()
            .all(|change| change.id().chain != old || !refused_durably)
    );
    assert_eq!(
        carl.tip(carl.chain).unwrap().hash,
        next.last().unwrap().hash()
    );
    crashed
}

#[test]
fn refused_pending_work_stays_apart_after_a_restart_at_any_write_and_a_promotion() {
    for at in 0.. {
        let dir = scratch(&format!("apart-{at}"));
        let crashed = refused_then_promoted(&dir, Some(at));
        let _ = fs::remove_dir_all(&dir);
        if !crashed {
            assert!(at > 1, "the move has writes to crash at");
            break;
        }
    }
    // And with no crash, restarted after the move.
    let dir = scratch("apart");
    assert!(!refused_then_promoted(&dir, None));
    let _ = fs::remove_dir_all(&dir);
}

/// What the scenario of [`replayed_state_after_a_crash_at_each_write_is_the_models`]
/// has made: each author's changes, Carl's own as made.
struct Scenario {
    ann: Vec<SignedChange>,
    bob: Vec<SignedChange>,
    carl_old: Vec<SignedChange>,
    carl_new: Vec<SignedChange>,
}

/// The tips the rules give after each step of the scenario, computed
/// from what was delivered and decided, not from the journal: what may
/// have been told then.
fn model(scenario: &Scenario) -> Vec<BTreeMap<ChainId, (u64, ChangeHash)>> {
    let tip = |changes: &[SignedChange], seq: u64| {
        let change = changes.iter().find(|change| change.id().seq == seq)?;
        Some((change.id().chain, (seq, change.hash())))
    };
    let mut steps = vec![BTreeMap::new(); 2];
    // Ann's three: admitted.
    let mut now: BTreeMap<_, _> = tip(&scenario.ann, 3).into_iter().collect();
    steps.push(now.clone());
    // Bob's start and edit; his next refused for good.
    now.extend(tip(&scenario.bob, 2));
    steps.push(now.clone());
    // Ann cut from 3.
    now.extend(tip(&scenario.ann, 2));
    steps.push(now.clone());
    // Carl's pending work: told nothing.
    steps.push(now.clone());
    // Judged: his start admitted, his edit refused and moved apart.
    now.extend(tip(&scenario.carl_old, 1));
    steps.push(now.clone());
    // His next, on a new chain: admitted.
    now.extend(tip(&scenario.carl_new, 2));
    steps.push(now);
    steps
}

/// What was told after each step.
type Told = Vec<BTreeMap<ChainId, (u64, ChangeHash)>>;

/// Runs the scenario in `dir` with a crash at write `at`: how many steps
/// completed, what was told after each, and what it made.
fn run(dir: &Path, at: Option<usize>, carl_id: &Identity) -> (usize, Told, Scenario) {
    let rules = Rules::of(&[1, 2, 3]);
    rules.members.lock().unwrap().insert(carl_id.public());
    let (mut ann, mut ann_edits) = member(1, &rules);
    let (mut bob, mut bob_edits) = member(2, &rules);
    let mut scenario = Scenario {
        ann: change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("a"))]),
        bob: change(&mut bob, &mut bob_edits, &[(Key::Comment(2), name("b"))]),
        carl_old: Vec::new(),
        carl_new: Vec::new(),
    };
    scenario.ann.extend(change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(3), name("a"))],
    ));
    let refused = change(&mut bob, &mut bob_edits, &[(Key::Comment(4), name("b"))]);
    rules
        .changes
        .lock()
        .unwrap()
        .insert(refused[0].id(), Verdict::Never(Why::new("refused")));
    let (mut edits, mut carl) = open(dir, carl_id).unwrap();
    let mut told = vec![tips(&carl)];
    crash::arm(at);
    let mut done = 0;
    for step in 0..7 {
        match step {
            0 => {
                carl.attach(judged(&rules));
                let _ = carl.share(GENESIS, of(), &BTreeMap::new(), &mut BTreeSet::new());
            }
            1 => {
                deliver(&mut carl, &mut edits, &scenario.ann);
            }
            2 => {
                let bob = [scenario.bob.clone(), refused.clone()].concat();
                deliver(&mut carl, &mut edits, &bob);
            }
            3 => {
                let ann = scenario.ann[0].id().chain;
                if let Ok((frozen, _)) = carl.freeze_and_keep(&[(ann, 3, CUT)], &mut edits) {
                    settled(&mut carl, &mut edits, frozen);
                }
            }
            4 => {
                carl.attach(None);
                scenario.carl_old = change(&mut carl, &mut edits, &[(Key::Comment(5), name("c"))]);
                let _ = carl.flush();
            }
            5 => {
                rules.judge(
                    carl_id.public(),
                    Some(Verdict::Never(Why::new("a viewer's edit"))),
                );
                carl.attach(judged(&rules));
                let _ = carl.promote(true, &mut BTreeSet::new());
            }
            _ => {
                rules.judge(carl_id.public(), None);
                if let Ok(made) = carl.commit_one(&mut edits, &Key::Comment(6), name("d")) {
                    scenario.carl_new = made;
                }
            }
        }
        if crash::crashed() {
            break;
        }
        done += 1;
        told.push(tips(&carl));
    }
    crash::arm(None);
    (done, told, scenario)
}

impl Journal {
    /// Commits `value` to `key` as one change by the user; what it made.
    fn commit_one(
        &mut self,
        edits: &mut Edits,
        key: &Key,
        value: Value,
    ) -> Result<Vec<SignedChange>, String> {
        self.begin("edit", Origin::User);
        self.write(key, value, edits);
        self.commit(edits).map(sealed)
    }
}

#[test]
fn replayed_state_after_a_crash_at_each_write_is_the_models() {
    let mut crashes = 0;
    for at in 0.. {
        let dir = scratch(&format!("crash-{at}"));
        let carl_id = Identity::ephemeral().unwrap();
        let (done, told, scenario) = run(&dir, Some(at), &carl_id);
        if done == 7 {
            // No crash: told after each step what the model says.
            let models = model(&scenario);
            assert_eq!(told, models);
            let _ = fs::remove_dir_all(&dir);
            break;
        }
        crashes += 1;
        let models = model(&scenario);
        // Opened again with no authority: it opens, and each chain's tip is
        // what was told before the step the crash fell in, or after it.
        let (_, again) = open(&dir, &carl_id).unwrap_or_else(|why| panic!("{at}: {why}"));
        let now = tips(&again);
        let (before, after) = (&models[done], models.get(done + 1).unwrap_or(&models[done]));
        let chains: BTreeSet<&ChainId> = now
            .keys()
            .chain(before.keys())
            .chain(after.keys())
            .collect();
        for chain in chains {
            let tip = now.get(chain);
            assert!(
                tip == before.get(chain) || tip == after.get(chain),
                "crash at write {at}, in step {}: {chain} told {tip:?}, before {:?}, after {:?}",
                done + 1,
                before.get(chain),
                after.get(chain),
            );
        }
        // Nothing told before the crash is lost but by a freeze since.
        assert_eq!(told[done], models[done], "{at}");
        // No freeze lacks what it rests on.
        for (chain, (from, by)) in &again.frozen {
            match by {
                FrozenBy::Never => assert!(matches!(
                    again.evidence.get(chain),
                    Some(Evidence::Refused(head)) if head.head.seq == *from
                )),
                FrozenBy::Fork => assert!(matches!(
                    again.evidence.get(chain),
                    Some(Evidence::Proof(_))
                )),
                FrozenBy::Cut { .. } => {}
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
    assert!(crashes > 10, "{crashes} writes crashed at");
}

/// Carl's journal of the share, kept in `dir`, with `changes` of Ann's
/// taken; its projection.
fn carl_with(
    dir: &Path,
    carl_id: &Identity,
    rules: &Arc<Rules>,
    changes: &[SignedChange],
) -> (Edits, Journal) {
    let (mut edits, mut carl) = open(dir, carl_id).unwrap();
    carl.attach(judged(rules));
    carl.share(GENESIS, of(), &BTreeMap::new(), &mut BTreeSet::new())
        .unwrap();
    let applied = deliver(&mut carl, &mut edits, changes);
    assert!(applied.failed.is_empty(), "{applied:?}");
    (edits, carl)
}

#[test]
fn a_directory_sync_that_fails_fails_the_write_it_ends() {
    let rules = Rules::of(&[1, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let a = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    let dir = scratch("sync");
    let carl_id = Identity::ephemeral().unwrap();
    let (mut edits, mut carl) = carl_with(&dir, &carl_id, &rules, &a);
    // The freeze's file written and renamed into place (write 0), its
    // directory's flush failing (write 1).
    crash::arm(Some(1));
    let frozen = carl.freeze_and_keep(&[(ann.chain, 2, CUT)], &mut edits);
    let crashed = crash::crashed();
    crash::arm(None);
    assert!(crashed);
    assert!(frozen.is_err());
    // Not in effect: the write is not done.
    assert_eq!(carl.frozen_from(ann.chain), None);
    assert_eq!(edits.comment(1), Some("one"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_intent_kept_has_its_freezes_in_force_before_the_log_is_read() {
    let rules = Rules::of(&[1, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let mut a = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    a.extend(change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(2), name("two"))],
    ));
    let dir = scratch("intent");
    let carl_id = Identity::ephemeral().unwrap();
    let (edits, _) = carl_with(&dir, &carl_id, &rules, &a);
    assert_eq!(edits.comment(2), Some("two"));
    // A record cutting Ann's chain after her first edit was being taken
    // when the process stopped (its intent written, nothing else); beside
    // it, an intent of another share.
    let intent = |genesis: [u8; 32], from: u64| Intent {
        genesis,
        record: b"the record, signed".to_vec(),
        seq: 2,
        hash: [2; 32],
        freezes: BTreeMap::from([(ann.chain, from)]),
    };
    for (share, intent) in [("aa", intent(GENESIS, 3)), ("bb", intent([0x11; 32], 2))] {
        let kept = dir.join("collab").join(share.repeat(16));
        fs::create_dir_all(&kept).unwrap();
        fs::write(kept.join("intent"), intent.encode()).unwrap();
    }
    // Opened again with no collaboration: the cut is kept and in force
    // before anything of the log is taken; the other share's is not.
    let (edits, again) = open(&dir, &carl_id).unwrap();
    assert_eq!(edits.comment(1), Some("one"));
    assert_eq!(edits.comment(2), None);
    assert_eq!(again.frozen.get(&ann.chain), Some(&(3, CUT)));
    let kept = store::Store::new(dir.join("log"))
        .frozen()
        .unwrap()
        .unwrap();
    assert_eq!(kept.get(&ann.chain), Some(&(3, CUT)));
    assert_eq!(tips(&again).get(&ann.chain).map(|tip| tip.0), Some(2));
    // An intent that does not read keeps the log from opening.
    let kept = dir.join("collab").join("cc".repeat(16));
    fs::create_dir_all(&kept).unwrap();
    fs::write(kept.join("intent"), "binbun intent 1\n").unwrap();
    assert!(open(&dir, &carl_id).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn changes_whose_write_or_marks_fail_are_taken_back_and_come_again() {
    let rules = Rules::of(&[1, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    // A comment, and a thread opened: conversation to be told.
    ann.begin("edit", Origin::User);
    let thread = ann.next_talk().unwrap();
    let opening = Opening {
        anchor: Anchor::Function(0x1000),
        quote: "int f(void)".to_owned(),
    };
    let opened = Value::Thread(ThreadOp::Open(Box::new(opening)));
    ann.write(&Key::Thread(thread), opened, &mut ann_edits);
    ann.write(&Key::Comment(1), name("one"), &mut ann_edits);
    let a = sealed(ann.commit(&mut ann_edits).unwrap());
    let carl_id = Identity::ephemeral().unwrap();
    for at in 0.. {
        let dir = scratch(&format!("unwritten-{at}"));
        let (mut edits, mut carl) = carl_with(&dir, &carl_id, &rules, &[]);
        let _ = carl.talked();
        let history = carl.history();
        crash::arm(Some(at));
        let applied = deliver(&mut carl, &mut edits, &a);
        let crashed = crash::crashed();
        crash::arm(None);
        if !crashed {
            // The chain's file (0), its directory (1), the marks (2) and
            // theirs (3).
            assert!(at >= 4, "{at}");
            let _ = fs::remove_dir_all(&dir);
            break;
        }
        // Nothing of it shown, told, known or admitted.
        assert!(!applied.failed.is_empty(), "{at}");
        assert_eq!(
            (&applied.taken, &applied.known, &applied.changes),
            (&Vec::new(), &Vec::new(), &Vec::new()),
            "{at}"
        );
        assert_eq!(edits.comment(1), None, "{at}");
        assert_eq!(carl.history(), history, "{at}");
        assert!(carl.talked().is_none(), "{at}");
        assert!(carl.chains().iter().all(|(chain, ..)| *chain != ann.chain));
        assert_eq!(tips(&carl).get(&ann.chain), None, "{at}");
        // It comes again and is taken, written once.
        let applied = deliver(&mut carl, &mut edits, &a);
        assert!(applied.failed.is_empty(), "{at}: {applied:?}");
        assert_eq!(applied.taken.len(), 2, "{at}");
        assert_eq!(edits.comment(1), Some("one"));
        let (talked, _) = carl.talked().unwrap();
        assert_eq!(talked.threads, [thread], "{at}");
        let told = tips(&carl);
        let file = dir.join("log/chains").join(format!("{}.log", ann.chain));
        let (held, _) = store::decode(&fs::read(file).unwrap()).unwrap();
        assert_eq!(held, a, "{at}");
        let (edits, again) = open(&dir, &carl_id).unwrap();
        assert_eq!(tips(&again), told, "{at}");
        assert_eq!(edits.comment(1), Some("one"));
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn an_own_change_that_cannot_be_written_is_not_made() {
    let rules = Rules::of(&[3]);
    let carl_id = Identity::ephemeral().unwrap();
    rules.members.lock().unwrap().insert(carl_id.public());
    let dir = scratch("own-unwritten");
    let (mut edits, mut carl) = carl_with(&dir, &carl_id, &rules, &[]);
    let history = carl.history();
    crash::arm(Some(0));
    let made = carl.commit_one(&mut edits, &Key::Comment(1), name("one"));
    crash::arm(None);
    assert!(made.is_err());
    assert_eq!(edits.comment(1), None);
    assert_eq!(carl.history(), history);
    assert_eq!(carl.tip(carl.chain), None);
    // Made again: written, then taken and told.
    let made = carl
        .commit_one(&mut edits, &Key::Comment(1), name("one"))
        .unwrap();
    assert_eq!(edits.comment(1), Some("one"));
    assert_eq!(
        carl.tip(carl.chain).map(|tip| tip.hash),
        made.last().map(SignedChange::hash)
    );
    let (edits, again) = open(&dir, &carl_id).unwrap();
    assert_eq!(edits.comment(1), Some("one"));
    assert_eq!(tips(&again), tips(&carl));
    let _ = fs::remove_dir_all(&dir);
}

/// Binds the log in `dir` to the bytes of the key returned, the label an
/// export of it takes (an export takes no other); done last, as the log's
/// marks name the binding it had.
fn labelled(dir: &Path) -> project::Key {
    let key = project::Key::new(b"the binary", "binary");
    fs::write(dir.join("log/bound"), format!("binary {} -\n", key.hex())).unwrap();
    key
}

/// The changes of the chains' files of `bundle`.
fn bundled(bundle: &Bundle) -> Vec<SignedChange> {
    bundle
        .logs()
        .iter()
        .filter(|(path, _)| path.starts_with("log/chains/"))
        .flat_map(|(_, bytes)| store::decode(bytes).unwrap().0)
        .collect()
}

#[test]
fn an_export_of_a_share_carries_its_admitted_and_pending_changes_and_nothing_else() {
    let dir = scratch("export");
    // Carl's pending work refused (moved apart), then new work admitted.
    assert!(!refused_then_promoted(&dir, None));
    let refused: Vec<ChangeId> = fs::read_dir(dir.join("log/apart"))
        .unwrap()
        .flat_map(|entry| {
            store::decode(&fs::read(entry.unwrap().path()).unwrap())
                .unwrap()
                .0
        })
        .map(|change| change.id())
        .collect();
    assert_eq!(refused.len(), 2, "{refused:?}");
    // What is no project's to export, beside what is.
    for (path, text) in [
        ("project.toml", "format = 1\n"),
        ("collab/lock", ""),
        (
            "collab/00112233445566778899aabbccddeeff/membership.log",
            "x",
        ),
        ("private.toml", ""),
        ("notes.txt", "mine"),
        ("states/any.zero.toml", ""),
        ("states/deeper/any.one.toml", ""),
        ("log/grants", ""),
        ("log/import/waiting.toml", "format = 1\n"),
        ("log/chains/not-a-chain.log", ""),
        ("log/project.toml.tmp", ""),
    ] {
        let at = dir.join(path);
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        fs::write(at, text).unwrap();
    }
    let key = labelled(&dir);
    let bundle = Bundle::of(&Project::new(&dir), &key).unwrap();
    let files: Vec<&str> = bundle
        .files()
        .iter()
        .map(|(path, _)| path.as_str())
        .collect();
    assert_eq!(files, ["project.toml", "states/any.zero.toml"]);
    let logs: Vec<&str> = bundle
        .logs()
        .iter()
        .map(|(path, _)| path.as_str())
        .collect();
    for path in &logs {
        assert!(
            [
                "log/project",
                "log/bound",
                "log/projected",
                "log/frozen",
                "log/evidence"
            ]
            .contains(path)
                || (path.starts_with("log/chains/") && path.len() == "log/chains/".len() + 36),
            "{logs:?}"
        );
    }
    // None of the refused work, in any file; the work admitted since.
    let changes = bundled(&bundle);
    assert!(changes.iter().all(|change| !refused.contains(&change.id())));
    assert!(
        changes
            .iter()
            .any(|change| change.id().chain != refused[0].chain)
    );
    // What a bundle holds beside that is not taken from it either.
    let mut text = bundle.to_toml().unwrap();
    for path in [
        "log/apart/00112233445566778899aabbccddeeff.log",
        "log/admitted",
        "log/local",
    ] {
        text += "[[file]]\npath = \"";
        text += path;
        text += "\"\ndata = \"\"\n";
    }
    text.push_str("[[file]]\npath = \"collab/lock\"\ntext = \"\"\n");
    assert_eq!(Bundle::parse(&text).unwrap(), bundle);
    // Labelled only as the binary its log is of.
    let other = project::Key::new(b"another binary", "binary");
    assert!(Bundle::of(&Project::new(&dir), &other).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn merging_an_overlapping_bundle_leaves_admitted_history_intact() {
    let rules = Rules::of(&[1, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let a = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    let later = change(&mut ann, &mut ann_edits, &[(Key::Comment(2), name("two"))]);
    let chain = ann.chain;
    let dir = scratch("merge-overlap");
    let carl_id = Identity::ephemeral().unwrap();
    {
        let (mut edits, mut carl) = open(&dir, &carl_id).unwrap();
        carl.attach(judged(&rules));
        carl.share(GENESIS, of(), &BTreeMap::new(), &mut BTreeSet::new())
            .unwrap();
        deliver(&mut carl, &mut edits, &a);
        // An authentic bundle of Ann's chain: what Carl admitted, and more.
        let bundle: Vec<SignedChange> = a.iter().chain(&later).cloned().collect();
        carl.merge_bundle(bundle, &mut BTreeSet::new()).unwrap();
    }
    {
        // What Carl held stays as it was; only the rest is apart.
        let (mut edits, mut carl) = open(&dir, &carl_id).unwrap();
        assert_eq!(
            carl.tip(chain).map(|tip| tip.hash),
            a.last().map(SignedChange::hash)
        );
        assert_eq!((edits.comment(1), edits.comment(2)), (Some("one"), None));
        let apart: Vec<ChangeId> = carl.apart_edits().iter().map(|edit| edit.change).collect();
        assert_eq!(
            apart,
            later.iter().map(SignedChange::id).collect::<Vec<_>>()
        );
        // The rest comes by a link and is admitted: the copy apart cuts
        // none of it at the next opening.
        carl.attach(judged(&rules));
        deliver(&mut carl, &mut edits, &later);
        assert_eq!(edits.comment(2), Some("two"));
    }
    let (edits, carl) = open(&dir, &carl_id).unwrap();
    assert_eq!(
        carl.tip(chain).map(|tip| tip.hash),
        later.last().map(SignedChange::hash)
    );
    assert_eq!(edits.comment(2), Some("two"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_share_takes_no_bundle_without_a_log_and_is_not_replaced_unasked() {
    let root = scratch("merge-unsigned");
    let text = format!(
        "format = 1\nsha256 = \"{}\"\nname = \"x\"\n[[file]]\npath = \"project.toml\"\ntext = \"\"\"\nformat = 1\n[[function]]\naddress = \"0x1190\"\nname = \"theirs\"\n\"\"\"\n",
        "ab".repeat(32)
    );
    let bundle = Bundle::parse(&text).unwrap();
    let dir = bundle.project_in(&root).dir().to_owned();
    let carl_id = Identity::ephemeral().unwrap();
    {
        let (_, mut carl) = open(&dir, &carl_id).unwrap();
        carl.attach(judged(&Rules::of(&[])));
        carl.share(GENESIS, of(), &BTreeMap::new(), &mut BTreeSet::new())
            .unwrap();
    }
    // A share with no edits yet is the user's still.
    assert_eq!(
        project::import(&bundle, &root, false).unwrap(),
        project::Imported::Exists(Project::new(&dir))
    );
    // Its edits would be signed as Carl's own work in the share, which
    // grants him editing: not merged, and nothing taken.
    let grant = format!("{} 1\n", store::hex(&carl_id.public().0));
    fs::write(dir.join("log/grants"), grant).unwrap();
    assert!(project::merge(&bundle, &root, &carl_id).is_err());
    let (edits, _) = open(&dir, &carl_id).unwrap();
    assert!(edits.is_empty());
    let _ = fs::remove_dir_all(&root);
}

/// The project's lock file opened as another process would open it.
fn writer(dir: &Path) -> fs::File {
    fs::create_dir_all(dir.join("collab")).unwrap();
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join("collab").join("lock"))
        .unwrap()
}

#[test]
fn a_bring_while_the_owners_journal_is_written_leaves_it_intact() {
    let rules = Rules::of(&[1, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let mut a = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    a.extend(change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(2), name("two"))],
    ));
    let dir = scratch("bring-written");
    let carl_id = Identity::ephemeral().unwrap();
    let marks = dir.join("log/admitted");
    let (mut edits, mut carl) = carl_with(&dir, &carl_id, &rules, &a[..2]);
    let before = fs::read(&marks).unwrap();
    deliver(&mut carl, &mut edits, &a[2..]);
    let after = fs::read(&marks).unwrap();
    drop(carl);
    // The writer (another process here) has appended Ann's second edit
    // and not marked it yet: a Bring from the same project now.
    fs::write(&marks, &before).unwrap();
    let file = dir.join("log/chains").join(format!("{}.log", ann.chain));
    let written = fs::read(&file).unwrap();
    let lock = writer(&dir);
    lock.try_lock().unwrap();
    assert!(Project::new(&dir).bringable(&carl_id).is_err());
    assert_eq!(fs::read(&file).unwrap(), written);
    // The writer marks it and lets go: the project opens, intact.
    fs::write(&marks, &after).unwrap();
    lock.unlock().unwrap();
    let (edits, _) = open(&dir, &carl_id).unwrap();
    assert_eq!(edits.comment(2), Some("two"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_lost_freeze_list_is_never_rebuilt_from_an_intent_alone() {
    let rules = Rules::of(&[1, 2, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let mut a = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    a.extend(change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(2), name("two"))],
    ));
    let (mut bob, mut bob_edits) = member(2, &rules);
    let b = change(&mut bob, &mut bob_edits, &[(Key::Comment(3), name("bob"))]);
    let dir = scratch("lost-frozen");
    let carl_id = Identity::ephemeral().unwrap();
    let (mut edits, mut carl) = carl_with(&dir, &carl_id, &rules, &[a, b].concat());
    // An earlier cut of Bob's chain, in force and kept.
    let frozen = carl.freeze_durably(&[(bob.chain, 2, CUT)]).unwrap();
    settled(&mut carl, &mut edits, frozen);
    assert_eq!(edits.comment(3), None);
    drop(carl);
    // A record cutting Ann's chain being taken (its intent kept), and the
    // freeze list lost.
    let kept = dir.join("collab").join("aa".repeat(16));
    fs::create_dir_all(&kept).unwrap();
    let intent = Intent {
        genesis: GENESIS,
        record: b"the record, signed".to_vec(),
        seq: 3,
        hash: [3; 32],
        freezes: BTreeMap::from([(ann.chain, 3)]),
    };
    fs::write(kept.join("intent"), intent.encode()).unwrap();
    fs::remove_file(dir.join("log/frozen")).unwrap();
    // Not opened, and no list made of the intent alone (Bob's cut lost).
    assert!(open(&dir, &carl_id).is_err());
    assert!(!dir.join("log/frozen").exists());
    assert!(open(&dir, &carl_id).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_marks_make_a_log_a_shares_and_every_marked_change_must_be_taken() {
    let rules = Rules::of(&[1, 3]);
    let (mut ann, mut ann_edits) = member(1, &rules);
    let mut a = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    a.extend(change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(2), name("two"))],
    ));
    let dir = scratch("lost-share");
    let carl_id = Identity::ephemeral().unwrap();
    drop(carl_with(&dir, &carl_id, &rules, &a));
    let log = dir.join("log");
    let copy = scratch("lost-share-copy");
    let reset = || {
        let _ = fs::remove_dir_all(copy.join("log"));
        let _ = fs::remove_file(Project::new(&copy).edits());
        copy_dir(&log, &copy.join("log"));
    };
    // The genesis lost: opened as the share's, its genesis written again.
    reset();
    fs::remove_file(copy.join("log/share")).unwrap();
    let (edits, again) = open(&copy, &carl_id).unwrap();
    assert_eq!(again.genesis(), Some(GENESIS));
    assert_eq!(edits.comment(2), Some("two"));
    assert_eq!(
        store::Store::new(copy.join("log")).share().unwrap(),
        Some(GENESIS)
    );
    // The genesis and the freezes lost: not opened, as shared or not.
    reset();
    fs::remove_file(copy.join("log/share")).unwrap();
    fs::remove_file(copy.join("log/frozen")).unwrap();
    assert!(open(&copy, &carl_id).is_err());
    // A marked change that replay refuses (its body not the one its head
    // commits to): not opened.
    reset();
    let file = copy.join("log/chains").join(format!("{}.log", ann.chain));
    let mut bytes = fs::read(&file).unwrap();
    let at = bytes.windows(3).rposition(|word| word == b"two").unwrap();
    bytes[at + 2] = b'x';
    fs::write(&file, bytes).unwrap();
    assert!(open(&copy, &carl_id).is_err());
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&copy);
}
