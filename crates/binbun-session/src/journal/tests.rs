//! The journal's merge rules and its change format: every delivery order
//! gives the same projection and conflicts; concurrent edits are
//! conflicts, resolved by an op naming every leaf; undo is per author by
//! compare-and-set; a chain begins with a start and nothing else; heads,
//! signed heads and proofs read back exactly as written; a body is read
//! within its bounds; a group too large for one change is one undo step
//! and one history entry; a forged, malformed or forked chain is refused
//! or frozen with its evidence kept.

use binbun::corrections::{Bounds, Data, Item, Unit};

use super::{
    Body, Bound, ChainId, ChangeHash, Committed, Evidence, ForkProof, Group, Head, Journal, Key,
    MAX_BODY, MAX_OPS, MAX_PARTS, MAX_START, Of, Op, Origin, ProjectId, PublicKey, SignedChange,
    SignedHead, Signer, Stated, Stopped, Value,
};
use crate::edits::{Edits, NumberForm, Typed, Variable};
use crate::identity::Identity;
use crate::number::canonical;
use crate::project::Project;

/// `SplitMix64`: a reproducible stream of numbers.
pub(super) struct Rng(pub(super) u64);

impl Rng {
    pub(super) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub(super) fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[usize::try_from(self.below(items.len() as u64)).unwrap()]
    }
}

const PROJECT: ProjectId = ProjectId([7; 16]);

/// What the tests' journals' chains are of.
pub(super) fn of() -> Of {
    Of::Binary {
        sha256: [7; 32],
        slice: None,
    }
}

/// An author's journal (identity `seed`) and its projection.
pub(super) fn author(seed: u8) -> (Journal, Edits) {
    let journal = Journal::new(PROJECT, of(), Signer::from_seed(&[seed; 32])).unwrap();
    (journal, Edits::default())
}

/// Writes `ops` as one change made by the user; what it made (its chain's
/// start first, if it began the chain).
pub(super) fn change(
    journal: &mut Journal,
    edits: &mut Edits,
    ops: &[(Key, Value)],
) -> Vec<SignedChange> {
    journal.begin("edit", Origin::User);
    for (key, value) in ops {
        journal.write(key, value.clone(), edits);
    }
    sealed(journal.commit(edits).unwrap())
}

/// The changes `committed` made.
pub(super) fn sealed(committed: Committed) -> Vec<SignedChange> {
    let Committed::Sealed(records) = committed else {
        panic!("nothing sealed");
    };
    records.iter().map(|record| record.signed.clone()).collect()
}

/// Takes `changes` into `journal`; what it came to, with the turns it
/// left run to the end ([`settled`]).
pub(super) fn deliver(
    journal: &mut Journal,
    edits: &mut Edits,
    changes: &[SignedChange],
) -> super::Applied {
    let applied = journal.receive(changes.to_vec(), edits).0;
    settled(journal, edits, applied)
}

/// `applied`, and what the turns it left came to
/// ([`Journal::settle_step`]), run to the end.
pub(super) fn settled(
    journal: &mut Journal,
    edits: &mut Edits,
    mut applied: super::Applied,
) -> super::Applied {
    while journal.busy() {
        let (turn, _) = journal.settle_step(edits);
        applied.changes.extend(turn.changes);
        applied.taken.extend(turn.taken);
        applied.known.extend(turn.known);
        applied.frozen.extend(turn.frozen);
        applied.forks.extend(turn.forks);
        applied.conflicts.extend(turn.conflicts);
        applied.refused.extend(turn.refused);
        applied.stopped.extend(turn.stopped);
        applied.failed.extend(turn.failed);
        applied.reanalyse |= turn.reanalyse;
        applied.held = journal.holding;
    }
    applied
}

/// `signed` with its body `body` in place of its own, its head committing
/// to it and signed by the key of seed `seed`: what a forger with that
/// key writes.
pub(super) fn forge(signed: &SignedChange, body: &Body, seed: u8) -> SignedChange {
    forge_bytes(signed, postcard::to_stdvec(body).unwrap(), seed)
}

/// `signed` with body bytes `bytes`, its head committing to them, signed
/// by the key of seed `seed`.
pub(super) fn forge_bytes(signed: &SignedChange, bytes: Vec<u8>, seed: u8) -> SignedChange {
    let head = Head {
        body: Body::commitment(&bytes),
        ..signed.head.head
    };
    SignedChange {
        head: SignedHead::sign(head, &Signer::from_seed(&[seed; 32])),
        body: bytes,
    }
}

/// The body of `signed`.
pub(super) fn body(signed: &SignedChange) -> Body {
    Body::decode(&signed.body).unwrap()
}

fn name(text: &str) -> Value {
    Value::Text(Some(text.to_owned()))
}

/// A random op over every kind of key: a few addresses each, so keys
/// collide; items that overlap; numbers at several widths; tombstones.
fn random_op(rng: &mut Rng, me: PublicKey) -> (Key, Value) {
    let address = 0x1000 + rng.below(6) * 4;
    let text = |rng: &mut Rng| {
        if rng.below(6) == 0 {
            Value::Text(None)
        } else {
            Value::Text(Some(format!("v{}", rng.below(1000))))
        }
    };
    match rng.below(12) {
        0 => (Key::FunctionName(address), text(rng)),
        1 => (Key::GlobalName(address), text(rng)),
        2 => (
            Key::VariableName(Variable {
                function: address,
                origins: vec![format!("slot -{}", 8 * rng.below(3))],
                ordinal: 0,
            }),
            text(rng),
        ),
        3 => (
            Key::Slot(address, -8 * i64::try_from(rng.below(3)).unwrap()),
            text(rng),
        ),
        4 => (Key::Comment(address), text(rng)),
        5 => (Key::Bookmark(me, address), text(rng)),
        6 => {
            let value = *rng.pick(&[0xff, 0xffff, 0xffff_ffff, u64::MAX, 0x7f, 0x80, 0x10]);
            let form = rng
                .pick(&[
                    NumberForm::Hex,
                    NumberForm::Decimal,
                    NumberForm::Char,
                    NumberForm::Enum("ACCESS_MASK".to_owned()),
                ])
                .clone();
            let stated = (rng.below(5) != 0).then_some(Stated { value, form });
            (
                Key::Number(address, canonical(value)),
                Value::Number(stated),
            )
        }
        7 => (Key::Type(Typed::Prototype(address)), text(rng)),
        8 => (
            Key::Definition(format!("struct s{}", rng.below(3))),
            text(rng),
        ),
        9 | 10 => {
            let start = 0x2000 + rng.below(24);
            let item = match rng.below(4) {
                0 => None,
                1 => Some(Item::Code),
                2 => Some(Item::Undefined {
                    size: 1 + rng.below(8),
                }),
                _ => Some(Item::Data(Data {
                    unit: *rng.pick(&[Unit::Byte, Unit::Word, Unit::Dword]),
                    count: 1 + rng.below(3),
                })),
            };
            (Key::Item(start), Value::Item(item))
        }
        _ => {
            let bounds = match rng.below(3) {
                0 => None,
                1 => Some(Bounds::Deleted),
                _ => Some(Bounds::Function {
                    end: Some(address + 0x40),
                }),
            };
            (Key::Bounds(address), Value::Bounds(bounds))
        }
    }
}

/// The project file and conflicts an observer (author 1's identity, a
/// chain of its own) has after taking `changes` one by one in that order.
fn observed(changes: &[SignedChange]) -> (String, Vec<super::Conflict>) {
    let (mut journal, mut edits) = author(1);
    for signed in changes {
        deliver(&mut journal, &mut edits, std::slice::from_ref(signed));
    }
    assert_eq!(edits, journal.projection(), "kept in step");
    (edits.to_toml().unwrap(), journal.conflicts())
}

#[test]
#[cfg_attr(debug_assertions, ignore = "10,000 ops, 1,000 orders: release only")]
fn every_delivery_order_gives_one_project_file_and_one_conflict_set() {
    let mut rng = Rng(0x00c0_ffee);
    let mut authors: Vec<(Journal, Edits)> = (1..=3).map(author).collect();
    // Each author's changes in its chain's order, and all as made.
    let mut chains: Vec<Vec<SignedChange>> = vec![Vec::new(); 3];
    let mut all: Vec<SignedChange> = Vec::new();
    let mut ops = 0;
    while ops < 10_000 {
        let at = usize::try_from(rng.below(3)).unwrap();
        let (journal, edits) = &mut authors[at];
        // Now and then, an author hears everything so far: later edits
        // name others' as seen.
        if rng.below(3) == 0 {
            deliver(journal, edits, &all);
        }
        let made = if rng.below(12) == 0
            && let Some(plan) = journal.plan_undo()
        {
            journal.begin(&plan.label, plan.origin);
            for (key, value) in plan.ops {
                journal.write(&key, value, edits);
            }
            match journal.commit(edits).unwrap() {
                committed @ Committed::Sealed(_) => sealed(committed),
                Committed::Empty | Committed::Open => continue,
            }
        } else {
            let me = journal.author();
            let count = 1 + rng.below(20);
            let made: Vec<(Key, Value)> = (0..count).map(|_| random_op(&mut rng, me)).collect();
            ops += made.len();
            change(journal, edits, &made)
        };
        chains[at].extend(made.iter().cloned());
        all.extend(made);
    }
    let (file, conflicts) = observed(&all);
    assert!(!conflicts.is_empty(), "concurrent edits made conflicts");
    // A thousand random orders that keep each chain's own (as pulls do),
    // on four threads: what one change names that is not here yet waits.
    std::thread::scope(|scope| {
        for thread in 0..4 {
            let (chains, file, conflicts) = (&chains, &file, &conflicts);
            scope.spawn(move || {
                let mut rng = Rng(thread);
                for _ in 0..250 {
                    let mut at = [0; 3];
                    let mut order = Vec::new();
                    while order.len() < chains.iter().map(Vec::len).sum() {
                        let pick = usize::try_from(rng.below(3)).unwrap();
                        if let Some(next) = chains[pick].get(at[pick]) {
                            order.push(next.clone());
                            at[pick] += 1;
                        }
                    }
                    let (now, seen) = observed(&order);
                    assert_eq!(&now, file);
                    assert_eq!(&seen, conflicts);
                }
            });
        }
    });
}

#[test]
fn concurrent_renames_are_a_conflict_until_one_is_chosen() {
    let (mut ann, mut ann_edits) = author(1);
    let (mut bob, mut bob_edits) = author(2);
    let key = Key::FunctionName(0x1000);
    let a = change(&mut ann, &mut ann_edits, &[(key.clone(), name("aes_init"))]);
    let b = change(
        &mut bob,
        &mut bob_edits,
        &[(key.clone(), name("key_setup"))],
    );
    deliver(&mut ann, &mut ann_edits, &b);
    deliver(&mut bob, &mut bob_edits, &a);
    for (journal, edits) in [(&ann, &ann_edits), (&bob, &bob_edits)] {
        let conflicts = journal.conflicts();
        assert_eq!(conflicts.len(), 1);
        let conflict = &conflicts[0];
        assert_eq!(conflict.key, key);
        let values: Vec<&Value> = conflict.leaves.iter().map(|leaf| &leaf.value).collect();
        assert_eq!(values.len(), 2);
        assert!(values.contains(&&name("aes_init")) && values.contains(&&name("key_setup")));
        // The later stamp shows, on both.
        let later = conflict
            .leaves
            .iter()
            .max_by_key(|leaf| leaf.stamp)
            .unwrap();
        assert_eq!(conflict.shown, later.op);
        assert_eq!(
            Value::Text(edits.function(0x1000).map(str::to_owned)),
            later.value
        );
    }
    // Ann keeps hers: one op naming both leaves; gone for Bob too.
    let resolved = change(&mut ann, &mut ann_edits, &[(key, name("aes_init"))]);
    let decoded = body(&resolved[0]);
    assert_eq!(decoded.ops.len(), 1);
    assert_eq!(decoded.ops[0].prev.len(), 2);
    deliver(&mut bob, &mut bob_edits, &resolved);
    assert!(ann.conflicts().is_empty() && bob.conflicts().is_empty());
    assert_eq!(bob_edits.function(0x1000), Some("aes_init"));
}

#[test]
fn undo_is_per_author_and_skips_what_another_changed_since() {
    let (mut ann, mut ann_edits) = author(1);
    let (mut bob, mut bob_edits) = author(2);
    let key = Key::FunctionName(0x1000);
    let a = change(&mut ann, &mut ann_edits, &[(key.clone(), name("ann"))]);
    deliver(&mut bob, &mut bob_edits, &a);
    let b = change(&mut bob, &mut bob_edits, &[(key.clone(), name("bob"))]);
    deliver(&mut ann, &mut ann_edits, &b);
    let plan = ann.plan_undo().unwrap();
    assert_eq!(plan.ops, Vec::new());
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].key, key);
    assert_eq!(plan.skipped[0].by, vec![bob.author()]);
    assert_eq!(plan.skipped[0].value, Some(name("bob")));
    // Bob's undo is his own: Ann's name back.
    let plan = bob.plan_undo().unwrap();
    assert_eq!(plan.ops, vec![(key, name("ann"))]);

    // Undoing a correction restores only that key, not a peer's.
    let mine = Key::Item(0x2000);
    let c = change(
        &mut ann,
        &mut ann_edits,
        &[(mine.clone(), Value::Item(Some(Item::Code)))],
    );
    deliver(&mut bob, &mut bob_edits, &c);
    let undefined = Item::Undefined { size: 4 };
    let d = change(
        &mut bob,
        &mut bob_edits,
        &[(Key::Item(0x2010), Value::Item(Some(undefined)))],
    );
    deliver(&mut ann, &mut ann_edits, &d);
    let plan = ann.plan_undo().unwrap();
    assert_eq!(plan.ops, vec![(mine, Value::Item(None))]);
    ann.begin(&plan.label, plan.origin);
    for (key, value) in plan.ops {
        ann.write(&key, value, &mut ann_edits);
    }
    ann.commit(&mut ann_edits).unwrap();
    let corrections = ann_edits.corrections();
    assert_eq!(corrections.items().len(), 1);
    assert_eq!(corrections.item(0x2010), Some(undefined));
}

#[test]
fn a_chain_begins_with_a_start_that_binds_it_and_edits_nothing() {
    let (mut ann, mut ann_edits) = author(1);
    let made = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    // The start, then the first edit at 2.
    assert_eq!(made.len(), 2);
    let (start, first) = (&made[0], &made[1]);
    assert_eq!((start.id().seq, first.id().seq), (1, 2));
    assert_eq!(first.head.head.prev, start.hash());
    let origin = start.head.head.origin.unwrap();
    assert_eq!(origin.author, ann.author());
    assert!(start.body.len() <= MAX_START);
    let opened = body(start);
    assert!(opened.is_start());
    assert_eq!(
        opened.bound,
        Some(Bound {
            share: None,
            of: of(),
        })
    );
    // Not an entry of the history; the next change follows on.
    assert_eq!(ann.history().len(), 1);
    let next = change(&mut ann, &mut ann_edits, &[(Key::Comment(2), name("two"))]);
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].id().seq, 3);

    // A start that is more than a start, or a change past it that binds
    // its chain again, are not taken: the first leaves nothing, the
    // second freezes the chain.
    let (mut bob, mut bob_edits) = author(2);
    let mut more = opened.clone();
    more.ops.push(Op {
        key: Key::Comment(9),
        value: name("smuggled"),
        prev: Vec::new(),
    });
    let applied = deliver(&mut bob, &mut bob_edits, &[forge(start, &more, 1)]);
    assert!(
        matches!(&applied.stopped[..], [stop] if matches!(stop.why, Stopped::Turned(_))),
        "{applied:?}"
    );
    assert!(bob.chains().is_empty() && bob_edits.comment(9).is_none());
    let mut rebinding = body(first);
    rebinding.bound = opened.bound;
    let applied = deliver(
        &mut bob,
        &mut bob_edits,
        &[start.clone(), forge(first, &rebinding, 1)],
    );
    assert_eq!(applied.known, [ann.chain]);
    assert_eq!(applied.frozen, [(ann.chain, 2)]);
    assert!(matches!(
        bob.evidence(ann.chain),
        Some(Evidence::Refused(head)) if head.id() == first.id()
    ));
}

#[test]
fn a_start_bound_to_another_binary_is_turned_away_and_leaves_nothing() {
    let (mut ann, mut ann_edits) = author(1);
    let made = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    // Bob's journal is of another slice of the same file.
    let other = Of::Binary {
        sha256: [7; 32],
        slice: Some("arm64".to_owned()),
    };
    let mut bob = Journal::new(PROJECT, other, Signer::from_seed(&[2; 32])).unwrap();
    let mut bob_edits = Edits::default();
    let applied = deliver(&mut bob, &mut bob_edits, &made);
    assert_eq!(applied.changes, Vec::new());
    assert!(bob.chains().is_empty() && bob.records.is_empty());
    assert!(matches!(applied.stopped[0].why, Stopped::Turned(_)));
    // Its edit, its chain not known: not held, nothing kept.
    assert_eq!(applied.stopped[1].why, Stopped::Unknown);
    assert_eq!(applied.held, 0);
}

#[test]
fn heads_signed_heads_and_proofs_read_back_exactly_and_nothing_else_does() {
    let (mut ann, mut ann_edits) = author(1);
    let made = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    for signed in &made {
        let head = signed.head;
        let bytes = head.bytes();
        assert_eq!(bytes.len(), if head.head.seq == 1 { 216 } else { 152 });
        assert_eq!(SignedHead::parse(&bytes).unwrap(), head);
        assert_eq!(Head::parse(&head.head.bytes()).unwrap(), head.head);
        assert!(SignedHead::parse(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(SignedHead::parse(&longer).is_err());
        assert_eq!(SignedChange::parse(&signed.encode()).unwrap(), *signed);
        assert!(head.verify(ann.author()));
        assert!(!head.verify(PublicKey(Signer::from_seed(&[2; 32]).public().0)));
    }
    // A first head whose origin does not make its chain does not read.
    let mut first = made[0].head.head;
    first.chain = ChainId([0; 16]);
    assert!(Head::parse(&first.bytes()).is_err());

    // Two changes at the same place, and one not naming the one before.
    let (mut fork, mut fork_edits) = (ann.clone(), ann_edits.clone());
    let left = change(&mut ann, &mut ann_edits, &[(Key::Comment(2), name("left"))]);
    let right = change(
        &mut fork,
        &mut fork_edits,
        &[(Key::Comment(2), name("right"))],
    );
    let origin = made[0].head.head.origin.unwrap();
    let same = ForkProof::new(origin, left[0].head, right[0].head).unwrap();
    assert_eq!(same.place(), 3);
    assert!(same.a.hash() < same.b.hash());
    let after = change(
        &mut fork,
        &mut fork_edits,
        &[(Key::Comment(3), name("after"))],
    );
    let next = ForkProof::new(origin, after[0].head, left[0].head).unwrap();
    assert_eq!(
        (next.place(), next.a.id(), next.b.id()),
        (3, left[0].id(), after[0].id())
    );
    for proof in [same, next] {
        let bytes = proof.bytes();
        assert_eq!(bytes.len(), 64 + 152 + 152);
        assert_eq!(ForkProof::parse(&bytes).unwrap(), proof);
        assert!(proof.verify());
        assert!(ForkProof::parse(&bytes[..bytes.len() - 1]).is_err());
    }
    // A pair that is no fork, out of order, or not the author's, is none.
    assert!(ForkProof::new(origin, made[1].head, left[0].head).is_none());
    let swapped = ForkProof {
        a: same.b,
        b: same.a,
        ..same
    };
    assert!(!swapped.verify());
    let stranger = SignedHead::sign(right[0].head.head, &Signer::from_seed(&[9; 32]));
    assert!(ForkProof::new(origin, left[0].head, stranger).is_none());
}

#[test]
fn a_body_reads_within_its_bounds_and_no_further() {
    binbun_bounded::walk::<Body>().unwrap();
    let (mut ann, mut ann_edits) = author(1);
    let made = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    // One op more than a change may hold: refused while reading.
    let mut many = body(&made[1]);
    many.ops = vec![
        Op {
            key: Key::Comment(0),
            value: Value::Text(None),
            prev: Vec::new(),
        };
        MAX_OPS + 1
    ];
    let bytes = postcard::to_stdvec(&many).unwrap();
    assert!(bytes.len() < MAX_BODY);
    assert!(Body::decode(&bytes).is_err());
    many.ops.pop();
    assert_eq!(
        Body::decode(&postcard::to_stdvec(&many).unwrap()).unwrap(),
        many
    );
    assert!(Body::decode(&vec![0; MAX_BODY + 1]).is_err());
    // A change declaring a body past the bound does not read.
    let mut encoded = made[1].head.bytes().to_vec();
    super::change::leb128(&mut encoded, MAX_BODY + 1);
    assert!(SignedChange::take(&encoded).is_err());
    // Taken from elsewhere, a body that does not read within its bounds
    // freezes its author's chain there.
    let (mut bob, mut bob_edits) = author(2);
    let mut over = body(&made[1]);
    over.ops = many.ops.clone();
    over.ops.push(over.ops[0].clone());
    let applied = deliver(
        &mut bob,
        &mut bob_edits,
        &[made[0].clone(), forge(&made[1], &over, 1)],
    );
    assert_eq!(applied.frozen, [(ann.chain, 2)]);
    // A body its head does not commit to is a fault of whoever sealed
    // it: stopped, nothing frozen, the true one taken after.
    let (mut cat, mut cat_edits) = author(3);
    let mut sealed_wrong = made[1].clone();
    sealed_wrong.body[0] ^= 1;
    let applied = deliver(&mut cat, &mut cat_edits, &[made[0].clone(), sealed_wrong]);
    assert_eq!(applied.stopped[0].why, Stopped::Sealing);
    assert!(cat.frozen.is_empty());
    deliver(&mut cat, &mut cat_edits, &made[1..]);
    assert_eq!(cat_edits.comment(1), Some("one"));
}

#[test]
fn an_edit_larger_than_a_change_is_not_made() {
    let (mut ann, mut ann_edits) = author(1);
    let huge = "x".repeat(MAX_BODY);
    ann.begin("edit", Origin::User);
    ann.write(&Key::Comment(1), name(&huge), &mut ann_edits);
    assert!(ann.commit(&mut ann_edits).is_err());
    assert_eq!(ann_edits.comment(1), None);
    assert!(ann.records.is_empty());
}

/// `count` comments of `bytes` bytes each, from address 0, of text `fill`.
fn big(count: u64, bytes: usize, fill: char) -> Vec<(Key, Value)> {
    (0..count)
        .map(|at| (Key::Comment(at), name(&fill.to_string().repeat(bytes))))
        .collect()
}

#[test]
fn a_group_too_large_for_one_change_is_one_undo_step_and_one_entry_everywhere() {
    let (mut ann, mut ann_edits) = author(1);
    let (mut bob, mut bob_edits) = author(2);
    let third = MAX_BODY / 3;
    let first = change(&mut ann, &mut ann_edits, &big(4, third, 'a'));
    let made = change(&mut ann, &mut ann_edits, &big(4, third, 'b'));
    // Split in op order, each part within the bound, one group.
    assert!(made.len() > 1);
    let group = body(&made[0]).group.unwrap();
    assert_eq!(
        group,
        Group {
            first: made[0].id().seq,
            count: u16::try_from(made.len()).unwrap(),
        }
    );
    for part in &made {
        assert!(part.body.len() <= MAX_BODY);
        assert_eq!(body(part).group, Some(group));
    }
    let history = ann.history();
    assert_eq!(history.len(), 2);
    assert_eq!((history[0].id, history[0].edits), (made[0].id(), 4));
    // On a peer: one entry too.
    deliver(&mut bob, &mut bob_edits, &first);
    deliver(&mut bob, &mut bob_edits, &made);
    assert_eq!(bob.history(), {
        let mut seen = ann.history();
        for entry in &mut seen {
            entry.mine = false;
        }
        seen
    });
    // Undone in one step: every part's comments back, the undo itself a
    // group (as large), naming the first part.
    let plan = ann.plan_undo().unwrap();
    assert_eq!(plan.ops.len(), 4);
    ann.begin(&plan.label, plan.origin.clone());
    for (key, value) in &plan.ops {
        ann.write(key, value.clone(), &mut ann_edits);
    }
    let undo = sealed(ann.commit(&mut ann_edits).unwrap());
    assert!(undo.len() > 1);
    let undone = body(&undo[0]);
    assert_eq!(undone.origin, Origin::Undo(made[0].id()));
    assert!(undone.group.is_some());
    for at in 0..4 {
        assert!(ann_edits.comment(at).unwrap().starts_with('a'));
    }
    // And made again in one step.
    let plan = ann.plan_redo().unwrap();
    assert_eq!(plan.origin, Origin::Redo(made[0].id()));
    assert_eq!(plan.ops.len(), 4);
    assert!(
        plan.ops
            .iter()
            .all(|(_, value)| value.text().unwrap().starts_with('b'))
    );
}

#[test]
fn a_part_that_does_not_follow_its_group_is_refused_and_a_group_cut_short_is_its_parts() {
    let (mut ann, mut ann_edits) = author(1);
    let made = change(&mut ann, &mut ann_edits, &big(4, MAX_BODY / 3, 'a'));
    assert!(made.len() > 2);
    // Only the start and the first part: the group is the part there is.
    let (mut bob, mut bob_edits) = author(2);
    deliver(&mut bob, &mut bob_edits, &made[..2]);
    let entry = &bob.history()[0];
    assert_eq!(entry.id, made[1].id());
    assert_eq!(entry.edits, body(&made[1]).ops.len());
    // A second part of another label: refused for good, the first kept.
    let mut stray = body(&made[2]);
    stray.label = "another".to_owned();
    let applied = deliver(&mut bob, &mut bob_edits, &[forge(&made[2], &stray, 1)]);
    assert_eq!(applied.frozen, [(ann.chain, made[2].id().seq)]);
    assert_eq!(bob.history().len(), 1);
    // A part claiming a group it cannot be in (more than 16 parts).
    let (mut cat, mut cat_edits) = author(3);
    let mut wide = body(&made[1]);
    wide.group = Some(Group {
        first: made[1].id().seq,
        count: MAX_PARTS + 1,
    });
    let applied = deliver(
        &mut cat,
        &mut cat_edits,
        &[made[0].clone(), forge(&made[1], &wide, 1)],
    );
    assert_eq!(applied.frozen, [(ann.chain, made[1].id().seq)]);
}

#[test]
fn a_group_past_sixteen_changes_is_not_made() {
    let (mut ann, mut ann_edits) = author(1);
    ann.begin("edit", Origin::User);
    for (key, value) in big(u64::from(MAX_PARTS) + 1, MAX_BODY - 4096, 'z') {
        ann.write(&key, value, &mut ann_edits);
    }
    let error = ann.commit(&mut ann_edits).unwrap_err();
    assert!(error.contains("16"), "{error}");
    assert!(ann.records.is_empty());
}

#[test]
fn a_forged_or_forked_change_is_refused_or_freezes_its_chain_with_its_proof() {
    let (mut ann, mut ann_edits) = author(1);
    let first = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    let second = change(&mut ann, &mut ann_edits, &[(Key::Comment(2), name("two"))]);
    // Signed by another key: refused, listed, nothing frozen.
    let forged = forge(&second[0], &body(&second[0]), 9);
    let (mut bob, mut bob_edits) = author(2);
    let applied = deliver(
        &mut bob,
        &mut bob_edits,
        &[first.clone(), vec![forged]].concat(),
    );
    assert_eq!(applied.changes.len(), 1);
    assert_eq!(applied.refused.len(), 1);
    assert!(applied.refused[0].why.contains("signature"), "{applied:?}");
    assert_eq!(bob_edits.comment(2), None);
    assert!(bob.frozen.is_empty());

    // Two changes at one place in Ann's chain: the chain freezes there,
    // neither shown; the proof kept and told with the tip.
    let (mut fork, mut fork_edits) = (ann.clone(), ann_edits.clone());
    let left = change(&mut ann, &mut ann_edits, &[(Key::Comment(3), name("left"))]);
    let right = change(
        &mut fork,
        &mut fork_edits,
        &[(Key::Comment(3), name("right"))],
    );
    let (mut carl, mut carl_edits) = author(3);
    deliver(&mut carl, &mut carl_edits, &[first, second, left].concat());
    assert_eq!(carl_edits.comment(3), Some("left"));
    let applied = deliver(&mut carl, &mut carl_edits, &right);
    let place = right[0].id().seq;
    assert_eq!(applied.forks.len(), 1);
    assert_eq!(applied.forks[0].place(), place);
    assert_eq!(applied.frozen, [(ann.chain, place)]);
    assert_eq!(carl_edits.comment(3), None);
    assert_eq!(carl_edits.comment(1), Some("one"));
    let tip = carl.tip(ann.chain).unwrap();
    assert_eq!((tip.seq, tip.fork), (place - 1, place));
    // A proof is taken only for a chain known here, and only lowering.
    let proof = applied.forks[0];
    let (mut dan, _) = author(4);
    let taken = dan.take_fork(&proof).unwrap().0;
    assert_eq!(taken, super::ForkTaken::Unknown);
    assert!(dan.evidence.is_empty() && dan.frozen.is_empty());
    let taken = carl.take_fork(&proof).unwrap().0;
    assert_eq!(taken, super::ForkTaken::Held);
}

#[test]
fn two_starts_of_one_chain_tell_the_empty_tip_wherever_either_is_kept() {
    let (ann, _) = author(1);
    let (mut left, mut left_edits) = (ann.clone(), Edits::default());
    let (mut right, mut right_edits) = (ann, Edits::default());
    let a = change(&mut left, &mut left_edits, &[(Key::Comment(1), name("a"))]);
    // Another start of the same chain: another blind, another hash.
    let b = change(
        &mut right,
        &mut right_edits,
        &[(Key::Comment(1), name("b"))],
    );
    assert_ne!(a[0].hash(), b[0].hash());
    let chain = a[0].id().chain;
    let mut tips = Vec::new();
    for (mine, theirs) in [(&a, &b), (&b, &a)] {
        let (mut bob, mut bob_edits) = author(2);
        deliver(&mut bob, &mut bob_edits, mine);
        let applied = deliver(&mut bob, &mut bob_edits, &theirs[..1]);
        assert_eq!(applied.forks[0].place(), 1);
        // The start verified is kept and served; nothing past it is.
        assert_eq!(bob.start(chain).unwrap(), mine[0]);
        assert_eq!(
            bob.changes_after(chain, 0, 10, usize::MAX),
            [mine[0].clone()]
        );
        assert_eq!(bob_edits.comment(1), None);
        tips.push(bob.tip(chain).unwrap());
    }
    assert_eq!(tips[0], tips[1]);
    assert_eq!(
        (tips[0].seq, tips[0].hash, tips[0].fork),
        (0, ChangeHash::ZERO, 1)
    );
}

/// The changes `journal` holds taken: what a hold took out of the keys is
/// the fall of this between its ends (each change below writes one key).
fn held_changes(journal: &Journal) -> usize {
    journal.records.len()
}

#[test]
fn a_fork_proof_against_a_long_chain_marks_it_in_one_bounded_hold() {
    const LONG: u64 = 2500;
    let (mut ann, mut ann_edits) = author(1);
    let first = change(&mut ann, &mut ann_edits, &[(Key::Comment(0), name("zero"))]);
    let mut fork = ann.clone();
    let mut long = first;
    for i in 1..=LONG {
        long.extend(change(
            &mut ann,
            &mut ann_edits,
            &[(Key::Comment(i), name("ann"))],
        ));
    }
    let other = change(
        &mut fork,
        &mut Edits::default(),
        &[(Key::Comment(1), name("fork"))],
    );
    // A proof from a replica that saw both heads at number 3.
    let (mut dan, mut dan_edits) = author(4);
    let proof = deliver(&mut dan, &mut dan_edits, &[&long[..3], &other[..]].concat()).forks[0];
    assert_eq!(proof.place(), 3);
    let (mut carl, mut carl_edits) = author(3);
    deliver(&mut carl, &mut carl_edits, &long);
    let chain = ann.chain;
    let last = Key::Comment(LONG);
    assert_eq!(carl_edits.comment(LONG), Some("ann"));
    // Carl's own edit over Ann's, before the freeze: it names hers.
    let over = Key::Comment(LONG - 1);
    change(&mut carl, &mut carl_edits, &[(over.clone(), name("mine"))]);

    // The proof's hold marks alone: nothing taken out under it.
    let before = held_changes(&carl);
    let (taken, frozen) = carl.take_fork(&proof).unwrap();
    assert_eq!(taken, super::ForkTaken::Lowered(3));
    assert_eq!(
        held_changes(&carl),
        before,
        "no change taken out in the proof's hold"
    );
    carl.settle(frozen, std::collections::BTreeSet::new(), &mut carl_edits);
    // Nothing of the suffix is told or served from the mark on.
    assert_eq!(carl.tip(chain).unwrap().seq, 2);
    assert_eq!(carl.head_at(chain, 3), None);
    assert_eq!(
        carl.changes_after(chain, 2, usize::MAX, usize::MAX),
        Vec::<SignedChange>::new()
    );
    // Undoing it, before Ann's is taken out, restores no frozen value.
    let plan = carl.plan_undo().unwrap();
    assert_eq!(plan.ops, [(over.clone(), Value::none(&over))]);

    // A commit on a key not yet reached names no frozen op, and its undo
    // restores no frozen value.
    let written = change(&mut carl, &mut carl_edits, &[(last.clone(), name("carl"))]);
    let op = &Body::decode(&written.last().unwrap().body).unwrap().ops[0];
    assert!(
        op.prev.iter().all(|prev| prev.change.chain != chain),
        "{:?}",
        op.prev
    );
    let plan = carl.plan_undo().unwrap();
    assert_eq!(plan.ops, [(last.clone(), Value::none(&last))]);

    // The rest in batches, each bounded, until the suffix is gone.
    let mut turns = 0;
    while carl.busy() {
        let before = held_changes(&carl);
        carl.settle_step(&mut carl_edits);
        let out = before - held_changes(&carl);
        assert!(out <= super::remote::WITHDRAW_BATCH, "{out} in one hold");
        turns += 1;
    }
    assert!(turns >= 3, "{turns}");
    assert_eq!(carl.changes_after(chain, 2, usize::MAX, usize::MAX), []);
    // Number 2 wrote comment 0 and stands; from number 3 on, nothing.
    assert_eq!(carl_edits.comment(0), Some("zero"));
    assert_eq!(carl_edits.comment(1), None);
    assert_eq!(carl_edits.comment(LONG - 2), None);
    assert_eq!(carl_edits.comment(LONG - 1), Some("mine"));
    assert_eq!(carl_edits.comment(LONG), Some("carl"));
    let refused = carl
        .refused()
        .iter()
        .filter(|refused| refused.why.starts_with("frozen"))
        .count();
    assert_eq!(refused, super::remote::MAX_REFUSED);
}

#[test]
fn an_undo_planned_before_a_freeze_is_planned_again_at_its_commit() {
    let (mut ann, mut ann_edits) = author(1);
    let key = Key::Comment(1);
    let hers = change(&mut ann, &mut ann_edits, &[(key.clone(), name("ann"))]);
    let (mut carl, mut carl_edits) = author(3);
    deliver(&mut carl, &mut carl_edits, &hers);
    // Carl's edit over Ann's: undoing it would restore hers.
    change(&mut carl, &mut carl_edits, &[(key.clone(), name("carl"))]);
    let plan = carl.plan_undo().unwrap();
    assert_eq!(plan.ops, [(key.clone(), name("ann"))]);
    // In the same instant, before the undo is made, Ann's change is cut.
    let cut = super::FrozenBy::Cut {
        record: 2,
        hash: [2; 32],
    };
    let frozen = carl.freeze_durably(&[(ann.chain, 2, cut)]).unwrap();
    carl.settle(frozen, std::collections::BTreeSet::new(), &mut carl_edits);
    // The plan made as planned: refused, never her withdrawn value signed
    // as Carl's.
    carl.begin_planned(&plan.label, plan.origin.clone(), plan.freezes);
    for (key, value) in &plan.ops {
        carl.write(key, value.clone(), &mut carl_edits);
    }
    assert!(carl.commit(&mut carl_edits).is_err());
    assert_ne!(carl.freezes(), plan.freezes);
    assert_eq!(carl_edits.comment(1), Some("carl"));
    // Planned again: the value before Carl's is none.
    let plan = carl.plan_undo().unwrap();
    assert_eq!(plan.ops, [(key.clone(), Value::none(&key))]);
    carl.begin_planned(&plan.label, plan.origin.clone(), plan.freezes);
    for (key, value) in &plan.ops {
        carl.write(key, value.clone(), &mut carl_edits);
    }
    sealed(carl.commit(&mut carl_edits).unwrap());
    assert_eq!(carl_edits.comment(1), None);
}

#[test]
fn a_cascade_of_held_changes_is_let_go_a_bounded_turn_at_a_time() {
    const LONG: u64 = 600;
    let (mut ann, mut ann_edits) = author(1);
    let x = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("ann"))]);
    let (mut bob, mut bob_edits) = author(2);
    deliver(&mut bob, &mut bob_edits, &x);
    let mut chain = Vec::new();
    for i in 0..LONG {
        chain.extend(change(
            &mut bob,
            &mut bob_edits,
            &[(Key::Comment(1 + i % 2), name("bob"))],
        ));
    }
    // Bob's chain comes first: its first edit waits for Ann's change, each
    // later one for the one before it.
    let (mut carl, mut carl_edits) = author(3);
    let applied = deliver(&mut carl, &mut carl_edits, &chain);
    assert_eq!(applied.held, usize::try_from(LONG).unwrap());
    // Ann's change lets them all go, a turn's worth in its own call.
    let applied = carl.receive(x.clone(), &mut carl_edits).0;
    assert_eq!(applied.taken.len(), x.len() + super::remote::MAX_RELEASED);
    assert!(carl.busy());
    let mut turns = 0;
    while carl.busy() {
        let (turn, _) = carl.settle_step(&mut carl_edits);
        assert!(turn.taken.len() <= super::remote::MAX_RELEASED);
        turns += 1;
    }
    assert!(turns >= 2, "{turns}");
    assert_eq!(carl.holding, 0);
    assert_eq!(
        carl.tip(bob.chain).unwrap().seq,
        u64::try_from(chain.len()).unwrap()
    );
}

#[test]
fn a_page_of_tips_looks_at_no_more_chains_than_its_scan_whatever_it_finds() {
    let (mut ann, mut ann_edits) = author(1);
    for i in 0..40 {
        ann.new_chain().unwrap();
        change(&mut ann, &mut ann_edits, &[(Key::Comment(i), name("x"))]);
    }
    let chains: Vec<ChainId> = ann.chains.keys().copied().collect();
    assert_eq!(chains.len(), 40);
    // Of an origin no chain has: empty, after 16 looked at, `next` set.
    let elsewhere = Some(ProjectId([9; 16]));
    let (tips, next) = ann.tips_page(None, elsewhere, 10, 16);
    assert_eq!((tips.len(), next), (0, Some(chains[15])));
    let (tips, next) = ann.tips_page(Some(chains[31]), elsewhere, 10, 16);
    assert_eq!((tips.len(), next), (0, None));
    // Of every origin: as many as asked, `next` the last returned.
    let (tips, next) = ann.tips_page(None, None, 10, 16);
    assert_eq!(tips.len(), 10);
    assert_eq!(next, Some(chains[9]));
    let (tips, next) = ann.tips_page(Some(chains[29]), Some(PROJECT), 100, 16);
    assert_eq!(tips.len(), 10);
    assert_eq!(next, None);
}

#[test]
fn a_chain_cut_back_to_its_start_keeps_it_and_serves_it() {
    let (mut ann, mut ann_edits) = author(1);
    let made = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("one"))]);
    let (mut bob, mut bob_edits) = author(2);
    deliver(&mut bob, &mut bob_edits, &made);
    let cut = super::FrozenBy::Cut {
        record: 2,
        hash: [3; 32],
    };
    let frozen = bob
        .freeze_and_keep(&[(ann.chain, 1, cut)], &mut bob_edits)
        .unwrap()
        .0;
    settled(&mut bob, &mut bob_edits, frozen);
    assert_eq!(bob_edits.comment(1), None);
    let tip = bob.tip(ann.chain).unwrap();
    assert_eq!((tip.seq, tip.hash, tip.fork), (1, made[0].hash(), 0));
    assert_eq!(bob.start(ann.chain).unwrap(), made[0]);
    assert_eq!(
        bob.changes_after(ann.chain, 0, 10, usize::MAX),
        [made[0].clone()]
    );
    assert_eq!(bob.head_at(ann.chain, 2), None);
}

#[test]
fn changes_after_a_number_come_in_order_within_a_count_and_bytes() {
    let (mut ann, mut ann_edits) = author(1);
    let made: Vec<SignedChange> = (0..10)
        .flat_map(|i| change(&mut ann, &mut ann_edits, &[(Key::Comment(i), name("x"))]))
        .collect();
    let chain = ann.chain;
    assert_eq!(ann.changes_after(chain, 0, usize::MAX, usize::MAX), made);
    assert_eq!(ann.changes_after(chain, 0, 3, usize::MAX), made[..3]);
    // One past the bytes, if it is the first.
    assert_eq!(ann.changes_after(chain, 0, usize::MAX, 1), made[..1]);
    let two = made[0].encode().len() + made[1].encode().len();
    assert_eq!(ann.changes_after(chain, 0, usize::MAX, two), made[..2]);
    // From any number on, within the count; past the tip, none.
    assert_eq!(ann.changes_after(chain, 4, 2, usize::MAX), made[4..6]);
    assert_eq!(ann.changes_after(chain, 11, 2, usize::MAX), []);
    let tips = ann.tips_after(None, 10);
    assert_eq!(tips.len(), 1);
    assert_eq!((tips[0].seq, tips[0].hash), (11, made[10].hash()));
    assert_eq!(ann.tips_after(Some(chain), 10), []);
}

#[test]
fn a_bookmark_is_written_and_taken_only_as_its_authors_own() {
    let (mut ann, mut ann_edits) = author(1);
    let (mut bob, mut bob_edits) = author(2);
    let hers = Key::Bookmark(ann.author(), 0x1000);
    let his = Key::Bookmark(bob.author(), 0x1000);
    // Ann cannot make a change bookmarking for Bob.
    ann.begin("edit", Origin::User);
    ann.write(&his, name("forged"), &mut ann_edits);
    assert!(ann.commit(&mut ann_edits).is_err());
    // Nor sign one Bob takes: her own bookmark's change, its key made
    // his, signed by her, freezes her chain there.
    let honest = change(&mut ann, &mut ann_edits, &[(hers, name("entry"))]);
    let mut theirs = body(&honest[1]);
    theirs.ops[0].key = his;
    let forged = forge(&honest[1], &theirs, 1);
    let applied = deliver(&mut bob, &mut bob_edits, &[honest[0].clone(), forged]);
    assert_eq!(applied.frozen, [(ann.chain, 2)]);
    assert!(
        applied.refused[0].why.contains("another's bookmark"),
        "{applied:?}"
    );
    assert_eq!(bob_edits.bookmark(0x1000), None);
    // Her own: taken, hers (not shown as Bob's).
    let (mut cat, mut cat_edits) = author(3);
    let applied = deliver(&mut cat, &mut cat_edits, &honest);
    assert_eq!((applied.changes.len(), applied.refused), (1, Vec::new()));
    assert_eq!(cat_edits.bookmark(0x1000), None);
    assert_eq!(ann_edits.bookmark(0x1000), Some("entry"));
}

#[test]
fn an_agents_bookmark_is_its_own_everywhere_and_never_undone_by_its_install() {
    let (mut ann, mut ann_edits) = author(1);
    let agent = ann
        .add_agent(Identity::ephemeral().unwrap(), "helper")
        .unwrap();
    ann.begin_as("Bookmark", Origin::Agent, Some(agent));
    let key = Key::Bookmark(ann.writing_as(), 0x1000);
    ann.write(&key, name("agent's"), &mut ann_edits);
    let made = sealed(ann.commit(&mut ann_edits).unwrap());
    assert_eq!(key, Key::Bookmark(agent, 0x1000));
    assert_eq!(made[0].head.head.author(), Some(agent));
    assert_eq!(ann_edits.bookmark(0x1000), None);
    let (mut bob, mut bob_edits) = author(2);
    let applied = deliver(&mut bob, &mut bob_edits, &made);
    assert_eq!((applied.changes.len(), applied.refused), (1, Vec::new()));
    // On the install's undo, but the agent's: skipped.
    let plan = ann.plan_undo().unwrap();
    let skipped: Vec<Key> = plan
        .skipped
        .into_iter()
        .map(|skipped| skipped.key)
        .collect();
    assert_eq!((plan.ops, skipped), (Vec::new(), vec![key]));
}

#[test]
fn the_chains_written_here_are_taken_up_again_after_opening_again() {
    let dir = std::env::temp_dir().join(format!("binbun-chains-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = Project::new(&dir);
    let (me, agent) = (
        Identity::ephemeral().unwrap(),
        Identity::ephemeral().unwrap(),
    );
    let (mut edits, mut journal) = super::open(&project, &me, of()).unwrap();
    let key = journal.add_agent(agent.clone(), "helper").unwrap();
    change(&mut journal, &mut edits, &[(Key::Comment(1), name("one"))]);
    journal.begin_as("edit", Origin::Agent, Some(key));
    journal.write(&Key::Comment(2), name("two"), &mut edits);
    let by_agent = sealed(journal.commit(&mut edits).unwrap());
    journal.save(&edits, &project).unwrap();
    let chains = [journal.chain, by_agent[0].id().chain];
    // Opened again: each chain taken up again, written here.
    let (_, mut again) = super::open(&project, &me, of()).unwrap();
    again.add_agent(agent, "helper").unwrap();
    assert_eq!(again.chain, chains[0]);
    assert_eq!(again.agents[&key].chain, chains[1]);
    assert_eq!(again.mine, chains.into_iter().collect());
    assert_eq!(again.of, of());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn number_forms_stored_before_enumerations_read_as_they_were() {
    // `Value::Number(Some(Stated { value: 0x41, form: Char }))` as a
    // journal written before forms named enumerations stores it: the
    // value's variant, `Some`, the number, the form's place.
    let old = [1, 1, 0x41, 2];
    let read: Value = postcard::from_bytes(&old).unwrap();
    assert_eq!(
        read,
        Value::Number(Some(Stated {
            value: 0x41,
            form: NumberForm::Char,
        }))
    );
    // An enumeration's form comes after them: its place, then its name.
    let named = Value::Number(Some(Stated {
        value: 0x41,
        form: NumberForm::Enum("M".to_owned()),
    }));
    let bytes = postcard::to_stdvec(&named).unwrap();
    assert_eq!(bytes, [1, 1, 0x41, 3, 1, b'M']);
    assert_eq!(postcard::from_bytes::<Value>(&bytes).unwrap(), named);
}

#[test]
fn changes_held_are_bounded_and_those_past_the_bound_come_again() {
    let held = super::remote::MAX_HELD;
    let (mut ann, mut ann_edits) = author(1);
    let (mut bob, mut bob_edits) = author(2);
    let key = Key::Comment(1);
    let hers = change(&mut ann, &mut ann_edits, &[(key.clone(), name("ann"))]);
    deliver(&mut bob, &mut bob_edits, &hers);
    // Bob's changes name Ann's (seen): the first waits for it, the rest
    // for the one before them.
    let mut his: Vec<SignedChange> = Vec::new();
    for at in 0..held + 3 {
        his.extend(change(
            &mut bob,
            &mut bob_edits,
            &[(key.clone(), name(&at.to_string()))],
        ));
    }
    let (mut carl, mut carl_edits) = author(3);
    deliver(&mut carl, &mut carl_edits, &hers[..1]);
    let applied = deliver(&mut carl, &mut carl_edits, &his);
    assert_eq!(applied.held, held);
    // Past the bound: the first not kept, those after it out of order.
    let full: Vec<_> = applied
        .stopped
        .iter()
        .filter(|stop| !matches!(stop.why, Stopped::Held(_)))
        .map(|stop| stop.id)
        .collect();
    assert_eq!(full.len(), 3);
    assert!(matches!(
        applied
            .stopped
            .iter()
            .find(|stop| stop.id == full[0])
            .unwrap()
            .why,
        Stopped::Full(_)
    ));
    // Ann's lets go those held; those past the bound come again.
    deliver(&mut carl, &mut carl_edits, &hers[1..]);
    let again: Vec<SignedChange> = his
        .iter()
        .filter(|signed| full.contains(&signed.id()))
        .cloned()
        .collect();
    deliver(&mut carl, &mut carl_edits, &again);
    assert_eq!(carl.tip(bob.chain).unwrap().seq, (held + 4) as u64);
}

#[test]
fn only_the_latest_refusals_are_listed() {
    let (mut ann, mut ann_edits) = author(1);
    let made = change(&mut ann, &mut ann_edits, &[(Key::Comment(1), name("x"))]);
    let forged = forge(&made[1], &body(&made[1]), 9);
    let (mut eve, mut eve_edits) = author(5);
    deliver(&mut eve, &mut eve_edits, &made[..1]);
    let most = super::remote::MAX_REFUSED;
    let applied = deliver(&mut eve, &mut eve_edits, &vec![forged; most + 5]);
    assert_eq!(applied.refused.len(), most + 5);
    assert_eq!(eve.refused().len(), most);
}

#[test]
fn a_start_naming_another_than_its_chains_author_does_not_take_the_chain() {
    let (mut ann, mut ann_edits) = author(1);
    let made = change(
        &mut ann,
        &mut ann_edits,
        &[(Key::Comment(1), name("ann's"))],
    );
    // Dan signs a start of Ann's chain naming himself.
    let mut head = made[0].head.head;
    let mut origin = head.origin.unwrap();
    origin.author = Signer::from_seed(&[4; 32]).public();
    head.origin = Some(origin);
    let claimed = SignedChange {
        head: SignedHead::sign(head, &Signer::from_seed(&[4; 32])),
        body: made[0].body.clone(),
    };
    let (mut bob, mut bob_edits) = author(2);
    let applied = deliver(&mut bob, &mut bob_edits, &[claimed]);
    assert_eq!((applied.known.len(), applied.refused.len()), (0, 1));
    // Ann's, coming after, is hers.
    let applied = deliver(&mut bob, &mut bob_edits, &made);
    assert_eq!(applied.changes.len(), 1);
    assert_eq!(applied.changes[0].author, ann.author());
    assert_eq!(bob_edits.comment(1), Some("ann's"));
}
