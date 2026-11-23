#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The solver on hand-written constraint sets.

use std::collections::BTreeSet;

use binbun_typeinfer::{
    Atom, Budget, Code, ConstraintId, Evidence, Field, Label, Level, Refusal, Side, Solution,
    Strength, System, Term, Var,
};

fn ev(tag: u32, strength: u8) -> Evidence {
    Evidence {
        tag,
        strength: Strength(strength),
    }
}

const WEAK: u8 = 2;
const OPERATION: u8 = 3;
const ACCESS: u8 = 4;
const DECLARED: u8 = 6;

fn field(offset: i64, bits: u16) -> Field {
    Field { offset, bits }
}

fn var(sys: &mut System, a: Var, b: Var, tag: u32) -> ConstraintId {
    sys.constrain(Term::Var(a), Term::Var(b), ev(tag, 0))
}

fn below(sys: &mut System, atom: Atom, v: Var, evidence: Evidence) -> ConstraintId {
    sys.constrain(Term::Atom(atom), Term::Var(v), evidence)
}

fn above(sys: &mut System, v: Var, atom: Atom, evidence: Evidence) -> ConstraintId {
    sys.constrain(Term::Var(v), Term::Atom(atom), evidence)
}

fn solve(sys: System) -> Solution {
    sys.solve(Budget::default()).unwrap()
}

/// A variable whose every value is one enumeration's keeps it: two values
/// of `status` into `kept`, through a copy and round a cycle, with demands
/// of its integer (no conflict: an enumeration is below its integer).
/// Values of `status` and `other`, of `status` and an unsigned integer,
/// or of `status` and an arithmetic result (nothing stated, nothing
/// flowing in) make the integer; a signed demand of an unsigned
/// enumeration conflicts as its integer would.
#[test]
fn a_variable_keeps_an_enumeration_only_where_every_value_is_one() {
    let status = Atom::Enum {
        id: 1,
        width: 32,
        signed: false,
    };
    let other = Atom::Enum {
        id: 2,
        width: 32,
        signed: false,
    };
    let signed = Atom::Enum {
        id: 3,
        width: 32,
        signed: true,
    };
    assert_eq!(status.join(other), Level::Atom(Atom::Unsigned(32)));
    assert_eq!(status.join(signed), Level::Atom(Atom::Int(32)));
    assert_eq!(status.meet(Atom::Unsigned(32)), Level::Atom(status));
    assert_eq!(status.meet(other), Level::Bottom);

    let mut sys = System::new();
    let [a, b, c, product, kept, copy, cycle, two, mixed, typed] = [(); 10].map(|()| sys.var());
    let unsigned = sys.var();
    below(&mut sys, status, a, ev(1, DECLARED));
    below(&mut sys, status, b, ev(2, DECLARED));
    below(&mut sys, other, c, ev(3, DECLARED));
    below(&mut sys, Atom::Unsigned(32), unsigned, ev(4, OPERATION));
    var(&mut sys, a, kept, 5);
    var(&mut sys, b, kept, 6);
    var(&mut sys, kept, copy, 7);
    var(&mut sys, kept, cycle, 8);
    var(&mut sys, cycle, kept, 9);
    above(&mut sys, copy, Atom::Unsigned(32), ev(10, OPERATION));
    above(&mut sys, kept, Atom::Int(32), ev(11, WEAK));
    var(&mut sys, a, two, 12);
    var(&mut sys, c, two, 13);
    var(&mut sys, a, mixed, 14);
    var(&mut sys, product, mixed, 15);
    var(&mut sys, b, typed, 16);
    var(&mut sys, unsigned, typed, 17);
    let demand = above(&mut sys, b, Atom::Signed(32), ev(18, OPERATION));
    let solution = solve(sys);

    for v in [kept, copy, cycle] {
        assert_eq!(solution.answer(v).lower_atom, Level::Atom(status), "{v:?}");
        assert_eq!(solution.enumeration(v), Some(status), "{v:?}");
    }
    assert_eq!(
        solution.answer(copy).upper_atom,
        Level::Atom(Atom::Unsigned(32))
    );
    for v in [two, mixed, typed] {
        assert_eq!(
            solution.answer(v).lower_atom,
            Level::Atom(Atom::Unsigned(32)),
            "{v:?}"
        );
        assert_eq!(solution.enumeration(v), None, "{v:?}");
    }
    let conflicts: Vec<_> = solution
        .conflicts()
        .iter()
        .map(|conflict| solution.origin(conflict.upper.term))
        .collect();
    assert_eq!(conflicts, [Some(demand)]);
}

/// The fields of what loads through `root` give (the store side also
/// carries the demands of every pointer `root` flows into: contravariance).
fn fields(solution: &Solution, root: Var) -> BTreeSet<Field> {
    let graph = solution.graph(&[root]);
    let loads: BTreeSet<usize> = graph
        .edges
        .iter()
        .filter(|e| e.from == 0 && e.label == Label::Load)
        .map(|e| e.to)
        .collect();
    graph
        .edges
        .iter()
        .filter(|e| loads.contains(&e.from))
        .filter_map(|edge| match edge.label {
            Label::Field(f) => Some(f),
            Label::Store | Label::Load | Label::Param(_) | Label::Result(_) => None,
        })
        .collect()
}

/// Figures 5 and 7 of Smith (SAS 2024): walking a linked list. The loaded `next`
/// field is the list itself (a cycle through variables); decomposition
/// terminates, and the value stored at field 0 is what loads from it see.
#[test]
fn linked_list() {
    let mut sys = System::new();
    let [x, y, slot1, slot2, t1, t2, t3] = [(); 7].map(|()| sys.var());
    var(&mut sys, x, slot1, 1);
    var(&mut sys, y, slot2, 2);
    var(&mut sys, slot1, slot2, 3);
    let next = sys.load(slot2, field(4, 32), t1, ev(4, ACCESS));
    var(&mut sys, t1, slot1, 5);
    sys.load(slot2, field(0, 32), t2, ev(6, ACCESS));
    above(&mut sys, t2, Atom::Int(32), ev(7, OPERATION));
    let int = below(&mut sys, Atom::Int(32), t3, ev(7, OPERATION));
    sys.store(slot2, field(0, 32), t3, ev(8, ACCESS));
    let solution = solve(sys);

    assert_eq!(solution.conflicts(), []);
    assert_eq!(solution.answer(t2).lower_atom, Level::Atom(Atom::Int(32)));

    // x's type: load → {(4, 32): t1}, and t1 loads through the same
    // pointer views again: a cycle.
    let graph = solution.graph(&[x]);
    let node = |v: Var| graph.nodes.iter().position(|n| n.var == v).unwrap();
    let (list, element) = (node(next.load()), node(t1));
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.from == 0 && e.label == Label::Load && e.to == list)
    );
    assert!(
        graph.edges.iter().any(|e| {
            e.from == list && e.label == Label::Field(field(4, 32)) && e.to == element
        })
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.from == element && e.label == Label::Load && e.to == list)
    );
    assert!(graph.nodes[element].pointer);
    assert_eq!(
        fields(&solution, x),
        BTreeSet::from([field(0, 32), field(4, 32)])
    );

    // Why t2 is an integer: the atom's constraint is among the reasons.
    let answer = solution.answer(t2);
    let bound = answer
        .lower
        .iter()
        .find(|b| b.atom == Some(Atom::Int(32)))
        .unwrap();
    assert!(solution.explain(t2, bound).contains(&int));
}

/// `f(NULL, 0)`: one zero passed as a pointer and as an integer. Upper
/// bounds meet without conflict, and each parameter keeps its own type
/// (unification would give both `⊤`).
#[test]
fn null_and_zero() {
    let mut sys = System::new();
    let [zero, p1, p2, store, load] = [(); 5].map(|()| sys.var());
    var(&mut sys, zero, p1, 1);
    var(&mut sys, zero, p2, 2);
    let pointer = sys.pointer(store, load, ev(3, DECLARED));
    sys.constrain(Term::Var(p1), Term::Pointer(pointer), ev(3, DECLARED));
    above(&mut sys, p2, Atom::Signed(32), ev(4, DECLARED));
    let solution = solve(sys);

    assert_eq!(solution.conflicts(), []);
    let first = solution.answer(p1);
    assert!(first.pointer);
    assert_eq!(first.upper_atom, Level::Top);
    let second = solution.answer(p2);
    assert!(!second.pointer);
    assert_eq!(second.upper_atom, Level::Atom(Atom::Signed(32)));
    let zero = solution.answer(zero);
    assert!(zero.pointer);
    assert_eq!(zero.upper_atom, Level::Atom(Atom::Signed(32)));
}

/// `q = p; *q = v; w = *p`: a load through the original sees what was
/// stored through the copy (S-Pointer across pointer views).
#[test]
fn store_through_copy() {
    let mut sys = System::new();
    let [p, q, v, w] = [(); 4].map(|()| sys.var());
    let copy = var(&mut sys, p, q, 1);
    sys.store(q, field(0, 32), v, ev(2, ACCESS));
    sys.load(p, field(0, 32), w, ev(3, ACCESS));
    let unsigned = below(&mut sys, Atom::Unsigned(32), v, ev(4, OPERATION));
    above(&mut sys, w, Atom::Int(32), ev(5, OPERATION));
    let solution = solve(sys);

    assert_eq!(solution.conflicts(), []);
    let answer = solution.answer(w);
    assert_eq!(answer.lower_atom, Level::Atom(Atom::Unsigned(32)));
    let why = solution.explain(w, &answer.lower[0]);
    assert!(why.contains(&copy) && why.contains(&unsigned));
    // The use of the loaded value is a demand on the stored one.
    assert_eq!(solution.answer(v).upper_atom, Level::Atom(Atom::Int(32)));
}

/// A signed value into an unsigned use: one conflict, both sides'
/// evidence, the stronger kept per variable; ties keep the lower bound.
#[test]
fn conflict() {
    let cases = [
        (OPERATION, WEAK, Side::Upper),
        (WEAK, OPERATION, Side::Lower),
        (OPERATION, OPERATION, Side::Upper),
    ];
    for (lower_strength, upper_strength, loser) in cases {
        let mut sys = System::new();
        let [a, b] = [(); 2].map(|()| sys.var());
        let signed = below(&mut sys, Atom::Signed(32), a, ev(10, lower_strength));
        var(&mut sys, a, b, 11);
        let unsigned = above(&mut sys, b, Atom::Unsigned(32), ev(12, upper_strength));
        let solution = solve(sys);

        let [conflict] = solution.conflicts() else {
            panic!("{:?}", solution.conflicts())
        };
        assert_eq!(conflict.lower.atom, Some(Atom::Signed(32)));
        assert_eq!(conflict.lower.evidence, ev(10, lower_strength));
        assert_eq!(conflict.upper.atom, Some(Atom::Unsigned(32)));
        assert_eq!(conflict.upper.evidence, ev(12, upper_strength));
        assert_eq!(conflict.loser, loser);
        let why = solution.explain_conflict(conflict);
        assert!(why.contains(&signed) && why.contains(&unsigned));

        for v in [a, b] {
            let answer = solution.answer(v);
            assert_eq!(answer.lost.len(), 1);
            assert_eq!(answer.lost[0].side, loser);
            let (lower, upper) = match loser {
                Side::Upper => (Level::Atom(Atom::Signed(32)), Level::Top),
                Side::Lower => (Level::Bottom, Level::Atom(Atom::Unsigned(32))),
            };
            assert_eq!((answer.lower_atom, answer.upper_atom), (lower, upper));
        }
    }
}

/// An atom against a constructor is a recorded conflict, not a panic.
#[test]
fn pointer_against_integer() {
    let mut sys = System::new();
    let [x, local] = [(); 2].map(|()| sys.var());
    let address = sys.pointer(local, local, ev(1, ACCESS));
    sys.constrain(Term::Pointer(address), Term::Var(x), ev(1, ACCESS));
    above(&mut sys, x, Atom::Signed(64), ev(2, OPERATION));
    let solution = solve(sys);

    assert_eq!(solution.conflicts().len(), 1);
    let answer = solution.answer(x);
    assert!(answer.pointer);
    assert_eq!(answer.upper_atom, Level::Top);
    assert_eq!(answer.lost[0].atom, Some(Atom::Signed(64)));
}

/// Width subtyping: a pointer used at fields 0 and 8 is passed to a
/// callee reading field 0 only. The caller's type has both fields, the
/// callee's only its own.
#[test]
fn record_width() {
    let mut sys = System::new();
    let [p, argument, f0, f8, g0, stored] = [(); 6].map(|()| sys.var());
    sys.load(p, field(0, 64), f0, ev(1, ACCESS));
    sys.load(p, field(8, 64), f8, ev(2, ACCESS));
    sys.store(p, field(0, 64), stored, ev(6, ACCESS));
    var(&mut sys, p, argument, 3);
    sys.load(argument, field(0, 64), g0, ev(4, ACCESS));
    above(&mut sys, g0, Atom::Signed(64), ev(5, OPERATION));
    let solution = solve(sys);

    assert_eq!(solution.conflicts(), []);
    assert_eq!(
        fields(&solution, p),
        BTreeSet::from([field(0, 64), field(8, 64)])
    );
    assert_eq!(fields(&solution, argument), BTreeSet::from([field(0, 64)]));
    // The callee's demand on field 0 reaches what the caller stored there,
    // not what the caller loaded (a sibling: neither is below the other).
    assert_eq!(
        solution.answer(stored).upper_atom,
        Level::Atom(Atom::Signed(64))
    );
    assert_eq!(solution.answer(f0).upper_atom, Level::Top);
}

/// A call through a code pointer: arguments flow into the callee's
/// parameters (contravariance), its results out to the call's.
#[test]
fn code_variance() {
    let mut sys = System::new();
    let [parameter, result, target, argument, value] = [(); 5].map(|()| sys.var());
    let function = Code::new([(0, parameter)], [(0, result)]);
    sys.constrain(Term::Code(function), Term::Var(target), ev(1, ACCESS));
    let call = Code::new([(0, argument)], [(0, value)]);
    sys.constrain(Term::Var(target), Term::Code(call), ev(2, ACCESS));
    below(&mut sys, Atom::Signed(32), argument, ev(3, OPERATION));
    below(&mut sys, Atom::Bool(32), parameter, ev(4, OPERATION));
    above(&mut sys, parameter, Atom::Int(32), ev(5, OPERATION));
    below(&mut sys, Atom::Unsigned(64), result, ev(6, OPERATION));
    let solution = solve(sys);

    assert_eq!(solution.conflicts(), []);
    let parameter = solution.answer(parameter);
    assert_eq!(parameter.lower_atom, Level::Atom(Atom::Int(32)));
    let argument = solution.answer(argument);
    assert_eq!(argument.lower_atom, Level::Atom(Atom::Signed(32)));
    assert_eq!(argument.upper_atom, Level::Atom(Atom::Int(32)));
    assert_eq!(
        solution.answer(value).lower_atom,
        Level::Atom(Atom::Unsigned(64))
    );
    assert_eq!(solution.answer(result).upper_atom, Level::Top);
    let graph = solution.graph(&[target]);
    assert!(graph.edges.iter().any(|e| e.label == Label::Param(0)));
    assert!(graph.edges.iter().any(|e| e.label == Label::Result(0)));
}

/// Past the budget, a refusal and no solution.
#[test]
fn budget() {
    let mut sys = System::new();
    let vars: Vec<Var> = (0..1000).map(|_| sys.var()).collect();
    for pair in vars.windows(2) {
        var(&mut sys, pair[0], pair[1], 0);
    }
    below(&mut sys, Atom::Signed(32), vars[0], ev(1, OPERATION));
    assert_eq!(
        sys.solve(Budget { steps: 100 }).unwrap_err(),
        Refusal::TooLarge { steps: 100 }
    );
}

/// Benchmark-sized sets: a 100,000-constraint chain closed into a cycle,
/// a fan-in and a fan-out of 50,000, linked lists of 10,000 nodes; solved
/// in a number of steps linear in the constraints.
#[test]
fn large() {
    let mut sys = System::new();
    let chain: Vec<Var> = (0..100_000).map(|_| sys.var()).collect();
    for pair in chain.windows(2) {
        var(&mut sys, pair[0], pair[1], 0);
    }
    var(&mut sys, chain[chain.len() - 1], chain[0], 0);
    below(&mut sys, Atom::Signed(32), chain[500], ev(1, OPERATION));
    above(&mut sys, chain[70_000], Atom::Int(32), ev(2, OPERATION));

    let hub = sys.var();
    above(&mut sys, hub, Atom::Int(32), ev(3, OPERATION));
    let out = sys.var();
    below(&mut sys, Atom::Unsigned(32), out, ev(4, OPERATION));
    for _ in 0..50_000 {
        let v = sys.var();
        below(&mut sys, Atom::Unsigned(32), v, ev(5, OPERATION));
        var(&mut sys, v, hub, 0);
        let w = sys.var();
        var(&mut sys, out, w, 0);
    }

    let mut list = sys.var();
    let head = list;
    for _ in 0..10_000 {
        let next = sys.var();
        sys.load(list, field(8, 64), next, ev(6, ACCESS));
        let value = sys.var();
        sys.store(list, field(0, 64), value, ev(7, ACCESS));
        below(&mut sys, Atom::Signed(64), value, ev(8, OPERATION));
        list = next;
    }
    var(&mut sys, list, head, 0);

    let constraints = sys.constraints().len();
    let solution = solve(sys);
    assert_eq!(solution.conflicts(), []);
    assert!(
        solution.steps() < 12 * constraints,
        "{} steps for {constraints} constraints",
        solution.steps()
    );
    let first = solution.answer(chain[0]);
    assert_eq!(first.lower_atom, Level::Atom(Atom::Signed(32)));
    assert_eq!(first.upper_atom, Level::Atom(Atom::Int(32)));
    assert_eq!(
        solution.answer(hub).lower_atom,
        Level::Atom(Atom::Unsigned(32))
    );
    assert!(solution.answer(head).pointer);
}
