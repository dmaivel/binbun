#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Schemes: a callee's solved type over its interface, instantiated
//! fresh at each call.

use binbun_typeinfer::{
    Atom, Budget, Evidence, Field, Format, Level, Record, Scheme, Solution, Strength, System, Term,
    Var,
};

fn ev(tag: u32, strength: u8) -> Evidence {
    Evidence {
        tag,
        strength: Strength(strength),
    }
}

const ACCESS: u8 = 4;
const OPERATION: u8 = 3;

const WORD: Field = Field {
    offset: 0,
    bits: 64,
};

fn solve(sys: System) -> Solution {
    sys.solve(Budget::default()).unwrap()
}

/// `memcpy`-like: `*dst = *src` (one 64-bit word); roots `[dst, src]`.
fn copy_scheme() -> Scheme {
    let mut sys = System::new();
    let (dst, src, value) = (sys.var(), sys.var(), sys.var());
    sys.load(src, WORD, value, ev(0, ACCESS));
    sys.store(dst, WORD, value, ev(1, ACCESS));
    Scheme::new(&solve(sys), &[dst, src])
}

/// A pointer whose loads give `atom` (a lower bound on `var`).
fn points_to(sys: &mut System, var: Var, atom: Atom) {
    let (store, load, value) = (sys.var(), sys.var(), sys.var());
    let pointer = sys.pointer(store, load, ev(9, ACCESS));
    sys.constrain(Term::Pointer(pointer), Term::Var(var), ev(9, ACCESS));
    sys.constrain(
        Term::Record(Record::field(WORD, value)),
        Term::Var(load),
        ev(9, ACCESS),
    );
    sys.constrain(Term::Atom(atom), Term::Var(value), ev(9, OPERATION));
}

/// A fresh destination pointer `var` (its own store and load).
fn fresh_pointer(sys: &mut System) -> (Var, Var) {
    let (var, store, load) = (sys.var(), sys.var(), sys.var());
    let pointer = sys.pointer(store, load, ev(8, ACCESS));
    sys.constrain(Term::Pointer(pointer), Term::Var(var), ev(8, ACCESS));
    (var, load)
}

/// The join of the lower atoms of the fields loads of `load` give.
fn loaded(solution: &Solution, load: Var) -> Level {
    solution
        .answer(load)
        .fields
        .iter()
        .map(|&(_, v)| solution.answer(v).lower_atom)
        .fold(Level::Bottom, Level::join)
}

/// Each call's copy: the destination of a call with a `double` source
/// holds doubles, that of a call with an integer source integers; no
/// unification through the callee (a monomorphic callee would give both
/// `bits`).
#[test]
fn two_calls_of_a_copy_stay_unrelated() {
    let scheme = copy_scheme();
    let mut sys = System::new();
    let double = Atom::Float(Format::Double);
    let int = Atom::Signed(64);
    let mut calls = Vec::new();
    for atom in [double, int] {
        let source = sys.var();
        points_to(&mut sys, source, atom);
        let (destination, load) = fresh_pointer(&mut sys);
        let roots = scheme.instantiate(&mut sys, |e| e);
        sys.constrain(Term::Var(destination), Term::Var(roots[0]), ev(7, 0));
        sys.constrain(Term::Var(source), Term::Var(roots[1]), ev(7, 0));
        calls.push(load);
    }
    let solution = solve(sys);
    assert_eq!(loaded(&solution, calls[0]), Level::Atom(double));
    assert_eq!(loaded(&solution, calls[1]), Level::Atom(int));
}

/// `f(q) { g(q); }` with `g` loading through its parameter: `q` is a
/// pointer through `g`'s scheme, and `f`'s own scheme says so to its
/// callers.
#[test]
fn a_wrapper_parameter_is_a_pointer_through_the_callee() {
    let mut g = System::new();
    let (p, value) = (g.var(), g.var());
    g.load(p, WORD, value, ev(0, ACCESS));
    let g = Scheme::new(&solve(g), &[p]);

    let mut f = System::new();
    let q = f.var();
    let roots = g.instantiate(&mut f, |e| e);
    f.constrain(Term::Var(q), Term::Var(roots[0]), ev(1, 0));
    let solved = solve(f);
    assert!(solved.answer(q).pointer);

    let f = Scheme::new(&solved, &[q]);
    let mut caller = System::new();
    let argument = caller.var();
    let roots = f.instantiate(&mut caller, |e| e);
    caller.constrain(Term::Var(argument), Term::Var(roots[0]), ev(2, 0));
    assert!(solve(caller).answer(argument).pointer);
}

/// A list walk `n = n->next` (next at offset 8): through the scheme, the
/// argument's type is still a cycle (a node's next is a node).
#[test]
fn a_recursive_type_survives_a_scheme() {
    let mut walk = System::new();
    let (node, next) = (walk.var(), walk.var());
    walk.load(
        node,
        Field {
            offset: 8,
            bits: 64,
        },
        next,
        ev(0, ACCESS),
    );
    walk.constrain(Term::Var(next), Term::Var(node), ev(1, 0));
    let scheme = Scheme::new(&solve(walk), &[node]);
    assert!(scheme.var_count() <= 4, "{scheme:?}");

    let mut caller = System::new();
    let list = caller.var();
    let roots = scheme.instantiate(&mut caller, |e| e);
    caller.constrain(Term::Var(list), Term::Var(roots[0]), ev(2, 0));
    let graph = solve(caller).graph(&[list]);
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.to <= edge.from && edge.from > 0),
        "{graph:?}"
    );
}

/// The same solution gives the same scheme, and its instances state the
/// same constraints; two calls of one callee on one parameter make no
/// bigger a scheme than one (the copies are merged).
#[test]
fn schemes_are_deterministic_and_merge_equal_instances() {
    assert_eq!(copy_scheme(), copy_scheme());
    let scheme = copy_scheme();
    let instance = || {
        let mut sys = System::new();
        let roots = scheme.instantiate(&mut sys, |e| e);
        (roots, sys.constraints().to_vec())
    };
    assert_eq!(instance(), instance());

    let wrapper = |calls: usize| {
        let mut sys = System::new();
        let (dst, src) = (sys.var(), sys.var());
        for _ in 0..calls {
            let roots = scheme.instantiate(&mut sys, |e| e);
            sys.constrain(Term::Var(dst), Term::Var(roots[0]), ev(1, 0));
            sys.constrain(Term::Var(src), Term::Var(roots[1]), ev(1, 0));
        }
        Scheme::new(&solve(sys), &[dst, src])
    };
    let (once, twice) = (wrapper(1), wrapper(2));
    assert_eq!(once.var_count(), twice.var_count());
    assert_eq!(once.constraint_count(), twice.constraint_count());
}

/// A callee returning a value of an enumeration (its id the callee's
/// system's) returns its integer to a caller: the id means nothing in the
/// caller's system.
#[test]
fn a_scheme_gives_an_enumerations_integer() {
    let status = Atom::Enum {
        id: 7,
        width: 32,
        signed: false,
    };
    let mut returning = System::new();
    let result = returning.var();
    returning.constrain(Term::Atom(status), Term::Var(result), ev(0, OPERATION));
    let solved = solve(returning);
    assert_eq!(solved.answer(result).lower_atom, Level::Atom(status));
    let scheme = Scheme::new(&solved, &[result]);

    let mut caller = System::new();
    let kept = caller.var();
    let roots = scheme.instantiate(&mut caller, |e| e);
    caller.constrain(Term::Var(roots[0]), Term::Var(kept), ev(1, 0));
    assert_eq!(
        solve(caller).answer(kept).lower_atom,
        Level::Atom(Atom::Unsigned(32))
    );
}
