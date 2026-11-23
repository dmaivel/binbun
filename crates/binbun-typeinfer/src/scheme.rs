//! Schemes: a solved type summarised over some of its variables (a
//! function's interface), and fresh instances of it in another system
//! (SimpleSub's generalisation and `freshenAbove`).
//!
//! [`Scheme::new`] keeps, of a [`Solution`]:
//!
//! - the variables the roots' constructors reach: the store and load
//!   parameters, fields, code parameters and results of their bounds,
//!   transitively (a recursive type is a cycle among them);
//! - each kept variable's bounds that stand in its
//!   [`Answer`](crate::Answer) (a bound that lost a conflict is left out:
//!   the scheme is the solved type), with their evidence; an enumeration
//!   as its integer ([`Atom::integer`]: its id names it only in its own
//!   system);
//! - the edges between kept variables, through chains of variables not
//!   kept (`α ≤ x ≤ β` is `α ≤ β`); an edge's evidence is the weakest
//!   (`Evidence::default()`): bounds carry their own.
//!
//! Then it is simplified by partition refinement: kept variables no
//! observation tells apart (the same bounds over the same classes, the
//! same edges to the same classes) are one variable; roots are never
//! merged with other variables. The result is deterministic (variables
//! numbered in the order found from the roots) and bounded: the bounds of
//! at most [`Scheme::LIMIT`] variables are kept (those found past it stay
//! free: nothing known), and collapsing chains takes at most
//! [`Scheme::STEPS`] steps (past them, the remaining edges are left out).
//!
//! [`Scheme::instantiate`] copies it into a system with fresh variables,
//! each constraint's evidence mapped by the caller, and gives the roots'
//! instances. Instances share no variable, so two instances relate only
//! through what the caller states (two calls of one callee are not unified
//! through it).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use crate::atom::Atom;
use crate::solution::Solution;
use crate::term::{Code, Evidence, Field, Pointer, Record, Side, Strength, System, Term, Var};

/// A term of a scheme, over its variables (by index).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Shape {
    Top,
    Bottom,
    Atom(Atom),
    Pointer(u32, u32),
    Record(Vec<(Field, u32)>),
    Code(Vec<(u32, u32)>, Vec<(u32, u32)>),
}

impl Shape {
    /// The shape with every variable mapped by `map`.
    fn map(&self, map: impl Fn(u32) -> u32) -> Self {
        match self {
            Self::Top => Self::Top,
            Self::Bottom => Self::Bottom,
            Self::Atom(atom) => Self::Atom(*atom),
            Self::Pointer(store, load) => Self::Pointer(map(*store), map(*load)),
            Self::Record(fields) => {
                Self::Record(fields.iter().map(|&(f, v)| (f, map(v))).collect())
            }
            Self::Code(params, results) => Self::Code(
                params.iter().map(|&(p, v)| (p, map(v))).collect(),
                results.iter().map(|&(r, v)| (r, map(v))).collect(),
            ),
        }
    }
}

/// A bound of a scheme: a variable, a side, a term, its evidence.
type SchemeBound = (u32, Side, Shape, Evidence);

/// A solved type over some root variables, to instantiate elsewhere (the
/// [module](self) says what it keeps).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Scheme {
    /// How many variables it has.
    vars: u32,
    /// The roots' variables, in the order given.
    roots: Vec<u32>,
    /// The bounds, ordered.
    bounds: Vec<SchemeBound>,
    /// The edges `lhs ≤ rhs`, ordered.
    edges: Vec<(u32, u32)>,
}

/// The variables found from the roots, in order.
#[derive(Default)]
struct Found {
    vars: Vec<Var>,
    index: BTreeMap<Var, u32>,
}

impl Found {
    /// The scheme variable of `var`, added if new.
    fn local(&mut self, var: Var) -> u32 {
        if let Some(&local) = self.index.get(&var) {
            return local;
        }
        let local = u32::try_from(self.vars.len()).unwrap_or(u32::MAX);
        self.vars.push(var);
        self.index.insert(var, local);
        local
    }

    /// The shape of `term`, its variables added (`None` for a variable).
    fn shape(&mut self, term: &Term) -> Option<Shape> {
        Some(match term {
            Term::Var(_) => return None,
            Term::Top => Shape::Top,
            Term::Bottom => Shape::Bottom,
            Term::Atom(atom) => Shape::Atom(atom.integer()),
            Term::Pointer(pointer) => {
                Shape::Pointer(self.local(pointer.store()), self.local(pointer.load()))
            }
            Term::Record(record) => Shape::Record(
                record
                    .fields()
                    .iter()
                    .map(|&(field, var)| (field, self.local(var)))
                    .collect(),
            ),
            Term::Code(code) => Shape::Code(
                code.params()
                    .iter()
                    .map(|&(p, var)| (p, self.local(var)))
                    .collect(),
                code.results()
                    .iter()
                    .map(|&(r, var)| (r, self.local(var)))
                    .collect(),
            ),
        })
    }
}

impl Scheme {
    /// The most variables whose bounds a scheme keeps.
    pub const LIMIT: usize = 512;

    /// The most steps collapsing chains of variables takes.
    pub const STEPS: usize = 1 << 16;

    /// The scheme of `roots` in `solution` (the [module](self) says what
    /// it keeps). A root may repeat; a variable `solution` does not have
    /// is free.
    pub fn new(solution: &Solution, roots: &[Var]) -> Self {
        let mut found = Found::default();
        let roots: Vec<u32> = roots.iter().map(|&root| found.local(root)).collect();
        let mut bounds: Vec<SchemeBound> = Vec::new();
        let mut next = 0;
        while next < Self::LIMIT
            && let Some(&var) = found.vars.get(next)
        {
            let local = u32::try_from(next).unwrap_or(u32::MAX);
            next += 1;
            let answer = solution.answer(var);
            for bound in answer.lower.iter().chain(&answer.upper) {
                if let Some(shape) = solution.term(bound.term).and_then(|t| found.shape(t)) {
                    bounds.push((local, bound.side, shape, bound.evidence));
                }
            }
        }
        let edges = collapse(solution, &found, next);
        let mut scheme = Self {
            vars: u32::try_from(found.vars.len()).unwrap_or(u32::MAX),
            roots,
            bounds,
            edges,
        };
        scheme.minimise();
        scheme
    }

    /// How many variables it has.
    pub fn var_count(&self) -> usize {
        self.vars as usize
    }

    /// How many constraints an instance states.
    pub fn constraint_count(&self) -> usize {
        self.bounds.len() + self.edges.len()
    }

    /// A fresh instance in `system`: a new variable per variable of the
    /// scheme, each bound and edge stated with its evidence mapped by
    /// `evidence`. Gives the roots' instances, in the order given to
    /// [`Scheme::new`].
    pub fn instantiate(
        &self,
        system: &mut System,
        mut evidence: impl FnMut(Evidence) -> Evidence,
    ) -> Vec<Var> {
        let fresh: Vec<Var> = (0..self.vars).map(|_| system.var()).collect();
        let var = |local: u32| fresh.get(local as usize).copied();
        for (local, side, shape, stated) in &self.bounds {
            let (Some(at), Some(term)) = (var(*local), term(shape, &var)) else {
                continue;
            };
            let (lhs, rhs) = match side {
                Side::Lower => (term, Term::Var(at)),
                Side::Upper => (Term::Var(at), term),
            };
            system.constrain(lhs, rhs, evidence(*stated));
        }
        for &(lhs, rhs) in &self.edges {
            if let (Some(lhs), Some(rhs)) = (var(lhs), var(rhs)) {
                system.constrain(
                    Term::Var(lhs),
                    Term::Var(rhs),
                    evidence(Evidence::default()),
                );
            }
        }
        self.roots.iter().filter_map(|&root| var(root)).collect()
    }

    /// Merges the variables no observation tells apart (partition
    /// refinement from the roots, each its own class), renumbered by first
    /// occurrence; bounds and edges deduplicated.
    fn minimise(&mut self) {
        let n = self.vars as usize;
        let mut initial: Vec<u32> = vec![0; n];
        for (position, &root) in self.roots.iter().enumerate() {
            if let Some(slot) = initial.get_mut(root as usize) {
                *slot = u32::try_from(position + 1).unwrap_or(u32::MAX);
            }
        }
        let (mut class, mut count) = renumber(initial);
        for _ in 0..n {
            let (refined, refined_count) = renumber(self.refine(&class));
            class = refined;
            if refined_count == count {
                break;
            }
            count = refined_count;
        }
        let of = |v: u32| class.get(v as usize).copied().unwrap_or(v);
        let mut bounds: Vec<SchemeBound> = self
            .bounds
            .iter()
            .map(|(v, side, shape, evidence)| (of(*v), *side, shape.map(of), *evidence))
            .collect();
        bounds.sort_unstable();
        bounds.dedup_by(|b, a| {
            a.0 == b.0 && a.1 == b.1 && a.2 == b.2 && a.3.strength == b.3.strength
        });
        let mut edges: Vec<(u32, u32)> = self
            .edges
            .iter()
            .map(|&(a, b)| (of(a), of(b)))
            .filter(|(a, b)| a != b)
            .collect();
        edges.sort_unstable();
        edges.dedup();
        self.vars = u32::try_from(count).unwrap_or(u32::MAX);
        self.roots = self.roots.iter().map(|&root| of(root)).collect();
        self.bounds = bounds;
        self.edges = edges;
        self.prune();
    }

    /// Drops the bounds an edge brings anyway: an upper bound of `a`
    /// that `b` has, where `a ≤ b` (it flows down), a lower bound of `b`
    /// that `a` has (it flows up); in order, never dropping one another
    /// drop relies on, so in a cycle one copy stays.
    fn prune(&mut self) {
        let mut above: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut below: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for &(a, b) in &self.edges {
            above.entry(a).or_default().push(b);
            below.entry(b).or_default().push(a);
        }
        let mut present: BTreeSet<(u32, Side, &Shape, Strength)> = self
            .bounds
            .iter()
            .map(|(v, side, shape, e)| (*v, *side, shape, e.strength))
            .collect();
        let mut keep = Vec::with_capacity(self.bounds.len());
        for (v, side, shape, e) in &self.bounds {
            let neighbours = match side {
                Side::Upper => above.get(v),
                Side::Lower => below.get(v),
            };
            let carried = neighbours.is_some_and(|list| {
                list.iter()
                    .any(|&n| present.contains(&(n, *side, shape, e.strength)))
            });
            if carried {
                present.remove(&(*v, *side, shape, e.strength));
            }
            keep.push(!carried);
        }
        let mut kept = keep.into_iter();
        self.bounds.retain(|_| kept.next().unwrap_or(true));
    }

    /// Each variable's signature under `class`: its class, its bounds
    /// and its edges over classes (to renumber).
    fn refine(&self, class: &[u32]) -> Vec<Signature> {
        let of = |v: u32| class.get(v as usize).copied().unwrap_or(v);
        let mut signatures: Vec<Signature> = class
            .iter()
            .map(|&c| (c, Vec::new(), Vec::new(), Vec::new()))
            .collect();
        for (v, side, shape, evidence) in &self.bounds {
            if let Some(signature) = signatures.get_mut(*v as usize) {
                signature.1.push((*side, shape.map(of), evidence.strength));
            }
        }
        for &(a, b) in &self.edges {
            if let Some(signature) = signatures.get_mut(a as usize) {
                signature.2.push(of(b));
            }
            if let Some(signature) = signatures.get_mut(b as usize) {
                signature.3.push(of(a));
            }
        }
        for signature in &mut signatures {
            signature.1.sort_unstable();
            signature.1.dedup();
            signature.2.sort_unstable();
            signature.2.dedup();
            signature.3.sort_unstable();
            signature.3.dedup();
        }
        signatures
    }
}

/// What tells a variable apart under a partition: its class, its bounds
/// over classes (side, term, strength), the classes above and below it.
type Signature = (u32, Vec<(Side, Shape, Strength)>, Vec<u32>, Vec<u32>);

/// Keys renumbered to dense classes by first occurrence, with how many.
fn renumber<K: Ord>(keys: Vec<K>) -> (Vec<u32>, usize) {
    let mut ids: BTreeMap<K, u32> = BTreeMap::new();
    let mut classes = Vec::with_capacity(keys.len());
    for key in keys {
        let next = u32::try_from(ids.len()).unwrap_or(u32::MAX);
        classes.push(*ids.entry(key).or_insert(next));
    }
    (classes, ids.len())
}

/// The edges between the variables `found` (the first `expanded` of them,
/// whose bounds are kept), through chains of variables not found, in
/// [`Scheme::STEPS`] steps at most.
fn collapse(solution: &Solution, found: &Found, expanded: usize) -> Vec<(u32, u32)> {
    let nodes = &solution.state.nodes;
    let mut edges: BTreeSet<(u32, u32)> = BTreeSet::new();
    let mut steps = 0;
    for (local, var) in found.vars.iter().take(expanded).enumerate() {
        let local = u32::try_from(local).unwrap_or(u32::MAX);
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        let mut stack: Vec<u32> = vec![var.0];
        while let Some(at) = stack.pop() {
            let Some(node) = nodes.get(at as usize) else {
                continue;
            };
            for &(above, _) in &node.upper_vars {
                steps += 1;
                if steps > Scheme::STEPS {
                    return edges.into_iter().collect();
                }
                match found.index.get(&Var(above)) {
                    Some(&target) => {
                        if target != local {
                            edges.insert((local, target));
                        }
                    }
                    None => {
                        if seen.insert(above) {
                            stack.push(above);
                        }
                    }
                }
            }
        }
    }
    edges.into_iter().collect()
}

/// The term of `shape`, its variables' instances by `var`.
fn term(shape: &Shape, var: &impl Fn(u32) -> Option<Var>) -> Option<Term> {
    Some(match shape {
        Shape::Top => Term::Top,
        Shape::Bottom => Term::Bottom,
        Shape::Atom(atom) => Term::Atom(*atom),
        Shape::Pointer(store, load) => Term::Pointer(Pointer {
            store: var(*store)?,
            load: var(*load)?,
        }),
        Shape::Record(fields) => Term::Record(Record::new(
            fields
                .iter()
                .map(|&(field, v)| Some((field, var(v)?)))
                .collect::<Option<Vec<_>>>()?,
        )),
        Shape::Code(params, results) => {
            let positions = |list: &[(u32, u32)]| {
                list.iter()
                    .map(|&(p, v)| Some((p, var(v)?)))
                    .collect::<Option<Vec<_>>>()
            };
            Term::Code(Code::new(positions(params)?, positions(results)?))
        }
    })
}
