//! What a solved [`System`](crate::System) answers: bounds per variable,
//! conflicts, the graph of a solved type, and why.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{OnceCell, RefCell};

use crate::atom::{Atom, Level};
use crate::solve::{Cause, State, Via, term_of};
use crate::term::{Constraint, ConstraintId, Evidence, Field, Side, Term, Var};

/// An occurrence of a term in the input (a side of one constraint): what
/// a [`Bound`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TermRef(pub(crate) u32);

/// A bound on a variable: a term of the input, below or above it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bound {
    /// The term ([`Solution::term`]).
    pub term: TermRef,
    /// Below or above.
    pub side: Side,
    /// The term if it is an atom.
    pub atom: Option<Atom>,
    /// The evidence of the constraint the term occurs in.
    pub evidence: Evidence,
}

/// A lower bound that is not below an upper bound: atoms out of order, or
/// different constructors (an atom against a pointer, a pointer against
/// code). Recorded once per pair of bounds, at the first variable they
/// met at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Conflict {
    /// Where they met (`None`: an input constraint between two terms).
    pub at: Option<Var>,
    /// The lower bound.
    pub lower: Bound,
    /// The upper bound.
    pub upper: Bound,
    /// The side whose evidence is weaker (on a tie, the upper bound: the
    /// value's producer outranks a use's demand, which C writes as a cast
    /// at the use).
    pub loser: Side,
}

/// What one variable solved to. Bounds that lost a conflict at this
/// variable are only in [`lost`](Self::lost); everything else is from the
/// rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// Its lower bounds (what flows in), by term.
    pub lower: Vec<Bound>,
    /// Its upper bounds (what is demanded), by term.
    pub upper: Vec<Bound>,
    /// Bounds that lost a conflict here.
    pub lost: Vec<Bound>,
    /// The join of its atomic lower bounds ([`Level::Bottom`] if none); an
    /// enumeration ([`Atom::Enum`]) only where every value flowing in is
    /// stated one of its ([`Solution::enumeration`]), else its integer.
    pub lower_atom: Level,
    /// The meet of its atomic upper bounds ([`Level::Top`] if none).
    pub upper_atom: Level,
    /// Whether a bound is a pointer.
    pub pointer: bool,
    /// The store parameters of its pointer bounds.
    pub stores: Vec<Var>,
    /// The load parameters of its pointer bounds.
    pub loads: Vec<Var>,
    /// The fields of its record bounds.
    pub fields: Vec<(Field, Var)>,
    /// The parameters of its code bounds, by position.
    pub params: Vec<(u32, Var)>,
    /// The results of its code bounds, by position.
    pub results: Vec<(u32, Var)>,
}

/// An edge's label in a [`Graph`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Label {
    /// To a pointer's store parameter.
    Store,
    /// To a pointer's load parameter.
    Load,
    /// To a record's field.
    Field(Field),
    /// To code's parameter.
    Param(u32),
    /// To code's result.
    Result(u32),
}

/// A variable in a [`Graph`], with its atomic bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Node {
    /// The variable.
    pub var: Var,
    /// [`Answer::lower_atom`].
    pub lower: Level,
    /// [`Answer::upper_atom`].
    pub upper: Level,
    /// [`Answer::pointer`].
    pub pointer: bool,
}

/// A labelled edge of a [`Graph`], between node indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GraphEdge {
    /// The source node's index.
    pub from: usize,
    /// What it reaches.
    pub label: Label,
    /// The target node's index.
    pub to: usize,
}

/// The solved type of some variables as a finite graph: the variables
/// their constructors' parameters reach, transitively, with labelled
/// edges. A recursive type is a cycle. A node may have several edges of
/// one label (one per access: every load through a pointer has its own
/// load variable); rounding merges them (loads and fields by meet, as
/// BinSub's lowering does).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Graph {
    /// The nodes, the roots first in the order given.
    pub nodes: Vec<Node>,
    /// The edges, ordered.
    pub edges: Vec<GraphEdge>,
}

/// A solved [`System`](crate::System).
#[derive(Clone, Debug)]
pub struct Solution {
    pub(crate) state: State,
    /// The answers given so far, by variable: rounding asks for one
    /// variable's many times (a pointer family's members, their views'
    /// fields), and an answer reads every bound that reached it.
    answers: RefCell<BTreeMap<u32, Answer>>,
    /// Per variable, [`Self::enumeration`] (found for all at the first
    /// question).
    enumerations: OnceCell<Vec<Option<Atom>>>,
}

impl Solution {
    /// The solution `state` holds.
    pub(crate) fn new(state: State) -> Self {
        Self {
            state,
            answers: RefCell::new(BTreeMap::new()),
            enumerations: OnceCell::new(),
        }
    }

    /// How many steps solving took.
    pub fn steps(&self) -> usize {
        self.state.steps
    }

    /// How many variables there are.
    pub fn var_count(&self) -> usize {
        self.state.nodes.len()
    }

    /// The conflicts, in the order found.
    pub fn conflicts(&self) -> &[Conflict] {
        &self.state.conflicts
    }

    /// An input constraint.
    pub fn constraint(&self, id: ConstraintId) -> Option<&Constraint> {
        self.state.constraints.get(id.index())
    }

    /// The term of a bound.
    pub fn term(&self, term: TermRef) -> Option<&Term> {
        term_of(&self.state.constraints, &self.state.occurrences, term.0)
    }

    /// The constraint a term occurs in.
    pub fn origin(&self, term: TermRef) -> Option<ConstraintId> {
        Some(self.state.occurrences.get(term.0 as usize)?.constraint)
    }

    /// What `var` solved to.
    pub fn answer(&self, var: Var) -> Answer {
        if let Some(known) = self.answers.borrow().get(&var.0) {
            return known.clone();
        }
        let answer = self.compute(var);
        self.answers.borrow_mut().insert(var.0, answer.clone());
        answer
    }

    /// What `var` solved to ([`Self::answer`]), not remembered.
    fn compute(&self, var: Var) -> Answer {
        let mut answer = Answer {
            lower: Vec::new(),
            upper: Vec::new(),
            lost: Vec::new(),
            lower_atom: Level::Bottom,
            upper_atom: Level::Top,
            pointer: false,
            stores: Vec::new(),
            loads: Vec::new(),
            fields: Vec::new(),
            params: Vec::new(),
            results: Vec::new(),
        };
        let Some(node) = self.state.nodes.get(var.index()) else {
            return answer;
        };
        let mut lost: BTreeSet<(u32, Side)> = BTreeSet::new();
        // The conflicts between a lower and an upper bound both here (by
        // the lower bound's conflicts: few, where the pairs are many).
        let mut uppers = node.upper.clone();
        uppers.sort_unstable();
        for &lower in &node.lower {
            let Some(conflicted) = self.state.conflicted.get(&lower) else {
                continue;
            };
            for &(upper, index) in conflicted {
                if uppers.binary_search(&upper).is_err() {
                    continue;
                }
                let Some(conflict) = self.state.conflicts.get(index as usize) else {
                    continue;
                };
                match conflict.loser {
                    Side::Lower => lost.insert((lower, Side::Lower)),
                    Side::Upper => lost.insert((upper, Side::Upper)),
                };
            }
        }
        let sides = [(&node.lower, Side::Lower), (&node.upper, Side::Upper)];
        for (terms, side) in sides {
            for &term in terms {
                let Some(bound) = self.state.bound_of(term, side) else {
                    continue;
                };
                if lost.contains(&(term, side)) {
                    answer.lost.push(bound);
                } else {
                    self.include(&mut answer, bound);
                }
            }
        }
        for list in [&mut answer.lower, &mut answer.upper, &mut answer.lost] {
            list.sort_unstable();
        }
        answer.stores.sort_unstable();
        answer.stores.dedup();
        answer.loads.sort_unstable();
        answer.loads.dedup();
        answer.fields.sort_unstable();
        answer.fields.dedup();
        answer.params.sort_unstable();
        answer.params.dedup();
        answer.results.sort_unstable();
        answer.results.dedup();
        if let Level::Atom(atom @ Atom::Enum { .. }) = answer.lower_atom
            && self.enumeration(var) != Some(atom)
        {
            answer.lower_atom = Level::Atom(atom.integer());
        }
        answer
    }

    /// The enumeration every value flowing into `var` is of, if one is:
    /// each term stated below it or below a variable below it (through
    /// any chain of edges) is a value of that one enumeration, and every
    /// variable those chains start from has one stated. A variable with
    /// nothing stated below it and nothing flowing in (an arithmetic
    /// result, a parameter's entry value) is a value of no enumeration,
    /// so a variable it flows into is of none.
    pub fn enumeration(&self, var: Var) -> Option<Atom> {
        self.enumerations
            .get_or_init(|| enumerations(&self.state))
            .get(var.index())
            .copied()
            .flatten()
    }

    /// Adds a bound that stands to an answer.
    fn include(&self, answer: &mut Answer, bound: Bound) {
        let level = match self.term(bound.term) {
            Some(Term::Atom(atom)) => Some(Level::Atom(*atom)),
            Some(Term::Top) => Some(Level::Top),
            Some(Term::Bottom) => Some(Level::Bottom),
            Some(Term::Pointer(pointer)) => {
                answer.pointer = true;
                answer.stores.push(pointer.store());
                answer.loads.push(pointer.load());
                None
            }
            Some(Term::Record(record)) => {
                answer.fields.extend_from_slice(record.fields());
                None
            }
            Some(Term::Code(code)) => {
                answer.params.extend_from_slice(code.params());
                answer.results.extend_from_slice(code.results());
                None
            }
            Some(Term::Var(_)) | None => None,
        };
        match bound.side {
            Side::Lower => {
                if let Some(level) = level {
                    answer.lower_atom = answer.lower_atom.join(level);
                }
                answer.lower.push(bound);
            }
            Side::Upper => {
                if let Some(level) = level {
                    answer.upper_atom = answer.upper_atom.meet(level);
                }
                answer.upper.push(bound);
            }
        }
    }

    /// The graph of the types of `roots`: every variable their
    /// constructors' parameters reach.
    pub fn graph(&self, roots: &[Var]) -> Graph {
        let mut graph = Graph::default();
        let mut index: BTreeMap<Var, usize> = BTreeMap::new();
        let mut queue: Vec<Var> = Vec::new();
        for &root in roots {
            visit(&mut graph, &mut index, &mut queue, root);
        }
        let mut next = 0;
        while let Some(&var) = queue.get(next) {
            let answer = self.answer(var);
            let from = next;
            next += 1;
            if let Some(node) = graph.nodes.get_mut(from) {
                node.lower = answer.lower_atom;
                node.upper = answer.upper_atom;
                node.pointer = answer.pointer;
            }
            let targets = answer
                .stores
                .iter()
                .map(|&v| (Label::Store, v))
                .chain(answer.loads.iter().map(|&v| (Label::Load, v)))
                .chain(answer.fields.iter().map(|&(f, v)| (Label::Field(f), v)))
                .chain(answer.params.iter().map(|&(p, v)| (Label::Param(p), v)))
                .chain(answer.results.iter().map(|&(r, v)| (Label::Result(r), v)));
            for (label, target) in targets {
                let to = visit(&mut graph, &mut index, &mut queue, target);
                graph.edges.push(GraphEdge { from, label, to });
            }
        }
        graph.edges.sort_unstable();
        graph.edges.dedup();
        graph
    }

    /// The input constraints behind a bound of `var`: from the bound back
    /// along the edges it travelled to the constraint it occurs in,
    /// including the constraints behind each edge (an edge decomposed from
    /// two bounds brings theirs). Each constraint once, nearest first.
    pub fn explain(&self, var: Var, bound: &Bound) -> Vec<ConstraintId> {
        self.why(vec![(var.0, bound.term.0, bound.side)])
    }

    /// The input constraints behind both sides of a conflict.
    pub fn explain_conflict(&self, conflict: &Conflict) -> Vec<ConstraintId> {
        match conflict.at {
            Some(at) => self.why(vec![
                (at.0, conflict.upper.term.0, Side::Upper),
                (at.0, conflict.lower.term.0, Side::Lower),
            ]),
            None => [conflict.lower.term, conflict.upper.term]
                .into_iter()
                .filter_map(|term| self.origin(term))
                .collect(),
        }
    }

    /// The constraints behind these bounds `(variable, term, side)`.
    fn why(&self, mut stack: Vec<(u32, u32, Side)>) -> Vec<ConstraintId> {
        let mut seen: BTreeSet<(u32, u32, Side)> = BTreeSet::new();
        let mut out: Vec<ConstraintId> = Vec::new();
        let mut listed: BTreeSet<ConstraintId> = BTreeSet::new();
        let mut list = |id: ConstraintId, out: &mut Vec<ConstraintId>| {
            if listed.insert(id) {
                out.push(id);
            }
        };
        while let Some((var, term, side)) = stack.pop() {
            if !seen.insert((var, term, side)) {
                continue;
            }
            match self.state.bounds.get(&(var, term, side)) {
                None => {}
                Some(Via::Stated) => {
                    if let Some(id) = self.origin(TermRef(term)) {
                        list(id, &mut out);
                    }
                }
                Some(&Via::Edge(edge)) => {
                    let Some(edge) = self.state.edges.get(edge as usize) else {
                        continue;
                    };
                    let previous = match side {
                        Side::Lower => edge.lhs,
                        Side::Upper => edge.rhs,
                    };
                    stack.push((previous, term, side));
                    match edge.cause {
                        Cause::Input(id) => list(id, &mut out),
                        Cause::Pair(lower, upper) => {
                            match self.state.pairs.get(&(lower, upper)).and_then(|p| p.at) {
                                Some(at) => {
                                    stack.push((at, upper, Side::Upper));
                                    stack.push((at, lower, Side::Lower));
                                }
                                None => {
                                    for term in [lower, upper] {
                                        if let Some(id) = self.origin(TermRef(term)) {
                                            list(id, &mut out);
                                        }
                                    }
                                }
                            }
                        }
                        Cause::Cross(a, b) => {
                            if let Some(&at) = self.state.crosses.get(&(a, b)) {
                                stack.push((at, b, Side::Upper));
                                stack.push((at, a, Side::Upper));
                            }
                        }
                    }
                }
            }
        }
        out
    }
}

/// The node of `var`, added (and queued, its bounds to fill in) if new.
/// Nodes and the queue grow together, so a node's index is its place in
/// the queue.
fn visit(
    graph: &mut Graph,
    index: &mut BTreeMap<Var, usize>,
    queue: &mut Vec<Var>,
    var: Var,
) -> usize {
    if let Some(&at) = index.get(&var) {
        return at;
    }
    let at = graph.nodes.len();
    graph.nodes.push(Node {
        var,
        lower: Level::Bottom,
        upper: Level::Top,
        pointer: false,
    });
    index.insert(var, at);
    queue.push(var);
    at
}

/// What flows into a variable, for [`Solution::enumeration`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// Nothing found yet.
    Nothing,
    /// Values of this enumeration only.
    One(Atom),
    /// Something else.
    Mixed,
}

impl Flow {
    /// What two flows together are.
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Nothing, flow) | (flow, Self::Nothing) => flow,
            (Self::One(a), Self::One(b)) if a == b => self,
            (Self::One(_) | Self::Mixed, Self::One(_) | Self::Mixed) => Self::Mixed,
        }
    }
}

/// [`Solution::enumeration`] of every variable of `state`: what is stated
/// below each, then joined along the edges to a fixed point (each
/// variable changes at most twice).
fn enumerations(state: &State) -> Vec<Option<Atom>> {
    let mut flow = vec![Flow::Nothing; state.nodes.len()];
    let mut stated = vec![false; state.nodes.len()];
    for constraint in &state.constraints {
        let (Term::Var(var), lower) = (&constraint.rhs, &constraint.lhs) else {
            continue;
        };
        let here = match lower {
            Term::Var(_) | Term::Bottom => continue,
            &Term::Atom(atom @ Atom::Enum { .. }) => Flow::One(atom),
            Term::Top | Term::Atom(_) | Term::Pointer(_) | Term::Record(_) | Term::Code(_) => {
                Flow::Mixed
            }
        };
        if let (Some(slot), Some(seen)) = (flow.get_mut(var.index()), stated.get_mut(var.index())) {
            *slot = slot.join(here);
            *seen = true;
        }
    }
    for ((slot, &seen), node) in flow.iter_mut().zip(&stated).zip(&state.nodes) {
        if !seen && node.lower_vars.is_empty() {
            *slot = Flow::Mixed;
        }
    }
    let mut work: Vec<usize> = (0..flow.len())
        .filter(|&index| flow.get(index) != Some(&Flow::Nothing))
        .collect();
    while let Some(index) = work.pop() {
        let (Some(&from), Some(node)) = (flow.get(index), state.nodes.get(index)) else {
            continue;
        };
        for &(above, _) in &node.upper_vars {
            let Some(slot) = flow.get_mut(above as usize) else {
                continue;
            };
            let joined = slot.join(from);
            if joined != *slot {
                *slot = joined;
                work.push(above as usize);
            }
        }
    }
    flow.into_iter()
        .map(|flow| match flow {
            Flow::One(atom) => Some(atom),
            Flow::Nothing | Flow::Mixed => None,
        })
        .collect()
}
