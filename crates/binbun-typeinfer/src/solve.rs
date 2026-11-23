//! Constraint decomposition (BinSub's Algorithm 1, SimpleSub's `constrain`)
//! as a worklist, with provenance.
//!
//! Every variable keeps its lower and upper bounds that are not variables
//! (occurrences of terms in the input), and its variable neighbours. A
//! lower bound reaching a variable is passed to every variable above it,
//! an upper bound to every variable below it, so each variable's bound
//! sets are closed; where a lower bound meets an upper bound at a variable
//! the pair is decomposed once (a cache of visited pairs, which is what
//! makes recursive constraints terminate), giving new variable edges or a
//! conflict. Two upper pointers of one variable are one pointer's views
//! (BinSub's pointer meet `ptr(a, b) ⊓ ptr(c, d) = ptr((a ⊔ c) ⊓ (b ⊓ d),
//! b ⊓ d)`, applied here rather than at lowering): each one's store is
//! below the other's load. The solver never makes a variable, so the
//! entries it can add (bounds: variables × occurrences; edges: variables²;
//! pairs: occurrences²) are finite and each is processed once.

use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::mem;

use crate::solution::{Bound, Conflict, Solution, TermRef};
use crate::term::{Code, Constraint, ConstraintId, Record, Side, System, Term, Var};

/// How much work [`System::solve`] may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Budget {
    /// The most steps (work items processed: a bound reaching a variable,
    /// an edge between variables, a pair of bounds decomposed, two pointer
    /// views merged).
    pub steps: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self { steps: 1 << 24 }
    }
}

/// Why [`System::solve`] gave no solution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// Solving needs more steps than the budget allows.
    TooLarge {
        /// The budget.
        steps: usize,
    },
    /// The system has `u32::MAX` variables or constraints or more.
    TooManyVariables,
    /// This constraint names a variable another system made.
    UnknownVariable(ConstraintId),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { steps } => write!(f, "more than the budget of {steps} steps"),
            Self::TooManyVariables => f.write_str("too many variables or constraints"),
            Self::UnknownVariable(id) => {
                write!(f, "constraint {} names an unknown variable", id.index())
            }
        }
    }
}

/// Where a term occurs in the input: which constraint, which side.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Occurrence {
    pub(crate) constraint: ConstraintId,
    pub(crate) rhs: bool,
}

/// A variable's bounds and neighbours.
#[derive(Clone, Debug, Default)]
pub(crate) struct Node {
    /// Occurrences below it.
    pub(crate) lower: Vec<u32>,
    /// Occurrences above it.
    pub(crate) upper: Vec<u32>,
    /// Variables directly below it, with the edge.
    pub(crate) lower_vars: Vec<(u32, u32)>,
    /// Variables directly above it, with the edge.
    pub(crate) upper_vars: Vec<(u32, u32)>,
    /// The pointers among `upper`.
    pub(crate) upper_pointers: Vec<u32>,
}

/// Why an edge between variables holds.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Cause {
    /// An input constraint between variables (a side condition among them).
    Input(ConstraintId),
    /// Decomposing a lower bound (first) against an upper bound.
    Pair(u32, u32),
    /// Merging two upper pointers of one variable (the smaller first).
    Cross(u32, u32),
}

/// `lhs ≤ rhs` between variables.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Edge {
    pub(crate) lhs: u32,
    pub(crate) rhs: u32,
    pub(crate) cause: Cause,
}

/// How a bound reached a variable.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Via {
    /// Its constraint names the variable.
    Stated,
    /// Along this edge, from the variable at its other end.
    Edge(u32),
}

/// A decomposed pair of bounds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pair {
    /// The variable where they met (`None`: an input constraint between
    /// two terms).
    pub(crate) at: Option<u32>,
}

#[derive(Clone, Copy, Debug)]
enum Task {
    Bound {
        var: u32,
        term: u32,
        side: Side,
        via: Via,
    },
    Edge {
        lhs: u32,
        rhs: u32,
        cause: Cause,
    },
    Pair {
        lower: u32,
        upper: u32,
        at: Option<u32>,
    },
    Cross {
        a: u32,
        b: u32,
        at: u32,
    },
}

/// The solver's state, kept by the [`Solution`].
#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    pub(crate) constraints: Vec<Constraint>,
    pub(crate) occurrences: Vec<Occurrence>,
    pub(crate) nodes: Vec<Node>,
    pub(crate) edges: Vec<Edge>,
    pub(crate) edge_ids: BTreeMap<(u32, u32), u32>,
    pub(crate) bounds: BTreeMap<(u32, u32, Side), Via>,
    pub(crate) pairs: BTreeMap<(u32, u32), Pair>,
    pub(crate) crosses: BTreeMap<(u32, u32), u32>,
    pub(crate) conflicts: Vec<Conflict>,
    /// Each conflict by its lower bound's occurrence: the upper bound's
    /// occurrence and the conflict's index.
    pub(crate) conflicted: BTreeMap<u32, Vec<(u32, u32)>>,
    pub(crate) steps: usize,
    work: Vec<Task>,
    scratch: Vec<(Var, Var)>,
}

/// The term an occurrence names.
pub(crate) fn term_of<'a>(
    constraints: &'a [Constraint],
    occurrences: &[Occurrence],
    id: u32,
) -> Option<&'a Term> {
    let occurrence = occurrences.get(id as usize)?;
    let constraint = constraints.get(occurrence.constraint.index())?;
    Some(if occurrence.rhs {
        &constraint.rhs
    } else {
        &constraint.lhs
    })
}

/// Whether every variable `term` names is below `vars`.
fn known(term: &Term, vars: u32) -> bool {
    let ok = |var: &Var| var.0 < vars;
    match term {
        Term::Var(var) => ok(var),
        Term::Top | Term::Bottom | Term::Atom(_) => true,
        Term::Pointer(pointer) => ok(&pointer.store()) && ok(&pointer.load()),
        Term::Record(record) => record.fields().iter().all(|(_, var)| ok(var)),
        Term::Code(code) => {
            code.params().iter().all(|(_, var)| ok(var))
                && code.results().iter().all(|(_, var)| ok(var))
        }
    }
}

/// The edges `lower ≤ upper` gives between variables, into `out`; `false`
/// where it cannot hold (a conflict).
fn decompose(lower: &Term, upper: &Term, out: &mut Vec<(Var, Var)>) -> bool {
    match (lower, upper) {
        (Term::Bottom | Term::Var(_), _) | (_, Term::Top | Term::Var(_)) => true,
        (Term::Atom(a), Term::Atom(b)) => a.is_subtype_of(*b),
        (Term::Pointer(p), Term::Pointer(q)) => {
            out.push((q.store(), p.store()));
            out.push((p.load(), q.load()));
            true
        }
        (Term::Record(r), Term::Record(s)) => {
            records(r, s, out);
            true
        }
        (Term::Code(f), Term::Code(g)) => {
            code(f, g, out);
            true
        }
        (
            Term::Top | Term::Atom(_) | Term::Pointer(_) | Term::Record(_) | Term::Code(_),
            Term::Bottom | Term::Atom(_) | Term::Pointer(_) | Term::Record(_) | Term::Code(_),
        ) => false,
    }
}

/// `r ≤ s`: each field both have, covariantly.
fn records(r: &Record, s: &Record, out: &mut Vec<(Var, Var)>) {
    for &(field, var) in r.fields() {
        let start = s.fields().partition_point(|&(f, _)| f < field);
        let matching = s.fields().iter().skip(start);
        for &(_, other) in matching.take_while(|&&(f, _)| f == field) {
            out.push((var, other));
        }
    }
}

/// `f ≤ g`: parameters contravariant, results covariant, by position.
fn code(f: &Code, g: &Code, out: &mut Vec<(Var, Var)>) {
    let matching = |a: &[(u32, Var)], b: &[(u32, Var)], out: &mut Vec<(Var, Var)>, flip: bool| {
        for &(position, var) in a {
            let start = b.partition_point(|&(p, _)| p < position);
            for &(_, other) in b.iter().skip(start).take_while(|&&(p, _)| p == position) {
                out.push(if flip { (other, var) } else { (var, other) });
            }
        }
    };
    matching(f.params(), g.params(), out, true);
    matching(f.results(), g.results(), out, false);
}

impl System {
    /// Solves the constraints: decomposes them into bounds per variable,
    /// recording conflicts.
    ///
    /// # Errors
    ///
    /// [`Refusal::TooLarge`] past `budget`, [`Refusal::TooManyVariables`]
    /// past `u32::MAX` variables or constraints,
    /// [`Refusal::UnknownVariable`] for a variable of another system.
    pub fn solve(self, budget: Budget) -> Result<Solution, Refusal> {
        let System { vars, constraints } = self;
        if vars == u32::MAX || u32::try_from(constraints.len()).is_err() {
            return Err(Refusal::TooManyVariables);
        }
        let mut state = State {
            nodes: vec![Node::default(); vars as usize],
            ..State::default()
        };
        for (index, constraint) in constraints.iter().enumerate() {
            let id = ConstraintId(u32::try_from(index).map_err(|_| Refusal::TooManyVariables)?);
            if !known(&constraint.lhs, vars) || !known(&constraint.rhs, vars) {
                return Err(Refusal::UnknownVariable(id));
            }
        }
        state.constraints = constraints;
        for index in 0..state.constraints.len() {
            let id = ConstraintId(u32::try_from(index).map_err(|_| Refusal::TooManyVariables)?);
            state.add(id)?;
            state.drain(budget)?;
        }
        Ok(Solution::new(state))
    }
}

impl State {
    /// A new occurrence of a side of a constraint.
    fn occurrence(&mut self, constraint: ConstraintId, rhs: bool) -> Result<u32, Refusal> {
        let id = u32::try_from(self.occurrences.len()).map_err(|_| Refusal::TooManyVariables)?;
        self.occurrences.push(Occurrence { constraint, rhs });
        Ok(id)
    }

    /// The work an input constraint starts.
    fn add(&mut self, id: ConstraintId) -> Result<(), Refusal> {
        let Some(constraint) = self.constraints.get(id.index()) else {
            return Ok(());
        };
        let task = match (&constraint.lhs, &constraint.rhs) {
            (Term::Var(lhs), Term::Var(rhs)) => Task::Edge {
                lhs: lhs.0,
                rhs: rhs.0,
                cause: Cause::Input(id),
            },
            (Term::Var(var), _) => {
                let var = var.0;
                Task::Bound {
                    var,
                    term: self.occurrence(id, true)?,
                    side: Side::Upper,
                    via: Via::Stated,
                }
            }
            (_, Term::Var(var)) => {
                let var = var.0;
                Task::Bound {
                    var,
                    term: self.occurrence(id, false)?,
                    side: Side::Lower,
                    via: Via::Stated,
                }
            }
            (_, _) => Task::Pair {
                lower: self.occurrence(id, false)?,
                upper: self.occurrence(id, true)?,
                at: None,
            },
        };
        self.work.push(task);
        Ok(())
    }

    /// Processes the work list to its end.
    fn drain(&mut self, budget: Budget) -> Result<(), Refusal> {
        while let Some(task) = self.work.pop() {
            self.steps += 1;
            if self.steps > budget.steps {
                return Err(Refusal::TooLarge {
                    steps: budget.steps,
                });
            }
            match task {
                Task::Bound {
                    var,
                    term,
                    side,
                    via,
                } => self.bound(var, term, side, via),
                Task::Edge { lhs, rhs, cause } => self.edge(lhs, rhs, cause),
                Task::Pair { lower, upper, at } => self.pair(lower, upper, at),
                Task::Cross { a, b, at } => self.cross(a, b, at),
            }
        }
        Ok(())
    }

    /// `term` reaches `var` on `side`.
    fn bound(&mut self, var: u32, term: u32, side: Side, via: Via) {
        match self.bounds.entry((var, term, side)) {
            Entry::Occupied(_) => return,
            Entry::Vacant(entry) => {
                entry.insert(via);
            }
        }
        let pointer = matches!(
            term_of(&self.constraints, &self.occurrences, term),
            Some(Term::Pointer(_))
        );
        let Some(node) = self.nodes.get_mut(var as usize) else {
            return;
        };
        match side {
            Side::Lower => {
                for &upper in &node.upper {
                    self.work.push(Task::Pair {
                        lower: term,
                        upper,
                        at: Some(var),
                    });
                }
                for &(above, edge) in &node.upper_vars {
                    self.work.push(Task::Bound {
                        var: above,
                        term,
                        side,
                        via: Via::Edge(edge),
                    });
                }
                node.lower.push(term);
            }
            Side::Upper => {
                for &lower in &node.lower {
                    self.work.push(Task::Pair {
                        lower,
                        upper: term,
                        at: Some(var),
                    });
                }
                for &(below, edge) in &node.lower_vars {
                    self.work.push(Task::Bound {
                        var: below,
                        term,
                        side,
                        via: Via::Edge(edge),
                    });
                }
                if pointer {
                    for &other in &node.upper_pointers {
                        self.work.push(Task::Cross {
                            a: other,
                            b: term,
                            at: var,
                        });
                    }
                    node.upper_pointers.push(term);
                }
                node.upper.push(term);
            }
        }
    }

    /// `lhs ≤ rhs` between variables.
    fn edge(&mut self, lhs: u32, rhs: u32, cause: Cause) {
        if lhs == rhs {
            return;
        }
        let Ok(id) = u32::try_from(self.edges.len()) else {
            return;
        };
        match self.edge_ids.entry((lhs, rhs)) {
            Entry::Occupied(_) => return,
            Entry::Vacant(entry) => {
                entry.insert(id);
            }
        }
        self.edges.push(Edge { lhs, rhs, cause });
        if let Some(node) = self.nodes.get_mut(lhs as usize) {
            node.upper_vars.push((rhs, id));
            for &term in &node.lower {
                self.work.push(Task::Bound {
                    var: rhs,
                    term,
                    side: Side::Lower,
                    via: Via::Edge(id),
                });
            }
        }
        if let Some(node) = self.nodes.get_mut(rhs as usize) {
            node.lower_vars.push((lhs, id));
            for &term in &node.upper {
                self.work.push(Task::Bound {
                    var: lhs,
                    term,
                    side: Side::Upper,
                    via: Via::Edge(id),
                });
            }
        }
    }

    /// A lower bound meets an upper bound (at a variable, or in the input).
    fn pair(&mut self, lower: u32, upper: u32, at: Option<u32>) {
        if self.pairs.contains_key(&(lower, upper)) {
            return;
        }
        let mut derived = mem::take(&mut self.scratch);
        derived.clear();
        let terms = (
            term_of(&self.constraints, &self.occurrences, lower),
            term_of(&self.constraints, &self.occurrences, upper),
        );
        let holds = match terms {
            (Some(l), Some(u)) => decompose(l, u, &mut derived),
            _ => true,
        };
        if !holds {
            self.conflict(lower, upper, at);
        }
        self.pairs.insert((lower, upper), Pair { at });
        for &(lhs, rhs) in &derived {
            self.work.push(Task::Edge {
                lhs: lhs.0,
                rhs: rhs.0,
                cause: Cause::Pair(lower, upper),
            });
        }
        self.scratch = derived;
    }

    /// Records that `lower ≤ upper` fails.
    fn conflict(&mut self, below: u32, above: u32, at: Option<u32>) {
        let Ok(index) = u32::try_from(self.conflicts.len()) else {
            return;
        };
        let (Some(lower), Some(upper)) = (
            self.bound_of(below, Side::Lower),
            self.bound_of(above, Side::Upper),
        ) else {
            return;
        };
        let weaker = if upper.evidence.strength > lower.evidence.strength {
            Side::Lower
        } else {
            Side::Upper
        };
        self.conflicts.push(Conflict {
            at: at.map(Var),
            lower,
            upper,
            loser: weaker,
        });
        self.conflicted
            .entry(below)
            .or_default()
            .push((above, index));
    }

    /// An occurrence as a bound.
    pub(crate) fn bound_of(&self, term: u32, side: Side) -> Option<Bound> {
        let occurrence = self.occurrences.get(term as usize)?;
        let constraint = self.constraints.get(occurrence.constraint.index())?;
        let atom = match term_of(&self.constraints, &self.occurrences, term)? {
            Term::Atom(atom) => Some(*atom),
            Term::Var(_)
            | Term::Top
            | Term::Bottom
            | Term::Pointer(_)
            | Term::Record(_)
            | Term::Code(_) => None,
        };
        Some(Bound {
            term: TermRef(term),
            side,
            atom,
            evidence: constraint.evidence,
        })
    }

    /// Two upper pointers of one variable: each one's store is below the
    /// other's load.
    fn cross(&mut self, a: u32, b: u32, at: u32) {
        let key = (a.min(b), a.max(b));
        match self.crosses.entry(key) {
            Entry::Occupied(_) => return,
            Entry::Vacant(entry) => {
                entry.insert(at);
            }
        }
        let (Some(Term::Pointer(p)), Some(Term::Pointer(q))) = (
            term_of(&self.constraints, &self.occurrences, a),
            term_of(&self.constraints, &self.occurrences, b),
        ) else {
            return;
        };
        let cause = Cause::Cross(key.0, key.1);
        for (lhs, rhs) in [(p.store(), q.load()), (q.store(), p.load())] {
            self.work.push(Task::Edge {
                lhs: lhs.0,
                rhs: rhs.0,
                cause,
            });
        }
    }
}
