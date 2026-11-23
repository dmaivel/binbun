//! Why the solver typed each value as it did: per kept L1 value asked for,
//! per global object accessed whole and for the return value, the bounds
//! its type variable solved to, each with its strength and the reasons
//! of the input constraints behind it ([`Solution::explain`]), and the
//! bounds that lost a conflict there. Read from a solve, never fed back:
//! explaining changes no type.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use binbun_ssa::ir::Value;
use binbun_typeinfer::{Atom, Bound, Side, Solution, Term, Var};

use super::{Generated, Reason};

/// The most reasons listed behind one bound, nearest first.
pub const REASONS: usize = 8;

/// The most bounds listed per value and side: the strongest.
pub const BOUNDS: usize = 16;

/// What a bound is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BoundShape {
    /// A scalar.
    Atom(Atom),
    /// A data pointer.
    Pointer,
    /// What a pointer reaches (fields).
    Record,
    /// Code (a function).
    Code,
    /// Above or below every type, or another variable.
    Other,
}

/// One bound of a value's type variable, with the evidence behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clue {
    /// Below the value (what flows in) or above it (what a use demands).
    pub lower: bool,
    /// What it is.
    pub shape: BoundShape,
    /// How strong the constraint stating it is (`typing`'s ranks: Prior
    /// 0 to Declared 6).
    pub strength: u8,
    /// The reason of the constraint stating it, where its tag names one.
    pub reason: Option<Reason>,
    /// The reasons of the input constraints it travelled through to the
    /// value, nearest first, at most [`REASONS`] (the stating one
    /// included).
    pub path: Vec<Reason>,
    /// Whether it lost a conflict at the value (its evidence was the
    /// weaker): conflicting evidence, which the type does not follow.
    pub lost: bool,
}

/// The evidence of a function's types: its bounds, strongest first
/// ([`Clue`]), per L1 value asked for, per global object, and of the
/// return value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Explained {
    /// By L1 value (those with a type variable).
    pub values: BTreeMap<Value, Vec<Clue>>,
    /// By global object accessed whole, by its first byte.
    pub globals: BTreeMap<u64, Vec<Clue>>,
    /// Of the return value.
    pub returns: Vec<Clue>,
}

/// The clues of `values` (of the function `generated` is of), of its
/// globals and its return value, solved to `solution`; a value with no
/// type variable has none.
pub(crate) fn explain(generated: &Generated, solution: &Solution, values: &[Value]) -> Explained {
    let mut out = Explained::default();
    for &value in values {
        if let Some(var) = generated.var(value) {
            let clues = clues(generated, solution, var);
            if !clues.is_empty() {
                out.values.insert(value, clues);
            }
        }
    }
    for (&address, &(var, _)) in &generated.globals {
        out.globals.insert(address, clues(generated, solution, var));
    }
    if let Some(var) = generated.returns {
        out.returns = clues(generated, solution, var);
    }
    out
}

/// The clues of type variable `var`.
fn clues(generated: &Generated, solution: &Solution, var: Var) -> Vec<Clue> {
    let answer = solution.answer(var);
    let mut clues: Vec<Clue> = Vec::new();
    for (bounds, lost) in [
        (&answer.lower, false),
        (&answer.upper, false),
        (&answer.lost, true),
    ] {
        let mut sorted: Vec<&Bound> = bounds.iter().collect();
        sorted.sort_by_key(|bound| core::cmp::Reverse(bound.evidence.strength));
        for bound in sorted.into_iter().take(BOUNDS) {
            let path = solution
                .explain(var, bound)
                .into_iter()
                .filter_map(|id| solution.constraint(id))
                .filter_map(|constraint| generated.reason(constraint.evidence.tag))
                .take(REASONS)
                .collect();
            clues.push(Clue {
                lower: bound.side == Side::Lower,
                shape: shape(solution, bound),
                strength: bound.evidence.strength.0,
                reason: generated.reason(bound.evidence.tag),
                path,
                lost,
            });
        }
    }
    clues.sort_by_key(|clue| (clue.lost, core::cmp::Reverse(clue.strength)));
    clues
}

/// What `bound`'s term is.
fn shape(solution: &Solution, bound: &Bound) -> BoundShape {
    if let Some(atom) = bound.atom {
        return BoundShape::Atom(atom);
    }
    match solution.term(bound.term) {
        Some(Term::Atom(atom)) => BoundShape::Atom(*atom),
        Some(Term::Pointer(_)) => BoundShape::Pointer,
        Some(Term::Record(_)) => BoundShape::Record,
        Some(Term::Code(_)) => BoundShape::Code,
        Some(Term::Var(_) | Term::Top | Term::Bottom) | None => BoundShape::Other,
    }
}
