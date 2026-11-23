//! Type inference for machine code by algebraic subtyping: subtyping
//! constraints in, solved bounds out.
//!
//! This is BinSub (Smith, SAS 2024: capabilities, contravariant stores
//! and recursive types as algebraic subtyping) solved by SimpleSub's
//! constraint decomposition (Parreaux,
//! ICFP 2020). It depends on no IR: a caller (`binbun-decompile`'s
//! constraint generation) makes variables, states constraints between
//! [`Term`]s with its [`Evidence`], solves, and reads an [`Answer`] per
//! variable; rounding the answers to C types is the caller's (it never
//! feeds back).
//!
//! # Terms
//!
//! - Type variables ([`Var`]) are the caller's, from [`System::var`]:
//!   dense ids, so answers can be kept in vectors. The solver makes none.
//! - [`Term::Top`] and [`Term::Bottom`]; atoms ([`Atom`]: the lattice is
//!   documented in [`atom`]).
//! - Pointers `ptr(store, load)` ([`Pointer`]): the store parameter is
//!   contravariant, the load parameter covariant, and only
//!   [`System::pointer`] makes one, adding the side condition
//!   `store ≤ load` (BinSub's S-Pointer). [`System::load`] and
//!   [`System::store`] state a whole access.
//! - Records of field capabilities ([`Record`]: `field(offset bytes,
//!   bits) → variable`, fields covariant, width subtyping: a missing field
//!   is unknown, not absent).
//! - Code ([`Code`]: parameters by position contravariant, results by
//!   position covariant; a code pointer is this constructor).
//! - Terms are shallow: a constructor's arguments are variables, so nested
//!   types are chains of variables and recursive types are cycles through
//!   them (no explicit `μ`).
//!
//! # Rules
//!
//! [`System::solve`] decomposes every constraint (BinSub's Algorithm 1
//! with records and code) into bounds per variable, each bound an
//! occurrence of a term in the input, so its evidence is that
//! constraint's:
//!
//! - `α ≤ β` between variables is an edge; every lower bound of `α`
//!   becomes one of `β` and every upper bound of `β` one of `α`, so each
//!   variable's bounds are all those reaching it.
//! - Where a lower bound meets an upper bound at a variable, the pair is
//!   decomposed once: pointers (`ptr(a, b) ≤ ptr(c, d)` gives `c ≤ a`,
//!   `b ≤ d`), records (fields both have, covariantly), code (positions
//!   both have: parameters contravariantly, results covariantly), atoms
//!   (checked in the lattice). Anything else (an atom against a
//!   constructor, two different constructors, atoms out of order) is a
//!   [`Conflict`].
//! - Two upper pointers of one variable are views of one pointer, so each
//!   one's store parameter is below the other's load parameter (BinSub's
//!   pointer meet, applied while solving): a value stored through a copy
//!   of a pointer is seen by loads through the original.
//! - Upper bounds meet without conflict: a value demanded as a pointer by
//!   one use and as an integer by another (`f(NULL, 0)`) keeps both
//!   demands; each use keeps its own type.
//! - Conflicts are recorded with both sides' evidence, never merged into
//!   a third type. A variable's [`Answer`] drops, of each conflicting
//!   pair at that variable, the bound with weaker [`Strength`]; on a tie
//!   the upper bound (the value's producer outranks a use's demand: C
//!   writes the disagreement as a cast at the use).
//! - An enumeration's value ([`Atom::Enum`]) is below its integer, so it
//!   meets every bound its integer meets; a variable's lower atom is the
//!   enumeration only where every value flowing into it is stated one
//!   ([`Solution::enumeration`]: a variable with nothing stated and
//!   nothing flowing in, such as an arithmetic result, is no
//!   enumeration's value), else its integer.
//! - [`Solution::explain`] gives the input constraints behind a bound:
//!   the path it travelled and the constraints behind each derived edge.
//! - [`Solution::graph`] gives the solved type of variables as a finite
//!   graph (load, store, field, parameter and result edges; a recursive
//!   type is a cycle) for rounding and struct identity.
//! - [`Scheme::new`] summarises a solved type over some of its variables
//!   (a function's interface) and [`Scheme::instantiate`] copies it into
//!   another system with fresh variables (SimpleSub's generalisation and
//!   `freshenAbove`): what a callee's body says of its parameters and
//!   result, at each call independently ([`scheme`] says what it keeps).
//!
//! # Admission
//!
//! - Input: any constraints over the system's own variables; a variable
//!   of another system is refused ([`Refusal::UnknownVariable`]).
//! - Budget: [`Budget::steps`] work items; past it,
//!   [`Refusal::TooLarge`] and no solution (the caller keeps its fallback).
//! - Complexity: every entry (a bound at a variable, an edge, a decomposed
//!   pair, a merged pointer pair) is added once, in `O(log n)`, and its
//!   work is proportional to the bounds and neighbours of one variable.
//!   On realistic sets (few bounds per variable) this is near-linear in
//!   the constraints; the worst case is quadratic (every bound at every
//!   variable), which the budget bounds. The solver never makes a
//!   variable, so it terminates on any input, recursive or not.
//! - Never panics.
//!
//! # Not yet
//!
//! Struct naming, unions, arrays.

#![no_std]
#![allow(
    clippy::doc_markdown,
    reason = "BinSub and SimpleSub are the papers' names, not identifiers"
)]

extern crate alloc;

pub mod atom;
pub mod scheme;
mod solution;
mod solve;
mod term;

pub use atom::{Atom, Format, Level};
pub use scheme::Scheme;
pub use solution::{Answer, Bound, Conflict, Graph, GraphEdge, Label, Node, Solution, TermRef};
pub use solve::{Budget, Refusal};
pub use term::{
    Code, Constraint, ConstraintId, Evidence, Field, Pointer, Record, Side, Strength, System, Term,
    Var,
};
