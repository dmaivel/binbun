//! Ranges of values on L2: the analysis [`Ranges`], for the loop rules
//! (rotated loops as `for`, `!=` as `<`), the `signs` pass
//! (sign-irrelevant values) and the `indices` pass ([`Indices`]: the
//! values of accesses' indices, for subscripts of array fields); and the
//! values an expression may have where
//! a statement runs ([`Values`]: the same facts, walking back from it),
//! for a front end's call arguments.
//!
//! # Counted loops
//!
//! A loop is *counted* ([`Counted`]) where
//!
//! - its step `S` is `i = i + d` (`d` a constant other than 0, read
//!   signed; `i - d` likewise) and is the last statement of the body (a
//!   `for`'s one step), so every iteration that reaches the test ran it
//!   exactly once: no `continue` in a `while` or `do`-`while` (it would
//!   skip `S`), no label in the loop (control would enter elsewhere);
//! - nothing else in the loop writes `i` (a local or parameter of at most
//!   64 bits, not in memory) or the bound `n` (a constant, or such a
//!   variable);
//! - its condition `c` compares `i` with `n`, possibly under `!`, in the
//!   direction it counts: `i != n`, `i < n`, `i <= n` counting up (`d >
//!   0`), `i != n`, `i > n`, `i >= n` counting down. The condition may
//!   read a variable bound zero or sign extended to the counter's width
//!   (`i != (uint64_t)n`): the extension's values are the variable's, a
//!   zero extension's its values read unsigned (in either reading of the
//!   wider value), a sign extension's its values read signed (read
//!   unsigned, the same where they are all of one sign, moved by `2^w`
//!   where negative; else any).
//!
//! Its canonical test `c'` ([`Test`]) is `i < n` (or `<=`; `n < i` counting
//! down), read signed or unsigned as `c` reads it; for `!=`, whichever
//! reading the facts at entry prove, unsigned first (as pointers compare;
//! where the counter's values read the same either way, the `signs` pass
//! gives the test its operands' signedness).
//!
//! **What holds at entry** comes from the code that dominates the loop,
//! found by walking back from it ([`walk::before`]): an `if` before it
//! whose one branch leaves (`if (n <= 0) return 0;` gives `n > 0`), the
//! branch of an `if` it is in, the condition of a `while` or `for` it is
//! the body of. A fact holds at the loop if nothing between writes what it
//! reads (the walk keeps the set written, and a loop around it counts as
//! writing all it writes); the walk stops at a label, where control may
//! come from elsewhere. The counter's start `k` is its last write before
//! the loop, an assignment met before any loop or other write of it. At
//! entry `i = k`, so facts about `i` are facts about `k` there. The facts
//! give intervals of variables read signed and unsigned (each refining the
//! other where they agree) and comparisons between variables
//! ([`facts::Known`]). A comparison of a constant with a zero or sign
//! extension of a variable is the comparison of the variable with the
//! constant truncated, where the constant is one of the extension's
//! values in the comparison's reading (`(uint64_t)n != 0` is `n != 0`;
//! [`facts::narrowed`]); a `do`-`while`'s first test against an extended
//! bound is so a fact about the bound's variable, for the proof and the
//! guard alike; a start `k` that is such an extension has its variable's
//! values likewise.
//!
//! **Equivalence.** `c` and `c'` agree wherever they are evaluated:
//!
//! - `c` is `c'` (or its `!` form): nothing to prove;
//! - `c` is `i != n` counting up by 1 and at the top of each iteration `k
//!   <= i < n` (in the reading of `c'`): the step writes `i + 1 <= n`, with
//!   no wrap (`i < n <= max`), so after it `i != n` exactly when `i < n`;
//!   the induction starts from `k < n` for a `do`-`while` (its first
//!   iteration is untested) and from `k <= n` for a `while` or `for` (its
//!   first test is `k != n` against `k < n`). Counting by `|d| > 1`, only
//!   where `k` and `n` are constants with `n - k` a multiple of `d` in its
//!   direction (`i` meets `n` rather than passing it). Counting down, the
//!   mirror image.
//!
//! A `do`-`while` is counted only if its first test is proved at entry
//! (`k < n`, or `k <= n` for `<=`): then `do { B; S } while (c)` runs
//! exactly as `for (; c'; S) { B }`. Its [`Counted::guard`] is the `if`
//! whose `then` it alone is, if that `if`'s condition holds for exactly
//! the values where `c'` holds at `i = k` ([`facts::equivalent`]: the same
//! comparison, or the same set of values of one variable): `if (g) do {
//! B; S } while (c)` then runs exactly as `for (; c'; S) { B }` with the
//! `if`'s decision as its first test.
//!
//! **Range.** In a counted loop the counter's values anywhere in the loop
//! (condition, body, step) lie in `[k, max(k, n - 1 + d)]` counting up
//! with `<` (`n + d` with `<=`), read as `c'` reads them, provided that
//! bound does not pass the domain's maximum (else a step could wrap, and
//! there is no range): each step happens with `i < n`, so writes at most
//! `n - 1 + d` and more than the value before. Counting down, the mirror
//! image. The bound, not written in the loop, has its values at entry
//! throughout it.
//!
//! # Sign-irrelevant values
//!
//! A value of `w` bits in `0..=2^(w-1) - 1` reads the same signed and
//! unsigned. [`Ranges::nonnegative`] says which expressions are proved
//! to be such everywhere they are evaluated:
//!
//! - a read of a counted loop's counter or bound inside the loop, where
//!   the range (the bound's interval) lies in `0..=` the signed maximum,
//!   and the read is no other statement's (an expression node shared with
//!   another statement gets no fact);
//! - a constant with its top bit clear; a zero extension; a sign extension,
//!   cast or arithmetic shift of such a value; `x % y` unsigned where `x`
//!   is one or `y` a nonzero one (the result is below both, or `x` for 0),
//!   signed where `x` is one; `x / y` unsigned where `y` is a constant of
//!   at least 2 (or 1 and `x` is one), signed where both are and `y` is a
//!   nonzero constant (a zero divisor gives all ones); a logical shift
//!   right by a nonzero constant, or of such a value; `x & y` where either
//!   is one; `x | y`, `x ^ y` and a select where both are.
//!
//! On such operands an operation's signed and unsigned forms agree: `<`,
//! `<=` (both operands), `/` and `%` (both operands, zero divisors
//! included: both give all ones and the dividend), `>>` (the shifted
//! value), extension (the value).
//!
//! # Admission
//!
//! An analysis (no change): computed on first use, linear in the
//! function's statements and expressions times the nesting depth; the walk
//! back from each loop looks at most at 256 statements, a statement lists
//! at most 64 variables it writes (more count as all), a condition gives
//! facts from at most 16 nodes. Kept by passes that change neither
//! statements nor expressions.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, Stmt, StmtId, VarId};
use binbun_semantics::core::pass::{Analyses, Analysis};
use binbun_semantics::ir::Binary;

use crate::pass::L2Env;
use crate::structure::always;

mod at;
mod counted;
mod facts;
mod indices;
mod walk;

pub use at::{Bounds, Values};
pub use counted::{Counted, Refused, Test};
pub use facts::{Interval, Term};
pub(crate) use facts::{Known, WIDEST};
pub use indices::Indices;
pub(crate) use walk::{Index, before};

/// What the loops of a function count, and which of its expressions are
/// the same read signed or unsigned (see the module's documentation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ranges {
    /// Every loop with a condition other than the constant 1: counted, or
    /// why not.
    loops: BTreeMap<StmtId, Result<Counted, Refused>>,
    /// Per expression: proved in `0..=` the signed maximum of its width.
    nonnegative: Vec<bool>,
}

impl Ranges {
    /// The ranges of `function`.
    pub fn of(function: &Function) -> Self {
        let index = Index::new(function);
        let mut loops = BTreeMap::new();
        let mut work = vec![&function.body];
        while let Some(block) = work.pop() {
            for &id in block {
                let Some(stmt) = function.stmt(id) else {
                    continue;
                };
                if let Stmt::While { condition, .. }
                | Stmt::DoWhile { condition, .. }
                | Stmt::For { condition, .. } = stmt
                    && !always(function, *condition)
                {
                    loops.insert(id, counted::counted(function, &index, id));
                }
                work.extend(stmt.blocks());
            }
        }
        let reads = Reads::new(function).free(function, &loops);
        let nonnegative = nonnegative(function, &reads);
        Self { loops, nonnegative }
    }

    /// Loop `id`'s counting, if it is counted.
    pub fn counted(&self, id: StmtId) -> Option<&Counted> {
        self.loops.get(&id).and_then(|found| found.as_ref().ok())
    }

    /// Loop `id`, counted or why not (`None`: no loop with a condition).
    pub fn outcome(&self, id: StmtId) -> Option<Result<&Counted, Refused>> {
        self.loops
            .get(&id)
            .map(|found| found.as_ref().map_err(|e| *e))
    }

    /// The counted loops.
    pub fn counters(&self) -> impl Iterator<Item = (StmtId, &Counted)> {
        self.loops
            .iter()
            .filter_map(|(&id, found)| found.as_ref().ok().map(|counted| (id, counted)))
    }

    /// Whether expression `id` (of the function as analysed) is proved to
    /// lie in `0..=` the signed maximum of its width wherever it is
    /// evaluated: the same read signed or unsigned.
    pub fn nonnegative(&self, id: ExprId) -> bool {
        self.nonnegative
            .get(id.0 as usize)
            .copied()
            .unwrap_or(false)
    }
}

impl<'e> Analysis<Function, L2Env<'e>> for Ranges {
    fn compute(
        function: &Function,
        _env: &L2Env<'e>,
        _analyses: &mut Analyses<Function, L2Env<'e>>,
    ) -> Self {
        Self::of(function)
    }
}

/// Which statement evaluates each expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    /// None does.
    None,
    /// This one alone.
    One(StmtId),
    /// More than one.
    Shared,
}

/// The expressions' owners.
struct Reads {
    owners: Vec<Owner>,
}

impl Reads {
    fn new(function: &Function) -> Self {
        let mut owners = vec![Owner::None; function.exprs.len()];
        let mut statements = vec![&function.body];
        while let Some(block) = statements.pop() {
            for &id in block {
                let Some(stmt) = function.stmt(id) else {
                    continue;
                };
                let mut work = stmt.roots();
                while let Some(at) = work.pop() {
                    let Some(owner) = owners.get_mut(at.0 as usize) else {
                        continue;
                    };
                    *owner = match *owner {
                        Owner::One(other) if other == id => continue,
                        Owner::None => Owner::One(id),
                        Owner::One(_) | Owner::Shared => Owner::Shared,
                    };
                    if let Some(expr) = function.expr(at) {
                        work.extend(expr.operands(function));
                    }
                }
                statements.extend(stmt.blocks());
            }
        }
        Self { owners }
    }

    /// Per expression: a read of a counted loop's sign-free counter or
    /// bound that a statement of that loop alone evaluates.
    fn free(
        &self,
        function: &Function,
        loops: &BTreeMap<StmtId, Result<Counted, Refused>>,
    ) -> Vec<bool> {
        let mut free = vec![false; function.exprs.len()];
        for (&id, found) in loops {
            let Ok(counted) = found else {
                continue;
            };
            let mut vars: Vec<VarId> = Vec::new();
            if counted.counter_free {
                vars.push(counted.counter);
            }
            if counted.bound_free
                && let Term::Var(bound) = counted.bound
            {
                vars.push(bound);
            }
            if vars.is_empty() {
                continue;
            }
            for stmt in inside(function, id) {
                let Some(roots) = function.stmt(stmt).map(Stmt::roots) else {
                    continue;
                };
                let mut work = roots;
                while let Some(at) = work.pop() {
                    if self.owners.get(at.0 as usize) != Some(&Owner::One(stmt)) {
                        continue;
                    }
                    match function.expr(at) {
                        Some(Expr::Var(var)) if vars.contains(var) => {
                            if let Some(slot) = free.get_mut(at.0 as usize) {
                                *slot = true;
                            }
                        }
                        Some(expr) => work.extend(expr.operands(function)),
                        None => {}
                    }
                }
            }
        }
        free
    }
}

/// The statements of loop `id` evaluated on each iteration: itself (its
/// condition), its body's and its step's (not a `for`'s `init`), and
/// those they hold.
fn inside(function: &Function, id: StmtId) -> Vec<StmtId> {
    let mut out = vec![id];
    let mut work: Vec<StmtId> = match function.stmt(id) {
        Some(Stmt::For { step, body, .. }) => step.iter().chain(body).copied().collect(),
        Some(Stmt::While { body, .. } | Stmt::DoWhile { body, .. }) => body.clone(),
        Some(_) | None => Vec::new(),
    };
    while let Some(at) = work.pop() {
        out.push(at);
        if let Some(stmt) = function.stmt(at) {
            work.extend(stmt.blocks().flatten().copied());
        }
    }
    out
}

/// Per expression of `function`: proved in `0..=` the signed maximum of
/// its width (`free`: the reads proved so), operands first (they are below
/// their expression).
fn nonnegative(function: &Function, free: &[bool]) -> Vec<bool> {
    let mut known: Vec<bool> = Vec::with_capacity(function.exprs.len());
    for (index, expr) in function.exprs.iter().enumerate() {
        let read = free.get(index).copied().unwrap_or(false);
        let value = node_nonnegative(function, expr, read, &|id: ExprId| {
            known.get(id.0 as usize).copied().unwrap_or(false)
        });
        known.push(value);
    }
    known
}

/// Whether `expr` (of `function`) is proved in `0..=` the signed maximum
/// of its width, given which of its operands are (`is`) and, for a
/// variable's read, whether the read is (`read`).
pub(crate) fn node_nonnegative(
    function: &Function,
    expr: &Expr,
    read: bool,
    is: &dyn Fn(ExprId) -> bool,
) -> bool {
    let constant = |id: ExprId| match function.expr(id) {
        Some(Expr::Const(bits)) if bits.width() <= 64 => Some(bits.low_u64()),
        _ => None,
    };
    let small = |id: ExprId| matches!(function.expr(id), Some(Expr::Const(bits)) if !bits.msb() && !bits.is_zero());
    match *expr {
        Expr::Const(bits) => !bits.msb(),
        Expr::Var(_) => read,
        Expr::Extend { signed: false, .. } => true,
        Expr::Extend {
            signed: true,
            value,
            ..
        }
        | Expr::Cast { value, .. } => is(value),
        Expr::Binary(op, a, b) => match op {
            Binary::URem => is(a) || small(b),
            Binary::SRem | Binary::AShr => is(a),
            Binary::UDiv => constant(b).is_some_and(|d| d >= 2 || (d == 1 && is(a))),
            Binary::SDiv => is(a) && small(b),
            Binary::LShr => constant(b).is_some_and(|d| d >= 1) || is(a),
            Binary::And => is(a) || is(b),
            Binary::Or | Binary::Xor => is(a) && is(b),
            Binary::Add
            | Binary::Sub
            | Binary::Mul
            | Binary::Shl
            | Binary::Rol
            | Binary::Ror
            | Binary::Eq
            | Binary::Ne
            | Binary::ULt
            | Binary::ULe
            | Binary::SLt
            | Binary::SLe => false,
        },
        Expr::Select {
            then, otherwise, ..
        } => is(then) && is(otherwise),
        Expr::Undefined(..)
        | Expr::AddressOf(_)
        | Expr::Unary(..)
        | Expr::Logical(..)
        | Expr::Flag(..)
        | Expr::Extract { .. }
        | Expr::Concat { .. }
        | Expr::Lanes { .. }
        | Expr::Float { .. }
        | Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Exception { .. }
        | Expr::Assign { .. } => false,
    }
}
