//! Code both arms of an `if` begin or end with: [`CommonArms`].

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{Block, Callee, Expr, ExprId, Function, Origin, Place, Stmt, StmtId, VarId};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};

use super::refine::negate;
use crate::pass::{L2Env, size};
use crate::simplify::expr::{in_memory, same};

/// Code both arms share (pass `common-arms`), on a structured function,
/// inner statements first: of an `if (c) { A; T; Z } else { A; E; Z }`,
///
/// - the statements both arms begin with (`A`: one by one, the same
///   assignment or call, [`same`] trees; one arm's first where it is among
///   the other's first few, after assignments and calls it does not
///   depend on and that do not depend on it: `v81 = K; v84 = K; …` and
///   `v84 = K; …` both begin with `v84 = K`) go before the `if` where that is
///   equivalent: `c` makes no call and assigns nothing, reads no variable
///   `A` writes, and, where it reads memory (a load, a variable in memory),
///   `A` neither reads nor writes memory nor calls (a store or a call
///   could change what `c` reads; a load ahead of `c`'s could fault in its
///   stead). `c` changes nothing, so `A` reads the same values before it;
/// - the statements both arms end with (`Z`) go after the `if`: both are
///   assignments or calls, which go on to the `if`'s end, so `Z` runs
///   there on every path through an arm (a `goto` to a label in an arm
///   before `Z` reaches it too, after the arm); paths leaving an arm
///   otherwise skip `Z` either way;
///
/// but never both arms' last statement: `if (c) {} else {}` would say
/// nothing. An arm left empty goes: `if (c) {} else B` is `if (!c) B`.
/// `if (n <= 0) w = 0; else { w = 0; i = 0; do { … } while (…); }` is `w
/// = 0; if (!(n <= 0)) { i = 0; do { … } while (…); }`, which the loop
/// rules can read as a `for` ([`super::Loops`]).
///
/// A statement moved keeps one arm's and takes the other's origins (a
/// call the L1 call values of both, so it stands for either L1 call; each
/// expression the other's matching one's instructions), but names no block: its
/// blocks' code no longer runs where they do (an arm's block may now
/// have no code; control passes through it to its jump's target, which
/// the structure check contracts), and it runs as the copies on an edge
/// do, which the structure check passes through.
///
/// Preserves nothing. Fuel: a unit per statement and expression.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommonArms;

impl<'e> Pass<Function, L2Env<'e>> for CommonArms {
    fn name(&self) -> &'static str {
        "common-arms"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(size(function))?;
        let mut changed = false;
        let body = mem::take(&mut function.body);
        function.body = block(function, body, &mut changed);
        Ok(changed.into())
    }
}

/// `block` with the blocks its statements hold done first, then each `if`.
fn block(function: &mut Function, block: Block, changed: &mut bool) -> Block {
    let mut out = Vec::with_capacity(block.len());
    for id in block {
        let taken: Vec<Block> = function
            .stmts
            .get_mut(id.0 as usize)
            .map(|stmt| stmt.blocks_mut().map(mem::take).collect())
            .unwrap_or_default();
        let done: Vec<Block> = taken
            .into_iter()
            .map(|inner| self::block(function, inner, changed))
            .collect();
        if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
            for (slot, inner) in stmt.blocks_mut().zip(done) {
                *slot = inner;
            }
        }
        shared(function, id, &mut out, changed);
    }
    out
}

/// `if` statement `id` (any other statement as it is) into `out`, with the
/// statements both its arms begin with before it and those both end with
/// after it.
fn shared(function: &mut Function, id: StmtId, out: &mut Block, changed: &mut bool) {
    let Some(Stmt::If {
        condition,
        then,
        otherwise,
    }) = function.stmt(id)
    else {
        out.push(id);
        return;
    };
    let (mut condition, mut then, mut otherwise) = (*condition, then.clone(), otherwise.clone());
    let test = Effects::of_expr(function, condition);
    let mut before = Vec::new();
    while then.len() + otherwise.len() > 2
        && let Some((i, j)) = common_start(function, &then, &otherwise)
        && let (Some(&a), Some(&b)) = (then.get(i), otherwise.get(j))
        && hoists(&Effects::of_stmt(function, a), &test)
    {
        merge(function, a, b);
        before.push(a);
        then.remove(i);
        otherwise.remove(j);
    }
    let mut after = Vec::new();
    while let (Some(&a), Some(&b)) = (then.last(), otherwise.last())
        && then.len() + otherwise.len() > 2
        && same_stmt(function, a, b)
    {
        merge(function, a, b);
        after.push(a);
        then.pop();
        otherwise.pop();
    }
    after.reverse();
    if before.is_empty() && after.is_empty() {
        out.push(id);
        return;
    }
    *changed = true;
    if then.is_empty() {
        condition = negate(function, condition);
        then = mem::take(&mut otherwise);
    }
    if let Some(slot) = function.stmts.get_mut(id.0 as usize) {
        *slot = Stmt::If {
            condition,
            then,
            otherwise,
        };
    }
    out.extend(before);
    out.push(id);
    out.extend(after);
}

/// How many statements of an arm [`common_start`] looks past.
const AHEAD: usize = 4;

/// Where `then` and `otherwise` begin with the same statement: their
/// first ones, or one's first and the other's statement that could be
/// its first (at most [`AHEAD`] in; [`leads`]). The positions in each.
fn common_start(
    function: &Function,
    then: &[StmtId],
    otherwise: &[StmtId],
) -> Option<(usize, usize)> {
    let (&a, &b) = (then.first()?, otherwise.first()?);
    if same_stmt(function, a, b) {
        return Some((0, 0));
    }
    let later = |first: StmtId, arm: &[StmtId]| {
        (1..arm.len().min(AHEAD + 1)).find(|&at| {
            arm.get(at)
                .is_some_and(|&found| same_stmt(function, first, found))
                && leads(function, arm, at)
        })
    };
    later(a, otherwise)
        .map(|at| (0, at))
        .or_else(|| later(b, then).map(|at| (at, 0)))
}

/// Whether `arm[at]` may run first in `arm`: it and each statement
/// before it are assignments or calls of which neither writes a variable
/// the other reads or writes, nor changes memory the other reads or
/// changes (a call does both).
fn leads(function: &Function, arm: &[StmtId], at: usize) -> bool {
    let Some(&moved) = arm.get(at) else {
        return false;
    };
    let plain = |id: StmtId| {
        matches!(
            function.stmt(id),
            Some(Stmt::Assign { .. } | Stmt::Call { .. })
        )
    };
    let own = Effects::of_stmt(function, moved);
    plain(moved)
        && arm.iter().take(at).all(|&earlier| {
            let other = Effects::of_stmt(function, earlier);
            plain(earlier)
                && own.writes.is_disjoint(&other.reads)
                && own.writes.is_disjoint(&other.writes)
                && other.writes.is_disjoint(&own.reads)
                && !(own.changes && (other.loads || other.changes))
                && !(other.changes && own.loads)
        })
}

/// Whether statements `a` and `b` do the same: assignments of the same
/// tree to the same place, or calls of the same callee with the same
/// arguments and results, none reading an undefined value (two may
/// differ) or an exception value.
fn same_stmt(function: &Function, a: StmtId, b: StmtId) -> bool {
    let defined = |id: StmtId| {
        let mut work = function.stmt(id).map(Stmt::roots).unwrap_or_default();
        while let Some(at) = work.pop() {
            match function.expr(at) {
                Some(Expr::Undefined(..) | Expr::Exception { .. }) | None => return false,
                Some(expr) => work.extend(expr.operands(function)),
            }
        }
        true
    };
    if !defined(a) || !defined(b) {
        return false;
    }
    match (function.stmt(a), function.stmt(b)) {
        (
            Some(&Stmt::Assign { place, value }),
            Some(&Stmt::Assign {
                place: other,
                value: its,
            }),
        ) => same_place(function, place, other) && same(function, value, its),
        (
            Some(Stmt::Call { results, call }),
            Some(Stmt::Call {
                results: others,
                call: its,
            }),
        ) => {
            let callee = match (call.callee, its.callee) {
                (Callee::Expr(x), Callee::Expr(y)) => same(function, x, y),
                (x, y) => x == y,
            };
            callee
                && call.signature == its.signature
                && call.variadic == its.variadic
                && call.arguments.len() == its.arguments.len()
                && call
                    .arguments
                    .iter()
                    .zip(&its.arguments)
                    .all(|(&x, &y)| same(function, x, y))
                && results.len() == others.len()
                && results
                    .iter()
                    .zip(others)
                    .all(|(&x, &y)| same_place(function, x, y))
        }
        _ => false,
    }
}

/// Whether places `a` and `b` are the same: one variable, or the same
/// type at the same address tree.
fn same_place(function: &Function, a: Place, b: Place) -> bool {
    match (a, b) {
        (Place::Var(x), Place::Var(y)) => x == y,
        (
            Place::Memory { address, ty },
            Place::Memory {
                address: other,
                ty: its,
            },
        ) => ty == its && same(function, address, other),
        (Place::Var(_), Place::Memory { .. }) | (Place::Memory { .. }, Place::Var(_)) => false,
    }
}

/// What evaluating an expression or running a statement may read and
/// change.
#[derive(Debug, Default)]
struct Effects {
    /// The variables not in memory it reads.
    reads: BTreeSet<VarId>,
    /// The variables not in memory it writes.
    writes: BTreeSet<VarId>,
    /// Whether it reads memory: a load, a variable in memory, a call.
    loads: bool,
    /// Whether it writes memory, assigns or calls.
    changes: bool,
}

impl Effects {
    /// What evaluating `root` does.
    fn of_expr(function: &Function, root: ExprId) -> Self {
        let mut effects = Self::default();
        effects.expr(function, root);
        effects
    }

    /// What statement `id` does: an assignment or a call (any other: all).
    fn of_stmt(function: &Function, id: StmtId) -> Self {
        let mut effects = Self::default();
        match function.stmt(id) {
            Some(&Stmt::Assign { place, value }) => {
                effects.expr(function, value);
                effects.place(function, place);
            }
            Some(Stmt::Call { results, call }) => {
                for operand in call.operands() {
                    effects.expr(function, operand);
                }
                for &place in results {
                    effects.place(function, place);
                }
                effects.loads = true;
                effects.changes = true;
            }
            Some(_) | None => {
                effects.loads = true;
                effects.changes = true;
            }
        }
        effects
    }

    /// Adds a write of `place`.
    fn place(&mut self, function: &Function, place: Place) {
        match place {
            Place::Var(var) if !in_memory(function, var) => {
                self.writes.insert(var);
            }
            Place::Var(_) => self.changes = true,
            Place::Memory { address, .. } => {
                self.expr(function, address);
                self.changes = true;
            }
        }
    }

    /// Adds what evaluating `root` does.
    fn expr(&mut self, function: &Function, root: ExprId) {
        let mut work = vec![root];
        while let Some(id) = work.pop() {
            let Some(expr) = function.expr(id) else {
                continue;
            };
            match *expr {
                Expr::Var(var) if in_memory(function, var) => self.loads = true,
                Expr::Var(var) => {
                    self.reads.insert(var);
                }
                Expr::Load { .. } | Expr::Exception { .. } => self.loads = true,
                Expr::Call(_) => {
                    self.loads = true;
                    self.changes = true;
                }
                Expr::Assign { var, .. } => {
                    self.writes.insert(var);
                    self.changes = true;
                }
                Expr::Const(_)
                | Expr::Undefined(..)
                | Expr::AddressOf(_)
                | Expr::Unary(..)
                | Expr::Binary(..)
                | Expr::Logical(..)
                | Expr::Flag(..)
                | Expr::Extract { .. }
                | Expr::Concat { .. }
                | Expr::Extend { .. }
                | Expr::Select { .. }
                | Expr::Lanes { .. }
                | Expr::Float { .. }
                | Expr::Cast { .. } => {}
            }
            work.extend(expr.operands(function));
        }
    }
}

/// Whether a statement doing `moved` may run before a condition doing
/// `test` (see [`CommonArms`]).
fn hoists(moved: &Effects, test: &Effects) -> bool {
    !test.changes
        && test.writes.is_empty()
        && moved.writes.is_disjoint(&test.reads)
        && !(test.loads && (moved.loads || moved.changes))
}

/// Statement `kept` standing for itself and `dropped` (the same, by
/// [`same_stmt`]): it takes `dropped`'s origins, each expression its match's
/// in `dropped`, and names no block.
fn merge(function: &mut Function, kept: StmtId, dropped: StmtId) {
    let mut pairs: Vec<(ExprId, ExprId)> = match (function.stmt(kept), function.stmt(dropped)) {
        (Some(x), Some(y)) => x.roots().into_iter().zip(y.roots()).collect(),
        _ => Vec::new(),
    };
    while let Some((x, y)) = pairs.pop() {
        if x == y {
            continue;
        }
        let origins = function.provenance.expr(y).to_vec();
        function.provenance.absorb_expr(x, &origins);
        if let (Some(&a), Some(&b)) = (function.expr(x), function.expr(y)) {
            pairs.extend(a.operands(function).zip(b.operands(function)));
        }
    }
    let mut origins: Vec<Origin> = Vec::new();
    for &origin in function
        .provenance
        .stmt(kept)
        .iter()
        .chain(function.provenance.stmt(dropped))
    {
        if !matches!(origin, Origin::Block(_) | Origin::Proved) && !origins.contains(&origin) {
            origins.push(origin);
        }
    }
    function.provenance.set_stmt(kept, &origins);
}
