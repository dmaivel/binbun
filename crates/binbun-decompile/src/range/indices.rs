//! The values of the indices of memory accesses: the pass [`Indices`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, Place, Stmt, StmtId, VarId};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::ir::Binary;

use super::facts::{Interval, max, min};
use super::{Ranges, Values};
use crate::pass::{L2Env, size};

/// The pass `indices`: records in [`Function::indices`] the values each
/// index of a memory access may have (`i` in a load or store at `p + k +
/// i·s`, `i << c` too, or in such a sum computed apart), read signed,
/// where they are known: what the code
/// before its statement says ([`Values::at`]), met with the range of the
/// counter of each counted loop the statement is in that the index is
/// (or extends: [`crate::range`]'s range, read as its test reads it, where
/// those values read the same as the index reads them), one step short
/// of its far end: that value only the test sees, and every statement of
/// the loop starts where the test held (`i < n`: at most `n - 1`). A
/// printer subscripts an array field with an index only where these keep
/// it in the array.
///
/// Exact: an index is recorded only where one statement alone evaluates
/// it (a node two share has the facts of neither) and that statement
/// assigns nothing within an expression (`(i = f()) + a[i]`: the facts
/// hold where the statement starts); a `for`'s `init` is outside its loop
/// (it runs before the counter's start).
///
/// Changes no statement or expression: run last, after every pass that
/// rewrites them (the ids it records stay theirs). Preserves everything.
/// Fuel: a unit per statement and expression.
#[derive(Clone, Copy, Debug, Default)]
pub struct Indices;

impl<'e> Pass<Function, L2Env<'e>> for Indices {
    fn name(&self) -> &'static str {
        "indices"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(size(function))?;
        let ranges = cx.analysis::<Ranges>(function);
        let found = proved(function, &ranges);
        if found == function.indices {
            return Ok(Changed::No);
        }
        function.indices = found;
        Ok(Changed::Yes)
    }
}

/// The indices of `function`'s accesses with the values proved for them
/// (see [`Indices`]).
fn proved(function: &Function, ranges: &Ranges) -> BTreeMap<ExprId, (i128, i128)> {
    let values = Values::new(function);
    let (owners, shared) = owners(function);
    let mut out = BTreeMap::new();
    for (stmt, loops) in placed(function) {
        let Some(owned) = owners.get(&stmt) else {
            continue;
        };
        let assigns = owned
            .iter()
            .any(|&id| matches!(function.expr(id), Some(Expr::Assign { .. })));
        if assigns {
            continue;
        }
        let stored = match function.stmt(stmt) {
            Some(&Stmt::Assign {
                place: Place::Memory { address, .. },
                ..
            }) => Some(address),
            Some(_) | None => None,
        };
        let loads = owned.iter().filter_map(|&id| match function.expr(id) {
            Some(&Expr::Load { address, .. }) => Some(address),
            Some(_) | None => None,
        });
        // An address computed apart (the exact view checks it before the
        // access: `q = p + k + i * s;`) is a sum of its own.
        let sums = owned
            .iter()
            .copied()
            .filter(|&id| matches!(function.expr(id), Some(Expr::Binary(Binary::Add, ..))));
        for address in loads.chain(stored).chain(sums) {
            for index in indices(function, address) {
                if shared.contains(&index) || !owned.contains(&index) {
                    continue;
                }
                if let Some(bounds) = bounds(function, ranges, &values, stmt, &loops, index) {
                    out.insert(index, bounds);
                }
            }
        }
    }
    out
}

/// The expressions each statement evaluates (its own, not those of the
/// statements it holds), and those more than one statement evaluates.
fn owners(function: &Function) -> (BTreeMap<StmtId, BTreeSet<ExprId>>, BTreeSet<ExprId>) {
    let mut owner: BTreeMap<ExprId, StmtId> = BTreeMap::new();
    let mut shared = BTreeSet::new();
    let mut evaluated: BTreeMap<StmtId, BTreeSet<ExprId>> = BTreeMap::new();
    let mut blocks = vec![&function.body];
    while let Some(block) = blocks.pop() {
        for &id in block {
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            let mut work = stmt.roots();
            let mut seen = BTreeSet::new();
            while let Some(at) = work.pop() {
                if !seen.insert(at) {
                    continue;
                }
                match owner.get(&at) {
                    Some(&other) if other != id => {
                        shared.insert(at);
                    }
                    Some(_) => {}
                    None => {
                        owner.insert(at, id);
                    }
                }
                evaluated.entry(id).or_default().insert(at);
                if let Some(expr) = function.expr(at) {
                    work.extend(expr.operands(function));
                }
            }
            blocks.extend(stmt.blocks());
        }
    }
    (evaluated, shared)
}

/// Every statement of `function` with the loops it is in (innermost
/// last); a `for`'s `init` is not in it.
fn placed(function: &Function) -> Vec<(StmtId, Vec<StmtId>)> {
    let mut out = Vec::new();
    let mut work: Vec<(StmtId, Vec<StmtId>)> =
        function.body.iter().map(|&id| (id, Vec::new())).collect();
    while let Some((id, loops)) = work.pop() {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        out.push((id, loops.clone()));
        let mut inside = loops.clone();
        inside.push(id);
        match stmt {
            Stmt::For {
                init, step, body, ..
            } => {
                work.extend(init.iter().map(|&inner| (inner, loops.clone())));
                work.extend(
                    step.iter()
                        .chain(body)
                        .map(|&inner| (inner, inside.clone())),
                );
            }
            Stmt::While { .. } | Stmt::DoWhile { .. } => {
                work.extend(
                    stmt.blocks()
                        .flatten()
                        .map(|&inner| (inner, inside.clone())),
                );
            }
            Stmt::If { .. }
            | Stmt::Switch { .. }
            | Stmt::Try { .. }
            | Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::VaStart { .. } => {
                work.extend(stmt.blocks().flatten().map(|&inner| (inner, loops.clone())));
            }
        }
    }
    out
}

/// The terms of address `address` that may be an index: `i` of `x + i·s`
/// or `x + (i << c)` (either side), and each side itself, below a
/// constant offset (`x + i·s + k`).
fn indices(function: &Function, address: ExprId) -> Vec<ExprId> {
    let mut top = address;
    if let Some(&Expr::Binary(Binary::Add | Binary::Sub, x, y)) = function.expr(top)
        && matches!(function.expr(y), Some(Expr::Const(_)))
    {
        top = x;
    }
    let Some(&Expr::Binary(Binary::Add, x, y)) = function.expr(top) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for term in [x, y] {
        match function.expr(term) {
            Some(&Expr::Binary(Binary::Mul | Binary::Shl, i, s))
                if matches!(function.expr(s), Some(Expr::Const(_))) =>
            {
                out.push(i);
            }
            Some(&Expr::Binary(Binary::Mul, s, i))
                if matches!(function.expr(s), Some(Expr::Const(_))) =>
            {
                out.push(i);
            }
            Some(_) | None => {}
        }
        out.push(term);
    }
    out
}

/// The values of index `index` where statement `stmt` (in `loops`) runs,
/// read signed, if anything is known of them.
fn bounds(
    function: &Function,
    ranges: &Ranges,
    values: &Values<'_>,
    stmt: StmtId,
    loops: &[StmtId],
    index: ExprId,
) -> Option<(i128, i128)> {
    let width = function.width(index)?;
    let mut known = values.at(stmt, index)?.signed;
    if let Some((var, signed, from)) = counted_read(function, index) {
        for &id in loops {
            let Some(counted) = ranges.counted(id) else {
                continue;
            };
            let Some(range) = counted.range else {
                continue;
            };
            if counted.counter != var || counted.width != from {
                continue;
            }
            // Each statement of the loop starts where its test held: one
            // step short of the range's far end, which only the test sees
            // (a counted `do`-`while`'s first test is proved at entry).
            let range = if counted.test.up {
                Interval {
                    lo: range.lo,
                    hi: range.hi - counted.delta,
                }
            } else {
                Interval {
                    lo: range.lo - counted.delta,
                    hi: range.hi,
                }
            };
            // The range is read as the test reads it: the index's reading
            // only where both readings agree.
            let same =
                counted.test.signed == signed || (range.lo >= 0 && range.hi <= max(true, from));
            if same {
                known = known.meet(range);
            }
        }
    }
    let full = Interval::full(true, width);
    (known != full
        && known.lo <= known.hi
        && known.lo >= min(true, width)
        && known.hi <= max(true, width))
    .then_some((known.lo, known.hi))
}

/// The variable `index` reads, through a sign (`true`) or zero
/// extension or none (read signed, as the index is), with the
/// variable's width.
fn counted_read(function: &Function, index: ExprId) -> Option<(VarId, bool, u16)> {
    if let Some(&Expr::Var(var)) = function.expr(index) {
        return Some((var, true, function.width(index)?));
    }
    let &Expr::Extend { value, signed, .. } = function.expr(index)? else {
        return None;
    };
    let &Expr::Var(var) = function.expr(value)? else {
        return None;
    };
    Some((var, signed, function.width(value)?))
}
