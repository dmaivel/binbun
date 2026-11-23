//! The pass `short-circuit`: an `if` whose arm is only another block's
//! `if`, with an arm in common, becomes one `if` on `&&` or `||`
//! ([`Expr::Logical`]).
//!
//! With `a` the outer condition (block A's decision) and `b` the inner
//! one (block B's), and "≡" meaning the same place (two empty arms, both
//! going on after the outer `if`; or the same `goto`, `break` or
//! `continue`):
//!
//! - `if (a) { if (b) T else F } else E`: `if (a && b) T else F` where
//!   `E ≡ F`, `if (!a || b) T else F` where `E ≡ T`;
//! - `if (a) T' else { if (b) T else F }`: `if (a || b) T else F` where
//!   `T' ≡ T`, `if (!a && b) T else F` where `T' ≡ F`;
//! - `if (a) J; if (b) T else F` (`J` a jump, so the second `if` is the
//!   first's `else`): as the second form;
//! - `while (a) { if (d) break; … }` (of that loop): `while (a && !d) { … }`.
//!
//! Each is exact. The inner `if` is all of B's code (B's first statement
//! is its decision: nothing between needs a statement, and nothing else
//! enters B there, as a label would sit before it), and C's `&&`/`||`
//! evaluate `b` exactly when B's decision ran: when `a` did not decide.
//! So a load in `b` faults, and a call in it is made, exactly when it was
//! before, after what `a` evaluates (C orders `&&`'s and `||`'s left
//! operand before the right: L2's ordering rule,
//! [`binbun_ast::verify::ordered`], holds by construction). The
//! merged condition's `b` is a copy of its root node with B's
//! `Origin::Block` (and the inner `if`'s other origins), so the structure
//! check ([`crate::validate::structure`]) still sees B's decision, now as
//! the right operand. A merge never makes a condition of more than
//! [`ShortCircuit::operands`] operands; inner `if`s merge first.

use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{Block, Expr, ExprId, Function, Logical, Origin, Stmt, StmtId};
use binbun_ast::verify::single;
use binbun_semantics::core::pass::{self, Changed, Cx, Pass};
use binbun_semantics::ir::Unary;
use binbun_ssa::ir::BlockId;

use super::refine::{always, negate};
use crate::pass::{L2Env, size};

/// Statements nested deeper than this are left as they are.
const DEPTH: usize = 1000;

/// The pass `short-circuit` (see the module documentation). It preserves
/// nothing. Fuel: a unit per statement and expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortCircuit {
    /// The most operands (conditions that are not `&&` or `||`) a merged
    /// condition may have. 8 by default.
    pub operands: usize,
    merged: usize,
}

impl Default for ShortCircuit {
    fn default() -> Self {
        Self::new(8)
    }
}

impl ShortCircuit {
    /// The pass, merging up to `operands` operands into a condition.
    pub fn new(operands: usize) -> Self {
        Self {
            operands,
            merged: 0,
        }
    }

    /// How many `if`s its last run merged into another's condition.
    pub fn merged(&self) -> usize {
        self.merged
    }
}

impl<'e> Pass<Function, L2Env<'e>> for ShortCircuit {
    fn name(&self) -> &'static str {
        "short-circuit"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, pass::Refusal> {
        self.merged = 0;
        cx.fuel.spend(size(function))?;
        let mut merger = Merger {
            function,
            operands: self.operands,
            merged: 0,
        };
        let body = mem::take(&mut merger.function.body);
        merger.function.body = merger.block(body, 0);
        self.merged = merger.merged;
        Ok(if self.merged > 0 {
            Changed::Yes
        } else {
            Changed::No
        })
    }
}

/// The block among `origins`, if one.
fn block_among(origins: &[Origin]) -> Option<BlockId> {
    origins.iter().find_map(|origin| match *origin {
        Origin::Block(block) => Some(block),
        Origin::Value(_)
        | Origin::Instruction(_)
        | Origin::Register(_)
        | Origin::Held(_)
        | Origin::Slot(_)
        | Origin::Absorbed(_)
        | Origin::Proved => None,
    })
}

/// An `if` statement's parts, and the block it decides.
struct If<'a> {
    condition: ExprId,
    then: &'a [StmtId],
    otherwise: &'a [StmtId],
    block: BlockId,
}

/// A merge: whether the outer condition is negated, the operator, and the
/// inner `if` (whose arms the merged one takes) and its condition.
struct Merge {
    negated: bool,
    op: Logical,
    inner: StmtId,
    condition: ExprId,
}

struct Merger<'f> {
    function: &'f mut Function,
    operands: usize,
    merged: usize,
}

impl Merger<'_> {
    fn set(&mut self, id: StmtId, stmt: Stmt) {
        if let Some(slot) = self.function.stmts.get_mut(id.0 as usize) {
            *slot = stmt;
        }
    }

    /// `block` with its statements' blocks merged first, then its own
    /// statements.
    fn block(&mut self, block: Block, depth: usize) -> Block {
        if depth < DEPTH {
            for &id in &block {
                let Some(slot) = self.function.stmts.get_mut(id.0 as usize) else {
                    continue;
                };
                let mut stmt = mem::replace(slot, Stmt::Unreachable);
                for inner in stmt.blocks_mut() {
                    let taken = mem::take(inner);
                    *inner = self.block(taken, depth + 1);
                }
                self.set(id, stmt);
            }
        }
        let mut out: Block = Vec::with_capacity(block.len());
        for id in block {
            out.push(id);
            while let Some(&last) = out.last() {
                if self.nested(last) || self.head(last) {
                    continue;
                }
                let Some(&previous) = out.len().checked_sub(2).and_then(|i| out.get(i)) else {
                    break;
                };
                if !self.sequential(previous, last) {
                    break;
                }
                out.pop();
            }
        }
        out
    }

    /// Statement `id` if it is an `if` of a block: its parts.
    fn branch(&self, id: StmtId) -> Option<If<'_>> {
        let Some(Stmt::If {
            condition,
            then,
            otherwise,
        }) = self.function.stmt(id)
        else {
            return None;
        };
        Some(If {
            condition: *condition,
            then,
            otherwise,
            block: block_among(self.function.provenance.stmt(id))?,
        })
    }

    /// Whether `a` and `b` go to the same place: both empty (on after
    /// the same statement), or the same `goto`, `break` or `continue`.
    fn same(&self, a: &[StmtId], b: &[StmtId]) -> bool {
        match (a, b) {
            ([], []) => true,
            ([a], [b]) => {
                matches!(
                    (self.function.stmt(*a), self.function.stmt(*b)),
                    (Some(Stmt::Goto(x)), Some(Stmt::Goto(y))) if x == y
                ) || matches!(
                    (self.function.stmt(*a), self.function.stmt(*b)),
                    (Some(Stmt::Break(x)), Some(Stmt::Break(y))) | (Some(Stmt::Continue(x)), Some(Stmt::Continue(y))) if x == y
                )
            }
            _ => false,
        }
    }

    /// Whether `block` is one jump (control never goes on after it).
    fn jump(&self, block: &[StmtId]) -> bool {
        matches!(block, [only] if matches!(
            self.function.stmt(*only),
            Some(Stmt::Goto(_) | Stmt::Break(_) | Stmt::Continue(_))
        ))
    }

    /// How many operands `expr` has as a condition.
    fn count(&self, expr: ExprId) -> usize {
        let mut count = 0;
        let mut work = vec![expr];
        while let Some(at) = work.pop() {
            match self.function.expr(at) {
                Some(&Expr::Logical(_, a, b)) => work.extend([a, b]),
                Some(&Expr::Unary(Unary::Not, a))
                    if matches!(self.function.expr(a), Some(Expr::Logical(..))) =>
                {
                    work.push(a);
                }
                Some(_) | None => count += 1,
            }
        }
        count
    }

    /// The merge of `outer` with the `if` that is its arm `inner` (`then`:
    /// its `then` arm; else its `else`).
    fn pick(&self, outer: &If<'_>, inner: StmtId, in_then: bool) -> Option<Merge> {
        let arms = self.branch(inner)?;
        if arms.block == outer.block
            || self.count(outer.condition) + self.count(arms.condition) > self.operands
        {
            return None;
        }
        let other = if in_then { outer.otherwise } else { outer.then };
        // In `then`, `a && b` shares `else`; in `else`, `a || b` shares
        // `then`; with the outer condition negated, the other arm.
        let (negated, op) = match (
            in_then,
            self.same(other, arms.otherwise),
            self.same(other, arms.then),
        ) {
            (true, true, _) => (false, Logical::And),
            (true, false, true) => (true, Logical::Or),
            (false, _, true) => (false, Logical::Or),
            (false, true, false) => (true, Logical::And),
            (true | false, false, false) => return None,
        };
        Some(Merge {
            negated,
            op,
            inner,
            condition: arms.condition,
        })
    }

    /// Merges `if` statement `id` with the `if` that is all of one of its
    /// arms, if they share an arm.
    fn nested(&mut self, id: StmtId) -> bool {
        let Some(outer) = self.branch(id) else {
            return false;
        };
        let merge = match outer.then {
            [inner] => self.pick(&outer, *inner, true),
            _ => None,
        }
        .or_else(|| match outer.otherwise {
            [inner] => self.pick(&outer, *inner, false),
            _ => None,
        });
        let condition = outer.condition;
        let Some(merge) = merge else {
            return false;
        };
        self.apply(id, condition, &merge)
    }

    /// Merges `if (a) J;` (`previous`) with the `if` after it (`last`):
    /// that `if` is its `else`.
    fn sequential(&mut self, previous: StmtId, last: StmtId) -> bool {
        let Some(outer) = self.branch(previous) else {
            return false;
        };
        if !outer.otherwise.is_empty() || !self.jump(outer.then) {
            return false;
        }
        let condition = outer.condition;
        let Some(merge) = self.pick(&outer, last, false) else {
            return false;
        };
        self.apply(previous, condition, &merge)
    }

    /// `while (a) { if (d) break; … }` (statement `id`) →
    /// `while (a && !d) { … }`.
    fn head(&mut self, id: StmtId) -> bool {
        let Some(Stmt::While { condition, body }) = self.function.stmt(id) else {
            return false;
        };
        let condition = *condition;
        let origins = self.function.provenance.stmt(id);
        // A loop the loop rules made of a guard and a latch (two blocks),
        // or whose first test is proved, decides at entry otherwise than
        // at each iteration: `!d` would be tested at entry too.
        let blocks = origins
            .iter()
            .filter(|origin| matches!(origin, Origin::Block(_)))
            .count();
        if blocks > 1 || origins.contains(&Origin::Proved) {
            return false;
        }
        let (Some(block), Some(&first)) = (block_among(origins), body.first()) else {
            return false;
        };
        if always(self.function, condition) {
            return false;
        }
        let Some(test) = self.branch(first) else {
            return false;
        };
        let leaves =
            matches!(test.then, [only] if self.function.stmt(*only) == Some(&Stmt::Break(id)));
        if !leaves
            || !test.otherwise.is_empty()
            || test.block == block
            || self.count(condition) + self.count(test.condition) > self.operands
        {
            return false;
        }
        let test = test.condition;
        let right = self.operand(first, test);
        let right = negate(self.function, right);
        let merged = self.join(Logical::And, condition, right);
        if single(self.function, &[merged]).is_err() {
            return false;
        }
        let Some(Stmt::While { condition, body }) = self.function.stmts.get_mut(id.0 as usize)
        else {
            return false;
        };
        *condition = merged;
        body.remove(0);
        self.merged += 1;
        true
    }

    /// A copy of the root of condition `expr` of `if` statement `stmt`,
    /// with the statement's origins (its block) unless it names a block
    /// of its own.
    fn operand(&mut self, stmt: StmtId, expr: ExprId) -> ExprId {
        let Some(&node) = self.function.expr(expr) else {
            return expr;
        };
        let mut origins = self.function.provenance.expr(expr).to_vec();
        if block_among(&origins).is_none() {
            origins.extend_from_slice(self.function.provenance.stmt(stmt));
        }
        let id = self.function.add_expr(node);
        self.function.provenance.set_expr(id, &origins);
        id
    }

    /// `left op right`, nested to the left where `right` is an `op` too
    /// (`a && (b && c)` as `a && b && c`, the same evaluation), each of
    /// `right`'s operands keeping the block it stood for.
    fn join(&mut self, op: Logical, left: ExprId, right: ExprId) -> ExprId {
        if let Some(&Expr::Logical(inner, x, y)) = self.function.expr(right)
            && inner == op
        {
            let origins = self.function.provenance.expr(right).to_vec();
            let x = self.retag(x, &origins);
            let y = self.retag(y, &origins);
            let left = self.join(op, left, x);
            return self.function.add_expr(Expr::Logical(op, left, y));
        }
        self.function.add_expr(Expr::Logical(op, left, right))
    }

    /// `expr`, or a copy of its root with `origins` added where they name
    /// a block it inherited (it names none of its own).
    fn retag(&mut self, expr: ExprId, origins: &[Origin]) -> ExprId {
        let own = self.function.provenance.expr(expr);
        let Some(&node) = self.function.expr(expr) else {
            return expr;
        };
        if block_among(origins).is_none() || block_among(own).is_some() {
            return expr;
        }
        let mut all = own.to_vec();
        all.extend_from_slice(origins);
        let id = self.function.add_expr(node);
        self.function.provenance.set_expr(id, &all);
        id
    }

    /// Makes `if` statement `id` (condition `condition`) the merge with
    /// its inner `if`, whose arms it takes (the inner one, unused, left
    /// without them).
    fn apply(&mut self, id: StmtId, condition: ExprId, merge: &Merge) -> bool {
        if !matches!(self.function.stmt(merge.inner), Some(Stmt::If { .. })) {
            return false;
        }
        let left = if merge.negated {
            negate(self.function, condition)
        } else {
            condition
        };
        let right = self.operand(merge.inner, merge.condition);
        let mut condition = self.join(merge.op, left, right);
        // An assignment expression's variable is read in a node of its
        // own after it: the two conditions may share one.
        if single(self.function, &[condition]).is_err() {
            return false;
        }
        let Some(Stmt::If {
            then, otherwise, ..
        }) = self.function.stmts.get_mut(merge.inner.0 as usize)
        else {
            return false;
        };
        let (mut then, mut otherwise) = (mem::take(then), mem::take(otherwise));
        if then.is_empty() && !otherwise.is_empty() {
            condition = negate(self.function, condition);
            mem::swap(&mut then, &mut otherwise);
        }
        self.set(
            id,
            Stmt::If {
                condition,
                then,
                otherwise,
            },
        );
        self.merged += 1;
        true
    }
}
