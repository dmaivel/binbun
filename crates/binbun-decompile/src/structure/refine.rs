//! Refinement: `if`s turned so that code un-nests, `while (c)` and
//! `do`-`while` from `while (1)`. Runs on the schemas' output, whose
//! nesting is bounded by [`Options::depth`](super::Options), so its
//! recursion is too.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{Block, Expr, ExprId, Function, LabelId, Logical, Origin, Stmt, StmtId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, Unary};

use super::cfg::stops;
use super::flow::Flow;

/// Refines `function`'s body.
pub(super) fn refine(function: &mut Function) {
    // First, so that one does not hide a loop's first or last test.
    drop_empty_ifs(function);
    let named = Flow::of(function);
    let body = mem::take(&mut function.body);
    function.body = block(function, body, &named);
    drop_empty_ifs(function);
}

/// How many times [`drop_empty_ifs`] looks again (an `if` left holding
/// only one it dropped is empty in turn).
const EMPTIED: usize = 8;

/// Drops the `if`s of `function` whose arms are both empty (both ways of
/// a branch reach the same place with nothing to do on either: a
/// rotate's test of its count for 0, a `goto` folded into falling
/// through): the statement goes where its condition neither loads, calls
/// nor assigns, else the condition stays, evaluated and dropped (it may
/// fault, or have an effect). Whether it dropped any.
pub(super) fn drop_empty_ifs(function: &mut Function) -> bool {
    let mut changed = false;
    for _ in 0..EMPTIED {
        let mut gone = BTreeSet::new();
        let mut kept = Vec::new();
        let mut holders = Vec::new();
        let mut work = function.body.clone();
        while let Some(id) = work.pop() {
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            if let Stmt::If {
                condition,
                then,
                otherwise,
            } = stmt
                && then.is_empty()
                && otherwise.is_empty()
            {
                if quiet(function, *condition) {
                    gone.insert(id);
                } else {
                    kept.push((id, *condition));
                }
                continue;
            }
            let before = work.len();
            work.extend(stmt.blocks().flatten().copied());
            if work.len() > before {
                holders.push(id);
            }
        }
        if gone.is_empty() && kept.is_empty() {
            break;
        }
        changed = true;
        for (id, condition) in kept {
            set(function, id, Stmt::Expr(condition));
        }
        function.body.retain(|id| !gone.contains(id));
        for id in holders {
            if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
                for block in stmt.blocks_mut() {
                    block.retain(|id| !gone.contains(id));
                }
            }
        }
        if gone.is_empty() {
            break;
        }
    }
    changed
}

/// Whether evaluating `condition` neither loads, calls nor assigns: it
/// cannot fault and changes nothing.
fn quiet(function: &Function, condition: ExprId) -> bool {
    let mut work = alloc::vec![condition];
    while let Some(id) = work.pop() {
        match function.expr(id) {
            Some(
                Expr::Load { .. } | Expr::Call(_) | Expr::Assign { .. } | Expr::Exception { .. },
            )
            | None => return false,
            Some(expr) => work.extend(expr.operands(function)),
        }
    }
    true
}

/// Whether `condition` is the constant 1.
pub(crate) fn always(function: &Function, condition: ExprId) -> bool {
    matches!(function.expr(condition), Some(Expr::Const(bits)) if *bits == Bits::from_u64(1, 1))
}

/// Whether control may go off the end of `block` (`broken`: the loops a
/// `break` names). Conservative: `true` unless its last statement never
/// goes on.
pub(super) fn falls(function: &Function, block: &[StmtId], broken: &BTreeSet<StmtId>) -> bool {
    let Some(&last) = block.last() else {
        return true;
    };
    match function.stmt(last) {
        Some(Stmt::Goto(_) | Stmt::Break(_) | Stmt::Continue(_)) => false,
        Some(Stmt::If {
            then, otherwise, ..
        }) => falls(function, then, broken) || falls(function, otherwise, broken),
        Some(&Stmt::While { condition, .. }) => {
            !always(function, condition) || broken.contains(&last)
        }
        // Its body's end, or a handler's that goes on after it.
        Some(Stmt::Try { body, handlers }) => {
            falls(function, body, broken)
                || handlers.iter().any(|handler| {
                    !handler.kind.propagates() && falls(function, &handler.body, broken)
                })
        }
        Some(stmt) => stops(stmt) != Some(true),
        None => true,
    }
}

fn set(function: &mut Function, id: StmtId, stmt: Stmt) {
    if let Some(slot) = function.stmts.get_mut(id.0 as usize) {
        *slot = stmt;
    }
}

/// `block` refined.
fn block(function: &mut Function, block: Block, named: &Flow) -> Block {
    let mut out = Vec::with_capacity(block.len());
    for id in block {
        let Some(slot) = function.stmts.get_mut(id.0 as usize) else {
            out.push(id);
            continue;
        };
        match mem::replace(slot, Stmt::Unreachable) {
            Stmt::If {
                condition,
                then,
                otherwise,
            } => {
                let then = self::block(function, then, named);
                let otherwise = self::block(function, otherwise, named);
                turn(function, id, condition, [then, otherwise], named, &mut out);
            }
            Stmt::While { condition, body } => {
                let body = self::block(function, body, named);
                loops(function, id, condition, body, named, &mut out);
            }
            Stmt::DoWhile { body, condition } => {
                let body = self::block(function, body, named);
                set(function, id, Stmt::DoWhile { body, condition });
                out.push(id);
            }
            Stmt::Switch {
                scrutinee,
                mut arms,
            } => {
                for arm in &mut arms {
                    arm.body = self::block(function, mem::take(&mut arm.body), named);
                }
                set(function, id, Stmt::Switch { scrutinee, arms });
                out.push(id);
            }
            Stmt::Try { body, mut handlers } => {
                let body = self::block(function, body, named);
                for handler in &mut handlers {
                    handler.body = self::block(function, mem::take(&mut handler.body), named);
                }
                set(function, id, Stmt::Try { body, handlers });
                out.push(id);
            }
            other @ (Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::For { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::VaStart { .. }) => {
                set(function, id, other);
                out.push(id);
            }
        }
    }
    out
}

/// `if (c) T else E`, turned so that an arm that never falls through is
/// the `if`'s only arm and the other follows it (the shorter inside if
/// both never fall through), and an empty `then` is not left alone.
fn turn(
    function: &mut Function,
    id: StmtId,
    condition: ExprId,
    [then, otherwise]: [Block; 2],
    named: &Flow,
    out: &mut Block,
) {
    let then_falls = named.falls(function, &then);
    let otherwise_falls = named.falls(function, &otherwise);
    let (condition, then, otherwise, after) = if then.is_empty() && !otherwise.is_empty() {
        (
            negate(function, condition),
            otherwise,
            Vec::new(),
            Vec::new(),
        )
    } else if !then_falls
        && !otherwise.is_empty()
        && (otherwise_falls || then.len() <= otherwise.len())
    {
        (condition, then, Vec::new(), otherwise)
    } else if !otherwise_falls && !then.is_empty() {
        (negate(function, condition), otherwise, Vec::new(), then)
    } else {
        (condition, then, otherwise, Vec::new())
    };
    set(
        function,
        id,
        Stmt::If {
            condition,
            then,
            otherwise,
        },
    );
    out.push(id);
    out.extend(after);
}

/// Whether `stmt` is `if (c) break loop;`: its condition.
fn breaks_out(function: &Function, stmt: StmtId, loop_id: StmtId) -> Option<ExprId> {
    match function.stmt(stmt) {
        Some(Stmt::If {
            condition,
            then,
            otherwise,
        }) if otherwise.is_empty()
            && matches!(then.as_slice(), [only] if function.stmt(*only) == Some(&Stmt::Break(loop_id))) =>
        {
            Some(*condition)
        }
        Some(_) | None => None,
    }
}

/// `while (1) { if (c) break; … }` (statement `id`) → `while (!c) { … }`,
/// the `if`'s provenance the loop's, as [`loops`] turns one at
/// refinement: whether it did.
pub(super) fn loop_head(function: &mut Function, id: StmtId) -> bool {
    let Some(Stmt::While { condition, body }) = function.stmt(id) else {
        return false;
    };
    let Some(&first) = body.first() else {
        return false;
    };
    if !always(function, *condition) {
        return false;
    }
    let Some(test) = breaks_out(function, first, id) else {
        return false;
    };
    let condition = negate(function, test);
    let origins = function.provenance.stmt(first).to_vec();
    function.provenance.set_stmt(id, &origins);
    if let Some(Stmt::While {
        condition: slot,
        body,
    }) = function.stmts.get_mut(id.0 as usize)
    {
        *slot = condition;
        body.remove(0);
    }
    true
}

/// `while (1) { l: if (c) break; … }` → `l: while (!c) { … }` (the label
/// may be missing);
/// `while (1) { …; if (c) break; }` without `continue` →
/// `do { … } while (!c)`, where a `goto` to a label ending the body is a
/// `continue`. The `if`'s provenance goes to the loop.
fn loops(
    function: &mut Function,
    id: StmtId,
    condition: ExprId,
    mut body: Block,
    named: &Flow,
    out: &mut Block,
) {
    if always(function, condition) {
        let head = match body.as_slice() {
            [label, test, ..] if matches!(function.stmt(*label), Some(Stmt::Label(_))) => {
                breaks_out(function, *test, id).map(|c| (Some(*label), *test, c))
            }
            [test, ..] => breaks_out(function, *test, id).map(|c| (None, *test, c)),
            [] => None,
        };
        if let Some((label, test, c)) = head {
            let condition = negate(function, c);
            let origins = function.provenance.stmt(test).to_vec();
            function.provenance.set_stmt(id, &origins);
            body.drain(..=usize::from(label.is_some()));
            set(function, id, Stmt::While { condition, body });
            out.extend(label);
            out.push(id);
            return;
        }
        let tail = body
            .last()
            .filter(|_| !named.continued.contains(&id))
            .and_then(|&test| breaks_out(function, test, id).map(|c| (test, c)));
        if let Some((test, c)) = tail {
            let condition = negate(function, c);
            let origins = function.provenance.stmt(test).to_vec();
            function.provenance.set_stmt(id, &origins);
            body.pop();
            if let Some(&last) = body.last()
                && let Some(&Stmt::Label(label)) = function.stmt(last)
            {
                continues(function, &body, label, id);
            }
            set(function, id, Stmt::DoWhile { body, condition });
            out.push(id);
            return;
        }
    }
    set(function, id, Stmt::While { condition, body });
    out.push(id);
}

/// Turns each `goto label` in `block`, outside inner loops, into a
/// `continue` of `loop_id` (`label` ends its body: the same place).
fn continues(function: &mut Function, block: &[StmtId], label: LabelId, loop_id: StmtId) {
    let mut work = block.to_vec();
    while let Some(id) = work.pop() {
        match function.stmt(id) {
            Some(&Stmt::Goto(target)) if target == label => {
                set(function, id, Stmt::Continue(loop_id));
            }
            Some(stmt) if !stmt.is_loop() => work.extend(stmt.blocks().flatten().copied()),
            Some(_) | None => {}
        }
    }
}

/// The negation of the 1-bit `condition`: its operand if a `not`, `ne`
/// for `eq` and back, `||` of the negations for `&&` and back (De
/// Morgan's laws, a few levels deep), else a `not` (operands keep their
/// order: they may fault). Keeps the provenance: a `not` standing for
/// instructions only gives them to its operand.
pub(super) fn negate(function: &mut Function, condition: ExprId) -> ExprId {
    negate_within(function, condition, 8)
}

fn negate_within(function: &mut Function, condition: ExprId, depth: usize) -> ExprId {
    let expr = match function.expr(condition) {
        Some(&Expr::Unary(Unary::Not, inner)) => {
            // Its operand, or a copy of it where the `not` has origins
            // besides instructions (a block).
            let origins = function.provenance.expr(condition);
            let instructions = origins
                .iter()
                .all(|origin| matches!(origin, Origin::Instruction(_)));
            match function.expr(inner) {
                Some(&copy) if !instructions => copy,
                Some(_) | None => {
                    let origins = origins.to_vec();
                    function.provenance.absorb_expr(inner, &origins);
                    return inner;
                }
            }
        }
        Some(&Expr::Binary(Binary::Eq, a, b)) => Expr::Binary(Binary::Ne, a, b),
        Some(&Expr::Binary(Binary::Ne, a, b)) => Expr::Binary(Binary::Eq, a, b),
        Some(&Expr::Logical(op, a, b)) if depth > 0 => {
            let op = match op {
                Logical::And => Logical::Or,
                Logical::Or => Logical::And,
            };
            let a = negate_within(function, a, depth - 1);
            let b = negate_within(function, b, depth - 1);
            Expr::Logical(op, a, b)
        }
        Some(_) | None => Expr::Unary(Unary::Not, condition),
    };
    let id = function.add_expr(expr);
    let origins = function.provenance.expr(condition).to_vec();
    function.provenance.set_expr(id, &origins);
    if let Some(&Expr::Unary(Unary::Not, inner)) = function.expr(condition) {
        let folded = function.provenance.expr(inner).to_vec();
        function.provenance.absorb_expr(id, &folded);
    }
    id
}
