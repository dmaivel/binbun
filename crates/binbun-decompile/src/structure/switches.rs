//! Switches from comparison chains: [`Switches`].

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{Arm, Block, Expr, ExprId, Function, Origin, Stmt, StmtId};
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::ir::Binary;
use binbun_ssa::ir::BlockId;

use crate::pass::{L2Env, size};
use crate::simplify::expr::{in_memory, same};

/// The fewest cases a chain needs to be a `switch` (two read as well as
/// an `if` and its `else`).
const MIN_CASES: usize = 3;

/// Comparison chains on one value as `switch` (pass `switches`), a
/// block's chains before those inside its statements, so a chain is
/// taken whole from its first test (inner blocks first would make a
/// `switch` of its last three cases and leave the ones before it `if`s).
/// A case is an `if (x == c)` (the constant on either side)
/// of its own L1 block, its condition one decision; `x` is the same tree
/// in every case, reads only variables not in memory and neither loads
/// nor calls, and the constants differ. Two shapes:
///
/// - *A chain of `else`s*: `if (x == a) A else if (x == b) B else … D`,
///   each `else` holding the next case alone, is `switch (x) { case a: A
///   case b: B … default: D }` (no `default` where `D` is empty). A chain
///   may end in a test for inequality, which is its last case the other
///   way round: `… else if (x != c) E else R`, or `… else { if (x != c)
///   E; R }` with `E` never going on and no label in `R`, is `… case c: R
///   default: E`;
/// - *A run of exits*: consecutive `if (x == a) A` with no `else`, each
///   `A` never going on (a `return`, a jump, a trap), is the `switch`
///   without a `default`; what follows the run follows it. A run too may
///   end in a test for inequality, with what follows it to the end of
///   the block as its last case: `… if (x != c) E; R`, neither `E` nor
///   `R` going on, is `… case c: R default: E`.
///
/// No arm falls through, and none may hold a `break` of a loop or
/// `switch` around the chain (inside the `switch` it would need a
/// label). The `switch` is the first `if`'s statement, naming every case's
/// block in the order of its values: the structure check reads it as the
/// chain of decisions it stands for (each value tested by its block, the
/// last test going to the `default`), so the control flow is L1's; the
/// values are tested in the same order on the same value, so the
/// function computes the same.
///
/// Preserves nothing. Fuel: a unit per statement and expression.
#[derive(Clone, Copy, Debug, Default)]
pub struct Switches;

impl<'e> Pass<Function, L2Env<'e>> for Switches {
    fn name(&self) -> &'static str {
        "switches"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(size(function))?;
        let mut changed = false;
        let body = mem::take(&mut function.body);
        function.body = block(function, &body, &mut changed);
        Ok(changed.into())
    }
}

/// One case: an `if (x == value)` of its own block.
#[derive(Clone)]
struct Case {
    /// The `if`.
    id: StmtId,
    /// The value compared.
    x: ExprId,
    /// The constant it is compared with.
    value: Bits,
    /// The block deciding it.
    block: BlockId,
    /// What runs where the value is the constant.
    body: Block,
}

/// `block` with its chains done first, then its statements' blocks.
fn block(function: &mut Function, block: &[StmtId], changed: &mut bool) -> Block {
    let mut out = Vec::with_capacity(block.len());
    let mut at = 0;
    while let Some(&id) = block.get(at) {
        let run = exits(function, block.get(at..).unwrap_or_default());
        // The run's last case, tested for inequality: `if (x != c) E;
        // R`, neither going on, is `case c: R default: E`, to the block's
        // end.
        let ended = block
            .get(at + run.len()..)
            .and_then(<[StmtId]>::split_first)
            .filter(|(_, rest)| !run.is_empty() && !rest.is_empty() && !goes_on(function, rest))
            .and_then(|(&next, rest)| unequal(function, next, rest))
            .filter(|(last, _)| fits(function, &run, last));
        if let Some((last, default)) = ended {
            let mut whole = run.clone();
            whole.push(last);
            if whole.len() >= MIN_CASES && build(function, &whole, default) {
                *changed = true;
                out.push(id);
                break;
            }
        }
        if run.len() >= MIN_CASES && build(function, &run, Vec::new()) {
            *changed = true;
            out.push(id);
            at += run.len();
            continue;
        }
        let (chain, default) = chain(function, id);
        if chain.len() >= MIN_CASES && build(function, &chain, default) {
            *changed = true;
        }
        out.push(id);
        at += 1;
    }
    for &id in &out {
        inner(function, id, changed);
    }
    out
}

/// The blocks statement `id` holds, each done.
fn inner(function: &mut Function, id: StmtId, changed: &mut bool) {
    let Some(stmt) = function.stmts.get_mut(id.0 as usize) else {
        return;
    };
    let taken: Vec<Block> = stmt.blocks_mut().map(mem::take).collect();
    let done: Vec<Block> = taken
        .into_iter()
        .map(|inner| block(function, &inner, changed))
        .collect();
    if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
        for (slot, inner) in stmt.blocks_mut().zip(done) {
            *slot = inner;
        }
    }
}

/// The case of statement `id`, if it is one (see [`Switches`]), and its
/// `else`.
fn case(function: &Function, id: StmtId) -> Option<(Case, &Block)> {
    let (case, then, otherwise) = test(function, id, Binary::Eq)?;
    Some((
        Case {
            body: then.clone(),
            ..case
        },
        otherwise,
    ))
}

/// The last case of a chain that statement `id`, followed by `rest` in
/// the chain's last `else`, is, if it is one: `if (x != c) E else R`
/// alone, or `if (x != c) E` with `E` never going on and `rest` (`R`),
/// which holds no label (a jump to one would enter the case), after it.
/// With the default's body, `E`.
fn unequal(function: &Function, id: StmtId, rest: &[StmtId]) -> Option<(Case, Block)> {
    let (case, then, otherwise) = test(function, id, Binary::Ne)?;
    let body = if rest.is_empty() {
        otherwise.clone()
    } else {
        let labelled = rest
            .iter()
            .any(|&id| matches!(function.stmt(id), Some(Stmt::Label(_))));
        if !otherwise.is_empty() || goes_on(function, then) || labelled {
            return None;
        }
        rest.to_vec()
    };
    Some((Case { body, ..case }, then.clone()))
}

/// Statement `id` as a test of a value against a constant by `relation`
/// (`==` or `!=`, the constant on either side), of its own L1 block, its
/// condition one decision (the case's body not set); and its `then` and
/// `else`.
fn test(function: &Function, id: StmtId, relation: Binary) -> Option<(Case, &Block, &Block)> {
    let Some(Stmt::If {
        condition,
        then,
        otherwise,
    }) = function.stmt(id)
    else {
        return None;
    };
    let block = only_block(function.provenance.stmt(id))?;
    let &Expr::Binary(op, a, b) = function.expr(*condition)? else {
        return None;
    };
    if op != relation {
        return None;
    }
    let (x, value) = if let &Expr::Const(value) = function.expr(b)? {
        (a, value)
    } else if let &Expr::Const(value) = function.expr(a)? {
        (b, value)
    } else {
        return None;
    };
    (own(function, *condition, block) && simple(function, x)).then_some((
        Case {
            id,
            x,
            value,
            block,
            body: Vec::new(),
        },
        then,
        otherwise,
    ))
}

/// The cases of a run of exits from the start of `block`: `if`s with no
/// `else` whose `then` never goes on, on the first one's value.
fn exits(function: &Function, block: &[StmtId]) -> Vec<Case> {
    let mut run: Vec<Case> = Vec::new();
    for &id in block {
        let Some((case, otherwise)) = case(function, id) else {
            break;
        };
        if !otherwise.is_empty() || goes_on(function, &case.body) || !fits(function, &run, &case) {
            break;
        }
        run.push(case);
    }
    run
}

/// The cases of the chain of `else`s from `if` statement `id`, and what
/// its last `else` holds (the default's body).
fn chain(function: &Function, id: StmtId) -> (Vec<Case>, Block) {
    let mut cases: Vec<Case> = Vec::new();
    let mut at = id;
    loop {
        let Some((case, otherwise)) =
            case(function, at).filter(|(case, ..)| fits(function, &cases, case))
        else {
            // An `if` that is not the next case: the last `else` holds it.
            return (cases, vec![at]);
        };
        let otherwise = otherwise.clone();
        cases.push(case);
        // The last case, tested for inequality.
        if let Some((&first, rest)) = otherwise.split_first()
            && let Some((last, default)) =
                unequal(function, first, rest).filter(|(last, _)| fits(function, &cases, last))
        {
            cases.push(last);
            return (cases, default);
        }
        match otherwise.as_slice() {
            &[next] if matches!(function.stmt(next), Some(Stmt::If { .. })) => at = next,
            _ => return (cases, otherwise),
        }
    }
}

/// Whether `case` may follow `cases`: the same value, another constant,
/// another block.
fn fits(function: &Function, cases: &[Case], case: &Case) -> bool {
    cases
        .first()
        .is_none_or(|first| same(function, first.x, case.x))
        && cases
            .iter()
            .all(|other| other.value != case.value && other.block != case.block)
}

/// Makes the `if` of `cases`' first case the `switch` of `cases`, each
/// arm its `if`'s `then`, `default` the default arm's body (none where
/// empty), if no arm holds a `break` of a statement around it: whether
/// it did.
fn build(function: &mut Function, cases: &[Case], default: Block) -> bool {
    let Some(first) = cases.first() else {
        return false;
    };
    let mut arms: Vec<Arm> = Vec::with_capacity(cases.len() + 1);
    for case in cases {
        arms.push(Arm {
            values: vec![case.value],
            default: false,
            body: case.body.clone(),
            fallthrough: false,
        });
    }
    if !default.is_empty() {
        arms.push(Arm {
            values: Vec::new(),
            default: true,
            body: default,
            fallthrough: false,
        });
    }
    if arms.iter().any(|arm| breaks_out(function, &arm.body)) {
        return false;
    }
    let mut origins: Vec<Origin> = cases.iter().map(|case| Origin::Block(case.block)).collect();
    origins.extend(
        function
            .provenance
            .stmt(first.id)
            .iter()
            .copied()
            .filter(|origin| !matches!(origin, Origin::Block(_) | Origin::Proved)),
    );
    let Some(slot) = function.stmts.get_mut(first.id.0 as usize) else {
        return false;
    };
    *slot = Stmt::Switch {
        scrutinee: first.x,
        arms,
    };
    function.provenance.set_stmt(first.id, &origins);
    true
}

/// Whether a `break` in `body` leaves a statement around it.
fn breaks_out(function: &Function, body: &[StmtId]) -> bool {
    let mut inside = BTreeSet::new();
    let mut breaks = Vec::new();
    let mut work: Vec<StmtId> = body.to_vec();
    while let Some(id) = work.pop() {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        if let &Stmt::Break(target) = stmt {
            breaks.push(target);
        }
        if stmt.is_loop() || matches!(stmt, Stmt::Switch { .. }) {
            inside.insert(id);
        }
        work.extend(stmt.blocks().flatten().copied());
    }
    breaks.iter().any(|target| !inside.contains(target))
}

/// Whether control may go on after `block`: `true` unless its last
/// statement never does (a `return`, a jump, a trap).
fn goes_on(function: &Function, block: &[StmtId]) -> bool {
    !matches!(
        block.last().and_then(|&last| function.stmt(last)),
        Some(
            Stmt::Return(_)
                | Stmt::Goto(_)
                | Stmt::Break(_)
                | Stmt::Continue(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
        )
    )
}

/// The block among `origins`, if exactly one.
fn only_block(origins: &[Origin]) -> Option<BlockId> {
    let mut blocks = origins.iter().filter_map(|origin| match *origin {
        Origin::Block(block) => Some(block),
        Origin::Value(_)
        | Origin::Instruction(_)
        | Origin::Register(_)
        | Origin::Held(_)
        | Origin::Slot(_)
        | Origin::Absorbed(_)
        | Origin::Proved => None,
    });
    match (blocks.next(), blocks.next()) {
        (Some(block), None) => Some(block),
        _ => None,
    }
}

/// Whether expression `id` and its operands name no block but `block`
/// (one decision, of the `if`'s block).
fn own(function: &Function, id: ExprId, block: BlockId) -> bool {
    let mut work = vec![id];
    while let Some(at) = work.pop() {
        let foreign = function
            .provenance
            .expr(at)
            .iter()
            .any(|origin| matches!(*origin, Origin::Block(other) if other != block));
        if foreign {
            return false;
        }
        if let Some(expr) = function.expr(at) {
            work.extend(expr.operands(function));
        }
    }
    true
}

/// Whether `id` neither loads nor calls nor is undefined: only constants,
/// variables not in memory and operations on them.
fn simple(function: &Function, id: ExprId) -> bool {
    let mut work = vec![id];
    while let Some(at) = work.pop() {
        match function.expr(at) {
            Some(
                Expr::Load { .. }
                | Expr::Call(_)
                | Expr::Assign { .. }
                | Expr::Undefined(..)
                | Expr::Exception { .. }
                | Expr::Logical(..),
            )
            | None => return false,
            Some(&Expr::Var(var)) if in_memory(function, var) => return false,
            Some(expr) => work.extend(expr.operands(function)),
        }
    }
    true
}
