//! Try regions (pass `try-regions`): after structuring, the `Try`s of one
//! landing pad become one around the code between them, and what C++ says
//! implicitly goes.
//!
//! Catch dispatch ([`super::CatchDispatch`]) leaves a `Try` around each
//! call, each handler its dispatch's assignments then the handler's code,
//! which structuring places in the first handler reaching it (the others
//! jump there). In each block, in order:
//!
//! 1. **Merging**: a `Try` and the later ones with the same handlers
//!    (same kinds, same dispatch block, each handler the same assignments
//!    going to the same code) become one whose body is theirs and the
//!    statements between them, if no exception can leave those statements
//!    other than as it does now: they hold no statement that may unwind
//!    but inside a `Try` whose handlers end with this one's (a nested
//!    `try` within it: what its own handlers do not take goes on to this
//!    one's, in the merged form as in the exception tables), whose
//!    handlers' code holds none either. A nested `Try`'s handlers that are
//!    this one's (same assignments, same code) are dropped; one left
//!    without handlers is its body.
//! 2. **Cleanups**: a cleanup handler ending in a call that resumes
//!    unwinding (not guarded) loses it: a cleanup's end propagates the
//!    exception. The call's block, left without code, is one the `Try`'s
//!    dispatch took over ([`Origin::Absorbed`]).
//!
//!    A cleanup whose resume is guarded by a `Try` of its own (Microsoft
//!    x64: the runtime goes on unwinding to the function's next handler,
//!    where the Itanium ABI's landing pad lists the outer clauses in its
//!    own chain) first moves that `Try`'s handlers out, around its own
//!    `Try` (before step 1): what the cleanup propagates reaches them, as
//!    it does now, and the resume is no longer guarded.
//! 3. **Tails**: where every handler that goes on after its `Try` ends in
//!    a `goto` to a label after it, the statements between the `Try` and
//!    the label (none of which may unwind) join its body, and the `goto`s
//!    go: the handlers fall off their end to the label.
//!
//! Labels no `goto` names are removed. Preserves nothing.

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{
    Block, Callee, Expr, ExprId, Function, Handler, HandlerKind, LabelId, Origin, Place, Stmt,
    StmtId,
};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_ssa::ir::BlockId;

use super::{Exceptions, unwinds};
use crate::pass::L2Env;

/// How deep blocks may nest for this pass (deeper ones are left).
const DEPTH: usize = 200;

/// How many expression nodes a comparison of two expressions may visit.
const NODES: usize = 256;

/// Try regions (pass `try-regions`, see the module documentation). Runs
/// after structuring. Preserves nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct TryRegions;

impl<'e> Pass<Function, L2Env<'e>> for TryRegions {
    fn name(&self) -> &'static str {
        "try-regions"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        if !has_try(function) {
            return Ok(Changed::No);
        }
        let exceptions = cx.env.exceptions;
        let mut changed = false;
        let mut body = mem::take(&mut function.body);
        changed |= guarded_resumes(function, &mut body, exceptions, 0);
        function.body = body;
        changed |= cleanups(function, exceptions);
        changed |= trivial_cleanups(function);
        let mut body = mem::take(&mut function.body);
        changed |= regions(function, &mut body, 0, cx);
        function.body = body;
        changed |= cleanups(function, exceptions);
        let mut body = mem::take(&mut function.body);
        changed |= tails(function, &mut body, exceptions, 0);
        function.body = body;
        if changed {
            unused_labels(function);
        }
        Ok(changed.into())
    }
}

/// Whether a statement of `function`'s body is a `Try` with handlers other
/// than a landing pad's.
fn has_try(function: &Function) -> bool {
    walk(function)
        .into_iter()
        .any(|id| transformed(function, id))
}

/// The statements in `function`'s body, at any depth.
fn walk(function: &Function) -> Vec<StmtId> {
    let mut out = Vec::new();
    let mut work: Vec<&Block> = vec![&function.body];
    while let Some(block) = work.pop() {
        for &id in block {
            out.push(id);
            if let Some(stmt) = function.stmt(id) {
                work.extend(stmt.blocks());
            }
        }
    }
    out
}

/// Whether statement `id` is a `Try` whose handlers are not a landing
/// pad's.
fn transformed(function: &Function, id: StmtId) -> bool {
    matches!(function.stmt(id), Some(Stmt::Try { handlers, .. })
        if !handlers.iter().any(|handler| matches!(handler.kind, HandlerKind::Landing(_))))
}

/// The statement's `Try` parts, if it is one.
fn try_parts(function: &Function, id: StmtId) -> Option<(&Block, &[Handler])> {
    match function.stmt(id)? {
        Stmt::Try { body, handlers } => Some((body, handlers)),
        Stmt::Assign { .. }
        | Stmt::Call { .. }
        | Stmt::Intrinsic { .. }
        | Stmt::Expr(_)
        | Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Return(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable
        | Stmt::Escape { .. }
        | Stmt::VaStart { .. } => None,
    }
}

/// Merges `Try`s in `block` (step 1), then in the blocks it holds.
fn regions(
    function: &mut Function,
    block: &mut Block,
    depth: usize,
    cx: &mut Cx<'_, Function, L2Env<'_>>,
) -> bool {
    if depth > DEPTH
        || cx
            .fuel
            .spend(u64::try_from(block.len()).unwrap_or(u64::MAX))
            .is_err()
    {
        return false;
    }
    let mut changed = false;
    let mut index = 0;
    while index < block.len() {
        changed |= merge_at(function, block, index, cx.env.exceptions);
        index += 1;
    }
    for &id in block.iter() {
        let Some(stmt) = function.stmts.get_mut(id.0 as usize) else {
            continue;
        };
        let mut inner: Vec<Block> = stmt.blocks_mut().map(mem::take).collect();
        for child in &mut inner {
            changed |= regions(function, child, depth + 1, cx);
        }
        if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
            for (slot, child) in stmt.blocks_mut().zip(inner) {
                *slot = child;
            }
        }
    }
    changed
}

/// A handler as structuring left it: the dispatch's assignments, then a
/// `goto` to its code, or the code itself (under the labels that start
/// it).
struct Shape {
    prefix: Vec<StmtId>,
    /// Where it goes, or the labels its code starts with.
    labels: Vec<LabelId>,
    /// Whether it is a `goto`.
    jumps: bool,
}

/// The shape of handler body `body`.
fn shape(function: &Function, body: &Block) -> Shape {
    let mut prefix = Vec::new();
    let mut labels = Vec::new();
    for &id in body {
        match function.stmt(id) {
            Some(&Stmt::Goto(label)) if labels.is_empty() => {
                return Shape {
                    prefix,
                    labels: vec![label],
                    jumps: true,
                };
            }
            Some(&Stmt::Label(label)) => labels.push(label),
            Some(Stmt::Assign { .. }) if labels.is_empty() && !has_block(function, id) => {
                prefix.push(id);
            }
            Some(_) | None => break,
        }
    }
    Shape {
        prefix,
        labels,
        jumps: false,
    }
}

/// Whether statement `id` stands for an L1 block's code.
fn has_block(function: &Function, id: StmtId) -> bool {
    function
        .provenance
        .stmt(id)
        .iter()
        .any(|origin| matches!(origin, Origin::Block(_)))
}

/// Whether handlers `a` and `b` are the same: entered for the same
/// exceptions, with the same assignments, going to the same code (one
/// may be that code).
fn same_handler(function: &Function, a: &Handler, b: &Handler) -> bool {
    if a.kind != b.kind {
        return false;
    }
    let (a, b) = (shape(function, &a.body), shape(function, &b.body));
    if !(a.jumps || b.jumps) {
        return false;
    }
    let target = |shape: &Shape| shape.labels.first().copied();
    let meets = match (a.jumps, b.jumps) {
        (true, true) => target(&a) == target(&b),
        (true, false) => target(&a).is_some_and(|label| b.labels.contains(&label)),
        (false, true) => target(&b).is_some_and(|label| a.labels.contains(&label)),
        (false, false) => false,
    };
    meets
        && a.prefix.len() == b.prefix.len()
        && a.prefix
            .iter()
            .zip(&b.prefix)
            .all(|(&x, &y)| same_assignment(function, x, y))
}

/// Whether assignments `first` and `second` write the same place the same
/// value.
fn same_assignment(function: &Function, first: StmtId, second: StmtId) -> bool {
    match (function.stmt(first), function.stmt(second)) {
        (
            Some(&Stmt::Assign {
                place: Place::Var(var),
                value,
            }),
            Some(&Stmt::Assign {
                place: Place::Var(other_var),
                value: other,
            }),
        ) => var == other_var && same_expr(function, value, other),
        (Some(_) | None, Some(_) | None) => false,
    }
}

/// Whether expressions `a` and `b` are the same tree.
fn same_expr(function: &Function, a: ExprId, b: ExprId) -> bool {
    let mut work = vec![(a, b)];
    let mut visited = 0;
    while let Some((a, b)) = work.pop() {
        visited += 1;
        if visited > NODES {
            return false;
        }
        if a == b {
            continue;
        }
        let (Some(&x), Some(&y)) = (function.expr(a), function.expr(b)) else {
            return false;
        };
        let blank = |expr: Expr| expr.map_own(&mut |_| ExprId(0));
        if matches!(x, Expr::Call(_)) || blank(x) != blank(y) {
            return false;
        }
        let (xs, ys): (Vec<ExprId>, Vec<ExprId>) = (
            x.operands(function).collect(),
            y.operands(function).collect(),
        );
        if xs.len() != ys.len() {
            return false;
        }
        work.extend(xs.into_iter().zip(ys));
    }
    true
}

/// The blocks `Try` `id`'s dispatch took over.
fn absorbed_of(function: &Function, id: StmtId) -> Vec<BlockId> {
    function
        .provenance
        .stmt(id)
        .iter()
        .filter_map(|origin| match *origin {
            Origin::Absorbed(block) => Some(block),
            Origin::Block(_)
            | Origin::Value(_)
            | Origin::Instruction(_)
            | Origin::Register(_)
            | Origin::Held(_)
            | Origin::Slot(_)
            | Origin::Proved => None,
        })
        .collect()
}

/// Whether `Try` `b` can join `Try` `a`: the same handlers.
fn joins(function: &Function, a: StmtId, b: StmtId) -> bool {
    let (Some((_, x)), Some((_, y))) = (try_parts(function, a), try_parts(function, b)) else {
        return false;
    };
    transformed(function, a)
        && transformed(function, b)
        && x.len() == y.len()
        && x.iter().zip(y).all(|(p, q)| same_handler(function, p, q))
}

/// Merges the `Try` at `index` of `block` with the later ones it can
/// (step 1). Whether it did.
fn merge_at(
    function: &mut Function,
    block: &mut Block,
    index: usize,
    exceptions: &Exceptions,
) -> bool {
    let Some(&first) = block.get(index) else {
        return false;
    };
    if !transformed(function, first) {
        return false;
    }
    let Some(handlers) = try_parts(function, first).map(|(_, handlers)| handlers.to_vec()) else {
        return false;
    };
    let mut end = index;
    for (offset, &id) in block.iter().enumerate().skip(index + 1) {
        if joins(function, first, id) {
            end = offset;
        } else if !fits(function, id, &handlers, exceptions, 0) {
            break;
        }
    }
    if end == index {
        return false;
    }
    let span: Vec<StmtId> = block.drain(index..=end).collect();
    let merged = merge(function, &span, &handlers);
    block.insert(index, merged);
    true
}

/// Whether the kinds of `inner`'s handlers end with `outer`'s (a cleanup
/// last aside).
fn nests(inner: &[Handler], outer: &[Handler]) -> bool {
    let kinds = |handlers: &[Handler]| -> Vec<HandlerKind> {
        handlers
            .iter()
            .map(|handler| handler.kind.clone())
            .collect()
    };
    let (inner, outer) = (kinds(inner), kinds(outer));
    let core = match inner.split_last() {
        Some((last, rest)) if last.cleans_up() => rest,
        Some(_) | None => inner.as_slice(),
    };
    inner.ends_with(&outer) || core.ends_with(&outer)
}

/// Whether statement `id`, inside a `Try` with `handlers`, lets no
/// exception reach them that does not now: it may not unwind, and holds
/// no statement that may but inside a `Try` that nests in this one.
fn fits(
    function: &Function,
    id: StmtId,
    handlers: &[Handler],
    exceptions: &Exceptions,
    depth: usize,
) -> bool {
    fits_in(function, id, handlers, exceptions, depth, false)
}

/// [`fits`], for statement `id` in a block of another statement but a
/// `Try` (`compound`: an `if`, a loop) or not. A `Try` there with one of
/// `handlers` that propagates (a cleanup) does not fit: merging drops a
/// nested `Try`'s handlers that are the merged one's only where the `Try`
/// is a statement of the span or of its handlers ([`nest`]), and kept, the
/// exception that handler propagates would run it again (for the merged
/// `Try`). A handler whose end goes on after its `Try` may stay. Only for
/// funclets ([`Exceptions::funclets`]): an Itanium landing pad's chain
/// lists the clauses of the `Try`s around it, which the nesting follows.
fn fits_in(
    function: &Function,
    id: StmtId,
    handlers: &[Handler],
    exceptions: &Exceptions,
    depth: usize,
    compound: bool,
) -> bool {
    let Some(stmt) = function.stmt(id) else {
        return false;
    };
    if depth > DEPTH {
        return false;
    }
    if let Some((_, inner)) = try_parts(function, id) {
        if compound
            && exceptions.funclets
            && inner.iter().any(|handler| {
                handler.kind.propagates()
                    && handlers
                        .iter()
                        .any(|outer| same_handler(function, handler, outer))
            })
        {
            return false;
        }
        let catches = matches!(
            inner.last().map(|handler| &handler.kind),
            Some(HandlerKind::Landing(_) | HandlerKind::CatchAll)
        ) && !inner.iter().any(|handler| handler.kind.propagates());
        if !catches && !nests(inner, handlers) {
            return false;
        }
        return inner
            .iter()
            .filter(|handler| {
                !handlers
                    .iter()
                    .any(|outer| same_handler(function, handler, outer))
            })
            .all(|handler| {
                handler.body.iter().all(|&inner| {
                    fits_in(function, inner, handlers, exceptions, depth + 1, compound)
                })
            });
    }
    !unwinds(function, stmt, exceptions)
        && stmt
            .blocks()
            .flatten()
            .all(|&inner| fits_in(function, inner, handlers, exceptions, depth + 1, true))
}

/// One `Try` for the statements `span` (a `Try`, the statements between,
/// and the `Try`s that join it): their body, and for each handler the one
/// holding its code (else the first).
fn merge(function: &mut Function, span: &[StmtId], handlers: &[Handler]) -> StmtId {
    let mut body = Vec::new();
    let mut merged: Vec<Handler> = handlers.to_vec();
    let mut absorbed: Vec<BlockId> = Vec::new();
    let mut origins: Vec<Origin> = span
        .first()
        .map(|&first| function.provenance.stmt(first).to_vec())
        .unwrap_or_default();
    for (position, &id) in span.iter().enumerate() {
        let joined =
            position == 0 || (transformed(function, id) && joins_all(function, id, handlers));
        if !joined {
            nest(function, id, &mut merged, &mut body, &mut absorbed);
            continue;
        }
        let Some((guarded, own)) = try_parts(function, id).map(|(b, h)| (b.clone(), h.to_vec()))
        else {
            continue;
        };
        body.extend(guarded);
        absorbed.extend(absorbed_of(function, id));
        for (slot, handler) in merged.iter_mut().zip(own) {
            if shape(function, &slot.body).jumps && !shape(function, &handler.body).jumps {
                *slot = handler;
            }
        }
    }
    for block in absorbed {
        if !origins.contains(&Origin::Absorbed(block)) {
            origins.push(Origin::Absorbed(block));
        }
    }
    let id = function.add_stmt(Stmt::Try {
        body,
        handlers: merged,
    });
    function.provenance.set_stmt(id, &origins);
    id
}

/// Whether `Try` `id` has exactly `handlers` (the same ones).
fn joins_all(function: &Function, id: StmtId, handlers: &[Handler]) -> bool {
    try_parts(function, id).is_some_and(|(_, own)| {
        own.len() == handlers.len()
            && own
                .iter()
                .zip(handlers)
                .all(|(a, b)| same_handler(function, a, b))
    })
}

/// Statement `id` placed in a `Try` with `handlers` (appended to `body`):
/// a `Try` loses the handlers that are those (one left with none is its
/// body, the blocks its dispatch took over added to `absorbed`; one
/// holding the code the other jumps to gives it its place), as do the
/// `Try`s nested in its handlers.
fn nest(
    function: &mut Function,
    id: StmtId,
    handlers: &mut [Handler],
    body: &mut Block,
    absorbed: &mut Vec<BlockId>,
) {
    let Some((guarded, own)) = try_parts(function, id).map(|(b, h)| (b.clone(), h.to_vec())) else {
        body.push(id);
        return;
    };
    let mut kept: Vec<Handler> = Vec::with_capacity(own.len());
    for handler in own {
        let Some(outer) = handlers
            .iter_mut()
            .find(|outer| same_handler(function, &handler, outer))
        else {
            kept.push(handler);
            continue;
        };
        if !shape(function, &handler.body).jumps {
            *outer = handler;
        }
    }
    for handler in &mut kept {
        let statements = mem::take(&mut handler.body);
        for statement in statements {
            nest(function, statement, handlers, &mut handler.body, absorbed);
        }
    }
    if kept.is_empty() {
        absorbed.extend(absorbed_of(function, id));
        body.extend(guarded);
        return;
    }
    if let Some(Stmt::Try { handlers: slot, .. }) = function.stmts.get_mut(id.0 as usize) {
        *slot = kept;
    }
    body.push(id);
}

/// Drops the resume call ending each cleanup handler (step 2), its block
/// taken over by the `Try` where no code of it is left. Whether it did.
fn cleanups(function: &mut Function, exceptions: &Exceptions) -> bool {
    let mut dropped: Vec<(StmtId, Vec<BlockId>)> = Vec::new();
    for id in walk(function) {
        let Some(Stmt::Try { body, handlers }) = function.stmt(id).cloned() else {
            continue;
        };
        let mut handlers = handlers;
        let mut blocks = Vec::new();
        for handler in &mut handlers {
            if !handler.kind.cleans_up() {
                continue;
            }
            let keep = resume_tail(function, &handler.body, exceptions);
            if keep < handler.body.len() {
                for &gone in handler.body.get(keep..).unwrap_or_default() {
                    blocks.extend(block_origins(function, gone));
                }
                handler.body.truncate(keep);
            }
        }
        if !blocks.is_empty() {
            if let Some(slot) = function.stmts.get_mut(id.0 as usize) {
                *slot = Stmt::Try { body, handlers };
            }
            dropped.push((id, blocks));
        }
    }
    if dropped.is_empty() {
        return false;
    }
    let present: BTreeSet<BlockId> = walk(function)
        .into_iter()
        .flat_map(|id| block_origins(function, id))
        .collect();
    for (id, blocks) in dropped {
        for block in blocks {
            if !present.contains(&block) {
                function
                    .provenance
                    .add_stmt_origin(id, Origin::Absorbed(block));
            }
        }
    }
    true
}

/// In `block` and the blocks it holds: each `Try` whose last handler, a
/// cleanup, ends in a resume guarded by a `Try` of its own (then
/// `unreachable`) goes into a new `Try` with that `Try`'s handlers, and the
/// resume loses its guard (the module documentation's step 2). Whether it
/// changed.
fn guarded_resumes(
    function: &mut Function,
    block: &mut Block,
    exceptions: &Exceptions,
    depth: usize,
) -> bool {
    if depth > DEPTH {
        return false;
    }
    let mut changed = false;
    for slot in block.iter_mut() {
        for _ in 0..DEPTH {
            let Some(wrapped) = unguard(function, *slot, exceptions) else {
                break;
            };
            *slot = wrapped;
            changed = true;
        }
    }
    for &id in block.iter() {
        let Some(stmt) = function.stmts.get_mut(id.0 as usize) else {
            continue;
        };
        let mut inner: Vec<Block> = stmt.blocks_mut().map(mem::take).collect();
        for child in &mut inner {
            changed |= guarded_resumes(function, child, exceptions, depth + 1);
        }
        if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
            for (slot, child) in stmt.blocks_mut().zip(inner) {
                *slot = child;
            }
        }
    }
    changed
}

/// `Try` `id` inside a new `Try` with the handlers guarding the resume its
/// last handler (a cleanup) ends in, that resume unguarded; `None` if its
/// last handler is no such cleanup, or if the new `Try` would take an
/// exception it does not now: every other statement of the `Try`'s
/// handlers must fit in it ([`fits`]: none may unwind but into a `Try`
/// that nests in it), as the statements a merged `Try` takes in must.
fn unguard(function: &mut Function, id: StmtId, exceptions: &Exceptions) -> Option<StmtId> {
    let (_, handlers) = try_parts(function, id)?;
    let cleanup = handlers.last()?;
    if !cleanup.kind.cleans_up() {
        return None;
    }
    let mut at = cleanup.body.len().checked_sub(1)?;
    if matches!(
        cleanup.body.get(at).and_then(|&last| function.stmt(last)),
        Some(Stmt::Unreachable)
    ) {
        at = at.checked_sub(1)?;
    }
    let guard = *cleanup.body.get(at)?;
    let (guarded, outer) = try_parts(function, guard)?;
    if !transformed(function, guard) || resume_tail(function, guarded, exceptions) != 0 {
        return None;
    }
    let (guarded, outer) = (guarded.clone(), outer.to_vec());
    let (_, handlers) = try_parts(function, id)?;
    let last = handlers.len().saturating_sub(1);
    let fit = handlers.iter().enumerate().all(|(index, handler)| {
        handler.body.iter().enumerate().all(|(position, &stmt)| {
            (index == last && position >= at) || fits(function, stmt, &outer, exceptions, 0)
        })
    });
    if !fit {
        return None;
    }
    let origins = function.provenance.stmt(guard).to_vec();
    if let Some(Stmt::Try { handlers, .. }) = function.stmts.get_mut(id.0 as usize)
        && let Some(last) = handlers.last_mut()
    {
        last.body.splice(at..=at, guarded);
    }
    let wrapped = function.add_stmt(Stmt::Try {
        body: vec![id],
        handlers: outer,
    });
    function.provenance.set_stmt(wrapped, &origins);
    Some(wrapped)
}

/// The blocks statement `id` stands for.
fn block_origins(function: &Function, id: StmtId) -> Vec<BlockId> {
    function
        .provenance
        .stmt(id)
        .iter()
        .filter_map(|origin| match *origin {
            Origin::Block(block) => Some(block),
            Origin::Value(_)
            | Origin::Instruction(_)
            | Origin::Register(_)
            | Origin::Held(_)
            | Origin::Slot(_)
            | Origin::Absorbed(_)
            | Origin::Proved => None,
        })
        .collect()
}

/// A cleanup handler's body that does nothing but assign variables pure
/// values: those assignments, the labels after them, and the label its
/// last `goto` goes to (if it ends in one).
fn idle(function: &Function, body: &Block) -> Option<(Vec<LabelId>, Option<LabelId>)> {
    let mut labels = Vec::new();
    for (position, &id) in body.iter().enumerate() {
        match function.stmt(id)? {
            &Stmt::Label(label) => labels.push(label),
            &Stmt::Goto(label) if position + 1 == body.len() => {
                return Some((labels, Some(label)));
            }
            &Stmt::Assign {
                place: Place::Var(_),
                value,
            } if labels.is_empty() && !loads_or_calls(function, value) => {}
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::Try { .. }
            | Stmt::VaStart { .. } => return None,
        }
    }
    Some((labels, None))
}

/// Whether expression `root` loads or calls.
fn loads_or_calls(function: &Function, root: ExprId) -> bool {
    let mut work = vec![root];
    let mut seen = BTreeSet::new();
    while let Some(id) = work.pop() {
        if !seen.insert(id) {
            continue;
        }
        match function.expr(id) {
            None | Some(Expr::Load { .. } | Expr::Call(_)) => return true,
            Some(expr) => work.extend(expr.operands(function)),
        }
    }
    false
}

/// Cleanup handlers that do nothing ([`idle`]: a landing pad's cleanup
/// clause with no code, after its resume went) are removed from the `Try`s
/// with other handlers (unwinding goes on as it would without them), and
/// lose their labels and `goto` where they are the only handler. Whether
/// it changed.
fn trivial_cleanups(function: &mut Function) -> bool {
    let statements = walk(function);
    let mut idle_bodies: BTreeSet<(StmtId, usize)> = BTreeSet::new();
    let mut empty: BTreeSet<LabelId> = BTreeSet::new();
    let mut jumps: Vec<(StmtId, usize, LabelId)> = Vec::new();
    for &id in &statements {
        let Some((_, handlers)) = try_parts(function, id) else {
            continue;
        };
        for (index, handler) in handlers.iter().enumerate() {
            if !handler.kind.cleans_up() {
                continue;
            }
            match idle(function, &handler.body) {
                Some((labels, None)) => {
                    empty.extend(labels);
                    idle_bodies.insert((id, index));
                }
                Some((labels, Some(target))) => {
                    empty.extend(labels);
                    jumps.push((id, index, target));
                }
                None => {}
            }
        }
    }
    // A label is empty code only if every `goto` to it is an idle cleanup's.
    let idle_gotos: BTreeSet<StmtId> = jumps
        .iter()
        .filter_map(|&(id, index, _)| {
            let (_, handlers) = try_parts(function, id)?;
            handlers.get(index)?.body.last().copied()
        })
        .collect();
    for &id in &statements {
        if let Some(&Stmt::Goto(label)) = function.stmt(id)
            && !idle_gotos.contains(&id)
        {
            empty.remove(&label);
        }
    }
    idle_bodies.extend(
        jumps
            .iter()
            .filter(|&&(_, _, target)| empty.contains(&target))
            .map(|&(id, index, _)| (id, index)),
    );
    let mut changed = false;
    for &id in &statements {
        let Some(Stmt::Try { handlers, .. }) = function.stmts.get(id.0 as usize) else {
            continue;
        };
        let mut handlers = handlers.clone();
        let before = handlers.clone();
        let mut index = 0;
        handlers.retain(|_| {
            let idle = idle_bodies.contains(&(id, index));
            index += 1;
            !idle
        });
        if handlers.is_empty() {
            handlers.clone_from(&before);
            for handler in &mut handlers {
                handler.body.retain(|&statement| {
                    !matches!(
                        function.stmt(statement),
                        Some(Stmt::Label(label) | Stmt::Goto(label)) if empty.contains(label)
                    )
                });
            }
        }
        if handlers != before
            && let Some(Stmt::Try { handlers: slot, .. }) = function.stmts.get_mut(id.0 as usize)
        {
            *slot = handlers;
            changed = true;
        }
    }
    changed
}

/// How many statements of `body` stay without its last call, if that
/// resumes unwinding (then `unreachable`): its length if not.
fn resume_tail(function: &Function, body: &Block, exceptions: &Exceptions) -> usize {
    let mut keep = body.len();
    if let Some(&last) = body.last()
        && matches!(function.stmt(last), Some(Stmt::Unreachable))
    {
        keep -= 1;
    }
    let resumes = keep
        .checked_sub(1)
        .and_then(|at| body.get(at))
        .and_then(|&call| function.stmt(call))
        .is_some_and(|stmt| {
            matches!(stmt, Stmt::Call { call, .. }
                if matches!(call.callee, Callee::Address(address) if exceptions.resume.contains(&address)))
        });
    if resumes { keep - 1 } else { body.len() }
}

/// Step 3 in `block` and the blocks it holds. Whether it changed.
fn tails(
    function: &mut Function,
    block: &mut Block,
    exceptions: &Exceptions,
    depth: usize,
) -> bool {
    if depth > DEPTH {
        return false;
    }
    let mut changed = false;
    let mut index = 0;
    while index < block.len() {
        changed |= tail_at(function, block, index, exceptions);
        index += 1;
    }
    for &id in block.iter() {
        let Some(stmt) = function.stmts.get_mut(id.0 as usize) else {
            continue;
        };
        let mut inner: Vec<Block> = stmt.blocks_mut().map(mem::take).collect();
        for child in &mut inner {
            changed |= tails(function, child, exceptions, depth + 1);
        }
        if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
            for (slot, child) in stmt.blocks_mut().zip(inner) {
                *slot = child;
            }
        }
    }
    changed
}

/// Step 3 for the statement at `index` of `block`. Whether it changed.
fn tail_at(
    function: &mut Function,
    block: &mut Block,
    index: usize,
    exceptions: &Exceptions,
) -> bool {
    let Some(&id) = block.get(index) else {
        return false;
    };
    let Some((_, handlers)) = try_parts(function, id) else {
        return false;
    };
    // The label every handler that goes on jumps to.
    let mut target = None;
    for handler in handlers.iter().filter(|handler| !handler.kind.propagates()) {
        let last = handler.body.last().and_then(|&last| function.stmt(last));
        let Some(&Stmt::Goto(label)) = last else {
            return false;
        };
        if target.is_some_and(|known| known != label) {
            return false;
        }
        target = Some(label);
    }
    let Some(label) = target else {
        return false;
    };
    let Some(at) = block
        .iter()
        .skip(index + 1)
        .position(|&next| function.stmt(next) == Some(&Stmt::Label(label)))
        .map(|offset| index + 1 + offset)
    else {
        return false;
    };
    let between: Vec<StmtId> = block.get(index + 1..at).unwrap_or_default().to_vec();
    if !between
        .iter()
        .all(|&statement| quiet(function, statement, exceptions, 0))
    {
        return false;
    }
    let Some(Stmt::Try { body, handlers }) = function.stmts.get_mut(id.0 as usize) else {
        return false;
    };
    body.extend(between);
    for handler in handlers
        .iter_mut()
        .filter(|handler| !handler.kind.propagates())
    {
        handler.body.pop();
    }
    block.drain(index + 1..at);
    true
}

/// Whether no exception can leave statement `id`: it holds no statement
/// that may unwind but in the body of a `Try` whose handlers take every
/// exception and never propagate one.
fn quiet(function: &Function, id: StmtId, exceptions: &Exceptions, depth: usize) -> bool {
    let Some(stmt) = function.stmt(id) else {
        return false;
    };
    if depth > DEPTH || unwinds(function, stmt, exceptions) {
        return false;
    }
    match stmt {
        Stmt::Try { handlers, .. } => {
            matches!(
                handlers.last().map(|handler| &handler.kind),
                Some(HandlerKind::Landing(_) | HandlerKind::CatchAll)
            ) && !handlers.iter().any(|handler| handler.kind.propagates())
                && handlers
                    .iter()
                    .flat_map(|handler| &handler.body)
                    .all(|&inner| quiet(function, inner, exceptions, depth + 1))
        }
        Stmt::Assign { .. }
        | Stmt::Call { .. }
        | Stmt::Intrinsic { .. }
        | Stmt::Expr(_)
        | Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Return(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable
        | Stmt::Escape { .. }
        | Stmt::VaStart { .. } => stmt
            .blocks()
            .flatten()
            .all(|&inner| quiet(function, inner, exceptions, depth + 1)),
    }
}

/// Removes the labels no `goto` names.
fn unused_labels(function: &mut Function) {
    let statements = walk(function);
    let used: BTreeSet<LabelId> = statements
        .iter()
        .filter_map(|&id| match function.stmt(id) {
            Some(&Stmt::Goto(label)) => Some(label),
            Some(_) | None => None,
        })
        .collect();
    let unused = |function: &Function, id: StmtId| matches!(function.stmt(id), Some(Stmt::Label(label)) if !used.contains(label));
    let mut body = mem::take(&mut function.body);
    body.retain(|&id| !unused(function, id));
    function.body = body;
    for id in statements {
        let Some(stmt) = function.stmts.get(id.0 as usize) else {
            continue;
        };
        let has_unused = stmt
            .blocks()
            .flatten()
            .any(|&inner| unused(function, inner));
        if !has_unused {
            continue;
        }
        let mut inner: Vec<Block> = function
            .stmts
            .get_mut(id.0 as usize)
            .map(|stmt| stmt.blocks_mut().map(mem::take).collect())
            .unwrap_or_default();
        for child in &mut inner {
            child.retain(|&statement| !unused(function, statement));
        }
        if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
            for (slot, child) in stmt.blocks_mut().zip(inner) {
                *slot = child;
            }
        }
    }
}
