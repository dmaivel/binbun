//! Small exits copied (code duplication under a cap; SAILR's duplication
//! of return blocks): [`Exits`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{Block, Callee, Expr, ExprId, Function, LabelId, Place, Stmt, StmtId};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};

use super::refine::{drop_empty_ifs, falls};
use super::{drop_labels, forward};
use crate::pass::{L2Env, size};

/// `if`s nested deeper than this are not in an exit.
const DEPTH: usize = 64;

/// The pass `exits`: a `goto` to a small exit becomes a copy of it.
///
/// A label's *exit* is the code after it, in its block, up to and
/// including the first statement that never goes on (a `return`, a trap,
/// the unreachable point after a call that does not return, an `if` whose
/// arms all end so), when that code is assignments, calls, intrinsics,
/// expression statements and `if`s of such code (labels between them are
/// passed over, not copied), at most [`Exits::statements`] statements
/// counting those inside `if`s. A `goto` to it is replaced by
/// a copy of those statements: fresh statements and expressions with the
/// originals' provenance, so each copy stands for the same L1 blocks.
/// That is exact: the `goto` ran those statements and stopped, and so
/// does the copy. Where a statement of the exit may unwind, the `goto`
/// must be in the same `Try` body as the label (else the copy's
/// exceptions would go to other handlers).
///
/// A label whose `goto`s were all replaced goes; where control cannot
/// fall into it either (the statement before it never goes on), so does
/// its exit, now dead (the copies stand for its blocks).
/// Then forward `goto`s are folded: skipped code that falls through
/// joins the opposite arm of the `if`; code that never goes on permits
/// the jumping arm to follow the `if` instead.
///
/// The structure check ([`crate::validate::structure`]) reads each copy
/// as an entry into the blocks it stands for, and holds every entry to
/// all of its block's L1 successors: each copy is checked against the
/// path it stands for.
///
/// Preserves nothing. Fuel: a unit per statement and expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exits {
    /// The most statements an exit may have to be copied. 3 by default.
    pub statements: usize,
    copied: usize,
}

impl Default for Exits {
    fn default() -> Self {
        Self::new(3)
    }
}

impl Exits {
    /// The pass, copying exits of up to `statements` statements.
    pub const fn new(statements: usize) -> Self {
        Self {
            statements,
            copied: 0,
        }
    }

    /// How many `goto`s its last run replaced by a copy.
    pub const fn copied(&self) -> usize {
        self.copied
    }
}

impl<'e> Pass<Function, L2Env<'e>> for Exits {
    fn name(&self) -> &'static str {
        "exits"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        self.copied = 0;
        cx.fuel.spend(size(function))?;
        let copied = copy(function, self.statements);
        // Fold forward joins, including those exposed by copied exits.
        let folded = forward::fold(function);
        if folded > 0 {
            drop_labels(function);
            // A `goto` to the label right after its `if` leaves the arm
            // it ended empty.
            drop_empty_ifs(function);
        }
        self.copied = copied;
        Ok((copied + folded > 0).into())
    }
}

/// Replaces the `goto`s to exits of at most `limit` statements in
/// `function` by copies and prunes what that leaves dead (see
/// [`Exits`]); how many it replaced.
fn copy(function: &mut Function, limit: usize) -> usize {
    let mut scan = Scan {
        limit,
        exits: BTreeMap::new(),
        broken: BTreeSet::new(),
    };
    scan.block(function, &function.body, None);
    if scan.exits.is_empty() {
        return 0;
    }
    let mut copier = Copier {
        function,
        exits: &scan.exits,
        replaced: BTreeSet::new(),
        copied: 0,
    };
    let body = mem::take(&mut copier.function.body);
    copier.function.body = copier.block(body, None);
    let (replaced, count) = (copier.replaced, copier.copied);
    if count == 0 {
        return 0;
    }
    let mut targets = BTreeSet::new();
    gotos(function, &function.body, &mut targets);
    let emptied: BTreeSet<LabelId> = replaced.difference(&targets).copied().collect();
    let body = mem::take(&mut function.body);
    function.body = prune(function, body, &emptied, &scan.broken);
    count
}

/// A label's exit: its statements, and where it is.
struct Exit {
    /// The statements to copy, in order (no labels).
    stmts: Vec<StmtId>,
    /// Whether one of them may unwind.
    unwinds: bool,
    /// The innermost `Try` whose body holds the label, if one.
    context: Option<StmtId>,
}

/// The labels' exits and the loops `break`s name.
struct Scan {
    limit: usize,
    exits: BTreeMap<LabelId, Exit>,
    broken: BTreeSet<StmtId>,
}

impl Scan {
    /// The exits in `block` (and the blocks inside it), in `Try` body
    /// `context`.
    fn block(&mut self, function: &Function, block: &[StmtId], context: Option<StmtId>) {
        for (at, &id) in block.iter().enumerate() {
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            if let Stmt::Label(label) = *stmt
                && let Some(exit) = self.exit(function, block.get(at + 1..).unwrap_or_default())
            {
                self.exits.insert(label, Exit { context, ..exit });
            }
            if let Stmt::Break(target) = *stmt {
                self.broken.insert(target);
            }
            for (index, inner) in stmt.blocks().enumerate() {
                let context = inner_context(stmt, id, index, context);
                self.block(function, inner, context);
            }
        }
    }

    /// The exit `code` starts, if it is one.
    fn exit(&self, function: &Function, code: &[StmtId]) -> Option<Exit> {
        let mut stmts = Vec::new();
        let mut unwinds = false;
        let mut count = 0;
        for &id in code {
            let stmt = function.stmt(id)?;
            if matches!(stmt, Stmt::Label(_)) {
                continue;
            }
            count += tree(function, stmt, &mut unwinds, 0)?;
            if count > self.limit {
                return None;
            }
            stmts.push(id);
            if !falls(function, &[id], &BTreeSet::new()) {
                return Some(Exit {
                    stmts,
                    unwinds,
                    context: None,
                });
            }
        }
        None
    }
}

/// How many statements `stmt` is, counting those inside it, if it may be
/// in an exit (see [`Exits`]); notes in `unwinds` whether one may unwind.
fn tree(function: &Function, stmt: &Stmt, unwinds: &mut bool, depth: usize) -> Option<usize> {
    *unwinds |= stmt.may_unwind(function);
    match stmt {
        Stmt::Assign { .. }
        | Stmt::Call { .. }
        | Stmt::Intrinsic { .. }
        | Stmt::Expr(_)
        | Stmt::Return(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable => Some(1),
        Stmt::If {
            then, otherwise, ..
        } if depth < DEPTH => {
            let mut count = 1;
            for &id in then.iter().chain(otherwise) {
                count += tree(function, function.stmt(id)?, unwinds, depth + 1)?;
            }
            Some(count)
        }
        Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Escape { .. }
        | Stmt::Try { .. }
        | Stmt::VaStart { .. } => None,
    }
}

/// The innermost `Try` body holding block `index` of statement `id`
/// (`stmt`), itself in `context`: a `Try`'s body is its own, its
/// handlers are in the `Try`'s context (an exception there propagates
/// out of it).
fn inner_context(stmt: &Stmt, id: StmtId, index: usize, context: Option<StmtId>) -> Option<StmtId> {
    if matches!(stmt, Stmt::Try { .. }) && index == 0 {
        Some(id)
    } else {
        context
    }
}

/// The labels `goto`s in `block` (and the blocks inside it) go to.
fn gotos(function: &Function, block: &[StmtId], targets: &mut BTreeSet<LabelId>) {
    for &id in block {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        if let Stmt::Goto(label) = *stmt {
            targets.insert(label);
        }
        for inner in stmt.blocks() {
            gotos(function, inner, targets);
        }
    }
}

/// Replaces `goto`s to exits by copies.
struct Copier<'f, 'x> {
    function: &'f mut Function,
    exits: &'x BTreeMap<LabelId, Exit>,
    /// The labels a `goto` to which was replaced.
    replaced: BTreeSet<LabelId>,
    copied: usize,
}

impl Copier<'_, '_> {
    /// `block` (in `Try` body `context`) with its `goto`s to exits
    /// replaced, in the blocks inside it too.
    fn block(&mut self, block: Block, context: Option<StmtId>) -> Block {
        let mut out = Vec::with_capacity(block.len());
        for id in block {
            let Some(stmt) = self.function.stmt(id) else {
                out.push(id);
                continue;
            };
            if let Stmt::Goto(label) = *stmt
                && let Some(exit) = self.exits.get(&label)
                && (!exit.unwinds || exit.context == context)
            {
                let start = out.len();
                for &original in &exit.stmts {
                    match copy_stmt(self.function, original) {
                        Some(copy) => out.push(copy),
                        None => break,
                    }
                }
                if out.len() - start == exit.stmts.len() {
                    self.replaced.insert(label);
                    self.copied += 1;
                    continue;
                }
                out.truncate(start);
            }
            self.inner(id, context);
            out.push(id);
        }
        out
    }

    /// The blocks statement `id` (in `context`) holds, each done.
    fn inner(&mut self, id: StmtId, context: Option<StmtId>) {
        let Some(stmt) = self.function.stmts.get_mut(id.0 as usize) else {
            return;
        };
        let taken: Vec<Block> = stmt.blocks_mut().map(mem::take).collect();
        let Some(stmt) = self.function.stmt(id) else {
            return;
        };
        let contexts: Vec<Option<StmtId>> = (0..taken.len())
            .map(|index| inner_context(stmt, id, index, context))
            .collect();
        let done: Vec<Block> = taken
            .into_iter()
            .zip(contexts)
            .map(|(inner, context)| self.block(inner, context))
            .collect();
        if let Some(stmt) = self.function.stmts.get_mut(id.0 as usize) {
            for (slot, inner) in stmt.blocks_mut().zip(done) {
                *slot = inner;
            }
        }
    }
}

/// A copy of statement `id` of an exit: a new statement evaluating new
/// copies of its expressions (an `if`'s arms copied too), all with the
/// originals' provenance; `None` if it cannot be in one.
fn copy_stmt(function: &mut Function, id: StmtId) -> Option<StmtId> {
    let stmt = function.stmt(id)?.clone();
    let memo = copy_exprs(function, &stmt.roots())?;
    let map = |expr: ExprId| memo.get(&expr).copied().unwrap_or(expr);
    let place = |place: Place| match place {
        Place::Var(_) => place,
        Place::Memory { address, ty } => Place::Memory {
            address: map(address),
            ty,
        },
    };
    let copy = match stmt {
        Stmt::Assign { place: to, value } => Stmt::Assign {
            place: place(to),
            value: map(value),
        },
        Stmt::Call { results, mut call } => {
            if let Callee::Expr(target) = &mut call.callee {
                *target = map(*target);
            }
            for argument in &mut call.arguments {
                *argument = map(*argument);
            }
            Stmt::Call {
                results: results.into_iter().map(place).collect(),
                call,
            }
        }
        Stmt::Intrinsic {
            results,
            intrinsic,
            inputs,
        } => Stmt::Intrinsic {
            results: results.into_iter().map(place).collect(),
            intrinsic,
            inputs: inputs.into_iter().map(map).collect(),
        },
        Stmt::Expr(value) => Stmt::Expr(map(value)),
        Stmt::Return(value) => Stmt::Return(value.map(map)),
        Stmt::Trap(trap) => Stmt::Trap(trap),
        Stmt::Unreachable => Stmt::Unreachable,
        Stmt::If {
            condition,
            then,
            otherwise,
        } => Stmt::If {
            condition: map(condition),
            then: copy_block(function, &then)?,
            otherwise: copy_block(function, &otherwise)?,
        },
        Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Escape { .. }
        | Stmt::Try { .. }
        | Stmt::VaStart { .. } => return None,
    };
    let origins = function.provenance.stmt(id).to_vec();
    let new = function.add_stmt(copy);
    function.provenance.set_stmt(new, &origins);
    Some(new)
}

/// Copies of the statements of `block` (of an exit), in order.
fn copy_block(function: &mut Function, block: &[StmtId]) -> Option<Block> {
    block.iter().map(|&id| copy_stmt(function, id)).collect()
}

/// Copies of the expressions `roots` reach (a node they share stays
/// shared), with the originals' provenance: each original's copy.
fn copy_exprs(function: &mut Function, roots: &[ExprId]) -> Option<BTreeMap<ExprId, ExprId>> {
    let mut reached = BTreeSet::new();
    let mut work = roots.to_vec();
    while let Some(id) = work.pop() {
        if reached.insert(id) {
            work.extend(function.expr(id)?.operands(function));
        }
    }
    let mut memo = BTreeMap::new();
    // Operands are below their users: ascending order copies them first.
    for id in reached {
        let expr = *function.expr(id)?;
        let map = |operand: ExprId| memo.get(&operand).copied().unwrap_or(operand);
        // Every call made is a call of its own.
        let copy = if let Expr::Call(call) = expr {
            let mut call = function.call(call)?.clone();
            if let Callee::Expr(target) = &mut call.callee {
                *target = map(*target);
            }
            for argument in &mut call.arguments {
                *argument = map(*argument);
            }
            Expr::Call(function.add_call(call))
        } else {
            expr.map_own(&mut { map })
        };
        let origins = function.provenance.expr(id).to_vec();
        let new = function.add_expr(copy);
        function.provenance.set_expr(new, &origins);
        memo.insert(id, new);
    }
    Some(memo)
}

/// `block` (and the blocks inside it) without the labels `emptied` (no
/// `goto` goes to them any more) and, where control cannot fall into one
/// (the statement before it never goes on), without the exit after it.
fn prune(
    function: &mut Function,
    block: Block,
    emptied: &BTreeSet<LabelId>,
    broken: &BTreeSet<StmtId>,
) -> Block {
    let mut out: Block = Vec::with_capacity(block.len());
    // Whether the statements being read are dead: an exit after an
    // emptied label control cannot fall into, until it stops.
    let mut dead = false;
    for id in block {
        let Some(stmt) = function.stmt(id) else {
            out.push(id);
            continue;
        };
        if dead {
            // A statement of the exit (it holds no label): skipped, up to
            // the one that never goes on.
            if tree(function, stmt, &mut false, 0).is_some() {
                dead = falls(function, &[id], broken);
                continue;
            }
            dead = false;
        }
        if let Stmt::Label(label) = *stmt
            && emptied.contains(&label)
        {
            dead = !out.is_empty() && !falls(function, &out, broken);
            continue;
        }
        if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
            let taken: Vec<Block> = stmt.blocks_mut().map(mem::take).collect();
            let done: Vec<Block> = taken
                .into_iter()
                .map(|inner| prune(function, inner, emptied, broken))
                .collect();
            if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
                for (slot, inner) in stmt.blocks_mut().zip(done) {
                    *slot = inner;
                }
            }
        }
        out.push(id);
    }
    out
}
