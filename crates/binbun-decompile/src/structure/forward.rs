//! Forward `goto`s folded into conditional arms: [`fold`].
//!
//! `if (c) { A; goto l; } else { E } Y` where `Y` (the statements after
//! the `if` in its block) never goes on, and control falling out of `Y`'s
//! place would reach `l` (`l` follows `Y` in the block, past labels only;
//! or `Y` ends the block and control falling out of the block reaches
//! `l`: the block is an arm of an `if` or the body of a `Try`, whose
//! statement is so placed in turn), becomes `if (!c) { E Y } A` (the arms
//! the other way round where the `goto` ends the `else`): control that
//! took the `goto` now runs `A` and falls to `l`, control that went
//! through `E` into `Y` still does, and `Y` can only leave by its own
//! jumps, so nothing else reaches `A` or `l` that did not before. With
//! `Y` empty (or labels only) the `goto` goes where control falls anyway
//! and is dropped. `A` and `Y` keep their statements and labels (a
//! `goto` may enter any block); the `if` keeps its provenance, its
//! condition negated as refinement negates one, so the control flow
//! through the blocks is unchanged. The arm that never goes on comes
//! first and the other follows, as refinement turns `if`s.
//!
//! When `Y` falls through, it instead joins the opposite arm:
//! `if (c) { A } else { E Y } l:`. Neither arm's code is copied, and
//! entering a label in `Y` still runs its suffix and reaches `l`.
//!
//! Either arm's `goto` may be the one folded: the `then`'s is tried
//! first, then the `else`'s (one going back, or to a label not in reach,
//! does not keep the other from folding). And `Y` moves into an arm only
//! where no `goto` from outside that arm and `Y` goes to a label in `Y`
//! ([`Flow::entered`]): under the `if`, that label's code would read as
//! run only where the test went that way, while the jump reaches it
//! without the test. The `goto` then stays: one more jump shown, none
//! hidden.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{Block, Function, LabelId, Stmt, StmtId};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};

use super::drop_labels;
use super::flow::Flow;
use super::refine::{drop_empty_ifs, negate};
use crate::pass::{L2Env, size};

/// Statements nested deeper than this are left as they are.
const DEPTH: usize = 1000;

/// Rounds of folding at most: a fold moves code, which may let a `goto`
/// in it fold in the next round.
const ROUNDS: usize = 4;

/// The pass `forward`: the forward `goto`s that fit folded into
/// conditional arms ([`fold`]), once the other tree passes are done.
/// [`Exits`](super::Exits) folds those that fit when it runs; the passes
/// after it make more fit: decisions merged to `&&`/`||` leave one `if`
/// whose arm is the `goto` where there were several nested, a loop or a
/// `switch` formed of the code between takes its labels with it.
///
/// Preserves nothing. Fuel: a unit per statement and expression.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Forward;

impl<'e> Pass<Function, L2Env<'e>> for Forward {
    fn name(&self) -> &'static str {
        "forward"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(size(function))?;
        let folded = fold(function);
        if folded > 0 {
            drop_labels(function);
            drop_empty_ifs(function);
        }
        Ok((folded > 0).into())
    }
}

/// Folds the forward `goto`s of `function` that fit (see the module
/// documentation), inner blocks first. Returns how many it dropped.
pub(super) fn fold(function: &mut Function) -> usize {
    let flow = Flow::of(function);
    let mut folder = Folder {
        function,
        flow,
        count: 0,
    };
    for _ in 0..ROUNDS {
        let before = folder.count;
        let body = mem::take(&mut folder.function.body);
        folder.function.body = folder.block(body, &BTreeSet::new(), 0);
        if folder.count == before {
            break;
        }
    }
    folder.count
}

struct Folder<'f> {
    function: &'f mut Function,
    /// The body's jumps, less the `goto`s folded so far.
    flow: Flow,
    count: usize,
}

impl Folder<'_> {
    /// The labels control reaches falling out of `block[..=at]` (the
    /// labels right after it; `after` too if only labels follow it).
    fn next(&self, block: &[StmtId], at: usize, after: &BTreeSet<LabelId>) -> BTreeSet<LabelId> {
        let mut labels = BTreeSet::new();
        for &id in block.get(at + 1..).unwrap_or_default() {
            match self.function.stmt(id) {
                Some(&Stmt::Label(label)) => {
                    labels.insert(label);
                }
                Some(_) | None => return labels,
            }
        }
        labels.extend(after);
        labels
    }

    /// `block` folded, the blocks inside it first; `after`: the labels
    /// control falling out of it reaches.
    fn block(&mut self, mut block: Block, after: &BTreeSet<LabelId>, depth: usize) -> Block {
        if depth > DEPTH {
            return block;
        }
        for at in 0..block.len() {
            let Some(&id) = block.get(at) else {
                continue;
            };
            let next = self.next(&block, at, after);
            self.inner(id, &next, depth);
        }
        let mut at = 0;
        while at < block.len() {
            if self.one(&mut block, at, after) {
                self.count += 1;
            } else {
                at += 1;
            }
        }
        block
    }

    /// The blocks statement `id` holds, each folded; `next`: the labels
    /// control falling out of the statement reaches.
    fn inner(&mut self, id: StmtId, next: &BTreeSet<LabelId>, depth: usize) {
        let Some(stmt) = self.function.stmts.get_mut(id.0 as usize) else {
            return;
        };
        // Falling out of an `if`'s arm or a `Try`'s body leaves the
        // statement; out of anything else, it goes elsewhere.
        let falls_out = |index: usize, stmt: &Stmt| match stmt {
            Stmt::If { .. } => true,
            Stmt::Try { .. } => index == 0,
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
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
            | Stmt::VaStart { .. } => false,
        };
        let outs: Vec<bool> = (0..stmt.blocks().count())
            .map(|index| falls_out(index, stmt))
            .collect();
        let taken: Vec<Block> = stmt.blocks_mut().map(mem::take).collect();
        let none = BTreeSet::new();
        let done: Vec<Block> = taken
            .into_iter()
            .zip(outs)
            .map(|(inner, out)| self.block(inner, if out { next } else { &none }, depth + 1))
            .collect();
        if let Some(stmt) = self.function.stmts.get_mut(id.0 as usize) {
            for (slot, inner) in stmt.blocks_mut().zip(done) {
                *slot = inner;
            }
        }
    }

    /// The label `arm`'s last statement, a `goto`, goes to.
    fn tail(&self, arm: &[StmtId]) -> Option<LabelId> {
        match self.function.stmt(*arm.last()?) {
            Some(&Stmt::Goto(label)) => Some(label),
            Some(_) | None => None,
        }
    }

    /// Folds the `goto` ending an arm of the `if` at `block[at]`, if it
    /// fits; `after`: the labels control falling out of `block` reaches.
    fn one(&mut self, block: &mut Block, at: usize, after: &BTreeSet<LabelId>) -> bool {
        let function = &*self.function;
        let Some(&id) = block.get(at) else {
            return false;
        };
        let Some(Stmt::If {
            then, otherwise, ..
        }) = function.stmt(id)
        else {
            return false;
        };
        // The arm a `goto` ends (`then` first) whose label is in reach,
        // and `Y`: up to the label, or to the end where falling out
        // reaches it.
        let reach = |label: LabelId| match block
            .iter()
            .skip(at + 1)
            .position(|&next| function.stmt(next) == Some(&Stmt::Label(label)))
        {
            Some(offset) => Some(at + 1 + offset),
            None if after.contains(&label) => Some(block.len()),
            None => None,
        };
        let Some((in_then, label, end)) = [(true, self.tail(then)), (false, self.tail(otherwise))]
            .into_iter()
            .find_map(|(in_then, label)| {
                let label = label?;
                Some((in_then, label, reach(label)?))
            })
        else {
            return false;
        };
        let other = if in_then { otherwise } else { then };
        let between = block.get(at + 1..end).unwrap_or_default();
        let only_labels = between
            .iter()
            .all(|&next| matches!(function.stmt(next), Some(Stmt::Label(_))));
        // `Y` goes under the `if` with `other`: not where a jump from
        // elsewhere enters it.
        if !only_labels && self.flow.entered(function, between, other) {
            return false;
        }
        let hoist =
            !only_labels && !self.flow.falls(function, between) && self.flow.falls(function, other);
        let Some(Stmt::If {
            condition,
            mut then,
            mut otherwise,
        }) = function.stmt(id).cloned()
        else {
            return false;
        };
        let arm = if in_then { &mut then } else { &mut otherwise };
        arm.pop();
        self.flow.drop_jump(label);
        if only_labels {
            self.set(
                id,
                Stmt::If {
                    condition,
                    then,
                    otherwise,
                },
            );
            return true;
        }
        let between: Vec<StmtId> = block.drain(at + 1..end).collect();
        if !hoist {
            let other = if in_then { &mut otherwise } else { &mut then };
            other.extend(between);
            self.set(
                id,
                Stmt::If {
                    condition,
                    then,
                    otherwise,
                },
            );
            return true;
        }
        // `if (c) { A; goto l } else { E } Y` → `if (!c) { E Y } A`.
        let (condition, mut stays, after) = if in_then {
            (negate(self.function, condition), otherwise, then)
        } else {
            (condition, then, otherwise)
        };
        stays.extend(between);
        self.set(
            id,
            Stmt::If {
                condition,
                then: stays,
                otherwise: Vec::new(),
            },
        );
        let position = at + 1;
        block.splice(position..position, after);
        true
    }

    fn set(&mut self, id: StmtId, stmt: Stmt) {
        if let Some(slot) = self.function.stmts.get_mut(id.0 as usize) {
            *slot = stmt;
        }
    }
}
