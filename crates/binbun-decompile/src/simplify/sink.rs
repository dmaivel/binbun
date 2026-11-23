//! Sinking pure assignments toward their uses: [`Sink`].

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{Block, Function, Origin, Place, Stmt, StmtId, VarId};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_ssa::ir::BlockId;

use super::expr::{Info, in_memory, reads, roots};
use crate::pass::L2Env;

/// Sinking (pass `sink`): an assignment with no effect but its write (to a
/// variable not in memory, of a value that neither loads nor calls) moves
/// down its block past statements that neither read nor write what it
/// writes, nor write what it reads, and that control can neither enter
/// from elsewhere (a label) nor leave for elsewhere in the function (a
/// `goto`, or a `break` or `continue` of a statement around them); it
/// stops before the first that does, or at the end of its block. Calls
/// and stores cannot touch such variables, so the move undoes a
/// compiler's scheduling: `v4 = v17 + 1; v17 = v4;` before
/// `checked(v3 % 7)` go after it, past the last use of `v17`'s old value,
/// where copy propagation and coalescing then fold them. An assignment
/// stops before a statement that may unwind to a handler of the function
/// (in a `Try`'s body), which may read what it writes. An assignment
/// moves only past a statement that does more than such an assignment
/// (else two independent ones would swap at each run); a block's
/// statements are taken bottom-up, so one moved stops before another it
/// feeds. A `for`'s `init` and `step` stay as they are. An assignment
/// moved past code of another L1 block (or past a statement holding
/// blocks) no longer stands at its block's place: it loses its
/// [`Origin::Block`] and, like a copy on an edge, is no node of the
/// control flow `validate::structure` compares (it has none: it neither
/// branches nor can be entered). Preserves nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sink;

impl<'e> Pass<Function, L2Env<'e>> for Sink {
    fn name(&self) -> &'static str {
        "sink"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let info = Info::new(function);
        let mut summaries = Summaries {
            function,
            info: &info,
            each: Vec::new(),
            visited: 0,
            guarded: 0,
        };
        summaries.each = vec_of(function.stmts.len());
        let mut holders = Vec::new();
        summaries.block(&function.body, &mut holders);
        cx.fuel.spend(summaries.visited)?;
        let each = mem::take(&mut summaries.each);
        let mut moved = Vec::new();
        let mut body = mem::take(&mut function.body);
        sink(&each, &mut body, &mut moved);
        function.body = body;
        for id in holders {
            let Some(stmt) = function.stmts.get_mut(id.0 as usize) else {
                continue;
            };
            let simple = matches!(stmt, Stmt::For { .. });
            for (index, block) in stmt.blocks_mut().enumerate() {
                // A `for`'s blocks: `init`, `step`, then the body.
                if simple && index < 2 {
                    continue;
                }
                sink(&each, block, &mut moved);
            }
        }
        for &(id, foreign) in &moved {
            if foreign {
                let origins: Vec<Origin> = function
                    .provenance
                    .stmt(id)
                    .iter()
                    .copied()
                    .filter(|origin| !matches!(origin, Origin::Block(_)))
                    .collect();
                function.provenance.set_stmt(id, &origins);
            }
        }
        Ok((!moved.is_empty()).into())
    }
}

/// `len` empty summaries.
fn vec_of(len: usize) -> Vec<Option<Summary>> {
    let mut each = Vec::with_capacity(len);
    each.resize_with(len, || None);
    each
}

/// What a statement (with the statements it holds) does, as sinking sees
/// it.
#[derive(Clone, Debug, Default)]
struct Summary {
    /// The variables not in memory it reads.
    reads: BTreeSet<VarId>,
    /// The variables not in memory it writes.
    writes: BTreeSet<VarId>,
    /// Whether control may enter it from elsewhere or leave it for
    /// elsewhere in the function.
    crossed: bool,
    /// Whether it is a pure assignment: its one write, to a variable not
    /// in memory, of a value that neither loads nor calls.
    pure: Option<VarId>,
    /// The loops and switches it is or holds (where its `break`s and
    /// `continue`s may go and stay inside).
    inner: BTreeSet<StmtId>,
    /// The statements its `break`s and `continue`s name.
    exits: BTreeSet<StmtId>,
    /// The L1 block whose code it is, if it holds no blocks (`None`: it
    /// holds some, or stands for none).
    block: Option<BlockId>,
}

struct Summaries<'a> {
    function: &'a Function,
    info: &'a Info,
    each: Vec<Option<Summary>>,
    visited: u64,
    /// How many `Try` bodies hold the statements being summarised: an
    /// exception there goes to a handler of the function.
    guarded: u32,
}

impl Summaries<'_> {
    /// Summarises `block`'s statements (and theirs), noting each that
    /// holds blocks in `holders`; the block's summary.
    fn block(&mut self, block: &Block, holders: &mut Vec<StmtId>) -> Summary {
        let mut total = Summary::default();
        for &id in block {
            let summary = self.stmt(id, holders);
            merge(&mut total, &summary);
            if let Some(slot) = self.each.get_mut(id.0 as usize) {
                *slot = Some(summary);
            }
        }
        total
    }

    fn stmt(&mut self, id: StmtId, holders: &mut Vec<StmtId>) -> Summary {
        self.visited += 1;
        let function = self.function;
        let mut summary = Summary::default();
        let Some(stmt) = function.stmt(id) else {
            summary.crossed = true;
            return summary;
        };
        for root in roots(stmt) {
            reads(function, root, &mut summary.reads);
        }
        let mut write = |place: &Place| {
            if let &Place::Var(var) = place
                && !in_memory(function, var)
            {
                summary.writes.insert(var);
            }
        };
        match stmt {
            Stmt::Assign { place, value } => {
                write(place);
                if let &Place::Var(var) = place
                    && !in_memory(function, var)
                    && !self.info.faults(*value)
                {
                    summary.pure = Some(var);
                }
            }
            Stmt::Call { results, .. }
            | Stmt::Intrinsic { results, .. }
            | Stmt::Escape { results, .. } => results.iter().for_each(&mut write),
            Stmt::VaStart { list } => write(list),
            Stmt::Label(_) | Stmt::Goto(_) => summary.crossed = true,
            &Stmt::Break(target) | &Stmt::Continue(target) => {
                summary.exits.insert(target);
            }
            Stmt::Expr(_)
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Try { .. }
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable => {}
        }
        if self.guarded > 0 && stmt.may_unwind(function) {
            summary.crossed = true;
        }
        if stmt.is_loop() || matches!(stmt, Stmt::Switch { .. }) {
            summary.inner.insert(id);
        }
        let mut held = false;
        let guards = matches!(stmt, Stmt::Try { .. });
        for (index, block) in stmt.blocks().enumerate() {
            held = true;
            let body = guards && index == 0;
            self.guarded += u32::from(body);
            let below = self.block(block, holders);
            self.guarded -= u32::from(body);
            merge(&mut summary, &below);
        }
        if held {
            holders.push(id);
        } else {
            summary.block = function
                .provenance
                .stmt(id)
                .iter()
                .find_map(|origin| match *origin {
                    Origin::Block(block) => Some(block),
                    Origin::Value(_)
                    | Origin::Instruction(_)
                    | Origin::Register(_)
                    | Origin::Held(_)
                    | Origin::Slot(_)
                    | Origin::Absorbed(_)
                    | Origin::Proved => None,
                });
        }
        // An exit to a statement it holds stays inside.
        let inner = &summary.inner;
        summary.exits.retain(|target| !inner.contains(target));
        summary
    }
}

/// Adds what `other` does to `summary` (not whether it is pure).
fn merge(summary: &mut Summary, other: &Summary) {
    summary.reads.extend(other.reads.iter().copied());
    summary.writes.extend(other.writes.iter().copied());
    summary.crossed |= other.crossed;
    summary.inner.extend(other.inner.iter().copied());
    summary.exits.extend(other.exits.iter().copied());
}

/// Sinks the pure assignments of `block`, bottom-up, noting each moved in
/// `moved` with whether it crossed another L1 block's code.
fn sink(each: &[Option<Summary>], block: &mut Block, moved: &mut Vec<(StmtId, bool)>) {
    let summary = |id: StmtId| each.get(id.0 as usize).and_then(Option::as_ref);
    for start in (0..block.len()).rev() {
        let Some(&id) = block.get(start) else {
            continue;
        };
        let Some(own) = summary(id) else {
            continue;
        };
        let Some(var) = own.pure else {
            continue;
        };
        // Past each statement that neither reads nor writes `var`, nor
        // writes what the value reads, nor can be entered or left.
        let mut end = start + 1;
        let mut anchored = false;
        let mut foreign = false;
        while let Some(&next) = block.get(end) {
            let Some(other) = summary(next) else {
                break;
            };
            let blocks = other.crossed
                || !other.exits.is_empty()
                || other.reads.contains(&var)
                || other.writes.contains(&var)
                || other.writes.iter().any(|write| own.reads.contains(write));
            if blocks {
                break;
            }
            anchored |= other.pure.is_none();
            foreign |= other.block.is_none() || other.block != own.block;
            end += 1;
        }
        if anchored {
            if let Some(range) = block.get_mut(start..end) {
                range.rotate_left(1);
            }
            moved.push((id, foreign));
        }
    }
}
