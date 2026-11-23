//! Where each statement is and what it writes ([`Index`]), and what holds
//! where a loop is entered ([`before`]): the facts of the code that
//! dominates it, and the counter's last write.

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Block, Escape, ExprId, Function, Place, Stmt, StmtId, VarId};

use super::facts::{Fact, Term, facts_of};
use crate::simplify::expr::reads;

/// The most variables a statement's write set lists; past it, the
/// statement counts as writing every variable.
const MANY: usize = 64;

/// The most statements the walk back from a loop looks at.
const REACH: usize = 256;

/// A statement's place: the statement holding it (`None`: the body),
/// which of that statement's blocks ([`Stmt::blocks`]' order), and its
/// position there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    /// The statement holding it.
    pub parent: Option<StmtId>,
    /// Which block of the parent.
    pub block: usize,
    /// Its position in that block.
    pub index: usize,
}

/// What a statement and those it holds do, as the walk needs it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Summary {
    /// The variables written, sorted; `None`: too many to list.
    writes: Option<Vec<VarId>>,
    /// Whether a label is among them.
    label: bool,
}

/// Every statement of a function in the body: its slot and summary.
#[derive(Debug)]
pub struct Index {
    slots: Vec<Option<Slot>>,
    summaries: Vec<Summary>,
}

impl Index {
    /// The index of `function`'s body (explicit stacks: nesting is not
    /// native recursion).
    pub fn new(function: &Function) -> Self {
        let count = function.stmts.len();
        let mut slots = vec![None; count];
        let mut order = Vec::new();
        let mut work: Vec<(Option<StmtId>, usize, &Block)> = vec![(None, 0, &function.body)];
        while let Some((parent, block, statements)) = work.pop() {
            for (index, &id) in statements.iter().enumerate() {
                let Some(slot) = slots.get_mut(id.0 as usize) else {
                    continue;
                };
                *slot = Some(Slot {
                    parent,
                    block,
                    index,
                });
                order.push(id);
                if let Some(stmt) = function.stmt(id) {
                    for (which, inner) in stmt.blocks().enumerate() {
                        work.push((Some(id), which, inner));
                    }
                }
            }
        }
        // Children come after their parent in `order`: summarise in
        // reverse, each statement then joining its children's.
        let mut summaries = vec![Summary::default(); count];
        for &id in order.iter().rev() {
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            let mut writes: Option<BTreeSet<VarId>> = Some(own_writes(stmt).collect());
            let mut label = matches!(stmt, Stmt::Label(_));
            for &child in stmt.blocks().flatten() {
                let Some(inner) = summaries.get(child.0 as usize) else {
                    continue;
                };
                label |= inner.label;
                match (&mut writes, &inner.writes) {
                    (Some(set), Some(list)) => set.extend(list.iter().copied()),
                    (_, None) => writes = None,
                    (None, Some(_)) => {}
                }
            }
            let writes = writes
                .filter(|set| set.len() <= MANY)
                .map(|set| set.into_iter().collect());
            if let Some(slot) = summaries.get_mut(id.0 as usize) {
                *slot = Summary { writes, label };
            }
        }
        Self { slots, summaries }
    }

    /// The slot of `id`, if in the body.
    pub fn slot(&self, id: StmtId) -> Option<Slot> {
        self.slots.get(id.0 as usize).copied().flatten()
    }

    /// Whether `id` (or a statement it holds) may write `var`.
    pub fn writes(&self, id: StmtId, var: VarId) -> bool {
        match self.summaries.get(id.0 as usize) {
            Some(Summary {
                writes: Some(list), ..
            }) => list.binary_search(&var).is_ok(),
            Some(Summary { writes: None, .. }) | None => true,
        }
    }

    /// The variables `id` (and what it holds) writes; `None`: too many to
    /// list (any).
    fn written(&self, id: StmtId) -> Option<&[VarId]> {
        self.summaries
            .get(id.0 as usize)
            .and_then(|summary| summary.writes.as_deref())
    }

    /// Whether `id` holds a label (or is one): control may enter it from
    /// elsewhere.
    pub fn labelled(&self, id: StmtId) -> bool {
        self.summaries
            .get(id.0 as usize)
            .is_none_or(|summary| summary.label)
    }
}

/// The variables `stmt` itself writes.
fn own_writes(stmt: &Stmt) -> impl Iterator<Item = VarId> + '_ {
    let places: &[Place] = match stmt {
        Stmt::Assign { place, .. } => core::slice::from_ref(place),
        Stmt::VaStart { list } => core::slice::from_ref(list),
        Stmt::Call { results, .. }
        | Stmt::Intrinsic { results, .. }
        | Stmt::Escape { results, .. } => results,
        Stmt::Expr(_)
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
        | Stmt::Try { .. } => &[],
    };
    places.iter().filter_map(|place| match *place {
        Place::Var(var) => Some(var),
        Place::Memory { .. } => None,
    })
}

/// The statements of block `which` of `parent` (`None`: the body).
pub fn block_at(function: &Function, parent: Option<StmtId>, which: usize) -> &[StmtId] {
    match parent {
        None => &function.body,
        Some(parent) => function
            .stmt(parent)
            .and_then(|stmt| stmt.blocks().nth(which))
            .map_or(&[], Vec::as_slice),
    }
}

/// Whether control never goes on past the end of `block`: its last
/// statement leaves (`return`, `goto`, `break`, `continue`, a trap,
/// unreachable code, a jump C cannot follow).
pub fn leaves(function: &Function, block: &[StmtId]) -> bool {
    let Some(&last) = block.last() else {
        return false;
    };
    match function.stmt(last) {
        Some(
            Stmt::Return(_)
            | Stmt::Goto(_)
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable,
        ) => true,
        Some(Stmt::Escape { kind, .. }) => match kind {
            Escape::UnresolvedJump | Escape::ForeignJump | Escape::OverlappingCode => true,
            Escape::NonStandardCall
            | Escape::StackTrick
            | Escape::SystemCall
            | Escape::Atomic
            | Escape::Update(_) => false,
        },
        Some(
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Label(_)
            | Stmt::Try { .. }
            | Stmt::VaStart { .. },
        )
        | None => false,
    }
}

/// What holds where a loop is entered.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Before {
    /// Comparisons that hold there.
    pub facts: Vec<Fact>,
    /// The counter's last write before it: an assignment, and its value
    /// (which reads no variable written after it). `None`: none found
    /// where the walk could see it.
    pub init: Option<(StmtId, ExprId)>,
    /// The `if` whose `then` is the loop alone (with no `else`).
    pub guard: Option<StmtId>,
}

/// The walk back from a loop.
struct Walk<'f> {
    function: &'f Function,
    index: &'f Index,
    counter: VarId,
    /// The variables written between the point reached and the loop.
    written: BTreeSet<VarId>,
    /// Whether something the walk cannot list was written (every fact
    /// from before is void).
    blind: bool,
    /// Whether the counter's last write may still be found.
    open: bool,
    before: Before,
}

impl Walk<'_> {
    /// The facts `condition` gives where it is `holds`, kept if they read
    /// nothing written between it and the loop (nor `also`).
    fn facts(&mut self, condition: ExprId, holds: bool, also: &[StmtId]) {
        if self.blind {
            return;
        }
        let mut found = Vec::new();
        facts_of(self.function, condition, holds, &mut found);
        for fact in found {
            let stale = |var: VarId| {
                self.written.contains(&var) || also.iter().any(|&id| self.index.writes(id, var))
            };
            let vars = [fact.a, fact.b].into_iter().filter_map(|term| match term {
                Term::Var(var) => Some(var),
                Term::Const(_) => None,
            });
            if !vars.into_iter().any(stale) {
                self.before.facts.push(fact);
            }
        }
    }

    /// Passes statement `id` (before the point reached).
    fn pass(&mut self, id: StmtId) {
        if let Some(Stmt::If {
            condition,
            then,
            otherwise,
        }) = self.function.stmt(id)
        {
            match (
                leaves(self.function, then),
                leaves(self.function, otherwise),
            ) {
                (true, false) => self.facts(*condition, false, otherwise),
                (false, true) => self.facts(*condition, true, then),
                (true, true) | (false, false) => {}
            }
        }
        if self.open && self.index.writes(id, self.counter) {
            self.open = false;
            if let Some(&Stmt::Assign {
                place: Place::Var(var),
                value,
            }) = self.function.stmt(id)
                && var == self.counter
            {
                let mut read = BTreeSet::new();
                reads(self.function, value, &mut read);
                if !self.blind && read.is_disjoint(&self.written) {
                    self.before.init = Some((id, value));
                }
            }
        }
        self.write(id);
    }

    /// Notes what `id` writes.
    fn write(&mut self, id: StmtId) {
        match self.index.written(id) {
            Some(list) => self.written.extend(list.iter().copied()),
            None => self.blind = true,
        }
    }
}

/// What holds where loop `loop_id` (counting with `counter`) is entered:
/// walking back from it through the statements before it in its block
/// (for a `for`, its `init` first), then those before the statement
/// holding the block, and so on, it collects the facts of
///
/// - an `if` before it whose one branch leaves (`if (g) return;`: `!g`),
/// - the `if` branch it is in (`g` in `then`, `!g` in `else`),
/// - the `while` or `for` body it is in (its condition),
///
/// each kept only if nothing between it and the loop writes what it
/// reads. A variable written in a loop around it voids the facts from
/// before that loop about it. It stops at a label (control may come from
/// elsewhere), a `for`'s `init` or `step`, a handler, the body's start or
/// after [`REACH`] statements. The counter's last write is its `init`
/// only if it is an assignment met before a loop or another write.
pub fn before(function: &Function, index: &Index, loop_id: StmtId, counter: VarId) -> Before {
    let mut walk = Walk {
        function,
        index,
        counter,
        written: BTreeSet::new(),
        blind: false,
        open: true,
        before: Before::default(),
    };
    if let Some(Stmt::For { init, .. }) = function.stmt(loop_id) {
        for &id in init.iter().rev() {
            walk.pass(id);
        }
    }
    let mut at = loop_id;
    let mut reach = REACH;
    let mut first = true;
    'walk: while let Some(slot) = index.slot(at) {
        let block = block_at(function, slot.parent, slot.block);
        for &id in block.get(..slot.index).unwrap_or(&[]).iter().rev() {
            reach = match reach.checked_sub(1) {
                Some(left) => left,
                None => break 'walk,
            };
            if index.labelled(id) {
                break 'walk;
            }
            walk.pass(id);
        }
        let Some(parent) = slot.parent else {
            break;
        };
        match function.stmt(parent) {
            Some(Stmt::If {
                condition,
                otherwise,
                ..
            }) => {
                let then = slot.block == 0;
                if first && then && block == [loop_id].as_slice() && otherwise.is_empty() {
                    walk.before.guard = Some(parent);
                }
                walk.facts(*condition, then, &[]);
            }
            Some(&Stmt::While { condition, .. }) => {
                walk.facts(condition, true, &[]);
                walk.open = false;
                walk.write(parent);
            }
            Some(&Stmt::For { condition, .. }) if slot.block == 2 => {
                walk.facts(condition, true, &[]);
                walk.open = false;
                walk.write(parent);
            }
            Some(Stmt::DoWhile { .. }) => {
                walk.open = false;
                walk.write(parent);
            }
            Some(Stmt::Switch { .. }) => walk.write(parent),
            Some(Stmt::Try { .. }) if slot.block == 0 => {}
            Some(_) | None => break,
        }
        first = false;
        at = parent;
    }
    walk.before
}
