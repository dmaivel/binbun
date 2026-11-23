//! Where each statement is, what it and the statements it holds write,
//! and where each variable is written and read: what the simplification
//! passes need to move a value from its assignment to a later reader
//! ([`Facts::available`]).

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Block, Expr, ExprId, Function, LabelId, Place, Stmt, StmtId, VarId};
use binbun_semantics::core::pass::{Fuel, Refusal};

use super::expr::{Info, in_memory, reads, roots};

/// Where a statement is: the statement holding its block (`None`: the
/// body), which of that statement's blocks ([`Stmt::blocks`] order), and
/// its index there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Position {
    pub(super) parent: Option<StmtId>,
    pub(super) block: usize,
    pub(super) index: usize,
}

/// What a statement and the statements it holds may do.
#[derive(Clone, Debug, Default)]
struct Summary {
    /// The variables not in memory it writes.
    writes: BTreeSet<VarId>,
    /// Whether it may write memory (a store, a call, an intrinsic, an
    /// escape).
    memory: bool,
    /// Whether it holds a label a `goto` names (control may enter there).
    label: bool,
    /// What it does besides assigning to variables not in memory and
    /// holding labels.
    noise: Noise,
}

/// What a statement does besides assigning to variables not in memory
/// and holding labels, ordered: the more, the less may move across it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Noise {
    /// Nothing: its values cannot fault.
    #[default]
    Quiet,
    /// Its values may load, but none calls: a load may move across it
    /// (that changes only which of two faulting loads faults first, as
    /// C's unordered operands may), a call may not.
    Loads,
    /// More (a call, a store, control): neither may.
    Effect,
}

/// The facts of one function, as it was when they were computed; a pass
/// that changes only expressions (not what a statement writes, nor where
/// it is) may go on using them.
#[derive(Debug)]
pub(super) struct Facts {
    position: Vec<Option<Position>>,
    summary: Vec<Summary>,
    /// The statements writing each variable not in memory, by id.
    pub(super) defs: Vec<Vec<StmtId>>,
    /// How many times each variable is read (each use of a shared node
    /// counted), by id.
    pub(super) reads: Vec<u32>,
    /// Of those, how many are in the value of an assignment to the
    /// variable itself.
    pub(super) own: Vec<u32>,
    /// The statements reading each variable, by id.
    pub(super) readers: Vec<Vec<StmtId>>,
}

/// The labels `goto`s in `block` (and the blocks it holds) name.
fn targets(function: &Function, block: &Block, found: &mut BTreeSet<LabelId>) {
    for &id in block {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        if let Stmt::Goto(label) = *stmt {
            found.insert(label);
        }
        for inner in stmt.blocks() {
            targets(function, inner, found);
        }
    }
}

/// Counts what the reads of each variable need: a node used twice is
/// evaluated twice.
struct Counter {
    paths: Vec<u32>,
}

impl Counter {
    /// Adds `roots`' reads of each variable not in memory to `reads`
    /// (grown as needed); the number of nodes visited.
    fn count(&mut self, function: &Function, roots: &[ExprId], reads: &mut Vec<u32>) -> u64 {
        if self.paths.len() < function.exprs.len() {
            self.paths.resize(function.exprs.len(), 0);
        }
        let mut work: Vec<ExprId> = roots.to_vec();
        let mut nodes: Vec<ExprId> = Vec::new();
        while let Some(id) = work.pop() {
            let Some(slot) = self.paths.get_mut(id.0 as usize) else {
                continue;
            };
            if *slot == u32::MAX {
                continue;
            }
            // Marked as seen; counted from 0 below.
            *slot = u32::MAX;
            nodes.push(id);
            if let Some(expr) = function.expr(id) {
                work.extend(expr.operands(function));
            }
        }
        for &id in &nodes {
            if let Some(slot) = self.paths.get_mut(id.0 as usize) {
                *slot = 0;
            }
        }
        for &root in roots {
            if let Some(slot) = self.paths.get_mut(root.0 as usize) {
                *slot = slot.saturating_add(1);
            }
        }
        // Users before their operands (operands have smaller ids).
        nodes.sort_unstable_by(|a, b| b.cmp(a));
        for &id in &nodes {
            let paths = self.paths.get(id.0 as usize).copied().unwrap_or(0);
            let Some(expr) = function.expr(id) else {
                continue;
            };
            if let Expr::Var(var) = *expr
                && !in_memory(function, var)
            {
                let index = var.0 as usize;
                if reads.len() <= index {
                    reads.resize(index + 1, 0);
                }
                if let Some(count) = reads.get_mut(index) {
                    *count = count.saturating_add(paths);
                }
            }
            for operand in expr.operands(function) {
                if let Some(slot) = self.paths.get_mut(operand.0 as usize) {
                    *slot = slot.saturating_add(paths);
                }
            }
        }
        for &id in &nodes {
            if let Some(slot) = self.paths.get_mut(id.0 as usize) {
                *slot = 0;
            }
        }
        u64::try_from(nodes.len()).unwrap_or(u64::MAX)
    }
}

/// What [`Facts::new`] builds as it walks the body.
struct Builder<'a> {
    function: &'a Function,
    info: &'a Info,
    targeted: BTreeSet<LabelId>,
    counter: Counter,
    facts: Facts,
    visited: u64,
}

impl Builder<'_> {
    /// Walks `block` (block `index` of `parent`); the summary of it.
    fn block(&mut self, block: &Block, parent: Option<StmtId>, index: usize) -> Summary {
        let mut total = Summary::default();
        for (at, &id) in block.iter().enumerate() {
            let Some(stmt) = self.function.stmt(id) else {
                continue;
            };
            if let Some(slot) = self.facts.position.get_mut(id.0 as usize) {
                *slot = Some(Position {
                    parent,
                    block: index,
                    index: at,
                });
            }
            let mut summary = self.own(id, stmt);
            for (inner, nested) in stmt.blocks().enumerate() {
                let below = self.block(nested, Some(id), inner);
                merge(&mut summary, below);
            }
            if let Some(slot) = self.facts.summary.get_mut(id.0 as usize) {
                *slot = summary.clone();
            }
            merge(&mut total, summary);
        }
        total
    }

    /// The summary of `stmt` itself (not its blocks); records its reads and
    /// writes.
    fn own(&mut self, id: StmtId, stmt: &Stmt) -> Summary {
        let function = self.function;
        let roots = roots(stmt);
        let mut counts = Vec::new();
        self.visited += 1 + self.counter.count(function, &roots, &mut counts);
        for (index, &count) in counts.iter().enumerate() {
            if count == 0 {
                continue;
            }
            if let Some(total) = self.facts.reads.get_mut(index) {
                *total = total.saturating_add(count);
            }
            if let Some(readers) = self.facts.readers.get_mut(index) {
                readers.push(id);
            }
        }
        let mut summary = Summary::default();
        let write = |place: &Place, summary: &mut Summary, facts: &mut Facts| match *place {
            Place::Var(var) if !in_memory(function, var) => {
                summary.writes.insert(var);
                if let Some(defs) = facts.defs.get_mut(var.0 as usize) {
                    defs.push(id);
                }
            }
            Place::Var(_) | Place::Memory { .. } => summary.memory = true,
        };
        match stmt {
            Stmt::Assign { place, value } => {
                write(place, &mut summary, &mut self.facts);
                summary.noise = if summary.memory || self.info.calls(*value) {
                    Noise::Effect
                } else if self.info.faults(*value) {
                    Noise::Loads
                } else {
                    Noise::Quiet
                };
                if let Place::Var(var) = *place
                    && let Some(own) = self.facts.own.get_mut(var.0 as usize)
                {
                    *own = own.saturating_add(counts.get(var.0 as usize).copied().unwrap_or(0));
                }
            }
            Stmt::Call { results, .. }
            | Stmt::Intrinsic { results, .. }
            | Stmt::Escape { results, .. } => {
                for place in results {
                    write(place, &mut summary, &mut self.facts);
                }
                summary.memory = true;
                summary.noise = Noise::Effect;
            }
            // The saves write the stack.
            Stmt::VaStart { list } => {
                write(list, &mut summary, &mut self.facts);
                summary.memory = true;
                summary.noise = Noise::Effect;
            }
            Stmt::Label(label) => summary.label = self.targeted.contains(label),
            Stmt::Expr(_)
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Try { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable => summary.noise = Noise::Effect,
        }
        // A call in an expression may write any memory.
        if roots.iter().any(|&root| self.info.calls(root)) {
            summary.memory = true;
            summary.noise = Noise::Effect;
        }
        summary
    }
}

/// Adds `other` to `summary`.
fn merge(summary: &mut Summary, other: Summary) {
    summary.writes.extend(other.writes);
    summary.memory |= other.memory;
    summary.label |= other.label;
    summary.noise = summary.noise.max(other.noise);
}

/// What a value moved to a reader reads.
struct Value {
    vars: BTreeSet<VarId>,
    faults: bool,
    undefined: bool,
    /// Whether it calls: a call stays in the `Try` bodies it is in (which
    /// say where it unwinds to).
    calls: bool,
}

impl Value {
    /// Whether a statement with `summary`, between the assignment and the
    /// reader, keeps the value from moving: a label; a write to what it
    /// reads; for a call, anything that may fault (a load it moved
    /// across could read what the call writes) or write memory; for a
    /// load, a write of memory or any effect but another load's.
    fn blocked(&self, summary: &Summary) -> bool {
        summary.label
            || (self.calls && (summary.memory || summary.noise >= Noise::Loads))
            || (self.faults && (summary.memory || summary.noise == Noise::Effect))
            || summary.writes.iter().any(|var| self.vars.contains(var))
    }
}

impl Facts {
    /// The facts of `function` (whose expressions `info` describes),
    /// spending a unit of `fuel` per statement and expression visited.
    ///
    /// # Errors
    ///
    /// Out of fuel.
    pub(super) fn new(function: &Function, info: &Info, fuel: &mut Fuel) -> Result<Self, Refusal> {
        let mut targeted = BTreeSet::new();
        targets(function, &function.body, &mut targeted);
        let vars = function.variables.len();
        let mut builder = Builder {
            function,
            info,
            targeted,
            counter: Counter { paths: Vec::new() },
            facts: Facts {
                position: vec![None; function.stmts.len()],
                summary: vec![Summary::default(); function.stmts.len()],
                defs: vec![Vec::new(); vars],
                reads: vec![0; vars],
                own: vec![0; vars],
                readers: vec![Vec::new(); vars],
            },
            visited: 0,
        };
        builder.block(&function.body, None, 0);
        fuel.spend(builder.visited)?;
        Ok(builder.facts)
    }

    /// Where statement `id` is, if it is in the body.
    pub(super) fn position(&self, id: StmtId) -> Option<Position> {
        self.position.get(id.0 as usize).copied().flatten()
    }

    /// Whether the statement `def`, assigning `value`, may be skipped and
    /// `value` evaluated where statement `at` evaluates its roots instead,
    /// with the same result (see the module documentation of
    /// [`super`]): `at` follows `def` in its block, or is inside a
    /// statement that does; no label a `goto` names, and no write to a
    /// variable `value` reads, lies between (with a loop on the way, the
    /// whole loop); if `value` loads, no store either, and nothing else
    /// that could make its fault happen at another point (`at` is then in
    /// `def`'s block, not a loop, and only assignments to variables not in
    /// memory lie between, of values that do not call and, if `value`
    /// calls, do not load either: a load may pass another, a call may
    /// not);
    /// if `value` has an undefined part, no loop is on the way.
    ///
    /// Also where `at` is a `do`-`while` and `def` is in its body: the
    /// condition is evaluated right after the body, so `value` is
    /// available there if nothing after `def` in the body blocks it (as
    /// between two statements of a block), no `continue` of the loop
    /// skips `def`, and `value` has no undefined part.
    pub(super) fn available(
        &self,
        function: &Function,
        info: &Info,
        def: StmtId,
        value: ExprId,
        at: StmtId,
    ) -> bool {
        let Some(from) = self.position(def) else {
            return false;
        };
        let mut moved = Value {
            vars: BTreeSet::new(),
            faults: info.faults(value),
            undefined: info.undefined(value),
            calls: info.calls(value),
        };
        reads(function, value, &mut moved.vars);
        if let Some(Stmt::DoWhile { body, .. }) = function.stmt(at)
            && from.parent == Some(at)
        {
            let after = body.get(from.index + 1..).unwrap_or_default();
            return !moved.undefined
                && !after.iter().any(|&id| moved.blocked(self.summary(id)))
                && !continues(function, body, at);
        }
        // `at`, then the statements holding it, up to the one in `def`'s
        // block.
        let mut chain = vec![at];
        let top = loop {
            let Some(&current) = chain.last() else {
                return false;
            };
            let Some(position) = self.position(current) else {
                return false;
            };
            if position.parent == from.parent && position.block == from.block {
                if position.index <= from.index {
                    return false;
                }
                break position;
            }
            match position.parent {
                Some(parent) => chain.push(parent),
                None => return false,
            }
        };
        if moved.faults && (chain.len() > 1 || is_loop(function, at)) {
            return false;
        }
        let Some(block) = block_of(function, from.parent, from.block) else {
            return false;
        };
        let between = block.get(from.index + 1..top.index).unwrap_or_default();
        if between.iter().any(|&id| moved.blocked(self.summary(id))) {
            return false;
        }
        let mut in_loop = false;
        for pair in chain.windows(2).rev() {
            let &[child, parent] = pair else {
                continue;
            };
            if self.entered(function, &moved, child, parent, &mut in_loop) {
                return false;
            }
        }
        if is_loop(function, at) {
            // Its condition is evaluated after its body, again and again.
            in_loop = true;
            if moved.blocked(self.summary(at)) {
                return false;
            }
        }
        !(moved.undefined && in_loop)
    }

    /// Whether what runs in `parent` before `child` (all of it, for a loop)
    /// blocks `moved`; notes a loop in `in_loop`.
    fn entered(
        &self,
        function: &Function,
        moved: &Value,
        child: StmtId,
        parent: StmtId,
        in_loop: &mut bool,
    ) -> bool {
        if is_loop(function, parent) {
            *in_loop = true;
            return moved.blocked(self.summary(parent));
        }
        let Some(position) = self.position(child) else {
            return true;
        };
        let Some(stmt) = function.stmt(parent) else {
            return true;
        };
        if let Stmt::Try { .. } = stmt {
            // Into its body, a call would unwind elsewhere; a handler is
            // entered from any point of the body, after any part of it.
            return match position.block {
                0 => {
                    moved.calls
                        || stmt
                            .blocks()
                            .next()
                            .and_then(|body| body.get(..position.index))
                            .unwrap_or_default()
                            .iter()
                            .any(|&id| moved.blocked(self.summary(id)))
                }
                _ => {
                    moved.calls
                        || stmt.blocks().next().is_none_or(|body| {
                            body.iter().any(|&id| moved.blocked(self.summary(id)))
                        })
                }
            };
        }
        // Earlier arms of a switch may fall through into this one.
        let earlier = matches!(stmt, Stmt::Switch { .. });
        for (index, block) in stmt.blocks().enumerate() {
            let before = if index == position.block {
                block.get(..position.index).unwrap_or_default()
            } else if earlier && index < position.block {
                block.as_slice()
            } else {
                continue;
            };
            if before.iter().any(|&id| moved.blocked(self.summary(id))) {
                return true;
            }
        }
        false
    }

    fn summary(&self, id: StmtId) -> &Summary {
        const NONE: &Summary = &Summary {
            writes: BTreeSet::new(),
            memory: true,
            label: true,
            noise: Noise::Effect,
        };
        self.summary.get(id.0 as usize).unwrap_or(NONE)
    }
}

/// Block `index` of `parent` (`None`: the body).
fn block_of(function: &Function, parent: Option<StmtId>, index: usize) -> Option<&Block> {
    match parent {
        None => Some(&function.body),
        Some(parent) => function.stmt(parent)?.blocks().nth(index),
    }
}

/// Whether statement `id` is a loop.
fn is_loop(function: &Function, id: StmtId) -> bool {
    function.stmt(id).is_some_and(Stmt::is_loop)
}

/// Whether `block` (and the blocks it holds) has a `continue` of loop
/// `of`.
fn continues(function: &Function, block: &Block, of: StmtId) -> bool {
    let mut work = vec![block];
    while let Some(block) = work.pop() {
        for stmt in block.iter().filter_map(|&id| function.stmt(id)) {
            if *stmt == Stmt::Continue(of) {
                return true;
            }
            work.extend(stmt.blocks());
        }
    }
    false
}
