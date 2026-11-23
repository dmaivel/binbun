//! Where each local is declared: [`Scopes`].
//!
//! A local is declared in the innermost C block holding every statement
//! that reads or writes it, just before the first of them there, where
//! its value from before does not matter: on no path from that point is
//! it read before it is written (liveness over the statements' control
//! flow, [`Flow`]: loops, `break`, `continue`, `goto`, exceptions). Where
//! it does (a value flows in from outside the block, or around a loop
//! from the iteration before), the next block out is tried, up to the
//! top of the body, which is where it stays otherwise. So an accumulator
//! set before a loop and updated in it is declared before the loop, and
//! a temporary each iteration sets before reading it is declared in the
//! loop's body.
//!
//! - The C blocks are the body, an `if`'s arms, a loop's body, a `Try`'s
//!   body and handlers. A `for`'s `init` and `step` are its header and a
//!   switch's arms share the switch's block (their statements follow
//!   `case` labels, where C declares nothing): what is in them counts as
//!   the `for` or the switch itself. A loop's condition is outside its
//!   body (C's `do { … } while (c)` does not see the body's
//!   declarations).
//! - A statement assigning the whole local first thing in its scope (the
//!   one it is declared at) is its initializer: `int32_t v = e;`. One in
//!   an `if` that may not run is not: `int32_t v;` goes before the `if`.
//! - A local every use of which is in one `for` whose `init` is that one
//!   assignment of it is declared in the header:
//!   `for (int32_t i = 0; …)`; one used after the loop is declared
//!   before it.
//! - No `goto` may jump into a scope past its declaration: a block whose
//!   part from the declaration on holds a label a `goto` from elsewhere
//!   names is not one.
//! - Only locals ([`VarKind::Local`]) move, not the `va_list`; variables
//!   in memory (a frame's objects, whose addresses calls are passed and
//!   may keep) live as long as the frame does, at the top.
//!
//! The placement is [`Function::declared`]; L2's interpreter makes a
//! local undefined where it is declared, so the differential check sees
//! a value read across its declaration. Runs last: other passes move
//! statements.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, LabelId, Place, Stmt, StmtId, VarId, VarKind};
use binbun_semantics::core::pass::{Changed, Cx, Fuel, Pass, Refusal};

use crate::pass::{L2Env, size};
use crate::simplify::flow::{Flow, Point};

/// Declaring locals where they are used (pass `scopes`): sets
/// [`Function::declared`] as the module says. Preserves everything but
/// the declarations.
#[derive(Clone, Copy, Debug, Default)]
pub struct Scopes;

impl<'e> Pass<Function, L2Env<'e>> for Scopes {
    fn name(&self) -> &'static str {
        "scopes"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(size(function))?;
        let declared = declarations(function, cx.fuel)?;
        if declared == function.declared {
            return Ok(Changed::No);
        }
        function.declared = declared;
        Ok(Changed::Yes)
    }
}

/// Where a statement is: the statement holding its block (`None`: the
/// body), which of that statement's blocks ([`Stmt::blocks`]), and its
/// position there.
#[derive(Clone, Copy, Debug)]
struct Parent {
    owner: Option<StmtId>,
    child: usize,
    position: usize,
}

/// A block: the statement holding it (`None`: the body) and which of its
/// blocks.
type BlockKey = (Option<StmtId>, usize);

/// The function's statements in their blocks, and its jumps.
struct Layout {
    parents: Vec<Option<Parent>>,
    /// Each label a `goto` names: the label's statement and the gotos'.
    jumps: Vec<(StmtId, Vec<StmtId>)>,
}

impl Layout {
    fn new(function: &Function) -> Self {
        let mut parents = vec![None; function.stmts.len()];
        let mut labels: BTreeMap<LabelId, StmtId> = BTreeMap::new();
        let mut gotos: BTreeMap<LabelId, Vec<StmtId>> = BTreeMap::new();
        let mut work = vec![(None, 0, &function.body)];
        while let Some((owner, child, block)) = work.pop() {
            for (position, &id) in block.iter().enumerate() {
                let Some(slot) = parents.get_mut(id.0 as usize) else {
                    continue;
                };
                *slot = Some(Parent {
                    owner,
                    child,
                    position,
                });
                let Some(stmt) = function.stmt(id) else {
                    continue;
                };
                if let &Stmt::Label(label) = stmt {
                    labels.insert(label, id);
                }
                if let &Stmt::Goto(label) = stmt {
                    gotos.entry(label).or_default().push(id);
                }
                for (index, inner) in stmt.blocks().enumerate() {
                    work.push((Some(id), index, inner));
                }
            }
        }
        let jumps = gotos
            .into_iter()
            .filter_map(|(label, from)| Some((*labels.get(&label)?, from)))
            .collect();
        Self { parents, jumps }
    }

    fn parent(&self, id: StmtId) -> Option<Parent> {
        self.parents.get(id.0 as usize).copied().flatten()
    }

    /// The C blocks around statement `id`, outermost first, each with the
    /// statement of its own that holds `id` (or is it).
    fn path(&self, function: &Function, id: StmtId) -> Vec<(BlockKey, StmtId)> {
        let mut out = Vec::new();
        let mut at = id;
        while let Some(parent) = self.parent(at) {
            match parent.owner {
                None => {
                    out.push(((None, 0), at));
                    break;
                }
                Some(owner) => {
                    if c_block(function, owner, parent.child) {
                        out.push(((Some(owner), parent.child), at));
                    }
                    at = owner;
                }
            }
        }
        out.reverse();
        out
    }

    /// Whether statement `id` is in block `key`, in or under a statement
    /// of it from position `from` on.
    fn within(&self, id: StmtId, key: BlockKey, from: usize) -> bool {
        let mut at = id;
        while let Some(parent) = self.parent(at) {
            if (parent.owner, parent.child) == key {
                return parent.position >= from;
            }
            match parent.owner {
                Some(owner) => at = owner,
                None => return false,
            }
        }
        false
    }

    /// Whether a `goto` from outside the part of block `key` from
    /// position `from` to before `to` names a label inside it.
    fn entered(&self, key: BlockKey, from: usize, to: Option<usize>) -> bool {
        let inside = |id: StmtId| {
            self.within(id, key, from) && to.is_none_or(|to| !self.within(id, key, to))
        };
        self.jumps
            .iter()
            .any(|(label, gotos)| inside(*label) && gotos.iter().any(|&from| !inside(from)))
    }
}

/// Whether block `child` of statement `owner` is a C block (else its
/// statements are the statement's own: a `for`'s header, a switch's
/// arms).
fn c_block(function: &Function, owner: StmtId, child: usize) -> bool {
    match function.stmt(owner) {
        Some(Stmt::If { .. } | Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::Try { .. }) => {
            true
        }
        Some(Stmt::For { .. }) => child == 2,
        Some(_) | None => false,
    }
}

/// What a statement itself (not the blocks it holds) does with the
/// locals that may move, by their index.
#[derive(Clone, Debug, Default)]
struct Refs {
    /// Read (and assignment expressions not surely run).
    reads: Vec<usize>,
    /// Written whole: by a simple statement's places, or by an assignment
    /// expression a condition surely runs (and does not read).
    writes: Vec<usize>,
}

/// The locals statement `stmt` reads and writes, by their index in
/// `index` (those not there are left out).
fn refs(function: &Function, stmt: &Stmt, index: &[Option<usize>]) -> Refs {
    let mut read = BTreeSet::new();
    let mut assigned = BTreeSet::new();
    let mut sure = BTreeSet::new();
    // Each expression with whether it surely runs.
    let mut seen: BTreeMap<ExprId, bool> = BTreeMap::new();
    let mut work: Vec<(ExprId, bool)> = stmt.roots().into_iter().map(|id| (id, true)).collect();
    while let Some((id, surely)) = work.pop() {
        match seen.get(&id) {
            Some(&before) if before || !surely => continue,
            Some(_) | None => {}
        }
        seen.insert(id, surely);
        let Some(expr) = function.expr(id) else {
            continue;
        };
        if let Expr::Var(var) = *expr {
            read.insert(var);
        } else if let Expr::Assign { var, value } = *expr {
            assigned.insert(var);
            if surely {
                sure.insert(var);
            }
            work.push((value, surely));
        } else if let Expr::Logical(_, left, right) = *expr {
            work.push((left, surely));
            work.push((right, false));
        } else {
            work.extend(expr.operands(function).map(|operand| (operand, surely)));
        }
    }
    let at = |var: &VarId| index.get(var.0 as usize).copied().flatten();
    let mut reads: Vec<usize> = read
        .iter()
        .chain(assigned.difference(&sure))
        .filter_map(at)
        .collect();
    reads.sort_unstable();
    reads.dedup();
    let mut writes: Vec<usize> = stmt
        .places()
        .iter()
        .filter_map(|place| match *place {
            Place::Var(var) => Some(var),
            Place::Memory { .. } => None,
        })
        .chain(sure.difference(&read).copied())
        .filter_map(|var| at(&var))
        .collect();
    writes.sort_unstable();
    writes.dedup();
    Refs { reads, writes }
}

/// The locals live at the start of each node of `flow` (`words` words
/// each, by index), `refs` saying what each statement does: backward to
/// a fixed point, a unit of fuel per node visited.
fn liveness(
    flow: &Flow,
    refs: &[Option<Refs>],
    words: usize,
    fuel: &mut Fuel,
) -> Result<Vec<u64>, Refusal> {
    let count = flow.points.len();
    let mut live = vec![0u64; count.checked_mul(words).ok_or(Refusal::OutOfFuel)?];
    let predecessors = flow.predecessors();
    let mut work: Vec<usize> = (0..count).collect();
    let mut queued = vec![true; count];
    let mut input = vec![0u64; words];
    while let Some(node) = work.pop() {
        fuel.spend(1)?;
        if let Some(flag) = queued.get_mut(node) {
            *flag = false;
        }
        input.fill(0);
        for &next in flow.successors.get(node).map_or(&[][..], Vec::as_slice) {
            let next = next as usize;
            if let Some(row) = live.get(next * words..(next + 1) * words) {
                for (word, bits) in input.iter_mut().zip(row) {
                    *word |= bits;
                }
            }
        }
        let own = match flow.points.get(node) {
            Some(&(Point::Simple(id) | Point::Test(id))) => {
                refs.get(id.0 as usize).and_then(Option::as_ref)
            }
            Some(Point::Entry | Point::Exit | Point::Label) | None => None,
        };
        if let Some(own) = own {
            for &var in &own.writes {
                if let Some(word) = input.get_mut(var / 64) {
                    *word &= !(1 << (var % 64));
                }
            }
            for &var in &own.reads {
                if let Some(word) = input.get_mut(var / 64) {
                    *word |= 1 << (var % 64);
                }
            }
        }
        let Some(row) = live.get_mut(node * words..(node + 1) * words) else {
            continue;
        };
        if *row != *input {
            row.copy_from_slice(&input);
            for &previous in predecessors.get(node).map_or(&[][..], Vec::as_slice) {
                if let Some(flag) = queued.get_mut(previous as usize)
                    && !*flag
                {
                    *flag = true;
                    work.push(previous as usize);
                }
            }
        }
    }
    Ok(live)
}

/// Where each local of `function` is declared ([`Function::declared`];
/// one left out is declared at the top).
///
/// # Errors
///
/// Out of fuel (in liveness).
fn declarations(
    function: &Function,
    fuel: &mut Fuel,
) -> Result<BTreeMap<StmtId, Vec<VarId>>, Refusal> {
    let va = function.va_list();
    let mut index = vec![None; function.variables.len()];
    let mut vars = Vec::new();
    for (number, variable) in (0u32..).zip(&function.variables) {
        if variable.kind == VarKind::Local && va != Some(VarId(number)) {
            if let Some(slot) = index.get_mut(number as usize) {
                *slot = Some(vars.len());
            }
            vars.push(VarId(number));
        }
    }
    let mut declared: BTreeMap<StmtId, Vec<VarId>> = BTreeMap::new();
    if vars.is_empty() {
        return Ok(declared);
    }
    let layout = Layout::new(function);
    // What each statement in a block does, and where each local is used.
    let mut all = vec![None; function.stmts.len()];
    let mut uses: Vec<Vec<StmtId>> = vec![Vec::new(); vars.len()];
    for (number, stmt) in (0u32..).zip(&function.stmts) {
        let id = StmtId(number);
        if layout.parent(id).is_none() {
            continue;
        }
        let own = refs(function, stmt, &index);
        for &var in own.reads.iter().chain(&own.writes) {
            if let Some(list) = uses.get_mut(var)
                && list.last() != Some(&id)
            {
                list.push(id);
            }
        }
        if let Some(slot) = all.get_mut(number as usize) {
            *slot = Some(own);
        }
    }
    let flow = Flow::new(function);
    let words = vars.len().div_ceil(64);
    let live = liveness(&flow, &all, words, fuel)?;
    let live_at = |id: StmtId, var: usize| {
        let node = flow.entries.get(id.0 as usize).copied().unwrap_or(u32::MAX) as usize;
        live.get(node * words + var / 64)
            .is_none_or(|word| word & (1 << (var % 64)) != 0)
    };
    for (var, used) in uses.iter().enumerate() {
        let Some(&local) = vars.get(var) else {
            continue;
        };
        if let Some(at) = place(function, &layout, used, local, |id| live_at(id, var)) {
            declared.entry(at).or_default().push(local);
        }
    }
    Ok(declared)
}

/// Where local `var`, used by the statements `used`, is declared: the
/// statement it is declared before (or the `for` header's assignment),
/// `None` for the top. `live` says whether it is live on entering a
/// statement.
fn place(
    function: &Function,
    layout: &Layout,
    used: &[StmtId],
    var: VarId,
    live: impl Fn(StmtId) -> bool,
) -> Option<StmtId> {
    let paths: Vec<Vec<(BlockKey, StmtId)>> =
        used.iter().map(|&id| layout.path(function, id)).collect();
    let first = paths.first()?;
    // How many C blocks every use is in.
    let common = paths.iter().fold(first.len(), |common, path| {
        first
            .iter()
            .zip(path)
            .take(common)
            .take_while(|(a, b)| a.0 == b.0)
            .count()
    });
    let position = |id: StmtId| layout.parent(id).map_or(0, |parent| parent.position);
    for level in (0..common).rev() {
        let (key, _) = *first.get(level)?;
        // The first statement of the block holding a use, and whether it
        // holds them all.
        let tops = paths
            .iter()
            .filter_map(|path| path.get(level).map(|&(_, top)| top));
        let at = tops.clone().min_by_key(|&top| position(top))?;
        let alone = tops.clone().all(|top| top == at);
        let from = position(at);
        // A `for` holding every use, its `init` the one assignment of the
        // local: declared in the header.
        if alone
            && let Some(Stmt::For { init, .. }) = function.stmt(at)
            && let [assignment] = init.as_slice()
            && matches!(
                function.stmt(*assignment),
                Some(&Stmt::Assign { place: Place::Var(written), .. }) if written == var
            )
        {
            if !live(at) && !layout.entered(key, from, Some(from + 1)) {
                return Some(*assignment);
            }
            continue;
        }
        if !live(at) && !layout.entered(key, from, None) {
            // Before the body's first statement, but as its initializer:
            // where it is declared anyway. An assignment of it, or a call
            // or intrinsic whose one result it is (`T v = f(a);`), as the
            // printer takes them.
            let initialized = matches!(
                function.stmt(at),
                Some(&Stmt::Assign { place: Place::Var(written), .. }) if written == var
            ) || matches!(
                function.stmt(at),
                Some(Stmt::Call { results, .. } | Stmt::Intrinsic { results, .. })
                    if results.as_slice() == [Place::Var(var)]
            );
            return (key.0.is_some() || from > 0 || initialized).then_some(at);
        }
    }
    None
}
