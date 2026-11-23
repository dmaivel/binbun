//! Catch dispatch (pass `catch-dispatch`): a landing pad's tests of the
//! selector become the handlers of its `Try`.
//!
//! Lowering guards each call that unwinds to a landing pad with a `Try`
//! whose one [`HandlerKind::Landing`] handler jumps to the pad's code,
//! which reads the selector and tests it against its action chain's
//! filters ([`Action::selector`]) to choose a handler. The personality
//! routine enters the pad only with one of those selectors (the filter of
//! the action it matched; 0 for a cleanup, entered only when no catch of
//! the chain matched), so for each action this pass follows the pad's code
//! from the handler with the selector known, on the goto-only body
//! lowering makes:
//!
//! - an assignment of a variable from a pure value (no load, no call) is
//!   evaluated (the selector, [`Expr::Exception`], is the action's);
//! - an `if` whose condition that decides is a dispatch decision: the
//!   assignments since the previous one (and on the arm taken) are part of
//!   the dispatch, and the walk follows the arm taken;
//! - anything else (a call, an `if` not decided, a load) is the handler's
//!   code: it starts at the label where the walk last entered code after
//!   a decision (the pad's own code, if none was taken).
//!
//! The `Try`'s handlers become one per action, in the order the
//! personality routine tries them (catches in chain order, up to a
//! catch-all; a cleanup last: it is entered only when no catch matches),
//! each the dispatch's assignments (the selector its constant) and a
//! `goto` to its code. A path of the dispatch no action takes must end in
//! a call that resumes unwinding ([`Exceptions::resume`]): the implicit
//! propagation when no handler matches. The `Try`'s provenance names the
//! blocks of the dispatch (the pad's assignments and decisions) and of its
//! resume paths as [`Origin::Absorbed`]: the choice among the handlers
//! stands for them, and the code reached from elsewhere and the code
//! only the landing handler reached is removed; a `Try` whose taken over
//! blocks would still have code reached from elsewhere keeps its landing
//! handler (the structure check could not tell them apart).
//! A resume path other code also reaches (a compiler shares one resume
//! between the pad and a cleanup) stays that code's, and is not absorbed:
//! going there only propagates the exception, as the `Try` says.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{
    Block, Callee, Escape, ExceptionValue, Expr, ExprId, Function, Handler, HandlerKind, LabelId,
    Logical, Origin, Place, Stmt, StmtId, VarId,
};
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::interpret::{self, Value};
use binbun_ssa::ir::BlockId;

use super::{Action, Exceptions, Floor, Unknown};
use crate::pass::L2Env;

/// How many statements (or expression nodes) one walk through a landing
/// pad's code may visit.
const STEPS: usize = 512;

/// Catch dispatch (pass `catch-dispatch`, see the module documentation).
/// Runs on lowering's goto-only body, before structuring. Preserves
/// nothing. Its last run's [`floors`](Self::floors) say why each landing
/// pad whose `Try` it left a landing handler kept it.
#[derive(Clone, Debug, Default)]
pub struct CatchDispatch {
    /// Why the `Try`s of each landing pad keep their landing handler (the
    /// goto floor), by the pad's address: those of its last run.
    pub floors: BTreeMap<u64, Floor>,
}

impl<'e> Pass<Function, L2Env<'e>> for CatchDispatch {
    fn name(&self) -> &'static str {
        "catch-dispatch"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let exceptions = cx.env.exceptions;
        self.floors.clear();
        if exceptions.pads.is_empty() && exceptions.unknown.is_empty() {
            return Ok(Changed::No);
        }
        let (plans, reached) = {
            let flat = Flat::new(function);
            let mut plans = BTreeMap::new();
            for &id in &function.body {
                cx.fuel.spend(1)?;
                let Some(Stmt::Try { handlers, .. }) = function.stmt(id) else {
                    continue;
                };
                let [
                    Handler {
                        kind: HandlerKind::Landing(pad),
                        body,
                    },
                ] = handlers.as_slice()
                else {
                    continue;
                };
                let Some(chain) = exceptions.pads.get(pad) else {
                    let unknown = exceptions.unknown.get(pad).copied();
                    let floor = Floor::Unknown(unknown.unwrap_or(Unknown::Damaged));
                    self.floors.insert(*pad, floor);
                    continue;
                };
                cx.fuel
                    .spend(u64::try_from(STEPS.saturating_mul(chain.len())).unwrap_or(u64::MAX))?;
                match flat.plan(body, chain, exceptions) {
                    Some(plan) => {
                        plans.insert(id, (*pad, plan));
                    }
                    None => {
                        self.floors.insert(*pad, Floor::Dispatch);
                    }
                }
            }
            // Code a dispatch takes over must have no other way in.
            loop {
                cx.fuel
                    .spend(u64::try_from(function.body.len()).unwrap_or(u64::MAX))?;
                let (_, reached) = flat.reached(&plans);
                let before = plans.len();
                plans.retain(|_, (pad, plan)| {
                    let alone = plan.taken_over().all(|block| !reached.contains(&block));
                    if !alone {
                        self.floors.insert(*pad, Floor::Shared);
                    }
                    alone
                });
                if plans.len() == before {
                    break;
                }
            }
            let (reached, blocks) = flat.reached(&plans);
            for (_, plan) in plans.values_mut() {
                let alone = plan.resumes.iter().filter(|block| !blocks.contains(block));
                plan.absorbed.extend(alone);
            }
            (plans, reached)
        };
        if plans.is_empty() {
            return Ok(Changed::No);
        }
        // Copies first: a plan whose copy fails leaves the function as it
        // was.
        let mut handlers = Vec::with_capacity(plans.len());
        for (&id, (pad, plan)) in &plans {
            let Some(new) = arms(function, plan) else {
                self.floors.insert(*pad, Floor::Dispatch);
                return Ok(Changed::No);
            };
            handlers.push((id, new));
        }
        for ((id, new), (_, plan)) in handlers.into_iter().zip(plans.values()) {
            apply(function, id, new, plan);
        }
        // The code only the landing pads' handlers reached is gone.
        let body = mem::take(&mut function.body);
        function.body = body
            .into_iter()
            .zip(reached)
            .filter_map(|(id, reached)| reached.then_some(id))
            .collect();
        Ok(Changed::Yes)
    }
}

/// A handler a `Try` gets: what it is entered for, with which selector,
/// the dispatch's assignments on its way, and where its code starts.
#[derive(Clone, Debug)]
struct Arm {
    kind: HandlerKind,
    selector: i64,
    prefix: Vec<StmtId>,
    leaf: LabelId,
}

/// What becomes of one `Try`.
#[derive(Clone, Debug)]
struct Plan {
    arms: Vec<Arm>,
    /// The blocks of the dispatch.
    absorbed: BTreeSet<BlockId>,
    /// The blocks of its resume paths: absorbed too, unless other code
    /// reaches them (another cleanup's resume that the compiler shared),
    /// where the dispatch still goes to them.
    resumes: BTreeSet<BlockId>,
}

impl Plan {
    fn taken_over(&self) -> impl Iterator<Item = BlockId> + '_ {
        self.absorbed.iter().copied()
    }
}

/// One walk through a landing pad's code with a known selector.
#[derive(Clone, Debug, Default)]
struct Walk {
    /// The dispatch's statements on the way, in order.
    prefix: Vec<StmtId>,
    /// Where the handler's code starts.
    leaf: Option<LabelId>,
    /// The blocks of the dispatch, in the order met.
    blocks: Vec<BlockId>,
    /// The labels the dispatch went through.
    labels: BTreeSet<LabelId>,
    /// Where the decisions' other arms go.
    untaken: Vec<LabelId>,
    /// Whether a decision was taken.
    decided: bool,
}

impl Walk {
    fn note(&mut self, function: &Function, id: StmtId) {
        for block in blocks_of(function.provenance.stmt(id)) {
            if !self.blocks.contains(&block) {
                self.blocks.push(block);
            }
        }
    }
}

/// The L1 blocks `origins` name.
fn blocks_of(origins: &[Origin]) -> impl Iterator<Item = BlockId> + '_ {
    origins.iter().filter_map(|origin| match *origin {
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

/// The chain as the personality routine tries it: catches in order, none
/// after a catch-all (which takes every exception), a cleanup last.
fn effective(chain: &[Action]) -> Vec<Action> {
    let mut out = Vec::with_capacity(chain.len());
    let mut cleanup = None;
    for action in chain {
        match action.kind {
            HandlerKind::Cleanup | HandlerKind::Finally => {
                cleanup.get_or_insert_with(|| action.clone());
            }
            // An `__except` block: the runtime enters it only for what
            // its filter took (no selector to test).
            HandlerKind::CatchAll | HandlerKind::Except(_) => {
                out.push(action.clone());
                return out;
            }
            HandlerKind::Catch(_) | HandlerKind::Unexpected(_) => out.push(action.clone()),
            HandlerKind::Landing(_) => return Vec::new(),
        }
    }
    out.extend(cleanup);
    out
}

/// A goto-only body: its statements, and where each label is.
struct Flat<'f> {
    function: &'f Function,
    labels: BTreeMap<LabelId, usize>,
}

impl<'f> Flat<'f> {
    fn new(function: &'f Function) -> Self {
        let labels = function
            .body
            .iter()
            .enumerate()
            .filter_map(|(index, &id)| match function.stmt(id) {
                Some(&Stmt::Label(label)) => Some((label, index)),
                Some(_) | None => None,
            })
            .collect();
        Self { function, labels }
    }

    /// The index after label `label`.
    fn after(&self, label: LabelId) -> Option<usize> {
        self.labels.get(&label).map(|index| index + 1)
    }

    fn at(&self, index: usize) -> Option<(StmtId, &'f Stmt)> {
        let &id = self.function.body.get(index)?;
        Some((id, self.function.stmt(id)?))
    }

    /// Statement `id` if it assigns a variable a pure value (no load, no
    /// call): its variable and value.
    fn quiet(&self, id: StmtId) -> Option<(VarId, ExprId)> {
        let &Stmt::Assign {
            place: Place::Var(var),
            value,
        } = self.function.stmt(id)?
        else {
            return None;
        };
        pure(self.function, value).then_some((var, value))
    }

    /// An arm of lowering's `if` (or a handler): quiet copies, then a
    /// `goto`.
    fn edge(&self, block: &'f Block) -> Option<(&'f [StmtId], LabelId)> {
        let (&last, copies) = block.split_last()?;
        let &Stmt::Goto(label) = self.function.stmt(last)? else {
            return None;
        };
        copies
            .iter()
            .all(|&copy| self.quiet(copy).is_some())
            .then_some((copies, label))
    }

    /// The plan for a `Try` whose landing handler is `handler`, unwinding
    /// to a pad with `chain`.
    fn plan(&self, handler: &Block, chain: &[Action], exceptions: &Exceptions) -> Option<Plan> {
        let chain = effective(chain);
        let mut arms = Vec::with_capacity(chain.len());
        let mut walks = Vec::with_capacity(chain.len());
        for action in chain {
            let walk = self.walk(handler, action.selector)?;
            arms.push(Arm {
                kind: action.kind,
                selector: action.selector,
                prefix: walk.prefix.clone(),
                leaf: walk.leaf?,
            });
            walks.push(walk);
        }
        let decided = walks.iter().filter(|walk| walk.decided).count();
        if arms.is_empty() || (decided != 0 && decided != walks.len()) {
            return None;
        }
        let absorbed: BTreeSet<BlockId> = walks
            .iter()
            .flat_map(|walk| walk.blocks.iter().copied())
            .collect();
        let reached: BTreeSet<LabelId> = walks
            .iter()
            .flat_map(|walk| walk.labels.iter().copied().chain(walk.leaf))
            .collect();
        let mut resumes = BTreeSet::new();
        for &other in walks.iter().flat_map(|walk| &walk.untaken) {
            if !reached.contains(&other) {
                resumes.extend(self.resume(other, exceptions)?);
            }
        }
        Some(Plan {
            arms,
            absorbed,
            resumes,
        })
    }

    /// Follows a landing pad's code from `handler` with the selector
    /// `selector` (see the module documentation).
    fn walk(&self, handler: &'f Block, selector: i64) -> Option<Walk> {
        let f = self.function;
        let (copies, start) = self.edge(handler)?;
        let mut env = Env {
            selector,
            vars: BTreeMap::new(),
        };
        let mut walk = Walk::default();
        for &copy in copies {
            env.assign(f, self.quiet(copy)?);
            walk.prefix.push(copy);
        }
        // The code since the last decision: where it starts, its labels and
        // assignments.
        let mut run = start;
        let mut run_labels = vec![start];
        let mut pending: Vec<StmtId> = Vec::new();
        let mut at = self.after(start)?;
        for _ in 0..STEPS {
            let (id, stmt) = self.at(at)?;
            match stmt {
                &Stmt::Label(label) => {
                    run_labels.push(label);
                    if pending.is_empty() {
                        run = label;
                    }
                    at += 1;
                }
                &Stmt::Goto(label) => {
                    run_labels.push(label);
                    if pending.is_empty() {
                        run = label;
                    }
                    at = self.after(label)?;
                }
                Stmt::If {
                    condition,
                    then,
                    otherwise,
                } => {
                    let decision = env.decide(f, *condition);
                    let (Some(holds), Some(then), Some(otherwise)) =
                        (decision, self.edge(then), self.edge(otherwise))
                    else {
                        walk.leaf = Some(run);
                        walk.labels.extend(run_labels);
                        return Some(walk);
                    };
                    for &statement in &pending {
                        walk.note(f, statement);
                    }
                    walk.prefix.append(&mut pending);
                    walk.labels.extend(run_labels.drain(..));
                    walk.note(f, id);
                    let ((copies, target), (_, other)) = if holds {
                        (then, otherwise)
                    } else {
                        (otherwise, then)
                    };
                    for &copy in copies {
                        env.assign(f, self.quiet(copy)?);
                        walk.note(f, copy);
                        walk.prefix.push(copy);
                    }
                    walk.untaken.push(other);
                    walk.decided = true;
                    run = target;
                    run_labels.push(target);
                    at = self.after(target)?;
                }
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
                | Stmt::Return(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Escape { .. }
                | Stmt::Try { .. }
                | Stmt::VaStart { .. } => {
                    let Some(assignment) = self.quiet(id) else {
                        walk.leaf = Some(run);
                        walk.labels.extend(run_labels);
                        return Some(walk);
                    };
                    env.assign(f, assignment);
                    pending.push(id);
                    at += 1;
                }
            }
        }
        None
    }

    /// The blocks of a path from `start` that only assigns and resumes
    /// unwinding (a call to one of [`Exceptions::resume`], not guarded),
    /// if it is one.
    fn resume(&self, start: LabelId, exceptions: &Exceptions) -> Option<Vec<BlockId>> {
        let f = self.function;
        let mut blocks = Vec::new();
        let mut at = self.after(start)?;
        for _ in 0..STEPS {
            let (id, stmt) = self.at(at)?;
            match stmt {
                Stmt::Label(_) => at += 1,
                &Stmt::Goto(label) => at = self.after(label)?,
                Stmt::Call { call, .. } => {
                    let Callee::Address(address) = call.callee else {
                        return None;
                    };
                    if !exceptions.resume.contains(&address) {
                        return None;
                    }
                    blocks.extend(blocks_of(f.provenance.stmt(id)));
                    return Some(blocks);
                }
                Stmt::Assign { .. }
                | Stmt::Intrinsic { .. }
                | Stmt::Expr(_)
                | Stmt::If { .. }
                | Stmt::While { .. }
                | Stmt::DoWhile { .. }
                | Stmt::For { .. }
                | Stmt::Switch { .. }
                | Stmt::Break(_)
                | Stmt::Continue(_)
                | Stmt::Return(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Escape { .. }
                | Stmt::Try { .. }
                | Stmt::VaStart { .. } => {
                    self.quiet(id)?;
                    blocks.extend(blocks_of(f.provenance.stmt(id)));
                    at += 1;
                }
            }
        }
        None
    }

    /// Which statements of the body are reached from its start, and their
    /// blocks, the `Try`s of `plans` going to their arms' code instead of
    /// their handlers' (each plan with its landing pad).
    fn reached(&self, plans: &BTreeMap<StmtId, (u64, Plan)>) -> (Vec<bool>, BTreeSet<BlockId>) {
        let f = self.function;
        let mut seen = vec![false; f.body.len()];
        let mut blocks = BTreeSet::new();
        let mut work = vec![0];
        while let Some(index) = work.pop() {
            let Some((id, stmt)) = self.at(index) else {
                continue;
            };
            match seen.get_mut(index) {
                Some(done) if !*done => *done = true,
                Some(_) | None => continue,
            }
            let mut gotos = Vec::new();
            match (stmt, plans.get(&id)) {
                (Stmt::Try { body, .. }, Some((_, plan))) => {
                    for &inner in body {
                        deep(f, inner, &mut blocks, &mut gotos);
                    }
                    gotos.extend(plan.arms.iter().map(|arm| arm.leaf));
                }
                (_, _) => deep(f, id, &mut blocks, &mut gotos),
            }
            work.extend(gotos.iter().filter_map(|label| self.labels.get(label)));
            if !stops(f, stmt) {
                work.push(index + 1);
            }
        }
        (seen, blocks)
    }
}

/// Adds the blocks of statement `id` and of those it holds to `blocks`,
/// and their `goto`s' labels to `gotos`.
fn deep(function: &Function, id: StmtId, blocks: &mut BTreeSet<BlockId>, gotos: &mut Vec<LabelId>) {
    let mut work = vec![id];
    while let Some(id) = work.pop() {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        blocks.extend(blocks_of(function.provenance.stmt(id)));
        if let &Stmt::Goto(label) = stmt {
            gotos.push(label);
        }
        for block in stmt.blocks() {
            work.extend(block.iter().copied());
        }
    }
}

/// Whether control never goes on after `stmt` (to the next statement).
fn stops(function: &Function, stmt: &Stmt) -> bool {
    let block_stops = |block: &Block| {
        block
            .last()
            .and_then(|&last| function.stmt(last))
            .is_some_and(|last| stops(function, last))
    };
    match stmt {
        Stmt::Goto(_) | Stmt::Return(_) | Stmt::Trap(_) | Stmt::Unreachable => true,
        Stmt::Escape { kind, .. } => match kind {
            Escape::UnresolvedJump | Escape::ForeignJump | Escape::OverlappingCode => true,
            Escape::NonStandardCall
            | Escape::StackTrick
            | Escape::SystemCall
            | Escape::Atomic
            | Escape::Update(_) => false,
        },
        Stmt::If {
            then, otherwise, ..
        } => block_stops(then) && block_stops(otherwise),
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
        | Stmt::Try { .. }
        | Stmt::VaStart { .. } => false,
    }
}

/// Whether expression `root` neither loads nor calls (and is small).
fn pure(function: &Function, root: ExprId) -> bool {
    let mut work = vec![root];
    let mut seen = BTreeSet::new();
    while let Some(id) = work.pop() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > STEPS {
            return false;
        }
        match function.expr(id) {
            None | Some(Expr::Load { .. } | Expr::Call(_)) => return false,
            Some(expr) => work.extend(expr.operands(function)),
        }
    }
    true
}

/// What is known of variables on a walk, the selector being `selector`.
struct Env {
    selector: i64,
    vars: BTreeMap<VarId, Value>,
}

impl Env {
    fn assign(&mut self, function: &Function, (var, value): (VarId, ExprId)) {
        match self.eval(function, value) {
            Some(value) => self.vars.insert(var, value),
            None => self.vars.remove(&var),
        };
    }

    /// Whether the 1-bit `condition` holds, if known.
    fn decide(&self, function: &Function, condition: ExprId) -> Option<bool> {
        let bits = self.eval(function, condition)?.known()?;
        Some(!bits.is_zero())
    }

    /// The value of `root` (unknown bits where it reads what is not known).
    fn eval(&self, function: &Function, root: ExprId) -> Option<Value> {
        let mut values: BTreeMap<ExprId, Value> = BTreeMap::new();
        let mut work = vec![(root, false)];
        while let Some((id, ready)) = work.pop() {
            if values.contains_key(&id) {
                continue;
            }
            let expr = *function.expr(id)?;
            if !ready {
                if values.len() + work.len() > STEPS {
                    return None;
                }
                work.push((id, true));
                work.extend(expr.operands(function).map(|operand| (operand, false)));
                continue;
            }
            let value = self.apply(function, id, expr, &values)?;
            values.insert(id, value);
        }
        values.get(&root).copied()
    }

    /// The value of `expr` (expression `id`) from its operands' `values`.
    fn apply(
        &self,
        function: &Function,
        id: ExprId,
        expr: Expr,
        values: &BTreeMap<ExprId, Value>,
    ) -> Option<Value> {
        let get = |operand: ExprId| values.get(&operand).copied();
        Some(match expr {
            Expr::Const(bits) => Value::defined(bits),
            Expr::Var(var) => match self.vars.get(&var) {
                Some(&value) => value,
                None => Value::unknown(function.width(id)?),
            },
            Expr::Exception {
                value: ExceptionValue::Selector,
                width,
            } => Value::defined(selector_bits(width, self.selector)),
            Expr::Unary(op, a) => interpret::unary(op, get(a)?),
            Expr::Binary(op, a, b) => interpret::binary(op, get(a)?, get(b)?),
            Expr::Logical(op, a, b) => {
                let decides = match op {
                    Logical::And => 0,
                    Logical::Or => 1,
                };
                match get(a)?.known() {
                    Some(bits) if bits.low_u128() == decides => Value::defined(bits),
                    Some(_) => get(b)?,
                    None => Value::unknown(1),
                }
            }
            Expr::Flag(op, a, b, c) => interpret::flag(op, get(a)?, get(b)?, get(c)?),
            Expr::Extract {
                value,
                offset,
                width,
            } => interpret::extract(get(value)?, offset, width),
            Expr::Concat { high, low } => interpret::concat(get(high)?, get(low)?),
            Expr::Extend {
                signed,
                value,
                width,
            } => interpret::extend(signed, get(value)?, width),
            Expr::Select {
                condition,
                then,
                otherwise,
            } => interpret::select(get(condition)?, get(then)?, get(otherwise)?),
            Expr::Cast { value, .. } => get(value)?,
            Expr::Undefined(..)
            | Expr::AddressOf(_)
            | Expr::Lanes { .. }
            | Expr::Float { .. }
            | Expr::Load { .. }
            | Expr::Call(_)
            | Expr::Assign { .. }
            | Expr::Exception {
                value: ExceptionValue::Object | ExceptionValue::Code | ExceptionValue::Abnormal,
                ..
            } => Value::unknown(function.width(id)?),
        })
    }
}

/// The selector `selector` as `width` bits.
fn selector_bits(width: u16, selector: i64) -> Bits {
    Bits::from_u128(width, i128::from(selector).cast_unsigned())
}

/// The handlers of `plan`: each its dispatch's assignments (copied, the
/// selector its constant, without the blocks' provenance: the dispatch
/// stands for those) and a `goto` to its code.
fn arms(function: &mut Function, plan: &Plan) -> Option<Vec<Handler>> {
    let mut handlers = Vec::with_capacity(plan.arms.len());
    for arm in &plan.arms {
        let mut body = Vec::with_capacity(arm.prefix.len() + 1);
        for &statement in &arm.prefix {
            body.push(copy_assignment(function, statement, arm.selector)?);
        }
        body.push(function.add_stmt(Stmt::Goto(arm.leaf)));
        handlers.push(Handler {
            kind: arm.kind.clone(),
            body,
        });
    }
    Some(handlers)
}

/// Gives `Try` `id` `handlers` and the blocks `plan`'s dispatch took over.
fn apply(function: &mut Function, id: StmtId, handlers: Vec<Handler>, plan: &Plan) {
    let Some(Stmt::Try { handlers: old, .. }) = function.stmts.get_mut(id.0 as usize) else {
        return;
    };
    *old = handlers;
    let mut origins: Vec<Origin> = function
        .provenance
        .stmt(id)
        .iter()
        .copied()
        .filter(|origin| !matches!(origin, Origin::Block(_) | Origin::Absorbed(_)))
        .collect();
    origins.extend(plan.absorbed.iter().map(|&block| Origin::Absorbed(block)));
    function.provenance.set_stmt(id, &origins);
}

/// The origins `origins` but the blocks'.
fn without_blocks(origins: &[Origin]) -> Vec<Origin> {
    origins
        .iter()
        .copied()
        .filter(|origin| !matches!(origin, Origin::Block(_) | Origin::Absorbed(_)))
        .collect()
}

/// A copy of the assignment `id` (a quiet one), its value's selector
/// reads the constant `selector`.
fn copy_assignment(function: &mut Function, id: StmtId, selector: i64) -> Option<StmtId> {
    let &Stmt::Assign { place, value } = function.stmt(id)? else {
        return None;
    };
    let value = copy_expr(function, value, selector)?;
    let copy = function.add_stmt(Stmt::Assign { place, value });
    let origins = without_blocks(function.provenance.stmt(id));
    function.provenance.set_stmt(copy, &origins);
    Some(copy)
}

/// A copy of expression `root` (pure), its selector reads the constant
/// `selector`.
fn copy_expr(function: &mut Function, root: ExprId, selector: i64) -> Option<ExprId> {
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    let mut work = vec![(root, false)];
    while let Some((id, ready)) = work.pop() {
        if ready {
            order.push(id);
            continue;
        }
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > STEPS {
            return None;
        }
        work.push((id, true));
        let expr = *function.expr(id)?;
        work.extend(expr.operands(function).map(|operand| (operand, false)));
    }
    let mut copies: BTreeMap<ExprId, ExprId> = BTreeMap::new();
    for id in order {
        let expr = *function.expr(id)?;
        let copy = if let Expr::Exception {
            value: ExceptionValue::Selector,
            width,
        } = expr
        {
            Expr::Const(selector_bits(width, selector))
        } else {
            function.map_operands(expr, &mut |operand| {
                copies.get(&operand).copied().unwrap_or(operand)
            })
        };
        let new = function.add_expr(copy);
        let origins = without_blocks(function.provenance.expr(id));
        function.provenance.set_expr(new, &origins);
        copies.insert(id, new);
    }
    copies.get(&root).copied()
}
