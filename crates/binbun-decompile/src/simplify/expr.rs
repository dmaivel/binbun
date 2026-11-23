//! Expression helpers the simplification passes share: widths and flags
//! per expression, a statement's root expressions, rebuilding a tree with
//! some of its nodes replaced (appending, never changing a node), and
//! structural equality.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Callee, Expr, ExprId, Function, Origin, Place, Stmt, VarId, VarKind};
use binbun_ast::verify::expr_width;

/// The expression may fault: it loads (a [`Expr::Load`], or a read of a
/// variable in memory) or calls. Whatever keeps a load from moving or
/// going keeps a call too.
const FAULTS: u8 = 1;
/// The expression has an undefined part (each evaluation is its own).
const UNDEFINED: u8 = 2;
/// The expression calls ([`Expr::Call`]): it may also change memory, and
/// is never evaluated twice, nor beside anything else that faults.
const CALLS: u8 = 4;

/// The width and flags of each expression of a function, by id; extended
/// with [`Info::update`] as expressions are appended.
#[derive(Debug, Default)]
pub(crate) struct Info {
    widths: Vec<u16>,
    flags: Vec<u8>,
}

impl Info {
    /// The facts of `function`'s expressions.
    pub(crate) fn new(function: &Function) -> Self {
        let mut info = Self::default();
        info.update(function);
        info
    }

    /// Adds the facts of the expressions appended since the last update.
    pub(crate) fn update(&mut self, function: &Function) {
        for expr in function.exprs.iter().skip(self.widths.len()) {
            let widths = &self.widths;
            let width = expr_width(function, expr, &mut |operand| {
                widths
                    .get(operand.0 as usize)
                    .copied()
                    .ok_or_else(String::new)
            })
            .unwrap_or(0);
            let mut flags = match *expr {
                // An exception value is what the runtime handed the
                // handler entered last: it stays where it is read, as a
                // load does (but never faults: see `loads`).
                Expr::Load { .. } | Expr::Exception { .. } => FAULTS,
                // An assignment expression is an effect, kept in place as
                // a call is.
                Expr::Call(_) | Expr::Assign { .. } => FAULTS | CALLS,
                Expr::Var(var) if in_memory(function, var) => FAULTS,
                Expr::Undefined(..) => UNDEFINED,
                Expr::Const(_)
                | Expr::Var(_)
                | Expr::AddressOf(_)
                | Expr::Unary(..)
                | Expr::Binary(..)
                | Expr::Flag(..)
                | Expr::Extract { .. }
                | Expr::Concat { .. }
                | Expr::Extend { .. }
                | Expr::Select { .. }
                | Expr::Lanes { .. }
                | Expr::Float { .. }
                | Expr::Cast { .. }
                | Expr::Logical(..) => 0,
            };
            for operand in expr.operands(function) {
                flags |= self.flags.get(operand.0 as usize).copied().unwrap_or(0);
            }
            self.widths.push(width);
            self.flags.push(flags);
        }
    }

    /// The width of expression `id` (`None` if it is not well formed).
    pub(super) fn width(&self, id: ExprId) -> Option<u16> {
        self.widths
            .get(id.0 as usize)
            .copied()
            .filter(|&width| width > 0)
    }

    /// Whether evaluating `id` may fault (it loads).
    pub(super) fn faults(&self, id: ExprId) -> bool {
        self.flag(id, FAULTS)
    }

    /// Whether `id` has an undefined part.
    pub(super) fn undefined(&self, id: ExprId) -> bool {
        self.flag(id, UNDEFINED)
    }

    /// Whether evaluating `id` calls.
    pub(super) fn calls(&self, id: ExprId) -> bool {
        self.flag(id, CALLS)
    }

    fn flag(&self, id: ExprId, flag: u8) -> bool {
        // An unknown expression is taken to have every flag.
        self.flags
            .get(id.0 as usize)
            .is_none_or(|flags| flags & flag != 0)
    }
}

/// Whether `var` lives in memory (reading it loads, writing it stores).
pub(crate) fn in_memory(function: &Function, var: VarId) -> bool {
    function
        .var(var)
        .is_none_or(|variable| matches!(variable.kind, VarKind::Global(_) | VarKind::Frame(_)))
}

/// Appends `expr` with the provenance of `like` and returns it.
pub(super) fn append(function: &mut Function, info: &mut Info, expr: Expr, like: ExprId) -> ExprId {
    let id = function.add_expr(expr);
    let origins = function.provenance.expr(like).to_vec();
    if !origins.is_empty() {
        function.provenance.set_expr(id, &origins);
    }
    info.update(function);
    id
}

/// How many levels below a rewritten node [`dropped`] looks for the nodes
/// a rewrite matched (a rule's pattern is a few deep).
const MATCHED: usize = 4;
/// How many levels below a rewrite's result [`dropped`] looks for the
/// nodes it keeps.
const KEPT: usize = 6;

/// The origins of the nodes a rewrite of `from` to `to` drops: those
/// within [`MATCHED`] levels of `from` not within [`KEPT`] levels of `to`
/// (what it matched and replaced, whose instructions `to` stands for
/// now).
pub(super) fn dropped(function: &Function, from: ExprId, to: ExprId) -> Vec<Origin> {
    let below = |root: ExprId, depth: usize| {
        let mut seen = BTreeSet::from([root]);
        let mut level = vec![root];
        for _ in 0..depth {
            let mut next = Vec::new();
            for id in level {
                if let Some(expr) = function.expr(id) {
                    next.extend(expr.operands(function).filter(|&o| seen.insert(o)));
                }
            }
            level = next;
        }
        seen
    };
    let kept = below(to, KEPT);
    below(from, MATCHED)
        .difference(&kept)
        .flat_map(|&id| function.provenance.expr(id).iter().copied())
        .collect()
}

/// The expressions `stmt` itself evaluates (not those of the blocks it
/// holds), in evaluation order.
pub(super) fn roots(stmt: &Stmt) -> Vec<ExprId> {
    stmt.roots()
}

/// Replaces each root of `stmt` (as [`roots`] lists them) by `map` of it.
pub(crate) fn map_roots(stmt: &mut Stmt, map: &mut dyn FnMut(ExprId) -> ExprId) {
    fn place(place: &mut Place, map: &mut dyn FnMut(ExprId) -> ExprId) {
        if let Place::Memory { address, .. } = place {
            *address = map(*address);
        }
    }
    match stmt {
        Stmt::Assign {
            place: target,
            value,
        } => {
            *value = map(*value);
            place(target, map);
        }
        Stmt::Call { results, call } => {
            if let Callee::Expr(id) = &mut call.callee {
                *id = map(*id);
            }
            for argument in &mut call.arguments {
                *argument = map(*argument);
            }
            for result in results {
                place(result, map);
            }
        }
        Stmt::Intrinsic {
            results,
            inputs: operands,
            ..
        }
        | Stmt::Escape {
            operands, results, ..
        } => {
            for operand in operands {
                *operand = map(*operand);
            }
            for result in results {
                place(result, map);
            }
        }
        Stmt::Expr(id)
        | Stmt::If { condition: id, .. }
        | Stmt::While { condition: id, .. }
        | Stmt::DoWhile { condition: id, .. }
        | Stmt::For { condition: id, .. }
        | Stmt::Switch { scrutinee: id, .. }
        | Stmt::Return(Some(id)) => *id = map(*id),
        Stmt::Return(None)
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable
        | Stmt::Try { .. }
        | Stmt::VaStart { .. } => {}
    }
}

/// What [`rebuild`] does at a node, given the node and its operands as
/// rebuilt (`None`: the node as it was, or with its rebuilt operands).
pub(crate) type Visit<'a> = dyn FnMut(&mut Function, &mut Info, ExprId) -> Option<ExprId> + 'a;

/// `root` with every node `before` replaces (looked at before its
/// operands) replaced, and every node above a replaced one rebuilt
/// (appended, with the provenance of the node it rebuilds); `after` is
/// then offered each node as rebuilt, whose replacement stands for it.
/// `memo` maps nodes already done to what they became. An explicit stack:
/// the depth of the tree is not native recursion.
pub(crate) fn rebuild(
    function: &mut Function,
    info: &mut Info,
    root: ExprId,
    memo: &mut BTreeMap<ExprId, ExprId>,
    before: &mut Visit<'_>,
    after: &mut Visit<'_>,
) -> ExprId {
    let mut work = vec![(root, false)];
    while let Some((id, ready)) = work.pop() {
        if memo.contains_key(&id) {
            continue;
        }
        let Some(&expr) = function.expr(id) else {
            memo.insert(id, id);
            continue;
        };
        if !ready {
            if let Some(new) = before(function, info, id) {
                memo.insert(id, new);
                continue;
            }
            work.push((id, true));
            work.extend(expr.operands(function).map(|operand| (operand, false)));
            continue;
        }
        let mut changed = false;
        let rebuilt = function.map_operands(expr, &mut |operand| {
            let new = memo.get(&operand).copied().unwrap_or(operand);
            changed |= new != operand;
            new
        });
        let current = if changed {
            append(function, info, rebuilt, id)
        } else {
            id
        };
        let done = after(function, info, current).unwrap_or(current);
        memo.insert(id, done);
        if done != id {
            memo.insert(done, done);
        }
    }
    memo.get(&root).copied().unwrap_or(root)
}

/// Whether `a` and `b` are the same tree (the same node, or nodes of the
/// same kind over the same trees), within `budget` nodes compared. Two
/// call nodes are two calls: never the same.
pub(crate) fn same(function: &Function, a: ExprId, b: ExprId) -> bool {
    let mut budget = 256u32;
    let mut work = vec![(a, b)];
    let mut seen = BTreeSet::new();
    while let Some((a, b)) = work.pop() {
        if a == b || !seen.insert((a, b)) {
            continue;
        }
        budget = match budget.checked_sub(1) {
            Some(left) => left,
            None => return false,
        };
        let (Some(&x), Some(&y)) = (function.expr(a), function.expr(b)) else {
            return false;
        };
        if matches!(x, Expr::Call(_)) || matches!(y, Expr::Call(_)) {
            return false;
        }
        let mut left = Vec::new();
        let shell_x = x.map_own(&mut |operand| {
            left.push(operand);
            ExprId(0)
        });
        let mut right = Vec::new();
        let shell_y = y.map_own(&mut |operand| {
            right.push(operand);
            ExprId(0)
        });
        if shell_x != shell_y || left.len() != right.len() {
            return false;
        }
        work.extend(left.into_iter().zip(right));
    }
    true
}

/// The variables `root` reads that are not in memory, into `vars`.
pub(crate) fn reads(function: &Function, root: ExprId, vars: &mut BTreeSet<VarId>) {
    let mut work = vec![root];
    let mut seen = BTreeSet::new();
    while let Some(id) = work.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(expr) = function.expr(id) else {
            continue;
        };
        if let Expr::Var(var) = *expr
            && !in_memory(function, var)
        {
            vars.insert(var);
        }
        work.extend(expr.operands(function));
    }
}

/// The outermost nodes of `root` that load or call (each evaluates the
/// loads under it), in evaluation order. An `&&`/`||` that loads is one
/// such node: the loads of its right operand happen only when the left
/// does not decide, so they are never taken out of it. A call is one with
/// its arguments.
pub(super) fn loads(function: &Function, info: &Info, root: ExprId) -> Vec<ExprId> {
    let mut found = Vec::new();
    let mut work = vec![root];
    while let Some(id) = work.pop() {
        if !info.faults(id) {
            continue;
        }
        let Some(expr) = function.expr(id) else {
            continue;
        };
        let loads = match *expr {
            // A `&&`/`||`: its right operand is evaluated only when the
            // left does not decide, so it is kept whole and its loads fault
            // exactly when they did.
            Expr::Load { .. } | Expr::Logical(..) | Expr::Call(_) | Expr::Assign { .. } => true,
            Expr::Var(var) => in_memory(function, var),
            Expr::Const(_)
            | Expr::Undefined(..)
            | Expr::AddressOf(_)
            | Expr::Unary(..)
            | Expr::Binary(..)
            | Expr::Flag(..)
            | Expr::Extract { .. }
            | Expr::Concat { .. }
            | Expr::Extend { .. }
            | Expr::Select { .. }
            | Expr::Lanes { .. }
            | Expr::Float { .. }
            | Expr::Cast { .. }
            | Expr::Exception { .. } => false,
        };
        if loads {
            found.push(id);
        } else {
            let start = work.len();
            work.extend(expr.operands(function));
            // The first operand on top: evaluated first.
            if let Some(added) = work.get_mut(start..) {
                added.reverse();
            }
        }
    }
    found
}
