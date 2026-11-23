//! Assignments into the conditions that read them (C's `if ((v = f())
//! != 0)`, `while ((c = getc(s)) != -1)`): [`Conditions`].

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;
use core::mem;

use binbun_ast::ir::{Block, Expr, ExprId, Function, Origin, Place, Stmt, StmtId, VarId, VarKind};
use binbun_ast::types::Type;
use binbun_ast::verify::{ordered, single};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::ir::Binary;
use binbun_ssa::ir::BlockId;

use super::flow::Flow;
use super::refine::loop_head;
use crate::pass::{L2Env, size};

/// Statements nested deeper than this are left as they are.
const DEPTH: usize = 1000;

/// Nodes [`Search`] visits in one condition at most (a condition sharing
/// nodes could make it visit one many times).
const VISITS: usize = 4096;

/// The pass `conditions`: `v = e;` right before the decision that reads
/// `v` (an `if`'s, or a `do`-`while`'s with the assignment ending its
/// body) becomes an assignment expression ([`Expr::Assign`]) in place of
/// the condition's first read of `v`: `if ((v = e) != 0)`. Then a
/// `while (1)` whose body starts with `if (c) break;` is `while (!c)`, as
/// refinement makes it: `while ((c = getc(s)) != -1)`.
///
/// Exact: the read is evaluated whenever the condition is (not on the
/// right of a `&&`/`||`, not in an arm of a select), so the assignment is
/// made exactly when the statement was; what the condition evaluates
/// before it neither loads, calls nor is undefined, so `e` is evaluated
/// at the same point of the function's effects; the reads of `v` after it
/// see the value it writes, as they saw the statement's. C orders it so
/// too ([`ordered`]: nothing C evaluates unsequenced with it reads `v`,
/// nor memory a call in `e` may change), and no node of the condition
/// reading or writing `v` is shared ([`single`]), as the verifier
/// requires. `v` is a parameter or local not in memory, of a scalar type.
/// The assignment ending a `do`-`while`'s body is taken only where no
/// `continue` names the loop: one reaches the test without the
/// assignment, which the condition would then make.
/// A read on the right of a 1-bit `&`/`|` (which L2 evaluates always) is
/// not taken: C prints that operator as `&&`/`||` when its right operand
/// has no effect, and the assignment would force `|` (`a < 0 | (v =
/// e)`), so it stays a statement.
/// The assignment is code of the
/// decision's L1 block (or of none), so the control flow through the
/// blocks is unchanged; in a `Try`'s body, an `e` that may unwind stays a
/// statement (an `if` cannot be the invoke that ends a block).
///
/// Preserves nothing. Fuel: a unit per statement and expression.
#[derive(Clone, Copy, Debug, Default)]
pub struct Conditions;

impl<'e> Pass<Function, L2Env<'e>> for Conditions {
    fn name(&self) -> &'static str {
        "conditions"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(size(function))?;
        let continued = Flow::of(function).continued;
        let mut folder = Folder {
            function,
            continued,
            changed: false,
        };
        let body = mem::take(&mut folder.function.body);
        folder.function.body = folder.block(body, false, 0);
        Ok(folder.changed.into())
    }
}

/// The block among `origins`, if one.
fn block_among(origins: &[Origin]) -> Option<BlockId> {
    origins.iter().find_map(|origin| match *origin {
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

/// The expressions `root` reaches, each once.
fn nodes(function: &Function, root: ExprId) -> Vec<ExprId> {
    let mut seen = BTreeSet::new();
    let mut work = vec![root];
    while let Some(id) = work.pop() {
        if seen.insert(id)
            && let Some(expr) = function.expr(id)
        {
            work.extend(expr.operands(function));
        }
    }
    seen.into_iter().collect()
}

/// The nodes from `root` down to `read` (`root` first, `read` last; a
/// tree: one path), or `None` if `read` is not below `root`.
fn path_to(function: &Function, root: ExprId, read: ExprId) -> Option<Vec<ExprId>> {
    let mut path = vec![root];
    while let Some(&at) = path.last() {
        if at == read {
            break;
        }
        let next = function
            .expr(at)?
            .operands(function)
            .find(|&operand| nodes(function, operand).contains(&read))?;
        path.push(next);
    }
    Some(path)
}

/// Whether operand `next` of node `at` is the right one of a 1-bit
/// `&`/`|`, which C prints as `&&`/`||` when it has no effect.
fn printed_conditional(function: &Function, at: ExprId, next: ExprId) -> bool {
    matches!(
        function.expr(at),
        Some(&Expr::Binary(Binary::And | Binary::Or, _, right)) if right == next
    ) && function.width(at) == Some(1)
}

/// Whether variable `var` is in memory (a global or a frame variable).
fn in_memory(function: &Function, var: VarId) -> bool {
    function
        .var(var)
        .is_some_and(|variable| matches!(variable.kind, VarKind::Global(_) | VarKind::Frame(_)))
}

/// Whether evaluating `id` makes a call or an assignment.
fn effects(function: &Function, id: ExprId) -> bool {
    nodes(function, id)
        .into_iter()
        .any(|at| matches!(function.expr(at), Some(Expr::Call(_) | Expr::Assign { .. })))
}

/// Whether evaluating `id` reads memory: a load, a variable in memory, a
/// call.
fn reads(function: &Function, id: ExprId) -> bool {
    nodes(function, id)
        .into_iter()
        .any(|at| match function.expr(at) {
            Some(Expr::Load { .. } | Expr::Call(_)) => true,
            Some(&Expr::Var(var)) => in_memory(function, var),
            Some(_) | None => false,
        })
}

/// Whether node `expr` itself (not its operands) only computes: no load,
/// call, assignment, undefined value or variable in memory.
fn pure_node(function: &Function, expr: Expr) -> bool {
    match expr {
        Expr::Var(var) => !in_memory(function, var),
        Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Assign { .. }
        | Expr::Undefined(..)
        | Expr::Exception { .. } => false,
        Expr::Const(_)
        | Expr::AddressOf(_)
        | Expr::Unary(..)
        | Expr::Binary(..)
        | Expr::Logical(..)
        | Expr::Flag(..)
        | Expr::Extract { .. }
        | Expr::Concat { .. }
        | Expr::Extend { .. }
        | Expr::Select { .. }
        | Expr::Lanes { .. }
        | Expr::Float { .. }
        | Expr::Cast { .. } => true,
    }
}

/// What a part of a condition holds, for [`Search`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Found {
    /// The first read of the variable, at this node.
    Read(ExprId),
    /// No read; it only computes (constants, variables not in memory,
    /// operations on them).
    Pure,
    /// No read; it loads, calls, assigns or is undefined.
    Impure,
}

/// Finds the place for an assignment of `var` in a condition: its first
/// read, as the interpreter evaluates it (operands in order, a
/// `&&`/`||`'s right one after its left).
struct Search<'a> {
    function: &'a Function,
    var: VarId,
    /// Visits left.
    budget: Cell<usize>,
}

impl Search<'_> {
    /// In `id` (evaluated only on some paths through the condition if
    /// `conditional`): where `var` is read first, or whether it is pure;
    /// `Err(())` if that read cannot take the assignment (it is
    /// conditional, or impure code is evaluated before it).
    fn find(&self, id: ExprId, conditional: bool, depth: usize) -> Result<Found, ()> {
        let left = self.budget.get();
        if depth > DEPTH || left == 0 {
            return Err(());
        }
        self.budget.set(left - 1);
        let function = self.function;
        let expr = *function.expr(id).ok_or(())?;
        match expr {
            Expr::Var(var) if var == self.var => {
                return if conditional {
                    Err(())
                } else {
                    Ok(Found::Read(id))
                };
            }
            Expr::Logical(_, left, right) => {
                let left = self.find(left, conditional, depth + 1)?;
                if matches!(left, Found::Read(_)) {
                    return Ok(left);
                }
                let right = self.find(right, true, depth + 1)?;
                return Ok(if left == Found::Pure && right == Found::Pure {
                    Found::Pure
                } else {
                    Found::Impure
                });
            }
            Expr::Select {
                condition,
                then,
                otherwise,
            } => {
                let condition = self.find(condition, conditional, depth + 1)?;
                if matches!(condition, Found::Read(_)) {
                    return Ok(condition);
                }
                let then = self.find(then, true, depth + 1)?;
                let otherwise = self.find(otherwise, true, depth + 1)?;
                return Ok(
                    if [condition, then, otherwise]
                        .iter()
                        .all(|&f| f == Found::Pure)
                    {
                        Found::Pure
                    } else {
                        Found::Impure
                    },
                );
            }
            Expr::Const(_)
            | Expr::Undefined(..)
            | Expr::Var(_)
            | Expr::AddressOf(_)
            | Expr::Unary(..)
            | Expr::Binary(..)
            | Expr::Flag(..)
            | Expr::Extract { .. }
            | Expr::Concat { .. }
            | Expr::Extend { .. }
            | Expr::Lanes { .. }
            | Expr::Float { .. }
            | Expr::Cast { .. }
            | Expr::Load { .. }
            | Expr::Call(_)
            | Expr::Exception { .. }
            | Expr::Assign { .. } => {}
        }
        // The node itself is evaluated after its operands: only those
        // before the read must be pure.
        let own = pure_node(function, expr);
        let mut before = true;
        for operand in expr.operands(function) {
            match self.find(operand, conditional, depth + 1)? {
                Found::Read(read) => {
                    return if before {
                        Ok(Found::Read(read))
                    } else {
                        Err(())
                    };
                }
                Found::Pure => {}
                Found::Impure => before = false,
            }
        }
        Ok(if own && before {
            Found::Pure
        } else {
            Found::Impure
        })
    }
}

struct Folder<'f> {
    function: &'f mut Function,
    /// The loops a `continue` names: it reaches a `do`-`while`'s test
    /// without running the end of the body.
    continued: BTreeSet<StmtId>,
    changed: bool,
}

impl Folder<'_> {
    /// `block` (in a `Try`'s body if `trying`) with its assignments moved
    /// into the conditions after them, the blocks inside it first.
    fn block(&mut self, block: Block, trying: bool, depth: usize) -> Block {
        if depth > DEPTH {
            return block;
        }
        for &id in &block {
            self.inner(id, trying, depth);
        }
        let mut out: Block = Vec::with_capacity(block.len());
        for id in block {
            if let Some(&previous) = out.last()
                && self.fold(previous, id, trying, false)
            {
                out.pop();
            }
            out.push(id);
        }
        out
    }

    /// The blocks statement `id` holds, each done; a `do`-`while` whose
    /// body ends in an assignment takes it into its condition, a
    /// `while (1)` starting with `if (c) break;` becomes `while (!c)`.
    fn inner(&mut self, id: StmtId, trying: bool, depth: usize) {
        let Some(stmt) = self.function.stmts.get_mut(id.0 as usize) else {
            return;
        };
        let is_try = matches!(stmt, Stmt::Try { .. });
        let taken: Vec<Block> = stmt.blocks_mut().map(mem::take).collect();
        let done: Vec<Block> = taken
            .into_iter()
            .enumerate()
            .map(|(index, inner)| self.block(inner, trying || (is_try && index == 0), depth + 1))
            .collect();
        if let Some(stmt) = self.function.stmts.get_mut(id.0 as usize) {
            for (slot, inner) in stmt.blocks_mut().zip(done) {
                *slot = inner;
            }
        }
        if let Some(Stmt::DoWhile { body, .. }) = self.function.stmt(id)
            && let Some(&last) = body.last()
            && !self.continued.contains(&id)
            && self.fold(last, id, trying, true)
            && let Some(Stmt::DoWhile { body, .. }) = self.function.stmts.get_mut(id.0 as usize)
        {
            body.pop();
        }
        if loop_head(self.function, id) {
            self.changed = true;
        }
    }

    /// Moves assignment `assign` into the condition of decision
    /// `decision` (an `if` after it; with `ends_body`, the `do`-`while`
    /// whose body it ends), if it fits (see [`Conditions`]).
    fn fold(&mut self, assign: StmtId, decision: StmtId, trying: bool, ends_body: bool) -> bool {
        let function = &*self.function;
        let Some(&Stmt::Assign {
            place: Place::Var(var),
            value,
        }) = function.stmt(assign)
        else {
            return false;
        };
        let ((Some(&Stmt::If { condition, .. }), false)
        | (Some(&Stmt::DoWhile { condition, .. }), true)) = (function.stmt(decision), ends_body)
        else {
            return false;
        };
        let Some(variable) = function.var(var) else {
            return false;
        };
        let scalar = !matches!(
            function.types.get(variable.ty),
            Some(Type::Struct(_) | Type::Union(_) | Type::Array { .. }) | None
        );
        if !matches!(variable.kind, VarKind::Local | VarKind::Parameter) || !scalar {
            return false;
        }
        let own = block_among(function.provenance.stmt(assign));
        if own.is_some() && own != block_among(function.provenance.stmt(decision)) {
            return false;
        }
        if trying
            && function
                .stmt(assign)
                .is_some_and(|stmt| stmt.may_unwind(function))
        {
            return false;
        }
        let search = Search {
            function,
            var,
            budget: Cell::new(VISITS),
        };
        let Ok(Found::Read(read)) = search.find(condition, false, 0) else {
            return false;
        };
        let Some(path) = path_to(function, condition, read) else {
            return false;
        };
        if path
            .iter()
            .zip(path.iter().skip(1))
            .any(|(&at, &next)| printed_conditional(function, at, next))
        {
            return false;
        }
        let Some(rebuilt) = self.rebuild(path, read, var, value, assign) else {
            return false;
        };
        let function = &*self.function;
        let calls = |id: ExprId| effects(function, id);
        let memory = |id: ExprId| reads(function, id);
        if single(function, &[rebuilt]).is_err()
            || ordered(function, &[rebuilt], &calls, &memory).is_err()
        {
            return false;
        }
        match self.function.stmts.get_mut(decision.0 as usize) {
            Some(Stmt::If { condition, .. } | Stmt::DoWhile { condition, .. }) => {
                *condition = rebuilt;
            }
            Some(_) | None => return false,
        }
        self.changed = true;
        true
    }

    /// The root of `path` (from a condition down to node `read`, a read
    /// of `var`) with `read` replaced by `var = value`, with the origins
    /// of the assignment statement `assign` but its block (the decision's
    /// block is the condition's), the nodes on the way copied with
    /// theirs.
    fn rebuild(
        &mut self,
        mut path: Vec<ExprId>,
        read: ExprId,
        var: VarId,
        value: ExprId,
        assign: StmtId,
    ) -> Option<ExprId> {
        let origins: Vec<Origin> = self
            .function
            .provenance
            .stmt(assign)
            .iter()
            .copied()
            .filter(|origin| !matches!(origin, Origin::Block(_)))
            .collect();
        path.pop();
        let mut below = read;
        let mut replaced = self.function.add_expr(Expr::Assign { var, value });
        self.function.provenance.set_expr(replaced, &origins);
        while let Some(at) = path.pop() {
            let node = *self.function.expr(at)?;
            let child = replaced;
            let copy = self.function.map_operands(node, &mut |operand| {
                if operand == below { child } else { operand }
            });
            let origins = self.function.provenance.expr(at).to_vec();
            replaced = self.function.add_expr(copy);
            self.function.provenance.set_expr(replaced, &origins);
            below = at;
        }
        Some(replaced)
    }
}
