//! Copies and dead code: [`Propagate`], [`Narrow`] and [`Prune`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{
    Block, Expr, ExprId, Function, Origin, Place, Stmt, StmtId, VarId, VarKind, Variable,
};
use binbun_ast::types::{Evidence, Type};
use binbun_ast::verify::ordered;
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};

use super::expr::{Info, append, in_memory, loads, map_roots, reads, rebuild, roots};
use super::facts::Facts;
use crate::pass::{Feeds, L2Env, size};

/// Copy propagation (pass `propagate`): a local assigned once is replaced
/// by its value in the statements that read it, where the value is
/// available there ([`Facts::available`]): every reader for a constant,
/// an address, a copy of a variable not in memory, or a value wider than
/// C's integers (over 128 bits: a vector, such as the lanes of an
/// instruction without semantics concatenated) that neither loads, calls
/// nor has an undefined part, which no C variable could hold; the one
/// reader of any other value read once. A call's one result in a local
/// read once is such
/// a value too: the call moves into its reader as an [`Expr::Call`] (as
/// a load would; into a call statement's arguments, made before its call,
/// but no intrinsic's or escape's), so `v = f(x); return v + 1` is
/// `return f(x) + 1` and `v = dcgettext(…); error(v, x)` is
/// `error(dcgettext(…), x)`. A value that loads or calls moves only where
/// C then fixes the order of the reader's calls and of what they read
/// ([`ordered`]): nothing C evaluates in either order with a call calls
/// or reads memory (`f(g(x), y)` with `y` a local; not `f(g(x), *p)`).
/// The assignment
/// stays, for [`Prune`] to remove once nothing reads it; one whose load or
/// call moved is removed (the load or call, and its fault or effect, are
/// the reader's now; its instructions go to the reader's nodes as
/// [`Prune`] gives them). A call directly in a
/// `Try`'s body stays a statement: it unwinds to the `Try`'s handlers
/// from where it is, and its block's decision (return or unwind) is its
/// own. Preserves nothing.
///
/// Runs out of fuel after substituting some values: it keeps those (each
/// is correct on its own, its assignment removed if its load or call
/// moved).
#[derive(Clone, Copy, Debug, Default)]
pub struct Propagate;

impl<'e> Pass<Function, L2Env<'e>> for Propagate {
    fn name(&self) -> &'static str {
        "propagate"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let mut info = Info::new(function);
        let facts = Facts::new(function, &info, cx.fuel)?;
        let guarded = guarded(function);
        // Variables whose reads changed in this run: their counts are stale.
        let mut touched: BTreeSet<VarId> = BTreeSet::new();
        let mut changed = false;
        // The assignments whose load or call moved into their one reader.
        let mut moved_out: Vec<StmtId> = Vec::new();
        let mut out_of_fuel = false;
        for (index, defs) in facts.defs.iter().enumerate() {
            let var = VarId(u32::try_from(index).unwrap_or(u32::MAX));
            let local = function
                .var(var)
                .is_some_and(|variable| variable.kind == VarKind::Local);
            let &[def] = defs.as_slice() else {
                continue;
            };
            if !local || touched.contains(&var) {
                continue;
            }
            let count = facts.reads.get(index).copied().unwrap_or(0);
            let call = if guarded.contains(&def) { 0 } else { count };
            let Some(value) = assigned(function, &mut info, def, var, call) else {
                continue;
            };
            if guarded.contains(&def) && info.calls(value) {
                continue;
            }
            let mut read = BTreeSet::new();
            reads(function, value, &mut read);
            if read.contains(&var) {
                continue;
            }
            let copy = matches!(
                function.expr(value),
                Some(Expr::Const(_) | Expr::AddressOf(_))
            ) || matches!(function.expr(value), Some(&Expr::Var(source)) if !in_memory(function, source))
                || (info.width(value).is_some_and(|width| width > 128)
                    && !info.faults(value)
                    && !info.calls(value)
                    && !info.undefined(value));
            if !copy && count != 1 {
                continue;
            }
            let mut moved = false;
            for &at in facts.readers.get(index).map_or(&[][..], Vec::as_slice) {
                if at == def
                    || !facts.available(function, &info, def, value, at)
                    || (info.faults(value)
                        && read_conditionally(function, at, var, info.calls(value)))
                    || (info.calls(value) && effectful(function, at))
                    || (info.faults(value) && !in_order(function, &info, at, var, value))
                {
                    continue;
                }
                let before = function.exprs.len();
                substitute(function, &mut info, at, var, value);
                moved = true;
                let added = function.exprs.len().saturating_sub(before);
                if cx
                    .fuel
                    .spend(u64::try_from(added).unwrap_or(u64::MAX))
                    .is_err()
                {
                    out_of_fuel = true;
                    break;
                }
            }
            if moved {
                changed = true;
                touched.insert(var);
                touched.extend(read);
                // A load or call moved into its one reader faults or calls
                // there now: the assignment, read by nothing, must not.
                if info.faults(value) {
                    moved_out.push(def);
                }
            }
            if out_of_fuel {
                break;
            }
        }
        if !moved_out.is_empty() {
            if let Some(feeds) = cx.env.feeds {
                // In the body's order, as `forward` passes them on.
                let going: BTreeSet<StmtId> = moved_out.iter().copied().collect();
                let mut ordered = Vec::new();
                super::rules::statements(function, &function.body, &mut ordered);
                ordered.retain(|id| going.contains(id));
                forward(function, &facts, feeds, &ordered);
            }
            let removed: BTreeMap<StmtId, Vec<StmtId>> =
                moved_out.into_iter().map(|id| (id, Vec::new())).collect();
            splice(&mut function.body, &removed);
            for (index, stmt) in function.stmts.iter_mut().enumerate() {
                let id = StmtId(u32::try_from(index).unwrap_or(u32::MAX));
                if facts.position(id).is_some() {
                    for block in blocks_mut(stmt) {
                        splice(block, &removed);
                    }
                }
            }
        }
        Ok(changed.into())
    }
}

/// The value statement `def` gives `var`, its one assignment: an
/// assignment's value, or, for a call whose one result is `var` and read
/// once (`count`, 0 where the call must stay a statement), the call as a
/// new [`Expr::Call`] (with the call's provenance but its block: it is no
/// decision).
fn assigned(
    function: &mut Function,
    info: &mut Info,
    def: StmtId,
    var: VarId,
    count: u32,
) -> Option<ExprId> {
    match function.stmt(def)? {
        &Stmt::Assign {
            place: Place::Var(target),
            value,
        } => (target == var).then_some(value),
        Stmt::Call { results, call } if count == 1 && results.as_slice() == [Place::Var(var)] => {
            let call = function.add_call(call.clone());
            let id = function.add_expr(Expr::Call(call));
            let origins: Vec<Origin> = function
                .provenance
                .stmt(def)
                .iter()
                .copied()
                .filter(|origin| !matches!(origin, Origin::Block(_)))
                .collect();
            function.provenance.set_expr(id, &origins);
            info.update(function);
            Some(id)
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
        | Stmt::Try { .. }
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

/// Whether statement `at` has an effect of its own besides what it
/// evaluates that a call moved into it could not be ordered with (an
/// intrinsic, an escape; a call statement's call follows its arguments).
fn effectful(function: &Function, at: StmtId) -> bool {
    matches!(
        function.stmt(at),
        None | Some(Stmt::Intrinsic { .. } | Stmt::Escape { .. })
    )
}

/// The statements directly in a `Try`'s body (whose calls unwind to its
/// handlers).
fn guarded(function: &Function) -> BTreeSet<StmtId> {
    let mut out = BTreeSet::new();
    let mut work = vec![&function.body];
    while let Some(block) = work.pop() {
        for &id in block {
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            if let Stmt::Try { body, .. } = stmt {
                out.extend(body.iter().copied());
            }
            work.extend(stmt.blocks());
        }
    }
    out
}

/// Whether statement `at`, its one read of `var` replaced by `value` (a
/// value that loads or calls), keeps its calls in an order C fixes
/// ([`ordered`]): the read stands for what `value` reads and calls. Not
/// in the address of a call's, intrinsic's or escape's result, which C
/// evaluates in either order with the effect.
fn in_order(function: &Function, info: &Info, at: StmtId, var: VarId, value: ExprId) -> bool {
    let Some(stmt) = function.stmt(at) else {
        return false;
    };
    let roots = roots(stmt);
    // The nodes below the roots, then those of them reading `var`
    // (operands have smaller ids: ascending order sees them first).
    let mut nodes = BTreeSet::new();
    let mut work = roots.clone();
    while let Some(id) = work.pop() {
        if nodes.insert(id)
            && let Some(expr) = function.expr(id)
        {
            work.extend(expr.operands(function));
        }
    }
    let mut reading = BTreeSet::new();
    for &id in &nodes {
        let Some(expr) = function.expr(id) else {
            continue;
        };
        if matches!(*expr, Expr::Var(read) if read == var)
            || expr
                .operands(function)
                .any(|operand| reading.contains(&operand))
        {
            reading.insert(id);
        }
    }
    let moved = info.calls(value);
    let results = match stmt {
        Stmt::Call { results, .. }
        | Stmt::Intrinsic { results, .. }
        | Stmt::Escape { results, .. } => results.as_slice(),
        Stmt::Assign { .. }
        | Stmt::Expr(_)
        | Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Try { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Return(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable
        | Stmt::VaStart { .. } => &[],
    };
    if results
        .iter()
        .any(|place| matches!(*place, Place::Memory { address, .. } if reading.contains(&address)))
    {
        return false;
    }
    let calls = |id: ExprId| info.calls(id) || (moved && reading.contains(&id));
    let reads = |id: ExprId| info.faults(id) || reading.contains(&id);
    ordered(function, &roots, &calls, &reads).is_ok()
}

/// Whether statement `at` reads `var` where it may not be evaluated: in
/// the right operand of an `&&`/`||`, evaluated only when the left does
/// not decide, and (with `arms`) in an arm of a select, which C
/// evaluates only when chosen. A load moved there would fault only
/// sometimes; a call would be made only sometimes.
fn read_conditionally(function: &Function, at: StmtId, var: VarId, arms: bool) -> bool {
    let Some(stmt) = function.stmt(at) else {
        return true;
    };
    let mut work: Vec<(ExprId, bool)> = roots(stmt).into_iter().map(|root| (root, false)).collect();
    let mut seen = BTreeSet::new();
    while let Some((id, conditional)) = work.pop() {
        if !seen.insert((id, conditional)) {
            continue;
        }
        match function.expr(id) {
            Some(&Expr::Var(read)) if read == var && conditional => return true,
            Some(&Expr::Logical(_, left, right)) => {
                work.push((left, conditional));
                work.push((right, true));
            }
            Some(&Expr::Select {
                condition,
                then,
                otherwise,
            }) => {
                work.push((condition, conditional));
                work.push((then, conditional || arms));
                work.push((otherwise, conditional || arms));
            }
            Some(expr) => work.extend(
                expr.operands(function)
                    .map(|operand| (operand, conditional)),
            ),
            None => {}
        }
    }
    false
}

/// Replaces the reads of `var` in the roots of statement `at` by `value`.
fn substitute(function: &mut Function, info: &mut Info, at: StmtId, var: VarId, value: ExprId) {
    let mut before = |function: &mut Function, _: &mut Info, id: ExprId| {
        matches!(function.expr(id), Some(&Expr::Var(read)) if read == var).then_some(value)
    };
    rewrite(function, info, at, &mut before);
}

/// Rebuilds the roots of statement `at` with the nodes `before` replaces
/// replaced.
fn rewrite(
    function: &mut Function,
    info: &mut Info,
    at: StmtId,
    before: &mut dyn FnMut(&mut Function, &mut Info, ExprId) -> Option<ExprId>,
) {
    let Some(stmt) = function.stmt(at) else {
        return;
    };
    let mut memo = BTreeMap::new();
    for root in roots(stmt) {
        rebuild(function, info, root, &mut memo, before, &mut |_, _, _| None);
    }
    if let Some(stmt) = function.stmts.get_mut(at.0 as usize) {
        map_roots(stmt, &mut |root| memo.get(&root).copied().unwrap_or(root));
    }
}

/// Narrowing (pass `narrow`): a local of [`Type::Bits`] with no evidence,
/// or a deduced integer, assigned only by assignments, whose every read
/// takes low bits (`extract(v, 0, k)`) becomes a variable of the widest
/// such `k` bits (a deduced integer keeps its signedness and evidence; a
/// pointer or a float does not narrow): each assignment stores the low
/// bits of its value, each read reads the new variable (or its low bits).
/// So `v = zext.64(x); … extract(v, 0, 32)` reads `x`'s width, which
/// [`Rewrite`](super::rules::Rewrite) then simplifies. The old variable is
/// left unused.
///
/// Its dual: such a local (not narrowed so) whose every assignment is a
/// zero extension (or every one a sign extension) of a value of at most
/// `k` bits (8, 16, 32 or 64, narrower than its own), a constant that is
/// one, or an undefined value (which may be one), becomes a variable of
/// `k` bits, unsigned (signed), assigned the
/// low `k` bits of each value; each read reads its extension back. So
/// `v = zext.64(x32); f(v)` is `v = x32; f(zext.64(v))`, and C's own
/// conversions say the extension (`uint32_t v = x; f(v)`), where the
/// 64-bit variable needed a cast at each assignment. Preserves nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Narrow;

impl<'e> Pass<Function, L2Env<'e>> for Narrow {
    fn name(&self) -> &'static str {
        "narrow"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let mut info = Info::new(function);
        let facts = Facts::new(function, &info, cx.fuel)?;
        let widths = narrow_widths(function, &facts);
        let extended = extended_widths(function, &facts, &widths);
        if widths.is_empty() && extended.is_empty() {
            return Ok(Changed::No);
        }
        cx.fuel.spend(size(function))?;
        let renamed = narrowed_variables(function, &facts, &widths, &extended);
        let live: Vec<StmtId> = (0..function.stmts.len())
            .map(|index| StmtId(u32::try_from(index).unwrap_or(u32::MAX)))
            .filter(|&id| facts.position(id).is_some())
            .collect();
        for at in live {
            let mut before = |function: &mut Function, info: &mut Info, id: ExprId| {
                if let Some(&Expr::Var(var)) = function.expr(id)
                    && let Some(&(new, _, Some(signed))) = renamed.get(&var)
                {
                    let own = function
                        .var(var)
                        .and_then(|variable| function.types.value_width(variable.ty))?;
                    let read = append(function, info, Expr::Var(new), id);
                    let extend = Expr::Extend {
                        signed,
                        value: read,
                        width: own,
                    };
                    return Some(append(function, info, extend, id));
                }
                let Some(&Expr::Extract {
                    value,
                    offset: 0,
                    width,
                }) = function.expr(id)
                else {
                    return None;
                };
                let Some(&Expr::Var(var)) = function.expr(value) else {
                    return None;
                };
                let &(new, narrow, None) = renamed.get(&var)? else {
                    return None;
                };
                let read = append(function, info, Expr::Var(new), value);
                Some(if width == narrow {
                    read
                } else {
                    let low = Expr::Extract {
                        value: read,
                        offset: 0,
                        width,
                    };
                    append(function, info, low, id)
                })
            };
            rewrite(function, &mut info, at, &mut before);
            let Some(&Stmt::Assign {
                place: Place::Var(var),
                value,
            }) = function.stmt(at)
            else {
                continue;
            };
            let Some(&(new, width, _)) = renamed.get(&var) else {
                continue;
            };
            let low = Expr::Extract {
                value,
                offset: 0,
                width,
            };
            let value = append(function, &mut info, low, value);
            if let Some(stmt) = function.stmts.get_mut(at.0 as usize) {
                *stmt = Stmt::Assign {
                    place: Place::Var(new),
                    value,
                };
            }
        }
        Ok(Changed::Yes)
    }
}

/// The new variables of the locals [`Narrow`] narrows (`widths`) and holds
/// at the width of their extensions (`extended`): per old variable, the new
/// one, its width, and for an extended one whether its reads sign-extend
/// it. One whose every assignment extends a `char` (a character loaded
/// with `movzx`) is a `char`, as what it holds is ([`characters`]).
fn narrowed_variables(
    function: &mut Function,
    facts: &Facts,
    widths: &BTreeMap<VarId, u16>,
    extended: &BTreeMap<VarId, (u16, bool)>,
) -> BTreeMap<VarId, (VarId, u16, Option<bool>)> {
    let mut renamed = BTreeMap::new();
    let wanted = widths
        .iter()
        .map(|(&var, &width)| (var, width, None))
        .chain(
            extended
                .iter()
                .map(|(&var, &(width, signed))| (var, width, Some(signed))),
        );
    for (var, width, extension) in wanted {
        let Some(old) = function.var(var) else {
            continue;
        };
        let (name, origins, evidence) = (old.name.clone(), old.origins.clone(), old.evidence);
        let character = characters(function, facts, var, width);
        let deduced = extension.is_some() || character.is_some();
        let narrowed = match (character, extension, function.types.get(old.ty)) {
            (Some(character), ..) => character,
            (None, Some(true), _) | (None, None, Some(&Type::Int(_))) => Type::Int(width),
            (None, Some(false), _) | (None, None, Some(&Type::UInt(_))) => Type::UInt(width),
            (None, None, Some(_) | None) => Type::Bits(width),
        };
        // The extension, or what is extended, is what the new type is
        // deduced from.
        let evidence = if deduced { Evidence::Deduced } else { evidence };
        let ty = function.types.intern(narrowed);
        let new = Variable {
            kind: VarKind::Local,
            name,
            ty,
            evidence,
            origins,
        };
        renamed.insert(var, (function.add_var(new), width, extension));
    }
    renamed
}

/// `char`, if every assignment of `var` extends a value of L2 type
/// `char` (a load's or a variable's) and `width` is 8: the type of what
/// the variable holds once it is narrowed to those bits.
fn characters(function: &Function, facts: &Facts, var: VarId, width: u16) -> Option<Type> {
    let defs = facts.defs.get(var.0 as usize)?;
    let mut found = None;
    for &def in defs {
        let &Stmt::Assign {
            place: Place::Var(target),
            value,
        } = function.stmt(def)?
        else {
            return None;
        };
        // What is extended, through an extension of an extension
        // (`movzx` to 32 bits, then the register's 64).
        let mut inner = value;
        while let Some(&Expr::Extend { value: from, .. }) = function.expr(inner) {
            inner = from;
        }
        if inner == value {
            return None;
        }
        let ty = if let Expr::Load { ty, .. } | Expr::Cast { ty, .. } = *function.expr(inner)? {
            ty
        } else if let Expr::Var(source) = *function.expr(inner)? {
            function.var(source)?.ty
        } else {
            return None;
        };
        let character @ Type::Char { .. } = function.types.get(ty)?.clone() else {
            return None;
        };
        if target != var || width != 8 || found.is_some_and(|other| other != character) {
            return None;
        }
        found = Some(character);
    }
    found
}

/// The locals [`Narrow`] narrows, with their new widths.
fn narrow_widths(function: &Function, facts: &Facts) -> BTreeMap<VarId, u16> {
    // Per variable: the widest low part read, or 0 for a read of another
    // kind.
    let mut widest: BTreeMap<VarId, u16> = BTreeMap::new();
    let mut other: BTreeSet<VarId> = BTreeSet::new();
    let mut seen: BTreeSet<ExprId> = BTreeSet::new();
    for (index, stmt) in function.stmts.iter().enumerate() {
        let id = StmtId(u32::try_from(index).unwrap_or(u32::MAX));
        if facts.position(id).is_none() {
            continue;
        }
        let mut work = Vec::new();
        for root in roots(stmt) {
            if let Some(&Expr::Var(var)) = function.expr(root) {
                other.insert(var);
            }
            work.push(root);
        }
        while let Some(at) = work.pop() {
            if !seen.insert(at) {
                continue;
            }
            let Some(&expr) = function.expr(at) else {
                continue;
            };
            for operand in expr.operands(function) {
                work.push(operand);
                let Some(&Expr::Var(var)) = function.expr(operand) else {
                    continue;
                };
                if let Expr::Extract {
                    offset: 0, width, ..
                } = expr
                {
                    let slot = widest.entry(var).or_insert(0);
                    *slot = (*slot).max(width);
                } else {
                    other.insert(var);
                }
            }
        }
    }
    widest.retain(|&var, width| {
        let Some(variable) = function.var(var) else {
            return false;
        };
        let narrower = match (function.types.get(variable.ty), variable.evidence) {
            (Some(&Type::Bits(own)), Evidence::Default)
            | (Some(&(Type::Int(own) | Type::UInt(own))), Evidence::Deduced) => *width < own,
            _ => false,
        };
        let assigned = facts.defs.get(var.0 as usize).is_some_and(|defs| {
            defs.iter().all(|&def| {
                matches!(function.stmt(def), Some(&Stmt::Assign { place: Place::Var(target), .. }) if target == var)
            })
        });
        *width > 0
            && narrower
            && assigned
            && variable.kind == VarKind::Local
            && !other.contains(&var)
    });
    widest
}

/// The variables read as an address (loaded or stored through) or as the
/// value of a variable that is no integer: C converts a narrower integer
/// to a pointer only by a cast through the pointer-wide one, which the
/// wide variable did not need.
fn pointer_reads(function: &Function) -> BTreeSet<VarId> {
    let var_of = |id: ExprId| match function.expr(id) {
        Some(&Expr::Var(var)) => Some(var),
        Some(_) | None => None,
    };
    let integer = |var: VarId| {
        function.var(var).is_some_and(|variable| {
            matches!(
                function.types.get(variable.ty),
                Some(Type::Bits(_) | Type::Int(_) | Type::UInt(_) | Type::Char { .. })
            )
        })
    };
    let mut pointers: BTreeSet<VarId> = function
        .exprs
        .iter()
        .filter_map(|expr| {
            if let Expr::Load { address, .. } = *expr {
                var_of(address)
            } else {
                None
            }
        })
        .collect();
    for stmt in &function.stmts {
        let Stmt::Assign { place, value } = stmt else {
            continue;
        };
        match *place {
            Place::Var(target) if !integer(target) => pointers.extend(var_of(*value)),
            Place::Var(_) => {}
            Place::Memory { address, .. } => pointers.extend(var_of(address)),
        }
    }
    pointers
}

/// The locals [`Narrow`] holds at the width of what extends into them,
/// with that width and whether the extensions are signed (none of
/// `narrowed`, none read as an address or assigned to a variable that is
/// no integer, [`pointer_reads`]).
fn extended_widths(
    function: &Function,
    facts: &Facts,
    narrowed: &BTreeMap<VarId, u16>,
) -> BTreeMap<VarId, (u16, bool)> {
    let pointers = pointer_reads(function);
    let mut out = BTreeMap::new();
    for (index, defs) in facts.defs.iter().enumerate() {
        let var = VarId(u32::try_from(index).unwrap_or(u32::MAX));
        let Some(variable) = function.var(var) else {
            continue;
        };
        let ((Some(&Type::Bits(own)), Evidence::Default)
        | (Some(&(Type::Int(own) | Type::UInt(own))), Evidence::Deduced)) =
            (function.types.get(variable.ty), variable.evidence)
        else {
            continue;
        };
        if variable.kind != VarKind::Local
            || narrowed.contains_key(&var)
            || pointers.contains(&var)
            || defs.is_empty()
        {
            continue;
        }
        // The extensions' kind and widest source, and the constants.
        let mut kind = None;
        let mut widest = 0;
        let mut constants = Vec::new();
        let every = defs.iter().all(|&def| {
            let Some(&Stmt::Assign {
                place: Place::Var(target),
                value,
            }) = function.stmt(def)
            else {
                return false;
            };
            if target != var {
                return false;
            }
            match function.expr(value) {
                Some(&Expr::Extend {
                    signed,
                    value: source,
                    ..
                }) => {
                    let Some(width) = function.width(source) else {
                        return false;
                    };
                    widest = widest.max(width);
                    *kind.get_or_insert(signed) == signed
                }
                Some(&Expr::Const(bits)) => {
                    constants.push(bits);
                    true
                }
                // Not an unknown value, which held narrow would be chosen
                // to extend its low bits.
                Some(_) | None => false,
            }
        });
        let Some(signed) = kind else {
            continue;
        };
        let width = [8, 16, 32, 64].into_iter().find(|&width| width >= widest);
        let Some(width) = width.filter(|&width| width < own) else {
            continue;
        };
        let fits = |bits: Bits| {
            let low = bits.extract(0, width);
            bits == if signed { low.sext(own) } else { low.zext(own) }
        };
        if every && constants.into_iter().all(fits) {
            out.insert(var, (width, signed));
        }
    }
    out
}

/// Dead code (pass `dead-code`): an assignment to a variable not in memory
/// that nothing reads (but assignments to itself) is removed, but for the
/// loads in its value, each kept as an expression statement (for its
/// fault, in order; a call as a call statement, the value dropped); so is
/// a variable's assignment to itself (`a = a`,
/// what propagating a saved copy back leaves); a call whose results all
/// go to such variables drops them. A variable nothing reads any more is
/// then not printed. An assignment removed with nothing kept gives its
/// instructions (and its value's) to the nodes standing for the
/// instructions that read the L1 values it stood for ([`Feeds`]): where
/// what it computed went (a copy coalescing made `a = a`, to the
/// instruction reading the copy). Preserves nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Prune;

impl<'e> Pass<Function, L2Env<'e>> for Prune {
    fn name(&self) -> &'static str {
        "dead-code"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let info = Info::new(function);
        let facts = Facts::new(function, &info, cx.fuel)?;
        let dead = |var: VarId| {
            let index = var.0 as usize;
            !in_memory(function, var)
                && facts.reads.get(index) == facts.own.get(index)
                && function.var(var).is_some_and(|variable| {
                    matches!(variable.kind, VarKind::Local | VarKind::Parameter)
                })
        };
        let mut replaced: BTreeMap<StmtId, Vec<ExprId>> = BTreeMap::new();
        let mut dropped: Vec<StmtId> = Vec::new();
        for (index, stmt) in function.stmts.iter().enumerate() {
            let id = StmtId(u32::try_from(index).unwrap_or(u32::MAX));
            if facts.position(id).is_none() {
                continue;
            }
            if let &Stmt::Assign {
                place: Place::Var(var),
                value,
            } = stmt
                && (dead(var)
                    || !in_memory(function, var)
                        && matches!(function.expr(value), Some(&Expr::Var(read)) if read == var))
            {
                replaced.insert(id, loads(function, &info, value));
            } else if let Stmt::Call { results, .. } = stmt
                && !results.is_empty()
                && results
                    .iter()
                    .all(|place| matches!(*place, Place::Var(var) if dead(var)))
            {
                dropped.push(id);
            }
        }
        if replaced.is_empty() && dropped.is_empty() {
            return Ok(Changed::No);
        }
        if let Some(feeds) = cx.env.feeds {
            let mut removed = Vec::new();
            super::rules::statements(function, &function.body, &mut removed);
            removed.retain(|id| replaced.get(id).is_some_and(Vec::is_empty));
            forward(function, &facts, feeds, &removed);
        }
        let mut kept: BTreeMap<StmtId, Vec<StmtId>> = BTreeMap::new();
        for (id, parts) in replaced {
            let origins = function.provenance.stmt(id).to_vec();
            let statements = parts
                .into_iter()
                .map(|part| {
                    let (stmt, own) = kept_part(function, part);
                    let new = function.add_stmt(stmt);
                    let all: Vec<Origin> = origins.iter().chain(&own).copied().collect();
                    if !all.is_empty() {
                        function.provenance.set_stmt(new, &all);
                    }
                    new
                })
                .collect();
            kept.insert(id, statements);
        }
        for id in dropped {
            if let Some(Stmt::Call { results, .. }) = function.stmts.get_mut(id.0 as usize) {
                results.clear();
            }
        }
        splice(&mut function.body, &kept);
        for (index, stmt) in function.stmts.iter_mut().enumerate() {
            let id = StmtId(u32::try_from(index).unwrap_or(u32::MAX));
            if facts.position(id).is_some() {
                for block in blocks_mut(stmt) {
                    splice(block, &kept);
                }
            }
        }
        Ok(Changed::Yes)
    }
}

/// The statement keeping `part` (an outermost load or call of a dead
/// value) for its fault or effect: a call as a call statement, its value
/// dropped (with the call's own origins, by which a call is known); else
/// an expression statement.
fn kept_part(function: &Function, part: ExprId) -> (Stmt, Vec<Origin>) {
    if let Some(&Expr::Call(id)) = function.expr(part)
        && let Some(call) = function.call(id)
    {
        let stmt = Stmt::Call {
            results: Vec::new(),
            call: call.clone(),
        };
        return (stmt, function.provenance.expr(part).to_vec());
    }
    (Stmt::Expr(part), Vec::new())
}

/// How many nodes of a removed assignment's value [`forward`] takes the
/// instructions of, at most.
const FORWARDED: usize = 256;

/// The nodes standing for each instruction: expressions, statements.
type Standing = (BTreeMap<u64, Vec<ExprId>>, BTreeMap<u64, Vec<StmtId>>);

/// The nodes of the statements in the body for which `take` holds (and
/// of their expressions) standing for each instruction.
fn standing(function: &Function, facts: &Facts, take: &dyn Fn(StmtId) -> bool) -> Standing {
    let (mut exprs, mut stmts): Standing = Default::default();
    let mut seen = BTreeSet::new();
    for (index, stmt) in function.stmts.iter().enumerate() {
        let id = StmtId(u32::try_from(index).unwrap_or(u32::MAX));
        if facts.position(id).is_none() || !take(id) {
            continue;
        }
        for origin in function.provenance.stmt(id) {
            if let &Origin::Instruction(address) = origin {
                stmts.entry(address).or_default().push(id);
            }
        }
        let mut work = roots(stmt);
        while let Some(e) = work.pop() {
            if !seen.insert(e) {
                continue;
            }
            for origin in function.provenance.expr(e) {
                if let &Origin::Instruction(address) = origin {
                    exprs.entry(address).or_default().push(e);
                }
            }
            if let Some(expr) = function.expr(e) {
                work.extend(expr.operands(function));
            }
        }
    }
    (exprs, stmts)
}

/// Gives the instructions each of the assignments `removed` and its
/// value's nodes stand for, and no node left does (an instruction still
/// standing elsewhere keeps its own line), to the nodes left standing
/// for the instructions that read its L1 values (`feeds`): an
/// expression's where one stands for such an instruction, else a
/// statement's; where a reader is another of `removed` (later: they are
/// in order), to that one, to pass on.
fn forward(function: &mut Function, facts: &Facts, feeds: &Feeds<'_>, removed: &[StmtId]) {
    let going: BTreeSet<StmtId> = removed.iter().copied().collect();
    let (exprs, stmts) = standing(function, facts, &|id| !going.contains(&id));
    let (_, passing) = standing(function, facts, &|id| going.contains(&id));
    let alive = |address: &u64| exprs.contains_key(address) || stmts.contains_key(address);
    let mut given: BTreeMap<StmtId, Vec<Origin>> = BTreeMap::new();
    for &id in removed {
        let own = function.provenance.stmt(id);
        let readers: Vec<u64> = own
            .iter()
            .filter_map(|origin| {
                if let Origin::Value(value) = *origin {
                    Some(feeds.readers(value))
                } else {
                    None
                }
            })
            .flatten()
            .collect();
        let mut folded: Vec<Origin> = own.to_vec();
        folded.extend(given.remove(&id).unwrap_or_default());
        if let Some(&Stmt::Assign { value, .. }) = function.stmt(id) {
            let mut nodes = BTreeSet::new();
            let mut work = vec![value];
            while let Some(e) = work.pop() {
                if nodes.len() >= FORWARDED || !nodes.insert(e) {
                    continue;
                }
                folded.extend_from_slice(function.provenance.expr(e));
                if let Some(expr) = function.expr(e) {
                    work.extend(expr.operands(function));
                }
            }
        }
        folded.retain(|origin| matches!(origin, Origin::Instruction(address) if !alive(address)));
        if folded.is_empty() {
            continue;
        }
        for address in readers {
            if let Some(targets) = exprs.get(&address) {
                for &target in targets {
                    function.provenance.absorb_expr(target, &folded);
                }
            } else if let Some(targets) = stmts.get(&address) {
                for &target in targets {
                    function.provenance.absorb_stmt(target, &folded);
                }
            } else {
                for &target in passing.get(&address).into_iter().flatten() {
                    if target != id {
                        given.entry(target).or_default().extend_from_slice(&folded);
                    }
                }
            }
        }
    }
}

/// `block` with each statement `replaced` maps replaced by its list.
fn splice(block: &mut Block, replaced: &BTreeMap<StmtId, Vec<StmtId>>) {
    if !block.iter().any(|id| replaced.contains_key(id)) {
        return;
    }
    let old = mem::take(block);
    for id in old {
        match replaced.get(&id) {
            Some(list) => block.extend(list.iter().copied()),
            None => block.push(id),
        }
    }
}

/// The blocks `stmt` holds, as [`Stmt::blocks`] lists them, to change.
fn blocks_mut(stmt: &mut Stmt) -> Vec<&mut Block> {
    match stmt {
        Stmt::If {
            then, otherwise, ..
        } => vec![then, otherwise],
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => vec![body],
        Stmt::For {
            init, step, body, ..
        } => vec![init, step, body],
        Stmt::Switch { arms, .. } => arms.iter_mut().map(|arm| &mut arm.body).collect(),
        Stmt::Try { body, handlers } => core::iter::once(body)
            .chain(handlers.iter_mut().map(|handler| &mut handler.body))
            .collect(),
        Stmt::Assign { .. }
        | Stmt::Call { .. }
        | Stmt::Intrinsic { .. }
        | Stmt::Expr(_)
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Return(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable
        | Stmt::Escape { .. }
        | Stmt::VaStart { .. } => Vec::new(),
    }
}
