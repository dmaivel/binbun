//! Locals given the signedness most of their reads ask for:
//! [`LocalSigns`]; and operations given the signedness of their operands
//! where both readings agree: [`Signs`].

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use binbun_ast::ir::{Block, Expr, ExprId, Function, StmtId, VarId, VarKind};
use binbun_ast::types::{Evidence, Type, TypeId};
use binbun_semantics::core::pass::{Changed, Cx, Fuel, Pass, Refusal};
use binbun_semantics::ir::{Binary, Unary};

use super::expr::{Info, append, map_roots, rebuild, roots};
use crate::pass::{L2Env, size};
use crate::range::{Ranges, node_nonnegative};

/// The pass `local-signs`, just before [`Signs`]: each local integer
/// variable of 8 to 64 bits not declared so takes the signedness more of
/// its reads ask for than the other (a tie keeps its type). A read asks
/// where its operation reads it signed or unsigned (`<`, `<=`, `/`, `%`;
/// the shifted value of `>>`; the value extended), directly or through
/// `+`, `-`, `*`, `&`, `|`, `^`, `<<`, `~`, unary `-` and `?:`'s arms
/// (whose C type follows their operands'), except where [`Signs`] will
/// give the operation the operands' signedness (its operands proved
/// sign-free, [`crate::range`]); and where `==` or `!=` compares it with
/// an integer whose signedness no choice here changes (C would convert
/// a signed one to the other's unsigned type, a mix the printer casts
/// away). An `==` or `!=` of two such locals asks that they agree. The
/// printer makes every read what its operation needs whatever the type,
/// so this changes only the casts it prints: a variable compared signed
/// three times and unsigned once is `int32_t`, one cast. From the types
/// as they are, one local at a time takes the other signedness where
/// fewer reads then ask otherwise ([`choose`]). Parameters (their
/// callers' declarations give their types) and variables in memory keep
/// theirs. Like Boomerang's signedness hints
/// ([`IntegerType::hintAsSigned`]), a vote; unlike Ghidra's most specific
/// type, where one unsigned read makes a variable unsigned.
///
/// [`IntegerType::hintAsSigned`]: https://github.com/BoomerangDecompiler/boomerang/blob/develop/src/boomerang/ssl/type/IntegerType.cpp
///
/// Changes types only. Fuel: a unit per statement, and per expression
/// each time a statement reads it.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalSigns;

impl<'e> Pass<Function, L2Env<'e>> for LocalSigns {
    fn name(&self) -> &'static str {
        "local-signs"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let ranges = cx.analysis::<Ranges>(function);
        let free: Vec<bool> = (0..function.exprs.len())
            .map(|index| ranges.nonnegative(ExprId(u32::try_from(index).unwrap_or(u32::MAX))))
            .collect();
        let reads = reads(function, &free, cx.fuel)?;
        let mut changed = false;
        for (var, signed) in choose(function, &reads) {
            let Some((width, _)) = choosable(function, var) else {
                continue;
            };
            let ty = function.types.intern(if signed {
                Type::Int(width)
            } else {
                Type::UInt(width)
            });
            if let Some(variable) = function.variables.get_mut(var.0 as usize) {
                variable.ty = ty;
                variable.evidence = Evidence::Deduced;
                changed = true;
            }
        }
        Ok(changed.into())
    }
}

/// The most rounds of [`choose`] (each flip leaves fewer casts, so it
/// ends; few functions take more than two).
const ROUNDS: usize = 4;

/// How a function's statements read its locals ([`LocalSigns`]).
struct Reads {
    /// Per variable: the reads asking for it unsigned, and signed.
    votes: Vec<[u32; 2]>,
    /// The `==`s and `!=`s of two choosable locals.
    links: Vec<(VarId, VarId)>,
}

/// The locals whose signedness changes, with the signedness each takes:
/// from their types, each set of locals `==`-linked to each other first
/// takes one signedness together where that leaves fewer reads asking
/// otherwise ([`together`]); then a variable at a time takes the other
/// signedness where fewer of its reads then ask otherwise (its votes,
/// and its links to a local of the other signedness), until none does or
/// [`ROUNDS`] rounds pass. A tie keeps the type.
fn choose(function: &Function, reads: &Reads) -> Vec<(VarId, bool)> {
    let start: Vec<Option<bool>> = (0..function.variables.len())
        .map(|index| {
            choosable(function, VarId(u32::try_from(index).unwrap_or(u32::MAX)))
                .map(|(_, signed)| signed)
        })
        .collect();
    let mut signs = start.clone();
    let mut linked: Vec<Vec<usize>> = vec![Vec::new(); signs.len()];
    for &(a, b) in &reads.links {
        let (a, b) = (a.0 as usize, b.0 as usize);
        if a == b {
            continue;
        }
        if let Some(list) = linked.get_mut(a) {
            list.push(b);
        }
        if let Some(list) = linked.get_mut(b) {
            list.push(a);
        }
    }
    together(&mut signs, &reads.votes, &linked);
    for _ in 0..ROUNDS {
        let mut flipped = false;
        for (index, (votes, links)) in reads.votes.iter().zip(&linked).enumerate() {
            let Some(Some(now)) = signs.get(index).copied() else {
                continue;
            };
            let [unsigned, signed] = *votes;
            let (mut kept, mut against) = if now {
                (signed, unsigned)
            } else {
                (unsigned, signed)
            };
            for &other in links {
                match signs.get(other).copied().flatten() {
                    Some(sign) if sign == now => kept += 1,
                    Some(_) => against += 1,
                    None => {}
                }
            }
            if kept < against
                && let Some(sign) = signs.get_mut(index)
            {
                *sign = Some(!now);
                flipped = true;
            }
        }
        if !flipped {
            break;
        }
    }
    start
        .iter()
        .zip(&signs)
        .enumerate()
        .filter_map(|(index, (&was, &now))| {
            let (Some(was), Some(now)) = (was, now) else {
                return None;
            };
            (was != now).then_some((VarId(u32::try_from(index).unwrap_or(u32::MAX)), now))
        })
        .collect()
}

/// Each set of locals `==`-linked to each other (`linked`, with their
/// `votes`) given one signedness where all of it leaves fewer reads asking
/// otherwise than their `signs` do (their votes for the other, and their
/// links between two signednesses): two locals compared with each other
/// and one compared unsigned are all unsigned, though each alone would
/// keep its type to agree with the other.
fn together(signs: &mut [Option<bool>], votes: &[[u32; 2]], linked: &[Vec<usize>]) {
    let against = |index: usize, sign: bool| {
        votes
            .get(index)
            .and_then(|counts| counts.get(usize::from(!sign)))
            .map_or(0, |&count| u64::from(count))
    };
    let none = Vec::new();
    let links = |index: usize| linked.get(index).unwrap_or(&none);
    let mut done = vec![false; signs.len()];
    for root in 0..signs.len() {
        let Some(Some(first)) = signs.get(root).copied() else {
            continue;
        };
        if links(root).is_empty() || done.get(root).copied().unwrap_or(true) {
            continue;
        }
        let mut members = vec![root];
        if let Some(seen) = done.get_mut(root) {
            *seen = true;
        }
        let mut at = 0;
        while let Some(&member) = members.get(at) {
            at += 1;
            for &other in links(member) {
                if let Some(seen) = done.get_mut(other)
                    && !*seen
                {
                    *seen = true;
                    members.push(other);
                }
            }
        }
        // Each link counted from both ends.
        let (mut now, mut mixed) = (0, 0);
        for &member in &members {
            let sign = signs.get(member).copied().flatten().unwrap_or(first);
            now += against(member, sign);
            mixed += links(member)
                .iter()
                .filter(|&&other| signs.get(other).copied().flatten() != Some(sign))
                .count();
        }
        let now = now + u64::try_from(mixed / 2).unwrap_or(u64::MAX);
        let cost = |sign: bool| {
            members
                .iter()
                .map(|&member| against(member, sign))
                .sum::<u64>()
        };
        let (unsigned, signed) = (cost(false), cost(true));
        let (sign, best) = match unsigned.cmp(&signed) {
            Ordering::Less => (false, unsigned),
            Ordering::Greater => (true, signed),
            Ordering::Equal => (first, signed),
        };
        if best < now {
            for &member in &members {
                if let Some(slot) = signs.get_mut(member) {
                    *slot = Some(sign);
                }
            }
        }
    }
}

/// The width of local `var` and whether it prints signed, if
/// [`LocalSigns`] may choose its signedness: an integer (or untyped bits)
/// of 8 to 64 bits not declared so.
fn choosable(function: &Function, var: VarId) -> Option<(u16, bool)> {
    let variable = function.var(var)?;
    if variable.kind != VarKind::Local
        || !matches!(variable.evidence, Evidence::Default | Evidence::Deduced)
    {
        return None;
    }
    let width = match *function.types.get(variable.ty)? {
        Type::Bits(width) | Type::Int(width) | Type::UInt(width) => width,
        Type::Char { .. }
        | Type::Bool(_)
        | Type::Float(_)
        | Type::Pointer(_)
        | Type::Code(_)
        | Type::Struct(_)
        | Type::Union(_)
        | Type::Array { .. }
        | Type::Vector { .. }
        | Type::Enum(_) => return None,
    };
    if !matches!(width, 8 | 16 | 32 | 64) {
        return None;
    }
    Some((width, sign_of_type(function, variable.ty)?))
}

/// How the statements of `function` read its locals ([`LocalSigns`]),
/// with `free` the expressions proved sign-free: each expression once
/// per statement that reads it, as the printer prints it, a unit of
/// `fuel` each.
fn reads(function: &Function, free: &[bool], fuel: &mut Fuel) -> Result<Reads, Refusal> {
    let mut votes = vec![[0u32; 2]; function.variables.len()];
    let mut links = Vec::new();
    let mut list = Vec::new();
    statements(function, &function.body, &mut list);
    let local = |id: ExprId| match function.expr(id) {
        Some(&Expr::Var(var)) => choosable(function, var).map(|_| var),
        Some(_) | None => None,
    };
    let mut work: Vec<(ExprId, Option<bool>)> = Vec::new();
    for at in list {
        fuel.spend(1)?;
        let Some(stmt) = function.stmt(at) else {
            continue;
        };
        work.extend(roots(stmt).into_iter().map(|root| (root, None)));
        while let Some((id, asked)) = work.pop() {
            fuel.spend(1)?;
            let Some(&expr) = function.expr(id) else {
                continue;
            };
            if let (Expr::Var(var), Some(signed)) = (expr, asked) {
                if let Some(count) = votes
                    .get_mut(var.0 as usize)
                    .and_then(|counts| counts.get_mut(usize::from(signed)))
                {
                    *count += 1;
                }
                continue;
            }
            if let Expr::Binary(Binary::Eq | Binary::Ne, a, b) = expr
                && let (Some(a), Some(b)) = (local(a), local(b))
            {
                links.push((a, b));
            }
            asks(function, free, expr, asked, &mut |operand, asked| {
                work.push((operand, asked));
            });
        }
    }
    Ok(Reads { votes, links })
}

/// Each operand of `expr` with the signedness it is read in (`None`: no
/// matter), `asked` the one `expr`'s reader reads it in, into `out`.
fn asks(
    function: &Function,
    free: &[bool],
    expr: Expr,
    asked: Option<bool>,
    out: &mut dyn FnMut(ExprId, Option<bool>),
) {
    let is = |id: ExprId| free.get(id.0 as usize).copied().unwrap_or(false);
    let wide = |id: ExprId| matches!(function.width(id), Some(32 | 64));
    // Proved sign-free at a width [`Signs`] flips.
    let flips = |id: ExprId| is(id) && wide(id);
    let literal = |a: ExprId, b: ExprId| {
        [a, b]
            .iter()
            .any(|&id| matches!(function.expr(id), Some(Expr::Const(_))))
    };
    match expr {
        Expr::Binary(op, a, b) => match op {
            Binary::SLt
            | Binary::SLe
            | Binary::SDiv
            | Binary::SRem
            | Binary::ULt
            | Binary::ULe
            | Binary::UDiv
            | Binary::URem => {
                let signed = matches!(op, Binary::SLt | Binary::SLe | Binary::SDiv | Binary::SRem);
                // An unsigned `/` or `%` of 32 or 64 bits with a literal:
                // the printer types the literal unsigned, and C converts
                // the other operand (`v / 100U`).
                let by_literal =
                    matches!(op, Binary::UDiv | Binary::URem) && wide(a) && literal(a, b);
                let read = (!(flips(a) && is(b) || by_literal)).then_some(signed);
                out(a, read);
                out(b, read);
            }
            Binary::AShr | Binary::LShr => {
                out(a, (!flips(a)).then_some(op == Binary::AShr));
                out(b, None);
            }
            Binary::Add | Binary::Sub | Binary::Mul | Binary::And | Binary::Or | Binary::Xor => {
                // Read unsigned, a sum, difference or product of 32 or 64
                // bits with a literal is so by its literal (`v - 14U`), a
                // mask by a literal is so (`v & 0xff`).
                let by_literal = asked == Some(false)
                    && literal(a, b)
                    && (op == Binary::And
                        || (matches!(op, Binary::Add | Binary::Sub | Binary::Mul) && wide(a)));
                let asked = if by_literal { None } else { asked };
                out(a, asked);
                out(b, asked);
            }
            Binary::Shl => {
                out(a, asked);
                out(b, None);
            }
            Binary::Eq | Binary::Ne => {
                out(a, fixed_sign(function, b));
                out(b, fixed_sign(function, a));
            }
            Binary::Rol | Binary::Ror => {
                out(a, None);
                out(b, None);
            }
        },
        Expr::Unary(Unary::Not | Unary::Neg, a) => out(a, asked),
        Expr::Extend { signed, value, .. } => out(value, (!flips(value)).then_some(signed)),
        Expr::Select {
            condition,
            then,
            otherwise,
        } => {
            out(condition, None);
            out(then, asked);
            out(otherwise, asked);
        }
        Expr::Unary(..)
        | Expr::Const(_)
        | Expr::Undefined(..)
        | Expr::Var(_)
        | Expr::AddressOf(_)
        | Expr::Logical(..)
        | Expr::Flag(..)
        | Expr::Extract { .. }
        | Expr::Concat { .. }
        | Expr::Lanes { .. }
        | Expr::Float { .. }
        | Expr::Cast { .. }
        | Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Exception { .. }
        | Expr::Assign { .. } => {
            for operand in expr.operands(function) {
                out(operand, None);
            }
        }
    }
}

/// Whether integer expression `id` reads as signed in C whatever
/// [`LocalSigns`] chooses (`None`: it does not say definitely, or a
/// choice there may change it, or it is a pointer).
fn fixed_sign(function: &Function, id: ExprId) -> Option<bool> {
    let integer = |ty: TypeId| {
        if matches!(function.types.get(ty)?, Type::Pointer(_) | Type::Code(_)) {
            None
        } else {
            sign_of_type(function, ty)
        }
    };
    match *function.expr(id)? {
        Expr::Var(var) => {
            if choosable(function, var).is_some() {
                None
            } else {
                integer(function.var(var)?.ty)
            }
        }
        Expr::Load { ty, .. } | Expr::Cast { ty, .. } => integer(ty),
        Expr::Call(call) => {
            let call = function.call(call)?;
            integer(function.types.signature(call.signature)?.returns?)
        }
        Expr::Const(_)
        | Expr::Undefined(..)
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
        | Expr::Exception { .. }
        | Expr::Assign { .. } => sign_of(function, id),
    }
}

/// The pass `signs`, the last pass: where the [`Ranges`] analysis
/// proves an operation's operands in `0..=` the signed maximum of their
/// width (both of `<`, `<=`, `/`, `%`; the shifted value of `>>`; the value
/// extended), its signed and unsigned forms give the same result
/// (`crate::range`, *Sign-irrelevant values*), so it takes the form the
/// operands' types say: signed where they are signed (or one is and the
/// other says nothing), unsigned where one is unsigned (as C's usual
/// arithmetic conversions would read it). The printer then needs no cast
/// to say it: `v3 % 7` with `int32_t v3` is a signed remainder. Only
/// operations of 32 or 64 bits (narrower operands are promoted in C).
///
/// An operand's signedness ([`sign_of`]) is the one C gives it without a
/// cast, where that is definite: a variable's, load's or cast's type
/// (`bits(32)` and `bits(64)` print signed; a pointer compares unsigned);
/// a signed or unsigned division, remainder or shift right; an
/// extension; a call's return type. Anything else says nothing: a
/// constant, and a sum or bitwise operation (whose C type follows C's
/// conversions of its operands as the printer spells them).
///
/// Expressions are appended (rebuilt above a changed one), never changed.
/// Preserves nothing. Fuel: a unit per statement and expression.
#[derive(Clone, Copy, Debug, Default)]
pub struct Signs;

impl<'e> Pass<Function, L2Env<'e>> for Signs {
    fn name(&self) -> &'static str {
        "signs"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(size(function))?;
        let ranges = cx.analysis::<Ranges>(function);
        let mut free: Vec<bool> = (0..function.exprs.len())
            .map(|index| ranges.nonnegative(ExprId(u32::try_from(index).unwrap_or(u32::MAX))))
            .collect();
        if !free.iter().any(|&is| is) {
            return Ok(Changed::No);
        }
        let mut info = Info::new(function);
        let mut list = Vec::new();
        statements(function, &function.body, &mut list);
        let mut changed = false;
        for at in list {
            let Some(stmt) = function.stmt(at) else {
                continue;
            };
            let mut memo = BTreeMap::new();
            for root in roots(stmt) {
                let mut after = |function: &mut Function, info: &mut Info, id: ExprId| {
                    extend(function, &mut free);
                    let flipped = flip(function, &free, id)?;
                    let new = append(function, info, flipped, id);
                    extend(function, &mut free);
                    Some(new)
                };
                rebuild(
                    function,
                    &mut info,
                    root,
                    &mut memo,
                    &mut |_, _, _| None,
                    &mut after,
                );
            }
            if let Some(stmt) = function.stmts.get_mut(at.0 as usize) {
                map_roots(stmt, &mut |root| {
                    let new = memo.get(&root).copied().unwrap_or(root);
                    changed |= new != root;
                    new
                });
            }
        }
        Ok(changed.into())
    }
}

/// The statements of `block` and those they hold, into `out`.
fn statements(function: &Function, block: &Block, out: &mut Vec<StmtId>) {
    let mut work: Vec<&Block> = vec![block];
    while let Some(block) = work.pop() {
        for &id in block {
            out.push(id);
            if let Some(stmt) = function.stmt(id) {
                work.extend(stmt.blocks());
            }
        }
    }
}

/// Extends `free` to the expressions appended: rebuilt and flipped nodes
/// have their originals' values.
fn extend(function: &Function, free: &mut Vec<bool>) {
    while let Some(expr) = function.exprs.get(free.len()) {
        let value = node_nonnegative(function, expr, false, &|id: ExprId| {
            free.get(id.0 as usize).copied().unwrap_or(false)
        });
        free.push(value);
    }
}

/// Expression `id` with its signedness flipped, if its operands are
/// proved sign-free (`free`) and their types ask for the other form.
fn flip(function: &Function, free: &[bool], id: ExprId) -> Option<Expr> {
    let is = |id: ExprId| free.get(id.0 as usize).copied().unwrap_or(false);
    let wide = |id: ExprId| matches!(function.width(id), Some(32 | 64));
    match *function.expr(id)? {
        Expr::Binary(op, a, b) => {
            let (signed, other, both) = match op {
                Binary::ULt => (false, Binary::SLt, true),
                Binary::SLt => (true, Binary::ULt, true),
                Binary::ULe => (false, Binary::SLe, true),
                Binary::SLe => (true, Binary::ULe, true),
                Binary::UDiv => (false, Binary::SDiv, true),
                Binary::SDiv => (true, Binary::UDiv, true),
                Binary::URem => (false, Binary::SRem, true),
                Binary::SRem => (true, Binary::URem, true),
                Binary::LShr => (false, Binary::AShr, false),
                Binary::AShr => (true, Binary::LShr, false),
                Binary::Add
                | Binary::Sub
                | Binary::Mul
                | Binary::And
                | Binary::Or
                | Binary::Xor
                | Binary::Shl
                | Binary::Rol
                | Binary::Ror
                | Binary::Eq
                | Binary::Ne => return None,
            };
            if !wide(a) || !is(a) || (both && !is(b)) {
                return None;
            }
            let wanted = if both {
                combine(sign_of(function, a), sign_of(function, b))
            } else {
                sign_of(function, a)
            };
            (wanted == Some(!signed)).then_some(Expr::Binary(other, a, b))
        }
        Expr::Extend {
            signed,
            value,
            width,
        } => (wide(value) && is(value) && sign_of(function, value) == Some(!signed)).then_some(
            Expr::Extend {
                signed: !signed,
                value,
                width,
            },
        ),
        Expr::Const(_)
        | Expr::Undefined(..)
        | Expr::Var(_)
        | Expr::AddressOf(_)
        | Expr::Unary(..)
        | Expr::Logical(..)
        | Expr::Flag(..)
        | Expr::Extract { .. }
        | Expr::Concat { .. }
        | Expr::Select { .. }
        | Expr::Lanes { .. }
        | Expr::Float { .. }
        | Expr::Cast { .. }
        | Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Exception { .. }
        | Expr::Assign { .. } => None,
    }
}

/// The signedness C reads two operands with: unsigned if either is, else
/// signed if either is.
fn combine(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), _) | (_, Some(true)) => Some(true),
        (None, None) => None,
    }
}

/// Whether type `ty` prints signed (`None`: not an integer or a pointer,
/// or one byte wide).
fn sign_of_type(function: &Function, ty: TypeId) -> Option<bool> {
    match function.types.get(ty)? {
        Type::Int(_) => Some(true),
        Type::UInt(_) | Type::Pointer(_) | Type::Code(_) => Some(false),
        Type::Enum(enumeration) => Some(enumeration.signed),
        &Type::Bits(width) => Some(matches!(width, 32 | 64)),
        Type::Char { .. }
        | Type::Bool(_)
        | Type::Float(_)
        | Type::Struct(_)
        | Type::Union(_)
        | Type::Array { .. }
        | Type::Vector { .. } => None,
    }
}

/// Whether expression `id` reads as signed in C (`None`: it does not
/// say definitely).
fn sign_of(function: &Function, id: ExprId) -> Option<bool> {
    match *function.expr(id)? {
        Expr::Var(var) => sign_of_type(function, function.var(var)?.ty),
        Expr::Load { ty, .. } | Expr::Cast { ty, .. } => sign_of_type(function, ty),
        Expr::Extend { signed, .. } => Some(signed),
        Expr::Call(call) => {
            let call = function.call(call)?;
            let returns = function.types.signature(call.signature)?.returns?;
            sign_of_type(function, returns)
        }
        Expr::Binary(op, ..) => match op {
            Binary::SDiv | Binary::SRem | Binary::AShr => Some(true),
            Binary::UDiv | Binary::URem | Binary::LShr => Some(false),
            Binary::Shl
            | Binary::Add
            | Binary::Sub
            | Binary::Mul
            | Binary::And
            | Binary::Or
            | Binary::Xor
            | Binary::Rol
            | Binary::Ror
            | Binary::Eq
            | Binary::Ne
            | Binary::ULt
            | Binary::ULe
            | Binary::SLt
            | Binary::SLe => None,
        },
        Expr::Const(_)
        | Expr::Undefined(..)
        | Expr::AddressOf(_)
        | Expr::Unary(..)
        | Expr::Logical(..)
        | Expr::Flag(..)
        | Expr::Extract { .. }
        | Expr::Concat { .. }
        | Expr::Select { .. }
        | Expr::Lanes { .. }
        | Expr::Float { .. }
        | Expr::Exception { .. }
        | Expr::Assign { .. } => None,
    }
}
