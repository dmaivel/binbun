//! Operations given the signedness of their operands where both readings
//! agree: [`Signs`].

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Block, Expr, ExprId, Function, StmtId};
use binbun_ast::types::{Type, TypeId};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::ir::Binary;

use super::expr::{Info, append, map_roots, rebuild, roots};
use crate::pass::{L2Env, size};
use crate::range::{Ranges, node_nonnegative};

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
