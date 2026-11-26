//! Expressions: an L2 expression tree walked with an explicit stack (no
//! native recursion on its depth), each node built from its operands' C
//! expressions with the casts its operation needs.

use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{ExceptionValue, Expr, ExprId, Logical, Node, VarId};
use binbun_ast::types::{Type, TypeId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, Flag, FloatOp, FloatOutput, Format, LaneOp, Unary};
use binbun_ssa::ir::Unknown;

use super::chars::Spelling;
use super::enums::Context;
use super::types::{CTy, common, container, native};
use super::value::{
    Class, EndLiteral, IntTy, Op, Range, Value, constant_value, int_of, parenthesized, promote,
};
use super::{PrintError, Printer, error};
use crate::document::Doc;

/// How many expression nodes a function may print (shared operands are
/// printed at each use, so a small DAG can stand for a huge tree).
pub(super) const BUDGET: usize = 1 << 20;

/// How many pieces of expressions a function's printing may copy (an
/// operand inside parentheses, a cast or on the right of an operator is
/// copied: a deep expression costs its depth times its size).
pub(super) const COPY_BUDGET: usize = 1 << 26;

/// How a node is printed: its own operands, or a pattern over its
/// subtree.
#[derive(Clone, Copy, Debug)]
pub(super) enum Shape {
    /// Its operands.
    Plain,
    /// The high half of a double-width product: `umulh(a, b)`.
    MulHigh { signed: bool, a: ExprId, b: ExprId },
    /// A load from `base + index * scale + offset`.
    Load {
        base: ExprId,
        index: Option<ExprId>,
        scale: u64,
        offset: i128,
    },
    /// A load from `base + (rows.0 * rows.1 + columns.0 * columns.1) *
    /// scale + offset`, `scale` the size of what `base` points to: two
    /// indices, each a whole number of elements (`p[i + j * 4]`, a pointer
    /// stepped through rows and columns).
    Rows {
        base: ExprId,
        rows: (ExprId, u64),
        columns: (ExprId, u64),
        scale: u64,
        offset: i128,
    },
    /// `pointer + index * scale (+ offset)`, `scale` the size of what
    /// `pointer` points to: `pointer + index`; with an offset (into a
    /// struct `pointer` points to), `&pointer[index].field`.
    Index {
        pointer: ExprId,
        index: ExprId,
        scale: u64,
        offset: i128,
    },
    /// The sign bit of each lane of a mask extended to lanes of that width
    /// (`lanes.n.extract.(w-1).1(lanes.n.sext.w(mask))`, as SSE's
    /// `pmovmskb` of `pcmpeqb`): the mask.
    Mask(ExprId),
    /// A concatenation wider than 128 bits of values of one width
    /// ([`Printer::concat_pieces`]): a vector of them as its lanes.
    Pieces,
    /// A concatenation of 256 or 512 bits of a value under the rest of a
    /// vector of that width ([`Printer::under`]): the vector `whole`'s
    /// bits (`concat(extract(v, 128, 384), x)`), or a named unknown value
    /// of a width no C type has (`concat(undefined:384, x)`, `whole`
    /// `None`), named at the concatenation's width: the vector, its low
    /// lane replaced by the value (`(u128x4){x, ((u128x4)v)[1], …}`).
    Under {
        whole: Option<ExprId>,
        high: ExprId,
        low: ExprId,
    },
    /// A concatenation of at most 128 bits whose high part is unknown but
    /// not the architecture's ([`Printer::declared_width`]): the low part
    /// at its declared width.
    Declared(ExprId),
    /// Bits of a concatenation wider than 128 bits whose high part is a
    /// constant or an unknown value not the architecture's
    /// (`extract(concat(undefined:448, x), 0, 128)`, a scalar float in a
    /// `zmm` register): bits of the low part, or, from bit 0 and at most
    /// 128 of them, the low part below the constant's bits (at its
    /// declared width below an unknown value's).
    Within {
        high: ExprId,
        low: ExprId,
        offset: u16,
        width: u16,
    },
    /// Bits of a value wider than 128 bits that lie within one element it
    /// is built of, through extensions, concatenations and extractions
    /// ([`Printer::lane_of`]: `extract(zext.512(v), 0, 64)`, a lane of a
    /// `zmm` register a 128-bit `v` was written to): those bits of the
    /// element, from `offset`.
    LaneOf { element: ExprId, offset: u16 },
    /// Some of the four outcomes of comparing two floats
    /// ([`Printer::float_relation_of`]: `(fcmp(a, b) & holds) != 0`): C's
    /// comparison of them.
    FloatRelation {
        left: ExprId,
        right: ExprId,
        format: Format,
        holds: u8,
    },
}

enum Task {
    Visit(ExprId),
    Build(ExprId, Shape, usize),
}

/// The values of a node's operands, `N` of them.
fn take<const N: usize>(operands: Vec<Value>) -> Result<[Value; N], PrintError> {
    <[Value; N]>::try_from(operands).map_err(|_| error(None, "operand count"))
}

impl Printer<'_> {
    /// Expression `root` as C.
    pub(super) fn expr(&mut self, root: ExprId) -> Result<Value, PrintError> {
        let saved = self.node;
        let mut tasks = vec![Task::Visit(root)];
        let mut values: Vec<Value> = Vec::new();
        while let Some(task) = tasks.pop() {
            match task {
                Task::Visit(id) => {
                    self.budget = self.budget.checked_sub(1).ok_or_else(|| {
                        error(
                            Some(Node::Expr(id)),
                            "expressions too large to print (shared operands)",
                        )
                    })?;
                    let shape = self.shape(id);
                    let children = self.children(id, shape)?;
                    tasks.push(Task::Build(id, shape, children.len()));
                    tasks.extend(children.into_iter().rev().map(Task::Visit));
                }
                Task::Build(id, shape, count) => {
                    let at = values.len().saturating_sub(count);
                    let operands = values.split_off(at);
                    self.node = Some(Node::Expr(id));
                    let built = self.build(id, shape, operands);
                    self.node = saved;
                    if self.copied.get() > COPY_BUDGET {
                        return Err(error(
                            Some(Node::Expr(id)),
                            "expressions too large to print (nested too deeply)",
                        ));
                    }
                    values.push(built?);
                }
            }
        }
        values
            .pop()
            .ok_or_else(|| error(Some(Node::Expr(root)), "nothing printed"))
    }

    /// The node's expression.
    fn node_expr(&self, id: ExprId) -> Result<Expr, PrintError> {
        self.f
            .expr(id)
            .copied()
            .ok_or_else(|| error(Some(Node::Expr(id)), "no such expression"))
    }

    fn shape(&self, id: ExprId) -> Shape {
        match self.f.expr(id) {
            Some(&Expr::Load { address, .. }) => self
                .rows_shape(address)
                .unwrap_or_else(|| self.address_shape(address)),
            Some(&Expr::Binary(Binary::Add, x, y)) => self.index_shape(id, x, y),
            Some(&Expr::Binary(op @ (Binary::Eq | Binary::Ne), masked, zero))
                if let Some(shape) = self.float_relation_of(op == Binary::Eq, masked, zero) =>
            {
                shape
            }
            Some(Expr::Concat { .. }) if self.concat_pieces(id).is_some() => Shape::Pieces,
            Some(Expr::Concat { .. }) if let Some((whole, high, low)) = self.under(id) => {
                Shape::Under { whole, high, low }
            }
            Some(Expr::Concat { .. })
                if self.width(id) <= 128
                    && let Some(low) = self.declared_width(id) =>
            {
                Shape::Declared(low)
            }
            Some(&Expr::Extract {
                value,
                offset,
                width,
            }) if self.width(value) > 128
                && let Some((element, offset)) = self.lane_of(value, offset, width) =>
            {
                Shape::LaneOf { element, offset }
            }
            Some(&Expr::Extract {
                value,
                offset,
                width,
            }) if self.width(value) > 128
                && let Some(&Expr::Concat { high, low }) = self.f.expr(value)
                && (offset + width <= self.width(low) || (offset == 0 && width <= 128))
                && match self.f.expr(high) {
                    Some(Expr::Const(_)) => true,
                    Some(Expr::Undefined(_, unknown, _)) => {
                        !matches!(unknown, Unknown::Architecture { .. })
                    }
                    Some(_) | None => false,
                } =>
            {
                Shape::Within {
                    high,
                    low,
                    offset,
                    width,
                }
            }
            Some(&Expr::Lanes {
                lanes,
                op: LaneOp::Extract { offset, width: 1 },
                operands: [extended, ..],
            }) if lanes > 1 => match self.f.expr(extended) {
                Some(&Expr::Lanes {
                    lanes: inner,
                    op:
                        LaneOp::Extend {
                            signed: true,
                            width,
                        },
                    operands: [mask, ..],
                }) if inner == lanes && offset + 1 == width && self.width(mask) == lanes => {
                    Shape::Mask(mask)
                }
                _ => Shape::Plain,
            },
            Some(&Expr::Extract {
                value,
                offset,
                width,
            }) if offset == width && matches!(width, 8 | 16 | 32 | 64) => {
                let Some(&Expr::Binary(Binary::Mul, x, y)) = self.f.expr(value) else {
                    return Shape::Plain;
                };
                match (self.f.expr(x), self.f.expr(y)) {
                    (
                        Some(&Expr::Extend {
                            signed, value: a, ..
                        }),
                        Some(&Expr::Extend {
                            signed: other,
                            value: b,
                            ..
                        }),
                    ) if signed == other && self.width(a) == width && self.width(b) == width => {
                        Shape::MulHigh { signed, a, b }
                    }
                    _ => Shape::Plain,
                }
            }
            Some(_) | None => Shape::Plain,
        }
    }

    /// The float relation `(outcome & mask) != 0` is (`negated`: `== 0`,
    /// the other outcomes), `outcome` a comparison of two `float`s or
    /// `double`s (one of four bits: less, equal, greater, unordered), as
    /// lowering writes a condition on a float comparison's flags.
    fn float_relation_of(&self, negated: bool, masked: ExprId, zero: ExprId) -> Option<Shape> {
        let &Expr::Const(zero) = self.f.expr(zero)? else {
            return None;
        };
        let &Expr::Binary(Binary::And, outcome, mask) = self.f.expr(masked)? else {
            return None;
        };
        let &Expr::Const(mask) = self.f.expr(mask)? else {
            return None;
        };
        let &Expr::Float {
            op: FloatOp::Compare { .. },
            format: format @ (Format::Single | Format::Double),
            lanes: 1,
            output: FloatOutput::Value,
            operands: [left, right, _],
            ..
        } = self.f.expr(outcome)?
        else {
            return None;
        };
        let mask = u8::try_from(mask.low_u64() & 0b1111).ok()?;
        let holds = if negated { !mask & 0b1111 } else { mask };
        (zero.is_zero() && holds != 0 && holds != 0b1111).then_some(Shape::FloatRelation {
            left,
            right,
            format,
            holds,
        })
    }

    /// The element holding bits `offset..offset + width` of `value` and
    /// where they start in it: through a zero or sign extension (bits it
    /// extends), a concatenation (bits of one side) and an extraction, as
    /// deep as they go; `None` if not even one step does.
    fn lane_of(&self, value: ExprId, offset: u16, width: u16) -> Option<(ExprId, u16)> {
        let (mut at, mut offset) = (value, offset);
        loop {
            let end = offset.checked_add(width)?;
            match *self.f.expr(at)? {
                Expr::Extend { value, .. } if end <= self.width(value) => at = value,
                Expr::Concat { high, low } => {
                    let below = self.width(low);
                    if end <= below {
                        at = low;
                    } else if offset >= below {
                        at = high;
                        offset -= below;
                    } else {
                        break;
                    }
                }
                Expr::Extract {
                    value,
                    offset: from,
                    ..
                } => {
                    at = value;
                    offset = offset.checked_add(from)?;
                }
                Expr::Extend { .. }
                | Expr::Const(_)
                | Expr::Undefined(..)
                | Expr::Var(_)
                | Expr::AddressOf(_)
                | Expr::Unary(..)
                | Expr::Binary(..)
                | Expr::Logical(..)
                | Expr::Flag(..)
                | Expr::Select { .. }
                | Expr::Lanes { .. }
                | Expr::Float { .. }
                | Expr::Cast { .. }
                | Expr::Load { .. }
                | Expr::Call(_)
                | Expr::Assign { .. }
                | Expr::Exception { .. } => break,
            }
        }
        (at != value).then_some((at, offset))
    }

    fn children(&self, id: ExprId, shape: Shape) -> Result<Vec<ExprId>, PrintError> {
        Ok(match shape {
            Shape::MulHigh { a, b, .. } => vec![a, b],
            Shape::FloatRelation { left, right, .. } => vec![left, right],
            Shape::Mask(mask) => vec![mask],
            Shape::Declared(low) | Shape::Within { low, .. } => vec![low],
            Shape::Under { whole, low, .. } => whole.into_iter().chain([low]).collect(),
            Shape::LaneOf { element, .. } => vec![element],
            Shape::Pieces => {
                let (pieces, _) = self
                    .concat_pieces(id)
                    .ok_or_else(|| error(Some(Node::Expr(id)), "no pieces"))?;
                // One value repeated (a broadcast): printed once.
                match pieces.first() {
                    Some(&first) if pieces.iter().all(|&piece| piece == first) => vec![first],
                    Some(_) | None => pieces,
                }
            }
            Shape::Load { base, index, .. } => core::iter::once(base).chain(index).collect(),
            Shape::Rows {
                base,
                rows: (rows, _),
                columns: (columns, _),
                ..
            } => vec![base, rows, columns],
            Shape::Index { pointer, index, .. } => vec![pointer, index],
            Shape::Plain => match self.node_expr(id)? {
                Expr::Lanes { op, operands, .. } => {
                    operands.iter().take(op.arity()).copied().collect()
                }
                Expr::Float {
                    op,
                    rounding,
                    operands,
                    ..
                } => operands
                    .iter()
                    .take(op.arity())
                    .copied()
                    .chain(core::iter::once(rounding))
                    .collect(),
                expr @ (Expr::Const(_)
                | Expr::Undefined(..)
                | Expr::Var(_)
                | Expr::AddressOf(_)
                | Expr::Unary(..)
                | Expr::Binary(..)
                | Expr::Logical(..)
                | Expr::Flag(..)
                | Expr::Extract { .. }
                | Expr::Concat { .. }
                | Expr::Extend { .. }
                | Expr::Select { .. }
                | Expr::Cast { .. }
                | Expr::Load { .. }
                | Expr::Call(_)
                | Expr::Exception { .. }
                | Expr::Assign { .. }) => expr.operands(self.f).collect(),
            },
        })
    }

    fn build(
        &mut self,
        id: ExprId,
        shape: Shape,
        operands: Vec<Value>,
    ) -> Result<Value, PrintError> {
        let width = self.width(id);
        match shape {
            Shape::MulHigh { signed, .. } => {
                let [a, b] = take(operands)?;
                self.mul_high(signed, a, b)
            }
            Shape::FloatRelation { format, holds, .. } => {
                let [a, b] = take(operands)?;
                self.float_relation(a, b, format, holds)
            }
            Shape::Load {
                base: base_id,
                index: index_id,
                scale,
                offset,
            } => {
                let Expr::Load { ty, .. } = self.node_expr(id)? else {
                    return Err(error(self.node, "not a load"));
                };
                let mut operands = operands.into_iter();
                let base = operands.next().ok_or_else(|| error(self.node, "no base"))?;
                let index = operands.next().map(|index| (index, scale));
                let bounds = self.bounds(index_id);
                self.access_at(base_id, base, (index, bounds), offset, ty, false)
            }
            Shape::Rows { .. } => self.rows_load(id, shape, operands),
            Shape::Index {
                pointer: pointer_id,
                index: index_id,
                scale,
                offset,
            } => {
                let [pointer, index] = take(operands)?;
                let index = self.int_view(index)?;
                let array = self.pointee_of(pointer_id).and_then(|target| {
                    self.array_field_at(target, scale, offset, self.bounds(Some(index_id)))
                });
                match array {
                    Some(found) => self.array_address(pointer, (index, scale), found),
                    None => self.pointer_add(pointer, Some((index, scale)), offset),
                }
            }
            Shape::Mask(_) => {
                let [mask] = take(operands)?;
                Ok(mask)
            }
            Shape::Declared(_) => {
                let [low] = take(operands)?;
                self.at_declared_width(low, width)
            }
            Shape::Under { whole: Some(_), .. } => {
                let [whole, low] = take(operands)?;
                self.vector_under(whole, low)
            }
            Shape::Under {
                whole: None, high, ..
            } => {
                let [low] = take(operands)?;
                let Expr::Undefined(_, unknown, _) = self.node_expr(high)? else {
                    return Err(error(self.node, "not an unknown value"));
                };
                let whole = self.unknown(high, width, unknown)?;
                self.vector_under(whole, low)
            }
            Shape::Within {
                high,
                offset,
                width,
                ..
            } => {
                let [low] = take(operands)?;
                if offset == 0 && width == low.width {
                    return Ok(low);
                }
                if offset + width <= low.width {
                    return self.extract(low, offset, width);
                }
                let above = width - low.width;
                let bits = match self.f.expr(high) {
                    Some(&Expr::Const(bits)) => bits.extract(0, above),
                    Some(_) | None => return self.at_declared_width(low, width),
                };
                let constant = self.constant(bits, Class::Zero, false)?;
                self.concat(constant, low, width)
            }
            Shape::LaneOf { offset, .. } => {
                let [element] = take(operands)?;
                if offset == 0 && width == element.width {
                    return Ok(element);
                }
                self.extract(element, offset, width)
            }
            Shape::Pieces => {
                let (_, ty) = self
                    .concat_pieces(id)
                    .ok_or_else(|| error(self.node, "no pieces"))?;
                self.pieces(&operands, ty)
            }
            Shape::Plain => self.plain(id, width, operands),
        }
    }

    /// Node `id` (of `width` bits) printed from its own operands' values.
    fn plain(&mut self, id: ExprId, width: u16, operands: Vec<Value>) -> Result<Value, PrintError> {
        match self.node_expr(id)? {
            Expr::Const(bits) if width > 128 => self.wide_constant(bits),
            Expr::Const(bits) => self.constant(bits, Class::Zero, false),
            Expr::Undefined(width, unknown, _) => self.unknown(id, width, unknown),
            Expr::Var(var) => self.var_value(var),
            Expr::AddressOf(var) => self.address_of(var),
            Expr::Unary(op, _) => {
                let [a] = take(operands)?;
                if Self::is_vector(&a) && (op == Unary::Not || width > 128) {
                    return self.vector_unary(op, a);
                }
                self.unary(op, a, width)
            }
            Expr::Binary(op, x, _) => {
                let [a, b] = take(operands)?;
                // Vectors bitwise as vectors; wider than 128 bits, any
                // operation as one (or not at all).
                if (Self::is_vector(&a) || Self::is_vector(&b))
                    && (matches!(op, Binary::And | Binary::Or | Binary::Xor) || a.width > 128)
                {
                    return self.vector_binary(op, a, b);
                }
                // Arithmetic on a frame struct's address by a value that is
                // no constant may cross its fields: on its bytes.
                if matches!(op, Binary::Add | Binary::Sub)
                    && width == self.pointer_width()
                    && b.constant.is_none()
                    && matches!(b.ty, CTy::Int { .. })
                    && let Some(base) = self.frame_bytes(x)?
                {
                    return self.byte_offset(base, op == Binary::Sub, b);
                }
                self.binary(op, a, b, width)
            }
            Expr::Logical(op, ..) => {
                let [a, b] = take(operands)?;
                self.logical(op, a, b)
            }
            Expr::Flag(op, ..) => {
                let [a, b, c] = take(operands)?;
                self.flag(op, a, b, c)
            }
            Expr::Extract { offset, width, .. } => {
                let [value] = take(operands)?;
                self.extract(value, offset, width)
            }
            Expr::Concat { .. } => {
                let [high, low] = take(operands)?;
                self.concat(high, low, width)
            }
            Expr::Extend { signed, width, .. } => {
                let [value] = take(operands)?;
                self.extend(value, signed, width)
            }
            Expr::Select { .. } => {
                let [condition, then, otherwise] = take(operands)?;
                if width > 128 {
                    return self.vector_select(condition, then, otherwise);
                }
                self.select(condition, then, otherwise)
            }
            Expr::Lanes { lanes, op, .. } => self.lane(lanes, op, operands, width),
            Expr::Float {
                op,
                format,
                lanes,
                output,
                ..
            } => self.float(op, format, lanes, output, operands, width),
            Expr::Cast { ty, .. } => {
                if let Some(function) = self.function_ref(id)? {
                    return Ok(function);
                }
                let [value] = take(operands)?;
                self.cast_to(value, ty)
            }
            Expr::Load { .. } => Err(error(self.node, "load printed as plain")),
            Expr::Call(id) => {
                let call = self
                    .f
                    .call(id)
                    .ok_or_else(|| error(self.node, "no such call"))?;
                let (_, value) = self.call_value(call, operands)?;
                value.ok_or_else(|| error(self.node, "a call's value, but it returns none"))
            }
            Expr::Exception { value, width } => Ok(self.exception(value, width)),
            Expr::Assign { var, .. } => self.assign_value(var, operands),
        }
    }

    /// `(var = value)` (`operands`: the value), C's assignment
    /// expression: the value converted to `var`'s type, as an assignment
    /// statement converts it; its value is `var`'s after the assignment
    /// (C11 6.5.16p3).
    fn assign_value(&mut self, var: VarId, operands: Vec<Value>) -> Result<Value, PrintError> {
        let [value] = take(operands)?;
        let ty = self
            .f
            .var(var)
            .ok_or_else(|| error(Some(Node::Var(var)), "no such variable"))?
            .ty;
        let storing = core::mem::replace(&mut self.storing, true);
        let lhs = self.var_value(var);
        self.storing = storing;
        let lhs = lhs?;
        if matches!(lhs.ty, CTy::Other(_)) {
            return Err(self.unsupported(self.node, "an aggregate assigned in an expression"));
        }
        let value = self.converted(value, ty)?;
        let depth = value.depth;
        let mut doc = self.operand(lhs.clone(), Op::Unary, false);
        doc.extend([Doc::Space, Doc::op("=", self.node), Doc::Space]);
        doc.extend(value.doc);
        Ok(Value {
            doc: parenthesized(doc, self.node),
            op: Op::Postfix,
            lvalue: false,
            constant: None,
            // An effect: evaluated exactly when L2 evaluates it.
            loads: true,
            depth,
            address_of: None,
            unsigned_literal: None,
            ..lhs
        })
    }

    /// `binbun_exception()` (a `void *`), `binbun_selector()` (an
    /// `intptr_t`) or `binbun_exception_code()` (a `uint32_t`), standing
    /// for a value of `width` bits.
    fn exception(&mut self, value: ExceptionValue, width: u16) -> Value {
        let bits = self.pointer_width();
        let (name, ty, class) = match value {
            ExceptionValue::Object => (
                "binbun_exception",
                CTy::Pointer(self.types.intern(Type::Pointer(None))),
                Class::Low,
            ),
            ExceptionValue::Selector => (
                "binbun_selector",
                CTy::Int { signed: true, bits },
                if width == bits {
                    Class::Sign
                } else {
                    Class::Low
                },
            ),
            ExceptionValue::Code => (
                "binbun_exception_code",
                CTy::Int {
                    signed: false,
                    bits: 32,
                },
                Class::Low,
            ),
            ExceptionValue::Abnormal => (
                "binbun_abnormal_termination",
                CTy::Int {
                    signed: true,
                    bits: 32,
                },
                Class::Low,
            ),
        };
        self.helper(name, Vec::new(), ty, class, width)
    }

    /// A `Lanes` node: of one lane, as its scalar operation; of more, as
    /// vectors ([`Self::vector_lanes`]).
    fn lane(
        &mut self,
        lanes: u16,
        op: LaneOp,
        operands: Vec<Value>,
        width: u16,
    ) -> Result<Value, PrintError> {
        if lanes != 1 {
            return self.vector_lanes(lanes, op, operands, width);
        }
        match op {
            LaneOp::Unary(op) => {
                let [a] = take(operands)?;
                self.unary(op, a, width)
            }
            LaneOp::Binary(op) => {
                let [a, b] = take(operands)?;
                self.binary(op, a, b, width)
            }
            LaneOp::Extract { offset, width } => {
                let [a] = take(operands)?;
                self.extract(a, offset, width)
            }
            LaneOp::Extend { signed, width } => {
                let [a] = take(operands)?;
                self.extend(a, signed, width)
            }
            LaneOp::Select => {
                let [c, t, o] = take(operands)?;
                self.select(c, t, o)
            }
        }
    }

    /// A literal argument printed in the class of a parameter of
    /// signedness `signed` (so C's conversion does not change its value);
    /// anything else as it is.
    pub(super) fn arg(&mut self, value: Value, signed: bool) -> Result<Value, PrintError> {
        match value.constant {
            Some(bits) => {
                self.constant(bits, if signed { Class::Sign } else { Class::Zero }, false)
            }
            None => Ok(value),
        }
    }

    /// A 1-bit condition whose C value is non-zero exactly when it is 1.
    pub(super) fn truthy(&mut self, value: Value) -> Result<Value, PrintError> {
        let value = self.int_view(value)?;
        if value.is(Class::Zero) || value.is(Class::Sign) {
            Ok(value)
        } else {
            self.coerce(value, Class::Zero)
        }
    }

    pub(super) fn unary(&mut self, op: Unary, a: Value, width: u16) -> Result<Value, PrintError> {
        let a = self.int_view(a)?;
        match op {
            Unary::Not if width == 1 => {
                let a = self.truthy(a)?;
                Ok(self.prefix("!", a, (true, 32), Class::Zero))
            }
            Unary::Not => {
                let a = if a.ty == CTy::Bool {
                    self.cast(
                        a,
                        CTy::Int {
                            signed: true,
                            bits: 32,
                        },
                    )
                } else {
                    a
                };
                let class = if a.class == Class::Sign {
                    Class::Sign
                } else {
                    Class::Low
                };
                let ty = a.promoted().unwrap_or((true, 32));
                Ok(self.prefix("~", a, ty, class))
            }
            Unary::Neg => {
                let ty = a.promoted().unwrap_or((true, 32));
                Ok(self.prefix("-", a, ty, Class::Low))
            }
            Unary::Popcount | Unary::LeadingZeros | Unary::TrailingZeros => {
                self.count(op, a, width)
            }
            Unary::ByteSwap => self.byte_swap(a, width),
            Unary::EvenParity8 => {
                // Bits above a narrower value's width count as 0.
                let a = if width < 8 {
                    self.coerce(a, Class::Zero)?
                } else {
                    self.arg(a, false)?
                };
                Ok(self.helper("even_parity8", vec![a], CTy::Bool, Class::Zero, 1))
            }
        }
    }

    /// `op a`.
    pub(super) fn prefix(&self, op: &str, a: Value, ty: (bool, u16), class: Class) -> Value {
        let mut doc = vec![Doc::op(op, self.node)];
        let (width, depth) = (a.width, a.depth);
        let parts = [&a];
        let loads = parts.iter().any(|part| part.loads);
        let operand = self.operand(a, Op::Unary, false);
        self.append(&mut doc, operand);
        let mut value = Self::built(doc, Op::Unary, ty, class, width, &[], depth);
        value.loads = loads;
        value
    }

    fn count(&mut self, op: Unary, a: Value, width: u16) -> Result<Value, PrintError> {
        let (a, bits) = self.helper_operand(a, false)?;
        let ty = CTy::Int {
            signed: false,
            bits,
        };
        let name = match op {
            Unary::LeadingZeros => "clz",
            Unary::TrailingZeros => "ctz",
            Unary::Popcount | Unary::Not | Unary::Neg | Unary::ByteSwap | Unary::EvenParity8 => {
                "popcount"
            }
        };
        if native(width) || name == "popcount" {
            return Ok(self.helper(name, vec![a], ty, Class::Zero, width));
        }
        let name = if name == "clz" { "clz_n" } else { "ctz_n" };
        let count = self.literal_number(u64::from(width), false);
        Ok(self.helper(name, vec![a, count], ty, Class::Zero, width))
    }

    fn byte_swap(&mut self, a: Value, width: u16) -> Result<Value, PrintError> {
        if native(width) {
            let (a, bits) = self.helper_operand(a, false)?;
            return Ok(self.helper(
                "bswap",
                vec![a],
                CTy::Int {
                    signed: false,
                    bits,
                },
                Class::Zero,
                width,
            ));
        }
        let bits =
            container(width).ok_or_else(|| self.unsupported(self.node, "values over 128 bits"))?;
        let a = self.coerce(a, Class::Zero)?;
        let a = self.exact(a, false, bits);
        let swapped = self.helper(
            "bswap",
            vec![a],
            CTy::Int {
                signed: false,
                bits,
            },
            Class::Zero,
            bits,
        );
        let count = self.literal_number(u64::from(bits - width), false);
        let (doc, depth) = self.binary_doc(swapped.clone(), ">>", Op::Shift, count);
        Ok(Self::built(
            doc,
            Op::Shift,
            promote((false, bits)),
            Class::Zero,
            width,
            &[&swapped],
            depth,
        ))
    }

    pub(super) fn binary(
        &mut self,
        op: Binary,
        a: Value,
        b: Value,
        width: u16,
    ) -> Result<Value, PrintError> {
        if let Some(signed) = self.float_sign(op, &a, &b, width) {
            return Ok(signed);
        }
        let difference = op == Binary::Sub && self.byte_pointers(&a, &b)?;
        // `i + p` as `p + i`: the pointer first, so the sum stays one.
        let (a, b) = if op == Binary::Add && b.ty.is_pointer() && matches!(a.ty, CTy::Int { .. }) {
            (b, a)
        } else {
            (a, b)
        };
        let byte_index = width == self.pointer_width()
            && a.ty.is_pointer()
            && matches!(b.ty, CTy::Int { .. })
            && b.constant.is_none();
        match op {
            Binary::Add | Binary::Sub if a.ty.is_pointer() && b.constant.is_some() => {
                let (negative, magnitude) =
                    constant_value(b.constant.unwrap_or(Bits::zero(width)), Class::Sign);
                let magnitude = i128::try_from(magnitude).unwrap_or(i128::MAX);
                let offset = if negative == (op == Binary::Add) {
                    -magnitude
                } else {
                    magnitude
                };
                self.pointer_add(a, None, offset)
            }
            // `p ± i` (`i` not a constant) bytes on from `p`: arithmetic in
            // bytes, not on `p`'s integer view.
            Binary::Add | Binary::Sub if byte_index => self.byte_offset(a, op == Binary::Sub, b),
            // `p - q` of byte or `void` pointers of one type: their
            // distance, exactly.
            Binary::Sub if difference => {
                let (doc, depth) = self.binary_doc(a, "-", Op::Additive, b);
                Ok(Self::built(
                    doc,
                    Op::Additive,
                    (true, width),
                    Class::Sign,
                    width,
                    &[],
                    depth,
                ))
            }
            Binary::Add | Binary::Sub | Binary::Mul | Binary::And | Binary::Or | Binary::Xor => {
                self.arith(op, a, b, width)
            }
            Binary::UDiv | Binary::URem | Binary::SDiv | Binary::SRem => {
                self.divide(op, a, b, width)
            }
            Binary::Shl => self.shift(Shift::Left, a, b, width),
            Binary::LShr => self.shift(Shift::Logical, a, b, width),
            Binary::AShr => self.shift(Shift::Arithmetic, a, b, width),
            Binary::Rol | Binary::Ror => self.rotate(op, a, b, width),
            Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe | Binary::SLt | Binary::SLe => {
                // The comparison being printed: an operand of an
                // enumeration's type names the other's constant, a
                // character has it written as one.
                let spelling = match self.node {
                    Some(Node::Expr(id)) => match self.f.expr(id) {
                        Some(&Expr::Binary(_, x, y)) => self.spelling(x, y),
                        Some(_) | None => Spelling::Number,
                    },
                    Some(_) | None => Spelling::Number,
                };
                self.compare(op, a, b, false, spelling)
            }
        }
    }

    /// C's `&&` or `||` of two 1-bit values (the right one evaluated only
    /// if needed, as in L2).
    fn logical(&mut self, op: Logical, a: Value, b: Value) -> Result<Value, PrintError> {
        let (a, b) = (self.truthy(a)?, self.truthy(b)?);
        let (text, kind) = match op {
            Logical::And => ("&&", Op::LogicalAnd),
            Logical::Or => ("||", Op::LogicalOr),
        };
        let loads = a.loads || b.loads;
        let (doc, depth) = self.binary_doc(a, text, kind, b);
        let mut value = Self::built(doc, kind, (true, 32), Class::Zero, 1, &[], depth);
        value.loads = loads;
        Ok(value)
    }

    fn arith(&mut self, op: Binary, a: Value, b: Value, width: u16) -> Result<Value, PrintError> {
        let a = self.int_view(a)?;
        let mut b = self.int_view(b)?;
        let mut op = op;
        // `x + -1` as `x - 1`.
        if let (Binary::Add | Binary::Sub, Some(bits)) = (op, b.constant) {
            let (negative, magnitude) = constant_value(bits, Class::Sign);
            if negative && magnitude < 1 << (width.min(32) - 1) {
                op = if op == Binary::Add {
                    Binary::Sub
                } else {
                    Binary::Add
                };
                b = self.constant(Bits::from_u128(width, magnitude), Class::Zero, false)?;
            }
        }
        if width == 1 && matches!(op, Binary::And | Binary::Or) && !b.loads {
            let (a, b) = (self.truthy(a)?, self.truthy(b)?);
            let (text, kind) = if op == Binary::And {
                ("&&", Op::LogicalAnd)
            } else {
                ("||", Op::LogicalOr)
            };
            let parts = [a.loads];
            let (doc, depth) = self.binary_doc(a, text, kind, b);
            let mut value = Self::built(doc, kind, (true, 32), Class::Zero, 1, &[], depth);
            value.loads = parts[0];
            return Ok(value);
        }
        let (text, kind) = match op {
            Binary::Add => ("+", Op::Additive),
            Binary::Sub => ("-", Op::Additive),
            Binary::Mul => ("*", Op::Multiplicative),
            Binary::And => ("&", Op::BitAnd),
            Binary::Or => ("|", Op::BitOr),
            Binary::Xor
            | Binary::UDiv
            | Binary::URem
            | Binary::SDiv
            | Binary::SRem
            | Binary::Shl
            | Binary::LShr
            | Binary::AShr
            | Binary::Rol
            | Binary::Ror
            | Binary::Eq
            | Binary::Ne
            | Binary::ULt
            | Binary::ULe
            | Binary::SLt
            | Binary::SLe => ("^", Op::BitXor),
        };
        let bitwise = matches!(kind, Op::BitAnd | Op::BitOr | Op::BitXor);
        let (a, b, ty) = self.operands(a, b, Class::Low, false, bitwise)?;
        let (zero, sign) = (
            (a.is_in(ty, Class::Zero), b.is_in(ty, Class::Zero)),
            (a.is_in(ty, Class::Sign), b.is_in(ty, Class::Sign)),
        );
        let class = match kind {
            Op::BitAnd if zero.0 || zero.1 => Class::Zero,
            Op::BitAnd | Op::BitOr | Op::BitXor if zero.0 && zero.1 => Class::Zero,
            Op::BitAnd | Op::BitOr | Op::BitXor if sign.0 && sign.1 => Class::Sign,
            Op::BitAnd
            | Op::BitOr
            | Op::BitXor
            | Op::Conditional
            | Op::LogicalOr
            | Op::LogicalAnd
            | Op::Equality
            | Op::Relational
            | Op::Shift
            | Op::Additive
            | Op::Multiplicative
            | Op::Unary
            | Op::Postfix => Class::Low,
        };
        let loads = a.loads || b.loads;
        let unsigned_literal = Self::end_literal(kind, &a, &b, ty, width);
        let (doc, depth) = self.binary_doc(a, text, kind, b);
        let mut value = Self::built(doc, kind, ty, class, width, &[], depth);
        value.loads = loads;
        value.unsigned_literal = unsigned_literal;
        Ok(value)
    }

    /// For `a op b` (`+`, `-` or `*`) computed in `ty`: its literal
    /// operand, if it is one that printed unsigned makes C compute in the
    /// unsigned type of the width ([`Value::unsigned_literal`]). The
    /// integer promotions make that `int` below 32 bits.
    fn end_literal(kind: Op, a: &Value, b: &Value, ty: IntTy, width: u16) -> Option<EndLiteral> {
        if !matches!(kind, Op::Additive | Op::Multiplicative)
            || ty != (true, width)
            || !matches!(width, 32 | 64)
        {
            return None;
        }
        [(b, true), (a, false)]
            .into_iter()
            .find_map(|(operand, last)| {
                let bits = operand.constant?;
                let signed = int_of(operand.ty).is_some_and(|(signed, _)| signed);
                (signed && operand.class == Class::Zero && operand.op == Op::Postfix)
                    .then_some(EndLiteral { last, bits })
            })
    }

    fn divide(&mut self, op: Binary, a: Value, b: Value, width: u16) -> Result<Value, PrintError> {
        let a = self.int_view(a)?;
        let b = self.int_view(b)?;
        let signed = matches!(op, Binary::SDiv | Binary::SRem);
        let need = if signed { Class::Sign } else { Class::Zero };
        let remainder = matches!(op, Binary::URem | Binary::SRem);
        let safe = b
            .constant
            .is_some_and(|k| !k.is_zero() && (!signed || k != Bits::ones(width)));
        if safe {
            let (a, b, ty) = self.operands(a, b, need, false, false)?;
            let loads = a.loads;
            let (doc, depth) =
                self.binary_doc(a, if remainder { "%" } else { "/" }, Op::Multiplicative, b);
            let mut value = Self::built(doc, Op::Multiplicative, ty, need, width, &[], depth);
            value.loads = loads;
            return Ok(value);
        }
        let (a, bits) = self.helper_operand(a, signed)?;
        let b = if native(width) {
            self.arg(b, signed)?
        } else {
            self.coerce(b, need)?
        };
        let name = match (signed, remainder) {
            (false, false) => "udiv",
            (false, true) => "urem",
            (true, false) => "sdiv",
            (true, true) => "srem",
        };
        let class = if remainder { need } else { Class::Low };
        Ok(self.helper(name, vec![a, b], CTy::Int { signed, bits }, class, width))
    }

    fn shift(&mut self, op: Shift, a: Value, b: Value, width: u16) -> Result<Value, PrintError> {
        let a = self.int_view(a)?;
        let b = self.int_view(b)?;
        let count = b
            .constant
            .map(|k| k.low_u128())
            .filter(|&k| k < u128::from(width));
        if let Some(count) = count {
            #[expect(clippy::cast_possible_truncation, reason = "below the width")]
            return self.shift_by(op, a, count as u16, width);
        }
        let signed = op == Shift::Arithmetic;
        let (a, bits) = self.helper_operand(a, signed)?;
        let b = self.count_operand(b, bits)?;
        let (name, class) = match op {
            Shift::Left => ("shl", Class::Low),
            Shift::Logical => ("lshr", Class::Zero),
            Shift::Arithmetic => ("ashr", Class::Sign),
        };
        Ok(self.helper(name, vec![a, b], CTy::Int { signed, bits }, class, width))
    }

    /// A count or divisor passed as a `bits`-bit unsigned parameter, with
    /// its unsigned value.
    fn count_operand(&mut self, b: Value, bits: u16) -> Result<Value, PrintError> {
        if b.constant.is_some() {
            return self.arg(b, false);
        }
        if b.is_in((false, bits), Class::Zero) {
            Ok(b)
        } else {
            self.coerce(b, Class::Zero)
        }
    }

    /// `a << count`, `a >> count` for a count below the width.
    pub(super) fn shift_by(
        &mut self,
        op: Shift,
        a: Value,
        count: u16,
        width: u16,
    ) -> Result<Value, PrintError> {
        let wide = container(width).unwrap_or(128).max(32);
        let a = match op {
            Shift::Left => match a.constant {
                Some(bits) => self.literal(bits, Class::Zero, (false, wide), false),
                None => a,
            },
            Shift::Logical => self.coerce(a, Class::Zero)?,
            Shift::Arithmetic => self.coerce(a, Class::Sign)?,
        };
        let promoted = a.promoted().unwrap_or((true, 32));
        let too_narrow = if op == Shift::Left {
            promoted.1 < width
        } else {
            promoted.1 <= count
        };
        let a = if too_narrow {
            self.cast(
                a,
                CTy::Int {
                    signed: op == Shift::Arithmetic,
                    bits: wide,
                },
            )
        } else {
            a
        };
        let ty = a.promoted().unwrap_or((true, 32));
        let class = match op {
            Shift::Left => match a.range() {
                Some(Range::Unsigned(bits))
                    if a.is(Class::Zero) && bits + count <= width.min(ty.1 - u16::from(ty.0)) =>
                {
                    Class::Zero
                }
                Some(Range::Unsigned(_) | Range::Signed(_)) | None => Class::Low,
            },
            Shift::Logical => Class::Zero,
            Shift::Arithmetic => Class::Sign,
        };
        let text = if op == Shift::Left { "<<" } else { ">>" };
        let amount = self.literal_number(u64::from(count), false);
        let loads = a.loads;
        let (doc, depth) = self.binary_doc(a, text, Op::Shift, amount);
        let mut value = Self::built(doc, Op::Shift, ty, class, width, &[], depth);
        value.loads = loads;
        Ok(value)
    }

    fn rotate(&mut self, op: Binary, a: Value, b: Value, width: u16) -> Result<Value, PrintError> {
        let a = self.int_view(a)?;
        let b = self.int_view(b)?;
        let (a, bits) = self.helper_operand(a, false)?;
        let b = self.count_operand(b, bits)?;
        let left = op == Binary::Rol;
        let ty = CTy::Int {
            signed: false,
            bits,
        };
        if native(width) {
            return Ok(self.helper(
                if left { "rotl" } else { "rotr" },
                vec![a, b],
                ty,
                Class::Zero,
                width,
            ));
        }
        let size = self.literal_number(u64::from(width), false);
        Ok(self.helper(
            if left { "rotl_n" } else { "rotr_n" },
            vec![a, b, size],
            ty,
            Class::Zero,
            width,
        ))
    }

    /// A comparison, or its negation (`negate`); a constant compared with
    /// a value of an enumeration by its names ([`Self::by_name`]), with
    /// a character as one ([`Self::by_character`]), as `spelling` says.
    pub(super) fn compare(
        &mut self,
        op: Binary,
        a: Value,
        b: Value,
        negate: bool,
        spelling: Spelling,
    ) -> Result<Value, PrintError> {
        let (text, kind, order) =
            relation(op, negate).ok_or_else(|| error(self.node, "not a comparison"))?;
        let loads = a.loads || b.loads;
        let same_pointers = a.ty.is_pointer()
            && b.ty.is_pointer()
            && self.key(a.ty)? == self.key(b.ty)?
            && matches!(op, Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe);
        // `p == 0`: C's null pointer comparison, exactly the L2 one.
        let zero = |v: &Value| v.constant.is_some_and(|bits| bits.low_u128() == 0);
        let null = matches!(op, Binary::Eq | Binary::Ne)
            && ((a.ty.is_pointer() && zero(&b)) || (b.ty.is_pointer() && zero(&a)));
        let (a, b) = if same_pointers || null {
            (a, b)
        } else {
            let (a, b) = (self.int_view(a)?, self.int_view(b)?);
            let need = order.unwrap_or_else(|| equality_need(&a, &b));
            let (x, y, ty) = self.operands(a.clone(), b.clone(), need, true, false)?;
            if need == Class::Low && ty.1 != a.width {
                let need = if a.is(Class::Sign) && b.is(Class::Sign) {
                    Class::Sign
                } else {
                    Class::Zero
                };
                let (x, y, _) = self.operands(a, b, need, true, false)?;
                (x, y)
            } else {
                (x, y)
            }
        };
        // A constant goes on the right (`x > 0`, not `0 < x`), with the
        // operator mirrored: the same comparison, and a literal has no
        // effect for C's unsequenced operands to reorder.
        let (a, text, b) = if a.constant.is_some() && b.constant.is_none() {
            (b, mirrored(text), a)
        } else {
            (a, text, b)
        };
        let literal = b.constant.is_some() && a.constant.is_none();
        let b = match (spelling, a.promoted()) {
            (Spelling::Enumeration(ty), Some(other)) if literal => {
                self.by_name(b, ty, Context::Compared(other))
            }
            (Spelling::Character, Some(_)) if literal => self.by_character(b),
            (Spelling::Number | Spelling::Enumeration(_) | Spelling::Character, _) => b,
        };
        let (doc, depth) = self.binary_doc(a, text, kind, b);
        let mut value = Self::built(doc, kind, (true, 32), Class::Zero, 1, &[], depth);
        value.loads = loads;
        Ok(value)
    }
}

/// A shift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Shift {
    /// `<<`.
    Left,
    /// `>>` of an unsigned value.
    Logical,
    /// `>>` of a signed value.
    Arithmetic,
}

/// A comparison's C operator (negated: `negate`), its precedence, and what
/// its operands must be (`None`: equal values, of either class).
fn relation(op: Binary, negate: bool) -> Option<(&'static str, Op, Option<Class>)> {
    let (text, negated, order) = match op {
        Binary::Eq => ("==", "!=", None),
        Binary::Ne => ("!=", "==", None),
        Binary::ULt => ("<", ">=", Some(Class::Zero)),
        Binary::ULe => ("<=", ">", Some(Class::Zero)),
        Binary::SLt => ("<", ">=", Some(Class::Sign)),
        Binary::SLe => ("<=", ">", Some(Class::Sign)),
        Binary::Add
        | Binary::Sub
        | Binary::Mul
        | Binary::UDiv
        | Binary::URem
        | Binary::SDiv
        | Binary::SRem
        | Binary::And
        | Binary::Or
        | Binary::Xor
        | Binary::Shl
        | Binary::LShr
        | Binary::AShr
        | Binary::Rol
        | Binary::Ror => return None,
    };
    let kind = if order.is_none() {
        Op::Equality
    } else {
        Op::Relational
    };
    Some((if negate { negated } else { text }, kind, order))
}

/// The comparison operator `text` with its operands swapped.
fn mirrored(text: &'static str) -> &'static str {
    match text {
        "<" => ">",
        "<=" => ">=",
        ">" => "<",
        ">=" => "<=",
        other => other,
    }
}

/// What equal values must be for C's `==` to say so: nothing more if C
/// compares at exactly the width, else both zero- or both sign-extended
/// (whichever needs fewer casts).
fn equality_need(a: &Value, b: &Value) -> Class {
    if let (Some(ta), Some(tb)) = (a.promoted(), b.promoted()) {
        let ty = common(ta, tb);
        if ty.1 == a.width && !a.mixes(ty) && !b.mixes(ty) {
            return Class::Low;
        }
    }
    let cost = |v: &Value, need| usize::from(v.constant.is_none() && !v.is(need));
    if cost(a, Class::Sign) + cost(b, Class::Sign) < cost(a, Class::Zero) + cost(b, Class::Zero) {
        Class::Sign
    } else {
        Class::Zero
    }
}

impl Printer<'_> {
    fn flag(&mut self, op: Flag, a: Value, b: Value, c: Value) -> Result<Value, PrintError> {
        let width = a.width;
        let name = match op {
            Flag::AddCarry => "add_carry",
            Flag::AddOverflow => "add_overflow",
            Flag::SubBorrow => "sub_borrow",
            Flag::SubOverflow => "sub_overflow",
            Flag::NibbleCarry => "nibble_carry",
        };
        let bits = if native(width) {
            width
        } else if op == Flag::NibbleCarry && width <= 128 {
            if width <= 64 { 64 } else { 128 }
        } else {
            return Err(self.unsupported(
                self.node,
                "carries and overflows at widths C has no type for",
            ));
        };
        let a = self.int_view(a)?;
        let a = self.exact(a, false, bits);
        let b = self.int_view(b)?;
        let b = self.arg(b, false)?;
        let c = self.int_view(c)?;
        let c = self.arg(c, false)?;
        Ok(self.helper(name, vec![a, b, c], CTy::Bool, Class::Zero, 1))
    }

    fn mul_high(&mut self, signed: bool, a: Value, b: Value) -> Result<Value, PrintError> {
        let width = a.width;
        let a = self.int_view(a)?;
        let a = self.exact(a, signed, width);
        let b = self.int_view(b)?;
        let b = self.arg(b, signed)?;
        let name = if signed { "smulh" } else { "umulh" };
        Ok(self.helper(
            name,
            vec![a, b],
            CTy::Int {
                signed,
                bits: width,
            },
            Class::Low,
            width,
        ))
    }

    pub(super) fn extract(
        &mut self,
        value: Value,
        offset: u16,
        width: u16,
    ) -> Result<Value, PrintError> {
        if matches!(value.ty, CTy::Vector(_)) || value.width > 128 {
            if let Some(bits) = value.constant {
                let part = bits.extract(offset, width);
                return if width > 128 {
                    self.wide_constant(part)
                } else {
                    self.constant(part, Class::Zero, false)
                };
            }
            if let Some(part) = self.vector_extract(value.clone(), offset, width)? {
                return Ok(part);
            }
        }
        let value = self.int_view(value)?;
        if let Some(bits) = value.constant {
            return self.constant(bits.extract(offset, width), Class::Zero, false);
        }
        if offset == 0 {
            let class = match (value.class, value.range()) {
                (Class::Zero, Some(Range::Unsigned(bits))) if bits <= width => Class::Zero,
                (Class::Sign, Some(Range::Signed(bits))) if bits <= width => Class::Sign,
                _ => Class::Low,
            };
            let mut value = value.with_width(width);
            value.class = class;
            return Ok(value);
        }
        let source = value.width;
        let class = if offset + width == source && value.is(Class::Zero) {
            Class::Zero
        } else if offset + width == source && value.is(Class::Sign) {
            Class::Sign
        } else {
            Class::Low
        };
        let value = if value.promoted().is_some_and(|ty| ty.1 <= offset) {
            let signed = class == Class::Sign;
            self.cast(
                value,
                CTy::Int {
                    signed,
                    bits: container(source).unwrap_or(128).max(32),
                },
            )
        } else {
            value
        };
        let ty = value.promoted().unwrap_or((true, 32));
        let amount = self.literal_number(u64::from(offset), false);
        let loads = value.loads;
        let (doc, depth) = self.binary_doc(value, ">>", Op::Shift, amount);
        let mut out = Self::built(doc, Op::Shift, ty, class, width, &[], depth);
        out.loads = loads;
        Ok(out)
    }

    fn concat(&mut self, high: Value, low: Value, width: u16) -> Result<Value, PrintError> {
        if width > 128 {
            return self.vector_concat(high, low, width);
        }
        let high = self.int_view(high)?;
        let low = self.int_view(low)?;
        let low_width = low.width;
        let wide = container(width).unwrap_or(128).max(32);
        let class = if high.is(Class::Zero) {
            Class::Zero
        } else {
            Class::Low
        };
        let mut high = match high.constant {
            Some(bits) => self.literal(bits, Class::Zero, (false, wide), false),
            None if high.promoted().is_some_and(|ty| ty.1 < width) => self.cast(
                high,
                CTy::Int {
                    signed: false,
                    bits: wide,
                },
            ),
            None => high,
        };
        high.width = width;
        high.class = class;
        high.constant = None;
        let mut shifted = self.shift_by(Shift::Left, high, low_width, width)?;
        // `high` below 2^(width - low_width): shifted, below 2^width.
        if class == Class::Zero
            && shifted
                .promoted()
                .is_some_and(|(signed, bits)| bits - u16::from(signed) >= width)
        {
            shifted.class = Class::Zero;
        }
        let mut low = self.coerce(low, Class::Zero)?.with_width(width);
        low.class = Class::Zero;
        if low.constant.is_some_and(|bits| bits.is_zero()) {
            return Ok(shifted);
        }
        low.constant = low.constant.map(|bits| bits.zext(width));
        self.arith(Binary::Or, shifted, low, width)
    }

    fn extend(&mut self, value: Value, signed: bool, width: u16) -> Result<Value, PrintError> {
        if width > 128 {
            return self.vector_extend(value, signed, width);
        }
        let value = self.int_view(value)?;
        let need = if signed { Class::Sign } else { Class::Zero };
        if let Some(bits) = value.constant {
            let bits = if signed {
                bits.sext(width)
            } else {
                bits.zext(width)
            };
            return self.constant(bits, need, false);
        }
        let mut value = self.coerce(value, need)?.with_width(width);
        value.class = need;
        Ok(value)
    }

    /// `low` (of a value of `width` bits whose bits above `low`'s are
    /// unknown, [`Shape::Declared`]) at its declared width: extended as
    /// its C type says, as C converts it.
    fn at_declared_width(&mut self, low: Value, width: u16) -> Result<Value, PrintError> {
        let low = self.int_view(low)?;
        let signed = int_of(low.ty).is_some_and(|(signed, _)| signed);
        self.extend(low, signed, width)
    }

    fn select(
        &mut self,
        condition: Value,
        then: Value,
        otherwise: Value,
    ) -> Result<Value, PrintError> {
        let width = then.width;
        let condition = self.truthy(condition)?;
        let loads = condition.loads || then.loads || otherwise.loads;
        // A pointer (or function pointer) against a constant 0, C's null
        // pointer constant: the pointer's type.
        let null = |value: &Value| value.constant.is_some_and(|bits| bits.is_zero());
        let pointer = |ty: CTy| ty.is_pointer() || matches!(ty, CTy::Code(_));
        let (then, otherwise, ty, class) = if pointer(then.ty) && null(&otherwise) {
            let ty = then.ty;
            (then, otherwise, ty, Class::Low)
        } else if pointer(otherwise.ty) && null(&then) {
            let ty = otherwise.ty;
            (then, otherwise, ty, Class::Low)
        } else if then.ty.is_pointer()
            && otherwise.ty.is_pointer()
            && self.key(then.ty)? == self.key(otherwise.ty)?
        {
            let ty = then.ty;
            (then, otherwise, ty, Class::Low)
        } else if matches!((then.ty, otherwise.ty), (CTy::Float(a), CTy::Float(b)) if a == b) {
            // One of two floats of a format is that float: `maxsd` is
            // `a > b ? a : b`, not a choice between their bits.
            let ty = then.ty;
            (then, otherwise, ty, Class::Low)
        } else {
            let then = self.int_view(then)?;
            let otherwise = self.int_view(otherwise)?;
            let (then, otherwise, ty) = self.operands(then, otherwise, Class::Low, true, false)?;
            let class = if then.is_in(ty, Class::Zero) && otherwise.is_in(ty, Class::Zero) {
                Class::Zero
            } else if then.is_in(ty, Class::Sign) && otherwise.is_in(ty, Class::Sign) {
                Class::Sign
            } else {
                Class::Low
            };
            (
                then,
                otherwise,
                CTy::Int {
                    signed: ty.0,
                    bits: ty.1,
                },
                class,
            )
        };
        let depth = condition.depth.max(then.depth).max(otherwise.depth);
        let mut doc = self.operand(condition, Op::Conditional, false);
        doc.extend([Doc::Space, Doc::op("?", self.node), Doc::Line]);
        let then = self.operand(then, Op::Conditional, true);
        self.append(&mut doc, then);
        doc.extend([Doc::Space, Doc::op(":", self.node), Doc::Line]);
        let otherwise = self.operand(otherwise, Op::Conditional, true);
        self.append(&mut doc, otherwise);
        Ok(Value {
            doc: vec![Doc::Group(doc)],
            op: Op::Conditional,
            ty,
            class,
            width,
            constant: None,
            lvalue: false,
            loads,
            depth: depth.saturating_add(1),
            address_of: None,
            unsigned_literal: None,
        })
    }

    /// `value`'s bits as L2 type `ty`.
    fn cast_to(&mut self, value: Value, ty: TypeId) -> Result<Value, PrintError> {
        let target = self.cty(ty)?;
        match target {
            CTy::Int { .. } | CTy::Bool => self.int_view(value),
            CTy::Float(format) => {
                if value.ty == target {
                    return Ok(value);
                }
                let value = self.int_view(value)?;
                let name = match format {
                    Format::Single => "as_f32",
                    Format::Double => "as_f64",
                    Format::Half | Format::Extended => {
                        return Err(self.unsupported(self.node, "half and extended floats"));
                    }
                };
                let value = self.arg(value, false)?;
                let width = value.width;
                Ok(self.helper(name, vec![value], target, Class::Low, width))
            }
            CTy::Pointer(_) | CTy::Code(_) | CTy::Bytes => {
                if value.ty.is_pointer() || matches!(value.ty, CTy::Code(_)) {
                    if self.key(value.ty)? == self.key(target)? {
                        return Ok(value);
                    }
                    return Ok(self.cast(value, target));
                }
                self.int_to_pointer(value, target)
            }
            CTy::Other(_) => {
                if value.ty == target {
                    return Ok(value);
                }
                if !value.lvalue {
                    return Err(self.unsupported(self.node, "a value read as an aggregate"));
                }
                Ok(self.reinterpret(value, target))
            }
            CTy::Vector(vector) => self.vector_view(value, vector),
        }
    }

    /// Whether `id` is surely a pointer in C (to peel address
    /// arithmetic off it): a pointer-typed variable (or the thread pointer,
    /// a `void *` in C), cast or load, or an address.
    pub(super) fn pointerish(&self, id: ExprId) -> bool {
        let is_pointer = |ty| matches!(self.types.get(ty), Some(Type::Pointer(_)));
        match self.f.expr(id) {
            Some(Expr::AddressOf(_)) => true,
            Some(&Expr::Var(var)) => {
                self.thread_variable(var) || self.f.var(var).is_some_and(|v| is_pointer(v.ty))
            }
            Some(&(Expr::Cast { ty, .. } | Expr::Load { ty, .. })) => is_pointer(ty),
            Some(_) | None => false,
        }
    }

    /// Whether `a` and `b` are pointers of one type to bytes or to `void`
    /// (`p - q` is then their distance in bytes; GCC and Clang take
    /// `void`'s size as 1).
    fn byte_pointers(&mut self, a: &Value, b: &Value) -> Result<bool, PrintError> {
        Ok(a.ty.is_pointer()
            && b.ty.is_pointer()
            && (self.pointee(a.ty).and_then(|(_, size)| size) == Some(1) || self.is_void(a.ty))
            && self.key(a.ty)? == self.key(b.ty)?)
    }

    /// Sum `id` (`x + y`, neither a constant) as `pointer + index` where
    /// one operand is surely a pointer and the other an index scaled by the
    /// size of what it points to; such a sum plus a constant where that is
    /// a struct, with the constant as its offset (`&p[i].field`); else
    /// [`Shape::Plain`].
    fn index_shape(&self, id: ExprId, x: ExprId, y: ExprId) -> Shape {
        // `(p + k) + i·s` into an array field of the struct `p` points to,
        // where the index is proved in it (`&p->f[i]`).
        for (sum, term) in [(x, y), (y, x)] {
            if let Some(&Expr::Binary(Binary::Add, pointer, k)) = self.f.expr(sum)
                && let Some(&Expr::Const(k)) = self.f.expr(k)
                && let Some(target) = self.pointee_of(pointer)
            {
                let (index, scale) = self.scaled(term);
                let (negative, magnitude) = constant_value(k, Class::Sign);
                let magnitude = i128::try_from(magnitude).unwrap_or(0);
                let offset = if negative { -magnitude } else { magnitude };
                let bounds = self.bounds(Some(index));
                if self.array_field_at(target, scale, offset, bounds).is_some() {
                    return Shape::Index {
                        pointer,
                        index,
                        scale,
                        offset,
                    };
                }
            }
        }
        // `(p + i·s) + k` into an array of structs of `s` bytes, or into an
        // array field at `k` of the struct `p` points to, where the index is
        // proved in it (`&p->f[i]`, the constant outermost as L2's rules
        // order it).
        if let (Some(&Expr::Binary(Binary::Add, a, b)), Some(&Expr::Const(k))) =
            (self.f.expr(x), self.f.expr(y))
            && let Some((pointer, index, scale)) = self.indexed(x, a, b)
        {
            let (negative, magnitude) = constant_value(k, Class::Sign);
            let magnitude = i128::try_from(magnitude).unwrap_or(0);
            let offset = if negative { -magnitude } else { magnitude };
            if self.points_to_struct(pointer) {
                return Shape::Index {
                    pointer,
                    index,
                    scale,
                    offset,
                };
            }
        }
        if let (Some(&Expr::Binary(Binary::Add, a, b)), Some(&Expr::Const(k))) =
            (self.f.expr(x), self.f.expr(y))
        {
            for (pointer, term) in [(a, b), (b, a)] {
                let Some(target) = self.pointee_of(pointer) else {
                    continue;
                };
                let (index, scale) = self.scaled(term);
                let (negative, magnitude) = constant_value(k, Class::Sign);
                let magnitude = i128::try_from(magnitude).unwrap_or(0);
                let offset = if negative { -magnitude } else { magnitude };
                let bounds = self.bounds(Some(index));
                if self.array_field_at(target, scale, offset, bounds).is_some() {
                    return Shape::Index {
                        pointer,
                        index,
                        scale,
                        offset,
                    };
                }
            }
        }
        match self.indexed(id, x, y) {
            Some((pointer, index, scale)) => Shape::Index {
                pointer,
                index,
                scale,
                offset: 0,
            },
            None => Shape::Plain,
        }
    }

    /// Address `address` as [`Shape::Rows`]: `(p + a·s) + b·t` (either
    /// way round, plus a constant), `p` surely a pointer to `e` bytes and
    /// `s`, `t` and the constant whole numbers of `e`; else `None`.
    pub(super) fn rows_shape(&self, address: ExprId) -> Option<Shape> {
        let mut sum = address;
        let mut offset = 0;
        if let Some(&Expr::Binary(op @ (Binary::Add | Binary::Sub), x, y)) = self.f.expr(sum)
            && let Some(&Expr::Const(k)) = self.f.expr(y)
        {
            let (negative, magnitude) = constant_value(k, Class::Sign);
            let magnitude = i128::try_from(magnitude).ok()?;
            offset = if negative == (op == Binary::Add) {
                -magnitude
            } else {
                magnitude
            };
            sum = x;
        }
        if self.width(sum) != self.pointer_width() {
            return None;
        }
        let &Expr::Binary(Binary::Add, x, y) = self.f.expr(sum)? else {
            return None;
        };
        for (inner, outer) in [(x, y), (y, x)] {
            let Some(&Expr::Binary(Binary::Add, a, b)) = self.f.expr(inner) else {
                continue;
            };
            for (pointer, term) in [(a, b), (b, a)] {
                if !self.pointerish(pointer) || self.pointerish(term) || self.pointerish(outer) {
                    continue;
                }
                let Some(size) = self.pointee_size(pointer) else {
                    continue;
                };
                let (rows, by_rows) = self.scaled(term);
                let (columns, by_columns) = self.scaled(outer);
                let constant = |id| matches!(self.f.expr(id), Some(Expr::Const(_)));
                let whole = by_rows.is_multiple_of(size)
                    && by_columns.is_multiple_of(size)
                    && offset % i128::from(size) == 0;
                if whole && !constant(rows) && !constant(columns) {
                    return Some(Shape::Rows {
                        base: pointer,
                        rows: (rows, by_rows / size),
                        columns: (columns, by_columns / size),
                        scale: size,
                        offset,
                    });
                }
            }
        }
        None
    }

    /// The index `rows.0 * rows.1 + columns.0 * columns.1` of
    /// [`Shape::Rows`] (each value an index, each factor its elements).
    pub(super) fn rows_index(
        &mut self,
        rows: (Value, u64),
        columns: (Value, u64),
    ) -> Result<Value, PrintError> {
        let width = self.pointer_width();
        let mut terms = Vec::with_capacity(2);
        for (value, factor) in [rows, columns] {
            let value = self.int_view(value)?;
            let term = if factor == 1 {
                value
            } else {
                let factor = self.constant(Bits::from_u64(width, factor), Class::Zero, false)?;
                self.binary(Binary::Mul, value, factor, width)?
            };
            terms.push(term);
        }
        let [rows, columns] = take(terms)?;
        self.binary(Binary::Add, rows, columns, width)
    }

    /// Load `id` of [`Shape::Rows`] `shape`, its base's and indices' values
    /// `operands`: `base[rows + columns * k]`.
    fn rows_load(
        &mut self,
        id: ExprId,
        shape: Shape,
        operands: Vec<Value>,
    ) -> Result<Value, PrintError> {
        let Shape::Rows {
            base: base_id,
            rows: (_, by_rows),
            columns: (_, by_columns),
            scale,
            offset,
        } = shape
        else {
            return Err(error(self.node, "not rows"));
        };
        let Expr::Load { ty, .. } = self.node_expr(id)? else {
            return Err(error(self.node, "not a load"));
        };
        let [base, rows, columns] = take(operands)?;
        let index = self.rows_index((rows, by_rows), (columns, by_columns))?;
        let indexed = (Some((index, scale)), None);
        self.access_at(base_id, base, indexed, offset, ty, false)
    }

    /// Sum `id` (`x + y`, neither a constant) as `(pointer, index, scale)`
    /// where one operand is surely a pointer and the other an index scaled
    /// by the size of what it points to.
    fn indexed(&self, id: ExprId, x: ExprId, y: ExprId) -> Option<(ExprId, ExprId, u64)> {
        let constant = |id| matches!(self.f.expr(id), Some(Expr::Const(_)));
        if self.width(id) != self.pointer_width() || constant(x) || constant(y) {
            return None;
        }
        for (pointer, term) in [(x, y), (y, x)] {
            if self.pointerish(term) {
                continue;
            }
            let (index, scale) = self.scaled(term);
            if self.pointee_size(pointer) == Some(scale) {
                return Some((pointer, index, scale));
            }
        }
        None
    }

    /// The size in bytes of what expression `id` points to: a pointer-typed
    /// variable, cast or load whose target has a size.
    fn pointee_size(&self, id: ExprId) -> Option<u64> {
        let target = self.pointee_of(id)?;
        self.types
            .width(target)
            .filter(|width| *width > 0 && width % 8 == 0)
            .map(|width| width / 8)
    }

    /// Whether expression `id` (as [`Self::pointee_size`] reads it) points
    /// to a struct.
    fn points_to_struct(&self, id: ExprId) -> bool {
        self.pointee_of(id)
            .is_some_and(|target| matches!(self.types.get(target), Some(Type::Struct(_))))
    }

    /// What expression `id` points to: a pointer-typed variable, cast or
    /// load's target.
    fn pointee_of(&self, id: ExprId) -> Option<TypeId> {
        let ty = match *self.f.expr(id)? {
            Expr::Var(var) => self.f.var(var)?.ty,
            Expr::Cast { ty, .. } | Expr::Load { ty, .. } => ty,
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
            | Expr::Call(_)
            | Expr::Exception { .. }
            | Expr::Assign { .. } => return None,
        };
        let Some(&Type::Pointer(Some(target))) = self.types.get(ty) else {
            return None;
        };
        Some(target)
    }
}
