//! Vectors: values wider than 128 bits and L0's lane-wise operations, as
//! GCC's and Clang's vector extensions with `binbun_defs.h`'s types (`u8x16`,
//! `i32x8`, `u64x4`: each `aligned(1)`).
//!
//! A vector value is *exact* (its L2 width is its C type's) or a *mask*:
//! L0's lanes of one bit (what a lane-wise comparison gives), one per lane
//! of its C type, each held as its class says: [`Class::Sign`], 0 or all
//! ones (C's comparison of vectors), or [`Class::Zero`], 0 or 1. Values of
//! up to 128 bits stay integers; a lane-wise operation views its operands
//! as the vectors it needs (`(u8x16)x`), and a vector used as an integer
//! is cast back (`(unsigned __int128)v`; a mask: `mask_bits(m)`, its lanes'
//! bits packed).
//!
//! Every operation means what L0's does: `+ - * & | ^ ~` wrap lane by
//! lane on unsigned lanes, shifts by constants below the lane width use
//! C's (`binbun_defs.h`'s `shl_lanes` and the like otherwise), comparisons of
//! unsigned or signed lanes give masks, `__builtin_convertvector` extends
//! and truncates lanes, a lane is read by subscript (`((u32x8)v)[3]`) and
//! halves are built and taken as lanes of 128 bits (`(u128x2){low, high}`)
//! or by `__builtin_shufflevector`. Anything else (divisions, rotations,
//! counts, float lanes) is refused as "vector operations".

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, FloatOp, Format, LaneOp, Unary};

use super::chars::Spelling;
use super::types::{CTy, LaneKind, VectorTy};
use super::value::{Class, Op, Value, parenthesized};
use super::{PrintError, Printer, error};
use crate::document::{Doc, TokenKind};

/// The values of `N` operands.
fn take<const N: usize>(operands: Vec<Value>) -> Result<[Value; N], PrintError> {
    <[Value; N]>::try_from(operands).map_err(|_| error(None, "operand count"))
}

/// The vector type `value` holds a mask in (L0's lanes of one bit, one per
/// lane), if it is one.
pub(super) fn mask_of(value: &Value) -> Option<VectorTy> {
    let CTy::Vector(vector) = value.ty else {
        return None;
    };
    (value.width == vector.lanes).then_some(vector)
}

/// The exact vector type `value` has, if it is one.
fn exact_of(value: &Value) -> Option<VectorTy> {
    let CTy::Vector(vector) = value.ty else {
        return None;
    };
    (value.width == vector.width()).then_some(vector)
}

/// A vector of type `ty` standing for an L2 value of `width` bits (its
/// type's: exact; its lane count: a mask held as `class` says).
fn vector_value(
    doc: Vec<Doc>,
    op: Op,
    ty: VectorTy,
    width: u16,
    class: Class,
    loads: bool,
    depth: u8,
) -> Value {
    Value {
        doc,
        op,
        ty: CTy::Vector(ty),
        class,
        width,
        constant: None,
        lvalue: false,
        loads,
        depth,
        address_of: None,
    }
}

/// Whether `docs` hold a comma outside parentheses and brackets (in a
/// vector literal's braces): one the preprocessor would take as a macro
/// argument's end.
fn bare_comma(docs: &[Doc]) -> bool {
    fn walk(docs: &[Doc], depth: &mut usize) -> bool {
        for doc in docs {
            match doc {
                Doc::Token(token) => match token.text.as_str() {
                    "(" | "[" => *depth += 1,
                    ")" | "]" => *depth = depth.saturating_sub(1),
                    "," if *depth == 0 => return true,
                    _ => {}
                },
                Doc::Group(items) | Doc::Nest(items) | Doc::Outdent(items) => {
                    if walk(items, depth) {
                        return true;
                    }
                }
                Doc::Block { .. }
                | Doc::Space
                | Doc::Line
                | Doc::SoftLine
                | Doc::HardLine
                | Doc::BlankLine
                | Doc::AfterBlock => {}
            }
        }
        false
    }
    walk(docs, &mut 0)
}

impl Printer<'_> {
    /// The vector type of `lanes` lanes of `bits` bits, if `binbun_defs.h` has
    /// one.
    fn lane_type(&self, kind: LaneKind, bits: u16, lanes: u16) -> Result<VectorTy, PrintError> {
        VectorTy::new(kind, bits, lanes)
            .ok_or_else(|| self.unsupported(self.node, "vector operations"))
    }

    /// The type's name as a token.
    fn type_token(&self, ty: VectorTy) -> Doc {
        Doc::token(TokenKind::Type, ty.name(), self.node)
    }

    /// `value` as an argument of one of `binbun_defs.h`'s macros: in
    /// parentheses where a comma in it (a vector literal's) would end it.
    fn macro_argument(&self, mut value: Value) -> Value {
        if bare_comma(&value.doc) {
            value.doc = parenthesized(value.doc, self.node);
            value.op = Op::Postfix;
        }
        value
    }

    /// A call of `binbun_defs.h`'s vector macro `name` with `arguments`: a
    /// vector of type `ty` standing for `width` bits.
    fn vector_macro(
        &self,
        name: &str,
        arguments: Vec<Value>,
        ty: VectorTy,
        class: Class,
        width: u16,
    ) -> Value {
        let arguments = arguments
            .into_iter()
            .map(|argument| self.macro_argument(argument))
            .collect();
        let mut value = self.helper(name, arguments, CTy::Vector(ty), class, width);
        value.ty = CTy::Vector(ty);
        value
    }

    /// A vector value as an integer (of at most 128 bits): a literal
    /// printed again, an exact one cast to the unsigned integer of its
    /// width, a mask's lanes packed by `mask_bits` (bit `i` of lane `i`).
    pub(super) fn vector_int(&mut self, value: Value) -> Result<Value, PrintError> {
        if value.width > 128 {
            return Err(self.unsupported(self.node, "values over 128 bits"));
        }
        if let Some(bits) = value.constant {
            return self.constant(bits, Class::Zero, false);
        }
        if mask_of(&value).is_some() {
            let width = value.width;
            let bits = CTy::Int {
                signed: false,
                bits: 64,
            };
            let value = self.macro_argument(value);
            return Ok(self.helper("mask_bits", vec![value], bits, Class::Zero, width));
        }
        let width = value.width;
        let mut cast = self.cast(
            value,
            CTy::Int {
                signed: false,
                bits: width,
            },
        );
        cast.class = Class::Zero;
        Ok(cast)
    }

    /// `value` (of `ty`'s width) as exactly vector type `ty`: a literal of
    /// its lanes, a vector of another type cast (the same bits), an
    /// integer cast from the unsigned integer of its width (`(u8x16)x`),
    /// an aggregate in memory punned.
    pub(super) fn vector_view(&mut self, value: Value, ty: VectorTy) -> Result<Value, PrintError> {
        let width = ty.width();
        if value.width != width {
            return Err(error(self.node, "a vector viewed at another width"));
        }
        if let Some(bits) = value.constant {
            return self.vector_literal(bits, ty);
        }
        match value.ty {
            CTy::Vector(own) if own == ty && exact_of(&value).is_some() => Ok(value),
            CTy::Vector(_) if exact_of(&value).is_some() => Ok(self.cast(value, CTy::Vector(ty))),
            CTy::Other(_) => {
                let punned = self.pun(value)?;
                self.vector_view(punned, ty)
            }
            CTy::Int { .. }
            | CTy::Bool
            | CTy::Float(_)
            | CTy::Bytes
            | CTy::Pointer(_)
            | CTy::Code(_)
            | CTy::Vector(_) => {
                if width > 128 {
                    return Err(self.unsupported(self.node, "values over 128 bits"));
                }
                let int = self.int_view(value)?;
                let int = if int.is(Class::Zero) || int.promoted().is_some_and(|ty| ty.1 <= width) {
                    int
                } else {
                    self.coerce(int, Class::Zero)?
                };
                let int = self.exact(int, false, width);
                Ok(self.cast(int, CTy::Vector(ty)))
            }
        }
    }

    /// The constant `bits` as a literal of vector type `ty`: `(u8x16){1, 2,
    /// …}`, lane 0 first; all zeros `(u8x16){0}`; float lanes as their
    /// bits' (`(f32x4)(u32x4){…}`).
    fn vector_literal(&mut self, bits: Bits, ty: VectorTy) -> Result<Value, PrintError> {
        if ty.kind == LaneKind::Float {
            let int = self.vector_literal(bits, ty.of(LaneKind::Unsigned))?;
            let mut cast = self.cast(int, CTy::Vector(ty));
            cast.constant = Some(bits);
            return Ok(cast);
        }
        let node = self.node;
        let mut doc = parenthesized(vec![self.type_token(ty)], node);
        doc.push(Doc::punct("{", node));
        if bits.is_zero() {
            doc.push(Doc::number("0", node));
        } else {
            let mut items = Vec::new();
            for lane in 0..ty.lanes {
                if lane > 0 {
                    items.push(Doc::punct(",", node));
                    items.push(Doc::Line);
                }
                let value = bits.extract(lane * ty.bits, ty.bits);
                let literal = self.lane_literal(value, ty.kind)?;
                items.extend(literal.doc);
            }
            doc.push(Doc::Nest(items));
        }
        doc.push(Doc::punct("}", node));
        let mut value = vector_value(
            vec![Doc::Group(doc)],
            Op::Postfix,
            ty,
            ty.width(),
            Class::Low,
            false,
            1,
        );
        value.constant = Some(bits);
        Ok(value)
    }

    /// A lane's constant as a scalar literal its lane converts from without
    /// changing it: unsigned lanes' unsigned value, signed lanes' signed.
    fn lane_literal(&mut self, bits: Bits, kind: LaneKind) -> Result<Value, PrintError> {
        let class = if kind == LaneKind::Signed {
            Class::Sign
        } else {
            Class::Zero
        };
        self.constant(bits, class, true)
    }

    /// `value` as an operand of a lane-wise operator on vectors of type
    /// `ty`: a constant with every lane the same as that lane's scalar
    /// literal (C converts a scalar operand to every lane), else
    /// [`Self::vector_view`].
    fn lane_operand(&mut self, value: Value, ty: VectorTy) -> Result<Value, PrintError> {
        if let Some(bits) = value.constant
            && bits.width() == ty.width()
            && ty.kind != LaneKind::Float
        {
            let first = bits.extract(0, ty.bits);
            if (1..ty.lanes).all(|lane| bits.extract(lane * ty.bits, ty.bits) == first) {
                return self.lane_literal(first, ty.kind);
            }
        }
        self.vector_view(value, ty)
    }

    /// `value`, `lanes` lanes of one bit, as a mask of 0 or all ones in
    /// lanes of `bits` bits: a mask held otherwise converted, a constant's
    /// lanes, an integer's bits spread by `lanes_from_bits`.
    fn mask_view(&mut self, value: Value, lanes: u16, bits: u16) -> Result<Value, PrintError> {
        let target = self.lane_type(LaneKind::Signed, bits, lanes)?;
        if let Some(constant) = value.constant {
            let spread = (0..lanes)
                .rev()
                .map(|lane| {
                    if constant.extract(lane, 1).is_zero() {
                        Bits::zero(bits)
                    } else {
                        Bits::ones(bits)
                    }
                })
                .reduce(|high, low| high.concat(&low))
                .ok_or_else(|| error(self.node, "a mask of no lanes"))?;
            let mut literal = self.vector_literal(spread, target)?;
            literal.width = lanes;
            literal.class = Class::Sign;
            literal.constant = None;
            return Ok(literal);
        }
        if let Some(own) = mask_of(&value) {
            let value = if value.class == Class::Sign {
                value
            } else {
                // 0 or 1: negated, 0 or all ones.
                self.lane_prefix("-", value, own, Class::Sign)
            };
            if own.bits == bits {
                return Ok(value);
            }
            let signed = own.of(LaneKind::Signed);
            let value = if own == signed {
                value
            } else {
                let mut cast = self.cast(value, CTy::Vector(signed));
                cast.width = lanes;
                cast
            };
            let mut converted = self.convert(value, target);
            converted.width = lanes;
            converted.class = Class::Sign;
            return Ok(converted);
        }
        let int = self.int_view(value)?;
        let int = self.arg(int, false)?;
        let int = self.macro_argument(int);
        let depth = int.depth;
        let loads = int.loads;
        let name = Doc::macro_name("lanes_from_bits", self.node);
        let (doc, depth) = self.call_doc(
            vec![name],
            vec![vec![self.type_token(target)], int.doc],
            depth,
        );
        Ok(vector_value(
            doc,
            Op::Postfix,
            target,
            lanes,
            Class::Sign,
            loads,
            depth,
        ))
    }

    /// `op value` lane by lane, of type `ty` and `class`.
    fn lane_prefix(&self, op: &str, value: Value, ty: VectorTy, class: Class) -> Value {
        let (width, depth, loads) = (value.width, value.depth, value.loads);
        let mut doc = vec![Doc::op(op, self.node)];
        let operand = self.operand(value, Op::Unary, false);
        self.append(&mut doc, operand);
        vector_value(doc, Op::Unary, ty, width, class, loads, depth)
    }

    /// `a op b` lane by lane: a vector of type `ty`, standing for `width`
    /// bits held as `class` says.
    #[expect(clippy::too_many_arguments, reason = "an operation's parts")]
    fn lane_infix(
        &self,
        a: Value,
        text: &str,
        kind: Op,
        b: Value,
        ty: VectorTy,
        width: u16,
        class: Class,
    ) -> Value {
        let loads = a.loads || b.loads;
        let (doc, depth) = self.binary_doc(a, text, kind, b);
        vector_value(doc, kind, ty, width, class, loads, depth)
    }

    /// `__builtin_convertvector(value, ty)`: each lane converted by value
    /// (extended as it is signed, or truncated).
    fn convert(&mut self, value: Value, ty: VectorTy) -> Value {
        let (depth, loads) = (value.depth, value.loads);
        let name = Doc::token(TokenKind::Function, "__builtin_convertvector", self.node);
        let (doc, depth) = self.call_doc(
            vec![name],
            vec![value.doc, vec![self.type_token(ty)]],
            depth,
        );
        vector_value(doc, Op::Postfix, ty, ty.width(), Class::Low, loads, depth)
    }

    /// `__builtin_shufflevector(a, b, indices…)`: the lanes of `a` then `b`
    /// (both of one type) at `indices`, a vector of type `ty`.
    fn shuffle(&mut self, a: Value, b: Value, indices: &[u16], ty: VectorTy) -> Value {
        let depth = a.depth.max(b.depth);
        let loads = a.loads || b.loads;
        let name = Doc::token(TokenKind::Function, "__builtin_shufflevector", self.node);
        let mut arguments = vec![a.doc, b.doc];
        arguments.extend(
            indices
                .iter()
                .map(|&index| vec![Doc::number(format!("{index}"), self.node)]),
        );
        let (doc, depth) = self.call_doc(vec![name], arguments, depth);
        vector_value(doc, Op::Postfix, ty, ty.width(), Class::Low, loads, depth)
    }

    /// `value[index]`: one lane of an exact vector, of its lane type.
    fn lane_at(&self, value: Value, index: u16) -> Value {
        let Some(ty) = exact_of(&value) else {
            return value;
        };
        let (depth, loads) = (value.depth, value.loads);
        let mut doc = self.operand(value, Op::Postfix, false);
        doc.push(Doc::punct("[", self.node));
        doc.push(Doc::number(format!("{index}"), self.node));
        doc.push(Doc::punct("]", self.node));
        Value {
            doc,
            op: Op::Postfix,
            ty: CTy::Int {
                signed: ty.kind == LaneKind::Signed,
                bits: ty.bits,
            },
            class: if ty.kind == LaneKind::Signed {
                Class::Sign
            } else {
                Class::Zero
            },
            width: ty.bits,
            constant: None,
            lvalue: false,
            loads,
            depth,
            address_of: None,
        }
    }

    /// `Lanes { lanes, op }` of more than one lane, of `width` bits, its
    /// operands' values given.
    pub(super) fn vector_lanes(
        &mut self,
        lanes: u16,
        op: LaneOp,
        operands: Vec<Value>,
        width: u16,
    ) -> Result<Value, PrintError> {
        match op {
            LaneOp::Unary(op) => {
                let [a] = take(operands)?;
                self.lanes_unary(lanes, op, a)
            }
            LaneOp::Binary(op) => {
                let [a, b] = take(operands)?;
                self.lanes_binary(lanes, op, a, b)
            }
            LaneOp::Extract { offset, width } => {
                let [a] = take(operands)?;
                self.lanes_extract(lanes, a, offset, width)
            }
            LaneOp::Extend { signed, width } => {
                let [a] = take(operands)?;
                self.lanes_extend(lanes, a, signed, width)
            }
            LaneOp::Select => {
                let [condition, then, otherwise] = take(operands)?;
                self.lanes_select(lanes, condition, then, otherwise, width)
            }
        }
    }

    fn lanes_unary(&mut self, lanes: u16, op: Unary, a: Value) -> Result<Value, PrintError> {
        let bits = a.width / lanes;
        if bits == 1 {
            return match op {
                // -x is x modulo 2.
                Unary::Neg => Ok(a),
                Unary::Not => match mask_of(&a) {
                    Some(ty) if a.class == Class::Sign => {
                        Ok(self.lane_prefix("~", a, ty, Class::Sign))
                    }
                    _ => {
                        let a = self.int_view(a)?;
                        self.unary(Unary::Not, a, lanes)
                    }
                },
                Unary::Popcount
                | Unary::LeadingZeros
                | Unary::TrailingZeros
                | Unary::ByteSwap
                | Unary::EvenParity8 => Err(self.unsupported(self.node, "vector operations")),
            };
        }
        let ty = self.lane_type(LaneKind::Unsigned, bits, lanes)?;
        let text = match op {
            Unary::Not => "~",
            Unary::Neg => "-",
            Unary::Popcount
            | Unary::LeadingZeros
            | Unary::TrailingZeros
            | Unary::ByteSwap
            | Unary::EvenParity8 => return Err(self.unsupported(self.node, "vector operations")),
        };
        let a = self.vector_view(a, ty)?;
        Ok(self.lane_prefix(text, a, ty, Class::Low))
    }

    fn lanes_binary(
        &mut self,
        lanes: u16,
        op: Binary,
        a: Value,
        b: Value,
    ) -> Result<Value, PrintError> {
        let bits = a.width / lanes;
        if bits == 1 {
            return self.mask_binary(lanes, op, a, b);
        }
        let (text, kind, lane_kind) = match op {
            Binary::Add => ("+", Op::Additive, LaneKind::Unsigned),
            Binary::Sub => ("-", Op::Additive, LaneKind::Unsigned),
            Binary::Mul => ("*", Op::Multiplicative, LaneKind::Unsigned),
            Binary::And => ("&", Op::BitAnd, LaneKind::Unsigned),
            Binary::Or => ("|", Op::BitOr, LaneKind::Unsigned),
            Binary::Xor => ("^", Op::BitXor, LaneKind::Unsigned),
            Binary::Shl => ("<<", Op::Shift, LaneKind::Unsigned),
            Binary::LShr => (">>", Op::Shift, LaneKind::Unsigned),
            Binary::AShr => (">>", Op::Shift, LaneKind::Signed),
            Binary::Eq => ("==", Op::Equality, LaneKind::Unsigned),
            Binary::Ne => ("!=", Op::Equality, LaneKind::Unsigned),
            Binary::ULt => ("<", Op::Relational, LaneKind::Unsigned),
            Binary::ULe => ("<=", Op::Relational, LaneKind::Unsigned),
            Binary::SLt => ("<", Op::Relational, LaneKind::Signed),
            Binary::SLe => ("<=", Op::Relational, LaneKind::Signed),
            Binary::UDiv
            | Binary::URem
            | Binary::SDiv
            | Binary::SRem
            | Binary::Rol
            | Binary::Ror => return Err(self.unsupported(self.node, "vector operations")),
        };
        let ty = self.lane_type(lane_kind, bits, lanes)?;
        if kind == Op::Shift {
            return self.lanes_shift(op, text, a, b, ty);
        }
        let a = self.vector_view(a, ty)?;
        let b = self.lane_operand(b, ty)?;
        if matches!(kind, Op::Equality | Op::Relational) {
            let mask = ty.of(LaneKind::Signed);
            return Ok(self.lane_infix(a, text, kind, b, mask, lanes, Class::Sign));
        }
        Ok(self.lane_infix(a, text, kind, b, ty, ty.width(), Class::Low))
    }

    /// A lane-wise shift of `a` by the lanes of `b`, on lanes of `ty`: by
    /// a literal where every count is below the lane width (one, or a
    /// vector of them), else `binbun_defs.h`'s helper.
    fn lanes_shift(
        &mut self,
        op: Binary,
        text: &str,
        a: Value,
        b: Value,
        ty: VectorTy,
    ) -> Result<Value, PrintError> {
        let a = self.vector_view(a, ty)?;
        let counts = b.constant.filter(|bits| {
            (0..ty.lanes)
                .all(|lane| bits.extract(lane * ty.bits, ty.bits).low_u128() < u128::from(ty.bits))
        });
        if let Some(counts) = counts {
            let first = counts.extract(0, ty.bits);
            let b = if (1..ty.lanes).all(|lane| counts.extract(lane * ty.bits, ty.bits) == first) {
                self.literal_number(u64::try_from(first.low_u128()).unwrap_or(0), false)
            } else {
                self.vector_literal(counts, ty)?
            };
            return Ok(self.lane_infix(a, text, Op::Shift, b, ty, ty.width(), Class::Low));
        }
        let b = self.vector_view(b, ty)?;
        let name = match op {
            Binary::Shl => "shl_lanes",
            Binary::AShr => "ashr_lanes",
            Binary::LShr
            | Binary::Add
            | Binary::Sub
            | Binary::Mul
            | Binary::UDiv
            | Binary::URem
            | Binary::SDiv
            | Binary::SRem
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
            | Binary::SLe => "lshr_lanes",
        };
        Ok(self.vector_macro(name, vec![a, b], ty, Class::Low, ty.width()))
    }

    /// A lane-wise operation on lanes of one bit: on two masks held alike
    /// (0 or all ones) lane by lane, else on the packed integers.
    fn mask_binary(
        &mut self,
        lanes: u16,
        op: Binary,
        a: Value,
        b: Value,
    ) -> Result<Value, PrintError> {
        // Modulo 2 a sum and a difference are an exclusive or, a product
        // an and; on the packed integers, equality is the complement of
        // the exclusive or.
        let (text, kind, packed) = match op {
            Binary::And | Binary::Mul => ("&", Op::BitAnd, Binary::And),
            Binary::Or => ("|", Op::BitOr, Binary::Or),
            Binary::Xor | Binary::Add | Binary::Sub => ("^", Op::BitXor, Binary::Xor),
            Binary::Eq => ("==", Op::Equality, Binary::Xor),
            Binary::Ne => ("!=", Op::Equality, Binary::Xor),
            Binary::UDiv
            | Binary::URem
            | Binary::SDiv
            | Binary::SRem
            | Binary::Shl
            | Binary::LShr
            | Binary::AShr
            | Binary::Rol
            | Binary::Ror
            | Binary::ULt
            | Binary::ULe
            | Binary::SLt
            | Binary::SLe => return Err(self.unsupported(self.node, "vector operations")),
        };
        if let (Some(ty), Some(other)) = (mask_of(&a), mask_of(&b))
            && ty.bits == other.bits
            && a.class == Class::Sign
            && b.class == Class::Sign
        {
            let b = if other == ty {
                b
            } else {
                let mut cast = self.cast(b, CTy::Vector(ty));
                cast.width = lanes;
                cast
            };
            let result = ty.of(LaneKind::Signed);
            let result = if kind == Op::Equality { result } else { ty };
            return Ok(self.lane_infix(a, text, kind, b, result, lanes, Class::Sign));
        }
        let a = self.int_view(a)?;
        let b = self.int_view(b)?;
        let value = self.binary(packed, a, b, lanes)?;
        if op == Binary::Eq {
            self.unary(Unary::Not, value, lanes)
        } else {
            Ok(value)
        }
    }

    fn lanes_extract(
        &mut self,
        lanes: u16,
        a: Value,
        offset: u16,
        width: u16,
    ) -> Result<Value, PrintError> {
        let bits = a.width / lanes;
        if width == bits {
            return Ok(a);
        }
        let ty = self.lane_type(LaneKind::Unsigned, bits, lanes)?;
        if width == 1 {
            if offset + 1 == bits {
                // The sign of each lane: a comparison's mask.
                let signed = ty.of(LaneKind::Signed);
                let a = self.vector_view(a, signed)?;
                let zero = self.literal_number(0, false);
                return Ok(self.lane_infix(
                    a,
                    "<",
                    Op::Relational,
                    zero,
                    signed,
                    lanes,
                    Class::Sign,
                ));
            }
            let a = self.vector_view(a, ty)?;
            let shifted = if offset == 0 {
                a
            } else {
                let count = self.literal_number(u64::from(offset), false);
                self.lane_infix(a, ">>", Op::Shift, count, ty, ty.width(), Class::Low)
            };
            let one = self.literal_number(1, false);
            return Ok(self.lane_infix(shifted, "&", Op::BitAnd, one, ty, lanes, Class::Zero));
        }
        let target = self.lane_type(LaneKind::Unsigned, width, lanes)?;
        if width > bits || offset + width > bits {
            return Err(self.unsupported(self.node, "vector operations"));
        }
        let a = self.vector_view(a, ty)?;
        let shifted = if offset == 0 {
            a
        } else {
            let count = self.literal_number(u64::from(offset), false);
            self.lane_infix(a, ">>", Op::Shift, count, ty, ty.width(), Class::Low)
        };
        Ok(self.convert(shifted, target))
    }

    fn lanes_extend(
        &mut self,
        lanes: u16,
        a: Value,
        signed: bool,
        width: u16,
    ) -> Result<Value, PrintError> {
        let bits = a.width / lanes;
        if bits == 1 {
            let target = self.lane_type(LaneKind::Signed, width, lanes)?;
            if !signed {
                if let Some(own) = mask_of(&a)
                    && a.class == Class::Zero
                {
                    let unsigned = target.of(LaneKind::Unsigned);
                    if own.bits == width {
                        let mut exact = a;
                        exact.width = own.width();
                        exact.class = Class::Low;
                        return Ok(exact);
                    }
                    let mut a = a;
                    a.width = own.width();
                    return Ok(self.convert(a, unsigned));
                }
                let mask = self.mask_view(a, lanes, width)?;
                let one = self.literal_number(1, false);
                let ty = mask_of(&mask).unwrap_or(target);
                return Ok(self.lane_infix(mask, "&", Op::BitAnd, one, ty, ty.width(), Class::Low));
            }
            let mut mask = self.mask_view(a, lanes, width)?;
            mask.width = width * lanes;
            mask.class = Class::Low;
            return Ok(mask);
        }
        let kind = if signed {
            LaneKind::Signed
        } else {
            LaneKind::Unsigned
        };
        let from = self.lane_type(kind, bits, lanes)?;
        let to = self.lane_type(kind, width, lanes)?;
        let a = self.vector_view(a, from)?;
        Ok(self.convert(a, to))
    }

    fn lanes_select(
        &mut self,
        lanes: u16,
        condition: Value,
        then: Value,
        otherwise: Value,
        width: u16,
    ) -> Result<Value, PrintError> {
        let bits = width / lanes;
        if bits == 1 {
            return Err(self.unsupported(self.node, "vector operations"));
        }
        let ty = self.lane_type(LaneKind::Unsigned, bits, lanes)?;
        let mask = self.mask_view(condition, lanes, bits)?;
        let then = self.vector_view(then, ty)?;
        let otherwise = self.vector_view(otherwise, ty)?;
        Ok(self.vector_macro("blend", vec![mask, then, otherwise], ty, Class::Low, width))
    }

    /// An IEEE operation (rounding to nearest, its value) on more than one
    /// lane of `format`: arithmetic on float lanes (`a + b`), conversions
    /// lane by lane (`__builtin_convertvector`); `operands` without the
    /// rounding.
    pub(super) fn vector_float(
        &mut self,
        op: FloatOp,
        format: Format,
        lanes: u16,
        operands: Vec<Value>,
        width: u16,
    ) -> Result<Value, PrintError> {
        let ty = self.lane_type(LaneKind::Float, format.width(), lanes)?;
        let (text, kind) = match op {
            FloatOp::Add => ("+", Op::Additive),
            FloatOp::Sub => ("-", Op::Additive),
            FloatOp::Mul => ("*", Op::Multiplicative),
            FloatOp::Div => ("/", Op::Multiplicative),
            FloatOp::FromInt { signed } => {
                let [a] = take(operands)?;
                let kind = if signed {
                    LaneKind::Signed
                } else {
                    LaneKind::Unsigned
                };
                let from = self.lane_type(kind, a.width / lanes, lanes)?;
                let a = self.vector_view(a, from)?;
                return Ok(self.convert(a, ty));
            }
            FloatOp::Convert(target) => {
                let [a] = take(operands)?;
                let to = self.lane_type(LaneKind::Float, target.width(), lanes)?;
                let a = self.vector_view(a, ty)?;
                return Ok(self.convert(a, to));
            }
            FloatOp::Sqrt
            | FloatOp::MulAdd
            | FloatOp::RoundToIntegral
            | FloatOp::Compare { .. }
            | FloatOp::ToInt { .. } => {
                return Err(self.unsupported(self.node, "vector operations"));
            }
        };
        let [a, b] = take(operands)?;
        let a = self.vector_view(a, ty)?;
        let b = self.vector_view(b, ty)?;
        Ok(self.lane_infix(a, text, kind, b, ty, width, Class::Low))
    }

    /// A constant of more than 128 bits: a literal of 64-bit lanes.
    pub(super) fn wide_constant(&mut self, bits: Bits) -> Result<Value, PrintError> {
        let ty = VectorTy::bits(bits.width())
            .ok_or_else(|| self.unsupported(self.node, "constants over 128 bits"))?;
        self.vector_literal(bits, ty)
    }

    /// Whether `value` is to be printed as a vector: wider than 128 bits,
    /// or an exact vector.
    pub(super) fn is_vector(value: &Value) -> bool {
        value.width > 128 || exact_of(value).is_some()
    }

    /// The vector type to compute `values` of `width` bits in: the first
    /// one's that is exact, else 64-bit lanes.
    fn common_vector(&self, values: &[&Value], width: u16) -> Result<VectorTy, PrintError> {
        values
            .iter()
            .find_map(|value| exact_of(value))
            .or_else(|| VectorTy::bits(width))
            .ok_or_else(|| self.unsupported(self.node, "values over 128 bits"))
    }

    /// `~a` of a vector (more than 128 bits, or exact).
    pub(super) fn vector_unary(&mut self, op: Unary, a: Value) -> Result<Value, PrintError> {
        if op != Unary::Not {
            return Err(self.unsupported(self.node, "values over 128 bits"));
        }
        let width = a.width;
        let ty = self.common_vector(&[&a], width)?;
        let a = self.vector_view(a, ty)?;
        Ok(self.lane_prefix("~", a, ty, Class::Low))
    }

    /// `a op b` of vectors (more than 128 bits, or exact): bitwise lane by
    /// lane; equality as no lane differing (`mask_bits(a != b) == 0`).
    pub(super) fn vector_binary(
        &mut self,
        op: Binary,
        a: Value,
        b: Value,
    ) -> Result<Value, PrintError> {
        let width = a.width;
        let ty = self.common_vector(&[&a, &b], width)?;
        let (text, kind) = match op {
            Binary::And => ("&", Op::BitAnd),
            Binary::Or => ("|", Op::BitOr),
            Binary::Xor => ("^", Op::BitXor),
            Binary::Eq | Binary::Ne => {
                let a = self.vector_view(a, ty)?;
                let b = self.lane_operand(b, ty)?;
                let mask = ty.of(LaneKind::Signed);
                let differ = self.lane_infix(a, "!=", Op::Equality, b, mask, ty.lanes, Class::Sign);
                let differ = self.vector_int(differ)?;
                let zero = self.constant(Bits::zero(ty.lanes), Class::Zero, false)?;
                return self.compare(op, differ, zero, false, Spelling::Number);
            }
            Binary::Shl | Binary::LShr => return self.vector_shift(op == Binary::Shl, a, &b),
            Binary::Add
            | Binary::Sub
            | Binary::Mul
            | Binary::UDiv
            | Binary::URem
            | Binary::SDiv
            | Binary::SRem
            | Binary::AShr
            | Binary::Rol
            | Binary::Ror
            | Binary::ULt
            | Binary::ULe
            | Binary::SLt
            | Binary::SLe => return Err(self.unsupported(self.node, "values over 128 bits")),
        };
        let a = self.vector_view(a, ty)?;
        let b = self.lane_operand(b, ty)?;
        Ok(self.lane_infix(a, text, kind, b, ty, width, Class::Low))
    }

    /// A vector shifted as a whole (`left`, else logically right) by a
    /// constant number `b` of whole bytes: its lanes moved, zeros coming
    /// in (`__builtin_shufflevector(v, (u64x4){0}, 4, 0, 1, 2)`), in the
    /// widest lanes the count is a multiple of.
    fn vector_shift(&mut self, left: bool, a: Value, b: &Value) -> Result<Value, PrintError> {
        let width = a.width;
        let count = b
            .constant
            .map(|bits| bits.low_u128())
            .filter(|&count| count < u128::from(width) && count.is_multiple_of(8))
            .ok_or_else(|| self.unsupported(self.node, "values over 128 bits"))?;
        #[expect(clippy::cast_possible_truncation, reason = "below the width")]
        let count = count as u16;
        if count == 0 {
            return Ok(a);
        }
        let lane = [64, 32, 16, 8]
            .into_iter()
            .find(|&lane| count.is_multiple_of(lane))
            .unwrap_or(8);
        let ty = self.lane_type(LaneKind::Unsigned, lane, width / lane)?;
        let a = self.vector_view(a, ty)?;
        let zero = self.vector_literal(Bits::zero(width), ty)?;
        let moved = count / lane;
        // Lane `lanes` is the zero vector's first.
        let indices: Vec<u16> = (0..ty.lanes)
            .map(|lane| {
                if left {
                    lane.checked_sub(moved).unwrap_or(ty.lanes)
                } else {
                    Some(lane + moved)
                        .filter(|&from| from < ty.lanes)
                        .unwrap_or(ty.lanes)
                }
            })
            .collect();
        Ok(self.shuffle(a, zero, &indices, ty))
    }

    /// `condition ? then : otherwise` of vectors of more than 128 bits.
    pub(super) fn vector_select(
        &mut self,
        condition: Value,
        then: Value,
        otherwise: Value,
    ) -> Result<Value, PrintError> {
        let width = then.width;
        let ty = self.common_vector(&[&then, &otherwise], width)?;
        let condition = self.truthy(condition)?;
        let then = self.vector_view(then, ty)?;
        let otherwise = self.vector_view(otherwise, ty)?;
        let loads = condition.loads || then.loads || otherwise.loads;
        let depth = condition.depth.max(then.depth).max(otherwise.depth);
        let mut doc = self.operand(condition, Op::Conditional, false);
        doc.extend([Doc::Space, Doc::op("?", self.node), Doc::Line]);
        let then = self.operand(then, Op::Conditional, true);
        self.append(&mut doc, then);
        doc.extend([Doc::Space, Doc::op(":", self.node), Doc::Line]);
        let otherwise = self.operand(otherwise, Op::Conditional, true);
        self.append(&mut doc, otherwise);
        Ok(vector_value(
            vec![Doc::Group(doc)],
            Op::Conditional,
            ty,
            width,
            Class::Low,
            loads,
            depth.saturating_add(1),
        ))
    }

    /// `width` bits of the vector `value` from bit `offset`, where that is
    /// a lane of a vector of its width (`((u32x8)v)[3]`), a part of one
    /// (the lane holding it, then the integer's bits), or a half of a
    /// 512-bit one (`__builtin_shufflevector`); `None` for a value of up to
    /// 128 bits where no lane is (it is then an integer's bits).
    pub(super) fn vector_extract(
        &mut self,
        value: Value,
        offset: u16,
        width: u16,
    ) -> Result<Option<Value>, PrintError> {
        let source = value.width;
        if mask_of(&value).is_some() {
            return Ok(None);
        }
        if width > 128 {
            let lanes = width / 64;
            let (Some(from), Some(to)) = (VectorTy::bits(source), VectorTy::bits(width)) else {
                return Err(self.unsupported(self.node, "values over 128 bits"));
            };
            if !offset.is_multiple_of(64) || offset + width > source {
                return Err(self.unsupported(self.node, "values over 128 bits"));
            }
            let v = self.vector_view(value, from)?;
            let first = offset / 64;
            let indices: Vec<u16> = (first..first + lanes).collect();
            // The second operand's lanes are not taken.
            let unused = self.vector_literal(Bits::zero(source), from)?;
            return Ok(Some(self.shuffle(v, unused, &indices, to)));
        }
        if let Some(lane) = lane_of(source, offset, width) {
            let ty = self.lane_type(LaneKind::Unsigned, width, source / width)?;
            let v = self.vector_view(value, ty)?;
            return Ok(Some(self.lane_at(v, lane)));
        }
        if source <= 128 {
            return Ok(None);
        }
        // Within one 128-bit lane: that lane, then its bits.
        let piece = offset / 128;
        if offset % 128 + width > 128 {
            return Err(self.unsupported(self.node, "values over 128 bits"));
        }
        let ty = self.lane_type(LaneKind::Unsigned, 128, source / 128)?;
        let v = self.vector_view(value, ty)?;
        let lane = self.lane_at(v, piece);
        Ok(Some(self.extract(lane, offset % 128, width)?))
    }

    /// `high` above `low`, more than 128 bits: two 128-bit halves as the
    /// lanes of `u128x2` (`(u128x2){low, high}`), two 256-bit halves
    /// joined by `__builtin_shufflevector`.
    pub(super) fn vector_concat(
        &mut self,
        high: Value,
        low: Value,
        width: u16,
    ) -> Result<Value, PrintError> {
        let half = width / 2;
        if high.width != half || low.width != half {
            return Err(self.unsupported(self.node, "values over 128 bits"));
        }
        if half <= 128 {
            let ty = self.lane_type(LaneKind::Unsigned, half, 2)?;
            return self.lanes_literal(&[low, high], ty);
        }
        let halves = VectorTy::bits(half)
            .ok_or_else(|| self.unsupported(self.node, "values over 128 bits"))?;
        let to = VectorTy::bits(width)
            .ok_or_else(|| self.unsupported(self.node, "values over 128 bits"))?;
        let low = self.vector_view(low, halves)?;
        let high = self.vector_view(high, halves)?;
        let indices: Vec<u16> = (0..to.lanes).collect();
        Ok(self.shuffle(low, high, &indices, to))
    }

    /// Where concatenation `id` (of 256 or 512 bits) is a value of a lane's
    /// width (8 to 128 bits) under the rest of a vector of its width: that
    /// vector's bits above the value's (`concat(extract(v, 128, 384), x)`,
    /// an SSE instruction writing a `zmm` register's low 128 bits), or a
    /// named unknown value of a width no `binbun_defs.h` helper gives
    /// (`concat(undefined:384, x)`, [`Printer::unknown_without_helper`]),
    /// then named at the concatenation's width: the vector (`None` for the
    /// unknown value), the part above and the value
    /// ([`Shape::Under`](super::expr::Shape::Under)).
    pub(super) fn under(&self, id: ExprId) -> Option<(Option<ExprId>, ExprId, ExprId)> {
        let &Expr::Concat { high, low } = self.f.expr(id)? else {
            return None;
        };
        let width = self.width(id);
        let below = self.width(low);
        if !matches!(width, 256 | 512) || !matches!(below, 8 | 16 | 32 | 64 | 128) {
            return None;
        }
        if let Expr::Extract { value, offset, .. } = *self.f.expr(high)?
            && offset == below
            && self.width(value) == width
        {
            return Some((Some(value), high, low));
        }
        self.unknown_without_helper(high)
            .then_some((None, high, low))
    }

    /// `whole` (256 or 512 bits) with its low lanes `low` (8 to 128 bits):
    /// the vector of lanes of `low`'s width, `low` then `whole`'s other
    /// lanes (`(u128x4){x, ((u128x4)_unknown)[1], ((u128x4)_unknown)[2],
    /// ((u128x4)_unknown)[3]}`, [`Shape::Under`](super::expr::Shape::Under)).
    pub(super) fn vector_under(&mut self, whole: Value, low: Value) -> Result<Value, PrintError> {
        let ty = self.lane_type(LaneKind::Unsigned, low.width, whole.width / low.width)?;
        let whole = self.vector_view(whole, ty)?;
        let mut parts = vec![low];
        for lane in 1..ty.lanes {
            parts.push(self.lane_at(whole.clone(), lane));
        }
        self.lanes_literal(&parts, ty)
    }

    /// `value` zero-extended to `width` bits (more than 128): its 128 bits
    /// as the low lane of a `u128x2` or `u128x4` (`(u128x2){x, 0}`), a
    /// 256-bit value as the low half of 512.
    pub(super) fn vector_extend(
        &mut self,
        value: Value,
        signed: bool,
        width: u16,
    ) -> Result<Value, PrintError> {
        if signed {
            return Err(self.unsupported(self.node, "values over 128 bits"));
        }
        if value.width <= 128 {
            let ty = self.lane_type(LaneKind::Unsigned, 128, width / 128)?;
            let int = self.int_view(value)?;
            let int = self.coerce(int, Class::Zero)?;
            let mut int = self.exact(int, false, 128);
            int.width = 128;
            let mut parts = vec![int];
            for _ in 1..ty.lanes {
                parts.push(self.constant(Bits::zero(128), Class::Zero, false)?);
            }
            return self.lanes_literal(&parts, ty);
        }
        let halves = VectorTy::bits(value.width)
            .ok_or_else(|| self.unsupported(self.node, "values over 128 bits"))?;
        let to = VectorTy::bits(width)
            .ok_or_else(|| self.unsupported(self.node, "values over 128 bits"))?;
        if halves.lanes * 2 != to.lanes {
            return Err(self.unsupported(self.node, "values over 128 bits"));
        }
        let low = self.vector_view(value, halves)?;
        let zero = self.vector_literal(Bits::zero(halves.width()), halves)?;
        let indices: Vec<u16> = (0..to.lanes).collect();
        Ok(self.shuffle(low, zero, &indices, to))
    }

    /// The values concatenation `id` (wider than 128 bits) is made of, low
    /// first, where they are all of one width a vector has lanes of, and
    /// that vector's (unsigned) type.
    pub(super) fn concat_pieces(&self, id: ExprId) -> Option<(Vec<ExprId>, VectorTy)> {
        let width = self.width(id);
        if width <= 128 {
            return None;
        }
        let mut pieces = Vec::new();
        let mut work = vec![id];
        // The low operand popped first: the pieces come low first.
        while let Some(at) = work.pop() {
            match self.f.expr(at) {
                Some(&Expr::Concat { high, low }) => work.extend([high, low]),
                Some(_) | None => pieces.push(at),
            }
        }
        let lane = self.width(*pieces.first()?);
        if pieces.iter().any(|&piece| self.width(piece) != lane) {
            return None;
        }
        let ty = VectorTy::new(LaneKind::Unsigned, lane, u16::try_from(pieces.len()).ok()?)?;
        (ty.width() == width).then_some((pieces, ty))
    }

    /// A vector of type `ty` of `parts` (its lanes, low first): `(u8x32){a,
    /// b, …}`; one part (all lanes the same): `splat(u8x32, a)`.
    pub(super) fn pieces(&mut self, parts: &[Value], ty: VectorTy) -> Result<Value, PrintError> {
        if let [part] = parts {
            if let Some(bits) = part.constant {
                let repeated = (0..ty.lanes)
                    .map(|_| bits)
                    .reduce(|high, low| high.concat(&low))
                    .ok_or_else(|| error(self.node, "no lanes"))?;
                return self.vector_literal(repeated, ty);
            }
            let int = self.int_view(part.clone())?;
            let int = self.macro_argument(int);
            let (depth, loads) = (int.depth, int.loads);
            let name = Doc::macro_name("splat", self.node);
            let (doc, depth) =
                self.call_doc(vec![name], vec![vec![self.type_token(ty)], int.doc], depth);
            return Ok(vector_value(
                doc,
                Op::Postfix,
                ty,
                ty.width(),
                Class::Low,
                loads,
                depth,
            ));
        }
        if parts.iter().all(|part| part.constant.is_some()) {
            let bits = parts
                .iter()
                .rev()
                .filter_map(|part| part.constant)
                .reduce(|high, low| high.concat(&low))
                .ok_or_else(|| error(self.node, "no lanes"))?;
            return self.vector_literal(bits, ty);
        }
        self.lanes_literal(parts, ty)
    }

    /// A vector of type `ty` of `parts` (integers of its lane width, lane 0
    /// first, each converted to the lane's type, which keeps its low bits):
    /// `(u128x2){low, high}`.
    fn lanes_literal(&mut self, parts: &[Value], ty: VectorTy) -> Result<Value, PrintError> {
        let node = self.node;
        let mut doc = parenthesized(vec![self.type_token(ty)], node);
        doc.push(Doc::punct("{", node));
        let mut items = Vec::new();
        let (mut depth, mut loads) = (0, false);
        for (index, part) in parts.iter().enumerate() {
            if index > 0 {
                items.push(Doc::punct(",", node));
                items.push(Doc::Line);
            }
            let int = self.int_view(part.clone())?;
            let int = if let Some(bits) = int.constant {
                self.lane_literal(bits, ty.kind)?
            } else {
                int
            };
            depth = depth.max(int.depth);
            loads |= int.loads;
            self.append(&mut items, int.doc);
        }
        doc.push(Doc::Nest(items));
        doc.push(Doc::punct("}", node));
        Ok(vector_value(
            vec![Doc::Group(doc)],
            Op::Postfix,
            ty,
            ty.width(),
            Class::Low,
            loads,
            depth.saturating_add(1),
        ))
    }
}

/// The index of the lane `width` bits from `offset` are in a vector of
/// `source` bits split into lanes of `width` (8 to 128 bits), if they are
/// one.
fn lane_of(source: u16, offset: u16, width: u16) -> Option<u16> {
    (matches!(width, 8 | 16 | 32 | 64 | 128)
        && offset.is_multiple_of(width)
        && source.is_multiple_of(width)
        && source / width >= 2
        && VectorTy::new(LaneKind::Unsigned, width, source / width).is_some())
    .then_some(offset / width)
}
