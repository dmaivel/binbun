//! C expressions as the printer builds them: tokens, the C type, the
//! precedence of the top operator, and how the C value relates to the L2
//! value it stands for; and the conversions that make a value what an
//! operation needs, with a cast only where it is not already so.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use binbun_ast::ir::{Node, VarId};
use binbun_ast::types::Type;
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Format;

use super::types::{CTy, VectorTy, common, container, native};
use super::{PrintError, Printer, error, number, string_literal};
use crate::document::{Doc, TokenKind};

/// What a C value is, of the L2 value `x` of width `w` it stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    /// The unsigned value of `x`.
    Zero,
    /// The signed value of `x`.
    Sign,
    /// Only congruent to `x` modulo 2^w.
    Low,
}

/// The top operator of a C expression, in C's precedence order (lowest
/// first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Op {
    Conditional,
    LogicalOr,
    LogicalAnd,
    BitOr,
    BitXor,
    BitAnd,
    Equality,
    Relational,
    Shift,
    Additive,
    Multiplicative,
    /// Unary operators and casts.
    Unary,
    /// Names, literals, calls, subscripts, member accesses, parentheses.
    Postfix,
}

/// How deep layout groups nest in one expression; deeper operators are
/// laid out flat (the document stays shallow whatever the expression).
const GROUP_DEPTH: u8 = 12;

/// A C expression.
#[derive(Clone, Debug)]
pub(super) struct Value {
    pub doc: Vec<Doc>,
    pub op: Op,
    pub ty: CTy,
    pub class: Class,
    /// The L2 width.
    pub width: u16,
    /// For a literal: the L2 constant, to print again as a use needs.
    pub constant: Option<Bits>,
    /// Whether it is an lvalue (a variable or a dereference).
    pub lvalue: bool,
    /// Whether evaluating it reads memory (and may fault) or has an
    /// effect (a call, an assignment): then it is never made the right
    /// operand of a `&&`/`||`, which C evaluates only on some paths.
    pub loads: bool,
    /// The depth of its layout groups.
    pub depth: u8,
    /// For `&v` (or an array `v` decayed): `v`.
    pub address_of: Option<VarId>,
}

/// The values of a C integer value's range: `[0, 2^n)` or
/// `[-2^(n-1), 2^(n-1))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Range {
    Unsigned(u16),
    Signed(u16),
}

/// An integer type: signedness and width (`bool`: unsigned, 1 bit).
pub(super) type IntTy = (bool, u16);

/// The integer type of `ty`, if it is one.
pub(super) const fn int_of(ty: CTy) -> Option<IntTy> {
    match ty {
        CTy::Int { signed, bits } => Some((signed, bits)),
        CTy::Bool => Some((false, 1)),
        CTy::Float(_)
        | CTy::Bytes
        | CTy::Pointer(_)
        | CTy::Code(_)
        | CTy::Other(_)
        | CTy::Vector(_) => None,
    }
}

/// `ty` after the integer promotions.
pub(super) const fn promote(ty: IntTy) -> IntTy {
    if ty.1 >= 32 { ty } else { (true, 32) }
}

/// Whether every value of `range` is a value of `ty`.
pub(super) const fn fits(range: Range, ty: IntTy) -> bool {
    match (range, ty.0) {
        (Range::Unsigned(bits), false) | (Range::Signed(bits), true) => bits <= ty.1,
        (Range::Unsigned(bits), true) => bits < ty.1,
        (Range::Signed(_), false) => false,
    }
}

/// The number of bits of `value`.
fn bit_length(value: u128) -> u16 {
    #[expect(clippy::cast_possible_truncation, reason = "at most 128")]
    let bits = (128 - value.leading_zeros()) as u16;
    bits
}

/// The C integer of an L2 constant read as `class` says: whether it is
/// negative, and its magnitude.
pub(super) fn constant_value(bits: Bits, class: Class) -> (bool, u128) {
    let width = bits.width();
    let unsigned = bits.low_u128();
    if class == Class::Sign && bits.msb() {
        let magnitude = if width >= 128 {
            unsigned.wrapping_neg()
        } else {
            (1u128 << width) - unsigned
        };
        (true, magnitude)
    } else {
        (false, unsigned)
    }
}

/// Whether the integer `(negative, magnitude)` is a value of `ty`.
pub(super) fn holds(ty: IntTy, negative: bool, magnitude: u128) -> bool {
    let (signed, bits) = ty;
    let top = |shift: u16| {
        if shift >= 128 {
            u128::MAX
        } else {
            (1u128 << shift) - 1
        }
    };
    match (signed, negative) {
        (false, true) => magnitude == 0,
        (false, false) => bits >= 128 || magnitude <= top(bits),
        (true, false) => magnitude <= top(bits - 1),
        (true, true) => magnitude == 0 || magnitude - 1 <= top(bits - 1),
    }
}

impl Value {
    /// The range of its C values.
    pub(super) fn range(&self) -> Option<Range> {
        let (signed, bits) = int_of(self.ty)?;
        if let Some(constant) = self.constant {
            let (negative, magnitude) = constant_value(constant, self.class);
            return Some(if negative {
                Range::Signed(bit_length(magnitude - 1) + 1)
            } else {
                Range::Unsigned(bit_length(magnitude))
            });
        }
        Some(match self.class {
            Class::Zero => Range::Unsigned(self.width.min(bits - u16::from(signed))),
            Class::Sign if signed => Range::Signed(self.width.min(bits)),
            Class::Sign | Class::Low if signed => Range::Signed(bits),
            Class::Sign | Class::Low => Range::Unsigned(bits),
        })
    }

    /// Whether it is what `need` asks for.
    pub(super) fn is(&self, need: Class) -> bool {
        let Some((signed, bits)) = int_of(self.ty) else {
            return false;
        };
        match need {
            Class::Low => true,
            Class::Zero => self.class == Class::Zero || (!signed && bits == self.width),
            Class::Sign => {
                self.class == Class::Sign
                    || (signed && bits == self.width)
                    || (self.class == Class::Zero
                        && matches!(self.range(), Some(Range::Unsigned(n)) if n < self.width))
            }
        }
    }

    /// Whether, converted to `ty` (by C's usual arithmetic conversions),
    /// it is what `need` asks for.
    pub(super) fn is_in(&self, ty: IntTy, need: Class) -> bool {
        let Some(range) = self.range() else {
            return false;
        };
        if fits(range, ty) {
            return self.is(need);
        }
        match ty.1.cmp(&self.width) {
            Ordering::Less => false,
            Ordering::Equal => {
                need == Class::Low || need == if ty.0 { Class::Sign } else { Class::Zero }
            }
            Ordering::Greater => need == Class::Low,
        }
    }

    /// Whether, compared with or chosen against a value of type `ty`, it
    /// would draw a warning about mixing signedness: a signed value C
    /// converts to unsigned, unless it is a literal or of an unsigned type
    /// narrower than `int`.
    pub(super) fn mixes(&self, ty: IntTy) -> bool {
        let Some(own) = int_of(self.ty) else {
            return false;
        };
        !ty.0
            && promote(own).0
            && own.0
            && self
                .constant
                .is_none_or(|bits| constant_value(bits, self.class).0)
    }

    /// Its integer type after the promotions.
    pub(super) fn promoted(&self) -> Option<IntTy> {
        int_of(self.ty).map(promote)
    }

    /// The same expression standing for an L2 value of `width` bits.
    pub(super) fn with_width(mut self, width: u16) -> Self {
        self.width = width;
        self
    }

    /// Whether its first token is `text` (to keep `- -x` apart).
    fn starts_with(&self, text: &str) -> bool {
        first_token(&self.doc).is_some_and(|token| token == text)
    }
}

fn first_token(docs: &[Doc]) -> Option<&str> {
    for doc in docs {
        match doc {
            Doc::Token(token) => return Some(&token.text),
            Doc::Group(items) | Doc::Nest(items) | Doc::Outdent(items) => {
                if let Some(text) = first_token(items) {
                    return Some(text);
                }
            }
            Doc::Space
            | Doc::Line
            | Doc::SoftLine
            | Doc::HardLine
            | Doc::BlankLine
            | Doc::Block { .. }
            | Doc::AfterBlock => {}
        }
    }
    None
}

/// Whether an operand with top operator `child` needs parentheses under
/// `parent` (on its right: `right`), by precedence or because compilers
/// warn that the precedence is easy to misread.
fn needs_parens(parent: Op, child: Op, right: bool) -> bool {
    if child < parent || (right && child == parent && parent < Op::Unary) {
        return true;
    }
    let arithmetic = matches!(child, Op::Additive | Op::Multiplicative | Op::Shift);
    let comparison = matches!(child, Op::Equality | Op::Relational);
    match parent {
        Op::Shift => child == Op::Additive,
        Op::BitAnd => arithmetic || comparison,
        Op::BitXor => arithmetic || comparison || child == Op::BitAnd,
        Op::BitOr => arithmetic || comparison || matches!(child, Op::BitAnd | Op::BitXor),
        Op::Equality | Op::Relational => comparison,
        Op::LogicalOr => child == Op::LogicalAnd,
        Op::Conditional => {
            arithmetic || matches!(child, Op::BitAnd | Op::BitXor | Op::BitOr | Op::Conditional)
        }
        Op::LogicalAnd | Op::Additive | Op::Multiplicative | Op::Unary | Op::Postfix => false,
    }
}

/// `docs` in parentheses.
pub(super) fn parenthesized(docs: Vec<Doc>, node: Option<Node>) -> Vec<Doc> {
    let mut out = Vec::with_capacity(docs.len() + 2);
    out.push(Doc::punct("(", node));
    out.extend(docs);
    out.push(Doc::punct(")", node));
    out
}

/// A cast's parentheses around the type name `spelled`: operator tokens
/// (casts are counted by them), all of it marked part of a cast.
pub(super) fn cast_parentheses(spelled: Vec<Doc>, node: Option<Node>) -> Vec<Doc> {
    let mut out = Vec::with_capacity(spelled.len() + 2);
    out.push(Doc::op("(", node));
    out.extend(spelled);
    out.push(Doc::op(")", node));
    for doc in &mut out {
        doc.mark_cast();
    }
    out
}

impl Printer<'_> {
    /// The tokens of `value` as an operand of `parent`.
    pub(super) fn operand(&self, value: Value, parent: Op, right: bool) -> Vec<Doc> {
        if needs_parens(parent, value.op, right)
            || (parent == Op::Unary && (value.starts_with("-") || value.starts_with("+")))
        {
            self.charge(value.doc.len());
            parenthesized(value.doc, self.node)
        } else {
            value.doc
        }
    }

    /// `docs` appended to `out` (a copy: counted against
    /// [`super::expr::COPY_BUDGET`]).
    pub(super) fn append(&self, out: &mut Vec<Doc>, docs: Vec<Doc>) {
        self.charge(docs.len());
        out.extend(docs);
    }

    fn charge(&self, pieces: usize) {
        self.copied.set(self.copied.get().saturating_add(pieces));
    }

    /// `a op b` as tokens, grouped for layout while groups stay shallow.
    pub(super) fn binary_doc(&self, a: Value, op: &str, kind: Op, b: Value) -> (Vec<Doc>, u8) {
        let depth = a.depth.max(b.depth);
        let mut docs = self.operand(a, kind, false);
        docs.push(Doc::Space);
        docs.push(Doc::op(op, self.node));
        if depth < GROUP_DEPTH {
            docs.push(Doc::Line);
            let right = self.operand(b, kind, true);
            self.append(&mut docs, right);
            (vec![Doc::Group(docs)], depth + 1)
        } else {
            docs.push(Doc::Space);
            let right = self.operand(b, kind, true);
            self.append(&mut docs, right);
            (docs, depth)
        }
    }

    /// A call of `name` (a helper or function) with `arguments`; one with
    /// none is never broken (`f()`, not `f(` and `)` on lines of their own).
    pub(super) fn call_doc(
        &self,
        name: Vec<Doc>,
        arguments: Vec<Vec<Doc>>,
        depth: u8,
    ) -> (Vec<Doc>, u8) {
        let mut docs = name;
        docs.push(Doc::punct("(", self.node));
        if arguments.is_empty() {
            docs.push(Doc::punct(")", self.node));
            return (docs, depth);
        }
        let mut inner = Vec::new();
        let count = arguments.len();
        for (position, argument) in arguments.into_iter().enumerate() {
            self.append(&mut inner, argument);
            if position + 1 < count {
                inner.push(Doc::punct(",", self.node));
                inner.push(Doc::Line);
            }
        }
        if depth < GROUP_DEPTH {
            let mut nested = vec![Doc::SoftLine];
            nested.extend(inner);
            docs.push(Doc::Nest(nested));
            docs.push(Doc::SoftLine);
            docs.push(Doc::punct(")", self.node));
            (vec![Doc::Group(docs)], depth + 1)
        } else {
            for doc in &mut inner {
                if matches!(doc, Doc::Line) {
                    *doc = Doc::Space;
                }
            }
            docs.extend(inner);
            docs.push(Doc::punct(")", self.node));
            (docs, depth)
        }
    }

    /// A helper call giving a value: `name` a macro of `binbun_defs.h`'s, or a
    /// compiler builtin (`__builtin_…`, a function).
    pub(super) fn helper(
        &self,
        name: &str,
        arguments: Vec<Value>,
        ty: CTy,
        class: Class,
        width: u16,
    ) -> Value {
        let depth = arguments.iter().map(|a| a.depth).max().unwrap_or(0);
        let loads = arguments.iter().any(|a| a.loads);
        let arguments = arguments.into_iter().map(|a| a.doc).collect();
        let kind = if name.starts_with("__builtin") {
            TokenKind::Function
        } else {
            TokenKind::Macro
        };
        let name = Doc::token(kind, name, self.node);
        let (doc, depth) = self.call_doc(vec![name], arguments, depth);
        Value {
            doc,
            op: Op::Postfix,
            ty,
            class,
            width,
            constant: None,
            lvalue: false,
            loads,
            depth,
            address_of: None,
        }
    }

    /// A literal of `width` bits: `value` in decimal or hexadecimal.
    pub(super) fn literal_number(&self, value: u64, hex: bool) -> Value {
        let hex = hex || value >= self.style.hex_threshold;
        Value {
            doc: vec![Doc::number(number(u128::from(value), hex), self.node)],
            op: Op::Postfix,
            ty: CTy::Int {
                signed: true,
                bits: 32,
            },
            class: Class::Zero,
            width: 32,
            constant: None,
            lvalue: false,
            loads: false,
            depth: 0,
            address_of: None,
        }
    }

    /// The constant `bits` as a literal of C type `ty`, read as `class`
    /// says (the caller checked that it is a value of `ty`); `bitwise`
    /// prefers hexadecimal.
    pub(super) fn literal(&mut self, bits: Bits, class: Class, ty: IntTy, bitwise: bool) -> Value {
        let (negative, magnitude) = constant_value(bits, class);
        let hex = magnitude >= u128::from(self.style.hex_threshold) || (bitwise && magnitude >= 10);
        let node = self.node;
        let suffix = match ty {
            (true, 32) => "",
            (false, 32) => "U",
            (signed, _) => self.long_suffix(signed),
        };
        let (doc, op) = if ty == (true, 32) && negative && magnitude == 1 << 31 {
            (vec![Doc::macro_name("INT32_MIN", node)], Op::Postfix)
        } else if ty == (true, 64) && negative && magnitude == 1 << 63 {
            (vec![Doc::macro_name("INT64_MIN", node)], Op::Postfix)
        } else if ty.1 > 64 {
            self.wide_literal(negative, magnitude, ty)
        } else {
            let text = format!("{}{suffix}", number(magnitude, hex));
            if negative {
                (vec![Doc::op("-", node), Doc::number(text, node)], Op::Unary)
            } else {
                (vec![Doc::number(text, node)], Op::Postfix)
            }
        };
        Value {
            doc,
            op,
            ty: CTy::Int {
                signed: ty.0,
                bits: ty.1,
            },
            class: if negative { Class::Sign } else { Class::Zero },
            width: bits.width(),
            constant: Some(bits),
            lvalue: false,
            loads: false,
            depth: 0,
            address_of: None,
        }
    }

    /// A 128-bit literal: a cast of a 64-bit one, or two halves.
    fn wide_literal(&mut self, negative: bool, magnitude: u128, ty: IntTy) -> (Vec<Doc>, Op) {
        let node = self.node;
        let suffix = self.long_suffix(false);
        let mut doc = Vec::new();
        if negative {
            doc.push(Doc::op("-", node));
        }
        doc.extend(self.cast_tokens(CTy::Int {
            signed: ty.0,
            bits: 128,
        }));
        #[expect(clippy::cast_possible_truncation, reason = "halves")]
        let (high, low) = ((magnitude >> 64) as u64, magnitude as u64);
        if high == 0 {
            doc.push(Doc::number(format!("{low:#x}{suffix}"), node));
            return (doc, Op::Unary);
        }
        let mut inner = doc;
        inner.push(Doc::number(format!("{high:#x}{suffix}"), node));
        inner.extend([Doc::Space, Doc::op("<<", node), Doc::Space]);
        inner.push(Doc::number("64", node));
        inner.extend([Doc::Space, Doc::op("|", node), Doc::Space]);
        inner.push(Doc::number(format!("{low:#x}{suffix}"), node));
        (parenthesized(inner, node), Op::Postfix)
    }

    /// The constant `bits` read as `class` says, in the narrowest of
    /// `int`, `unsigned`, `long`, `unsigned long` and the 128-bit types
    /// that holds it.
    pub(super) fn constant(
        &mut self,
        bits: Bits,
        class: Class,
        bitwise: bool,
    ) -> Result<Value, PrintError> {
        let (negative, magnitude) = constant_value(bits, class);
        let ty = CANDIDATES
            .into_iter()
            .find(|&ty| holds(ty, negative, magnitude))
            .ok_or_else(|| self.unsupported(self.node, "constants over 128 bits"))?;
        Ok(self.literal(bits, class, ty, bitwise))
    }

    /// `-value`, of its promoted type.
    fn negate(&self, value: Value) -> Value {
        let ty = value.promoted().unwrap_or((true, 32));
        let (width, depth, loads) = (value.width, value.depth, value.loads);
        let mut doc = vec![Doc::op("-", self.node)];
        let operand = self.operand(value, Op::Unary, false);
        self.append(&mut doc, operand);
        let mut out = Self::built(doc, Op::Unary, ty, Class::Low, width, &[], depth);
        out.loads = loads;
        out
    }

    /// `(T)` for C type `ty`.
    pub(super) fn cast_tokens(&mut self, ty: CTy) -> Vec<Doc> {
        let spelled = self.declare_c(ty, Vec::new()).unwrap_or_default();
        cast_parentheses(spelled, self.node)
    }

    /// `(T)value`.
    pub(super) fn cast(&mut self, value: Value, ty: CTy) -> Value {
        let class = match (int_of(ty), value.range()) {
            (Some(target), Some(range)) if fits(range, target) => value.class,
            _ => Class::Low,
        };
        let mut doc = self.cast_tokens(ty);
        let depth = value.depth;
        let loads = value.loads;
        let width = value.width;
        let operand = self.operand(value, Op::Unary, false);
        self.append(&mut doc, operand);
        Value {
            doc,
            op: Op::Unary,
            ty,
            class,
            width,
            constant: None,
            lvalue: false,
            loads,
            depth,
            address_of: None,
        }
    }

    /// `(T *)`, a cast to a pointer to `pointee` (`volatile T *`:
    /// `volatile`).
    pub(super) fn pointer_cast_tokens(
        &mut self,
        pointee: CTy,
        volatile: bool,
    ) -> Result<Vec<Doc>, PrintError> {
        let spelled = self.pointer_to(pointee, volatile)?;
        Ok(cast_parentheses(spelled, self.node))
    }

    /// `(T *)` for an access of `pointee` at an address the program
    /// computed: a 128-bit integer as `binbun_defs.h`'s `binbun_u128_u` (or
    /// `binbun_i128_u`), of alignment 1, since the address need not be a
    /// multiple of 16 (the instructions, `movdqu`, do not ask it) and
    /// through `unsigned __int128 *` compilers load and store with aligned
    /// vector instructions, which fault where it is not.
    pub(super) fn access_cast_tokens(
        &mut self,
        pointee: CTy,
        volatile: bool,
    ) -> Result<Vec<Doc>, PrintError> {
        let CTy::Int { signed, bits: 128 } = pointee else {
            return self.pointer_cast_tokens(pointee, volatile);
        };
        let name = if signed {
            "binbun_i128_u"
        } else {
            "binbun_u128_u"
        };
        let mut spelled = Vec::new();
        if volatile {
            spelled.extend([Doc::keyword("volatile", None), Doc::Space]);
        }
        spelled.extend([
            Doc::token(TokenKind::Type, name, None),
            Doc::Space,
            Doc::op("*", None),
        ]);
        Ok(cast_parentheses(spelled, self.node))
    }

    /// `value` as an integer: pointers through `uintptr_t`'s width,
    /// floats by their bits, aggregates in memory by punning, vectors
    /// ([`Self::vector_int`]).
    pub(super) fn int_view(&mut self, value: Value) -> Result<Value, PrintError> {
        match value.ty {
            CTy::Int { .. } | CTy::Bool => Ok(value),
            CTy::Pointer(_) | CTy::Bytes | CTy::Code(_) => {
                let bits = self.pointer_width();
                Ok(self.cast(
                    value,
                    CTy::Int {
                        signed: false,
                        bits,
                    },
                ))
            }
            CTy::Float(format) => {
                let (name, bits) = match format {
                    Format::Single => ("f32_bits", 32),
                    Format::Double => ("f64_bits", 64),
                    Format::Half | Format::Extended => {
                        return Err(self.unsupported(self.node, "half and extended floats as bits"));
                    }
                };
                let width = value.width;
                Ok(self.helper(
                    name,
                    vec![value],
                    CTy::Int {
                        signed: false,
                        bits,
                    },
                    Class::Zero,
                    width,
                ))
            }
            CTy::Other(_) => {
                let punned = self.pun(value)?;
                if matches!(punned.ty, CTy::Vector(_)) {
                    return self.vector_int(punned);
                }
                Ok(punned)
            }
            CTy::Vector(_) => self.vector_int(value),
        }
    }

    /// An aggregate lvalue's bits as an unsigned integer: `*(uintN_t *)&v`
    /// (of 256 or 512 bits: as `u64x4` or `u64x8`).
    pub(super) fn pun(&mut self, value: Value) -> Result<Value, PrintError> {
        if value.lvalue
            && let Some(vector) = VectorTy::bits(value.width)
        {
            return Ok(self.reinterpret(value, CTy::Vector(vector)));
        }
        if !value.lvalue || !native(value.width) {
            return Err(self.unsupported(
                self.node,
                "an aggregate value that is not in memory or not 1, 2, 4, 8 or 16 bytes",
            ));
        }
        let ty = CTy::Int {
            signed: false,
            bits: value.width,
        };
        Ok(self.reinterpret(value, ty))
    }

    /// An integer `value` (of the pointer width) as pointer type `ty`:
    /// `(T *)x`, through the pointer-wide integer type where C holds it
    /// narrower (so compilers see no change of size); a constant address
    /// of a string in read-only data as a `char *`, that string's literal.
    pub(super) fn int_to_pointer(&mut self, value: Value, ty: CTy) -> Result<Value, PrintError> {
        if let Some(literal) = self.string_constant(&value, ty) {
            return Ok(literal);
        }
        let value = self.int_view(value)?;
        let bits = self.pointer_width();
        let value = if value.promoted().is_some_and(|own| own.1 == bits) {
            value
        } else {
            let value = self.coerce(value, Class::Zero)?;
            self.exact(value, false, bits)
        };
        Ok(self.cast(value, ty))
    }

    /// Constant `value` as the literal of the string it points to, if `ty`
    /// is a pointer to plain `char` and the image holds a string there in
    /// read-only data. C gives a literal static storage holding those
    /// bytes and their NUL, which the program cannot change either; it
    /// lives at an address of the compiler's choosing, as every object
    /// of the C does (the integer is no more the run-time address: a
    /// relocatable image's strings move with it).
    fn string_constant(&self, value: &Value, ty: CTy) -> Option<Value> {
        let bits = value.constant?;
        let CTy::Pointer(pointer) = ty else {
            return None;
        };
        let &Type::Pointer(Some(element)) = self.types.get(pointer)? else {
            return None;
        };
        if !matches!(self.types.get(element), Some(Type::Char { .. }))
            || bits.width() != self.pointer_width()
        {
            return None;
        }
        let text = self.image.string(u64::try_from(bits.low_u128()).ok()?)?;
        Some(Value {
            doc: vec![Doc::string(string_literal(&text), self.node)],
            op: Op::Postfix,
            ty,
            class: Class::Low,
            width: self.pointer_width(),
            constant: None,
            lvalue: false,
            loads: false,
            depth: 0,
            address_of: None,
        })
    }

    /// `*(T *)&lvalue`.
    pub(super) fn reinterpret(&mut self, value: Value, ty: CTy) -> Value {
        let node = self.node;
        let mut doc = vec![Doc::op("*", node)];
        doc.extend(self.access_cast_tokens(ty, false).unwrap_or_default());
        doc.push(Doc::op("&", node));
        let (depth, loads, width) = (value.depth, value.loads, value.width);
        let operand = self.operand(value, Op::Unary, false);
        self.append(&mut doc, operand);
        Value {
            doc,
            op: Op::Unary,
            ty,
            class: Class::Low,
            width,
            constant: None,
            lvalue: true,
            loads,
            depth,
            address_of: None,
        }
    }

    /// `value` (an integer) made what `need` asks for: a literal printed
    /// again, a cast to the exact type of its width, or at widths C lacks
    /// a mask or `sext_n`.
    pub(super) fn coerce(&mut self, value: Value, need: Class) -> Result<Value, PrintError> {
        if value.is(need) {
            return Ok(value);
        }
        let width = value.width;
        if let Some(bits) = value.constant {
            return self.constant(bits, need, false);
        }
        if native(width) {
            return Ok(self.cast(
                value,
                CTy::Int {
                    signed: need == Class::Sign,
                    bits: width,
                },
            ));
        }
        if width == 1 && need == Class::Sign && value.is(Class::Zero) {
            // 0 or 1 sign-extended: 0 or -1.
            let mut negated = self.negate(value);
            negated.class = Class::Sign;
            return Ok(negated);
        }
        let wide = if width < 64 { 64 } else { 128 };
        if width > 128 {
            return Err(self.unsupported(self.node, "values over 128 bits"));
        }
        if need == Class::Sign {
            let unsigned = self.exact(value, false, wide);
            return Ok(self.helper(
                "sext_n",
                vec![unsigned, self.literal_number(u64::from(width), false)],
                CTy::Int {
                    signed: true,
                    bits: wide,
                },
                Class::Sign,
                width,
            ));
        }
        let value = if value.promoted().is_some_and(|ty| ty.1 < width) {
            self.cast(
                value,
                CTy::Int {
                    signed: false,
                    bits: wide,
                },
            )
        } else {
            value
        };
        let ty = value.promoted().unwrap_or((false, 32));
        let mask = Bits::ones(width).zext(ty.1);
        let mask = self.literal(mask, Class::Zero, (false, ty.1), true);
        let (doc, depth) = self.binary_doc(value.clone(), "&", Op::BitAnd, mask);
        let (signed, bits) = common(ty, (false, ty.1));
        Ok(Value {
            doc,
            op: Op::BitAnd,
            ty: CTy::Int { signed, bits },
            class: Class::Zero,
            width,
            constant: None,
            lvalue: false,
            loads: value.loads,
            depth,
            address_of: None,
        })
    }

    /// `value` (an integer congruent to the L2 value) as exactly C type
    /// `(signed, bits)`, `bits` at least its width: unchanged if it is of
    /// that type, else cast.
    pub(super) fn exact(&mut self, value: Value, signed: bool, bits: u16) -> Value {
        let ty = CTy::Int { signed, bits };
        if value.ty == ty {
            return value;
        }
        if let Some(constant) = value.constant {
            let class = if signed { Class::Sign } else { Class::Zero };
            if bits >= 32 {
                return self.literal(constant, class, (signed, bits), false);
            }
        }
        self.cast(value, ty)
    }

    /// `value` (an integer of its width's class `need`) as exactly the
    /// type a `binbun_defs.h` helper of its width takes: the exact type at a
    /// width C has, else the 64- or 128-bit one with the value of that
    /// class.
    pub(super) fn helper_operand(
        &mut self,
        value: Value,
        signed: bool,
    ) -> Result<(Value, u16), PrintError> {
        let width = value.width;
        if width > 128 {
            return Err(self.unsupported(self.node, "values over 128 bits"));
        }
        if native(width) {
            return Ok((self.exact(value, signed, width), width));
        }
        let wide = if width <= 64 { 64 } else { 128 };
        let need = if signed { Class::Sign } else { Class::Zero };
        let value = self.coerce(value, need)?;
        Ok((self.exact(value, signed, wide), wide))
    }

    /// The two operands of a binary operation of width `width` whose
    /// operands must be `need` (a comparison: `compare`, which must not
    /// mix signedness): literals typed, operands widened where C would
    /// compute narrower and cast where they are not what is needed. Gives
    /// the operands and the type C computes in.
    pub(super) fn operands(
        &mut self,
        mut a: Value,
        mut b: Value,
        need: Class,
        compare: bool,
        bitwise: bool,
    ) -> Result<(Value, Value, IntTy), PrintError> {
        let width = a.width.max(b.width);
        for _ in 0..6 {
            if a.constant.is_some() && b.constant.is_some() {
                let bits = a.constant.unwrap_or(Bits::zero(width));
                a = self.constant(
                    bits,
                    if need == Class::Sign {
                        Class::Sign
                    } else {
                        Class::Zero
                    },
                    bitwise,
                )?;
                a.constant = None;
            }
            if a.constant.is_some() {
                a = self.fit_literal(&a, &b, need, compare, bitwise)?;
            } else if b.constant.is_some() {
                b = self.fit_literal(&b, &a, need, compare, bitwise)?;
            }
            let (Some(ta), Some(tb)) = (a.promoted(), b.promoted()) else {
                return Err(error(self.node, "operands are not integers"));
            };
            let ty = common(ta, tb);
            if ty.1 < width {
                let wide = container(width).unwrap_or(128).max(32);
                let signed = need == Class::Sign;
                if a.constant.is_none() && (ta.1 <= tb.1 || b.constant.is_some()) {
                    a = self.cast(a, CTy::Int { signed, bits: wide });
                } else {
                    b = self.cast(b, CTy::Int { signed, bits: wide });
                }
                continue;
            }
            let good = |v: &Value| v.is_in(ty, need) && !(compare && v.mixes(ty));
            let (good_a, good_b) = (good(&a), good(&b));
            if good_a && good_b {
                return Ok((a, b, ty));
            }
            // First make each operand what is needed, then keep it so
            // through the conversions.
            if !a.is(need) && a.constant.is_none() {
                a = self.coerce(a, need)?;
            } else if !b.is(need) && b.constant.is_none() {
                b = self.coerce(b, need)?;
            } else if !good_a {
                a = self.fix(a, need, ty)?;
            } else {
                b = self.fix(b, need, ty)?;
            }
        }
        Err(error(
            self.node,
            "operands could not be given a common C type",
        ))
    }

    /// `value` made `need` (or, if it is, cast to the type of `need`'s
    /// signedness and `ty`'s width so the conversions keep it).
    fn fix(&mut self, value: Value, need: Class, ty: IntTy) -> Result<Value, PrintError> {
        if !value.is(need) {
            return self.coerce(value, need);
        }
        let bits = container(value.width).unwrap_or(128).max(ty.1);
        let signed = match need {
            Class::Sign => true,
            Class::Zero => false,
            Class::Low => ty.0,
        };
        if let Some(bits_value) = value.constant {
            let class = if signed { Class::Sign } else { Class::Zero };
            return self.constant(bits_value, class, false);
        }
        Ok(self.cast(value, CTy::Int { signed, bits }))
    }

    /// The literal `literal` typed to go with `other`: the first of
    /// `other`'s promoted type and the candidate types that holds its
    /// value as `need` reads it, makes C compute at the width, and keeps
    /// `other` what it must be.
    fn fit_literal(
        &mut self,
        literal: &Value,
        other: &Value,
        need: Class,
        compare: bool,
        bitwise: bool,
    ) -> Result<Value, PrintError> {
        let bits = literal.constant.unwrap_or(Bits::zero(literal.width));
        let width = bits.width();
        let other_ty = other.promoted().unwrap_or((true, 32));
        let class = match need {
            Class::Zero | Class::Sign => need,
            Class::Low => {
                let (negative, magnitude) = constant_value(bits, Class::Sign);
                // A signed operand: `x - 1`, `x & -16`, `x | -1`, not
                // values beyond its type (compilers warn when the result
                // is converted back).
                if negative && magnitude < 1 << 15 && other_ty.0 {
                    Class::Sign
                } else {
                    Class::Zero
                }
            }
        };
        let (negative, magnitude) = constant_value(bits, class);
        let mut first = None;
        // `int` where it holds the value, else the other operand's type,
        // else the narrowest that does.
        let order = [(true, 32), other_ty].into_iter().chain(CANDIDATES);
        for ty in order {
            if !holds(ty, negative, magnitude) {
                continue;
            }
            let common = common(other_ty, ty);
            if common.1 < width {
                continue;
            }
            // What the literal would be, without its tokens (a 128-bit
            // one is a cast, counted only if printed).
            let probe = Value {
                doc: Vec::new(),
                op: Op::Postfix,
                ty: CTy::Int {
                    signed: ty.0,
                    bits: ty.1,
                },
                class: if negative { Class::Sign } else { Class::Zero },
                width,
                constant: Some(bits),
                lvalue: false,
                loads: false,
                depth: 0,
                address_of: None,
            };
            let keeps = other.is_in(common, need)
                && probe.is_in(common, need)
                && !(compare && (other.mixes(common) || probe.mixes(common)));
            if keeps {
                return Ok(self.literal(bits, class, ty, bitwise));
            }
            first.get_or_insert(ty);
        }
        let ty = first.ok_or_else(|| self.unsupported(self.node, "constants over 128 bits"))?;
        Ok(self.literal(bits, class, ty, bitwise))
    }

    /// A value of `width` bits, of C type `ty` and `class`, built from
    /// tokens.
    pub(super) fn built(
        doc: Vec<Doc>,
        op: Op,
        ty: IntTy,
        class: Class,
        width: u16,
        parts: &[&Value],
        depth: u8,
    ) -> Value {
        Value {
            doc,
            op,
            ty: CTy::Int {
                signed: ty.0,
                bits: ty.1,
            },
            class,
            width,
            constant: None,
            lvalue: false,
            loads: parts.iter().any(|part| part.loads),
            depth,
            address_of: None,
        }
    }
}

/// The literal types, narrowest first.
const CANDIDATES: [IntTy; 6] = [
    (true, 32),
    (false, 32),
    (true, 64),
    (false, 64),
    (true, 128),
    (false, 128),
];
