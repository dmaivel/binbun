//! C expressions as the printer builds them: tokens, the C type, the
//! precedence of the top operator, and how the C value relates to the L2
//! value it stands for; and the conversions that make a value what an
//! operation needs, as [`super::convert`] decides them, with a cast only
//! where it is not already so.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Node, VarId};
use binbun_ast::types::Type;
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Format;

use super::convert::{
    self, Ask, Class, Conversion, Form, IntTy, Refusal, Side, common, constant_value,
};
use super::plan::{One, Two};
use super::types::{CTy, VectorTy, native};
use super::{PrintError, Printer, error, number, string_literal};
use crate::document::{Doc, Token, TokenKind};

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
    /// For `x + k`, `k - x` or `x * k` computed in the signed type of
    /// exactly the L2 width (32 or 64 bits), `k` a literal of a signed
    /// type and not negative: where `k` is, to print it unsigned
    /// ([`convert::unsigned_literal`]).
    pub unsigned_literal: Option<EndLiteral>,
}

/// A literal operand at one end of a value's tokens: the last (else the
/// first), and its L2 constant.
#[derive(Clone, Copy, Debug)]
pub(super) struct EndLiteral {
    pub last: bool,
    pub bits: Bits,
}

impl Value {
    /// What the conversion rules see of it.
    pub(super) fn form(&self) -> Form {
        let unsigned_literal = self.unsigned_literal.is_some_and(|end| {
            matches!(self.op, Op::Additive | Op::Multiplicative) && end_number(&self.doc, end.last)
        });
        Form {
            ty: self.ty,
            class: self.class,
            width: self.width,
            constant: self.constant,
            unsigned_literal,
        }
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
            | Doc::Gap
            | Doc::Block { .. }
            | Doc::AfterBlock => {}
        }
    }
    None
}

/// The first (`last`: the last) token of `docs`, inside its groups.
fn end_token(docs: &mut [Doc], last: bool) -> Option<&mut Token> {
    let doc = if last {
        docs.last_mut()?
    } else {
        docs.first_mut()?
    };
    match doc {
        Doc::Token(token) => Some(token),
        Doc::Group(items) => end_token(items, last),
        Doc::Space
        | Doc::Line
        | Doc::SoftLine
        | Doc::HardLine
        | Doc::BlankLine
        | Doc::Gap
        | Doc::Nest(_)
        | Doc::Outdent(_)
        | Doc::Block { .. }
        | Doc::AfterBlock => None,
    }
}

/// Whether the first (`last`: the last) token of `docs`, inside its
/// groups, is a number ([`end_token`]).
fn end_number(docs: &[Doc], last: bool) -> bool {
    let doc = if last { docs.last() } else { docs.first() };
    match doc {
        Some(Doc::Token(token)) => token.kind == TokenKind::Number,
        Some(Doc::Group(items)) => end_number(items, last),
        Some(
            Doc::Space
            | Doc::Line
            | Doc::SoftLine
            | Doc::HardLine
            | Doc::BlankLine
            | Doc::Gap
            | Doc::Nest(_)
            | Doc::Outdent(_)
            | Doc::Block { .. }
            | Doc::AfterBlock,
        )
        | None => false,
    }
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
            unsigned_literal: None,
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
            unsigned_literal: None,
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
            unsigned_literal: None,
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
        let ty =
            convert::narrowest(bits, class).ok_or_else(|| self.refused(Refusal::WideConstant))?;
        Ok(self.literal(bits, class, ty, bitwise))
    }

    /// The error for a conversion [`super::convert`] refuses.
    pub(super) fn refused(&self, refusal: Refusal) -> PrintError {
        match refusal {
            Refusal::WideConstant => self.unsupported(self.node, "constants over 128 bits"),
            Refusal::WideValue => self.unsupported(self.node, "values over 128 bits"),
            Refusal::NotIntegers => error(self.node, "operands are not integers"),
            Refusal::NoCommonType => {
                error(self.node, "operands could not be given a common C type")
            }
        }
    }

    /// `-value`, of its promoted type.
    fn negate(&self, value: Value) -> Value {
        let ty = value.form().promoted().unwrap_or((true, 32));
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
        self.cast_of(spelled)
    }

    /// A cast's parentheses around the type name `spelled`
    /// ([`cast_parentheses`]), the cast noted in the plan as one to that
    /// type ([`super::plan::Ledger::note_cast`]).
    pub(super) fn cast_of(&mut self, spelled: Vec<Doc>) -> Vec<Doc> {
        self.ledger.note_cast(self.node, &spelled);
        cast_parentheses(spelled, self.node)
    }

    /// `(T)value`.
    pub(super) fn cast(&mut self, value: Value, ty: CTy) -> Value {
        let class = value.form().cast(ty).class;
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
            unsigned_literal: None,
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
        Ok(self.cast_of(spelled))
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
        Ok(self.cast_of(spelled))
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
        let value = if value.form().promoted().is_some_and(|own| own.1 == bits) {
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
            unsigned_literal: None,
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
            unsigned_literal: None,
        }
    }

    /// `value` (an integer) made what `need` asks for: a literal printed
    /// again, a cast to the exact type of its width, or at widths C lacks
    /// a mask or `sext_n` ([`convert::coerce`]).
    pub(super) fn coerce(&mut self, value: Value, need: Class) -> Result<Value, PrintError> {
        self.asked(value, Ask::Coerce(need))
    }

    /// `value` (an integer congruent to the L2 value) as exactly C type
    /// `(signed, bits)`, `bits` at least its width: unchanged if it is of
    /// that type, else cast ([`convert::exact`]).
    pub(super) fn exact(&mut self, value: Value, signed: bool, bits: u16) -> Value {
        let form = value.form();
        let conversion = convert::exact(form, signed, bits);
        self.ledger.note_one(One {
            node: self.node,
            ask: Ask::Exact((signed, bits)),
            form,
            conversion: Ok(conversion),
        });
        self.apply(value, conversion)
    }

    /// `value` made what `ask` asks for, as C's rules decide
    /// ([`convert::conversion`]), the decision noted in the plan
    /// ([`super::plan`]).
    pub(super) fn asked(&mut self, value: Value, ask: Ask) -> Result<Value, PrintError> {
        let form = value.form();
        let conversion = convert::conversion(ask, form);
        self.ledger.note_one(One {
            node: self.node,
            ask,
            form,
            conversion,
        });
        let conversion = conversion.map_err(|r| self.refused(r))?;
        Ok(self.apply(value, conversion))
    }

    /// `value` converted as `conversion` says.
    pub(super) fn apply(&mut self, value: Value, conversion: Conversion) -> Value {
        #[cfg(debug_assertions)]
        let expected = value.form().after(conversion);
        let value = match conversion {
            Conversion::Keep => value,
            Conversion::UnsignedLiteral => self.print_unsigned(value),
            Conversion::Literal(literal) => {
                let bits = value.form().literal_bits();
                self.literal(bits, literal.class, literal.ty, literal.bitwise)
            }
            Conversion::Folded(literal) => {
                let bits = value.form().literal_bits();
                let mut folded = self.literal(bits, literal.class, literal.ty, literal.bitwise);
                folded.constant = None;
                folded
            }
            Conversion::Cast((signed, bits)) => self.cast(value, CTy::Int { signed, bits }),
            Conversion::Negate => {
                // 0 or 1 sign-extended: 0 or -1.
                let mut negated = self.negate(value);
                negated.class = Class::Sign;
                negated
            }
            Conversion::SignExtend(wide) => {
                let width = value.width;
                let unsigned = self.exact(value, false, wide);
                self.helper(
                    "sext_n",
                    vec![unsigned, self.literal_number(u64::from(width), false)],
                    CTy::Int {
                        signed: true,
                        bits: wide,
                    },
                    Class::Sign,
                    width,
                )
            }
            Conversion::Mask { widen, ty } => self.mask(value, widen, ty),
        };
        #[cfg(debug_assertions)]
        debug_assert_eq!(value.form(), expected, "{conversion:?}");
        value
    }

    /// `value & mask`, the mask of its width ([`Conversion::Mask`]).
    fn mask(&mut self, value: Value, widen: bool, ty: IntTy) -> Value {
        let width = value.width;
        let value = if widen {
            self.cast(
                value,
                CTy::Int {
                    signed: false,
                    bits: ty.1,
                },
            )
        } else {
            value
        };
        let mask = Bits::ones(width).zext(ty.1);
        let mask = self.literal(mask, Class::Zero, (false, ty.1), true);
        let loads = value.loads;
        let (doc, depth) = self.binary_doc(value, "&", Op::BitAnd, mask);
        let (signed, bits) = common(ty, (false, ty.1));
        Value {
            doc,
            op: Op::BitAnd,
            ty: CTy::Int { signed, bits },
            class: Class::Zero,
            width,
            constant: None,
            lvalue: false,
            loads,
            depth,
            address_of: None,
            unsigned_literal: None,
        }
    }

    /// `value`, `x + k`, `k - x` or `x * k`, with the literal `k` printed
    /// unsigned ([`convert::unsigned_literal`]).
    fn print_unsigned(&mut self, mut value: Value) -> Value {
        let width = value.width;
        if let Some(end) = value.unsigned_literal {
            let literal = self.literal(end.bits, Class::Zero, (false, width), false);
            if let ([Doc::Token(spelled)], Some(token)) =
                (literal.doc.as_slice(), end_token(&mut value.doc, end.last))
            {
                token.text.clone_from(&spelled.text);
            }
        }
        value.ty = CTy::Int {
            signed: false,
            bits: width,
        };
        value.class = Class::Zero;
        value.unsigned_literal = None;
        value
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
    /// the operands and the type C computes in ([`convert::operands`]).
    pub(super) fn operands(
        &mut self,
        mut a: Value,
        mut b: Value,
        need: Class,
        compare: bool,
        bitwise: bool,
    ) -> Result<(Value, Value, IntTy), PrintError> {
        let forms = (a.form(), b.form());
        let plan = convert::operands(forms.0, forms.1, need, compare, bitwise);
        self.ledger.note_two(Two {
            node: self.node,
            need,
            compare,
            bitwise,
            forms,
            operands: plan.clone(),
        });
        for &(side, conversion) in plan.steps() {
            match side {
                Side::Left => a = self.apply(a, conversion),
                Side::Right => b = self.apply(b, conversion),
            }
        }
        let ty = plan.outcome.map_err(|r| self.refused(r))?;
        Ok((a, b, ty))
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
            unsigned_literal: None,
        }
    }
}
