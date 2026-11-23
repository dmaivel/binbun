//! L0's canonical text form: s-expressions, printed by [`print`] and read
//! back by [`parse`] (`parse(print(x)) == x`).
//!
//! ```text
//! (semantics
//!   (locals 64 64)
//!   (exprs
//!     (e0 64 (local l0))
//!     (e1 64 (local l1))
//!     (e2 64 (add e0 e1))
//!     (e3 1 (add-carry e0 e1 e4)) ...)
//!   (body
//!     (read l0 rax 0 64)
//!     (read l1 rbx 0 64)
//!     (write rax 0 64 e2)))
//! ```
//!
//! Expressions are numbered in order and each line gives the width; register
//! views are `register offset width`; constants are hexadecimal.
//! An undefined value names its site and inputs, if it has one:
//! `(e9 1 (undefined 0 @shrd.of dst=e1 src=e2 count=e3 ...))`.

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write};

use crate::bits::Bits;
use crate::ir::{
    Binary, Declarations, Expr, ExprId, Flag, FloatOp, FloatOutput, Format, LaneOp, Local,
    Semantics, SiteUse, Stmt, Trap, Unary, View,
};

const UNARY: [(Unary, &str); 7] = [
    (Unary::Not, "not"),
    (Unary::Neg, "neg"),
    (Unary::Popcount, "popcount"),
    (Unary::LeadingZeros, "leading-zeros"),
    (Unary::TrailingZeros, "trailing-zeros"),
    (Unary::ByteSwap, "byte-swap"),
    (Unary::EvenParity8, "even-parity8"),
];

const BINARY: [(Binary, &str); 21] = [
    (Binary::Add, "add"),
    (Binary::Sub, "sub"),
    (Binary::Mul, "mul"),
    (Binary::UDiv, "udiv"),
    (Binary::URem, "urem"),
    (Binary::SDiv, "sdiv"),
    (Binary::SRem, "srem"),
    (Binary::And, "and"),
    (Binary::Or, "or"),
    (Binary::Xor, "xor"),
    (Binary::Shl, "shl"),
    (Binary::LShr, "lshr"),
    (Binary::AShr, "ashr"),
    (Binary::Rol, "rol"),
    (Binary::Ror, "ror"),
    (Binary::Eq, "eq"),
    (Binary::Ne, "ne"),
    (Binary::ULt, "ult"),
    (Binary::ULe, "ule"),
    (Binary::SLt, "slt"),
    (Binary::SLe, "sle"),
];

const FLAG: [(Flag, &str); 5] = [
    (Flag::AddCarry, "add-carry"),
    (Flag::AddOverflow, "add-overflow"),
    (Flag::SubBorrow, "sub-borrow"),
    (Flag::SubOverflow, "sub-overflow"),
    (Flag::NibbleCarry, "nibble-carry"),
];

const TRAP: [(Trap, &str); 8] = [
    (Trap::Divide, "divide"),
    (Trap::InvalidInstruction, "invalid-instruction"),
    (Trap::Breakpoint, "breakpoint"),
    (Trap::Protection, "protection"),
    (Trap::Stack, "stack"),
    (Trap::FloatingPoint, "floating-point"),
    (Trap::Authentication, "authentication"),
    (Trap::Alignment, "alignment"),
];

const FORMAT: [(Format, &str); 4] = [
    (Format::Half, "half"),
    (Format::Single, "single"),
    (Format::Double, "double"),
    (Format::Extended, "extended"),
];

const OUTPUT: [(FloatOutput, &str); 2] = [
    (FloatOutput::Value, "value"),
    (FloatOutput::Status, "status"),
];

/// Sets the operands from `used` on to the first (unused operands repeat
/// it).
fn repeat_first(operands: &mut [ExprId; 3], used: usize) {
    let [first, ..] = *operands;
    for slot in operands.iter_mut().skip(used) {
        *slot = first;
    }
}

/// The name of a floating-point operation: `add`, `convert-double`,
/// `to-sint-32`, ...
pub fn float_name(op: FloatOp) -> String {
    match op {
        FloatOp::Add => "add".into(),
        FloatOp::Sub => "sub".into(),
        FloatOp::Mul => "mul".into(),
        FloatOp::Div => "div".into(),
        FloatOp::Sqrt => "sqrt".into(),
        FloatOp::MulAdd => "mul-add".into(),
        FloatOp::RoundToIntegral => "round-to-integral".into(),
        FloatOp::Compare { signaling: false } => "compare-quiet".into(),
        FloatOp::Compare { signaling: true } => "compare-signaling".into(),
        FloatOp::Convert(target) => format!("convert-{}", name(&FORMAT, target)),
        FloatOp::FromInt { signed } => format!("from-{}int", if signed { "s" } else { "u" }),
        FloatOp::ToInt { signed, width } => {
            format!("to-{}int-{width}", if signed { "s" } else { "u" })
        }
    }
}

/// The floating-point operation named `text` ([`float_name`]).
fn float_op(text: &str) -> Option<FloatOp> {
    Some(match text {
        "add" => FloatOp::Add,
        "sub" => FloatOp::Sub,
        "mul" => FloatOp::Mul,
        "div" => FloatOp::Div,
        "sqrt" => FloatOp::Sqrt,
        "mul-add" => FloatOp::MulAdd,
        "round-to-integral" => FloatOp::RoundToIntegral,
        "compare-quiet" => FloatOp::Compare { signaling: false },
        "compare-signaling" => FloatOp::Compare { signaling: true },
        "from-sint" => FloatOp::FromInt { signed: true },
        "from-uint" => FloatOp::FromInt { signed: false },
        _ => {
            if let Some(target) = text.strip_prefix("convert-") {
                FloatOp::Convert(lookup(&FORMAT, target)?)
            } else if let Some(width) = text.strip_prefix("to-sint-") {
                FloatOp::ToInt {
                    signed: true,
                    width: width.parse().ok()?,
                }
            } else {
                FloatOp::ToInt {
                    signed: false,
                    width: text.strip_prefix("to-uint-")?.parse().ok()?,
                }
            }
        }
    })
}

fn name<T: PartialEq + Copy>(table: &[(T, &'static str)], value: T) -> &'static str {
    table
        .iter()
        .find(|&&(v, _)| v == value)
        .map_or("?", |&(_, name)| name)
}

/// The name of a unary operation: `not`, `leading-zeros`, ...
pub fn unary_name(op: Unary) -> &'static str {
    name(&UNARY, op)
}

/// The name of a binary operation: `add`, `ashr`, `slt`, ...
pub fn binary_name(op: Binary) -> &'static str {
    name(&BINARY, op)
}

/// The name of a flag computation: `add-carry`, `sub-overflow`, ...
pub fn flag_name(op: Flag) -> &'static str {
    name(&FLAG, op)
}

/// The name of a trap: `divide`, `breakpoint`, ..., `interrupt-0x29`.
pub fn trap_name(trap: Trap) -> Cow<'static, str> {
    match trap {
        Trap::Interrupt(vector) => Cow::Owned(format!("interrupt-{vector:#x}")),
        Trap::Divide
        | Trap::InvalidInstruction
        | Trap::Breakpoint
        | Trap::Protection
        | Trap::Stack
        | Trap::FloatingPoint
        | Trap::Authentication
        | Trap::Alignment => Cow::Borrowed(name(&TRAP, trap)),
    }
}

/// The trap [`trap_name`] names `text`.
fn trap(text: &str) -> Option<Trap> {
    match text.strip_prefix("interrupt-0x") {
        Some(vector) => u8::from_str_radix(vector, 16).ok().map(Trap::Interrupt),
        None => lookup(&TRAP, text),
    }
}

/// The name of a floating-point format: `half`, `single`, `double`,
/// `extended`.
pub fn format_name(format: Format) -> &'static str {
    name(&FORMAT, format)
}

fn lookup<T: Copy>(table: &[(T, &'static str)], text: &str) -> Option<T> {
    table
        .iter()
        .find(|&&(_, name)| name == text)
        .map(|&(v, _)| v)
}

/// The text of `semantics`, with register and intrinsic names from
/// `declarations`.
pub fn print(semantics: &Semantics, declarations: &Declarations) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ = Printer {
        out: &mut out,
        declarations,
    }
    .semantics(semantics);
    out
}

struct Printer<'a> {
    out: &'a mut String,
    declarations: &'a Declarations,
}

impl Printer<'_> {
    fn semantics(&mut self, s: &Semantics) -> fmt::Result {
        self.out.push_str("(semantics\n  (locals");
        for width in &s.locals {
            write!(self.out, " {width}")?;
        }
        self.out.push_str(")\n  (exprs");
        for (index, &(expr, width)) in s.exprs.iter().enumerate() {
            write!(self.out, "\n    (e{index} {width} ")?;
            if let Expr::Undefined { serial, .. } = expr {
                self.undefined(s, serial)?;
            } else {
                self.expr(expr)?;
            }
            self.out.push(')');
        }
        self.out.push_str(")\n  (body");
        self.block(&s.body, 2)?;
        self.out.push_str("))\n");
        Ok(())
    }

    /// `(undefined serial)`, or with its site and inputs:
    /// `(undefined 0 @shrd.of dst=e1 src=e2 ...)`.
    fn undefined(&mut self, s: &Semantics, serial: u32) -> fmt::Result {
        write!(self.out, "(undefined {serial}")?;
        if let Some(site) = s.site(serial) {
            if let Some(info) = self.declarations.site(site.site) {
                write!(self.out, " @{}", info.name)?;
                for (name, input) in info.inputs.iter().zip(&site.inputs) {
                    write!(self.out, " {name}=e{}", input.0)?;
                }
            } else {
                write!(self.out, " @{}", site.site.0)?;
                for input in &site.inputs {
                    write!(self.out, " e{}", input.0)?;
                }
            }
        }
        self.out.push(')');
        Ok(())
    }

    fn expr(&mut self, expr: Expr) -> fmt::Result {
        let out = &mut *self.out;
        match expr {
            Expr::Const(bits) => write!(out, "(const {bits})"),
            Expr::Local(local) => write!(out, "(local l{})", local.0),
            Expr::Undefined { serial, .. } => write!(out, "(undefined {serial})"),
            Expr::Unary(op, a) => write!(out, "({} e{})", name(&UNARY, op), a.0),
            Expr::Binary(op, a, b) => write!(out, "({} e{} e{})", name(&BINARY, op), a.0, b.0),
            Expr::Flag(op, a, b, c) => {
                write!(out, "({} e{} e{} e{})", name(&FLAG, op), a.0, b.0, c.0)
            }
            Expr::Extract {
                value,
                offset,
                width,
            } => write!(out, "(extract e{} {offset} {width})", value.0),
            Expr::Concat { high, low } => write!(out, "(concat e{} e{})", high.0, low.0),
            Expr::Extend { signed, value, .. } => {
                write!(
                    out,
                    "({} e{})",
                    if signed { "sext" } else { "zext" },
                    value.0
                )
            }
            Expr::Select {
                condition,
                then,
                otherwise,
            } => write!(
                out,
                "(select e{} e{} e{})",
                condition.0, then.0, otherwise.0
            ),
            Expr::Lanes {
                lanes,
                op,
                operands: [a, b, c],
            } => match op {
                LaneOp::Unary(op) => write!(out, "(lanes {lanes} {} e{})", name(&UNARY, op), a.0),
                LaneOp::Binary(op) => write!(
                    out,
                    "(lanes {lanes} {} e{} e{})",
                    name(&BINARY, op),
                    a.0,
                    b.0
                ),
                LaneOp::Extract { offset, width } => {
                    write!(out, "(lanes {lanes} extract e{} {offset} {width})", a.0)
                }
                LaneOp::Extend { signed, .. } => write!(
                    out,
                    "(lanes {lanes} {} e{})",
                    if signed { "sext" } else { "zext" },
                    a.0
                ),
                LaneOp::Select => {
                    write!(out, "(lanes {lanes} select e{} e{} e{})", a.0, b.0, c.0)
                }
            },
            Expr::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands,
            } => {
                write!(
                    out,
                    "(float {} {} {lanes} {} e{}",
                    float_name(op),
                    name(&FORMAT, format),
                    name(&OUTPUT, output),
                    rounding.0
                )?;
                for operand in operands.iter().take(op.arity()) {
                    write!(out, " e{}", operand.0)?;
                }
                out.write_char(')')
            }
        }
    }

    fn view(&mut self, view: View) -> fmt::Result {
        let register = self
            .declarations
            .info(view.register)
            .map_or("?", |info| info.name);
        write!(self.out, "{register} {} {}", view.offset, view.width)
    }

    fn block(&mut self, statements: &[Stmt], depth: usize) -> fmt::Result {
        for stmt in statements {
            self.out.push('\n');
            for _ in 0..=depth {
                self.out.push_str("  ");
            }
            self.statement(stmt, depth)?;
        }
        Ok(())
    }

    fn statement(&mut self, stmt: &Stmt, depth: usize) -> fmt::Result {
        match stmt {
            Stmt::Read { local, view } => {
                write!(self.out, "(read l{} ", local.0)?;
                self.view(*view)?;
                self.out.push(')');
            }
            Stmt::Write { view, value } => {
                self.out.push_str("(write ");
                self.view(*view)?;
                write!(self.out, " e{})", value.0)?;
            }
            Stmt::Load {
                local,
                address,
                bytes,
            } => write!(self.out, "(load l{} e{} {bytes})", local.0, address.0)?,
            Stmt::Store { address, value } => {
                write!(self.out, "(store e{} e{})", address.0, value.0)?;
            }
            Stmt::If {
                condition,
                then,
                otherwise,
            } => {
                write!(self.out, "(if e{} (then", condition.0)?;
                self.block(then, depth + 1)?;
                self.out.push_str(") (else");
                self.block(otherwise, depth + 1)?;
                self.out.push_str("))");
            }
            Stmt::Loop(body) => {
                self.out.push_str("(loop");
                self.block(body, depth + 1)?;
                self.out.push(')');
            }
            Stmt::Break => self.out.push_str("(break)"),
            Stmt::Atomic(body) => {
                self.out.push_str("(atomic");
                self.block(body, depth + 1)?;
                self.out.push(')');
            }
            Stmt::SystemCall => self.out.push_str("(system-call)"),
            Stmt::Intrinsic {
                intrinsic,
                inputs,
                outputs,
            } => {
                let name = self
                    .declarations
                    .intrinsic(*intrinsic)
                    .map_or("?", |info| info.name);
                write!(self.out, "(intrinsic {name} (")?;
                for (i, input) in inputs.iter().enumerate() {
                    let space = if i == 0 { "" } else { " " };
                    write!(self.out, "{space}e{}", input.0)?;
                }
                self.out.push_str(") (");
                for (i, output) in outputs.iter().enumerate() {
                    let space = if i == 0 { "" } else { " " };
                    write!(self.out, "{space}l{}", output.0)?;
                }
                self.out.push_str("))");
            }
            Stmt::Trap(kind) => write!(self.out, "(trap {})", trap_name(*kind))?,
            Stmt::Jump { target } => write!(self.out, "(jump e{})", target.0)?,
            Stmt::Call {
                target,
                return_address,
            } => write!(self.out, "(call e{} e{})", target.0, return_address.0)?,
            Stmt::Return { target } => write!(self.out, "(return e{})", target.0)?,
        }
        Ok(())
    }
}

/// A mistake in L0 text: what, and the byte offset where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// The byte offset.
    pub at: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at byte {}: {}", self.at, self.message)
    }
}

/// An s-expression with its byte offset.
#[derive(Debug)]
enum Sexp<'a> {
    Atom(usize, &'a str),
    List(usize, Vec<Sexp<'a>>),
}

impl Sexp<'_> {
    const fn at(&self) -> usize {
        match self {
            Self::Atom(at, _) | Self::List(at, _) => *at,
        }
    }
}

fn fail<T>(at: usize, message: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError {
        at,
        message: message.into(),
    })
}

/// Reads s-expressions (`;` starts a comment to the end of the line).
fn read(text: &str) -> Result<Vec<Sexp<'_>>, ParseError> {
    let bytes = text.as_bytes();
    let mut stack: Vec<(usize, Vec<Sexp<'_>>)> = Vec::new();
    let mut top = Vec::new();
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        match byte {
            b';' => {
                while bytes.get(i).is_some_and(|&b| b != b'\n') {
                    i += 1;
                }
            }
            b'(' => {
                stack.push((i, core::mem::take(&mut top)));
                i += 1;
            }
            b')' => {
                let Some((start, outer)) = stack.pop() else {
                    return fail(i, "unbalanced `)`");
                };
                let list = core::mem::replace(&mut top, outer);
                top.push(Sexp::List(start, list));
                i += 1;
            }
            _ if byte.is_ascii_whitespace() => i += 1,
            _ => {
                let start = i;
                while bytes.get(i).is_some_and(|&b| {
                    !b.is_ascii_whitespace() && b != b'(' && b != b')' && b != b';'
                }) {
                    i += 1;
                }
                top.push(Sexp::Atom(start, text.get(start..i).unwrap_or("")));
            }
        }
    }
    if let Some((start, _)) = stack.last() {
        return fail(*start, "unclosed `(`");
    }
    Ok(top)
}

/// Reads the text form back.
///
/// # Errors
///
/// Malformed text, unknown names, or references out of order. Widths are
/// taken as written; [`crate::verify::verify`] checks them.
pub fn parse(text: &str, declarations: &Declarations) -> Result<Semantics, ParseError> {
    let top = read(text)?;
    let [Sexp::List(at, items)] = top.as_slice() else {
        return fail(0, "expected one `(semantics ...)`");
    };
    let [Sexp::Atom(_, "semantics"), locals, exprs, body] = items.as_slice() else {
        return fail(
            *at,
            "expected `(semantics (locals ...) (exprs ...) (body ...))`",
        );
    };
    let mut parser = Parser {
        declarations,
        semantics: Semantics::default(),
    };
    for item in section(locals, "locals")? {
        parser.semantics.locals.push(number(item)?);
    }
    for (index, item) in section(exprs, "exprs")?.iter().enumerate() {
        let (expr, width, site) = parser.expr_entry(item, index)?;
        parser.semantics.exprs.push((expr, width));
        parser.semantics.sites.extend(site);
    }
    if !parser.semantics.sites.is_sorted_by_key(|site| site.serial) {
        return fail(*at, "undefined values with sites out of serial order");
    }
    parser.semantics.body = parser.block(section(body, "body")?)?;
    Ok(parser.semantics)
}

fn section<'s, 'a>(sexp: &'s Sexp<'a>, head: &str) -> Result<&'s [Sexp<'a>], ParseError> {
    match sexp {
        Sexp::List(_, items) => match items.split_first() {
            Some((Sexp::Atom(_, word), rest)) if *word == head => Ok(rest),
            _ => fail(sexp.at(), format!("expected `({head} ...)`")),
        },
        Sexp::Atom(at, _) => fail(*at, format!("expected `({head} ...)`")),
    }
}

fn atom<'a>(sexp: &Sexp<'a>) -> Result<&'a str, ParseError> {
    match sexp {
        Sexp::Atom(_, text) => Ok(text),
        Sexp::List(at, _) => fail(*at, "expected a word, found a list"),
    }
}

fn number<T: TryFrom<u64>>(sexp: &Sexp<'_>) -> Result<T, ParseError> {
    let text = atom(sexp)?;
    text.parse::<u64>()
        .ok()
        .and_then(|n| T::try_from(n).ok())
        .map_or_else(|| fail(sexp.at(), format!("bad number `{text}`")), Ok)
}

fn prefixed(sexp: &Sexp<'_>, prefix: char) -> Result<u32, ParseError> {
    let text = atom(sexp)?;
    text.strip_prefix(prefix)
        .and_then(|n| n.parse().ok())
        .map_or_else(
            || fail(sexp.at(), format!("expected `{prefix}N`, found `{text}`")),
            Ok,
        )
}

/// A hexadecimal constant `0x...` of `width` bits.
fn constant(sexp: &Sexp<'_>, width: u16) -> Result<Bits, ParseError> {
    let text = atom(sexp)?;
    let Some(digits) = text.strip_prefix("0x") else {
        return fail(sexp.at(), format!("expected `0x...`, found `{text}`"));
    };
    let mut bytes = Vec::new();
    let mut end = digits.len();
    while end > 0 {
        let start = end.saturating_sub(2);
        let Some(byte) = digits
            .get(start..end)
            .and_then(|d| u8::from_str_radix(d, 16).ok())
        else {
            return fail(sexp.at(), format!("bad hexadecimal `{text}`"));
        };
        bytes.push(byte);
        end = start;
    }
    Ok(Bits::from_le_bytes(width, &bytes))
}

struct Parser<'a> {
    declarations: &'a Declarations,
    semantics: Semantics,
}

impl Parser<'_> {
    fn expr_ref(&self, sexp: &Sexp<'_>) -> Result<ExprId, ParseError> {
        let index = prefixed(sexp, 'e')?;
        if index as usize >= self.semantics.exprs.len() {
            return fail(sexp.at(), format!("e{index} used before it is defined"));
        }
        Ok(ExprId(index))
    }

    /// One `(eN width (...))`, and the site of an undefined value.
    fn expr_entry(
        &self,
        sexp: &Sexp<'_>,
        index: usize,
    ) -> Result<(Expr, u16, Option<SiteUse>), ParseError> {
        let Sexp::List(at, items) = sexp else {
            return fail(sexp.at(), "expected `(eN width (...))`");
        };
        let [id, width, body] = items.as_slice() else {
            return fail(*at, "expected `(eN width (...))`");
        };
        if prefixed(id, 'e')? as usize != index {
            return fail(id.at(), format!("expected e{index}"));
        }
        let width: u16 = number(width)?;
        let Sexp::List(at, parts) = body else {
            return fail(body.at(), "expected an operation in parentheses");
        };
        let Some((head, args)) = parts.split_first() else {
            return fail(*at, "empty operation");
        };
        let head = atom(head)?;
        if head == "undefined" {
            return self.undefined(*at, args, width);
        }
        let e = |i: usize| -> Result<ExprId, ParseError> {
            args.get(i).map_or_else(
                || fail(*at, format!("`{head}` needs more operands")),
                |a| self.expr_ref(a),
            )
        };
        let arity = |n: usize| -> Result<(), ParseError> {
            if args.len() == n {
                Ok(())
            } else {
                fail(*at, format!("`{head}` takes {n} operands"))
            }
        };
        let expr = if let Some(op) = lookup(&UNARY, head) {
            arity(1)?;
            Expr::Unary(op, e(0)?)
        } else if let Some(op) = lookup(&BINARY, head) {
            arity(2)?;
            Expr::Binary(op, e(0)?, e(1)?)
        } else if let Some(op) = lookup(&FLAG, head) {
            arity(3)?;
            Expr::Flag(op, e(0)?, e(1)?, e(2)?)
        } else {
            match head {
                "const" => {
                    arity(1)?;
                    match args.first() {
                        Some(value) => Expr::Const(constant(value, width)?),
                        None => return fail(*at, "`const` needs a value"),
                    }
                }
                "local" => {
                    arity(1)?;
                    let local = args.first().map_or(Ok(0), |a| prefixed(a, 'l'))?;
                    Expr::Local(Local(local))
                }
                "extract" => {
                    arity(3)?;
                    let offset = args.get(1).map_or(Ok(0), |a| number(a))?;
                    let own = args.get(2).map_or(Ok(0), |a| number(a))?;
                    Expr::Extract {
                        value: e(0)?,
                        offset,
                        width: own,
                    }
                }
                "concat" => {
                    arity(2)?;
                    Expr::Concat {
                        high: e(0)?,
                        low: e(1)?,
                    }
                }
                "zext" | "sext" => {
                    arity(1)?;
                    Expr::Extend {
                        signed: head == "sext",
                        value: e(0)?,
                        width,
                    }
                }
                "select" => {
                    arity(3)?;
                    Expr::Select {
                        condition: e(0)?,
                        then: e(1)?,
                        otherwise: e(2)?,
                    }
                }
                "lanes" => self.lanes(*at, args, width)?,
                "float" => self.float(*at, args)?,
                _ => return fail(*at, format!("unknown operation `{head}`")),
            }
        };
        Ok((expr, width, None))
    }

    /// `(undefined serial [@site input=eN ...])`, `width` bits wide.
    fn undefined(
        &self,
        at: usize,
        args: &[Sexp<'_>],
        width: u16,
    ) -> Result<(Expr, u16, Option<SiteUse>), ParseError> {
        let Some((serial, site)) = args.split_first() else {
            return fail(at, "`undefined` needs a serial");
        };
        let serial = number(serial)?;
        let site_use = match site.split_first() {
            Some((name, inputs)) => Some(self.site_use(serial, name, inputs)?),
            None => None,
        };
        Ok((Expr::Undefined { width, serial }, width, site_use))
    }

    /// The site of undefined value `serial`: `@name input=eN ...`, the
    /// inputs named as the site declares them.
    fn site_use(
        &self,
        serial: u32,
        name: &Sexp<'_>,
        inputs: &[Sexp<'_>],
    ) -> Result<SiteUse, ParseError> {
        let text = atom(name)?;
        let Some(site) = text
            .strip_prefix('@')
            .and_then(|name| self.declarations.find_site(name))
        else {
            return fail(name.at(), format!("unknown site `{text}`"));
        };
        let declared = self
            .declarations
            .site(site)
            .map_or(&[][..], |info| info.inputs);
        if declared.len() != inputs.len() {
            return fail(
                name.at(),
                format!("`{text}` takes {} inputs", declared.len()),
            );
        }
        let inputs = inputs
            .iter()
            .zip(declared)
            .map(|(input, expected)| {
                let text = atom(input)?;
                match text.split_once('=') {
                    Some((name, value)) if name == *expected => {
                        self.expr_ref(&Sexp::Atom(input.at() + name.len() + 1, value))
                    }
                    _ => fail(input.at(), format!("expected `{expected}=eN`")),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SiteUse {
            serial,
            site,
            inputs,
        })
    }

    /// `(lanes N op operands...)`, `width` bits wide.
    fn lanes(&self, at: usize, args: &[Sexp<'_>], width: u16) -> Result<Expr, ParseError> {
        let [count, op, rest @ ..] = args else {
            return fail(at, "expected `(lanes N op operands...)`");
        };
        let lanes: u16 = number(count)?;
        let head = atom(op)?;
        let refs = |n: usize| -> Result<[ExprId; 3], ParseError> {
            let operands = rest
                .get(..n)
                .filter(|_| rest.len() >= n)
                .map_or_else(|| fail(at, format!("`{head}` lanes take {n} operands")), Ok)?;
            let mut ids = [ExprId(0); 3];
            for (index, operand) in operands.iter().enumerate() {
                let id = self.expr_ref(operand)?;
                if let Some(slot) = ids.get_mut(index) {
                    *slot = id;
                }
            }
            repeat_first(&mut ids, n);
            Ok(ids)
        };
        let exact = |n: usize| -> Result<(), ParseError> {
            if rest.len() == n {
                Ok(())
            } else {
                fail(at, format!("`{head}` lanes take {n} operands"))
            }
        };
        let op = if let Some(op) = lookup(&UNARY, head) {
            exact(1)?;
            LaneOp::Unary(op)
        } else if let Some(op) = lookup(&BINARY, head) {
            exact(2)?;
            LaneOp::Binary(op)
        } else {
            match head {
                "extract" => {
                    exact(3)?;
                    LaneOp::Extract {
                        offset: rest.get(1).map_or(Ok(0), |a| number(a))?,
                        width: rest.get(2).map_or(Ok(0), |a| number(a))?,
                    }
                }
                "zext" | "sext" => {
                    exact(1)?;
                    if lanes == 0 || !width.is_multiple_of(lanes) {
                        return fail(at, format!("{width} bits do not split into {lanes} lanes"));
                    }
                    LaneOp::Extend {
                        signed: head == "sext",
                        width: width / lanes,
                    }
                }
                "select" => {
                    exact(3)?;
                    LaneOp::Select
                }
                _ => return fail(at, format!("unknown lane operation `{head}`")),
            }
        };
        Ok(Expr::Lanes {
            lanes,
            op,
            operands: refs(op.arity())?,
        })
    }

    /// `(float op format N output rounding operands...)`.
    fn float(&self, at: usize, args: &[Sexp<'_>]) -> Result<Expr, ParseError> {
        let [op, format, count, output, rounding, rest @ ..] = args else {
            return fail(
                at,
                "expected `(float op format N output rounding operands...)`",
            );
        };
        let text = atom(op)?;
        let Some(op) = float_op(text) else {
            return fail(
                op.at(),
                format!("unknown floating-point operation `{text}`"),
            );
        };
        let format_text = atom(format)?;
        let Some(format) = lookup(&FORMAT, format_text) else {
            return fail(format.at(), format!("unknown format `{format_text}`"));
        };
        let output_text = atom(output)?;
        let Some(output) = lookup(&OUTPUT, output_text) else {
            return fail(output.at(), format!("unknown output `{output_text}`"));
        };
        if rest.len() != op.arity() {
            return fail(at, format!("`{text}` takes {} operands", op.arity()));
        }
        let mut operands = [ExprId(0); 3];
        for (slot, operand) in operands.iter_mut().zip(rest) {
            *slot = self.expr_ref(operand)?;
        }
        repeat_first(&mut operands, op.arity());
        Ok(Expr::Float {
            op,
            format,
            lanes: number(count)?,
            output,
            rounding: self.expr_ref(rounding)?,
            operands,
        })
    }

    fn view(&self, parts: &[Sexp<'_>]) -> Result<View, ParseError> {
        let [register, offset, width] = parts else {
            let at = parts.first().map_or(0, Sexp::at);
            return fail(at, "expected `register offset width`");
        };
        let name = atom(register)?;
        let Some(id) = self.declarations.find(name) else {
            return fail(register.at(), format!("unknown register `{name}`"));
        };
        Ok(View {
            register: id,
            offset: number(offset)?,
            width: number(width)?,
        })
    }

    fn local(&self, sexp: &Sexp<'_>) -> Result<Local, ParseError> {
        let index = prefixed(sexp, 'l')?;
        if index as usize >= self.semantics.locals.len() {
            return fail(sexp.at(), format!("no local l{index}"));
        }
        Ok(Local(index))
    }

    fn block(&self, items: &[Sexp<'_>]) -> Result<Vec<Stmt>, ParseError> {
        items.iter().map(|item| self.statement(item)).collect()
    }

    fn statement(&self, sexp: &Sexp<'_>) -> Result<Stmt, ParseError> {
        let Sexp::List(at, parts) = sexp else {
            return fail(sexp.at(), "expected a statement in parentheses");
        };
        let Some((head, args)) = parts.split_first() else {
            return fail(*at, "empty statement");
        };
        let head = atom(head)?;
        let bad = || fail(*at, format!("malformed `{head}`"));
        Ok(match (head, args) {
            ("read", [local, view @ ..]) => Stmt::Read {
                local: self.local(local)?,
                view: self.view(view)?,
            },
            ("write", [view @ .., value]) => Stmt::Write {
                view: self.view(view)?,
                value: self.expr_ref(value)?,
            },
            ("load", [local, address, bytes]) => Stmt::Load {
                local: self.local(local)?,
                address: self.expr_ref(address)?,
                bytes: number(bytes)?,
            },
            ("store", [address, value]) => Stmt::Store {
                address: self.expr_ref(address)?,
                value: self.expr_ref(value)?,
            },
            ("if", [condition, then, otherwise]) => Stmt::If {
                condition: self.expr_ref(condition)?,
                then: self.block(section(then, "then")?)?,
                otherwise: self.block(section(otherwise, "else")?)?,
            },
            ("loop", body) => Stmt::Loop(self.block(body)?),
            ("break", []) => Stmt::Break,
            ("atomic", body) => Stmt::Atomic(self.block(body)?),
            ("system-call", []) => Stmt::SystemCall,
            ("intrinsic", [name, Sexp::List(_, inputs), Sexp::List(_, outputs)]) => {
                let text = atom(name)?;
                let Some(intrinsic) = self.declarations.find_intrinsic(text) else {
                    return fail(name.at(), format!("unknown intrinsic `{text}`"));
                };
                Stmt::Intrinsic {
                    intrinsic,
                    inputs: inputs
                        .iter()
                        .map(|input| self.expr_ref(input))
                        .collect::<Result<_, _>>()?,
                    outputs: outputs
                        .iter()
                        .map(|output| self.local(output))
                        .collect::<Result<_, _>>()?,
                }
            }
            ("trap", [kind]) => {
                let kind = atom(kind)?;
                Stmt::Trap(
                    trap(kind).map_or_else(|| fail(*at, format!("unknown trap `{kind}`")), Ok)?,
                )
            }
            ("jump", [target]) => Stmt::Jump {
                target: self.expr_ref(target)?,
            },
            ("call", [target, return_address]) => Stmt::Call {
                target: self.expr_ref(target)?,
                return_address: self.expr_ref(return_address)?,
            },
            ("return", [target]) => Stmt::Return {
                target: self.expr_ref(target)?,
            },
            _ => return bad(),
        })
    }
}
