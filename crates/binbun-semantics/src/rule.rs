//! Rules: what a processor does at a site ([`crate::ir::SiteInfo`]), as an
//! expression over the site's named inputs.
//!
//! ```text
//! rule  := expr
//! expr  := literal | input | "osz" | name "(" expr { "," expr } ")"
//!        | "!" expr | expr binop expr | "(" expr ")"
//!        | "if" expr "{" expr "}" "else" "{" expr "}"
//! name  := msb | bit | bits | parity8 | zext | sext | trunc | popcount
//! binop := ^ & | + - << >> == != < <=      (Rust's precedence)
//! ```
//!
//! - An input is named as its site declares it (`dst`, `count`, `old`,
//!   `defined.dst`); `osz` is the width of the first input.
//! - Widths follow from the inputs: a literal takes its operand's width;
//!   operands of different widths are zero-extended to the wider; a
//!   comparison is 1 bit; a shift's count is cut or extended to the
//!   value's width; `msb(x)`, `bit(x, i)` (bit `i`, 0 past the width) and
//!   `parity8(x)` (1 if the low byte has even parity) are 1 bit;
//!   `bits(x, offset, width)`, `zext`, `sext` and `trunc` take widths and
//!   offsets known from `osz` and literals.
//! - A rule is width-generic: [`Rule::instantiate`] makes L0 expressions of
//!   it for one form's input widths ([`Compiled`]), which evaluate with
//!   undefined bits tracked as the interpreter does ([`Compiled::eval`])
//!   and can stand in for the undefined value in the instruction's
//!   semantics ([`Compiled::emit`]).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::bits::Bits;
use crate::interpret::{self, Value};
use crate::ir::{Binary, Expr, ExprId, Local, Unary};

/// Why a rule cannot be read or made for some widths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleError(pub String);

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail<T>(message: impl Into<String>) -> Result<T, RuleError> {
    Err(RuleError(message.into()))
}

/// A built-in function of the rule language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Function {
    Msb,
    Bit,
    Bits,
    Parity8,
    Zext,
    Sext,
    Trunc,
    Popcount,
}

const FUNCTIONS: [(&str, Function, usize); 8] = [
    ("msb", Function::Msb, 1),
    ("bit", Function::Bit, 2),
    ("bits", Function::Bits, 3),
    ("parity8", Function::Parity8, 1),
    ("zext", Function::Zext, 2),
    ("sext", Function::Sext, 2),
    ("trunc", Function::Trunc, 2),
    ("popcount", Function::Popcount, 1),
];

/// A binary operator, with its precedence (higher binds tighter) and L0
/// operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Operator {
    text: &'static str,
    precedence: u8,
    op: Binary,
}

const OPERATORS: [Operator; 12] = [
    Operator {
        text: "<<",
        precedence: 6,
        op: Binary::Shl,
    },
    Operator {
        text: ">>",
        precedence: 6,
        op: Binary::LShr,
    },
    Operator {
        text: "==",
        precedence: 2,
        op: Binary::Eq,
    },
    Operator {
        text: "!=",
        precedence: 2,
        op: Binary::Ne,
    },
    Operator {
        text: "<=",
        precedence: 2,
        op: Binary::ULe,
    },
    Operator {
        text: "<",
        precedence: 2,
        op: Binary::ULt,
    },
    Operator {
        text: "+",
        precedence: 7,
        op: Binary::Add,
    },
    Operator {
        text: "-",
        precedence: 7,
        op: Binary::Sub,
    },
    Operator {
        text: "&",
        precedence: 5,
        op: Binary::And,
    },
    Operator {
        text: "^",
        precedence: 4,
        op: Binary::Xor,
    },
    Operator {
        text: "|",
        precedence: 3,
        op: Binary::Or,
    },
    Operator {
        text: "*",
        precedence: 8,
        op: Binary::Mul,
    },
];

/// A rule's syntax tree.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Literal(u64),
    Input(usize),
    Osz,
    Not(Box<Node>),
    Binary(Binary, Box<Node>, Box<Node>),
    If(Box<Node>, Box<Node>, Box<Node>),
    Call(Function, Vec<Node>),
}

/// A rule over a site's inputs, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    text: String,
    root: Node,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Splits rule text into tokens: names (with dots), numbers, operators and
/// punctuation.
fn tokens(text: &str) -> Result<Vec<&str>, RuleError> {
    let mut out = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let first = rest.chars().next().unwrap_or(' ');
        let length = if first.is_ascii_alphanumeric() || first == '_' {
            rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .unwrap_or(rest.len())
        } else if ["<<", ">>", "==", "!=", "<="]
            .iter()
            .any(|op| rest.starts_with(op))
        {
            2
        } else if "()+-*&^|<!,{}".contains(first) {
            1
        } else {
            return fail(format!("unexpected `{first}` in `{text}`"));
        };
        let (token, after) = rest.split_at(length);
        out.push(token);
        rest = after.trim_start();
    }
    Ok(out)
}

struct Parser<'a> {
    tokens: Vec<&'a str>,
    at: usize,
    inputs: &'a [&'a str],
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.tokens.get(self.at).copied()
    }

    fn next(&mut self) -> Result<&'a str, RuleError> {
        let token = self
            .peek()
            .ok_or_else(|| RuleError("unexpected end".into()))?;
        self.at += 1;
        Ok(token)
    }

    fn expect(&mut self, wanted: &str) -> Result<(), RuleError> {
        match self.next()? {
            token if token == wanted => Ok(()),
            token => fail(format!("expected `{wanted}`, found `{token}`")),
        }
    }

    fn expr(&mut self, least: u8) -> Result<Node, RuleError> {
        let mut left = self.primary()?;
        while let Some(operator) = self
            .peek()
            .and_then(|token| OPERATORS.iter().find(|o| o.text == token))
            .filter(|o| o.precedence >= least)
        {
            self.at += 1;
            let right = self.expr(operator.precedence + 1)?;
            left = Node::Binary(operator.op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn primary(&mut self) -> Result<Node, RuleError> {
        let token = self.next()?;
        match token {
            "(" => {
                let inner = self.expr(0)?;
                self.expect(")")?;
                Ok(inner)
            }
            "!" => Ok(Node::Not(Box::new(self.primary()?))),
            "if" => {
                let condition = self.expr(0)?;
                self.expect("{")?;
                let then = self.expr(0)?;
                self.expect("}")?;
                self.expect("else")?;
                self.expect("{")?;
                let otherwise = self.expr(0)?;
                self.expect("}")?;
                Ok(Node::If(
                    Box::new(condition),
                    Box::new(then),
                    Box::new(otherwise),
                ))
            }
            "osz" => Ok(Node::Osz),
            _ if token.starts_with(|c: char| c.is_ascii_digit()) => {
                let digits = token.replace('_', "");
                let value = match digits.strip_prefix("0x") {
                    Some(hex) => u64::from_str_radix(hex, 16),
                    None => digits.parse(),
                };
                value
                    .map(Node::Literal)
                    .map_err(|_| RuleError(format!("bad number `{token}`")))
            }
            _ => {
                if let Some(&(_, function, arity)) =
                    FUNCTIONS.iter().find(|(name, ..)| *name == token)
                {
                    self.expect("(")?;
                    let mut args = vec![self.expr(0)?];
                    while self.peek() == Some(",") {
                        self.at += 1;
                        args.push(self.expr(0)?);
                    }
                    self.expect(")")?;
                    if args.len() != arity {
                        return fail(format!("`{token}` takes {arity} arguments"));
                    }
                    return Ok(Node::Call(function, args));
                }
                match self.inputs.iter().position(|name| *name == token) {
                    Some(index) => Ok(Node::Input(index)),
                    None => fail(format!("no input `{token}`")),
                }
            }
        }
    }
}

impl Rule {
    /// Reads `text`, a rule over inputs named `inputs` (in order).
    ///
    /// # Errors
    ///
    /// Text that is not a rule, or names no input of these.
    pub fn parse(text: &str, inputs: &[&str]) -> Result<Self, RuleError> {
        let mut parser = Parser {
            tokens: tokens(text)?,
            at: 0,
            inputs,
        };
        let root = parser.expr(0)?;
        if let Some(token) = parser.peek() {
            return fail(format!("unexpected `{token}` in `{text}`"));
        }
        Ok(Self {
            text: text.trim().to_string(),
            root,
        })
    }

    /// The text it was read from.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The rule for inputs of `widths` (in order), giving `width` bits.
    ///
    /// # Errors
    ///
    /// The rule does not fit these widths (an input of the wrong width for
    /// an operation, a result of another width).
    pub fn instantiate(&self, widths: &[u16], width: u16) -> Result<Compiled, RuleError> {
        let mut compiler = Compiling {
            exprs: widths
                .iter()
                .zip(0u32..)
                .map(|(&width, i)| (Expr::Local(Local(i)), width))
                .collect(),
            osz: widths.first().copied().unwrap_or(0),
        };
        let (result, own) = compiler.node(&self.root, Some(width))?;
        if own != width {
            return fail(format!("{own} bits, not {width}"));
        }
        Ok(Compiled {
            exprs: compiler.exprs,
            inputs: widths.len(),
            result,
        })
    }
}

/// A rule made for some input widths: L0 expressions whose first ones are
/// `Expr::Local(i)` for input `i`, and the one that is the rule's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    exprs: Vec<(Expr, u16)>,
    inputs: usize,
    result: ExprId,
}

struct Compiling {
    exprs: Vec<(Expr, u16)>,
    osz: u16,
}

/// An expression and its width.
type Sized2 = (ExprId, u16);

impl Compiling {
    fn add(&mut self, expr: Expr, width: u16) -> (ExprId, u16) {
        let id = ExprId(u32::try_from(self.exprs.len()).unwrap_or(u32::MAX));
        self.exprs.push((expr, width));
        (id, width)
    }

    fn constant(&mut self, width: u16, value: u64) -> (ExprId, u16) {
        self.add(Expr::Const(Bits::from_u64(width, value)), width)
    }

    /// `node`'s value if it is known without inputs (literals and `osz`).
    fn fixed(&self, node: &Node) -> Option<u64> {
        match node {
            Node::Literal(value) => Some(*value),
            Node::Osz => Some(u64::from(self.osz)),
            Node::Binary(op, a, b) => {
                let (a, b) = (self.fixed(a)?, self.fixed(b)?);
                match op {
                    Binary::Add => Some(a.wrapping_add(b)),
                    Binary::Sub => Some(a.wrapping_sub(b)),
                    Binary::Mul => Some(a.wrapping_mul(b)),
                    Binary::UDiv
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
                    | Binary::Ror
                    | Binary::Eq
                    | Binary::Ne
                    | Binary::ULt
                    | Binary::ULe
                    | Binary::SLt
                    | Binary::SLe => None,
                }
            }
            Node::Input(_) | Node::Not(_) | Node::If(..) | Node::Call(..) => None,
        }
    }

    /// A width or offset known without inputs.
    fn small(&self, node: &Node) -> Result<u16, RuleError> {
        self.fixed(node)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| RuleError("a width or offset must be known from osz and numbers".into()))
    }

    /// `id` (of `own` bits) made `width` bits: zero-extended or cut.
    fn fit(&mut self, (id, own): (ExprId, u16), width: u16) -> (ExprId, u16) {
        match own.cmp(&width) {
            core::cmp::Ordering::Equal => (id, own),
            core::cmp::Ordering::Less => self.add(
                Expr::Extend {
                    signed: false,
                    value: id,
                    width,
                },
                width,
            ),
            core::cmp::Ordering::Greater => self.add(
                Expr::Extract {
                    value: id,
                    offset: 0,
                    width,
                },
                width,
            ),
        }
    }

    /// Two operands of one width: a literal takes the other's, else the
    /// narrower is zero-extended.
    fn pair(&mut self, a: &Node, b: &Node, hint: Option<u16>) -> Result<[Sized2; 2], RuleError> {
        let (a, b) = match (self.fixed(a), self.fixed(b)) {
            (Some(_), None) => {
                let b = self.node(b, hint)?;
                (self.node(a, Some(b.1))?, b)
            }
            (None, Some(_)) => {
                let a = self.node(a, hint)?;
                let b = self.node(b, Some(a.1))?;
                (a, b)
            }
            _ => (self.node(a, hint)?, self.node(b, hint)?),
        };
        let width = a.1.max(b.1);
        Ok([self.fit(a, width), self.fit(b, width)])
    }

    fn node(&mut self, node: &Node, hint: Option<u16>) -> Result<(ExprId, u16), RuleError> {
        Ok(match node {
            Node::Literal(_) | Node::Osz => {
                let value = self.fixed(node).unwrap_or(0);
                let Some(width) = hint else {
                    return fail("a number whose width nothing gives");
                };
                self.constant(width, value)
            }
            Node::Input(index) => {
                let width = self.exprs.get(*index).map_or(0, |&(_, w)| w);
                (ExprId(u32::try_from(*index).unwrap_or(u32::MAX)), width)
            }
            Node::Not(a) => {
                let (a, width) = self.node(a, hint)?;
                self.add(Expr::Unary(Unary::Not, a), width)
            }
            Node::Binary(op @ (Binary::Shl | Binary::LShr), value, count) => {
                let value = self.node(value, hint)?;
                let count = if let Some(n) = self.fixed(count) {
                    self.constant(value.1, n)
                } else {
                    let count = self.node(count, None)?;
                    self.fit(count, value.1)
                };
                self.add(Expr::Binary(*op, value.0, count.0), value.1)
            }
            Node::Binary(op, a, b) => {
                let compare = matches!(op, Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe);
                let [(a, width), (b, _)] = self.pair(a, b, if compare { None } else { hint })?;
                self.add(Expr::Binary(*op, a, b), if compare { 1 } else { width })
            }
            Node::If(condition, then, otherwise) => {
                let condition = self.node(condition, None)?;
                let condition = if condition.1 == 1 {
                    condition
                } else {
                    let zero = self.constant(condition.1, 0);
                    self.add(Expr::Binary(Binary::Ne, condition.0, zero.0), 1)
                };
                let [(then, width), (otherwise, _)] = self.pair(then, otherwise, hint)?;
                self.add(
                    Expr::Select {
                        condition: condition.0,
                        then,
                        otherwise,
                    },
                    width,
                )
            }
            Node::Call(function, args) => self.call(*function, args)?,
        })
    }

    fn call(&mut self, function: Function, args: &[Node]) -> Result<(ExprId, u16), RuleError> {
        let arg = |i: usize| {
            args.get(i)
                .ok_or_else(|| RuleError("too few arguments".into()))
        };
        let extract = |c: &mut Self, (value, own): (ExprId, u16), offset: u16, width: u16| {
            if u32::from(offset) + u32::from(width) > u32::from(own) || width == 0 {
                return fail(format!("bits {offset}..+{width} of a {own}-bit value"));
            }
            Ok(c.add(
                Expr::Extract {
                    value,
                    offset,
                    width,
                },
                width,
            ))
        };
        Ok(match function {
            Function::Msb => {
                let value = self.node(arg(0)?, None)?;
                let Some(top) = value.1.checked_sub(1) else {
                    return fail("msb of no bits");
                };
                extract(self, value, top, 1)?
            }
            Function::Bit => {
                let value = self.node(arg(0)?, None)?;
                if let Some(index) = self.fixed(arg(1)?) {
                    match u16::try_from(index) {
                        Ok(index) if index < value.1 => extract(self, value, index, 1)?,
                        _ => self.constant(1, 0),
                    }
                } else {
                    let index = self.node(arg(1)?, None)?;
                    let index = self.fit(index, value.1);
                    let shifted = self.add(Expr::Binary(Binary::LShr, value.0, index.0), value.1);
                    extract(self, shifted, 0, 1)?
                }
            }
            Function::Bits => {
                let value = self.node(arg(0)?, None)?;
                let offset = self.small(arg(1)?)?;
                let width = self.small(arg(2)?)?;
                extract(self, value, offset, width)?
            }
            Function::Parity8 => {
                let value = self.node(arg(0)?, None)?;
                let value = if value.1 < 8 {
                    self.fit(value, 8)
                } else {
                    value
                };
                self.add(Expr::Unary(Unary::EvenParity8, value.0), 1)
            }
            Function::Popcount => {
                let (value, width) = self.node(arg(0)?, None)?;
                self.add(Expr::Unary(Unary::Popcount, value), width)
            }
            Function::Zext | Function::Sext => {
                let value = self.node(arg(0)?, None)?;
                let width = self.small(arg(1)?)?;
                if width <= value.1 {
                    return fail(format!("extension of {} bits to {width}", value.1));
                }
                self.add(
                    Expr::Extend {
                        signed: function == Function::Sext,
                        value: value.0,
                        width,
                    },
                    width,
                )
            }
            Function::Trunc => {
                let value = self.node(arg(0)?, None)?;
                let width = self.small(arg(1)?)?;
                extract(self, value, 0, width)?
            }
        })
    }
}

impl Compiled {
    /// Its value for inputs with `inputs` values (undefined input bits
    /// make what depends on them undefined, as in the interpreter).
    ///
    /// # Errors
    ///
    /// Inputs of other widths or another number than it was made for.
    pub fn eval(&self, inputs: &[Value]) -> Result<Value, RuleError> {
        if inputs.len() != self.inputs {
            return fail(format!("{} inputs, not {}", inputs.len(), self.inputs));
        }
        let mut values: Vec<Value> = Vec::with_capacity(self.exprs.len());
        let get = |values: &[Value], id: ExprId| {
            values
                .get(id.0 as usize)
                .copied()
                .ok_or_else(|| RuleError(format!("e{} before it is made", id.0)))
        };
        for &(expr, width) in &self.exprs {
            let value = match expr {
                Expr::Local(local) => {
                    let value = inputs
                        .get(local.0 as usize)
                        .copied()
                        .ok_or_else(|| RuleError("no such input".into()))?;
                    if value.width() != width {
                        return fail(format!("a {}-bit input for {width} bits", value.width()));
                    }
                    value
                }
                Expr::Const(bits) => Value::defined(bits),
                Expr::Unary(op, a) => interpret::unary(op, get(&values, a)?),
                Expr::Binary(op, a, b) => interpret::binary(op, get(&values, a)?, get(&values, b)?),
                Expr::Extract {
                    value,
                    offset,
                    width,
                } => interpret::extract(get(&values, value)?, offset, width),
                Expr::Extend {
                    signed,
                    value,
                    width,
                } => interpret::extend(signed, get(&values, value)?, width),
                Expr::Select {
                    condition,
                    then,
                    otherwise,
                } => interpret::select(
                    get(&values, condition)?,
                    get(&values, then)?,
                    get(&values, otherwise)?,
                ),
                Expr::Undefined { .. }
                | Expr::Flag(..)
                | Expr::Concat { .. }
                | Expr::Lanes { .. }
                | Expr::Float { .. } => return fail("not a rule's expression"),
            };
            values.push(value);
        }
        get(&values, self.result)
    }

    /// Appends its expressions to `exprs` (a semantics' expressions), its
    /// inputs being the expressions `inputs`: the expression that is its
    /// value.
    pub fn emit(&self, exprs: &mut Vec<(Expr, u16)>, inputs: &[ExprId]) -> ExprId {
        let mut ids: Vec<ExprId> = Vec::with_capacity(self.exprs.len());
        for &(expr, width) in &self.exprs {
            let id = if let Expr::Local(local) = expr {
                inputs
                    .get(local.0 as usize)
                    .copied()
                    .unwrap_or(ExprId(u32::MAX))
            } else {
                let expr = expr.map_operands(&mut |id| {
                    ids.get(id.0 as usize).copied().unwrap_or(ExprId(u32::MAX))
                });
                exprs.push((expr, width));
                ExprId(u32::try_from(exprs.len() - 1).unwrap_or(u32::MAX))
            };
            ids.push(id);
        }
        ids.get(self.result.0 as usize)
            .copied()
            .unwrap_or(ExprId(u32::MAX))
    }
}
