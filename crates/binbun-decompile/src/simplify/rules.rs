//! Rewrite rules as data, compiled and proved.
//!
//! The rules live in `crates/binbun-decompile/rules/*.rules` (one group
//! per file), in a small language over L2 expressions with L0's
//! operators; `cargo xtask codegen` compiles them into [`RULES`] (each
//! rule as data: what the proof reads) and a matcher (Rust, checked in,
//! `generated.rs`), and the test `rules` proves every rule with z3 at
//! every width it claims. A rule:
//!
//! ```text
//! rule slt-of-sign: ne(lshr(x:W, #c), 0) => slt(x, 0) if eq(#c, {W-1})
//! ```
//!
//! - Pattern variables (`x`, `y`, …) match any expression; one written
//!   twice on the left matches the same tree twice, and only one with no
//!   undefined part (two evaluations of it then agree).
//! - Constants (`#c`) match constant expressions; literals (`0`, `-1`,
//!   `0x80`) match and make constants of the width the context gives;
//!   `{W-1}` is a literal whose value is a width.
//! - Width variables (`W`, `N`, …) are bound by what the left side
//!   matches (`x:W` annotates a variable's width); each ranges over the
//!   widths it claims (8, 16, 32 and 64 unless the rule says
//!   `widths W in 1 8 16 32 64`), and the matcher applies the rule at
//!   those widths only.
//! - Side conditions after `if`: width relations (`N < W`) and 1-bit L0
//!   expressions over the constants (`eq(#c, {W-1})`), evaluated with
//!   L0's operations by the matcher and encoded by L0's SMT encoding in
//!   the proof.
//!
//! The matcher adds what the proof cannot see: a variable the right side
//! drops is only dropped if it cannot fault (a load's fault is kept);
//! one the right side uses more often than the left has no undefined
//! part and makes no call (which would then be made twice); if the right
//! side evaluates variables in another order than the left, at most one
//! of them may fault (a call counting as one).
//!
//! [`Rewrite`] applies the rules bottom-up (operands first) to every
//! expression of the function, and after each rewrite to what it built,
//! with constant folding (an operation on constants is its value, by L0's
//! interpreter), to a fixed point within fuel.

mod generated;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Block, Expr, ExprId, Function, StmtId};
use binbun_ast::verify::expr_width;
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::interpret::{self, Value};
use binbun_semantics::ir::{Binary, Flag, Unary};

use super::expr::{Info, append, dropped, map_roots, roots, same};
use crate::pass::{L2Env, size};

pub use generated::RULES;

/// A width: `constant` plus the sum of each coefficient times its width
/// variable's value (by index into [`Rule::widths`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Width {
    /// The constant part.
    pub constant: i32,
    /// `(variable, coefficient)` pairs.
    pub terms: &'static [(u8, i32)],
}

impl Width {
    /// Its value when the width variables have `values`.
    pub fn eval(&self, values: &[i64]) -> Option<i64> {
        self.terms
            .iter()
            .try_fold(i64::from(self.constant), |sum, &(var, coefficient)| {
                let value = values.get(usize::from(var))?;
                sum.checked_add(value.checked_mul(i64::from(coefficient))?)
            })
    }
}

/// The value of a [`Node::Literal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Literal {
    /// An integer, sign-extended (or truncated) to the literal's width.
    Int(i64),
    /// The value of a width.
    Width(Width),
}

/// A node of a rule's side: operands are indices of earlier nodes of the
/// same side (the last node is the root).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    /// Pattern variable (index into [`Rule::vars`]).
    Var(u8),
    /// Constant variable (index into [`Rule::constants`]).
    Const(u8),
    /// A constant of a known value.
    Literal {
        /// Its value.
        value: Literal,
        /// Its width.
        width: Width,
    },
    /// An operation of one operand.
    Unary(Unary, u8),
    /// An operation of two operands.
    Binary(Binary, u8, u8),
    /// A flag computation.
    Flag(Flag, u8, u8, u8),
    /// Bits of a value.
    Extract {
        /// The value.
        value: u8,
        /// The first bit.
        offset: Width,
        /// How many bits.
        width: Width,
    },
    /// Two values side by side.
    Concat {
        /// The high part.
        high: u8,
        /// The low part.
        low: u8,
    },
    /// An extension.
    Extend {
        /// Sign (true) or zero.
        signed: bool,
        /// The value.
        value: u8,
        /// The resulting width.
        width: Width,
    },
    /// A choice.
    Select {
        /// The 1-bit condition.
        condition: u8,
        /// The value if it holds.
        then: u8,
        /// The value if not.
        otherwise: u8,
    },
}

/// How a [`Constraint`] relates two widths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
}

impl Relation {
    /// Whether `left` relates so to `right`.
    pub fn holds(self, left: i64, right: i64) -> bool {
        match self {
            Self::Eq => left == right,
            Self::Ne => left != right,
            Self::Lt => left < right,
            Self::Le => left <= right,
        }
    }
}

/// A side condition on widths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Constraint {
    /// The left width.
    pub left: Width,
    /// The relation.
    pub relation: Relation,
    /// The right width.
    pub right: Width,
}

/// A width variable and the widths it claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WidthVar {
    /// Its name.
    pub name: &'static str,
    /// The widths the rule is proved at and applied at.
    pub claimed: &'static [u16],
}

/// A rewrite rule, as `cargo xtask codegen` compiled it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Its name, unique.
    pub name: &'static str,
    /// Its group (the file it is in).
    pub group: &'static str,
    /// Its text, as written.
    pub text: &'static str,
    /// Its width variables.
    pub widths: &'static [WidthVar],
    /// Its pattern variables: name and width.
    pub vars: &'static [(&'static str, Width)],
    /// Its constant variables: name and width.
    pub constants: &'static [(&'static str, Width)],
    /// The left side (matched).
    pub lhs: &'static [Node],
    /// The right side (built).
    pub rhs: &'static [Node],
    /// Side conditions on widths.
    pub constraints: &'static [Constraint],
    /// Nodes of the 1-bit side conditions over constants and literals.
    pub conditions: &'static [Node],
    /// The roots (in [`Rule::conditions`]) that must be 1.
    pub holds: &'static [u8],
}

/// The kind of an expression's root, which rules are filed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Unary(Unary),
    Binary(Binary),
    Flag(Flag),
    Extract,
    Concat,
    Extend,
    Select,
}

impl Shape {
    fn of(expr: &Expr) -> Option<Self> {
        Some(match *expr {
            Expr::Unary(op, _) => Self::Unary(op),
            Expr::Binary(op, ..) => Self::Binary(op),
            Expr::Flag(op, ..) => Self::Flag(op),
            Expr::Extract { .. } => Self::Extract,
            Expr::Concat { .. } => Self::Concat,
            Expr::Extend { .. } => Self::Extend,
            Expr::Select { .. } => Self::Select,
            Expr::Const(_)
            | Expr::Undefined(..)
            | Expr::Var(_)
            | Expr::AddressOf(_)
            | Expr::Lanes { .. }
            | Expr::Float { .. }
            | Expr::Cast { .. }
            | Expr::Load { .. }
            | Expr::Logical(..)
            | Expr::Call(_)
            | Expr::Exception { .. }
            | Expr::Assign { .. } => return None,
        })
    }
}

/// A rule's compiled matcher: what it builds for the root, if it matches.
type Apply = fn(&mut Matcher<'_>, ExprId) -> Option<ExprId>;

/// What the generated matchers use: the function and its expressions'
/// facts, and the node whose provenance new nodes take.
struct Matcher<'f> {
    function: &'f mut Function,
    info: &'f mut Info,
    origin: ExprId,
}

/// A constant of `width` bits with `value` (sign-extended or truncated).
fn int(width: i64, value: i64) -> Option<Bits> {
    let width = u16::try_from(width)
        .ok()
        .filter(|&w| (1..=128).contains(&w))?;
    Some(Bits::from_u128(width, i128::from(value).cast_unsigned()))
}

/// `op` of constants.
fn un(op: Unary, a: Bits) -> Option<Bits> {
    interpret::unary(op, Value::defined(a)).known()
}

/// `op` of constants (of one width).
fn bin(op: Binary, a: Bits, b: Bits) -> Option<Bits> {
    (a.width() == b.width())
        .then(|| interpret::binary(op, Value::defined(a), Value::defined(b)).known())
        .flatten()
}

/// `op` of constants (of one width).
fn flag(op: Flag, a: Bits, b: Bits, c: Bits) -> Option<Bits> {
    (a.width() == b.width() && a.width() == c.width())
        .then(|| {
            interpret::flag(op, Value::defined(a), Value::defined(b), Value::defined(c)).known()
        })
        .flatten()
}

/// Bits of a constant.
fn extract(a: Bits, offset: i64, width: i64) -> Option<Bits> {
    let offset = u16::try_from(offset).ok()?;
    let width = u16::try_from(width).ok()?;
    (width > 0 && u32::from(offset) + u32::from(width) <= u32::from(a.width()))
        .then(|| a.extract(offset, width))
}

/// Two constants side by side.
fn concat(high: Bits, low: Bits) -> Option<Bits> {
    (u32::from(high.width()) + u32::from(low.width()) <= 128).then(|| high.concat(&low))
}

/// A constant extended.
fn extend(signed: bool, a: Bits, width: i64) -> Option<Bits> {
    let width = u16::try_from(width)
        .ok()
        .filter(|&w| w > a.width() && w <= 128)?;
    Some(if signed { a.sext(width) } else { a.zext(width) })
}

/// A choice between constants.
fn select(condition: Bits, then: Bits, otherwise: Bits) -> Option<Bits> {
    (condition.width() == 1 && then.width() == otherwise.width())
        .then(|| if condition.is_zero() { otherwise } else { then })
}

/// Whether a 1-bit constant is 1.
fn holds(bits: Bits) -> bool {
    bits.width() == 1 && !bits.is_zero()
}

/// Whether `width` is one of `claimed`.
fn claimed(width: i64, claimed: &[u16]) -> bool {
    claimed.iter().any(|&w| i64::from(w) == width)
}

impl Matcher<'_> {
    fn expr(&self, id: ExprId) -> Option<Expr> {
        self.function.expr(id).copied()
    }

    fn width(&self, id: ExprId) -> Option<i64> {
        self.info.width(id).map(i64::from)
    }

    fn constant(&self, id: ExprId) -> Option<Bits> {
        if let Some(&Expr::Const(bits)) = self.function.expr(id) {
            Some(bits)
        } else {
            None
        }
    }

    /// Whether `id` is the constant `value` of `width` bits.
    fn literal(&self, id: ExprId, width: i64, value: i64) -> bool {
        int(width, value).is_some_and(|bits| self.constant(id) == Some(bits))
    }

    /// Whether `a` and `b` are one tree, with no undefined part.
    fn same(&self, a: ExprId, b: ExprId) -> bool {
        !self.info.undefined(a) && same(self.function, a, b)
    }

    /// Whether `id` may be evaluated twice with one result and effect: it
    /// has no undefined part and makes no call.
    fn defined(&self, id: ExprId) -> bool {
        !self.info.undefined(id) && !self.info.calls(id)
    }

    /// Whether `id` cannot fault.
    fn harmless(&self, id: ExprId) -> bool {
        !self.info.faults(id)
    }

    /// Whether at most one of `ids` may fault.
    fn alone(&self, ids: &[ExprId]) -> bool {
        ids.iter().filter(|&&id| self.info.faults(id)).count() <= 1
    }

    fn add(&mut self, expr: Expr) -> Option<ExprId> {
        // Checked before it is added: the verifier reads every node, used
        // or not.
        let info = &*self.info;
        expr_width(self.function, &expr, &mut |operand| {
            info.width(operand).ok_or_else(String::new)
        })
        .ok()?;
        Some(append(self.function, self.info, expr, self.origin))
    }

    fn int(&mut self, width: i64, value: i64) -> Option<ExprId> {
        let bits = int(width, value)?;
        self.add(Expr::Const(bits))
    }

    fn unary(&mut self, op: Unary, a: ExprId) -> Option<ExprId> {
        self.add(Expr::Unary(op, a))
    }

    fn binary(&mut self, op: Binary, a: ExprId, b: ExprId) -> Option<ExprId> {
        self.add(Expr::Binary(op, a, b))
    }

    fn extract(&mut self, value: ExprId, offset: i64, width: i64) -> Option<ExprId> {
        let offset = u16::try_from(offset).ok()?;
        let width = u16::try_from(width).ok()?;
        self.add(Expr::Extract {
            value,
            offset,
            width,
        })
    }

    fn concat(&mut self, high: ExprId, low: ExprId) -> Option<ExprId> {
        self.add(Expr::Concat { high, low })
    }

    fn extend(&mut self, signed: bool, value: ExprId, width: i64) -> Option<ExprId> {
        let width = u16::try_from(width).ok()?;
        self.add(Expr::Extend {
            signed,
            value,
            width,
        })
    }

    fn select(&mut self, condition: ExprId, then: ExprId, otherwise: ExprId) -> Option<ExprId> {
        self.add(Expr::Select {
            condition,
            then,
            otherwise,
        })
    }
}

/// Rule `index` of [`RULES`] applied at `root` of `function`, if it
/// matches: the new root (for the test that checks the matcher against
/// the rule's data).
pub fn apply(function: &mut Function, index: usize, root: ExprId) -> Option<ExprId> {
    let mut info = Info::new(function);
    let rule = generated::MATCHERS.get(index)?;
    let mut matcher = Matcher {
        function,
        info: &mut info,
        origin: root,
    };
    rule(&mut matcher, root)
}

/// The constant `expr` computes, if its operands are constants (by L0's
/// interpreter, up to 128 bits).
fn fold(function: &Function, expr: &Expr) -> Option<Bits> {
    let constant = |id: ExprId| {
        if let Some(&Expr::Const(bits)) = function.expr(id) {
            (bits.width() <= 128).then_some(bits)
        } else {
            None
        }
    };
    match *expr {
        Expr::Unary(op, a) => un(op, constant(a)?),
        Expr::Binary(op, a, b) => bin(op, constant(a)?, constant(b)?),
        Expr::Flag(op, a, b, c) => flag(op, constant(a)?, constant(b)?, constant(c)?),
        Expr::Extract {
            value,
            offset,
            width,
        } => extract(constant(value)?, offset.into(), width.into()),
        Expr::Concat { high, low } => concat(constant(high)?, constant(low)?),
        Expr::Extend {
            signed,
            value,
            width,
        } => extend(signed, constant(value)?, width.into()),
        Expr::Select {
            condition,
            then,
            otherwise,
        } => select(constant(condition)?, constant(then)?, constant(otherwise)?),
        Expr::Const(_)
        | Expr::Undefined(..)
        | Expr::Var(_)
        | Expr::AddressOf(_)
        | Expr::Lanes { .. }
        | Expr::Float { .. }
        | Expr::Cast { .. }
        | Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Exception { .. }
        | Expr::Assign { .. }
        // `&&`/`||` are not folded: no rule is filed under them, and their
        // operands are simplified on their own.
        | Expr::Logical(..) => None,
    }
}

/// The rewrite pass (`rules`): [`RULES`] and constant folding, bottom-up,
/// on every expression the body evaluates, each rewritten tree simplified
/// again, a unit of fuel per node visited and per rewrite (out of fuel it
/// stops rewriting and keeps what it did, each rewrite being correct on
/// its own). Preserves nothing.
#[derive(Clone, Debug, Default)]
pub struct Rewrite {
    fired: Vec<usize>,
}

impl Rewrite {
    /// How many times each rule (by index into [`RULES`]) fired, over
    /// every run.
    pub fn fired(&self) -> &[usize] {
        &self.fired
    }
}

/// A step of [`Rewrite`]'s walk.
enum Step {
    /// Simplify the operands of the node, then it.
    Visit(ExprId),
    /// The operands are done; rebuild and rewrite the node.
    Build(ExprId),
    /// The node became what the second simplifies to.
    Alias(ExprId, ExprId),
}

/// One run of [`Rewrite`] on a function.
struct Run<'a> {
    memo: BTreeMap<ExprId, ExprId>,
    fired: &'a mut Vec<usize>,
    /// Fuel left (none: only rebuild).
    fuel: u64,
    /// The statement whose expressions are simplified.
    at: StmtId,
}

impl Run<'_> {
    /// `root` simplified.
    fn simplify(&mut self, function: &mut Function, info: &mut Info, root: ExprId) -> ExprId {
        let mut work = vec![Step::Visit(root)];
        while let Some(step) = work.pop() {
            match step {
                Step::Visit(id) => {
                    if self.memo.contains_key(&id) {
                        continue;
                    }
                    let Some(expr) = function.expr(id) else {
                        self.memo.insert(id, id);
                        continue;
                    };
                    work.push(Step::Build(id));
                    work.extend(expr.operands(function).map(Step::Visit));
                }
                Step::Build(id) => {
                    let Some(&expr) = function.expr(id) else {
                        continue;
                    };
                    let mut changed = false;
                    let rebuilt = function.map_operands(expr, &mut |operand| {
                        let new = self.memo.get(&operand).copied().unwrap_or(operand);
                        changed |= new != operand;
                        new
                    });
                    let current = if changed {
                        append(function, info, rebuilt, id)
                    } else {
                        id
                    };
                    let fresh = function.exprs.len();
                    if let Some(new) = self.rewrite(function, info, current, id) {
                        // The result stands for what the rewrite matched:
                        // a new node takes its instructions, else (an
                        // operand kept, which may be shared) the statement.
                        let folded = dropped(function, current, new);
                        if new.0 as usize >= fresh {
                            function.provenance.absorb_expr(new, &folded);
                        } else {
                            function.provenance.absorb_stmt(self.at, &folded);
                        }
                        work.push(Step::Alias(id, new));
                        work.push(Step::Visit(new));
                    } else {
                        self.memo.insert(id, current);
                        self.memo.insert(current, current);
                    }
                }
                Step::Alias(id, new) => {
                    let done = self.memo.get(&new).copied().unwrap_or(new);
                    self.memo.insert(id, done);
                }
            }
        }
        self.memo.get(&root).copied().unwrap_or(root)
    }

    /// One rewrite at `id` (a fold or a rule), if any applies; `origin` gives
    /// the provenance.
    fn rewrite(
        &mut self,
        function: &mut Function,
        info: &mut Info,
        id: ExprId,
        origin: ExprId,
    ) -> Option<ExprId> {
        self.fuel = self.fuel.checked_sub(1)?;
        let expr = *function.expr(id)?;
        if let Some(bits) = fold(function, &expr) {
            return Some(append(function, info, Expr::Const(bits), origin));
        }
        let shape = Shape::of(&expr)?;
        let rules = generated::DISPATCH
            .iter()
            .find(|(filed, _)| *filed == shape)
            .map(|(_, rules)| *rules)?;
        let mut matcher = Matcher {
            function,
            info,
            origin,
        };
        for &index in rules {
            let Some(rule) = generated::MATCHERS.get(index) else {
                continue;
            };
            if let Some(new) = rule(&mut matcher, id) {
                if self.fired.len() <= index {
                    self.fired.resize(index + 1, 0);
                }
                if let Some(count) = self.fired.get_mut(index) {
                    *count += 1;
                }
                return Some(new);
            }
        }
        None
    }
}

/// The statements of `block` and the blocks they hold, in order.
pub(super) fn statements(function: &Function, block: &Block, out: &mut Vec<StmtId>) {
    for &id in block {
        out.push(id);
        if let Some(stmt) = function.stmt(id) {
            for inner in stmt.blocks() {
                statements(function, inner, out);
            }
        }
    }
}

impl<'e> Pass<Function, L2Env<'e>> for Rewrite {
    fn name(&self) -> &'static str {
        "rules"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let budget = size(function);
        cx.fuel.spend(budget)?;
        let mut info = Info::new(function);
        let mut list = Vec::new();
        statements(function, &function.body, &mut list);
        let mut run = Run {
            memo: BTreeMap::new(),
            fired: &mut self.fired,
            // As much again for rewrites, at most.
            fuel: budget.min(cx.fuel.left()),
            at: StmtId(0),
        };
        // Whether a statement now evaluates something else (nodes built
        // and not used change nothing).
        let mut changed = false;
        for at in list {
            let Some(stmt) = function.stmt(at) else {
                continue;
            };
            // A loop on a constant reads as one without a decision
            // (`while (1)`): a loop's condition keeps its decision.
            let looped = stmt.is_loop();
            run.at = at;
            for root in roots(stmt) {
                run.simplify(function, &mut info, root);
            }
            let memo = &run.memo;
            let exprs = &function.exprs;
            let mut new = |root: ExprId| {
                let new = memo.get(&root).copied().unwrap_or(root);
                let constant = matches!(exprs.get(new.0 as usize), Some(Expr::Const(_)));
                let new = if looped && constant { root } else { new };
                changed |= new != root;
                new
            };
            if let Some(stmt) = function.stmts.get_mut(at.0 as usize) {
                map_roots(stmt, &mut new);
            }
        }
        let spent = budget.min(cx.fuel.left()) - run.fuel;
        // Never more than is left: this cannot refuse after the change.
        cx.fuel.spend(spent.min(cx.fuel.left()))?;
        Ok(changed.into())
    }
}
