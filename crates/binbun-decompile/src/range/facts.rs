//! Comparisons known to hold at a point ([`Fact`]) and what they prove:
//! the interval of a value read signed or unsigned ([`Known::interval`]),
//! a comparison between two values ([`Known::proves`]), and whether two
//! conditions on one variable hold for the same values
//! ([`equivalent`]). A comparison of a constant with a zero or sign
//! extension of a variable is a fact about the variable ([`narrowed`]).

use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, Logical, VarId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, Unary};

use crate::simplify::expr::in_memory;

/// The widest value the facts reason about (their arithmetic is in
/// `i128`).
pub const WIDEST: u16 = 64;

/// A value a [`Fact`] compares: a variable not in memory, or a constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Term {
    /// The variable's value.
    Var(VarId),
    /// A constant.
    Const(Bits),
}

/// How the two values of a [`Fact`] compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rel {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Less than, read signed (`true`) or unsigned.
    Lt(bool),
    /// Less than or equal, read signed (`true`) or unsigned.
    Le(bool),
}

/// `a rel b`, both of `width` bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fact {
    /// The left value.
    pub a: Term,
    /// How they compare.
    pub rel: Rel,
    /// The right value.
    pub b: Term,
    /// Their width.
    pub width: u16,
}

impl Fact {
    /// The fact with `var` replaced by `with`.
    #[must_use]
    pub fn substitute(self, var: VarId, with: Term) -> Self {
        let swap = |term: Term| if term == Term::Var(var) { with } else { term };
        Self {
            a: swap(self.a),
            b: swap(self.b),
            ..self
        }
    }
}

/// The values from `lo` to `hi` (inclusive) of a domain: one width, read
/// signed or unsigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Interval {
    /// The least.
    pub lo: i128,
    /// The greatest.
    pub hi: i128,
}

impl Interval {
    /// Every value of `width` bits read signed or not.
    pub fn full(signed: bool, width: u16) -> Self {
        Self {
            lo: min(signed, width),
            hi: max(signed, width),
        }
    }

    /// `value` alone.
    pub const fn point(value: i128) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }

    /// Whether it holds no value (the point is unreachable).
    pub const fn is_empty(self) -> bool {
        self.lo > self.hi
    }

    /// The values in both.
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        Self {
            lo: self.lo.max(other.lo),
            hi: self.hi.min(other.hi),
        }
    }

    /// Whether every value of `width` bits in it, read signed (`signed`)
    /// or not, is in `0..=` the signed maximum: the same read either way.
    pub fn sign_free(self, signed: bool, width: u16) -> bool {
        !self.is_empty()
            && if signed {
                self.lo >= 0
            } else {
                self.hi <= max(true, width)
            }
    }
}

/// The least value of `width` bits read signed or not.
pub fn min(signed: bool, width: u16) -> i128 {
    if signed { -(1i128 << (width - 1)) } else { 0 }
}

/// The greatest value of `width` bits read signed or not.
pub fn max(signed: bool, width: u16) -> i128 {
    if signed {
        (1i128 << (width - 1)) - 1
    } else {
        (1i128 << width) - 1
    }
}

/// `bits` read signed or not (at most [`WIDEST`] bits).
pub fn value(bits: Bits, signed: bool) -> i128 {
    let width = bits.width();
    if signed {
        i128::from(bits.sext(64).low_u64().cast_signed())
    } else if width >= 64 {
        i128::from(bits.low_u64())
    } else {
        i128::from(bits.low_u64() & ((1u64 << width) - 1))
    }
}

/// The term `id` is, if a variable not in memory or a constant of at most
/// [`WIDEST`] bits.
pub fn term(function: &Function, id: ExprId) -> Option<Term> {
    match *function.expr(id)? {
        Expr::Var(var) => (!in_memory(function, var)).then_some(Term::Var(var)),
        Expr::Const(bits) => (bits.width() <= WIDEST).then_some(Term::Const(bits)),
        Expr::Undefined(..)
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
        | Expr::Cast { .. }
        | Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Exception { .. }
        | Expr::Assign { .. } => None,
    }
}

/// The facts condition `id` gives where it is `holds` (1 if true, 0 if
/// false), into `out`: comparisons of terms, through `!`, `&&` where it
/// holds and `||` where it does not. At most 16 nodes are looked at.
pub fn facts_of(function: &Function, id: ExprId, holds: bool, out: &mut Vec<Fact>) {
    let mut work = vec![(id, holds)];
    let mut budget = 16u32;
    while let Some((at, holds)) = work.pop() {
        budget = match budget.checked_sub(1) {
            Some(left) => left,
            None => return,
        };
        match function.expr(at) {
            Some(&Expr::Unary(Unary::Not, inner)) => work.push((inner, !holds)),
            Some(&Expr::Logical(Logical::And, left, right)) if holds => {
                work.extend([(left, true), (right, true)]);
            }
            Some(&Expr::Logical(Logical::Or, left, right)) if !holds => {
                work.extend([(left, false), (right, false)]);
            }
            Some(&Expr::Binary(op, a, b)) => {
                if let Some(fact) = compare(function, op, a, b, holds) {
                    out.push(fact);
                }
            }
            Some(_) | None => {}
        }
    }
}

/// The one fact condition `id` is (where it holds), if it is a comparison
/// of terms under any number of `!` (at most 8), and nothing else.
pub fn fact_of(function: &Function, mut id: ExprId) -> Option<Fact> {
    let mut holds = true;
    for _ in 0..8 {
        let expr = *function.expr(id)?;
        if let Expr::Unary(Unary::Not, inner) = expr {
            id = inner;
            holds = !holds;
        } else if let Expr::Binary(op, a, b) = expr {
            return compare(function, op, a, b, holds);
        } else {
            return None;
        }
    }
    None
}

/// The fact `op(a, b)` is where it is `holds`, if a comparison of terms.
fn compare(function: &Function, op: Binary, a: ExprId, b: ExprId, holds: bool) -> Option<Fact> {
    let (ta, tb) = match (term(function, a), term(function, b)) {
        (Some(ta), Some(tb)) => (ta, tb),
        // A constant against an extension of a variable: the extension's
        // value stands for the variable, then the fact is narrowed.
        (Some(constant @ Term::Const(_)), None) => {
            let (var, signed, from) = extension(function, b)?;
            let fact = relation(op, constant, Term::Var(var), function.width(b)?, holds)?;
            return narrowed(fact, var, signed, from);
        }
        (None, Some(constant @ Term::Const(_))) => {
            let (var, signed, from) = extension(function, a)?;
            let fact = relation(op, Term::Var(var), constant, function.width(a)?, holds)?;
            return narrowed(fact, var, signed, from);
        }
        (Some(_) | None, _) => return None,
    };
    let width = match (ta, tb) {
        (Term::Const(bits), _) | (_, Term::Const(bits)) => bits.width(),
        (Term::Var(_), Term::Var(_)) => function.width(a)?,
    };
    relation(op, ta, tb, width, holds)
}

/// The fact `op(ta, tb)` (of `width` bits) is where it is `holds`, if `op`
/// is a comparison.
fn relation(op: Binary, ta: Term, tb: Term, width: u16, holds: bool) -> Option<Fact> {
    if width == 0 || width > WIDEST {
        return None;
    }
    let fact = |a: Term, rel: Rel, b: Term| Fact { a, rel, b, width };
    Some(match (op, holds) {
        (Binary::Eq, true) | (Binary::Ne, false) => fact(ta, Rel::Eq, tb),
        (Binary::Ne, true) | (Binary::Eq, false) => fact(ta, Rel::Ne, tb),
        (Binary::SLt, true) => fact(ta, Rel::Lt(true), tb),
        (Binary::ULt, true) => fact(ta, Rel::Lt(false), tb),
        (Binary::SLe, true) => fact(ta, Rel::Le(true), tb),
        (Binary::ULe, true) => fact(ta, Rel::Le(false), tb),
        // !(a < b) is b <= a; !(a <= b) is b < a.
        (Binary::SLt, false) => fact(tb, Rel::Le(true), ta),
        (Binary::ULt, false) => fact(tb, Rel::Le(false), ta),
        (Binary::SLe, false) => fact(tb, Rel::Lt(true), ta),
        (Binary::ULe, false) => fact(tb, Rel::Lt(false), ta),
        (
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
            | Binary::Ror,
            _,
        ) => return None,
    })
}

/// `id` as a zero (`false`) or sign (`true`) extension of a variable not in
/// memory to at most [`WIDEST`] bits: the variable, the kind and the
/// variable's width (less than the extension's).
pub fn extension(function: &Function, id: ExprId) -> Option<(VarId, bool, u16)> {
    let &Expr::Extend {
        signed,
        value,
        width,
    } = function.expr(id)?
    else {
        return None;
    };
    let Term::Var(var) = term(function, value)? else {
        return None;
    };
    let from = function.width(value)?;
    (from > 0 && from < width && width <= WIDEST).then_some((var, signed, from))
}

/// `fact`, a comparison of a constant with `var` standing for its zero or
/// sign (`signed`) extension from `from` bits, as the same comparison of
/// `var` itself (`from` bits) with the constant truncated: where the
/// constant is one of the extension's values in the comparison's reading.
/// A zero extension's values, read signed or unsigned, are the variable's
/// read unsigned; a sign extension's, read signed, are the variable's read
/// signed (read unsigned they are not in order: only `==` and `!=`). For
/// `==` and `!=`, the constant must be the extension of its truncation.
/// Otherwise the comparison holds for every value of the variable or for
/// none: `None`.
pub fn narrowed(fact: Fact, var: VarId, signed: bool, from: u16) -> Option<Fact> {
    let (constant, left) = match (fact.a, fact.b) {
        (Term::Var(v), Term::Const(c)) if v == var => (c, false),
        (Term::Const(c), Term::Var(v)) if v == var => (c, true),
        _ => return None,
    };
    let short = constant.extract(0, from);
    let extended = if signed {
        short.sext(fact.width)
    } else {
        short.zext(fact.width)
    };
    let rel = match fact.rel {
        Rel::Eq | Rel::Ne => (extended == constant).then_some(fact.rel)?,
        Rel::Lt(reading) | Rel::Le(reading) => {
            let narrow_signed = match (signed, reading) {
                (false, _) => false,
                (true, true) => true,
                (true, false) => return None,
            };
            let c = value(constant, reading);
            if c < min(narrow_signed, from) || c > max(narrow_signed, from) {
                return None;
            }
            if matches!(fact.rel, Rel::Lt(_)) {
                Rel::Lt(narrow_signed)
            } else {
                Rel::Le(narrow_signed)
            }
        }
    };
    let (a, b) = if left {
        (Term::Const(short), Term::Var(var))
    } else {
        (Term::Var(var), Term::Const(short))
    };
    Some(Fact {
        a,
        rel,
        b,
        width: from,
    })
}

/// Facts that hold together at one point.
#[derive(Clone, Copy, Debug)]
pub struct Known<'f> {
    facts: &'f [Fact],
}

impl<'f> Known<'f> {
    /// What `facts` say.
    pub const fn new(facts: &'f [Fact]) -> Self {
        Self { facts }
    }

    /// The values `term` (of `width` bits) may have, read signed or not.
    pub fn interval(&self, term: Term, signed: bool, width: u16) -> Interval {
        match term {
            Term::Const(bits) => Interval::point(value(bits, signed)),
            Term::Var(var) => {
                let (s, u) = self.var(var, width);
                if signed { s } else { u }
            }
        }
    }

    /// The values `var` may have, read signed and unsigned: the facts
    /// comparing it with constants, each reading refining the other where
    /// they agree, twice over (a `!=` cuts an end the other facts made).
    fn var(&self, var: VarId, width: u16) -> (Interval, Interval) {
        let mut s = Interval::full(true, width);
        let mut u = Interval::full(false, width);
        for _ in 0..2 {
            for fact in self.facts.iter().filter(|fact| fact.width == width) {
                let (constant, left) = match (fact.a, fact.b) {
                    (Term::Var(v), Term::Const(c)) if v == var => (c, true),
                    (Term::Const(c), Term::Var(v)) if v == var => (c, false),
                    _ => continue,
                };
                for (domain, signed) in [(&mut s, true), (&mut u, false)] {
                    narrow(domain, fact.rel, value(constant, signed), signed, left);
                }
            }
            let span = 1i128 << width;
            let top = max(true, width);
            if s.lo >= 0 {
                u = u.meet(s);
            } else if s.hi < 0 {
                u = u.meet(Interval {
                    lo: s.lo + span,
                    hi: s.hi + span,
                });
            }
            if u.hi <= top {
                s = s.meet(u);
            } else if u.lo > top {
                s = s.meet(Interval {
                    lo: u.lo - span,
                    hi: u.hi - span,
                });
            }
        }
        (s, u)
    }

    /// Whether the facts prove `a rel b` (of `width` bits): by the
    /// intervals, or as a fact (`<` also proving `<=` and `!=`, `==`
    /// proving `<=`).
    pub fn proves(&self, a: Term, rel: Rel, b: Term, width: u16) -> bool {
        if let Rel::Lt(signed) | Rel::Le(signed) = rel {
            let (ia, ib) = (
                self.interval(a, signed, width),
                self.interval(b, signed, width),
            );
            if !ia.is_empty() && !ib.is_empty() {
                let proved = match rel {
                    Rel::Lt(_) => ia.hi < ib.lo,
                    Rel::Le(_) | Rel::Eq | Rel::Ne => ia.hi <= ib.lo,
                };
                if proved {
                    return true;
                }
            }
        }
        self.facts.iter().any(|fact| {
            fact.width == width
                && match (rel, fact.rel) {
                    (Rel::Eq | Rel::Ne, other) if other == rel => {
                        (fact.a, fact.b) == (a, b) || (fact.a, fact.b) == (b, a)
                    }
                    (Rel::Ne, Rel::Lt(_)) | (Rel::Le(_), Rel::Eq) => {
                        (fact.a, fact.b) == (a, b) || (fact.a, fact.b) == (b, a)
                    }
                    (Rel::Le(signed), Rel::Lt(other)) if signed == other => {
                        (fact.a, fact.b) == (a, b)
                    }
                    (wanted, other) => wanted == other && (fact.a, fact.b) == (a, b),
                }
        })
    }
}

/// `domain` (read `signed`) narrowed by `x rel c` (`left`) or `c rel x`.
fn narrow(domain: &mut Interval, rel: Rel, c: i128, signed: bool, left: bool) {
    match rel {
        Rel::Eq => *domain = domain.meet(Interval::point(c)),
        Rel::Ne => {
            if domain.lo == c {
                domain.lo += 1;
            }
            if domain.hi == c {
                domain.hi -= 1;
            }
        }
        Rel::Lt(s) | Rel::Le(s) if s == signed => {
            let strict = i128::from(matches!(rel, Rel::Lt(_)));
            if left {
                domain.hi = domain.hi.min(c - strict);
            } else {
                domain.lo = domain.lo.max(c + strict);
            }
        }
        Rel::Lt(_) | Rel::Le(_) => {}
    }
}

/// The values of the one variable `fact` compares with a constant for
/// which it holds, as unsigned ranges, sorted and merged; `None` if it
/// compares two variables or two constants.
fn values(fact: &Fact) -> Option<(VarId, Vec<(i128, i128)>)> {
    let (var, constant, left) = match (fact.a, fact.b) {
        (Term::Var(v), Term::Const(c)) => (v, c, true),
        (Term::Const(c), Term::Var(v)) => (v, c, false),
        (Term::Var(_), Term::Var(_)) | (Term::Const(_), Term::Const(_)) => return None,
    };
    let width = fact.width;
    let signed = matches!(fact.rel, Rel::Lt(true) | Rel::Le(true));
    let c = value(constant, signed);
    let (lo, hi) = (min(signed, width), max(signed, width));
    let ranges: Vec<(i128, i128)> = match fact.rel {
        Rel::Eq => vec![(c, c)],
        Rel::Ne => vec![(lo, c - 1), (c + 1, hi)],
        Rel::Lt(_) if left => vec![(lo, c - 1)],
        Rel::Le(_) if left => vec![(lo, c)],
        Rel::Lt(_) => vec![(c + 1, hi)],
        Rel::Le(_) => vec![(c, hi)],
    };
    let span = 1i128 << width;
    let mut unsigned = Vec::new();
    for (lo, hi) in ranges.into_iter().filter(|(lo, hi)| lo <= hi) {
        if lo < 0 {
            unsigned.push((lo + span, hi.min(-1) + span));
        }
        if hi >= 0 {
            unsigned.push((lo.max(0), hi));
        }
    }
    unsigned.sort_unstable();
    let mut merged: Vec<(i128, i128)> = Vec::with_capacity(unsigned.len());
    for (lo, hi) in unsigned {
        match merged.last_mut() {
            Some(last) if lo <= last.1 + 1 => last.1 = last.1.max(hi),
            Some(_) | None => merged.push((lo, hi)),
        }
    }
    Some((var, merged))
}

/// Whether facts `a` and `b` hold for the same values: the same
/// comparison of the same terms, or comparisons of one variable with
/// constants that hold for the same values of it.
pub fn equivalent(a: &Fact, b: &Fact) -> bool {
    if a.width != b.width {
        return false;
    }
    let symmetric = matches!(a.rel, Rel::Eq | Rel::Ne);
    if a.rel == b.rel && ((a.a, a.b) == (b.a, b.b) || (symmetric && (a.a, a.b) == (b.b, b.a))) {
        return true;
    }
    match (values(a), values(b)) {
        (Some(va), Some(vb)) => va == vb,
        _ => false,
    }
}
