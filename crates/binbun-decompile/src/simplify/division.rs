//! Division by a constant (a compiler optimisation undone): the sequences
//! GCC and Clang emit for `x / d` and `x % d` at 32 and 64 bits, back to
//! `udiv`/`sdiv` by `d` ([`Divisions`]), and the remainder `x - q * d`,
//! `q` being `x / d` (so recognised, or already a division, in the
//! expression or a variable), to `urem`/`srem`.
//!
//! # What is recognised
//!
//! Every form below is read as a *product* `floor(x' * m / 2^k)` of an
//! `N`-bit dividend `x` (`N` = 8, 16, 32 or 64: compilers divide 8- and
//! 16-bit values at 32 bits, but nothing below depends on the width, and
//! the small widths are where z3 proves every divisor), with `x' = x` or,
//! unsigned, `x' = x >> p` (a pre-shift):
//!
//! - bits `k..k+N` of `ext(x') * c` computed at `W` bits (`W > N`,
//!   usually `2N`; `zext` unsigned, `sext` signed): `extract(P, k, N)` or
//!   `extract(lshr|ashr(P, k), 0, N)` (a shift that brings in other bits
//!   than the product's sign only where they are not taken: `k + N <=
//!   W`), where the product `P` is exact (`|x'| * |c| < 2^W`, signed
//!   `2^(W-1)`) and so is the result (it fits `N` bits);
//! - a product shifted right again (`lshr` unsigned, `ashr` signed): `k`
//!   grows;
//! - unsigned, the 33rd/65th bit of the multiplier (`2^N + c`):
//!   `((x - t) >> 1) + t` with `t` the product of `x` by `c` at `k = N`
//!   (`c < 2^N`), which is `floor(x * (2^N + c) / 2^(N + 1))`;
//! - signed, a negative multiplier corrected: `t + x` with `t` the
//!   product of `x` by `c < 0` at `k = N`, which is
//!   `floor(x * (c + 2^N) / 2^N)`.
//!
//! An unsigned product is the quotient; a signed one is rounded toward
//! zero by `t - (x >>a (N-1))` or `t + (x >> (N-1))` (adding 1 for a
//! negative `x`). Fewer bits taken of an unsigned product (a quotient
//! stored as a byte: `extract(lshr(P, k), 0, 8)`) are those bits of the
//! quotient.
//!
//! # Why it is the quotient: the side condition
//!
//! The divisor is `d = ceil(2^k / m)`, and `e = m*d - 2^k` (so `e >= 0`).
//!
//! Write `x' = q*d + r` (`0 <= r < d`): `x'*m/2^k = q + (r + x'*e/2^k)/d`.
//!
//! - Unsigned, `0 <= x' <= 2^n - 1` (`n = N - p`): with
//!   `(2^n - 1) * e < 2^k`, `r + x'*e/2^k < r + 1 <= d`, so the floor is
//!   `q = floor(x'/d)`; and `floor((x >> p) / d) = floor(x / (d << p))`.
//! - Signed, `-2^(N-1) <= x < 2^(N-1)`, with `e > 0` and
//!   `e * 2^(N-1) <= 2^k`: for `x >= 0` as above; for `x = -a < 0`
//!   (`a = q*d + r`), `floor(-a*m/2^k) + 1 = -ceil(q + (r + a*e/2^k)/d) +
//!   1`, and `0 < r + a*e/2^k <= r + 1 <= d` makes the ceiling `q + 1`:
//!   the result is `-q = trunc(x/d)`.
//!
//! These are Granlund and Montgomery's conditions ("Division by invariant
//! integers using multiplication", PLDI 1994, theorems 4.2 and 5.1; the
//! unsigned one slightly wider), checked exactly (128-bit integers) for
//! every rewrite: the recogniser
//! accepts any multiplier that satisfies them, whichever compiler chose
//! it, and nothing else. The test `division` builds GCC's and Clang's
//! sequences (from GCC's own `choose_multiplier`) for every divisor at 8
//! bits and fifty at 16, and z3 finds no input where the rewrite
//! differs (nor for the remainders); at 32 and 64 bits, where z3 needs
//! minutes for one divisor, it checks the rewrite for a thousand
//! divisors each and runs each against the division from edge and
//! random values. The recogniser does not depend on the width but
//! through `N`, so the small widths exercise every path the large ones
//! take, and the side condition is the proof at every width.
//!
//! # Where
//!
//! The parts of a sequence are usually separate assignments (the
//! multiply-high is read twice). A variable read in the sequence is
//! looked through to its one assignment when that assignment's value is
//! available at the statement being rewritten (the check copy
//! propagation makes, [`Facts::available`]) and neither loads nor has an
//! undefined part: the rewritten statement then computes what the
//! sequence did. The assignments looked through stay, for dead code to
//! remove once nothing reads them.
//!
//! # Provenance
//!
//! The division stands for every instruction of the sequence it replaces:
//! it takes the origins of the sequence's nodes and of the assignments
//! looked through (not those of the dividend, which stays).

#![allow(
    clippy::many_single_char_names,
    reason = "x, t, m, k, d, e as in the arithmetic above"
)]

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, Origin, Place, Stmt, StmtId, VarKind};
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::ir::Binary;
use binbun_ssa::ir::Unknown;

use super::expr::{Info, append, map_roots, reads, rebuild, roots, same};
use super::facts::Facts;
use super::rules::statements;
use crate::pass::{L2Env, size};

/// The division pass (`divisions`): multiply-high sequences dividing by
/// a constant become `udiv`/`sdiv` by it, and `x - q * d` with `q` such a
/// quotient (in a variable) `urem`/`srem`; see the module documentation
/// for what is recognised and why it is exact. A unit of fuel per
/// statement and expression. Preserves nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Divisions;

/// `floor(x' * multiplier / 2^shift)`, `x'` being `x >> pre` (unsigned)
/// or `x` (signed); `x` is `width` bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Product {
    x: ExprId,
    width: u16,
    /// The low bits of the result the expression takes (`width`: all).
    taken: u16,
    signed: bool,
    multiplier: i128,
    shift: u32,
    pre: u32,
}

/// What a quotient divides, by what.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Quotient {
    x: ExprId,
    width: u16,
    /// The low bits of the quotient taken (`width`: all).
    taken: u16,
    signed: bool,
    divisor: u128,
}

/// `2^k` (`k` at most 126).
fn power(k: u32) -> Option<i128> {
    (k <= 126).then(|| 1i128 << k)
}

/// How many nodes of a sequence [`Search::folded`] takes the origins of,
/// at most (a sequence has a few dozen).
const SEQUENCE: usize = 256;

/// The value of a constant as a signed (`signed`) or unsigned integer.
fn value(bits: &Bits, signed: bool) -> Option<i128> {
    if bits.width() > 128 {
        return None;
    }
    let raw = bits.low_u128();
    if signed && bits.msb() {
        let magnitude = bits.wrapping_neg().low_u128();
        i128::try_from(magnitude).ok().map(|m| -m)
    } else {
        i128::try_from(raw).ok()
    }
}

/// The divisor `product` divides by, if the side condition holds (module
/// documentation).
fn divisor(product: &Product) -> Option<u128> {
    let m = u128::try_from(product.multiplier).ok().filter(|&m| m > 0)?;
    let k = product.shift;
    let n = u32::from(product.width);
    let two = |k: u32| (k <= 127).then(|| 1u128 << k);
    let two_k = two(k)?;
    let d = two_k.div_ceil(m);
    let e = m.checked_mul(d)? - two_k;
    if product.signed {
        // 0 < e, e * 2^(N-1) <= 2^k.
        let limit = two(n - 1)?;
        let ok = e > 0 && e.checked_mul(limit)? <= two_k && d >= 2 && d < limit;
        return ok.then_some(d);
    }
    // e * (2^n - 1) < 2^k.
    let bits = n.checked_sub(product.pre)?;
    let full = d.checked_mul(two(product.pre)?)?;
    let ok = e.checked_mul(two(bits)? - 1)? < two_k && d >= 2 && full < two(n)?;
    ok.then_some(full)
}

/// Recognition at one statement: the function, its facts, and where.
struct Search<'a> {
    function: &'a Function,
    info: &'a Info,
    facts: &'a Facts,
    at: StmtId,
}

impl Search<'_> {
    /// `id` with a variable looked through to its one assignment, where
    /// that is allowed (module documentation).
    fn resolve(&self, id: ExprId) -> Expr {
        let function = self.function;
        let Some(&expr) = function.expr(id) else {
            return Expr::Undefined(0, Unknown::Lowering, None);
        };
        match self.through(id) {
            Some((_, value)) => function.expr(value).copied().unwrap_or(expr),
            None => expr,
        }
    }

    /// The assignment variable read `id` is looked through to and its
    /// value, where that is allowed (module documentation).
    fn through(&self, id: ExprId) -> Option<(StmtId, ExprId)> {
        let function = self.function;
        let &Expr::Var(var) = function.expr(id)? else {
            return None;
        };
        let local = function
            .var(var)
            .is_some_and(|variable| variable.kind == VarKind::Local);
        let &[def] = self.facts.defs.get(var.0 as usize).map(Vec::as_slice)? else {
            return None;
        };
        let &Stmt::Assign {
            place: Place::Var(target),
            value,
        } = function.stmt(def)?
        else {
            return None;
        };
        let mut read = BTreeSet::new();
        reads(function, value, &mut read);
        let usable = local
            && target == var
            && !read.contains(&var)
            && !self.info.faults(value)
            && !self.info.undefined(value)
            && self
                .facts
                .available(function, self.info, def, value, self.at);
        usable.then_some((def, value))
    }

    /// The origins of the sequence rooted at `id` that becomes a division
    /// of `x`: of its nodes and of the assignments looked through, not of
    /// `x` (which stays).
    fn folded(&self, id: ExprId, x: ExprId) -> Vec<Origin> {
        let function = self.function;
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut work = Vec::from([id]);
        while let Some(node) = work.pop() {
            if seen.len() >= SEQUENCE || !seen.insert(node) || self.same(node, x) {
                continue;
            }
            out.extend_from_slice(function.provenance.expr(node));
            if let Some((def, value)) = self.through(node) {
                out.extend_from_slice(function.provenance.stmt(def));
                work.push(value);
            } else if let Some(expr) = function.expr(node) {
                work.extend(expr.operands(function));
            }
        }
        out
    }

    /// `id` resolved, if it is a constant.
    fn constant(&self, id: ExprId) -> Option<Bits> {
        if let Expr::Const(bits) = self.resolve(id) {
            Some(bits)
        } else {
            None
        }
    }

    fn width(&self, id: ExprId) -> Option<u16> {
        self.info.width(id)
    }

    /// Whether `a` and `b` are the same tree (both from assignments
    /// available at the statement, or from the statement: the same value
    /// there).
    fn same(&self, a: ExprId, b: ExprId) -> bool {
        same(self.function, a, b)
    }

    /// `id` (`width` bits) as a [`Product`].
    fn product(&self, id: ExprId) -> Option<Product> {
        let width = self.width(id)?;
        match self.resolve(id) {
            Expr::Extract {
                value,
                offset,
                width: taken,
            } if taken == width => {
                let wide = self.resolve(value);
                if let Expr::Binary(op @ (Binary::LShr | Binary::AShr), inner, count) = wide {
                    if offset != 0 {
                        return None;
                    }
                    let count = self.constant(count)?;
                    let shift = u32::try_from(count.low_u128()).ok()?;
                    let product = self.wide(inner, shift, width)?;
                    // A logical shift of a negative product brings zeros
                    // into the bits taken past the product's width.
                    let total = u32::from(self.width(inner)?);
                    let fills = op == Binary::LShr && product.signed
                        || op == Binary::AShr && !product.signed;
                    (!fills || shift + u32::from(width) <= total).then_some(product)
                } else {
                    self.wide(value, u32::from(offset), width)
                }
            }
            Expr::Binary(op @ (Binary::LShr | Binary::AShr), inner, count) => {
                let mut product = self.product(inner)?;
                if product.signed != (op == Binary::AShr) || product.taken != width {
                    return None;
                }
                let count = u32::try_from(self.constant(count)?.low_u128()).ok()?;
                if count >= u32::from(width) {
                    return None;
                }
                product.shift = product.shift.checked_add(count)?;
                Some(product)
            }
            Expr::Binary(Binary::Add, a, b) => self.added(a, b).or_else(|| self.added(b, a)),
            Expr::Const(_)
            | Expr::Undefined(..)
            | Expr::Var(_)
            | Expr::AddressOf(_)
            | Expr::Unary(..)
            | Expr::Binary(..)
            | Expr::Flag(..)
            | Expr::Extract { .. }
            | Expr::Concat { .. }
            | Expr::Extend { .. }
            | Expr::Select { .. }
            | Expr::Lanes { .. }
            | Expr::Float { .. }
            | Expr::Cast { .. }
            | Expr::Load { .. }
            | Expr::Logical(..)
            | Expr::Call(_)
            | Expr::Exception { .. }
            | Expr::Assign { .. } => None,
        }
    }

    /// `a + b` as a product: unsigned `((x - t) >> 1) + t` (`a` the
    /// shifted difference), signed `t + x` (`a` the product).
    fn added(&self, a: ExprId, b: ExprId) -> Option<Product> {
        let n = self.width(a)?;
        let bits = u32::from(n);
        if let Some(t) = self.product(a)
            && t.signed
            && t.taken == t.width
            && t.multiplier < 0
            && t.shift == bits
            && self.same(t.x, b)
        {
            return Some(Product {
                multiplier: t.multiplier + power(bits)?,
                ..t
            });
        }
        let Expr::Binary(Binary::LShr, difference, one) = self.resolve(a) else {
            return None;
        };
        if self.constant(one)?.low_u128() != 1 {
            return None;
        }
        let Expr::Binary(Binary::Sub, x, t_again) = self.resolve(difference) else {
            return None;
        };
        let t = self.product(b)?;
        let fits = t.multiplier < power(bits)?;
        let matches = !t.signed
            && t.taken == t.width
            && t.pre == 0
            && t.shift == bits
            && fits
            && self.same(t.x, x)
            && self.same(t_again, b);
        matches
            .then(|| {
                Some(Product {
                    multiplier: t.multiplier + power(bits)?,
                    shift: bits + 1,
                    ..t
                })
            })
            .flatten()
    }

    /// The product whose bits from `shift` are taken, `taken` of them (at
    /// most the dividend's width), from `wide` (a `W`-bit `mul` of an
    /// extended dividend by a constant).
    fn wide(&self, wide: ExprId, shift: u32, taken: u16) -> Option<Product> {
        let total = self.width(wide)?;
        if shift >= u32::from(total) {
            return None;
        }
        let Expr::Binary(Binary::Mul, a, b) = self.resolve(wide) else {
            return None;
        };
        let (extended, c) = match (self.constant(a), self.constant(b)) {
            (None, Some(c)) => (a, c),
            (Some(c), None) => (b, c),
            (Some(_), Some(_)) | (None, None) => return None,
        };
        let Expr::Extend {
            signed,
            value: dividend,
            ..
        } = self.resolve(extended)
        else {
            return None;
        };
        let width = self.width(dividend)?;
        if taken > width {
            return None;
        }
        let c = value(&c, signed)?;
        let (x, pre) = if let Expr::Binary(Binary::LShr, x, p) = self.resolve(dividend)
            && !signed
        {
            (x, u32::try_from(self.constant(p)?.low_u128()).ok()?)
        } else {
            (dividend, 0)
        };
        let product = Product {
            x,
            width,
            taken,
            signed,
            multiplier: c,
            shift,
            pre,
        };
        exact(&product, total).then_some(product)
    }

    /// `id` as a quotient (unsigned, possibly only its low bits).
    fn quotient(&self, id: ExprId) -> Option<Quotient> {
        let expr = self.resolve(id);
        if let Some(product) = self.product(id)
            && !product.signed
        {
            if !matches!(product.width, 8 | 16 | 32 | 64) {
                return None;
            }
            return Some(Quotient {
                x: product.x,
                width: product.width,
                taken: product.taken,
                signed: false,
                divisor: divisor(&product)?,
            });
        }
        let width = self.width(id)?;
        if !matches!(width, 8 | 16 | 32 | 64) {
            return None;
        }
        let (t, sign, add) = if let Expr::Binary(Binary::Sub, t, sign) = expr {
            (t, sign, false)
        } else if let Expr::Binary(Binary::Add, a, b) = expr {
            if self.is_sign(b, Binary::LShr).is_some() {
                (a, b, true)
            } else {
                (b, a, true)
            }
        } else {
            return None;
        };
        let product = self.product(t)?;
        let x = self.is_sign(sign, if add { Binary::LShr } else { Binary::AShr })?;
        (product.signed
            && product.taken == width
            && product.width == width
            && self.same(product.x, x))
        .then(|| {
            Some(Quotient {
                x: product.x,
                width,
                taken: width,
                signed: true,
                divisor: divisor(&product)?,
            })
        })
        .flatten()
    }

    /// The `x` of `op(x, N-1)`, if `id` is that.
    fn is_sign(&self, id: ExprId, op: Binary) -> Option<ExprId> {
        let width = u128::from(self.width(id)?);
        let Expr::Binary(found, x, count) = self.resolve(id) else {
            return None;
        };
        (found == op && self.constant(count)?.low_u128() == width - 1).then_some(x)
    }

    /// `x - q * d` (or `x - d * q`) with `q` the quotient of `x` by `d`:
    /// the remainder.
    fn remainder(&self, id: ExprId) -> Option<Quotient> {
        let Expr::Binary(Binary::Sub, x, product) = self.resolve(id) else {
            return None;
        };
        let Expr::Binary(Binary::Mul, a, b) = self.resolve(product) else {
            return None;
        };
        let (q, d) = match (self.constant(a), self.constant(b)) {
            (None, Some(d)) => (a, d),
            (Some(d), None) => (b, d),
            (Some(_), Some(_)) | (None, None) => return None,
        };
        let quotient = if let Expr::Binary(op @ (Binary::UDiv | Binary::SDiv), dividend, divisor) =
            self.resolve(q)
        {
            let width = self.width(q)?;
            Quotient {
                x: dividend,
                width,
                taken: width,
                signed: op == Binary::SDiv,
                divisor: self.constant(divisor)?.low_u128(),
            }
        } else {
            self.quotient(q)?
        };
        let whole = quotient.taken == quotient.width;
        (whole && quotient.divisor == d.low_u128() && self.same(quotient.x, x)).then_some(quotient)
    }
}

/// Whether `product`'s multiplication at `total` bits is exact, and its
/// result fits its width.
fn exact(product: &Product, total: u16) -> bool {
    let n = u32::from(product.width);
    let total = u32::from(total);
    let k = product.shift;
    // |c| < 2^bits.
    let bits = 128 - product.multiplier.unsigned_abs().leading_zeros();
    if product.signed {
        // |x| <= 2^(N-1), so |x * c| < 2^(N-1+bits) <= 2^(W-1), and
        // |x * c / 2^k| < 2^(N-1) when bits <= k.
        n - 1 + bits < total && bits <= k
    } else {
        // x' < 2^(N-p), so x' * c < 2^(N-p+bits) <= 2^W, and the result
        // is below 2^N when N-p+bits <= k+N.
        let x = n.saturating_sub(product.pre);
        product.multiplier >= 0 && x + bits <= total && x + bits <= k + n
    }
}

impl<'e> Pass<Function, L2Env<'e>> for Divisions {
    fn name(&self) -> &'static str {
        "divisions"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let mut info = Info::new(function);
        if !function
            .exprs
            .iter()
            .any(|expr| matches!(expr, Expr::Binary(Binary::Mul, ..)))
        {
            return Ok(Changed::No);
        }
        let facts = Facts::new(function, &info, cx.fuel)?;
        let mut list = Vec::new();
        statements(function, &function.body, &mut list);
        let mut changed = false;
        for at in list {
            let Some(stmt) = function.stmt(at) else {
                continue;
            };
            let mut memo = BTreeMap::new();
            for root in roots(stmt) {
                // Outermost first: a sequence's parts are not rewritten
                // before it.
                let mut before = |function: &mut Function, info: &mut Info, id: ExprId| {
                    if matches!(function.expr(id), Some(Expr::Var(_) | Expr::Const(_))) {
                        return None;
                    }
                    let search = Search {
                        function,
                        info,
                        facts: &facts,
                        at,
                    };
                    let (found, remainder) = match search.remainder(id) {
                        Some(found) => (found, true),
                        None => (search.quotient(id)?, false),
                    };
                    let folded = search.folded(id, found.x);
                    let op = match (found.signed, remainder) {
                        (false, false) => Binary::UDiv,
                        (true, false) => Binary::SDiv,
                        (false, true) => Binary::URem,
                        (true, true) => Binary::SRem,
                    };
                    let d = Bits::from_u128(found.width, found.divisor);
                    let d = append(function, info, Expr::Const(d), id);
                    let result = append(function, info, Expr::Binary(op, found.x, d), id);
                    if found.taken == found.width {
                        function.provenance.absorb_expr(result, &folded);
                        return Some(result);
                    }
                    let low = Expr::Extract {
                        value: result,
                        offset: 0,
                        width: found.taken,
                    };
                    let low = append(function, info, low, id);
                    function.provenance.absorb_expr(low, &folded);
                    Some(low)
                };
                rebuild(
                    function,
                    &mut info,
                    root,
                    &mut memo,
                    &mut before,
                    &mut |_, _, _| None,
                );
            }
            let mut stmt_changed = false;
            if let Some(stmt) = function.stmts.get_mut(at.0 as usize) {
                map_roots(stmt, &mut |root| {
                    let new = memo.get(&root).copied().unwrap_or(root);
                    stmt_changed |= new != root;
                    new
                });
            }
            changed |= stmt_changed;
        }
        cx.fuel.spend(size(function).min(cx.fuel.left()))?;
        Ok(changed.into())
    }
}
