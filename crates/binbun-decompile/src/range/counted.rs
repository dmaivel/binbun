//! Counted loops: which loops count a variable by a constant step towards
//! a bound, what their test is equivalent to, and the counter's range
//! ([`counted`]).

use alloc::vec::Vec;
use core::fmt;

use binbun_ast::ir::{Expr, ExprId, Function, Place, Stmt, StmtId, VarId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, Unary};

use super::facts::{
    Fact, Interval, Known, Rel, Term, WIDEST, equivalent, extension, fact_of, max, min, narrowed,
    term, value,
};
use super::walk::{Index, before};
use crate::simplify::expr::in_memory;

/// A loop's canonical test: the counter against the bound, `i < n` (or
/// `<=`) counting up, `n < i` (or `<=`) counting down.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Test {
    /// Whether the counter counts up.
    pub up: bool,
    /// `<` (else `<=`).
    pub strict: bool,
    /// Read signed (else unsigned).
    pub signed: bool,
}

impl Test {
    /// Its operation.
    pub const fn op(self) -> Binary {
        match (self.strict, self.signed) {
            (true, true) => Binary::SLt,
            (true, false) => Binary::ULt,
            (false, true) => Binary::SLe,
            (false, false) => Binary::ULe,
        }
    }

    /// Its operands in order, given the counter's and the bound's: the
    /// counter first counting up.
    pub const fn operands(self, counter: ExprId, bound: ExprId) -> (ExprId, ExprId) {
        if self.up {
            (counter, bound)
        } else {
            (bound, counter)
        }
    }

    /// The test as a fact, the counter being `counter`.
    fn fact(self, counter: Term, bound: Term, width: u16) -> Fact {
        let rel = if self.strict {
            Rel::Lt(self.signed)
        } else {
            Rel::Le(self.signed)
        };
        let (a, b) = if self.up {
            (counter, bound)
        } else {
            (bound, counter)
        };
        Fact { a, rel, b, width }
    }
}

/// A counted loop: `counter` stepped by `delta` once per iteration (the
/// last statement of the body, or a `for`'s step), towards `bound`; its
/// test is [`Counted::test`] wherever it is evaluated (for a
/// `do`-`while`, including the first iteration, which it does not test).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Counted {
    /// The counter.
    pub counter: VarId,
    /// Its width.
    pub width: u16,
    /// The step: `counter = counter + delta`.
    pub step: StmtId,
    /// What the step adds, read signed (not 0).
    pub delta: i128,
    /// The counter's last write before the loop, if the walk back found
    /// it.
    pub init: Option<StmtId>,
    /// The bound: a constant, or a variable the loop does not write.
    pub bound: Term,
    /// Where the condition compares the counter with the bound (a
    /// variable) extended: sign (`true`) or zero, and the variable's own
    /// width.
    pub extension: Option<(bool, u16)>,
    /// The counter's read in the loop's condition.
    pub counter_read: ExprId,
    /// The bound's read in the loop's condition.
    pub bound_read: ExprId,
    /// The test the condition is equivalent to.
    pub test: Test,
    /// Whether the condition is that test already (else a `!=`, or the
    /// test under `!`).
    pub canonical: bool,
    /// For a `do`-`while`: the `if` it alone is the `then` of, whose
    /// condition holds exactly where the test does at the first iteration.
    pub guard: Option<StmtId>,
    /// The values the counter has anywhere in the loop (its condition,
    /// body and step), read as the test reads it.
    pub range: Option<Interval>,
    /// Whether every value of the counter in the loop is the same read
    /// signed or unsigned (`0..=` the signed maximum).
    pub counter_free: bool,
    /// Whether the bound is a variable whose value in the loop is the same
    /// read signed or unsigned (at its own width).
    pub bound_free: bool,
}

/// Why a loop is not counted (or its test not proved), for counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Refused {
    /// Its last statement (a `for`'s one step) does not add a constant to
    /// a variable of at most 64 bits not in memory.
    Step,
    /// Something else in the loop writes the counter.
    Counter,
    /// Control may enter the loop elsewhere (a label in it), or a
    /// `continue` skips the step.
    Entered,
    /// The condition does not compare the counter with a constant or a
    /// variable (or its zero or sign extension), in the direction it
    /// counts.
    Test,
    /// The loop writes the bound.
    Bound,
    /// What the test needs at entry is not proved (a `do`-`while`'s first
    /// test; where `!=` and `<` would differ), or the step may pass a `!=`
    /// bound.
    Entry,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Step => "step",
            Self::Counter => "counter",
            Self::Entered => "entered",
            Self::Test => "test",
            Self::Bound => "bound",
            Self::Entry => "entry",
        })
    }
}

/// The loop forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    /// `do { B; S } while (c)`.
    Do,
    /// `while (c) { B; S }`.
    While,
    /// `for (…; c; S) { B }`.
    For,
}

/// The condition as the counter against the bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmp {
    Eq,
    Ne,
    Lt(bool),
    Le(bool),
    Gt(bool),
    Ge(bool),
}

impl Cmp {
    const fn negated(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Lt(s) => Self::Ge(s),
            Self::Le(s) => Self::Gt(s),
            Self::Gt(s) => Self::Le(s),
            Self::Ge(s) => Self::Lt(s),
        }
    }
}

/// `counter = counter ± constant` at `id`: the counter, the delta (read
/// signed) and the width.
fn stepping(function: &Function, id: StmtId) -> Option<(VarId, i128, u16)> {
    let &Stmt::Assign {
        place: Place::Var(counter),
        value: sum,
    } = function.stmt(id)?
    else {
        return None;
    };
    let &Expr::Binary(op, a, b) = function.expr(sum)? else {
        return None;
    };
    let is_counter = |e: ExprId| matches!(function.expr(e), Some(&Expr::Var(v)) if v == counter);
    let constant = |e: ExprId| match function.expr(e) {
        Some(&Expr::Const(bits)) => Some(bits),
        _ => None,
    };
    let (bits, negate): (Bits, bool) = if op == Binary::Add && is_counter(a) {
        (constant(b)?, false)
    } else if op == Binary::Add && is_counter(b) {
        (constant(a)?, false)
    } else if op == Binary::Sub && is_counter(a) {
        (constant(b)?, true)
    } else {
        return None;
    };
    let width = bits.width();
    if !(2..=WIDEST).contains(&width) || in_memory(function, counter) {
        return None;
    }
    let delta = value(bits, true);
    let delta = if negate { -delta } else { delta };
    (delta != 0).then_some((counter, delta, width))
}

/// The condition `id` as `counter cmp bound`: the comparison and the
/// counter's and the bound's reads.
fn test_of(function: &Function, mut id: ExprId, counter: VarId) -> Option<(Cmp, ExprId, ExprId)> {
    let mut holds = true;
    for _ in 0..8 {
        let &Expr::Unary(Unary::Not, inner) = function.expr(id)? else {
            break;
        };
        id = inner;
        holds = !holds;
    }
    let &Expr::Binary(op, a, b) = function.expr(id)? else {
        return None;
    };
    let is_counter = |e: ExprId| matches!(function.expr(e), Some(&Expr::Var(v)) if v == counter);
    let (left, counter_read, bound_read) = match (is_counter(a), is_counter(b)) {
        (true, false) => (true, a, b),
        (false, true) => (false, b, a),
        (true, true) | (false, false) => return None,
    };
    let cmp = match (op, left) {
        (Binary::Eq, _) => Cmp::Eq,
        (Binary::Ne, _) => Cmp::Ne,
        (Binary::SLt, true) => Cmp::Lt(true),
        (Binary::ULt, true) => Cmp::Lt(false),
        (Binary::SLe, true) => Cmp::Le(true),
        (Binary::ULe, true) => Cmp::Le(false),
        (Binary::SLt, false) => Cmp::Gt(true),
        (Binary::ULt, false) => Cmp::Gt(false),
        (Binary::SLe, false) => Cmp::Ge(true),
        (Binary::ULe, false) => Cmp::Ge(false),
        _ => return None,
    };
    let cmp = if holds { cmp } else { cmp.negated() };
    Some((cmp, counter_read, bound_read))
}

/// Whether a statement of `block` (or one it holds) continues `loop_id`.
fn continued(function: &Function, block: &[StmtId], loop_id: StmtId) -> bool {
    let mut work = block.to_vec();
    while let Some(id) = work.pop() {
        match function.stmt(id) {
            Some(&Stmt::Continue(target)) if target == loop_id => return true,
            Some(stmt) => work.extend(stmt.blocks().flatten().copied()),
            None => {}
        }
    }
    false
}

/// The values `id` may have (read `signed`, `width` bits) under `known`:
/// constants, variables, zero or sign extensions of variables (their
/// values, [`bound_interval`]), and sums and differences with a constant
/// that do not wrap; any value otherwise.
fn evaluate(
    function: &Function,
    known: &Known<'_>,
    id: ExprId,
    signed: bool,
    width: u16,
) -> Interval {
    let full = Interval::full(signed, width);
    if let Some(term) = term(function, id) {
        return known.interval(term, signed, width);
    }
    if let Some((var, sign, from)) = extension(function, id) {
        return bound_interval(known, Term::Var(var), Some((sign, from)), signed, width);
    }
    let Some(&Expr::Binary(op, a, b)) = function.expr(id) else {
        return full;
    };
    let constant = |e: ExprId| match function.expr(e) {
        Some(&Expr::Const(bits)) if bits.width() == width => Some(value(bits, signed)),
        _ => None,
    };
    let found = match (op, constant(a), constant(b)) {
        (Binary::Add, _, Some(c)) => Some((a, c)),
        (Binary::Add, Some(c), None) => Some((b, c)),
        (Binary::Sub, _, Some(c)) => Some((a, -c)),
        (_, _, _) => None,
    };
    let Some((inner, add)) = found else {
        return full;
    };
    let Some(Term::Var(var)) = term(function, inner) else {
        return full;
    };
    let base = known.interval(Term::Var(var), signed, width);
    if base.is_empty() {
        return full;
    }
    // A sum modulo 2^width: unsigned, a constant may stand for its
    // difference with 2^width.
    let span = 1i128 << width;
    for shift in [0, -span, span] {
        let moved = Interval {
            lo: base.lo + add + shift,
            hi: base.hi + add + shift,
        };
        if moved.lo >= full.lo && moved.hi <= full.hi {
            return moved;
        }
    }
    full
}

/// A loop's shape as a counted loop, before anything is proved.
struct Shape {
    form: Form,
    condition: ExprId,
    step: StmtId,
    counter: VarId,
    delta: i128,
    width: u16,
    cmp: Cmp,
    counter_read: ExprId,
    bound_read: ExprId,
    bound: Term,
    extension: Option<(bool, u16)>,
}

/// Loop `id` as a counted loop's shape: a step, a counter nothing else in
/// the loop writes, no way in but its top, a test of the counter against
/// a bound the loop does not write, in the direction it counts.
fn shape(function: &Function, index: &Index, id: StmtId) -> Result<Shape, Refused> {
    let (form, condition, body, step) = match function.stmt(id) {
        Some(Stmt::DoWhile { body, condition }) => {
            let (&step, rest) = body.split_last().ok_or(Refused::Step)?;
            (Form::Do, *condition, rest, step)
        }
        Some(Stmt::While { condition, body }) => {
            let (&step, rest) = body.split_last().ok_or(Refused::Step)?;
            (Form::While, *condition, rest, step)
        }
        Some(Stmt::For {
            condition,
            step,
            body,
            ..
        }) => {
            let &[step] = step.as_slice() else {
                return Err(Refused::Step);
            };
            (Form::For, *condition, body.as_slice(), step)
        }
        Some(_) | None => return Err(Refused::Step),
    };
    let (counter, delta, width) = stepping(function, step).ok_or(Refused::Step)?;
    if body.iter().any(|&s| index.writes(s, counter)) {
        return Err(Refused::Counter);
    }
    if body.iter().any(|&s| index.labelled(s))
        || (form != Form::For && continued(function, body, id))
    {
        return Err(Refused::Entered);
    }
    let (cmp, counter_read, bound_read) =
        test_of(function, condition, counter).ok_or(Refused::Test)?;
    let (bound, extension) = if let Some(bound) = term(function, bound_read) {
        (bound, None)
    } else {
        let (var, signed, from) = extension(function, bound_read).ok_or(Refused::Test)?;
        (Term::Var(var), Some((signed, from)))
    };
    if function.width(bound_read) != Some(width) {
        return Err(Refused::Test);
    }
    if let Term::Var(n) = bound
        && body.iter().any(|&s| index.writes(s, n))
    {
        return Err(Refused::Bound);
    }
    let up = delta > 0;
    if matches!(
        (cmp, up),
        (Cmp::Eq, _) | (Cmp::Lt(_) | Cmp::Le(_), false) | (Cmp::Gt(_) | Cmp::Ge(_), true)
    ) {
        return Err(Refused::Test);
    }
    Ok(Shape {
        form,
        condition,
        step,
        counter,
        delta,
        width,
        cmp,
        counter_read,
        bound_read,
        bound,
        extension,
    })
}

/// The counted loop `id` is (a `while`, `do`-`while` or `for`), or why it
/// is not (see [`super::Ranges`] for the rules).
pub fn counted(function: &Function, index: &Index, id: StmtId) -> Result<Counted, Refused> {
    let shape = shape(function, index, id)?;
    let Shape {
        form,
        counter,
        delta,
        width,
        cmp,
        bound,
        extension,
        ..
    } = shape;
    let entered = before(function, index, id, counter);
    let start_value = entered.init.map(|(_, value)| value);
    let start_term = start_value.and_then(|value| term(function, value));
    // At entry the counter is its start: facts about it are about that.
    let facts: Vec<Fact> = match start_term {
        Some(start) => entered
            .facts
            .iter()
            .map(|fact| fact.substitute(counter, start))
            .collect(),
        None => entered.facts.clone(),
    };
    let known = Known::new(&facts);
    let start = start_term.unwrap_or(Term::Var(counter));
    let start_interval = |signed: bool| {
        let own = known.interval(start, signed, width);
        match (start_term, start_value) {
            (None, Some(value)) => own.meet(evaluate(function, &known, value, signed, width)),
            (Some(_) | None, _) => own,
        }
    };
    let (strict, candidates): (bool, &[bool]) = match cmp {
        Cmp::Ne => (true, &[false, true]),
        Cmp::Lt(true) | Cmp::Gt(true) => (true, &[true]),
        Cmp::Lt(false) | Cmp::Gt(false) => (true, &[false]),
        Cmp::Le(true) | Cmp::Ge(true) => (false, &[true]),
        Cmp::Le(false) | Cmp::Ge(false) | Cmp::Eq => (false, &[false]),
    };
    for &signed in candidates {
        let test = Test {
            up: delta > 0,
            strict,
            signed,
        };
        let (k, n) = (
            start_interval(signed),
            bound_interval(&known, bound, extension, signed, width),
        );
        // What must hold at entry: a `do`-`while`'s first iteration is
        // untested; where `!=` stands for `<`, they agree at entry only if
        // the start is not past the bound.
        let first = match (form, cmp) {
            (Form::Do, _) => Some(test),
            (Form::While | Form::For, Cmp::Ne) => Some(Test {
                strict: false,
                ..test
            }),
            (Form::While | Form::For, _) => None,
        };
        if let Some(first) = first
            && !holds(&known, first, (start, k), (bound, n), width, extension)
        {
            continue;
        }
        if cmp == Cmp::Ne && delta.abs() != 1 && !exact(k, n, delta) {
            continue;
        }
        let range = range(test, delta, k, n, width);
        let guard = entered.guard.filter(|&guard| {
            form == Form::Do
                && as_fact(test, start, bound, width, extension)
                    .is_some_and(|first| guarded(function, guard, counter, start_term, &first))
        });
        // The bound's own reads: of its own width.
        let own = extension.map_or(width, |(_, from)| from);
        return Ok(Counted {
            counter,
            width,
            step: shape.step,
            delta,
            init: entered.init.map(|(stmt, _)| stmt),
            bound,
            extension,
            counter_read: shape.counter_read,
            bound_read: shape.bound_read,
            test,
            canonical: cmp != Cmp::Ne
                && matches!(function.expr(shape.condition), Some(Expr::Binary(..))),
            guard,
            range,
            counter_free: range.is_some_and(|range| range.sign_free(signed, width)),
            bound_free: matches!(bound, Term::Var(_))
                && (known.interval(bound, true, own).sign_free(true, own)
                    || known.interval(bound, false, own).sign_free(false, own)),
        });
    }
    Err(Refused::Entry)
}

/// The values of the bound `bound` (`width` bits) read `signed` or not,
/// under `known`; with an `extension` (sign or zero, from the variable's
/// own width), those of the extended variable: a zero extension's are the
/// variable's read unsigned either way, a sign extension's read signed are
/// the variable's read signed, and read unsigned the same where those are
/// all of one sign (moved by `2^width` where negative).
fn bound_interval(
    known: &Known<'_>,
    bound: Term,
    extension: Option<(bool, u16)>,
    signed: bool,
    width: u16,
) -> Interval {
    let Some((sign, from)) = extension else {
        return known.interval(bound, signed, width);
    };
    if !sign {
        return known.interval(bound, false, from);
    }
    let own = known.interval(bound, true, from);
    if signed || own.is_empty() || own.lo >= 0 {
        own
    } else if own.hi < 0 {
        let span = 1i128 << width;
        Interval {
            lo: own.lo + span,
            hi: own.hi + span,
        }
    } else {
        Interval::full(false, width)
    }
}

/// `test` of the counter at `start` against `bound` (`width` bits) as a
/// fact; with an `extension` of the bound, as the fact about the bound
/// variable itself ([`narrowed`]: `start` a constant within the
/// extension's values), else `None`.
fn as_fact(
    test: Test,
    start: Term,
    bound: Term,
    width: u16,
    extension: Option<(bool, u16)>,
) -> Option<Fact> {
    let fact = test.fact(start, bound, width);
    match (extension, bound) {
        (None, _) => Some(fact),
        (Some((signed, from)), Term::Var(var)) => narrowed(fact, var, signed, from),
        (Some(_), Term::Const(_)) => None,
    }
}

/// Whether `test` holds of the start (its term and values) and the bound
/// (likewise; with its `extension`): by their values, or as a fact.
fn holds(
    known: &Known<'_>,
    test: Test,
    (start, k): (Term, Interval),
    (bound, n): (Term, Interval),
    width: u16,
    extension: Option<(bool, u16)>,
) -> bool {
    let by_values = !k.is_empty()
        && !n.is_empty()
        && match (test.up, test.strict) {
            (true, true) => k.hi < n.lo,
            (true, false) => k.hi <= n.lo,
            (false, true) => n.hi < k.lo,
            (false, false) => n.hi <= k.lo,
        };
    by_values
        || as_fact(test, start, bound, width, extension)
            .is_some_and(|fact| known.proves(fact.a, fact.rel, fact.b, fact.width))
}

/// Whether a `!=` bound `n` is met exactly stepping by `delta` from `k`:
/// both constants (points), `n - k` a multiple of `delta` in the
/// direction of the step.
fn exact(k: Interval, n: Interval, delta: i128) -> bool {
    if k.lo != k.hi || n.lo != n.hi {
        return false;
    }
    let distance = n.lo - k.lo;
    distance.signum() == delta.signum() && distance % delta == 0
}

/// The counter's values anywhere in the loop, from its start `k` and the
/// bound `n` (read as `test` reads them), stepping by `delta`; `None` if
/// a step could wrap.
///
/// Counting up with `i < n` at the top of each iteration (the test, or
/// for a `do`-`while` its proved first test), the step writes at most
/// `n - 1 + delta`, and never less than `k`: no step wraps if that is at
/// most the domain's maximum (`<=`: `n + delta`). Counting down, the
/// mirror image.
fn range(test: Test, delta: i128, k: Interval, n: Interval, width: u16) -> Option<Interval> {
    if k.is_empty() || n.is_empty() {
        return None;
    }
    let step = delta.abs();
    let slack = if test.strict { step - 1 } else { step };
    if test.up {
        let top = n.hi + slack;
        (top <= max(test.signed, width)).then_some(Interval {
            lo: k.lo,
            hi: k.hi.max(top),
        })
    } else {
        let bottom = n.lo - slack;
        (bottom >= min(test.signed, width)).then_some(Interval {
            lo: k.lo.min(bottom),
            hi: k.hi,
        })
    }
}

/// Whether `if` statement `guard`'s condition holds exactly where `first`
/// (the test at the first iteration, the counter at its start) does.
fn guarded(
    function: &Function,
    guard: StmtId,
    counter: VarId,
    start_term: Option<Term>,
    first: &Fact,
) -> bool {
    let Some(&Stmt::If { condition, .. }) = function.stmt(guard) else {
        return false;
    };
    let Some(fact) = fact_of(function, condition) else {
        return false;
    };
    let fact = match start_term {
        Some(start) => fact.substitute(counter, start),
        None => fact,
    };
    equivalent(&fact, first)
}
