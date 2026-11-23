//! Evaluation of AARCHMRS decode conditions on instruction words.

use std::cell::OnceCell;

use xtask::aarchmrs::{BinaryOp, Encodeset, Expr, Pattern};

use super::cube::{Cube, cubes};
use crate::Result;

/// The value of a (sub)expression.
#[derive(Debug, Clone, Copy)]
enum Value<'a> {
    Bool(bool),
    /// A field's bits.
    Bits(u64),
    /// A constant pattern, possibly with `x` bits.
    Pattern(&'a Pattern),
}

/// The fields a condition may test: name → (lowest bit, width).
pub fn field(encoding: &Encodeset, name: &str) -> Option<(u32, u32)> {
    encoding
        .fields
        .iter()
        .find(|f| f.name.as_deref() == Some(name))
        .map(|f| (f.start, f.width))
}

/// The bits of `word` in field `(start, width)`.
pub const fn extract(word: u32, (start, width): (u32, u32)) -> u64 {
    ((word as u64) >> start) & ((1 << width) - 1)
}

/// The word bits of field `(start, width)` (width at least 1).
pub const fn field_mask((start, width): (u32, u32)) -> u32 {
    (u32::MAX >> (32 - width)) << start
}

/// Mask of the word bits the condition's field tests read.
pub fn bits_read(condition: &Expr, encoding: &Encodeset) -> Result<u32> {
    let mut mask = 0;
    let mut error = None;
    condition.walk(&mut |expr| {
        if let Expr::Identifier(name) = expr {
            if name.starts_with("FEAT_") {
                return;
            }
            match field(encoding, name) {
                Some(range) => mask |= field_mask(range),
                None => error = Some(format!("`{condition}` names unknown field {name}")),
            }
        }
    });
    error.map_or(Ok(mask), |error| Err(error.into()))
}

/// Whether `condition` holds for `word`, with `feature` deciding feature
/// checks.
pub fn holds(
    condition: &Expr,
    encoding: &Encodeset,
    feature: &dyn Fn(&str) -> bool,
    word: u32,
) -> Result<bool> {
    match eval(condition, encoding, feature, word)? {
        Value::Bool(value) => Ok(value),
        Value::Bits(_) | Value::Pattern(_) => {
            Err(format!("`{condition}` is not a condition").into())
        }
    }
}

/// The words of `space` the condition rejects, as cubes over the bits it
/// reads; the cubes leave out the bits `space` fixes. Fails if evaluating
/// the condition fails for any word (`&&` and `||` short-circuit, so an
/// unsupported subexpression may be reached for some words only).
pub fn rejected(
    condition: &Expr,
    encoding: &Encodeset,
    feature: &dyn Fn(&str) -> bool,
    space: Cube,
) -> Result<Vec<Cube>> {
    let bits = bits_read(condition, encoding)?;
    let failure = OnceCell::new();
    let found = cubes(space, bits, |word| {
        holds(condition, encoding, feature, word).map_or_else(
            |error| {
                // Only the first failure is reported.
                let _ = failure.set(error);
                false
            },
            |holds| !holds,
        )
    })?;
    match failure.into_inner() {
        Some(error) => Err(error),
        None => Ok(found),
    }
}

fn eval<'a>(
    expr: &'a Expr,
    encoding: &Encodeset,
    feature: &dyn Fn(&str) -> bool,
    word: u32,
) -> Result<Value<'a>> {
    let eval_bool = |expr: &'a Expr| -> Result<bool> { holds(expr, encoding, feature, word) };
    Ok(match expr {
        Expr::Bool(value) => Value::Bool(*value),
        Expr::Bits(pattern) => Value::Pattern(pattern),
        Expr::Identifier(name) => {
            let range = field(encoding, name).ok_or_else(|| format!("unknown field {name}"))?;
            Value::Bits(extract(word, range))
        }
        Expr::Not(operand) => Value::Bool(!eval_bool(operand)?),
        Expr::Call { .. } => {
            let name = expr
                .feature_check()
                .ok_or_else(|| format!("`{expr}` in a decode condition"))?;
            Value::Bool(feature(name))
        }
        Expr::Binary { op, left, right } => match op {
            BinaryOp::And => Value::Bool(eval_bool(left)? && eval_bool(right)?),
            BinaryOp::Or => Value::Bool(eval_bool(left)? || eval_bool(right)?),
            BinaryOp::Eq | BinaryOp::Ne => {
                let left = eval(left, encoding, feature, word)?;
                let right = eval(right, encoding, feature, word)?;
                let equal =
                    equal(left, right).ok_or_else(|| format!("cannot compare in `{expr}`"))?;
                Value::Bool(equal == (*op == BinaryOp::Eq))
            }
            BinaryOp::In => {
                let left = eval(left, encoding, feature, word)?;
                let Expr::Set(items) = right.as_ref() else {
                    return Err(format!("`{expr}`: IN without a set").into());
                };
                let mut any = false;
                for item in items {
                    let item = eval(item, encoding, feature, word)?;
                    any |=
                        equal(left, item).ok_or_else(|| format!("cannot compare in `{expr}`"))?;
                }
                Value::Bool(any)
            }
            BinaryOp::Lt
            | BinaryOp::Gt
            | BinaryOp::Ge
            | BinaryOp::Add
            | BinaryOp::Concat
            | BinaryOp::Implies
            | BinaryOp::Iff => return Err(format!("`{expr}` in a decode condition").into()),
        },
        Expr::Integer(_)
        | Expr::Set(_)
        | Expr::Index { .. }
        | Expr::Dot(_)
        | Expr::Field { .. }
        | Expr::String(_) => return Err(format!("`{expr}` in a decode condition").into()),
    })
}

fn equal(left: Value<'_>, right: Value<'_>) -> Option<bool> {
    match (left, right) {
        (Value::Bits(bits), Value::Pattern(pattern))
        | (Value::Pattern(pattern), Value::Bits(bits)) => Some(pattern.matches(bits)),
        (Value::Bits(left), Value::Bits(right)) => Some(left == right),
        (Value::Bool(left), Value::Bool(right)) => Some(left == right),
        (Value::Bool(_) | Value::Pattern(_), _) | (Value::Bits(_), Value::Bool(_)) => None,
    }
}
