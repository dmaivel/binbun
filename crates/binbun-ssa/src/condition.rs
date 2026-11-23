//! What a 1-bit condition says as a comparison of two values: the flag
//! patterns compare-and-branch leaves in L1 (x86: the borrow, zero, sign
//! and overflow flags of a subtraction; AArch64: its carry `b <= a`, zero
//! and sign and overflow; combined as each condition code does), read back
//! as `a < b`, `a == b` and so on.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::Value as Bitvalue;
use binbun_semantics::ir::{Binary, Flag, FloatOp, FloatOutput, Format, LaneOp, Unary};

use crate::constant::{Constants, evaluate};
use crate::ir::{Definition, Function, Op, Type, Value};

/// How two values compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Relation {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Unsigned less than.
    ULt,
    /// Unsigned less than or equal.
    ULe,
    /// Unsigned greater than.
    UGt,
    /// Unsigned greater than or equal.
    UGe,
    /// Signed less than.
    SLt,
    /// Signed less than or equal.
    SLe,
    /// Signed greater than.
    SGt,
    /// Signed greater than or equal.
    SGe,
}

impl Relation {
    /// The relation that holds exactly when `self` does not.
    #[must_use]
    pub const fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::ULt => Self::UGe,
            Self::ULe => Self::UGt,
            Self::UGt => Self::ULe,
            Self::UGe => Self::ULt,
            Self::SLt => Self::SGe,
            Self::SLe => Self::SGt,
            Self::SGt => Self::SLe,
            Self::SGe => Self::SLt,
        }
    }

    /// The relation with its operands swapped (`a < b` is `b > a`).
    #[must_use]
    pub const fn swap(self) -> Self {
        match self {
            Self::Eq => Self::Eq,
            Self::Ne => Self::Ne,
            Self::ULt => Self::UGt,
            Self::ULe => Self::UGe,
            Self::UGt => Self::ULt,
            Self::UGe => Self::ULe,
            Self::SLt => Self::SGt,
            Self::SLe => Self::SGe,
            Self::SGt => Self::SLt,
            Self::SGe => Self::SLe,
        }
    }
}

/// `left relation right`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Comparison {
    /// How they compare.
    pub relation: Relation,
    /// The left operand.
    pub left: Value,
    /// The right operand.
    pub right: Value,
}

impl Comparison {
    /// The comparison that holds exactly when `self` does not.
    #[must_use]
    pub const fn negate(self) -> Self {
        Self {
            relation: self.relation.negate(),
            ..self
        }
    }
}

/// The comparison the 1-bit `condition` of `function` is, if it is one
/// (`constants` tells which operands are zero).
pub fn comparison(
    function: &Function,
    constants: &Constants,
    condition: Value,
) -> Option<Comparison> {
    let op = defining(function, condition)?;
    let compare = |relation, left, right| {
        Some(Comparison {
            relation,
            left,
            right,
        })
    };
    let zero = |value: Value| constants.constant(value).is_some_and(|bits| bits.is_zero());
    match *op {
        Op::Binary(Binary::ULt, a, b) => compare(Relation::ULt, a, b),
        Op::Binary(Binary::ULe, a, b) => compare(Relation::ULe, a, b),
        Op::Binary(Binary::SLt, a, b) => compare(Relation::SLt, a, b),
        Op::Binary(Binary::SLe, a, b) => compare(Relation::SLe, a, b),
        // The zero flag: `a - b == 0`; `test a, a`: `a & a == 0`.
        Op::Binary(relation @ (Binary::Eq | Binary::Ne), x, y) => {
            let relation = if relation == Binary::Eq {
                Relation::Eq
            } else {
                Relation::Ne
            };
            // Sign different from (equal to) overflow: less (not less).
            if let Some(less) = signed_less(function, constants, x, y)
                .or_else(|| signed_less(function, constants, y, x))
            {
                return Some(if relation == Relation::Ne {
                    less
                } else {
                    less.negate()
                });
            }
            let (value, other) = if zero(y) {
                (x, y)
            } else if zero(x) {
                (y, x)
            } else {
                return compare(relation, x, y);
            };
            match defining(function, value) {
                Some(&Op::Binary(Binary::Sub, a, b)) => compare(relation, a, b),
                Some(&Op::Binary(Binary::And, a, b)) if a == b => compare(relation, a, other),
                Some(_) | None => compare(relation, value, other),
            }
        }
        // The borrow flag of `a - b`.
        Op::Flag(Flag::SubBorrow, a, b, c) if zero(c) => compare(Relation::ULt, a, b),
        Op::Unary(Unary::Not, x) => comparison(function, constants, x).map(Comparison::negate),
        // Borrow or zero: below or equal; sign differs from overflow (or
        // zero): less (or equal).
        Op::Binary(Binary::Or, x, y) => {
            let p = comparison(function, constants, x)?;
            let q = comparison(function, constants, y)?;
            let (strict, equal) = if q.relation == Relation::Eq {
                (p, q)
            } else {
                (q, p)
            };
            let same = equal.relation == Relation::Eq
                && ((strict.left, strict.right) == (equal.left, equal.right)
                    || (strict.left, strict.right) == (equal.right, equal.left));
            match strict.relation {
                Relation::ULt if same => compare(Relation::ULe, strict.left, strict.right),
                Relation::SLt if same => compare(Relation::SLe, strict.left, strict.right),
                Relation::Eq
                | Relation::Ne
                | Relation::ULt
                | Relation::ULe
                | Relation::UGt
                | Relation::UGe
                | Relation::SLt
                | Relation::SLe
                | Relation::SGt
                | Relation::SGe => None,
            }
        }
        // Not below and not equal: above (AArch64 `hi`, carry and not
        // zero); likewise signed (`gt`).
        Op::Binary(Binary::And, x, y) => strict(
            comparison(function, constants, x)?,
            comparison(function, constants, y)?,
        ),
        Op::Binary(Binary::Xor, x, y) => signed_less(function, constants, x, y)
            .or_else(|| signed_less(function, constants, y, x)),
        Op::Const(_)
        | Op::Undefined(..)
        | Op::Unary(..)
        | Op::Binary(..)
        | Op::Flag(..)
        | Op::Extract { .. }
        | Op::Concat { .. }
        | Op::Extend { .. }
        | Op::Select { .. }
        | Op::Lanes { .. }
        | Op::Float { .. }
        | Op::Load { .. }
        | Op::Store { .. }
        | Op::Intrinsic { .. }
        | Op::Call { .. }
        | Op::SystemCall { .. }
        | Op::Landing { .. } => None,
    }
}

/// Both `p` and `q` hold: a non-strict comparison and the two operands'
/// inequality make the strict one (`a <= b && a != b`: `a < b`).
fn strict(p: Comparison, q: Comparison) -> Option<Comparison> {
    let (loose, unequal) = if q.relation == Relation::Ne {
        (p, q)
    } else {
        (q, p)
    };
    let same = unequal.relation == Relation::Ne
        && ((loose.left, loose.right) == (unequal.left, unequal.right)
            || (loose.left, loose.right) == (unequal.right, unequal.left));
    let relation = match loose.relation {
        Relation::ULe => Relation::ULt,
        Relation::UGe => Relation::UGt,
        Relation::SLe => Relation::SLt,
        Relation::SGe => Relation::SGt,
        Relation::Eq
        | Relation::Ne
        | Relation::ULt
        | Relation::UGt
        | Relation::SLt
        | Relation::SGt => return None,
    };
    same.then_some(Comparison { relation, ..loose })
}

/// `sign ^ overflow` of `left - right`: `left < right`, signed (`sign`
/// being the top bit of the difference, `overflow` its overflow flag).
fn signed_less(
    function: &Function,
    constants: &Constants,
    sign: Value,
    overflow: Value,
) -> Option<Comparison> {
    let Op::Flag(Flag::SubOverflow, left, right, borrow) = *defining(function, overflow)? else {
        return None;
    };
    if !constants
        .constant(borrow)
        .is_some_and(|bits| bits.is_zero())
    {
        return None;
    }
    let Op::Extract {
        value,
        offset,
        width: 1,
    } = *defining(function, sign)?
    else {
        return None;
    };
    let Op::Binary(Binary::Sub, minuend, subtrahend) = *defining(function, value)? else {
        return None;
    };
    let top = match function.ty(value)? {
        Type::Bits(width) => width.checked_sub(1)?,
        Type::Memory => return None,
    };
    (offset == top && (minuend, subtrahend) == (left, right)).then_some(Comparison {
        relation: Relation::SLt,
        left,
        right,
    })
}

/// The operation that defines `value`, if an instruction does.
pub fn defining(function: &Function, value: Value) -> Option<&Op> {
    match function.value(value)?.definition {
        Definition::Result { inst, .. } => function.inst(inst).map(|i| &i.op),
        Definition::Parameter { .. } => None,
    }
}

/// How two floats compare where a 1-bit value holds: the flag patterns
/// a float comparison leaves (x86's `ucomisd`: ZF, PF and CF from the
/// four outcomes, then a condition code of them), read back as the
/// outcomes themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FloatRelation {
    /// The left operand.
    pub left: Value,
    /// The right operand.
    pub right: Value,
    /// Their format.
    pub format: Format,
    /// Whether the comparison is a signalling one
    /// ([`FloatOp::Compare`]).
    pub signaling: bool,
    /// The outcomes the value is 1 for (it is 0 for the others), by
    /// their bits in the comparison's value: less (bit 0), equal (1),
    /// greater (2), unordered (3). Not none and not all.
    pub holds: u8,
}

/// How many operations [`float_relation`] looks through, and how deep.
const CONE: usize = 48;
const DEPTH: usize = 12;

/// The float relation `condition` of `function` is, if it is one: a
/// value computed from the outcome of one float comparison (of one lane)
/// and constants (by `constants`: `xor eax, eax` before `setp al` is
/// one) alone by the operations flags are made and chosen with
/// (bits taken and put together, `and`, `or`, `xor`, `not`, equality, a
/// choice: `ucomisd` then `setp`, `cmovne`), 1 for some of the
/// comparison's four outcomes and 0 for the others (found by evaluating
/// it for each). A condition on integers stops at its first arithmetic.
pub fn float_relation(
    function: &Function,
    constants: &Constants,
    condition: Value,
) -> Option<FloatRelation> {
    let Some(Type::Bits(width)) = function.ty(condition) else {
        return None;
    };
    let mut cone = Vec::new();
    let mut compare = None;
    collect(
        function,
        constants,
        condition,
        &mut cone,
        &mut compare,
        DEPTH,
    )?;
    let compare = compare?;
    let &Op::Float {
        op: FloatOp::Compare { signaling },
        format,
        operands: [left, right, _],
        ..
    } = defining(function, compare)?
    else {
        return None;
    };
    let mut holds = 0u8;
    for outcome in 0..4u8 {
        let mut values: BTreeMap<Value, Bitvalue> = BTreeMap::new();
        values.insert(compare, Bitvalue::defined(Bits::from_u64(4, 1 << outcome)));
        for &value in &cone {
            let result = if let Some(bits) = constants.constant(value) {
                Bitvalue::defined(bits)
            } else {
                let op = defining(function, value)?;
                let operands: Vec<Bitvalue> = op
                    .operands()
                    .into_iter()
                    .map(|operand| values.get(&operand).copied())
                    .collect::<Option<_>>()?;
                evaluate(op, &operands)?
            };
            values.insert(value, result);
        }
        let value = values.get(&condition)?.known()?;
        if value == Bits::from_u64(width, 1) {
            holds |= 1 << outcome;
        } else if !value.is_zero() {
            return None;
        }
    }
    (holds != 0 && holds != 0b1111).then_some(FloatRelation {
        left,
        right,
        format,
        signaling,
        holds,
    })
}

/// The values `value` is computed from by pure operations, operands
/// first, into `cone`, down to constants and to one float comparison of
/// one lane (`compare`); `None` if it is computed from anything else, or
/// from more than [`CONE`] operations, or more than `depth` deep.
fn collect(
    function: &Function,
    constants: &Constants,
    value: Value,
    cone: &mut Vec<Value>,
    compare: &mut Option<Value>,
    depth: usize,
) -> Option<()> {
    if cone.contains(&value) || *compare == Some(value) {
        return Some(());
    }
    if constants.constant(value).is_some() {
        return (cone.len() < CONE).then(|| cone.push(value));
    }
    let op = defining(function, value)?;
    let depth = depth.checked_sub(1)?;
    let plumbing = |binary: Binary| {
        matches!(
            binary,
            Binary::And | Binary::Or | Binary::Xor | Binary::Eq | Binary::Ne
        )
    };
    match op {
        Op::Float {
            op: FloatOp::Compare { .. },
            lanes: 1,
            output: FloatOutput::Value,
            ..
        } => {
            return compare.is_none().then(|| *compare = Some(value));
        }
        Op::Const(_)
        | Op::Unary(Unary::Not, _)
        | Op::Extract { .. }
        | Op::Concat { .. }
        | Op::Extend { .. }
        | Op::Select { .. }
        // The same on one lane (`maxsd`'s choice is made of these).
        | Op::Lanes {
            lanes: 1,
            op:
                LaneOp::Unary(Unary::Not)
                | LaneOp::Extract { .. }
                | LaneOp::Extend { .. }
                | LaneOp::Select,
            ..
        } => {}
        Op::Binary(binary, ..)
        | Op::Lanes {
            lanes: 1,
            op: LaneOp::Binary(binary),
            ..
        } if plumbing(*binary) => {}
        Op::Undefined(..)
        | Op::Unary(..)
        | Op::Binary(..)
        | Op::Flag(..)
        | Op::Lanes { .. }
        | Op::Float { .. }
        | Op::Load { .. }
        | Op::Store { .. }
        | Op::Intrinsic { .. }
        | Op::Call { .. }
        | Op::SystemCall { .. }
        | Op::Landing { .. } => return None,
    }
    for operand in op.operands() {
        collect(function, constants, operand, cone, compare, depth)?;
    }
    if cone.len() >= CONE {
        return None;
    }
    cone.push(value);
    Some(())
}
