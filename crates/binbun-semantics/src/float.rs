//! IEEE 754 arithmetic for [`Expr::Float`](crate::ir::Expr::Float): one
//! lane at a time, by `rustc_apfloat` (a port of LLVM's `APFloat`, exact in
//! every format and rounding), and a square root of binbun's own (`APFloat`
//! has none) from an exact integer square root.
//!
//! A NaN result is the format's default NaN (positive, quiet, payload 0).
//! Exceptions follow IEEE 754's default handling: underflow is a tiny
//! result that is inexact, tiny meaning that, rounded with an unbounded
//! exponent, it is below the smallest normal number; overflow is a result
//! that, rounded with an unbounded exponent, exceeds the largest finite
//! number. `APFloat` differs at both edges: it reports no overflow when a
//! rounding toward zero gives the largest finite number, and no underflow
//! when a result rounds up to the smallest normal number from below (it
//! takes "tiny" as "rounded to a subnormal"). binbun checks such results
//! again in a format with a wider exponent range and more precision (none
//! is wider than the x87 format, whose results keep `APFloat`'s answer,
//! except conversions from it, whose operand is exact as it is).

use core::cmp::Ordering;

use alloc::vec::Vec;

use rustc_apfloat::ieee::{Double, Half, Single, X87DoubleExtended};
use rustc_apfloat::{ExpInt, Float, FloatConvert, Round, Status, StatusAnd};

use crate::bits::Bits;
use crate::ir::{FloatOp, Format, Rounding};

/// A format `rustc_apfloat` computes in, convertible to all the others.
trait Ieee:
    Float
    + FloatConvert<Half>
    + FloatConvert<Single>
    + FloatConvert<Double>
    + FloatConvert<X87DoubleExtended>
{
}

impl<T> Ieee for T where
    T: Float
        + FloatConvert<Half>
        + FloatConvert<Single>
        + FloatConvert<Double>
        + FloatConvert<X87DoubleExtended>
{
}

/// `op` on one lane of `format`: the result and its exceptions (a bit per
/// [`Exception`](crate::ir::Exception)). `operands` are the lanes, as many
/// as `op` takes.
pub(crate) fn lane(
    op: FloatOp,
    format: Format,
    rounding: Rounding,
    operands: &[Bits],
) -> (Bits, u8) {
    let round = round(rounding);
    let result = match format {
        Format::Half => {
            let result = compute::<Half>(op, round, operands);
            let result = overflow::<Half, Single>(op, operands, result);
            underflow::<Half, Single>(op, round, operands, result)
        }
        Format::Single => {
            let result = compute::<Single>(op, round, operands);
            let result = overflow::<Single, Double>(op, operands, result);
            underflow::<Single, Double>(op, round, operands, result)
        }
        Format::Double => {
            let result = compute::<Double>(op, round, operands);
            let result = overflow::<Double, X87DoubleExtended>(op, operands, result);
            underflow::<Double, X87DoubleExtended>(op, round, operands, result)
        }
        Format::Extended => {
            let result = compute::<X87DoubleExtended>(op, round, operands);
            // A conversion's operand is exact in the x87 format itself, so
            // it decides a narrower target's edges; other operations keep
            // `APFloat`'s answer (no format is wider).
            if let FloatOp::Convert(_) = op {
                let result = overflow::<X87DoubleExtended, X87DoubleExtended>(op, operands, result);
                underflow::<X87DoubleExtended, X87DoubleExtended>(op, round, operands, result)
            } else {
                result
            }
        }
    };
    (result.value, result.status.bits())
}

/// `result` (of `op` on `operands`, of format `F`) with overflow raised if
/// it is the largest finite number of its format, inexact, and the exact
/// result is at least 2^(emax + 1): computed toward zero in `W`, whose
/// exponent range is wider, it is too.
fn overflow<F: Ieee + FloatConvert<W>, W: Ieee>(
    op: FloatOp,
    operands: &[Bits],
    result: StatusAnd<Bits>,
) -> StatusAnd<Bits> {
    let target = match op {
        FloatOp::Add
        | FloatOp::Sub
        | FloatOp::Mul
        | FloatOp::Div
        | FloatOp::MulAdd
        | FloatOp::FromInt { .. } => (width::<F>(), F::MAX_EXP),
        FloatOp::Convert(target) => match target {
            Format::Half => (16, Half::MAX_EXP),
            Format::Single => (32, Single::MAX_EXP),
            Format::Double => (64, Double::MAX_EXP),
            Format::Extended => return result,
        },
        FloatOp::Sqrt
        | FloatOp::RoundToIntegral
        | FloatOp::Compare { .. }
        | FloatOp::ToInt { .. } => return result,
    };
    if result.status != Status::INEXACT || !largest(result.value, target.0) {
        return result;
    }
    let exact = widened::<F, W>(op, Round::TowardZero, operands);
    let threshold = W::from_u128(1).value.scalbn(target.1 + 1);
    if exact.is_some_and(|exact| exact.abs() >= threshold) {
        (Status::OVERFLOW | Status::INEXACT).and(result.value)
    } else {
        result
    }
}

/// The exact result of `op` on `operands` (of format `F`) in `W`, rounded
/// as `round` says (or `None` for operations that cannot be tiny or huge).
/// An integer's conversion ([`FloatOp::FromInt`]) is the integer itself.
fn widened<F: Ieee + FloatConvert<W>, W: Ieee>(
    op: FloatOp,
    round: Round,
    operands: &[Bits],
) -> Option<W> {
    if let FloatOp::FromInt { signed } = op {
        let integer = operands.first()?;
        return Some(if signed {
            W::from_i128_r(integer.sext(128).low_u128().cast_signed(), round).value
        } else {
            W::from_u128_r(integer.low_u128(), round).value
        });
    }
    let wide: Vec<Bits> = operands
        .iter()
        .map(|bits| {
            let mut loses_info = false;
            let value: W = F::from_bits(bits.low_u128())
                .convert_r(Round::TowardZero, &mut loses_info)
                .value;
            Bits::from_u128(width::<W>(), value.to_bits())
        })
        .collect();
    match op {
        // A conversion's operand is exact in `F` already.
        FloatOp::Convert(_) => wide.first().map(|bits| W::from_bits(bits.low_u128())),
        FloatOp::Add | FloatOp::Sub | FloatOp::Mul | FloatOp::Div | FloatOp::MulAdd => {
            let value = compute::<W>(op, round, &wide).value;
            Some(W::from_bits(value.low_u128()))
        }
        FloatOp::Sqrt
        | FloatOp::RoundToIntegral
        | FloatOp::Compare { .. }
        | FloatOp::FromInt { .. }
        | FloatOp::ToInt { .. } => None,
    }
}

/// `result` (of `op` on `operands`, of format `F`, rounded as `round`
/// says) with underflow raised if it is the smallest normal number,
/// inexact, and tiny: rounded to `F`'s precision with an unbounded
/// exponent, below the smallest normal number. To nearest, that is an exact
/// result below 2^emin − 2^(emin − p − 1); rounding away from zero, at most
/// 2^emin − 2^(emin − p) (the largest `p`-bit number below 2^emin); toward
/// zero, never. Decided in `W` with a directed rounding, which keeps those
/// comparisons exact.
fn underflow<F: Ieee + FloatConvert<W>, W: Ieee>(
    op: FloatOp,
    round: Round,
    operands: &[Bits],
    result: StatusAnd<Bits>,
) -> StatusAnd<Bits> {
    let target = match op {
        FloatOp::Convert(target) => match target {
            Format::Half => (16, Half::MIN_EXP, Half::PRECISION),
            Format::Single => (32, Single::MIN_EXP, Single::PRECISION),
            Format::Double => (64, Double::MIN_EXP, Double::PRECISION),
            Format::Extended => return result,
        },
        FloatOp::Add | FloatOp::Sub | FloatOp::Mul | FloatOp::Div | FloatOp::MulAdd => {
            (width::<F>(), F::MIN_EXP, F::PRECISION)
        }
        FloatOp::Sqrt
        | FloatOp::RoundToIntegral
        | FloatOp::Compare { .. }
        | FloatOp::FromInt { .. }
        | FloatOp::ToInt { .. } => return result,
    };
    let (bits, emin, precision) = target;
    if result.status != Status::INEXACT || !smallest_normal(result.value, bits) {
        return result;
    }
    let negative = result.value.bit(bits - 1);
    let away = matches!(
        (round, negative),
        (Round::TowardPositive, false) | (Round::TowardNegative, true)
    );
    let p = ExpInt::try_from(precision).unwrap_or(ExpInt::MAX);
    let one = W::from_u128(1).value;
    let normal = one.scalbn(emin);
    let tiny = if away {
        // Rounded away from zero in `W`: at most the largest `p`-bit
        // number below 2^emin.
        let direction = if negative {
            Round::TowardNegative
        } else {
            Round::TowardPositive
        };
        let threshold = (normal - one.scalbn(emin - p)).value;
        widened::<F, W>(op, direction, operands).is_some_and(|x| x.abs() <= threshold)
    } else if round == Round::NearestTiesToEven || round == Round::NearestTiesToAway {
        let threshold = (normal - one.scalbn(emin - p - 1)).value;
        widened::<F, W>(op, Round::TowardZero, operands).is_some_and(|x| x.abs() < threshold)
    } else {
        false
    };
    if tiny {
        (Status::UNDERFLOW | Status::INEXACT).and(result.value)
    } else {
        result
    }
}

/// Whether `bits` (a `width`-bit float) is the smallest normal number of
/// its format, of either sign.
fn smallest_normal(bits: Bits, width: u16) -> bool {
    let magnitude = bits.low_u128() & ((1u128 << (width - 1)) - 1);
    let smallest = match width {
        16 => Half::smallest_normalized().to_bits(),
        32 => Single::smallest_normalized().to_bits(),
        64 => Double::smallest_normalized().to_bits(),
        _ => X87DoubleExtended::smallest_normalized().to_bits(),
    };
    magnitude == smallest
}

/// Whether `bits` (a `width`-bit float) is the largest finite number of
/// its format, of either sign: all exponent bits but the lowest set, and
/// the whole fraction.
fn largest(bits: Bits, width: u16) -> bool {
    let magnitude = bits.low_u128() & ((1u128 << (width - 1)) - 1);
    let largest = match width {
        16 => Half::largest().to_bits(),
        32 => Single::largest().to_bits(),
        64 => Double::largest().to_bits(),
        _ => X87DoubleExtended::largest().to_bits(),
    };
    magnitude == largest
}

const fn round(rounding: Rounding) -> Round {
    match rounding {
        Rounding::NearestEven => Round::NearestTiesToEven,
        Rounding::Down => Round::TowardNegative,
        Rounding::Up => Round::TowardPositive,
        Rounding::TowardZero => Round::TowardZero,
    }
}

/// The width of `F`'s values.
fn width<F: Float>() -> u16 {
    u16::try_from(F::BITS).unwrap_or(u16::MAX)
}

/// `result` as bits, with the default NaN for any NaN.
fn bits<F: Float>(result: StatusAnd<F>) -> StatusAnd<Bits> {
    let value = if result.value.is_nan() {
        F::NAN
    } else {
        result.value
    };
    result
        .status
        .and(Bits::from_u128(width::<F>(), value.to_bits()))
}

fn compute<F: Ieee>(op: FloatOp, round: Round, operands: &[Bits]) -> StatusAnd<Bits> {
    let raw = |index: usize| operands.get(index).copied().unwrap_or(Bits::zero(1));
    let value = |index: usize| F::from_bits(raw(index).low_u128());
    match op {
        FloatOp::Add => bits(value(0).add_r(value(1), round)),
        FloatOp::Sub => bits(value(0).sub_r(value(1), round)),
        FloatOp::Mul => bits(value(0).mul_r(value(1), round)),
        FloatOp::Div => bits(value(0).div_r(value(1), round)),
        FloatOp::MulAdd => bits(value(0).mul_add_r(value(1), value(2), round)),
        FloatOp::Sqrt => bits(sqrt(value(0), round)),
        FloatOp::RoundToIntegral => bits(value(0).round_to_integral(round)),
        FloatOp::Compare { signaling } => compare(value(0), value(1), signaling),
        FloatOp::Convert(target) => match target {
            Format::Half => bits(convert::<F, Half>(value(0), round)),
            Format::Single => bits(convert::<F, Single>(value(0), round)),
            Format::Double => bits(convert::<F, Double>(value(0), round)),
            Format::Extended => bits(convert::<F, X87DoubleExtended>(value(0), round)),
        },
        FloatOp::FromInt { signed } => {
            let integer = raw(0);
            let result = if signed {
                F::from_i128_r(integer.sext(128).low_u128().cast_signed(), round)
            } else {
                F::from_u128_r(integer.low_u128(), round)
            };
            bits(result)
        }
        FloatOp::ToInt { signed, width } => to_int(value(0), signed, width, round),
    }
}

fn convert<F: FloatConvert<T>, T: Float>(value: F, round: Round) -> StatusAnd<T> {
    let mut loses_info = false;
    value.convert_r(round, &mut loses_info)
}

/// Less (bit 0), equal (1), greater (2) or unordered (3).
fn compare<F: Float>(a: F, b: F, signaling: bool) -> StatusAnd<Bits> {
    let relation = match a.partial_cmp(&b) {
        Some(Ordering::Less) => 1,
        Some(Ordering::Equal) => 2,
        Some(Ordering::Greater) => 4,
        None => 8,
    };
    let invalid = a.is_signaling() || b.is_signaling() || (signaling && (a.is_nan() || b.is_nan()));
    let status = if invalid {
        Status::INVALID_OP
    } else {
        Status::OK
    };
    status.and(Bits::from_u64(4, relation))
}

/// `value` as a `width`-bit integer; 0 if invalid.
fn to_int<F: Float>(value: F, signed: bool, width: u16, round: Round) -> StatusAnd<Bits> {
    let mut exact = false;
    let result = if signed {
        let result = value.to_i128_r(usize::from(width), round, &mut exact);
        result.status.and(result.value.cast_unsigned())
    } else {
        value.to_u128_r(usize::from(width), round, &mut exact)
    };
    let integer = if result.status.intersects(Status::INVALID_OP) {
        0
    } else {
        result.value
    };
    result.status.and(Bits::from_u128(width, integer))
}

/// The square root of `a`, correctly rounded: from the exact integer
/// square root of its significand, scaled to have at least two bits more
/// than the format keeps, plus a sticky bit if it is inexact.
fn sqrt<F: Float>(a: F, round: Round) -> StatusAnd<F> {
    if a.is_nan() {
        let status = if a.is_signaling() {
            Status::INVALID_OP
        } else {
            Status::OK
        };
        return status.and(F::NAN);
    }
    if a.is_zero() || (a.is_infinite() && !a.is_negative()) {
        return Status::OK.and(a);
    }
    if a.is_negative() {
        return Status::INVALID_OP.and(F::NAN);
    }
    let precision = ExpInt::try_from(F::PRECISION).unwrap_or(ExpInt::MAX);
    // a = m × 2^k, m an integer of `precision` bits.
    let mut k = a.ilogb() - (precision - 1);
    let mut exact = false;
    let m = a
        .scalbn(-k)
        .to_u128_r(128, Round::TowardZero, &mut exact)
        .value;
    // An even k: a = m' × 2^k', and the root is √m' × 2^(k'/2).
    let m = if k.rem_euclid(2) == 1 {
        k -= 1;
        m << 1
    } else {
        m
    };
    // √(m × 4^s) = √m × 2^s has at least precision + 2 bits.
    let s = precision / 2 + 3;
    let shift = u32::try_from(2 * s).unwrap_or(0);
    let (root, exact) = isqrt(Bits::from_u128(256, m).shift_left(shift));
    let root = root.low_u128() | u128::from(!exact);
    let rounded = F::from_u128_r(root, round);
    // The scaling is exact: a square root is never tiny or huge.
    rounded.status.and(rounded.value.scalbn(k / 2 - s))
}

/// The integer square root of `n` (rounded down), and whether it is exact.
fn isqrt(n: Bits) -> (Bits, bool) {
    let width = n.width();
    let mut rest = n;
    let mut root = Bits::zero(width);
    let top = u32::from(width) - 1 - n.leading_zeros().min(u32::from(width) - 1);
    let mut bit = Bits::from_u64(width, 1).shift_left(top & !1);
    while !bit.is_zero() {
        let trial = root.wrapping_add(&bit);
        if rest.ucmp(&trial) == Ordering::Less {
            root = root.shift_right(1);
        } else {
            rest = rest.wrapping_sub(&trial);
            root = root.shift_right(1).wrapping_add(&bit);
        }
        bit = bit.shift_right(2);
    }
    (root, rest.is_zero())
}
