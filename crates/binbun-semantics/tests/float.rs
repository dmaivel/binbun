//! L0's vector and floating-point operations: lane-wise operations against
//! the same operation per lane, IEEE arithmetic against the host's (Rust's
//! `f32`/`f64` operations round to nearest, ties to even), directed
//! rounding of square roots against exact squares, and exceptions on known
//! cases.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "test helpers fail loudly; float results are compared bit for bit; test values convert between widths"
)]

use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{self, Value};
use binbun_semantics::ir::{
    Binary, Exception, FloatOp, FloatOutput, Format, LaneOp, Rounding, Unary,
};

/// Deterministic pseudo-random numbers.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A double, often a special value or one near a boundary.
    fn double(&mut self) -> f64 {
        let specials = [
            0.0,
            -0.0,
            f64::MIN_POSITIVE,
            -f64::MIN_POSITIVE,
            f64::MIN_POSITIVE / 3.0,
            f64::from_bits(1),
            f64::MAX,
            f64::MIN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            f64::from_bits(0x7ff0_0000_0000_0001),
            1.0,
            -1.0,
            0.5,
            3.0,
        ];
        match self.next() % 4 {
            0 => specials[(self.next() % 16) as usize],
            1 => f64::from_bits(self.next()),
            _ => (self.next() % 2000) as f64 / 7.0 - 100.0,
        }
    }

    /// A single, often a special value or one near a boundary.
    fn single(&mut self) -> f32 {
        let specials = [
            0.0,
            -0.0,
            f32::MIN_POSITIVE,
            f32::from_bits(1),
            f32::MAX,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::NAN,
            f32::from_bits(0x7f80_0001),
            1.0,
            -3.5,
        ];
        match self.next() % 4 {
            0 => specials[(self.next() % 11) as usize],
            1 => f32::from_bits(self.next() as u32),
            _ => (self.next() % 2000) as f32 / 7.0 - 100.0,
        }
    }
}

fn defined(width: u16, value: u64) -> Value {
    Value::defined(Bits::from_u64(width, value))
}

fn nearest() -> Value {
    defined(2, Rounding::NearestEven.bits())
}

/// `op` on one lane of `format`: result bits and exceptions.
fn scalar(op: FloatOp, format: Format, rounding: Rounding, operands: &[u64]) -> (u64, u64) {
    let width = format.width();
    let operands: Vec<Value> = operands
        .iter()
        .map(|&bits| {
            let operand_width = match op {
                FloatOp::FromInt { .. } => 64,
                FloatOp::Add
                | FloatOp::Sub
                | FloatOp::Mul
                | FloatOp::Div
                | FloatOp::Sqrt
                | FloatOp::MulAdd
                | FloatOp::RoundToIntegral
                | FloatOp::Compare { .. }
                | FloatOp::Convert(_)
                | FloatOp::ToInt { .. } => width,
            };
            defined(operand_width, bits)
        })
        .collect();
    let rounding = defined(2, rounding.bits());
    let value = interpret::float(op, format, 1, FloatOutput::Value, rounding, &operands);
    let status = interpret::float(op, format, 1, FloatOutput::Status, rounding, &operands);
    (
        value.known().unwrap().low_u64(),
        status.known().unwrap().low_u64(),
    )
}

/// The host's result bits, or `None` for a NaN: Rust leaves a NaN's sign
/// and payload unspecified (the optimizer may change them), and L0 gives
/// the default NaN.
fn host_double(result: f64) -> Option<u64> {
    (!result.is_nan()).then(|| result.to_bits())
}

fn host_single(result: f32) -> Option<u64> {
    (!result.is_nan()).then(|| u64::from(result.to_bits()))
}

const DOUBLE_NAN: u64 = 0x7ff8_0000_0000_0000;
const SINGLE_NAN: u64 = 0x7fc0_0000;

/// `got` is the host's result, or the default NaN `nan` where it is a NaN.
fn check(got: u64, host: Option<u64>, nan: u64, what: &str) {
    match host {
        Some(bits) => assert_eq!(got, bits, "{what}"),
        None => assert_eq!(got, nan, "{what}: a NaN"),
    }
}

#[test]
fn double_arithmetic_matches_the_host() {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    for _ in 0..20_000 {
        let (a, b, c) = (random.double(), random.double(), random.double());
        let near = Rounding::NearestEven;
        let run = |op, operands: &[f64]| {
            let bits: Vec<u64> = operands.iter().map(|x| x.to_bits()).collect();
            scalar(op, Format::Double, near, &bits).0
        };
        let context = format!("{a:e} {b:e} {c:e}");
        check(
            run(FloatOp::Add, &[a, b]),
            host_double(a + b),
            DOUBLE_NAN,
            &format!("add {context}"),
        );
        check(
            run(FloatOp::Sub, &[a, b]),
            host_double(a - b),
            DOUBLE_NAN,
            &format!("sub {context}"),
        );
        check(
            run(FloatOp::Mul, &[a, b]),
            host_double(a * b),
            DOUBLE_NAN,
            &format!("mul {context}"),
        );
        check(
            run(FloatOp::Div, &[a, b]),
            host_double(a / b),
            DOUBLE_NAN,
            &format!("div {context}"),
        );
        check(
            run(FloatOp::Sqrt, &[a]),
            host_double(a.sqrt()),
            DOUBLE_NAN,
            &format!("sqrt {context}"),
        );
        check(
            run(FloatOp::MulAdd, &[a, b, c]),
            host_double(a.mul_add(b, c)),
            DOUBLE_NAN,
            &format!("fma {context}"),
        );
        check(
            run(FloatOp::Convert(Format::Single), &[a]),
            host_single(a as f32),
            SINGLE_NAN,
            &format!("convert {context}"),
        );
        let relation = run(FloatOp::Compare { signaling: false }, &[a, b]);
        let expected = match a.partial_cmp(&b) {
            Some(std::cmp::Ordering::Less) => 1,
            Some(std::cmp::Ordering::Equal) => 2,
            Some(std::cmp::Ordering::Greater) => 4,
            None => 8,
        };
        assert_eq!(relation, expected, "compare {context}");
        let integer = random.next() as i64;
        assert_eq!(
            scalar(
                FloatOp::FromInt { signed: true },
                Format::Double,
                near,
                &[integer as u64],
            )
            .0,
            (integer as f64).to_bits(),
            "from {integer}",
        );
        if a.is_finite() && a.trunc().abs() < 9.2e18 {
            let truncated = scalar(
                FloatOp::ToInt {
                    signed: true,
                    width: 64,
                },
                Format::Double,
                Rounding::TowardZero,
                &[a.to_bits()],
            );
            assert_eq!(truncated.0 as i64, a as i64, "to int {context}");
        }
    }
}

#[test]
fn single_arithmetic_matches_the_host() {
    let mut random = Random(0x2545_f491_4f6c_dd1d);
    for _ in 0..20_000 {
        let (a, b) = (random.single(), random.single());
        let run = |op, operands: &[f32]| {
            let bits: Vec<u64> = operands.iter().map(|x| u64::from(x.to_bits())).collect();
            scalar(op, Format::Single, Rounding::NearestEven, &bits).0
        };
        let context = format!("{a:e} {b:e}");
        check(
            run(FloatOp::Add, &[a, b]),
            host_single(a + b),
            SINGLE_NAN,
            &format!("add {context}"),
        );
        check(
            run(FloatOp::Mul, &[a, b]),
            host_single(a * b),
            SINGLE_NAN,
            &format!("mul {context}"),
        );
        check(
            run(FloatOp::Div, &[a, b]),
            host_single(a / b),
            SINGLE_NAN,
            &format!("div {context}"),
        );
        check(
            run(FloatOp::Sqrt, &[a]),
            host_single(a.sqrt()),
            SINGLE_NAN,
            &format!("sqrt {context}"),
        );
        check(
            run(FloatOp::Convert(Format::Double), &[a]),
            host_double(f64::from(a)),
            DOUBLE_NAN,
            &format!("convert {context}"),
        );
    }
}

/// In every rounding, a single's square root r satisfies r² ≤ a < r'² for
/// the rounding down (r' the next single up), and is the nearer of the two
/// to nearest; squares of singles are exact in doubles.
#[test]
fn square_roots_round_in_every_direction() {
    let mut random = Random(0xdead_beef_cafe_f00d);
    let root = |a: f32, rounding| {
        f32::from_bits(
            scalar(
                FloatOp::Sqrt,
                Format::Single,
                rounding,
                &[u64::from(a.to_bits())],
            )
            .0 as u32,
        )
    };
    for _ in 0..20_000 {
        let a = f32::from_bits(random.next() as u32 & 0x7fff_ffff);
        if !a.is_finite() || a == 0.0 {
            continue;
        }
        let exact = f64::from(a);
        let down = root(a, Rounding::Down);
        let up = root(a, Rounding::Up);
        let square = |x: f32| f64::from(x) * f64::from(x);
        assert!(square(down) <= exact, "{a:e}: {down:e}² > a");
        let next = f32::from_bits(down.to_bits() + 1);
        assert!(square(next) > exact, "{a:e}: {down:e} is not the largest");
        assert_eq!(root(a, Rounding::TowardZero), down, "{a:e}");
        if square(down) == exact {
            assert_eq!(up, down, "{a:e}: exact root");
        } else {
            assert_eq!(up, next, "{a:e}: up");
        }
        assert_eq!(root(a, Rounding::NearestEven), a.sqrt(), "{a:e}: nearest");
    }
}

#[test]
fn exceptions_on_known_cases() {
    let bit = |e: Exception| 1u64 << e.bit();
    let double = |op, operands: &[f64]| {
        let bits: Vec<u64> = operands.iter().map(|x| x.to_bits()).collect();
        scalar(op, Format::Double, Rounding::NearestEven, &bits).1
    };
    let inexact = bit(Exception::Inexact);
    assert_eq!(
        double(FloatOp::Div, &[1.0, 0.0]),
        bit(Exception::DivideByZero)
    );
    assert_eq!(double(FloatOp::Div, &[0.0, 0.0]), bit(Exception::Invalid));
    assert_eq!(double(FloatOp::Sqrt, &[-1.0]), bit(Exception::Invalid));
    assert_eq!(double(FloatOp::Div, &[1.0, 3.0]), inexact);
    assert_eq!(double(FloatOp::Add, &[1.0, 2.0]), 0);
    assert_eq!(
        double(FloatOp::Mul, &[f64::MAX, 2.0]),
        bit(Exception::Overflow) | inexact
    );
    assert_eq!(
        double(FloatOp::Div, &[f64::MIN_POSITIVE, 3.0]),
        bit(Exception::Underflow) | inexact
    );
    // An exact tiny result raises nothing.
    assert_eq!(double(FloatOp::Div, &[f64::MIN_POSITIVE, 2.0]), 0);
    // Tiny means below the smallest normal number when rounded with an
    // unbounded exponent: (1 - 2^-24) * 2^-126 is a single (24 bits), so
    // the product is tiny, though it rounds to -2^-126 (measured on x86:
    // `mulps` raises underflow); QEMU's FMA case is not tiny (it rounds to
    // -2^-1022 even with an unbounded exponent): only inexact.
    let single = |op, operands: &[u64]| scalar(op, Format::Single, Rounding::NearestEven, operands);
    assert_eq!(
        single(FloatOp::Mul, &[0x3f7f_ffff, 0x8080_0000]),
        (0x8080_0000, bit(Exception::Underflow) | inexact)
    );
    assert_eq!(
        double(
            FloatOp::MulAdd,
            &[
                f64::from_bits(0x3fdf_ffff_ffff_ffff),
                f64::from_bits(0x001f_ffff_ffff_ffff),
                f64::from_bits(0x801f_ffff_ffff_ffff)
            ]
        ),
        inexact
    );
    // Rounded toward zero, an overflow gives the largest finite number,
    // still raising overflow; a sum just past it that rounds back to it
    // (below 2^1024) is only inexact.
    let toward_zero = |op, operands: &[f64]| {
        let bits: Vec<u64> = operands.iter().map(|x| x.to_bits()).collect();
        scalar(op, Format::Double, Rounding::TowardZero, &bits)
    };
    assert_eq!(
        toward_zero(FloatOp::Mul, &[f64::MAX, 2.0]),
        (f64::MAX.to_bits(), bit(Exception::Overflow) | inexact)
    );
    assert_eq!(
        toward_zero(FloatOp::Mul, &[-f64::MAX, 2.0]),
        ((-f64::MAX).to_bits(), bit(Exception::Overflow) | inexact)
    );
    assert_eq!(
        toward_zero(FloatOp::Add, &[f64::MAX, f64::MAX * 2f64.powi(-60)]),
        (f64::MAX.to_bits(), inexact)
    );
    // A signalling NaN is invalid in any operation; a quiet one only in a
    // signalling comparison.
    let snan = f64::from_bits(0x7ff0_0000_0000_0001);
    assert_eq!(double(FloatOp::Add, &[snan, 1.0]), bit(Exception::Invalid));
    assert_eq!(
        double(FloatOp::Compare { signaling: false }, &[f64::NAN, 1.0]),
        0
    );
    assert_eq!(
        double(FloatOp::Compare { signaling: true }, &[f64::NAN, 1.0]),
        bit(Exception::Invalid)
    );
    // An invalid conversion gives 0.
    let (value, status) = scalar(
        FloatOp::ToInt {
            signed: true,
            width: 32,
        },
        Format::Double,
        Rounding::NearestEven,
        &[1e10f64.to_bits()],
    );
    assert_eq!((value, status), (0, bit(Exception::Invalid)));
    // The x87 format: 1/3 in 64 bits of significand.
    let one = 0x3fff_8000_0000_0000_0000u128;
    let three = 0x4000_c000_0000_0000_0000u128;
    let operands = [one, three].map(|x| Value::defined(Bits::from_u128(80, x)));
    let third = interpret::float(
        FloatOp::Div,
        Format::Extended,
        1,
        FloatOutput::Value,
        nearest(),
        &operands,
    );
    assert_eq!(
        third.known().unwrap().low_u128(),
        0x3ffd_aaaa_aaaa_aaaa_aaab
    );
}

/// An integer converted past the largest finite number overflows: in
/// binary16, 65520 rounds to nearest to 2^16 (+infinity), 65519 to 65504;
/// toward zero, 2^16 gives 65504, still overflowing (and -2^16 -65504),
/// 65535 only inexact.
#[test]
fn integer_conversions_overflow() {
    let half = |rounding, integer: i64| {
        scalar(
            FloatOp::FromInt { signed: true },
            Format::Half,
            rounding,
            &[integer as u64],
        )
    };
    let inexact = 1u64 << Exception::Inexact.bit();
    let overflow = 1u64 << Exception::Overflow.bit() | inexact;
    assert_eq!(half(Rounding::NearestEven, 65520), (0x7c00, overflow));
    assert_eq!(half(Rounding::NearestEven, 65519), (0x7bff, inexact));
    assert_eq!(half(Rounding::TowardZero, 65536), (0x7bff, overflow));
    assert_eq!(half(Rounding::TowardZero, -65536), (0xfbff, overflow));
    assert_eq!(half(Rounding::TowardZero, 65535), (0x7bff, inexact));
}

/// Packed operations equal the scalar operation on each lane; an undefined
/// lane leaves the other lanes defined.
#[test]
fn lanes_are_independent() {
    let mut random = Random(0x0123_4567_89ab_cdef);
    let bytes: Vec<u8> = (0..32).flat_map(|_| random.next().to_le_bytes()).collect();
    let a = Value::defined(Bits::from_le_bytes(256, &bytes[..32]));
    let b = Value::defined(Bits::from_le_bytes(256, &bytes[32..64]));
    let lane =
        |value: &Value, index: u16, width: u16| interpret::extract(*value, index * width, width);
    for width in [8u16, 16, 32, 64] {
        let count = 256 / width;
        for op in [
            Binary::Add,
            Binary::Sub,
            Binary::Mul,
            Binary::SLt,
            Binary::Eq,
        ] {
            let packed = interpret::lanes(LaneOp::Binary(op), count, &[a, b]);
            let result = if matches!(op, Binary::SLt | Binary::Eq) {
                1
            } else {
                width
            };
            for index in 0..count {
                assert_eq!(
                    lane(&packed, index, result),
                    interpret::binary(op, lane(&a, index, width), lane(&b, index, width)),
                    "{op:?} on {count} lanes, lane {index}"
                );
            }
        }
        let negated = interpret::lanes(LaneOp::Unary(Unary::Neg), count, &[a]);
        let widened = interpret::lanes(
            LaneOp::Extend {
                signed: true,
                width: width * 2,
            },
            count / 2,
            &[interpret::extract(a, 0, 128)],
        );
        for index in 0..count / 2 {
            assert_eq!(
                lane(&negated, index, width),
                interpret::unary(Unary::Neg, lane(&a, index, width))
            );
            assert_eq!(
                lane(&widened, index, width * 2),
                interpret::extend(true, lane(&a, index, width), width * 2)
            );
        }
    }
    // Four singles at once; lane 2 undefined.
    let singles = [1.5f32, -0.25, 3.0, 1e30];
    let others = [2.0f32, 0.75, -1.0, 1e10];
    let pack = |values: [f32; 4]| {
        let bytes: Vec<u8> = values.iter().flat_map(|x| x.to_le_bytes()).collect();
        Value::defined(Bits::from_le_bytes(128, &bytes))
    };
    let mut x = pack(singles);
    x.undefined = Bits::from_u128(128, 0xffff_ffff << 64);
    x.bits = x.bits.and(&x.undefined.invert());
    let product = interpret::float(
        FloatOp::Mul,
        Format::Single,
        4,
        FloatOutput::Value,
        nearest(),
        &[x, pack(others)],
    );
    for index in [0u16, 1, 3] {
        let got = lane(&product, index, 32).known().unwrap().low_u64() as u32;
        let i = usize::from(index);
        assert_eq!(f32::from_bits(got), singles[i] * others[i], "lane {index}");
    }
    assert_eq!(lane(&product, 2, 32).undefined, Bits::ones(32));
}
