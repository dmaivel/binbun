//! L0: bit-vector arithmetic against references, flag operators against
//! their expansions, undefined-bit tracking, the verifier, the text form and
//! the interpreter's control flow.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::BTreeMap;

use binbun_semantics::bits::{Bits, MAX_WIDTH};
use binbun_semantics::build::Builder;
use binbun_semantics::expand::expand;
use binbun_semantics::interpret::{self, Fault, Machine, Outcome, Value};
use binbun_semantics::ir::{
    Binary, Declarations, Expr, ExprId, Flag, FloatOp, Format, IntrinsicId, IntrinsicInfo, LaneOp,
    RegisterId, RegisterInfo, Semantics, Stmt, Trap, Unary, View,
};
use binbun_semantics::text::{parse, print};
use binbun_semantics::verify::verify;

const REGISTERS: [RegisterInfo; 4] = [
    RegisterInfo {
        name: "a",
        width: 64,
    },
    RegisterInfo {
        name: "b",
        width: 64,
    },
    RegisterInfo {
        name: "f",
        width: 1,
    },
    RegisterInfo {
        name: "v",
        width: 512,
    },
];
const DECLARATIONS: Declarations = Declarations {
    registers: &REGISTERS,
    intrinsics: &[IntrinsicInfo {
        name: "clock",
        inputs: &[8],
        outputs: &[64, 1],
        escapes: true,
        stores: true,
        opaque: false,
    }],
    sites: &[],
};
const CLOCK: IntrinsicId = IntrinsicId(0);
const A: RegisterId = RegisterId(0);
const B: RegisterId = RegisterId(1);
const F: RegisterId = RegisterId(2);
const V: RegisterId = RegisterId(3);

fn view(register: RegisterId, offset: u16, width: u16) -> View {
    View {
        register,
        offset,
        width,
    }
}

/// Deterministic pseudo-random numbers, biased towards edge values.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn word(&mut self) -> u64 {
        match self.next() % 8 {
            0 => 0,
            1 => u64::MAX,
            2 => 1 << (self.next() % 64),
            3 => (1 << 63) - 1,
            _ => self.next(),
        }
    }

    fn bits(&mut self, width: u16) -> Bits {
        let bytes: Vec<u8> = (0..64).flat_map(|_| self.word().to_le_bytes()).collect();
        Bits::from_le_bytes(width, &bytes)
    }
}

fn mask(width: u16) -> u128 {
    if width >= 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    }
}

#[test]
fn bit_vector_arithmetic_matches_u128() {
    let mut random = Random(0x1234_5678_9abc_def1);
    for width in 1..=128u16 {
        let ones = mask(width);
        for _ in 0..200 {
            let (x, y) = (random.bits(width), random.bits(width));
            let (left, right) = (x.low_u128(), y.low_u128());
            assert_eq!(
                x.wrapping_add(&y).low_u128(),
                left.wrapping_add(right) & ones
            );
            assert_eq!(
                x.wrapping_sub(&y).low_u128(),
                left.wrapping_sub(right) & ones
            );
            assert_eq!(x.invert().low_u128(), !left & ones);
            assert_eq!(x.ucmp(&y), left.cmp(&right));
            let signed =
                |v: u128| (v << (128 - u32::from(width))).cast_signed() >> (128 - u32::from(width));
            assert_eq!(
                x.scmp(&y),
                signed(left).cmp(&signed(right)),
                "{width} {left:x} {right:x}"
            );
            let count = u32::try_from(random.next() % (u64::from(width) + 2)).unwrap();
            let past = count >= u32::from(width);
            let shifted_left = if past { 0 } else { (left << count) & ones };
            let logical = if past { 0 } else { left >> count };
            let arithmetic = (signed(left) >> count.min(127)).cast_unsigned() & ones;
            assert_eq!(
                x.shift_left(count).low_u128(),
                shifted_left,
                "shl {width} {count}"
            );
            assert_eq!(
                x.shift_right(count).low_u128(),
                logical,
                "lshr {width} {count}"
            );
            assert_eq!(
                x.shift_right_signed(count).low_u128(),
                arithmetic,
                "ashr {width} {count}"
            );
            assert_eq!(x.sext(128).low_u128(), signed(left).cast_unsigned());
            let (_, carry) = x.add_carry(&y, false);
            assert_eq!(carry, left.checked_add(right).is_none_or(|sum| sum > ones));
        }
    }
}

/// Bit `index` of a value given as bits, by a bit-by-bit model.
fn bit_list(bits: &Bits) -> Vec<bool> {
    (0..bits.width()).map(|index| bits.bit(index)).collect()
}

fn from_list(list: &[bool]) -> Bits {
    let mut bytes = vec![0u8; list.len().div_ceil(8)];
    for (index, &bit) in list.iter().enumerate() {
        if bit {
            bytes[index / 8] |= 1 << (index % 8);
        }
    }
    Bits::from_le_bytes(u16::try_from(list.len()).unwrap(), &bytes)
}

#[test]
fn wide_shifts_and_concatenation_cross_word_boundaries() {
    let mut random = Random(0xfeed_beef_cafe_f00d);
    for width in [65u16, 127, 128, 129, 200, 256, 383, 511, MAX_WIDTH] {
        for _ in 0..50 {
            let x = random.bits(width);
            let list = bit_list(&x);
            for count in [0u32, 1, 31, 63, 64, 65, 127, 128, 200, u32::from(width) - 1] {
                let n = count as usize;
                let shifted_left: Vec<bool> =
                    (0..list.len()).map(|i| i >= n && list[i - n]).collect();
                let shifted_right: Vec<bool> = (0..list.len())
                    .map(|i| list.get(i + n).copied().unwrap_or(false))
                    .collect();
                assert_eq!(
                    x.shift_left(count),
                    from_list(&shifted_left),
                    "shl {width} {count}"
                );
                assert_eq!(
                    x.shift_right(count),
                    from_list(&shifted_right),
                    "lshr {width} {count}"
                );
            }
            let low = random.bits(MAX_WIDTH - width.min(MAX_WIDTH - 1));
            let joined = x.concat(&low);
            let expected: Vec<bool> = bit_list(&low)
                .into_iter()
                .chain(list.iter().copied())
                .collect();
            assert_eq!(joined, from_list(&expected[..usize::from(joined.width())]));
            assert_eq!(
                joined
                    .extract(low.width(), width.min(joined.width() - low.width()))
                    .width(),
                width.min(joined.width() - low.width())
            );
        }
    }
}

/// Rotations take the whole count modulo the width, also counts beyond
/// `u32::MAX` (2^63 rotates a 64-bit value by 0, 2^32 + 5 by 5).
#[test]
fn rotation_counts_wrap_modulo_the_width() {
    let value = Bits::from_u64(64, 0x0123_4567_89ab_cdef);
    for (count, by) in [
        (1u64 << 63, 0u32),
        ((1 << 32) + 5, 5),
        (u64::MAX, 63),
        (70, 6),
    ] {
        let count = Value::defined(Bits::from_u64(64, count));
        let left = interpret::binary(Binary::Rol, Value::defined(value), count);
        let right = interpret::binary(Binary::Ror, Value::defined(value), count);
        let raw = value.low_u64();
        assert_eq!(left.bits.low_u64(), raw.rotate_left(by), "rol by {count:?}");
        assert_eq!(
            right.bits.low_u64(),
            raw.rotate_right(by),
            "ror by {count:?}"
        );
    }
}

/// A machine with registers and sparse memory, for tests.
#[derive(Default)]
struct Test {
    registers: BTreeMap<RegisterId, Value>,
    memory: BTreeMap<u64, u8>,
}

impl Machine for Test {
    fn read(&mut self, register: RegisterId) -> Value {
        let width = DECLARATIONS.info(register).map_or(1, |info| info.width);
        self.registers
            .get(&register)
            .copied()
            .unwrap_or_else(|| Value::defined(Bits::zero(width)))
    }

    fn write(&mut self, register: RegisterId, value: Value) {
        self.registers.insert(register, value);
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        let data: Option<Vec<u8>> = (0..u64::from(bytes))
            .map(|i| self.memory.get(&(address + i)).copied())
            .collect();
        let data = data.ok_or(Fault {
            address,
            write: false,
        })?;
        Ok(Value::defined(Bits::from_le_bytes(bytes * 8, &data)))
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        for (i, byte) in value.bits.to_le_bytes().enumerate() {
            self.memory.insert(address + i as u64, byte);
        }
        Ok(())
    }
}

/// Evaluates one expression built by `f` from constant operands.
fn evaluate(operands: &[Bits], f: impl FnOnce(&mut Builder, &[ExprId]) -> ExprId) -> Value {
    let mut b = Builder::new();
    let ids: Vec<ExprId> = operands.iter().map(|&bits| b.bits(bits)).collect();
    let result = f(&mut b, &ids);
    let width = b.width(result);
    let target = view(V, 0, width);
    b.write(target, result);
    let semantics = b.finish().expect("well-formed");
    verify(&semantics, &DECLARATIONS).expect("verifies");
    let mut machine = Test::default();
    assert_eq!(interpret::run(&semantics, &mut machine), Outcome::Next);
    let full = machine.read(V);
    Value {
        bits: full.bits.extract(0, width),
        undefined: full.undefined.extract(0, width),
    }
}

/// Expressions form a DAG: a value used twice in each of 100 steps is
/// computed once per step (as a tree it would take 2^100 evaluations).
#[test]
fn shared_expressions_are_evaluated_once() {
    let start = 0x0123_4567_89ab_cdefu64;
    let result = evaluate(&[Bits::from_u64(64, start)], |b, ids| {
        let one = b.constant(64, 1);
        let mut value = ids[0];
        for _ in 0..100 {
            let rotated = b.binary(Binary::Rol, value, one);
            value = b.binary(Binary::Add, value, rotated);
        }
        value
    });
    let mut expected = start;
    for _ in 0..100 {
        expected = expected.wrapping_add(expected.rotate_left(1));
    }
    assert_eq!(result.known(), Some(Bits::from_u64(64, expected)));
}

#[test]
fn flag_operators_equal_their_expansions() {
    let mut random = Random(0x0bad_cafe_dead_beef);
    let ops = [
        Flag::AddCarry,
        Flag::AddOverflow,
        Flag::SubBorrow,
        Flag::SubOverflow,
        Flag::NibbleCarry,
    ];
    for width in [1u16, 4, 5, 8, 16, 32, 64, 128, 256] {
        for _ in 0..300 {
            let (a, b) = (random.bits(width), random.bits(width));
            let c = Bits::from_u64(width, random.next() & 1);
            for op in ops {
                let direct = evaluate(&[a, b, c], |builder, e| builder.flag(op, e[0], e[1], e[2]));
                let expanded = evaluate(&[a, b, c], |builder, e| {
                    expand(builder, op, e[0], e[1], e[2])
                });
                assert_eq!(direct, expanded, "{op:?} {width} {a:?} {b:?} {c:?}");
            }
        }
    }
}

#[test]
fn flag_operators_on_known_x86_cases() {
    let byte = |v| Bits::from_u64(8, v);
    let check = |op, a, b, c| {
        evaluate(&[byte(a), byte(b), byte(c)], |builder, e| {
            builder.flag(op, e[0], e[1], e[2])
        })
        .bits
        .low_u64()
            == 1
    };
    // add al, 1 with al = 0xff: carry, no signed overflow, nibble carry.
    assert!(check(Flag::AddCarry, 0xff, 1, 0));
    assert!(!check(Flag::AddOverflow, 0xff, 1, 0));
    assert!(check(Flag::NibbleCarry, 0xff, 1, 0x00));
    // add al, 1 with al = 0x7f: signed overflow, no carry.
    assert!(check(Flag::AddOverflow, 0x7f, 1, 0));
    assert!(!check(Flag::AddCarry, 0x7f, 1, 0));
    // adc al, 0 with al = 0xff and carry in: carry out.
    assert!(check(Flag::AddCarry, 0xff, 0, 1));
    // sub al, 1 with al = 0: borrow; with al = 0x80: signed overflow.
    assert!(check(Flag::SubBorrow, 0, 1, 0));
    assert!(check(Flag::SubOverflow, 0x80, 1, 0));
    assert!(!check(Flag::SubOverflow, 0x7f, 1, 0));
    // sbb al, 0xff with al = 0xff and borrow in: borrow out.
    assert!(check(Flag::SubBorrow, 0xff, 0xff, 1));
}

#[test]
fn undefined_bits_follow_the_operations() {
    // Low byte undefined, the rest known.
    let mut b = Builder::new();
    let unknown = b.undefined(8);
    let high = b.constant(56, 0xab_cdef);
    let value = b.concat(high, unknown);
    // Extraction above the undefined byte is defined.
    let above = b.extract(value, 8, 16);
    // An and with all ones keeps the undefined byte undefined (per bit).
    let ones = b.constant(64, u64::MAX);
    let and = b.binary(Binary::And, value, ones);
    // A sum with any undefined bit is undefined throughout.
    let one = b.constant(64, 1);
    let sum = b.binary(Binary::Add, value, one);
    // A shift by a defined count moves the undefined bits.
    let eight = b.constant(64, 8);
    let shifted = b.binary(Binary::Shl, value, eight);
    for (offset, id) in [(0u16, above), (64, and), (128, sum), (192, shifted)] {
        let width = b.width(id);
        b.write(view(V, offset, width), id);
    }
    let semantics = b.finish().expect("well-formed");
    verify(&semantics, &DECLARATIONS).expect("verifies");
    let mut machine = Test::default();
    assert_eq!(interpret::run(&semantics, &mut machine), Outcome::Next);
    let full = machine.read(V);
    let undefined = |offset, width| full.undefined.extract(offset, width).low_u64();
    let bits = |offset, width| full.bits.extract(offset, width).low_u64();
    assert_eq!((undefined(0, 16), bits(0, 16)), (0, 0xcdef));
    assert_eq!(undefined(64, 64), 0xff);
    assert_eq!(undefined(128, 64), u64::MAX);
    assert_eq!(undefined(192, 64), 0xff00);
}

#[test]
fn and_with_0_and_or_with_1_are_defined() {
    // Low nibble undefined; the other operand 0b0101_0011.
    let unknown = Value {
        bits: Bits::from_u64(8, 0x30),
        undefined: Bits::from_u64(8, 0x0f),
    };
    let other = Value::defined(Bits::from_u64(8, 0x53));
    let and = interpret::binary(Binary::And, unknown, other);
    let or = interpret::binary(Binary::Or, unknown, other);
    let xor = interpret::binary(Binary::Xor, unknown, other);
    let low = |value: Value| (value.undefined.low_u64(), value.bits.low_u64());
    // AND: bits 3 and 2 (other's 0s) are defined 0, bits 1 and 0 stay
    // undefined; OR the other way round; XOR needs both.
    assert_eq!(low(and), (0x03, 0x10));
    assert_eq!(low(or), (0x0c, 0x73));
    assert_eq!(low(xor), (0x0f, 0x60));
    // Lane by lane alike: two 4-bit lanes of the same operands.
    let lanes = interpret::lanes(LaneOp::Binary(Binary::And), 2, &[unknown, other]);
    assert_eq!(low(lanes), (0x03, 0x10));
}

#[test]
fn a_condition_on_undefined_bits_is_undetermined() {
    let mut b = Builder::new();
    let unknown = b.undefined(1);
    b.begin_if(unknown);
    let one = b.constant(64, 1);
    b.write(view(A, 0, 64), one);
    b.end_if();
    let semantics = b.finish().expect("well-formed");
    assert_eq!(
        interpret::run(&semantics, &mut Test::default()),
        Outcome::Undetermined
    );
}

/// `rep stosb`-like: while b != 0, store a's low byte at [a's high bits],
/// then decrement b; then jump to 0x1000.
fn countdown() -> Semantics {
    let mut b = Builder::new();
    b.begin_loop();
    let count = b.read(view(B, 0, 64));
    let zero = b.constant(64, 0);
    let done = b.binary(Binary::Eq, count, zero);
    b.begin_if(done);
    b.brk();
    b.end_if();
    let address = b.binary(Binary::Add, count, zero);
    let byte = b.read(view(A, 0, 8));
    b.store(address, byte);
    let one = b.constant(64, 1);
    let next = b.binary(Binary::Sub, count, one);
    b.write(view(B, 0, 64), next);
    b.end_loop();
    let target = b.constant(64, 0x1000);
    b.jump(target);
    b.finish().expect("well-formed")
}

#[test]
fn loops_break_and_transfer() {
    let semantics = countdown();
    verify(&semantics, &DECLARATIONS).expect("verifies");
    let mut machine = Test::default();
    machine.write(A, Value::defined(Bits::from_u64(64, 0x5a)));
    machine.write(B, Value::defined(Bits::from_u64(64, 3)));
    assert_eq!(
        interpret::run(&semantics, &mut machine),
        Outcome::Transfer(0x1000)
    );
    assert_eq!(machine.read(B).bits.low_u64(), 0);
    assert_eq!(
        machine.memory,
        BTreeMap::from([(1, 0x5a), (2, 0x5a), (3, 0x5a)])
    );
    // A count past the fuel stops instead of running forever.
    machine.write(B, Value::defined(Bits::from_u64(64, 1000)));
    assert_eq!(
        interpret::run_with_fuel(&semantics, &mut machine, 100),
        Outcome::OutOfFuel
    );
}

#[test]
fn traps_and_faults_stop_the_instruction() {
    let mut b = Builder::new();
    let address = b.constant(64, 0x10);
    let value = b.load(address, 4);
    let wide = b.zext(value, 64);
    b.write(view(A, 0, 64), wide);
    b.trap(Trap::Divide);
    let semantics = b.finish().expect("well-formed");
    let mut machine = Test::default();
    assert_eq!(
        interpret::run(&semantics, &mut machine),
        Outcome::Fault(Fault {
            address: 0x10,
            write: false
        })
    );
    machine.memory.extend((0x10..0x14).map(|a| (a, 0x11)));
    let before = machine.read(A);
    assert_eq!(
        interpret::run(&semantics, &mut machine),
        Outcome::Trap(Trap::Divide)
    );
    // Exceptions are precise: the write before the trap is undone.
    assert_eq!(machine.read(A), before);

    // Stores are undone too, latest first (the same byte twice).
    let mut b = Builder::new();
    let address = b.constant(64, 0x11);
    let first = b.constant(8, 0xaa);
    let second = b.constant(8, 0xbb);
    b.store(address, first);
    b.store(address, second);
    b.trap(Trap::Protection);
    let semantics = b.finish().expect("well-formed");
    assert_eq!(
        interpret::run(&semantics, &mut machine),
        Outcome::Trap(Trap::Protection)
    );
    assert_eq!(machine.memory[&0x11], 0x11);
}

#[test]
fn the_builder_reports_width_mistakes() {
    let mut b = Builder::new();
    let byte = b.constant(8, 1);
    let word = b.constant(16, 1);
    b.binary(Binary::Add, byte, word);
    b.write(view(A, 0, 64), byte);
    b.extract(byte, 4, 8);
    b.begin_if(byte);
    let errors = b.finish().expect_err("mistakes");
    // Mismatched operands, a write of the wrong width, an extract past the
    // end, a multi-bit condition and the open if.
    assert_eq!(errors.len(), 5, "{errors:?}");
}

#[test]
fn the_verifier_rejects_broken_rules() {
    // A local used outside the `if` that defines it.
    let mut b = Builder::new();
    let flag = b.read(view(F, 0, 1));
    b.begin_if(flag);
    let inner = b.read(view(A, 0, 64));
    b.end_if();
    b.write(view(B, 0, 64), inner);
    let semantics = b.finish().expect("widths are fine");
    let error = verify(&semantics, &DECLARATIONS).expect_err("scope");
    assert!(error.0.contains("not defined"), "{error}");

    // A view past the end of its register.
    let mut s = countdown();
    s.body.push(Stmt::Write {
        view: view(F, 0, 2),
        value: ExprId(0),
    });
    assert!(verify(&s, &DECLARATIONS).is_err());

    // An expression whose operand comes after it.
    let mut s = countdown();
    let last = ExprId(u32::try_from(s.exprs.len()).unwrap());
    s.exprs.insert(0, (Expr::Unary(Unary::Not, last), 64));
    assert!(verify(&s, &DECLARATIONS).is_err());

    // `break` outside a loop.
    let mut s = Semantics::default();
    s.body.push(Stmt::Break);
    assert!(verify(&s, &DECLARATIONS).is_err());

    // An intrinsic given a 64-bit input where it takes 8 bits.
    let mut b = Builder::new();
    let a = b.read(view(A, 0, 64));
    b.intrinsic(CLOCK, &[a], &[64, 1]);
    let s = b.finish().unwrap();
    let error = verify(&s, &DECLARATIONS).expect_err("input width");
    assert!(error.0.contains("8-bit input"), "{error}");
}

/// Every lane and floating-point construct, ending in a trap.
fn vector_constructs(b: &mut Builder) {
    let vector = b.read(view(V, 0, 256));
    let other = b.read(view(V, 256, 256));
    let sums = b.lanes(LaneOp::Binary(Binary::Add), 8, &[vector, other]);
    let less = b.lanes(LaneOp::Binary(Binary::SLt), 8, &[vector, sums]);
    let mask = b.lanes(
        LaneOp::Extend {
            signed: true,
            width: 32,
        },
        8,
        &[less],
    );
    let halves = b.lanes(
        LaneOp::Extract {
            offset: 16,
            width: 16,
        },
        8,
        &[mask],
    );
    let negated = b.lanes(LaneOp::Unary(Unary::Neg), 16, &[halves]);
    let chosen = b.lanes(LaneOp::Select, 8, &[less, sums, vector]);
    let rounding = b.constant(2, 3);
    let product = b.float(
        FloatOp::MulAdd,
        Format::Single,
        8,
        rounding,
        &[chosen, sums, vector],
    );
    let flags = b.float_status(FloatOp::Sqrt, Format::Double, 4, rounding, &[product]);
    let order = b.float(
        FloatOp::Compare { signaling: true },
        Format::Double,
        4,
        rounding,
        &[sums, chosen],
    );
    let narrow = b.float(
        FloatOp::Convert(Format::Half),
        Format::Double,
        4,
        rounding,
        &[product],
    );
    let integers = b.float(
        FloatOp::ToInt {
            signed: false,
            width: 16,
        },
        Format::Double,
        4,
        rounding,
        &[sums],
    );
    let back = b.float(
        FloatOp::FromInt { signed: true },
        Format::Single,
        4,
        rounding,
        &[integers],
    );
    let extended = b.extract(vector, 0, 80);
    let rounded = b.float(
        FloatOp::RoundToIntegral,
        Format::Extended,
        1,
        rounding,
        &[extended],
    );
    let all = [negated, flags, order, narrow, back, rounded];
    let mut joined = b.constant(1, 0);
    for part in all {
        let low = b.extract(part, 0, 1);
        joined = b.binary(Binary::Xor, joined, low);
    }
    b.write(view(F, 0, 1), joined);
    b.trap(Trap::FloatingPoint);
}

#[test]
fn text_round_trips_every_construct() {
    let mut b = Builder::new();
    let a = b.read(view(A, 0, 64));
    let low = b.read(view(A, 8, 8));
    let wide = b.bits(Bits::from_u128(100, 0x1_2345_6789_abcd_ef01_2345));
    let not = b.unary(Unary::Not, a);
    for op in [
        Unary::Neg,
        Unary::Popcount,
        Unary::LeadingZeros,
        Unary::TrailingZeros,
        Unary::ByteSwap,
        Unary::EvenParity8,
    ] {
        b.unary(op, a);
    }
    let sum = b.binary(Binary::Add, a, not);
    let carry = b.flag(Flag::AddCarry, a, not, sum);
    let part = b.extract(sum, 3, 9);
    let joined = b.concat(low, part);
    let extended = b.sext(joined, 64);
    let zero_extended = b.zext(low, 32);
    let chosen = b.select(carry, extended, sum);
    let unknown = b.undefined(1);
    b.write(view(F, 0, 1), unknown);
    b.begin_if(carry);
    b.store(chosen, zero_extended);
    b.otherwise();
    let loaded = b.load(sum, 2);
    let target = b.zext(loaded, 64);
    b.call(target, sum);
    b.end_if();
    b.begin_loop();
    b.brk();
    b.end_loop();
    b.begin_atomic();
    b.store(chosen, zero_extended);
    b.end_atomic();
    b.system_call();
    let byte = b.extract(a, 0, 8);
    let outputs = b.intrinsic(CLOCK, &[byte], &[64, 1]);
    b.write(view(A, 0, 64), outputs[0]);
    b.ret(a);
    b.trap(Trap::Protection);
    let _ = wide;
    vector_constructs(&mut b);
    let semantics = b.finish().expect("well-formed");
    verify(&semantics, &DECLARATIONS).expect("verifies");
    let text = print(&semantics, &DECLARATIONS);
    let back = parse(&text, &DECLARATIONS).unwrap_or_else(|e| panic!("{e}\n{text}"));
    assert_eq!(back, semantics, "{text}");
    assert_eq!(print(&back, &DECLARATIONS), text);
}

#[test]
fn text_errors_point_at_the_mistake() {
    let text = "(semantics (locals 64) (exprs (e0 64 (local l0)) (e1 64 (frob e0))) (body))";
    let error = parse(text, &DECLARATIONS).expect_err("unknown operation");
    assert_eq!(&text[error.at..error.at + 9], "(frob e0)");
    let text = "(semantics (locals 64) (exprs (e0 64 (local l0))) (body (read l0 rax 0 64)))";
    let error = parse(text, &DECLARATIONS).expect_err("unknown register");
    assert!(error.message.contains("rax"), "{error}");
    assert!(parse("(semantics (locals) (exprs) (body)", &DECLARATIONS).is_err());
}
