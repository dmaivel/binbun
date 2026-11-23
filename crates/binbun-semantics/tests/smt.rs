//! The SMT encoding against the interpreter: z3 must prove that what the
//! encoding computes from a concrete state is exactly what the interpreter
//! computes from it, for every operation at several widths and for
//! semantics with branches, loops, traps, memory and control transfers.
//!
//! Needs `z3` on the `PATH` (skipped with a notice otherwise).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{self, Fault, Machine, Outcome, Value};
use binbun_semantics::ir::{
    Binary, Declarations, ExprId, Flag, IntrinsicId, IntrinsicInfo, LaneOp, RegisterId,
    RegisterInfo, Trap, Unary,
};
use binbun_semantics::smt::{self, Final, Options, Script, State, Term};
use binbun_semantics::{Builder, Semantics, View};

const REGISTERS: [RegisterInfo; 5] = [
    RegisterInfo {
        name: "a",
        width: 64,
    },
    RegisterInfo {
        name: "b",
        width: 64,
    },
    RegisterInfo {
        name: "c",
        width: 64,
    },
    RegisterInfo {
        name: "f",
        width: 1,
    },
    RegisterInfo {
        name: "v",
        width: 128,
    },
];

const INTRINSICS: [IntrinsicInfo; 1] = [IntrinsicInfo {
    name: "mix",
    inputs: &[64],
    outputs: &[64],
    escapes: true,
    stores: true,
    opaque: false,
}];

const TEST: Declarations = Declarations {
    registers: &REGISTERS,
    intrinsics: &INTRINSICS,
    sites: &[],
};

const A: RegisterId = RegisterId(0);
const B: RegisterId = RegisterId(1);
const C: RegisterId = RegisterId(2);
const F: RegisterId = RegisterId(3);
const V: RegisterId = RegisterId(4);

fn view(register: RegisterId, offset: u16, width: u16) -> View {
    View {
        register,
        offset,
        width,
    }
}

fn whole(register: RegisterId) -> View {
    view(register, 0, REGISTERS[usize::from(register.0)].width)
}

/// Runs z3 on `script`; one answer (`sat`, `unsat`, a value list) per line
/// group. `None` if z3 is not installed.
fn z3(script: &str) -> Option<Vec<String>> {
    let mut child = match Command::new("z3")
        .args(["-in", "-smt2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!("skipped: cannot run z3 ({error})");
            return None;
        }
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    Some(text.lines().map(str::to_owned).collect())
}

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Mostly edge values.
    fn value(&mut self, width: u16) -> Bits {
        let ones = Bits::ones(width);
        let msb = Bits::from_u64(width, 1).shift_left(u32::from(width) - 1);
        match self.next() % 8 {
            0 => Bits::zero(width),
            1 => Bits::from_u64(width, 1),
            2 => ones,
            3 => msb,
            4 => msb.wrapping_sub(&Bits::from_u64(width, 1)),
            _ => Bits::from_u128(
                width,
                u128::from(self.next()) << 64 | u128::from(self.next()),
            ),
        }
    }
}

/// Semantics reading `a`, `b` and `c` at `width` bits and writing `op` of
/// them (as many as it takes) to the low bits of `v`; and the result's
/// width.
fn operation(width: u16, build: impl Fn(&mut Builder, [ExprId; 3]) -> ExprId) -> (Semantics, u16) {
    let mut b = Builder::new();
    let x = b.read(view(A, 0, width));
    let y = b.read(view(B, 0, width));
    let z = b.read(view(C, 0, width));
    let result = build(&mut b, [x, y, z]);
    let result_width = b.width(result);
    b.write(view(V, 0, result_width), result);
    (b.finish().unwrap(), result_width)
}

/// A push/pop group asserting `state` and that `term` is not `expected`;
/// z3 must answer `unsat`.
fn refute(script: &mut Script, assumptions: &[Term], term: &Term, expected: &Term) {
    script.push();
    for assumption in assumptions {
        script.assert(assumption);
    }
    script.assert(&smt::not(&smt::eq(term, expected)));
    script.command("(check-sat)");
    script.pop();
}

fn initial_values(state: &State, values: &[(RegisterId, Bits)]) -> Vec<Term> {
    values
        .iter()
        .map(|(id, bits)| {
            let register = state.register(*id).unwrap();
            let width = bits.width();
            let full = REGISTERS[usize::from(id.0)].width;
            let low = if width == full {
                register.clone()
            } else {
                Term::new(format!("((_ extract {} 0) {register})", width - 1))
            };
            smt::eq(&low, &smt::constant(bits))
        })
        .collect()
}

fn low_bits(term: &Term, width: u16) -> Term {
    Term::new(format!("((_ extract {} 0) {term})", width - 1))
}

const UNARY: [Unary; 7] = [
    Unary::Not,
    Unary::Neg,
    Unary::Popcount,
    Unary::LeadingZeros,
    Unary::TrailingZeros,
    Unary::ByteSwap,
    Unary::EvenParity8,
];

const BINARY: [Binary; 21] = [
    Binary::Add,
    Binary::Sub,
    Binary::Mul,
    Binary::UDiv,
    Binary::URem,
    Binary::SDiv,
    Binary::SRem,
    Binary::And,
    Binary::Or,
    Binary::Xor,
    Binary::Shl,
    Binary::LShr,
    Binary::AShr,
    Binary::Rol,
    Binary::Ror,
    Binary::Eq,
    Binary::Ne,
    Binary::ULt,
    Binary::ULe,
    Binary::SLt,
    Binary::SLe,
];

const FLAGS: [Flag; 5] = [
    Flag::AddCarry,
    Flag::AddOverflow,
    Flag::SubBorrow,
    Flag::SubOverflow,
    Flag::NibbleCarry,
];

/// The interpreter's answer for three operand values.
type Compute = Box<dyn Fn(&[Bits; 3]) -> Bits>;

/// One operation at one width: its semantics (writing the result to `v`),
/// the result's width, and the interpreter's answer for operand values.
struct Case {
    name: String,
    width: u16,
    semantics: Semantics,
    result_width: u16,
    compute: Compute,
    /// The third operand is a carry in (0 or 1).
    carry_in: bool,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let mut add = |name: String, width, (semantics, result_width), compute, carry_in| {
        cases.push(Case {
            name,
            width,
            semantics,
            result_width,
            compute,
            carry_in,
        });
    };
    for width in [1u16, 5, 8, 16, 64] {
        for op in UNARY {
            if op == Unary::ByteSwap && !width.is_multiple_of(8) {
                continue;
            }
            add(
                format!("{op:?}/{width}"),
                width,
                operation(width, |b, [x, _, _]| b.unary(op, x)),
                Box::new(move |v| interpret::unary(op, Value::defined(v[0])).bits),
                false,
            );
        }
        for op in BINARY {
            add(
                format!("{op:?}/{width}"),
                width,
                operation(width, |b, [x, y, _]| b.binary(op, x, y)),
                Box::new(move |v| {
                    interpret::binary(op, Value::defined(v[0]), Value::defined(v[1])).bits
                }),
                false,
            );
        }
        for op in FLAGS {
            add(
                format!("{op:?}/{width}"),
                width,
                operation(width, |b, [x, y, z]| b.flag(op, x, y, z)),
                Box::new(move |v| {
                    let [a, b, c] = v.map(Value::defined);
                    interpret::flag(op, a, b, c).bits
                }),
                // Carries and borrows take 0 or 1 as their third operand.
                op != Flag::NibbleCarry,
            );
        }
    }
    cases
}

#[test]
fn operations_match_the_interpreter() {
    let mut random = Random(0x5eed_1234_9876_abcd);
    let mut script = Script::new();
    let mut checks = Vec::new();
    let options = Options::default();
    for case in cases() {
        script.push();
        let initial = script.initial_state(&TEST, "s.", &options);
        let done = script
            .encode(&case.semantics, &TEST, &initial, "e", &options)
            .unwrap();
        let v = done.state.register(V).unwrap();
        for _ in 0..12 {
            let mut values = [0; 3].map(|_| random.value(case.width));
            if case.carry_in {
                values[2] = Bits::from_u64(case.width, random.next() & 1);
            }
            let expected = (case.compute)(&values);
            let assumptions =
                initial_values(&initial, &[(A, values[0]), (B, values[1]), (C, values[2])]);
            refute(
                &mut script,
                &assumptions,
                &low_bits(v, case.result_width),
                &smt::constant(&expected),
            );
            checks.push(format!(
                "{} on {values:?}: interpreter {expected:?}",
                case.name
            ));
        }
        script.pop();
    }
    let Some(answers) = z3(script.as_str()) else {
        return;
    };
    assert_eq!(answers.len(), checks.len(), "{answers:?}");
    let failures: Vec<&String> = checks
        .iter()
        .zip(&answers)
        .filter(|(_, answer)| answer.as_str() != "unsat")
        .map(|(check, _)| check)
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A concrete machine for the interpreter: registers, and memory whose
/// bytes are a function of the address until stored to. Records every
/// address accessed.
struct Test {
    registers: BTreeMap<u16, Value>,
    memory: BTreeMap<u64, u8>,
    touched: Vec<u64>,
}

fn initial_byte(address: u64) -> u8 {
    (address.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as u8
}

impl Test {
    fn byte(&mut self, address: u64) -> u8 {
        self.touched.push(address);
        *self
            .memory
            .entry(address)
            .or_insert_with(|| initial_byte(address))
    }
}

impl Machine for Test {
    fn read(&mut self, register: RegisterId) -> Value {
        self.registers[&register.0]
    }

    fn write(&mut self, register: RegisterId, value: Value) {
        self.registers.insert(register.0, value);
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        let data: Vec<u8> = (0..u64::from(bytes))
            .map(|i| self.byte(address.wrapping_add(i)))
            .collect();
        Ok(Value::defined(Bits::from_le_bytes(bytes * 8, &data)))
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        for (i, byte) in value.bits.to_le_bytes().enumerate() {
            let at = address.wrapping_add(i as u64);
            self.byte(at);
            self.memory.insert(at, byte);
        }
        Ok(())
    }
}

/// Checks `semantics` from random states: z3 must refute every difference
/// between the encoding and the interpreter (unroll `unroll` times).
fn agrees_with_interpreter(semantics: &Semantics, states: usize, unroll: u32, seed: u64) {
    let mut random = Random(seed);
    let options = Options {
        address_width: 64,
        unroll,
    };
    let mut script = Script::new();
    let mut cases = Vec::new();
    for _ in 0..states {
        let mut values: Vec<(RegisterId, Bits)> = REGISTERS
            .iter()
            .enumerate()
            .map(|(index, info)| {
                let id = RegisterId(u16::try_from(index).unwrap());
                (id, random.value(info.width))
            })
            .collect();
        // Small counts in `c`, so loops end within the unrolling.
        values[2].1 = Bits::from_u64(64, random.next() % 6);
        let mut machine = Test {
            registers: values
                .iter()
                .map(|(id, bits)| (id.0, Value::defined(*bits)))
                .collect(),
            memory: BTreeMap::new(),
            touched: Vec::new(),
        };
        let outcome = interpret::run(semantics, &mut machine);
        script.push();
        let initial = script.initial_state(&TEST, "s.", &options);
        let done = script
            .encode(semantics, &TEST, &initial, "e", &options)
            .unwrap();
        let mut assumptions = initial_values(&initial, &values);
        for &address in &machine.touched {
            assumptions.push(smt::eq(
                &Term::new(format!(
                    "(select {} {})",
                    initial.memory,
                    smt::literal(64, address)
                )),
                &smt::literal(8, u64::from(initial_byte(address))),
            ));
        }
        let expected = expectation(&done, &machine, outcome);
        refute(&mut script, &assumptions, &expected, &smt::top());
        script.pop();
        cases.push(format!("{values:x?}: {outcome:?}"));
    }
    let Some(answers) = z3(script.as_str()) else {
        return;
    };
    assert_eq!(answers.len(), cases.len(), "{answers:?}");
    let failures: Vec<&String> = cases
        .iter()
        .zip(&answers)
        .filter(|(_, answer)| answer.as_str() != "unsat")
        .map(|(case, _)| case)
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Boolean: the encoding ends as the interpreter did.
fn expectation(done: &Final, machine: &Test, outcome: Outcome) -> Term {
    let mut parts = vec![smt::not(&done.exhausted)];
    match outcome {
        Outcome::Trap(trap) => {
            let kind = done
                .traps
                .iter()
                .filter(|(kind, _)| *kind == trap)
                .map(|(_, condition)| condition.clone())
                .collect::<Vec<_>>();
            parts.push(smt::or(&kind));
            return smt::and(&parts);
        }
        Outcome::Next => parts.push(smt::not(&done.transferred)),
        Outcome::Transfer(target) => {
            parts.push(done.transferred.clone());
            parts.push(smt::eq(&done.target, &smt::literal(64, target)));
        }
        Outcome::SystemCall => parts.push(done.system_call.clone()),
        Outcome::Fault(_) | Outcome::Undetermined | Outcome::OutOfFuel | Outcome::Malformed => {
            panic!("unexpected {outcome:?}")
        }
    }
    parts.push(smt::not(&done.trap));
    for (index, value) in &machine.registers {
        let register = done.state.register(RegisterId(*index)).unwrap();
        parts.push(smt::eq(register, &smt::constant(&value.bits)));
    }
    for (address, byte) in &machine.memory {
        parts.push(smt::eq(
            &Term::new(format!(
                "(select {} {})",
                done.state.memory,
                smt::literal(64, *address)
            )),
            &smt::literal(8, u64::from(*byte)),
        ));
    }
    smt::and(&parts)
}

#[test]
fn branches_traps_and_transfers_match_the_interpreter() {
    // if a < b { if f { trap } else { v.hi = a } ; jump b } else { a = b - a }
    // store a at c + 0x1000; b = load c + 0x1000 (8 bytes) + 1
    let mut b = Builder::new();
    let first = b.read(whole(A));
    let second = b.read(whole(B));
    let flag = b.read(whole(F));
    let less = b.binary(Binary::ULt, first, second);
    b.begin_if(less);
    b.begin_if(flag);
    b.trap(Trap::Protection);
    b.otherwise();
    b.write(view(V, 64, 64), first);
    b.end_if();
    b.jump(second);
    b.otherwise();
    let difference = b.binary(Binary::Sub, second, first);
    b.write(whole(A), difference);
    b.end_if();
    let count = b.read(whole(C));
    let base = b.constant(64, 0x1000);
    let address = b.binary(Binary::Add, count, base);
    let now = b.read(whole(A));
    b.store(address, now);
    let back = b.load(address, 8);
    let one = b.constant(64, 1);
    let sum = b.binary(Binary::Add, back, one);
    b.write(whole(B), sum);
    let semantics = b.finish().unwrap();
    agrees_with_interpreter(&semantics, 40, 4, 0x1111_2222_3333_4444);
}

#[test]
fn loops_with_breaks_match_the_interpreter() {
    // loop { if c == 0 { break }; a = a * 3 + b; store byte a at 0x2000 + c; c -= 1 }
    let mut b = Builder::new();
    b.begin_loop();
    let count = b.read(whole(C));
    let zero = b.constant(64, 0);
    let done = b.binary(Binary::Eq, count, zero);
    b.begin_if(done);
    b.brk();
    b.end_if();
    let x = b.read(whole(A));
    let y = b.read(whole(B));
    let three = b.constant(64, 3);
    let product = b.binary(Binary::Mul, x, three);
    let next = b.binary(Binary::Add, product, y);
    b.write(whole(A), next);
    let base = b.constant(64, 0x2000);
    let address = b.binary(Binary::Add, base, count);
    let low = b.extract(next, 0, 8);
    b.store(address, low);
    let one = b.constant(64, 1);
    let less = b.binary(Binary::Sub, count, one);
    b.write(whole(C), less);
    b.end_loop();
    let semantics = b.finish().unwrap();
    agrees_with_interpreter(&semantics, 30, 6, 0x5555_6666_7777_8888);
}

#[test]
fn lanes_selects_and_extensions_match_the_interpreter() {
    let mut b = Builder::new();
    let vector = b.read(whole(V));
    let x = b.read(whole(A));
    let y = b.read(whole(B));
    let wide = b.concat(x, y);
    let sums = b.lanes(LaneOp::Binary(Binary::Add), 8, &[vector, wide]);
    let less = b.lanes(LaneOp::Binary(Binary::SLt), 4, &[vector, wide]);
    let minimum = b.lanes(LaneOp::Select, 4, &[less, vector, wide]);
    let halves = b.lanes(
        LaneOp::Extract {
            offset: 0,
            width: 16,
        },
        4,
        &[minimum],
    );
    let widened = b.lanes(
        LaneOp::Extend {
            signed: true,
            width: 32,
        },
        4,
        &[halves],
    );
    let counts = b.lanes(LaneOp::Unary(Unary::Popcount), 2, &[sums]);
    b.write(whole(V), widened);
    let low = b.extract(counts, 0, 64);
    let f = b.read(whole(F));
    let signed = b.sext(f, 64);
    let chosen = b.select(f, low, signed);
    b.write(whole(A), chosen);
    let semantics = b.finish().unwrap();
    agrees_with_interpreter(&semantics, 40, 1, 0x9999_aaaa_bbbb_cccc);
}

/// Two encodings of the same semantics from one state agree, and the
/// encoding sees an intrinsic's outputs as a function of its inputs: equal
/// inputs, equal outputs; different inputs, possibly different outputs.
#[test]
fn intrinsics_are_functions_of_their_inputs() {
    let mut b = Builder::new();
    let x = b.read(whole(A));
    let [out] = b.intrinsic(IntrinsicId(0), &[x], &[64])[..] else {
        unreachable!()
    };
    b.write(whole(B), out);
    let semantics = b.finish().unwrap();
    let options = Options::default();
    let mut script = Script::new();
    let initial = script.initial_state(&TEST, "s.", &options);
    let first = script
        .encode(&semantics, &TEST, &initial, "p", &options)
        .unwrap();
    let second = script
        .encode(&semantics, &TEST, &initial, "q", &options)
        .unwrap();
    // From the same state: the same outcome.
    script.push();
    script.assert(&smt::not(&smt::same_outcome(&first, &second, &[])));
    script.command("(check-sat)");
    script.pop();
    // From states differing in `a`: `b` may differ.
    let other = script.initial_state(&TEST, "t.", &options);
    let third = script
        .encode(&semantics, &TEST, &other, "r", &options)
        .unwrap();
    script.assert(&smt::not(&smt::eq(
        third.state.register(B).unwrap(),
        first.state.register(B).unwrap(),
    )));
    script.command("(check-sat)");
    let Some(answers) = z3(script.as_str()) else {
        return;
    };
    assert_eq!(answers, ["unsat", "sat"]);
}
