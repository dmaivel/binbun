#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The L2 interpreter on hand-built functions: loops left from inside
//! nested ones, switch fallthrough and default, gotos into and out of
//! blocks, calls, memory through typed places, wrapping at narrow widths,
//! `&&` and `||` evaluating their right operand only where needed.

mod build;

use binbun_ast::interpret::{Observer, Outcome, run, run_observed};
use binbun_ast::ir::{
    Arm, Call, Callee, Escape, Expr, ExprId, Function, Logical, Place, Save, Stmt, StmtId, Update,
    Va, VaList, VarKind,
};
use binbun_ast::types::Type;
use binbun_ast::verify::verify;
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{Fault, Value};
use binbun_semantics::ir::{Binary, IntrinsicId, RegisterId};
use build::{Builder, DECLARATIONS, FUEL, LIMIT, Memory, STACK, defined};

/// Verifies `function`, then runs it on `memory` with `arguments`.
fn check_and_run(function: &Function, memory: &mut Memory, arguments: &[Value]) -> Outcome {
    if let Err(error) = verify(function, &DECLARATIONS) {
        panic!("{error}");
    }
    run(function, memory, arguments, STACK, FUEL)
}

fn returned(width: u16, value: u64) -> Outcome {
    Outcome::Returned(Some(defined(width, value)))
}

#[test]
fn break_and_continue_leave_the_loop_they_name() {
    // total = 0; i = 0;
    // outer: while (i < 10) {
    //   i += 1; j = 0;
    //   while (1) {
    //     j += 1;
    //     if (j == 3) continue outer;
    //     if (i == 5) break outer;
    //     total += 1;
    //   }
    // }
    // for (k = 0; k < 4; k += 1) { if (k == 1) continue; total += k << 8; }
    // return total;
    let mut b = Builder::new();
    let int32 = b.int32;
    let (total, i, j, k) = (
        b.local(int32),
        b.local(int32),
        b.local(int32),
        b.local(int32),
    );
    let outer = b.f.add_stmt(Stmt::Unreachable);
    let inner = b.f.add_stmt(Stmt::Unreachable);
    let next_outer = b.s(Stmt::Continue(outer));
    let three = b.op_c(Binary::Eq, j, 3);
    let if_three = b.s(Stmt::If {
        condition: three,
        then: vec![next_outer],
        otherwise: vec![],
    });
    let leave_outer = b.s(Stmt::Break(outer));
    let five = b.op_c(Binary::Eq, i, 5);
    let if_five = b.s(Stmt::If {
        condition: five,
        then: vec![leave_outer],
        otherwise: vec![],
    });
    let count = b.add_to(total, 1);
    let bump_j = b.add_to(j, 1);
    let forever = b.c(1, 1);
    b.f.stmts[inner.0 as usize] = Stmt::While {
        condition: forever,
        body: vec![bump_j, if_three, if_five, count],
    };
    let below_ten = b.op_c(Binary::SLt, i, 10);
    let bump_i = b.add_to(i, 1);
    let clear_j = b.set(j, 0);
    b.f.stmts[outer.0 as usize] = Stmt::While {
        condition: below_ten,
        body: vec![bump_i, clear_j, inner],
    };

    let for_loop = b.f.add_stmt(Stmt::Unreachable);
    let init = b.set(k, 0);
    let step = b.add_to(k, 1);
    let below_four = b.op_c(Binary::SLt, k, 4);
    let next_k = b.s(Stmt::Continue(for_loop));
    let one = b.op_c(Binary::Eq, k, 1);
    let if_one = b.s(Stmt::If {
        condition: one,
        then: vec![next_k],
        otherwise: vec![],
    });
    let shifted = b.op_c(Binary::Shl, k, 8);
    let old = b.read(total);
    let sum = b.bin(Binary::Add, old, shifted);
    let accumulate = b.assign(total, sum);
    b.f.stmts[for_loop.0 as usize] = Stmt::For {
        init: vec![init],
        condition: below_four,
        step: vec![step],
        body: vec![if_one, accumulate],
    };

    let start_total = b.set(total, 0);
    let start_i = b.set(i, 0);
    let done = b.ret(total);
    b.f.returns = Some(int32);
    b.f.body = vec![start_total, start_i, outer, for_loop, done];
    // Two per pass of the outer loop for i = 1..=4, then k = 0, 2, 3.
    assert_eq!(
        check_and_run(&b.f, &mut Memory::default(), &[]),
        returned(32, 8 + (5 << 8))
    );
}

#[test]
fn switch_falls_through_and_defaults() {
    // switch (x) {
    //   case 1: r += 1; fallthrough
    //   case 2: r += 0x10;
    //   case 3, default: r += 0x100; fallthrough
    //   case 4: r += 0x1000;
    //   case 5: if (1) break; r += 5;
    // }
    let mut b = Builder::new();
    let int32 = b.int32;
    let x = b.param(int32);
    let r = b.local(int32);
    let switch = b.f.add_stmt(Stmt::Unreachable);
    let one = b.add_to(r, 1);
    let sixteen = b.add_to(r, 0x10);
    let hundred = b.add_to(r, 0x100);
    let thousand = b.add_to(r, 0x1000);
    let leave = b.s(Stmt::Break(switch));
    let always = b.c(1, 1);
    let if_always = b.s(Stmt::If {
        condition: always,
        then: vec![leave],
        otherwise: vec![],
    });
    let five = b.add_to(r, 5);
    let arm = |values: &[u64], default, body, fallthrough| Arm {
        values: values.iter().map(|&v| Bits::from_u64(32, v)).collect(),
        default,
        body,
        fallthrough,
    };
    let scrutinee = b.read(x);
    b.f.stmts[switch.0 as usize] = Stmt::Switch {
        scrutinee,
        arms: vec![
            arm(&[1], false, vec![one], true),
            arm(&[2], false, vec![sixteen], false),
            arm(&[3], true, vec![hundred], true),
            arm(&[4], false, vec![thousand], false),
            arm(&[5], false, vec![if_always, five], false),
        ],
    };
    let clear = b.set(r, 0);
    let done = b.ret(r);
    b.f.returns = Some(int32);
    b.f.body = vec![clear, switch, done];
    for (input, expected) in [
        (1, 0x11),
        (2, 0x10),
        (3, 0x1100),
        (4, 0x1000),
        (5, 0),
        (9, 0x1100),
    ] {
        let outcome = check_and_run(&b.f, &mut Memory::default(), &[defined(32, input)]);
        assert_eq!(outcome, returned(32, expected), "x = {input}");
    }
}

#[test]
fn goto_enters_and_leaves_blocks() {
    // i = 10; count = 0;
    // goto inside;
    // while (i < 3) { count += 0x10; inside: i += 1; }
    // top: count += 1;
    // if (count < 3) { if (1) { goto top; } }
    // return count * 0x100 + i;
    let mut b = Builder::new();
    let int32 = b.int32;
    let (i, count) = (b.local(int32), b.local(int32));
    let (inside, top) = (b.f.add_label(), b.f.add_label());
    let start_i = b.set(i, 10);
    let start_count = b.set(count, 0);
    let jump_in = b.s(Stmt::Goto(inside));
    let below_three = b.op_c(Binary::SLt, i, 3);
    let skipped = b.add_to(count, 0x10);
    let label_inside = b.s(Stmt::Label(inside));
    let bump_i = b.add_to(i, 1);
    let loop_ = b.s(Stmt::While {
        condition: below_three,
        body: vec![skipped, label_inside, bump_i],
    });
    let label_top = b.s(Stmt::Label(top));
    let bump_count = b.add_to(count, 1);
    let back = b.s(Stmt::Goto(top));
    let always = b.c(1, 1);
    let inner_if = b.s(Stmt::If {
        condition: always,
        then: vec![back],
        otherwise: vec![],
    });
    let few = b.op_c(Binary::SLt, count, 3);
    let outer_if = b.s(Stmt::If {
        condition: few,
        then: vec![inner_if],
        otherwise: vec![],
    });
    let scaled = b.op_c(Binary::Mul, count, 0x100);
    let read_i = b.read(i);
    let result = b.bin(Binary::Add, scaled, read_i);
    let done = b.s(Stmt::Return(Some(result)));
    b.f.returns = Some(int32);
    b.f.body = vec![
        start_i,
        start_count,
        jump_in,
        loop_,
        label_top,
        bump_count,
        outer_if,
        done,
    ];
    // Entering the loop at the label skips its first check: i = 11, and
    // the loop ends at the check after the body.
    assert_eq!(
        check_and_run(&b.f, &mut Memory::default(), &[]),
        returned(32, 0x300 + 11)
    );
}

#[test]
fn a_call_stops_the_run() {
    // p = param; v = call 0x2000(x + 1, *(int32 *)p); *(int32 *)p = v; return v;
    let mut b = Builder::new();
    let (int32, int64) = (b.int32, b.int64);
    let p = b.param(int64);
    let v = b.local(int32);
    let signature = b.code(vec![int32, int32], Some(int32));
    let argument = b.c(32, 7);
    let one = b.c(32, 1);
    let sum = b.bin(Binary::Add, argument, one);
    let address = b.read(p);
    let loaded = b.e(Expr::Load { address, ty: int32 });
    let call = b.s(Stmt::Call {
        results: vec![Place::Var(v)],
        call: Call {
            callee: Callee::Address(0x2000),
            arguments: vec![sum, loaded],
            signature,
            variadic: Vec::new(),
        },
    });
    let value = b.read(v);
    let store = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int32 },
        value,
    });
    let done = b.ret(v);
    b.f.returns = Some(int32);
    b.f.body = vec![call, store, done];
    let mut memory = Memory::default();
    memory.bytes.extend([(0x100, 0x2a), (0x101, 0x01)]);
    let outcome = check_and_run(&b.f, &mut memory, &[defined(64, 0x100)]);
    assert_eq!(
        outcome,
        Outcome::Call {
            at: binbun_ast::ir::CallSite::Stmt(call),
            target: 0x2000,
            arguments: vec![defined(32, 8), defined(32, 0x12a)],
        }
    );
    // Nothing after the call ran.
    assert_eq!(memory.bytes.len(), 2);
}

#[test]
fn a_call_in_an_expression_stops_the_run_after_its_arguments() {
    // *(int32 *)p = 5; return v + f(7 + 1): the store runs, the call
    // stops the run with its argument, before the expression it is in
    // finishes (v is undefined: an addition would not stop the run).
    let mut b = Builder::new();
    let (int32, int64) = (b.int32, b.int64);
    let p = b.param(int64);
    let signature = b.code(vec![int32], Some(int32));
    let address = b.read(p);
    let five = b.c(32, 5);
    let store = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int32 },
        value: five,
    });
    let (seven, one) = (b.c(32, 7), b.c(32, 1));
    let argument = b.bin(Binary::Add, seven, one);
    let call = b.f.add_call(Call {
        callee: Callee::Address(0x2000),
        arguments: vec![argument],
        signature,
        variadic: Vec::new(),
    });
    let made = b.e(Expr::Call(call));
    let local = b.local(int32);
    let read = b.read(local);
    let sum = b.bin(Binary::Add, read, made);
    let done = b.s(Stmt::Return(Some(sum)));
    b.f.returns = Some(int32);
    b.f.body = vec![store, done];
    let mut memory = Memory::default();
    let outcome = check_and_run(&b.f, &mut memory, &[defined(64, 0x100)]);
    assert_eq!(
        outcome,
        Outcome::Call {
            at: binbun_ast::ir::CallSite::Expr(made),
            target: 0x2000,
            arguments: vec![defined(32, 8)],
        }
    );
    assert_eq!(memory.bytes.get(&0x100), Some(&5));
}

#[test]
fn typed_places_load_and_store_memory() {
    // *(int16 *)(p + 2) = 0xbeef; frame = *(int16 *)(p + 2) as int32 (zext);
    // global = intrinsic outputs; return *(int64 *)&frame...
    let mut b = Builder::new();
    let (int16, int32, int64) = (b.int16, b.int32, b.int64);
    let p = b.param(int64);
    let frame = b.var(VarKind::Frame(-8), int32);
    let global = b.var(VarKind::Global(0x200), int32);
    let (low, high) = (b.local(int32), b.local(int32));
    let two = b.c(64, 2);
    let base = b.read(p);
    let address = b.bin(Binary::Add, base, two);
    let value = b.c(16, 0xbeef);
    let store = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int16 },
        value,
    });
    let loaded = b.e(Expr::Load { address, ty: int16 });
    let widened = b.e(Expr::Extend {
        signed: false,
        value: loaded,
        width: 32,
    });
    let to_frame = b.assign(frame, widened);
    let input = b.read(frame);
    let pair = b.s(Stmt::Intrinsic {
        results: vec![Place::Var(low), Place::Var(high)],
        intrinsic: IntrinsicId(0),
        inputs: vec![input],
    });
    let high_value = b.read(high);
    let to_global = b.assign(global, high_value);
    // Both words at once, through the frame variable's address.
    let frame_address = b.e(Expr::AddressOf(frame));
    let both = b.e(Expr::Load {
        address: frame_address,
        ty: int64,
    });
    let done = b.s(Stmt::Return(Some(both)));
    b.f.returns = Some(int64);
    b.f.body = vec![store, to_frame, pair, to_global, done];
    let mut memory = Memory::default();
    // The word above the frame variable.
    memory.bytes.extend([(STACK - 4, 0x11), (STACK - 1, 0x22)]);
    let outcome = check_and_run(&b.f, &mut memory, &[defined(64, 0x100)]);
    assert_eq!(outcome, returned(64, 0x2200_0011_0000_beef));
    let bytes = |address: u64, count: u64| -> Vec<u8> {
        (address..address + count)
            .map(|a| memory.bytes.get(&a).copied().unwrap_or(0))
            .collect()
    };
    assert_eq!(bytes(0x102, 2), [0xef, 0xbe]);
    assert_eq!(bytes(STACK - 8, 4), [0xef, 0xbe, 0, 0]);
    assert_eq!(bytes(0x200, 4), [0xf0, 0xbe, 0, 0]);

    // A load past the memory faults.
    let outcome = run(
        &b.f,
        &mut Memory::default(),
        &[defined(64, 0xfff)],
        STACK,
        FUEL,
    );
    assert_eq!(
        outcome,
        Outcome::Fault(Fault {
            address: 0x1001,
            write: true,
        })
    );
}

#[test]
fn an_assignment_expression_writes_where_the_condition_evaluates_it() {
    // n = 0; v = x;
    // while ((v = v - 1) != 0 && v != 7) n += 1;
    // if (x < 3 || (v = v + 100) != 0) return v + n; return 0;
    let mut b = Builder::new();
    let int32 = b.int32;
    let x = b.param(int32);
    let (v, n) = (b.local(int32), b.local(int32));
    let start = b.set(n, 0);
    let read_x = b.read(x);
    let copy = b.assign(v, read_x);
    let less = b.op_c(Binary::Sub, v, 1);
    let step = b.e(Expr::Assign {
        var: v,
        value: less,
    });
    let zero = b.c(32, 0);
    let nonzero = b.bin(Binary::Ne, step, zero);
    let seven = b.op_c(Binary::Ne, v, 7);
    let condition = b.e(Expr::Logical(Logical::And, nonzero, seven));
    let count = b.add_to(n, 1);
    let looping = b.s(Stmt::While {
        condition,
        body: vec![count],
    });
    let small = b.op_c(Binary::ULt, x, 3);
    let more = b.op_c(Binary::Add, v, 100);
    let bump = b.e(Expr::Assign {
        var: v,
        value: more,
    });
    let zero = b.c(32, 0);
    let bumped = b.bin(Binary::Ne, bump, zero);
    let test = b.e(Expr::Logical(Logical::Or, small, bumped));
    let read_v = b.read(v);
    let read_n = b.read(n);
    let sum = b.bin(Binary::Add, read_v, read_n);
    let early = b.s(Stmt::Return(Some(sum)));
    let decision = b.s(Stmt::If {
        condition: test,
        then: vec![early],
        otherwise: vec![],
    });
    let none = b.c(32, 0);
    let last = b.s(Stmt::Return(Some(none)));
    b.f.body = vec![start, copy, looping, decision, last];
    b.f.returns = Some(int32);
    let mut memory = Memory::default();
    // x = 5: v counts 4, 3, 2, 1, 0 (n = 4), then 100 is added.
    let five = check_and_run(&b.f, &mut memory, &[defined(32, 5)]);
    assert_eq!(five, returned(32, 104));
    // x = 9: v reaches 7 after one step (n = 1), and 107 + 1.
    assert_eq!(
        check_and_run(&b.f, &mut memory, &[defined(32, 9)]),
        returned(32, 108)
    );
    // x = 2: `||` decides on `x < 3`, so no 100: v = 0 after one step.
    assert_eq!(
        check_and_run(&b.f, &mut memory, &[defined(32, 2)]),
        returned(32, 1)
    );

    // The observer hears each assignment expression's write for the
    // statement whose condition makes it, before that statement decides.
    let mut heard = Log::default();
    let outcome = run_observed(
        &b.f,
        &mut memory,
        &[defined(32, 3)],
        STACK,
        FUEL,
        &mut heard,
    );
    assert_eq!(outcome, returned(32, 102));
    // x = 3: v = 2, 1 (n = 2), then 0 ends the loop; then 100.
    let expected = [
        Heard::Stmt(start, 0),
        Heard::Stmt(copy, 3),
        Heard::Expr(looping, step, 2),
        Heard::Decided(looping, 0),
        Heard::Stmt(count, 1),
        Heard::Expr(looping, step, 1),
        Heard::Decided(looping, 0),
        Heard::Stmt(count, 2),
        Heard::Expr(looping, step, 0),
        Heard::Decided(looping, 1),
        Heard::Expr(decision, bump, 100),
        Heard::Decided(decision, 0),
        Heard::Stmt(early, 102),
    ];
    assert_eq!(heard.0, expected);
    // x = 2: the `||` decides first; no assignment for the `if`.
    let mut heard = Log::default();
    run_observed(
        &b.f,
        &mut memory,
        &[defined(32, 2)],
        STACK,
        FUEL,
        &mut heard,
    );
    assert!(
        !heard
            .0
            .iter()
            .any(|event| matches!(event, Heard::Expr(id, ..) if *id == decision)),
        "{heard:?}"
    );
}

/// What [`run_observed`] tells an observer, in order: a statement's write
/// (its first value), an assignment expression's (its statement, itself,
/// the value), a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Heard {
    Stmt(StmtId, u64),
    Expr(StmtId, ExprId, u64),
    Decided(StmtId, usize),
}

/// An observer keeping what it hears.
#[derive(Debug, Default)]
struct Log(Vec<Heard>);

impl Observer for Log {
    fn assigned(&mut self, id: StmtId, values: &[Value]) {
        let value = values.first().and_then(Value::known).unwrap();
        self.0.push(Heard::Stmt(id, value.low_u64()));
    }

    fn assigned_in(&mut self, id: StmtId, at: ExprId, value: Value) {
        let value = value.known().unwrap();
        self.0.push(Heard::Expr(id, at, value.low_u64()));
    }

    fn decided(&mut self, id: StmtId, arm: usize) {
        self.0.push(Heard::Decided(id, arm));
    }
}

#[test]
fn arithmetic_wraps_at_narrow_widths() {
    // return concat(x + 1, x * x) for 8-bit x, and whether
    // 0x7f + 1 < 0 signed at 8 bits.
    let mut b = Builder::new();
    let (int8, bool1) = (b.int8, b.bool1);
    let x = b.param(int8);
    let sixteen = b.f.types.intern(Type::UInt(16));
    let read = b.read(x);
    let one = b.c(8, 1);
    let sum = b.bin(Binary::Add, read, one);
    let product = b.bin(Binary::Mul, read, read);
    let both = b.e(Expr::Concat {
        high: sum,
        low: product,
    });
    let done = b.s(Stmt::Return(Some(both)));
    b.f.returns = Some(sixteen);
    b.f.body = vec![done];
    assert_eq!(
        check_and_run(&b.f, &mut Memory::default(), &[defined(8, 0xff)]),
        returned(16, 0x0001)
    );

    let mut b = Builder::new();
    let largest = b.c(8, 0x7f);
    let one = b.c(8, 1);
    let zero = b.c(8, 0);
    let sum = b.bin(Binary::Add, largest, one);
    let negative = b.bin(Binary::SLt, sum, zero);
    let done = b.s(Stmt::Return(Some(negative)));
    b.f.returns = Some(bool1);
    b.f.body = vec![done];
    assert_eq!(
        check_and_run(&b.f, &mut Memory::default(), &[]),
        returned(1, 1)
    );
}

#[test]
fn fuel_and_undefined_conditions_stop_the_run() {
    // while (1) {}
    let mut b = Builder::new();
    let forever = b.c(1, 1);
    let spin = b.s(Stmt::While {
        condition: forever,
        body: vec![],
    });
    b.f.body = vec![spin];
    assert_eq!(
        check_and_run(&b.f, &mut Memory::default(), &[]),
        Outcome::OutOfFuel
    );

    // if (local never written == 0) {}
    let mut b = Builder::new();
    let int32 = b.int32;
    let unset = b.local(int32);
    let zero = b.op_c(Binary::Eq, unset, 0);
    let test = b.s(Stmt::If {
        condition: zero,
        then: vec![],
        otherwise: vec![],
    });
    b.f.body = vec![test];
    assert_eq!(
        check_and_run(&b.f, &mut Memory::default(), &[]),
        Outcome::Undetermined
    );
}

#[test]
fn atomic_accesses_run_as_the_access_they_stand_for() {
    // old = atomic load32(p); atomic store32(p, old + 1); return old;
    let mut b = Builder::new();
    let int32 = b.int32;
    let p = b.param(b.int64);
    let old = b.local(int32);
    let address = b.read(p);
    let load = b.s(Stmt::Escape {
        kind: Escape::Atomic,
        operands: vec![address],
        results: vec![Place::Var(old)],
    });
    let address = b.read(p);
    let next = b.op_c(Binary::Add, old, 1);
    let store = b.s(Stmt::Escape {
        kind: Escape::Atomic,
        operands: vec![address, next],
        results: Vec::new(),
    });
    let done = b.ret(old);
    b.f.returns = Some(int32);
    b.f.body = vec![load, store, done];
    let mut memory = Memory::default();
    memory
        .bytes
        .extend([(0x100, 0xff), (0x101, 0xff), (0x102, 0xff), (0x103, 0xff)]);
    // The run goes on through both: the old value back, the new one stored
    // (wrapping at 32 bits).
    assert_eq!(
        check_and_run(&b.f, &mut memory, &[defined(64, 0x100)]),
        returned(32, 0xffff_ffff)
    );
    assert_eq!(
        (0x100..0x104).map(|a| memory.bytes[&a]).collect::<Vec<_>>(),
        [0, 0, 0, 0]
    );
}

/// `old = atomic-update(p, operands); return old;` on four bytes holding
/// `before`: what it returns, and the bytes after.
fn updated(update: Update, operands: &[u64], before: u32) -> (Outcome, u32) {
    let mut b = Builder::new();
    let int32 = b.int32;
    let p = b.param(b.int64);
    let old = b.local(int32);
    let mut list = vec![b.read(p)];
    list.extend(operands.iter().map(|&value| b.c(32, value)));
    let update = b.s(Stmt::Escape {
        kind: Escape::Update(update),
        operands: list,
        results: vec![Place::Var(old)],
    });
    let done = b.ret(old);
    b.f.returns = Some(int32);
    b.f.body = vec![update, done];
    let mut memory = Memory::default();
    memory
        .bytes
        .extend((0x100..0x104).zip(before.to_le_bytes()));
    let outcome = check_and_run(&b.f, &mut memory, &[defined(64, 0x100)]);
    let after = [0x100, 0x101, 0x102, 0x103].map(|a| memory.bytes[&a]);
    (outcome, u32::from_le_bytes(after))
}

#[test]
fn an_atomic_update_gives_the_value_read_and_writes_the_one_it_makes() {
    let cases = [
        (Update::Exchange, vec![9], 5, 9),
        (Update::Add, vec![3], 0xffff_fffe, 1),
        (Update::Sub, vec![3], 5, 2),
        (Update::And, vec![6], 5, 4),
        (Update::Or, vec![6], 5, 7),
        (Update::Xor, vec![6], 5, 3),
        // What was expected was there: the new value. It was not: what
        // was there stays.
        (Update::CompareExchange, vec![5, 9], 5, 9),
        (Update::CompareExchange, vec![4, 9], 5, 5),
    ];
    for (update, operands, before, after) in cases {
        assert_eq!(
            updated(update, &operands, before),
            (returned(32, u64::from(before)), after),
            "{update:?} {operands:?}"
        );
    }
}

/// `return in_memory(p) op *(int8 *)p == 7` (`op` a logical operator, or
/// with `None` the bitwise `&`, which evaluates both sides), where
/// `in_memory(p)` is `p < LIMIT` for `&&` and `&`, `LIMIT <= p` for `||`.
fn guarded_load(op: Option<Logical>) -> Function {
    let mut b = Builder::new();
    let (int8, int64, bool1) = (b.int8, b.int64, b.bool1);
    let p = b.param(int64);
    let read = b.read(p);
    let limit = b.c(64, LIMIT);
    let guard = match op {
        Some(Logical::Or) => b.bin(Binary::ULe, limit, read),
        Some(Logical::And) | None => b.bin(Binary::ULt, read, limit),
    };
    let byte = b.e(Expr::Load {
        address: read,
        ty: int8,
    });
    let seven = b.c(8, 7);
    let loaded = b.bin(Binary::Eq, byte, seven);
    let both = match op {
        Some(op) => b.e(Expr::Logical(op, guard, loaded)),
        None => b.bin(Binary::And, guard, loaded),
    };
    let done = b.s(Stmt::Return(Some(both)));
    b.f.returns = Some(bool1);
    b.f.body = vec![done];
    b.f
}

#[test]
fn logical_operators_evaluate_the_right_operand_only_where_needed() {
    let run_at = |f: &Function, p: u64| {
        let mut memory = Memory::default();
        memory.bytes.insert(0x10, 7);
        check_and_run(f, &mut memory, &[defined(64, p)])
    };
    let and = guarded_load(Some(Logical::And));
    assert_eq!(run_at(&and, 0x10), returned(1, 1));
    assert_eq!(run_at(&and, 0x11), returned(1, 0));
    // Out of memory: `&&` decides on its left operand, without the load.
    assert_eq!(run_at(&and, LIMIT), returned(1, 0));
    let or = guarded_load(Some(Logical::Or));
    assert_eq!(run_at(&or, 0x10), returned(1, 1));
    assert_eq!(run_at(&or, 0x11), returned(1, 0));
    assert_eq!(run_at(&or, LIMIT), returned(1, 1));
    // `&` loads either way, and faults.
    let both = guarded_load(None);
    assert_eq!(
        run_at(&both, LIMIT),
        Outcome::Fault(Fault {
            address: LIMIT,
            write: false,
        })
    );
}

/// `va_start` saves the registers' values at the run's start (a guarded
/// save only where the guard's low byte is not 0), then writes System V's
/// four fields into its `va_list`, AAPCS64's five (an unset top's bytes
/// left as they were), or Microsoft's pointer into its local.
#[test]
fn va_start_saves_the_registers_and_writes_the_list() {
    let rdi = RegisterId(0);
    let spills = vec![
        Save {
            register: rdi,
            offset: -0x40,
            bytes: 8,
            guard: None,
        },
        Save {
            register: rdi,
            offset: -0x30,
            bytes: 4,
            guard: Some(rdi),
        },
    ];
    let run_with = |list: VaList, value: u64| {
        let mut b = Builder::new();
        let ty = match list {
            VaList::Tag { .. } => b.f.types.intern(Type::Array {
                element: b.int8,
                length: Some(24),
            }),
            VaList::Aapcs64 { .. } => b.f.types.intern(Type::Array {
                element: b.int8,
                length: Some(32),
            }),
            VaList::Pointer(_) => b.int64,
        };
        let kind = match list {
            VaList::Tag { .. } | VaList::Aapcs64 { .. } => VarKind::Frame(-0x60),
            VaList::Pointer(_) => VarKind::Local,
        };
        let ap = b.var(kind, ty);
        b.f.variadic = true;
        // AAPCS64 has no guarded save: the first only.
        let spilled = match list {
            VaList::Aapcs64 { .. } => spills[..1].to_vec(),
            VaList::Tag { .. } | VaList::Pointer(_) => spills.clone(),
        };
        b.f.va = Some(Va {
            list,
            saves: spilled,
        });
        let start = b.s(Stmt::VaStart {
            list: Place::Var(ap),
        });
        let done = b.ret(ap);
        b.f.body = vec![start];
        if kind == VarKind::Local {
            b.f.returns = Some(b.int64);
            b.f.body.push(done);
        }
        let mut memory = Memory::default();
        memory.registers.insert(rdi, defined(64, value));
        let outcome = check_and_run(&b.f, &mut memory, &[]);
        let read = |address: u64, bytes: u64| {
            (0..bytes).rev().fold(0u64, |word, byte| {
                word << 8 | u64::from(memory.bytes.get(&(address + byte)).copied().unwrap_or(0))
            })
        };
        let saved = [read(STACK - 0x40, 8), read(STACK - 0x30, 4)];
        let fields = [
            read(STACK - 0x60, 4),
            read(STACK - 0x5c, 4),
            read(STACK - 0x58, 8),
            read(STACK - 0x50, 8),
        ];
        let aapcs64 = [
            read(STACK - 0x60, 8),
            read(STACK - 0x58, 8),
            read(STACK - 0x50, 8),
            read(STACK - 0x48, 4),
            read(STACK - 0x44, 4),
        ];
        (outcome, saved, fields, aapcs64)
    };
    let tag = VaList::Tag {
        gp_offset: 8,
        fp_offset: Some(48),
        overflow: 8,
        save_area: -0x40,
    };
    // The guard's low byte is 0: the guarded save is not made.
    let (outcome, saved, fields, _) = run_with(tag, 0x1122_3344_5566_7700);
    assert_eq!(outcome, Outcome::Returned(None));
    assert_eq!(saved, [0x1122_3344_5566_7700, 0]);
    assert_eq!(fields, [8, 48, STACK + 8, STACK - 0x40]);
    let (_, saved, _, _) = run_with(tag, 0x1122_3344_5566_7701);
    assert_eq!(saved, [0x1122_3344_5566_7701, 0x5566_7701]);
    // AAPCS64's: `__stack`, `__gr_top`, `__vr_top` unset, the offsets.
    let aapcs64 = VaList::Aapcs64 {
        stack: 0,
        gr_top: Some(-0x38),
        vr_top: None,
        gr_offs: -8,
        vr_offs: -128,
    };
    let (outcome, _, _, fields) = run_with(aapcs64, 0x0102);
    assert_eq!(outcome, Outcome::Returned(None));
    assert_eq!(fields, [STACK, STACK - 0x38, 0, 0xffff_fff8, 0xffff_ff80]);
    // Microsoft's: a pointer to the first unnamed argument.
    let (outcome, saved, _, _) = run_with(VaList::Pointer(0x10), 0x0102);
    assert_eq!(outcome, returned(64, STACK + 0x10));
    assert_eq!(saved, [0x0102, 0x0102]);
}
