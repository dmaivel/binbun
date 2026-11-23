#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! What the printer refuses, and the sizes it still handles: deep
//! expressions print without native recursion; shared operands that
//! would blow up and statements nested past the limit are refused.

mod common;

use binbun_ast::ir::{Expr, Stmt};
use binbun_ast::types::Type;
use binbun_print::c;
use binbun_print::style::Style;
use binbun_semantics::ir::{Binary, LaneOp};
use common::{Builder, DECLARATIONS, print};

fn refusal(f: &binbun_ast::ir::Function) -> String {
    c::function(f, &DECLARATIONS, &Style::kr(), &|_| None, c::Opaque::Calls)
        .unwrap_err()
        .message
}

#[test]
fn deep_expressions_print_on_a_small_stack() {
    let thread = std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(|| {
            let mut b = Builder::new(0x1000, "deep");
            let int32 = b.int(32);
            b.f.returns = Some(int32);
            let x = b.param(int32);
            let mut left = b.read(x);
            let mut right = b.read(x);
            for _ in 0..20_000 {
                let one = b.c(32, 1);
                left = b.bin(Binary::Add, left, one);
            }
            for _ in 0..2_000 {
                let rx = b.read(x);
                right = b.bin(Binary::Sub, rx, right);
            }
            let both = b.bin(Binary::Xor, left, right);
            let ret = b.ret(both);
            let f = b.done(vec![ret]);
            let (text, _) = print(&f, &Style::kr());
            (text.matches('+').count(), text.matches('(').count())
        });
    let (additions, parentheses) = thread.unwrap().join().unwrap();
    // A left-nested chain needs no parentheses, a right-nested one one
    // pair per level.
    assert_eq!(additions, 20_000);
    assert!(parentheses >= 2_000);
}

#[test]
fn shared_operands_beyond_the_budget_are_refused() {
    let mut b = Builder::new(0x1000, "shared");
    let int32 = b.int(32);
    b.f.returns = Some(int32);
    let x = b.param(int32);
    let mut value = b.read(x);
    // 2^40 leaves as a tree.
    for _ in 0..40 {
        value = b.bin(Binary::Add, value, value);
    }
    let ret = b.ret(value);
    let f = b.done(vec![ret]);
    assert!(refusal(&f).contains("too large"));
    // A right-nested chain is copied at each level: refused when deep.
    let mut b = Builder::new(0x1000, "right");
    let int32 = b.int(32);
    b.f.returns = Some(int32);
    let x = b.param(int32);
    let mut value = b.read(x);
    for _ in 0..12_000 {
        let rx = b.read(x);
        value = b.bin(Binary::Sub, rx, value);
    }
    let ret = b.ret(value);
    let f = b.done(vec![ret]);
    assert!(refusal(&f).contains("too large"));
}

#[test]
fn statements_nested_past_the_limit_are_refused() {
    let nested = |depth: usize| {
        let mut b = Builder::new(0x1000, "nested");
        let int32 = b.int(32);
        let x = b.param(int32);
        let rx = b.read(x);
        let zero = b.c(32, 0);
        let condition = b.bin(Binary::Ne, rx, zero);
        let mut stmt = b.s(Stmt::Return(None));
        for _ in 0..depth {
            stmt = b.s(Stmt::If {
                condition,
                then: vec![stmt],
                otherwise: vec![],
            });
        }
        b.done(vec![stmt])
    };
    let (text, _) = print(&nested(98), &Style::kr());
    assert_eq!(text.matches("if (").count(), 98);
    assert!(refusal(&nested(101)).contains("nested deeper"));
    assert!(refusal(&nested(100_000)).contains("nested deeper"));
}

/// Lane-wise operations C's vector extensions have no exact operator for
/// (a division by a lane of 0 is all ones in L0, undefined in C) are
/// refused; the others print (`meaning.rs`).
#[test]
fn lane_wise_divisions_are_refused() {
    let mut b = Builder::new(0x1000, "vector");
    let wide = b.ty(Type::UInt(64));
    b.f.returns = Some(wide);
    let x = b.param(wide);
    let rx = b.read(x);
    let lanes = b.e(Expr::Lanes {
        lanes: 2,
        op: LaneOp::Binary(Binary::UDiv),
        operands: [rx, rx, rx],
    });
    let ret = b.ret(lanes);
    let f = b.done(vec![ret]);
    assert!(refusal(&f).contains("vector operations"));
}
