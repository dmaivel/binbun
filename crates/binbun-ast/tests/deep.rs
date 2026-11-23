#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Nesting deeper than any native stack holds: the verifier, the
//! interpreter and the printer walk statements and expressions with
//! explicit stacks.

mod build;

use std::thread;

use binbun_ast::interpret::{Outcome, run};
use binbun_ast::ir::{Expr, Function, Node, Stmt};
use binbun_ast::text::print;
use binbun_ast::verify::verify;
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Binary;
use build::{Builder, DECLARATIONS, Memory, STACK, defined};

const DEPTH: u32 = 100_000;

/// Runs `test` on a thread with a 2 MiB stack (the default for spawned
/// threads, set explicitly so `RUST_MIN_STACK` cannot hide an overflow).
fn on_small_stack(test: impl FnOnce() + Send + 'static) {
    thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

/// ```text
/// r = 0
/// if (x == 0xffffffff) goto deep;
/// outer: while (1) {
///   if (x == 0) { r = 0x10000; break outer; }
///   else if (x == 1) { r = 0x10001; break outer; }
///   ... DEPTH levels ...
///   else { deep: r = r + 1; break outer; }
/// }
/// return r + 1 + 1 + ... (DEPTH times)
/// ```
fn chain() -> Function {
    let mut b = Builder::new();
    let int32 = b.int32;
    let x = b.param(int32);
    let r = b.local(int32);
    let deep = b.f.add_label();
    let outer = b.f.add_stmt(Stmt::Unreachable);
    let label = b.s(Stmt::Label(deep));
    let bump = b.add_to(r, 1);
    let leave = b.s(Stmt::Break(outer));
    let mut otherwise = vec![label, bump, leave];
    for level in (0..DEPTH).rev() {
        let test = b.op_c(Binary::Eq, x, u64::from(level));
        let set = b.set(r, 0x10000 + u64::from(level));
        let leave = b.s(Stmt::Break(outer));
        let branch = b.s(Stmt::If {
            condition: test,
            then: vec![set, leave],
            otherwise,
        });
        otherwise = vec![branch];
    }
    let forever = b.c(1, 1);
    b.f.stmts[outer.0 as usize] = Stmt::While {
        condition: forever,
        body: otherwise,
    };
    let start = b.set(r, 0);
    let all_ones = b.op_c(Binary::Eq, x, 0xffff_ffff);
    let jump = b.s(Stmt::Goto(deep));
    let jump_in = b.s(Stmt::If {
        condition: all_ones,
        then: vec![jump],
        otherwise: vec![],
    });
    // A DEPTH-deep expression: ((r + 1) + 1) + ...
    let mut sum = b.read(r);
    let one = b.c(32, 1);
    for _ in 0..DEPTH {
        sum = b.e(Expr::Binary(Binary::Add, sum, one));
    }
    let done = b.s(Stmt::Return(Some(sum)));
    b.f.returns = Some(int32);
    b.f.body = vec![start, jump_in, outer, done];
    b.f
}

#[test]
fn deep_nesting_verifies_runs_and_prints() {
    on_small_stack(|| {
        let f = chain();
        assert_eq!(verify(&f, &DECLARATIONS), Ok(()));
        let fuel = 10 * u64::from(DEPTH);
        let outcome = |x: u64| run(&f, &mut Memory::default(), &[defined(32, x)], STACK, fuel);
        let depth = u64::from(DEPTH);
        // The last level's test, through every level before it.
        assert_eq!(
            outcome(depth - 1),
            Outcome::Returned(Some(defined(32, 0x10000 + 2 * depth - 1)))
        );
        // The innermost `else`, and a `goto` straight into it.
        assert_eq!(
            outcome(depth),
            Outcome::Returned(Some(defined(32, depth + 1)))
        );
        assert_eq!(
            outcome(0xffff_ffff),
            Outcome::Returned(Some(defined(32, depth + 1)))
        );
        let text = print(&f, &DECLARATIONS);
        assert_eq!(text.matches("break s").count(), DEPTH as usize + 1);
        assert!(text.contains("label l0"));
    });
}

#[test]
fn deep_nesting_is_still_checked() {
    on_small_stack(|| {
        // A `break` at the bottom of the chain naming a loop it is not in.
        let mut f = chain();
        let never = f.add_expr(Expr::Const(Bits::from_u64(1, 0)));
        let stray = f.add_stmt(Stmt::While {
            condition: never,
            body: vec![],
        });
        let wrong = f.add_stmt(Stmt::Break(stray));
        // The innermost `else` is the first `if` built.
        let innermost = f
            .stmts
            .iter_mut()
            .find(|stmt| matches!(stmt, Stmt::If { .. }))
            .unwrap();
        if let Stmt::If { otherwise, .. } = innermost {
            otherwise.push(wrong);
        }
        f.body.push(stray);
        let error = verify(&f, &DECLARATIONS).unwrap_err();
        assert_eq!(error.node, Some(Node::Stmt(wrong)));
    });
}
