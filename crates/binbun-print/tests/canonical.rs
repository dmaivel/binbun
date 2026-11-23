#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! L0's canonical-address check (`if (sext(extract(p, 0, 48)) != p)
//! trap`) printed as `binbun_defs.h`'s `binbun_check_canonical(p);` (#GP) and
//! `binbun_check_canonical_stack(p);` (#SS), compiled with GCC and Clang
//! and run: the macros trap exactly when the 64 bits are not a canonical
//! 48-bit address, with the kind of the check. Any other shape keeps the
//! explicit test.

mod common;

use binbun_ast::ir::{Expr, ExprId, Logical, Stmt, StmtId};
use binbun_ast::types::Type;
use binbun_print::style::Style;
use binbun_semantics::ir::{Binary, Trap};
use common::{Builder, Scratch, compilers, print, warnings};

/// `sext(extract(address, 0, width), 64) != other` (the extension on the
/// left: `extended_first`).
fn test(
    b: &mut Builder,
    address: ExprId,
    width: u16,
    other: ExprId,
    extended_first: bool,
) -> ExprId {
    let low = b.bits_of(address, 0, width);
    let extended = b.ext(true, low, 64);
    if extended_first {
        b.bin(Binary::Ne, extended, other)
    } else {
        b.bin(Binary::Ne, other, extended)
    }
}

/// `if (condition) trap;`.
fn guard(b: &mut Builder, condition: ExprId, trap: Trap) -> StmtId {
    let trap = b.s(Stmt::Trap(trap));
    b.when(condition, vec![trap])
}

/// The program that runs `checks` (printed in `out.c`) with a canonical or
/// a non-canonical value in each argument; it prints the trap kind of each
/// run (-1: none).
const MAIN: &str = r#"#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void checks(int32_t *, int32_t (*)(int32_t), uint64_t, uint64_t);

static jmp_buf back;
static volatile int trapped;

_Noreturn void binbun_hook_trap(int kind) {
    trapped = kind;
    longjmp(back, 1);
}

uint64_t binbun_hook_escape(int kind, size_t count, const uint64_t *operands) {
    (void)kind;
    (void)count;
    (void)operands;
    return 0;
}

static int run(uint64_t p, uint64_t f, uint64_t n, uint64_t m) {
    trapped = -1;
    if (setjmp(back) == 0)
        checks((int32_t *)(uintptr_t)p, (int32_t (*)(int32_t))(uintptr_t)f, n, m);
    return trapped;
}

int main(void) {
    const uint64_t low = 0x00007ffffffff000, high = 0xffff800000000000;
    const uint64_t bad = 0x0000800000000000, edge = 0x00007ffffffffff8;
    printf("%d %d %d %d %d %d %d\n", run(low, high, low, 1), run(bad, high, low, 1),
           run(low, bad, low, 1), run(low, high, bad, 1), run(low, high, edge, 1),
           run(low, high, edge, 0), run(high, 0xffff7fffffffffff, low, 1));
    return 0;
}
"#;

#[test]
fn canonical_checks_are_one_statement_and_trap_as_the_machine_does() {
    // A data pointer (the extension left, one node for both operands), a
    // code pointer (the extension right, two reads), an integer, and an
    // integer sum alone in an `else` (not chained into `else if`).
    let mut b = Builder::new(0x9400, "checks");
    let (int32, word) = (b.int(32), b.uint(64));
    let ints = b.ty(Type::Pointer(Some(int32)));
    let code = b.code(vec![int32], Some(int32), false);
    let (data, function, number, flag) =
        (b.param(ints), b.param(code), b.param(word), b.param(word));
    let pointer = b.read(data);
    let condition = test(&mut b, pointer, 48, pointer, true);
    let first = guard(&mut b, condition, Trap::Protection);
    let (callee, again) = (b.read(function), b.read(function));
    let condition = test(&mut b, callee, 48, again, false);
    let second = guard(&mut b, condition, Trap::Stack);
    let (value, again) = (b.read(number), b.read(number));
    let condition = test(&mut b, value, 48, again, true);
    let third = guard(&mut b, condition, Trap::Protection);
    let sum = |b: &mut Builder| {
        let (value, eight) = (b.read(number), b.c(64, 8));
        b.bin(Binary::Add, value, eight)
    };
    let (address, again) = (sum(&mut b), sum(&mut b));
    let condition = test(&mut b, address, 48, again, false);
    let inner = guard(&mut b, condition, Trap::Stack);
    let (test_flag, zero) = (b.read(flag), b.c(64, 0));
    let unset = b.bin(Binary::Eq, test_flag, zero);
    let early = b.s(Stmt::Return(None));
    let fourth = b.s(Stmt::If {
        condition: unset,
        then: vec![early],
        otherwise: vec![inner],
    });
    let f = b.done(vec![first, second, third, fourth]);
    let (text, counts) = print(&f, &Style::kr());
    for line in [
        "    binbun_check_canonical(a1);\n",
        "    binbun_check_canonical_stack(a2);\n",
        "    binbun_check_canonical(a3);\n",
        "        binbun_check_canonical_stack(a3 + 8);\n",
    ] {
        assert!(text.contains(line), "{line}missing:\n{text}");
    }
    assert!(!text.contains("else if"), "{text}");
    assert!(!text.contains("sext_n"), "{text}");
    assert_eq!(counts.casts, 0, "{text}");
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped compiling: no C compiler to check with");
        return;
    }
    let scratch = Scratch::new("canonical");
    scratch.write("out.c", &text);
    scratch.write("main.c", MAIN);
    for compiler in compilers {
        for optimization in ["-O0", "-O2"] {
            let stderr = scratch
                .compile(compiler, &["-c", "-o", "out.o", optimization], &["out.c"])
                .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
            assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
            let stderr = scratch
                .compile(
                    compiler,
                    &["-DBINBUN_HOOKS", "-o", "checks", optimization],
                    &["out.c", "main.c"],
                )
                .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
            assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
            // None; a1, a2, a3 non-canonical (#GP, #SS, #GP); a3 + 8 not
            // (#SS) unless the `else` is not taken; and bit 47 differing
            // from bit 48 at the top of the address space.
            assert_eq!(
                scratch.run("checks"),
                "-1 3 4 3 4 -1 4\n",
                "{compiler} {optimization}"
            );
        }
    }
}

#[test]
fn near_misses_keep_the_explicit_test() {
    // Another width, another trap, an `else`, another statement in the
    // arm, a condition combined with another, and two different operands.
    let mut b = Builder::new(0x9500, "near");
    let (int32, word) = (b.int(32), b.uint(64));
    let ints = b.ty(Type::Pointer(Some(int32)));
    let (data, number) = (b.param(ints), b.param(word));
    let other = b.local(word);
    b.f.returns = Some(word);
    let zero = b.c(64, 0);
    let clear = b.assign(other, zero);
    let pointer = |b: &mut Builder| b.read(data);
    let (address, again) = (pointer(&mut b), pointer(&mut b));
    let narrow = test(&mut b, address, 32, again, true);
    let width = guard(&mut b, narrow, Trap::Protection);
    let (address, again) = (pointer(&mut b), pointer(&mut b));
    let condition = test(&mut b, address, 48, again, true);
    let kind = guard(&mut b, condition, Trap::Divide);
    let (address, again) = (pointer(&mut b), pointer(&mut b));
    let condition = test(&mut b, address, 48, again, true);
    let trap = b.s(Stmt::Trap(Trap::Protection));
    let value = b.read(number);
    let set = b.assign(other, value);
    let otherwise = b.s(Stmt::If {
        condition,
        then: vec![trap],
        otherwise: vec![set],
    });
    let (address, again) = (pointer(&mut b), pointer(&mut b));
    let condition = test(&mut b, address, 48, again, false);
    let value = b.read(number);
    let set = b.assign(other, value);
    let trap = b.s(Stmt::Trap(Trap::Stack));
    let more = b.when(condition, vec![set, trap]);
    let (address, again) = (pointer(&mut b), pointer(&mut b));
    let condition = test(&mut b, address, 48, again, true);
    let (value, zero) = (b.read(number), b.c(64, 0));
    let nonzero = b.bin(Binary::Ne, value, zero);
    let both = b.e(Expr::Logical(Logical::And, nonzero, condition));
    let merged = guard(&mut b, both, Trap::Protection);
    let (address, value) = (pointer(&mut b), b.read(number));
    let condition = test(&mut b, address, 48, value, true);
    let operands = guard(&mut b, condition, Trap::Protection);
    let result = b.read(other);
    let ret = b.ret(result);
    let f = b.done(vec![
        clear, width, kind, otherwise, more, merged, operands, ret,
    ]);
    let (text, _) = print(&f, &Style::kr());
    assert!(!text.contains("binbun_check_canonical"), "{text}");
    assert_eq!(text.matches("binbun_trap(").count(), 6, "{text}");
    assert_eq!(text.matches("sext_n(").count(), 5, "{text}");
    let scratch = Scratch::new("near");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}
