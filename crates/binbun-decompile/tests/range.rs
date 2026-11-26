#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Counted loops ([`Ranges`]), rotated loops as `for` (the `loops` pass,
//! rule 4), the guard of an inverted `for` with its counter's start
//! (rule 1) and first tests a guard decides through the code after it
//! (rule 5), counters held narrow (rule 6), the code both arms of an `if`
//! share (`common-arms`), comparison chains as
//! `switch` (`switches`), and values whose signedness is free (`signs`) on
//! hand-built L2, with locals typed by the signedness their reads ask for
//! (`local-signs`): where each applies (a bound zero-extended included), and
//! where it must refuse (the bound written in the loop, a step that may
//! pass a `!=` bound, a guard that does not prove the first test, a
//! sign-extended bound of unknown sign, a range that does not fit the
//! signed reading, a write between a guard and its loop, two cases or a
//! value tested twice, a guard other than the first test, a start read
//! after the loop, a counter written in its loop, a shared statement
//! writing what the condition reads or a call or store ahead of the
//! condition's loads, arms that leave). Every rewrite is run against the
//! function before it in the L2 interpreter.

use std::mem;

use binbun_ast::interpret::{Outcome, run};
use binbun_ast::ir::{
    Call, Callee, Expr, ExprId, Function, Origin, Place, Stmt, StmtId, VarId, VarKind, Variable,
};
use binbun_ast::types::{Evidence, Signature, Type, Types};
use binbun_decompile::itanium::NONE;
use binbun_decompile::pass::{self, L2Env};
use binbun_decompile::range::{Ranges, Refused};
use binbun_decompile::simplify::signs::{LocalSigns, Signs};
use binbun_decompile::structure::{CommonArms, Conditions, Loops, Rotated, Switches};
use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Fuel, Manager, Pass};
use binbun_semantics::interpret::{Fault, Machine, Value};
use binbun_semantics::ir::{Binary, RegisterId, Unary};
use binbun_ssa::ir::BlockId;

const DECLARATIONS: Declarations = Declarations {
    registers: &[],
    intrinsics: &[],
    sites: &[],
};

/// No registers, and memory that faults everywhere: the functions here
/// compute on variables only.
struct Nothing;

impl Machine for Nothing {
    fn read(&mut self, _: RegisterId) -> Value {
        unreachable!("L2 holds registers in variables")
    }

    fn write(&mut self, _: RegisterId, _: Value) {
        unreachable!("L2 holds registers in variables")
    }

    fn load(&mut self, address: u64, _: u16) -> Result<Value, Fault> {
        Err(Fault {
            address,
            write: false,
        })
    }

    fn store(&mut self, address: u64, _: Value) -> Result<(), Fault> {
        Err(Fault {
            address,
            write: true,
        })
    }
}

struct Builder {
    f: Function,
    /// The block the next statement stands for.
    block: u32,
}

impl Builder {
    fn new() -> Self {
        Self {
            f: Function::new(0x1000, Types::new(64)),
            block: 0,
        }
    }

    /// A parameter of 32 bits, declared `int32_t`.
    fn param(&mut self) -> VarId {
        let ty = self.f.types.intern(Type::Int(32));
        let id = self.f.add_var(Variable {
            kind: VarKind::Parameter,
            name: None,
            ty,
            evidence: Evidence::Declared,
            origins: Vec::new(),
        });
        self.f.parameters.push(id);
        id
    }

    fn local(&mut self) -> VarId {
        let ty = self.f.types.intern(Type::Bits(32));
        self.f.add_var(Variable {
            kind: VarKind::Local,
            name: None,
            ty,
            evidence: Evidence::Default,
            origins: Vec::new(),
        })
    }

    fn c(&mut self, value: u64) -> ExprId {
        self.f.add_expr(Expr::Const(Bits::from_u64(32, value)))
    }

    fn read(&mut self, var: VarId) -> ExprId {
        self.f.add_expr(Expr::Var(var))
    }

    /// `op(var, constant)`.
    fn vc(&mut self, op: Binary, var: VarId, value: u64) -> ExprId {
        let (a, b) = (self.read(var), self.c(value));
        self.f.add_expr(Expr::Binary(op, a, b))
    }

    /// `op(a, b)` of two variables.
    fn vv(&mut self, op: Binary, a: VarId, b: VarId) -> ExprId {
        let (a, b) = (self.read(a), self.read(b));
        self.f.add_expr(Expr::Binary(op, a, b))
    }

    /// A statement of a new block.
    fn stmt(&mut self, stmt: Stmt) -> StmtId {
        self.block += 1;
        self.stmt_here(stmt)
    }

    /// A statement of the current block.
    fn stmt_here(&mut self, stmt: Stmt) -> StmtId {
        let id = self.f.add_stmt(stmt);
        self.f
            .provenance
            .set_stmt(id, &[Origin::Block(BlockId(self.block))]);
        id
    }

    fn assign(&mut self, var: VarId, value: ExprId) -> StmtId {
        self.stmt_here(Stmt::Assign {
            place: Place::Var(var),
            value,
        })
    }

    /// `var = var + delta` (two's complement).
    fn step(&mut self, var: VarId, delta: i32) -> StmtId {
        let sum = self.vc(Binary::Add, var, u64::from(delta.cast_unsigned()));
        self.assign(var, sum)
    }

    fn ret(&mut self, value: ExprId) -> StmtId {
        let ty = self.f.types.intern(Type::Bits(32));
        self.f.returns = Some(ty);
        self.stmt(Stmt::Return(Some(value)))
    }

    /// `do { s = s + i % 7; <extra>; i = i + delta } while (latch)`,
    /// blocks of its own: the loop.
    fn summing(
        &mut self,
        s: VarId,
        i: VarId,
        delta: i32,
        extra: Vec<StmtId>,
        latch: ExprId,
    ) -> StmtId {
        self.block += 1;
        let remainder = self.vc(Binary::URem, i, 7);
        let rs = self.read(s);
        let sum = self.f.add_expr(Expr::Binary(Binary::Add, rs, remainder));
        let mut body = vec![self.assign(s, sum)];
        body.extend(extra);
        body.push(self.step(i, delta));
        self.stmt(Stmt::DoWhile {
            body,
            condition: latch,
        })
    }

    /// Runs `passes` (the verifier after each change): the manager.
    fn run(
        &mut self,
        passes: &mut [&mut dyn Pass<Function, L2Env<'static>>],
    ) -> Manager<Function, L2Env<'static>> {
        let env = L2Env {
            declarations: &DECLARATIONS,
            exceptions: &NONE,
            feeds: None,
        };
        let mut manager = Manager::new(Fuel::new(u64::MAX)).with_verifier(pass::verify);
        for pass in passes {
            manager.run(&mut **pass, &mut self.f, &env).unwrap();
        }
        manager
    }

    /// The loop rules: what became of the `do`-`while`s.
    fn loops(&mut self) -> Vec<(Rotated, usize)> {
        let mut loops = Loops::default();
        self.run(&mut [&mut loops]);
        loops.rotated().iter().map(|(&k, &v)| (k, v)).collect()
    }
}

/// The parameter values every function here is run with.
const ARGUMENTS: [i32; 12] = [i32::MIN, -100, -7, -1, 0, 1, 2, 3, 7, 40, 41, 100];

/// What `function` does with each of [`ARGUMENTS`].
fn outcomes(function: &Function) -> Vec<Outcome> {
    ARGUMENTS
        .iter()
        .map(|&n| {
            let argument = Value::defined(Bits::from_u64(32, u64::from(n.cast_unsigned())));
            run(function, &mut Nothing, &[argument], 0x800, 100_000)
        })
        .collect()
}

/// `if (guard) return 0; [i = start;] s = 0; do { s += i % 7; i += delta; }
/// while (latch(i, n)); return s;` — the loop of the fixture's
/// `loop_sum` with a guard, a start, a step and a latch of the caller's.
fn rotated(
    guard: impl FnOnce(&mut Builder, VarId) -> ExprId,
    start: Option<u64>,
    delta: i32,
    latch: impl FnOnce(&mut Builder, VarId, VarId) -> ExprId,
) -> (Builder, StmtId) {
    let mut b = Builder::new();
    let n = b.param();
    let (i, s) = (b.local(), b.local());
    let guard = guard(&mut b, n);
    let zero = b.c(0);
    let early = b.ret(zero);
    let test = b.stmt(Stmt::If {
        condition: guard,
        then: vec![early],
        otherwise: Vec::new(),
    });
    b.block += 1;
    let mut body = vec![test];
    if let Some(start) = start {
        let start = b.c(start);
        body.push(b.assign(i, start));
    } else {
        let rn = b.read(n);
        body.push(b.assign(i, rn));
    }
    let zero = b.c(0);
    body.push(b.assign(s, zero));
    let latch = latch(&mut b, i, n);
    let lp = b.summing(s, i, delta, Vec::new(), latch);
    body.push(lp);
    let rs = b.read(s);
    body.push(b.ret(rs));
    b.f.body = body;
    (b, lp)
}

/// `i != n`.
fn not_equal(b: &mut Builder, i: VarId, n: VarId) -> ExprId {
    b.vv(Binary::Ne, i, n)
}

/// `n <= 0` (signed).
fn not_positive(b: &mut Builder, n: VarId) -> ExprId {
    b.vc(Binary::SLe, n, 0)
}

/// Runs the loop rules, then signs, checking each against the
/// interpreter: what became of the `do`-`while`s.
fn rewrite(b: &mut Builder) -> Vec<(Rotated, usize)> {
    let before = outcomes(&b.f);
    let rotated = b.loops();
    assert_eq!(
        outcomes(&b.f),
        before,
        "the loop rules changed what it does"
    );
    b.run(&mut [&mut Signs]);
    assert_eq!(outcomes(&b.f), before, "signs changed what it does");
    rotated
}

/// The `for` loop `id` is: its init, condition and step.
fn for_parts(b: &Builder, id: StmtId) -> (Vec<StmtId>, ExprId, Vec<StmtId>) {
    let Some(Stmt::For {
        init,
        condition,
        step,
        ..
    }) = b.f.stmt(id)
    else {
        panic!("not a for: {:?}", b.f.stmt(id));
    };
    (init.clone(), *condition, step.clone())
}

/// The operation of binary expression `id`.
fn op(b: &Builder, id: ExprId) -> Binary {
    let Some(&Expr::Binary(op, ..)) = b.f.expr(id) else {
        panic!("not binary: {:?}", b.f.expr(id));
    };
    op
}

/// The operations of the body's remainders.
fn remainders(b: &Builder) -> Vec<Binary> {
    let mut found = Vec::new();
    let mut work: Vec<StmtId> = b.f.body.clone();
    while let Some(id) = work.pop() {
        let stmt = b.f.stmt(id).unwrap();
        work.extend(stmt.blocks().flatten().copied());
        let mut exprs = stmt.roots();
        while let Some(e) = exprs.pop() {
            let expr = b.f.expr(e).unwrap();
            if let Expr::Binary(op @ (Binary::URem | Binary::SRem), ..) = *expr {
                found.push(op);
            }
            exprs.extend(expr.operands(&b.f));
        }
    }
    found
}

#[test]
fn loop_sums_rotated_loop_is_a_proved_for_with_a_signed_counter() {
    let (mut b, lp) = rotated(not_positive, Some(0), 1, not_equal);
    assert_eq!(rewrite(&mut b), [(Rotated::Proved, 1)]);
    let (init, condition, step) = for_parts(&b, lp);
    assert_eq!(init.len(), 1, "i = 0 went into the for");
    assert_eq!(step.len(), 1);
    assert_eq!(op(&b, condition), Binary::SLt);
    assert!(b.f.provenance.stmt(lp).contains(&Origin::Proved));
    // The guard stays: it has an exit of its own.
    assert!(matches!(b.f.stmt(b.f.body[0]), Some(Stmt::If { .. })));
    // `i` in [0, n) with 0 < n: its signedness is free; `bits(32)` prints
    // signed, so the remainder is signed.
    assert_eq!(remainders(&b), [Binary::SRem]);
}

#[test]
fn a_guard_that_is_the_first_test_becomes_the_for_test() {
    // i = 0; if (n != 0) do { … } while (i != n): unsigned, and `n != 0` is
    // `0 < n` unsigned, the first test.
    let mut b = Builder::new();
    let n = b.param();
    let (i, s) = (b.local(), b.local());
    let zero = b.c(0);
    let init = b.assign(i, zero);
    let zero = b.c(0);
    let clear = b.assign(s, zero);
    let latch = b.vv(Binary::Ne, i, n);
    let lp = b.summing(s, i, 1, Vec::new(), latch);
    let guard = b.vc(Binary::Ne, n, 0);
    let test = b.stmt(Stmt::If {
        condition: guard,
        then: vec![lp],
        otherwise: Vec::new(),
    });
    let rs = b.read(s);
    let ret = b.ret(rs);
    b.f.body = vec![init, clear, test, ret];
    assert_eq!(rewrite(&mut b), [(Rotated::Guarded, 1)]);
    assert_eq!(b.f.body.len(), 3, "the if went: {:?}", b.f.body);
    let (init, condition, _) = for_parts(&b, lp);
    assert_eq!(init.len(), 1);
    assert_eq!(op(&b, condition), Binary::ULt);
    let blocks = b.f.provenance.stmt(lp);
    assert_eq!(
        blocks.len(),
        2,
        "the guard's and the latch's blocks: {blocks:?}"
    );
    // `i` in [0, n) with n up to 2^32 - 1: not sign-free.
    assert_eq!(remainders(&b), [Binary::URem]);
}

/// `i = 0; if (n != 0) do { s = s + 1; i = i + 1; } while (i != ext(n))`,
/// `i` 64-bit, `n` zero or sign (`signed`) extended: the loop.
fn extended(signed: bool) -> (Builder, StmtId) {
    let mut b = Builder::new();
    let n = b.param();
    let wide = b.f.types.intern(Type::UInt(64));
    let i = b.f.add_var(Variable {
        kind: VarKind::Local,
        name: None,
        ty: wide,
        evidence: Evidence::Default,
        origins: Vec::new(),
    });
    let s = b.local();
    let zero = b.f.add_expr(Expr::Const(Bits::from_u64(64, 0)));
    let init = b.assign(i, zero);
    let zero = b.c(0);
    let clear = b.assign(s, zero);
    b.block += 1;
    let more = b.vc(Binary::Add, s, 1);
    let add = b.assign(s, more);
    let (ri, one) = (b.read(i), b.f.add_expr(Expr::Const(Bits::from_u64(64, 1))));
    let next = b.f.add_expr(Expr::Binary(Binary::Add, ri, one));
    let step = b.assign(i, next);
    let (ri, rn) = (b.read(i), b.read(n));
    let bound = b.f.add_expr(Expr::Extend {
        signed,
        value: rn,
        width: 64,
    });
    let latch = b.f.add_expr(Expr::Binary(Binary::Ne, ri, bound));
    let lp = b.stmt(Stmt::DoWhile {
        body: vec![add, step],
        condition: latch,
    });
    let guard = b.vc(Binary::Ne, n, 0);
    let test = b.stmt(Stmt::If {
        condition: guard,
        then: vec![lp],
        otherwise: Vec::new(),
    });
    let rs = b.read(s);
    let ret = b.ret(rs);
    b.f.body = vec![init, clear, test, ret];
    (b, lp)
}

#[test]
fn an_extended_bound_counts_and_its_guard_is_the_first_test() {
    // Zero-extended, the bound's values are `n`'s read unsigned, and `n !=
    // 0` is `0 < (uint64_t)n`, the first test.
    let (mut b, lp) = extended(false);
    assert_eq!(rewrite(&mut b), [(Rotated::Guarded, 1)]);
    assert_eq!(b.f.body.len(), 3, "the if went: {:?}", b.f.body);
    let (_, condition, _) = for_parts(&b, lp);
    assert_eq!(op(&b, condition), Binary::ULt);
}

#[test]
fn a_sign_extended_bound_of_unknown_sign_is_refused() {
    // Sign-extended, `n != 0` proves neither `0 < (uint64_t)(int64_t)n`
    // (`n = -1` is 2^64 - 1, `n = 1` is 1, `n = INT32_MIN` between) nor
    // `0 < (int64_t)n`.
    let (mut b, _) = extended(true);
    assert_eq!(rewrite(&mut b), [(Rotated::Left(Refused::Entry), 1)]);
}

#[test]
fn a_local_takes_the_signedness_more_of_its_reads_ask_for() {
    // more = n; tie = n; same = n;
    // if (more <u 10) return more /u 3;  one read unsigned (`more / 3U`
    //                                    is so)
    // if (more <=u 20) return 0;         another
    // if (more <s 5) return 1;           one signed
    // if (tie <u 7) return 2;
    // if (tie <s 9) return 3;            one each: a tie
    // if (same == more) return 4;        as `more`
    // return n <u 4 ? 5 : 6;             a parameter
    let mut b = Builder::new();
    let n = b.param();
    let (more, tie, same) = (b.local(), b.local(), b.local());
    let mut body = Vec::new();
    for var in [more, tie, same] {
        let rn = b.read(n);
        body.push(b.assign(var, rn));
    }
    let quotient = b.vc(Binary::UDiv, more, 3);
    let tests = [
        (b.vc(Binary::ULt, more, 10), quotient),
        (b.vc(Binary::ULe, more, 20), b.c(0)),
        (b.vc(Binary::SLt, more, 5), b.c(1)),
        (b.vc(Binary::ULt, tie, 7), b.c(2)),
        (b.vc(Binary::SLt, tie, 9), b.c(3)),
        (b.vv(Binary::Eq, same, more), b.c(4)),
    ];
    for (condition, value) in tests {
        let early = b.ret(value);
        body.push(b.stmt(Stmt::If {
            condition,
            then: vec![early],
            otherwise: Vec::new(),
        }));
    }
    let below = b.vc(Binary::ULt, n, 4);
    let (five, six) = (b.c(5), b.c(6));
    let choice = b.f.add_expr(Expr::Select {
        condition: below,
        then: five,
        otherwise: six,
    });
    body.push(b.ret(choice));
    b.f.body = body;
    let before = outcomes(&b.f);
    b.run(&mut [&mut LocalSigns]);
    assert_eq!(outcomes(&b.f), before, "local-signs changed what it does");
    let ty = |var: VarId| b.f.types.get(b.f.var(var).unwrap().ty).cloned();
    assert_eq!(ty(more), Some(Type::UInt(32)));
    assert_eq!(ty(tie), Some(Type::Bits(32)), "a tie keeps the type");
    assert_eq!(
        ty(same),
        Some(Type::UInt(32)),
        "compared with `more`, as it"
    );
    assert_eq!(ty(n), Some(Type::Int(32)), "a parameter keeps its type");
}

#[test]
fn an_exact_larger_step_counts_to_a_constant() {
    // i = 0; do { … i += 4; } while (i != 40), no guard: proved.
    let (mut b, lp) = rotated(not_positive, Some(0), 4, |b, i, _| b.vc(Binary::Ne, i, 40));
    assert_eq!(rewrite(&mut b), [(Rotated::Proved, 1)]);
    let (_, condition, _) = for_parts(&b, lp);
    assert_eq!(op(&b, condition), Binary::SLt);
    assert_eq!(remainders(&b), [Binary::SRem]);
}

#[test]
fn counting_down_to_zero_is_a_for() {
    // if (n <= 0) return 0; i = n; do { … i -= 1; } while (i != 0).
    let (mut b, lp) = rotated(not_positive, None, -1, |b, i, _| b.vc(Binary::Ne, i, 0));
    assert_eq!(rewrite(&mut b), [(Rotated::Proved, 1)]);
    let (init, condition, _) = for_parts(&b, lp);
    assert_eq!(init.len(), 1, "i = n went into the for");
    assert_eq!(op(&b, condition), Binary::SLt);
    // i in [1, n]: sign-free.
    assert_eq!(remainders(&b), [Binary::SRem]);

    // if (n == 0) return 0; i = n; …: i in [1, 2^32 - 1] unsigned, not
    // sign-free: a for, but `i != 0` stays (no claim `0 < i` would add).
    let (mut b, lp) = rotated(
        |b, n| b.vc(Binary::Eq, n, 0),
        None,
        -1,
        |b, i, _| b.vc(Binary::Ne, i, 0),
    );
    assert_eq!(rewrite(&mut b), [(Rotated::Proved, 1)]);
    let (_, condition, _) = for_parts(&b, lp);
    assert_eq!(op(&b, condition), Binary::Ne);
    assert_eq!(remainders(&b), [Binary::URem]);
}

#[test]
fn a_step_that_may_pass_the_bound_is_refused() {
    // i += 2 towards a variable bound with `!=`: it may step over it.
    let (mut b, lp) = rotated(not_positive, Some(0), 2, not_equal);
    assert_eq!(rewrite(&mut b), [(Rotated::Left(Refused::Entry), 1)]);
    assert!(matches!(b.f.stmt(lp), Some(Stmt::DoWhile { .. })));
    // i += 4 towards 42: never equal.
    let (mut b, lp) = rotated(not_positive, Some(0), 4, |b, i, _| b.vc(Binary::Ne, i, 42));
    assert_eq!(rewrite(&mut b), [(Rotated::Left(Refused::Entry), 1)]);
    assert!(matches!(b.f.stmt(lp), Some(Stmt::DoWhile { .. })));
    assert_eq!(remainders(&b), [Binary::URem]);
}

#[test]
fn a_guard_that_does_not_prove_the_first_test_is_refused() {
    // if (n == 3) return 0; … while (i != n): n may be 0 or negative.
    let (mut b, lp) = rotated(|b, n| b.vc(Binary::Eq, n, 3), Some(0), 1, not_equal);
    assert_eq!(rewrite(&mut b), [(Rotated::Left(Refused::Entry), 1)]);
    assert!(matches!(b.f.stmt(lp), Some(Stmt::DoWhile { .. })));
    assert_eq!(remainders(&b), [Binary::URem]);
    // if (n <= 0) return 0; i = 5; … while (i != n): 5 < n is not proved.
    let (mut b, lp) = rotated(not_positive, Some(5), 1, not_equal);
    assert_eq!(rewrite(&mut b), [(Rotated::Left(Refused::Entry), 1)]);
    assert!(matches!(b.f.stmt(lp), Some(Stmt::DoWhile { .. })));
}

#[test]
fn the_bound_or_counter_written_in_the_loop_is_refused() {
    for (target, refused) in [(0usize, Refused::Bound), (1, Refused::Counter)] {
        let mut b = Builder::new();
        let n = b.param();
        let (i, s) = (b.local(), b.local());
        let guard = not_positive(&mut b, n);
        let zero = b.c(0);
        let early = b.ret(zero);
        let test = b.stmt(Stmt::If {
            condition: guard,
            then: vec![early],
            otherwise: Vec::new(),
        });
        b.block += 1;
        let zero = b.c(0);
        let init = b.assign(i, zero);
        let zero = b.c(0);
        let clear = b.assign(s, zero);
        let written = [n, i][target];
        let extra = b.step(written, 3);
        let latch = not_equal(&mut b, i, n);
        let lp = b.summing(s, i, 1, vec![extra], latch);
        let rs = b.read(s);
        let ret = b.ret(rs);
        b.f.body = vec![test, init, clear, lp, ret];
        assert_eq!(rewrite(&mut b), [(Rotated::Left(refused), 1)]);
        assert!(matches!(b.f.stmt(lp), Some(Stmt::DoWhile { .. })));
        assert_eq!(remainders(&b), [Binary::URem]);
    }
}

#[test]
fn a_range_past_the_signed_maximum_keeps_the_unsigned_reading() {
    // if (n <= 0) return 0; i = 0; do { … } while (i <=s n): counted, but
    // the last step may write n + 1 = 2^31: no range.
    let (mut b, lp) = rotated(not_positive, Some(0), 1, |b, i, n| b.vv(Binary::SLe, i, n));
    let ranges = Ranges::of(&b.f);
    let counted = ranges.counted(lp).unwrap();
    assert_eq!(counted.range, None);
    assert!(!counted.counter_free);
    assert_eq!(rewrite(&mut b), [(Rotated::Proved, 1)]);
    // The remainder stays unsigned (`i` is not proved within the signed
    // maximum; the printer casts it for the remainder).
    assert_eq!(remainders(&b), [Binary::URem]);
}

#[test]
fn a_bound_written_before_the_loop_voids_the_guard() {
    // if (n <= 0) return 0; n = n - 5; i = 0; do … while (i != n): the guard
    // is about the old n.
    let mut b = Builder::new();
    let n = b.param();
    let (i, s) = (b.local(), b.local());
    let guard = not_positive(&mut b, n);
    let zero = b.c(0);
    let early = b.ret(zero);
    let test = b.stmt(Stmt::If {
        condition: guard,
        then: vec![early],
        otherwise: Vec::new(),
    });
    b.block += 1;
    let shrink = b.step(n, -5);
    let zero = b.c(0);
    let init = b.assign(i, zero);
    let zero = b.c(0);
    let clear = b.assign(s, zero);
    let latch = not_equal(&mut b, i, n);
    let lp = b.summing(s, i, 1, Vec::new(), latch);
    let rs = b.read(s);
    let ret = b.ret(rs);
    b.f.body = vec![test, shrink, init, clear, lp, ret];
    assert_eq!(rewrite(&mut b), [(Rotated::Left(Refused::Entry), 1)]);
}

/// `if (n == 0) return 0; s = 0; [n = n + 1;]`
/// `do { s = s + n % 7; n = n >> 1; } while (n != 0); return s;`: a loop
/// no counter counts.
fn halving(write_between: bool) -> (Builder, StmtId) {
    let mut b = Builder::new();
    let n = b.param();
    let s = b.local();
    let guard = b.vc(Binary::Eq, n, 0);
    let zero = b.c(0);
    let early = b.ret(zero);
    let test = b.stmt(Stmt::If {
        condition: guard,
        then: vec![early],
        otherwise: Vec::new(),
    });
    b.block += 1;
    let zero = b.c(0);
    let mut body = vec![test, b.assign(s, zero)];
    if write_between {
        body.push(b.step(n, 1));
    }
    b.block += 1;
    let remainder = b.vc(Binary::URem, n, 7);
    let rs = b.read(s);
    let sum = b.f.add_expr(Expr::Binary(Binary::Add, rs, remainder));
    let add = b.assign(s, sum);
    let half = b.vc(Binary::LShr, n, 1);
    let shift = b.assign(n, half);
    let latch = b.vc(Binary::Ne, n, 0);
    let lp = b.stmt(Stmt::DoWhile {
        body: vec![add, shift],
        condition: latch,
    });
    body.push(lp);
    let rs = b.read(s);
    body.push(b.ret(rs));
    b.f.body = body;
    (b, lp)
}

#[test]
fn a_guard_deciding_the_first_test_makes_a_while_then_a_for() {
    let (mut b, lp) = halving(false);
    assert_eq!(rewrite(&mut b), [(Rotated::Implied, 1)]);
    let (init, _, step) = for_parts(&b, lp);
    assert_eq!(init, []);
    assert_eq!(step.len(), 1);
    assert!(b.f.provenance.stmt(lp).contains(&Origin::Proved));
}

#[test]
fn a_write_between_guard_and_loop_keeps_the_do() {
    let (mut b, lp) = halving(true);
    assert!(
        rewrite(&mut b)
            .iter()
            .all(|&(rotated, _)| rotated != Rotated::Implied)
    );
    assert!(matches!(b.f.stmt(lp), Some(Stmt::DoWhile { .. })));
}

/// `if (n == a) return 10a; …` for each of `values`, each test a block of
/// its own, then `return 0`: the run of exits; with `nested`, a chain of
/// `else`s ending in `return 0` instead.
fn cases(values: &[u64], nested: bool) -> Builder {
    let mut b = Builder::new();
    let n = b.param();
    let zero = b.c(0);
    let mut rest = vec![b.ret(zero)];
    let mut run = Vec::new();
    for &value in values.iter().rev() {
        let result = b.c(value * 10);
        let exit = b.ret(result);
        let test = b.vc(Binary::Eq, n, value);
        let otherwise = if nested {
            mem::take(&mut rest)
        } else {
            Vec::new()
        };
        let id = b.stmt(Stmt::If {
            condition: test,
            then: vec![exit],
            otherwise,
        });
        if nested {
            rest = vec![id];
        } else {
            run.insert(0, id);
        }
    }
    run.extend(rest);
    b.f.body = run;
    b
}

#[test]
fn comparison_chains_on_one_value_are_switches() {
    for nested in [false, true] {
        let mut b = cases(&[1, 2, 7], nested);
        let before = outcomes(&b.f);
        b.run(&mut [&mut Switches]);
        assert_eq!(outcomes(&b.f), before, "switches changed what it does");
        let first = b.f.body[0];
        let Some(Stmt::Switch { arms, .. }) = b.f.stmt(first) else {
            panic!("not a switch: {:?}", b.f.stmt(first));
        };
        let values: Vec<u64> = arms
            .iter()
            .flat_map(|arm| arm.values.iter().map(Bits::low_u64))
            .collect();
        assert_eq!(values, [1, 2, 7]);
        assert_eq!(arms.iter().any(|arm| arm.default), nested);
        let blocks =
            b.f.provenance
                .stmt(first)
                .iter()
                .filter(|origin| matches!(origin, Origin::Block(_)))
                .count();
        assert_eq!(blocks, 3, "one block per value");
    }
    // Two cases, or a value tested twice, stay `if`s.
    for values in [&[1, 2][..], &[1, 2, 1]] {
        let mut b = cases(values, false);
        b.run(&mut [&mut Switches]);
        assert!(
            b.f.body
                .iter()
                .all(|&id| !matches!(b.f.stmt(id), Some(Stmt::Switch { .. })))
        );
    }
}

/// The values of the `switch` that is `id`, in order, and whether it has
/// a `default`.
fn switch_values(f: &Function, id: StmtId) -> (Vec<u64>, bool) {
    let Some(Stmt::Switch { arms, .. }) = f.stmt(id) else {
        panic!("not a switch: {:?}", f.stmt(id));
    };
    let values = arms
        .iter()
        .flat_map(|arm| arm.values.iter().map(Bits::low_u64))
        .collect();
    (values, arms.iter().any(|arm| arm.default))
}

/// A chain of five `else`s is one `switch` from its first test, not two
/// `if`s around a `switch` of its last three cases.
#[test]
fn a_chain_is_one_switch_from_its_first_test() {
    let mut b = cases(&[1, 2, 7, 9, 12], true);
    let before = outcomes(&b.f);
    b.run(&mut [&mut Switches]);
    assert_eq!(outcomes(&b.f), before, "switches changed what it does");
    assert_eq!(
        switch_values(&b.f, b.f.body[0]),
        (vec![1, 2, 7, 9, 12], true)
    );
}

/// `if (n == 1) return 10; else if (n == 2) return 20; else { if (n != 7)
/// return 0; return 70; }`: the last test is the chain's third case the
/// other way round, `case 7: return 70; default: return 0;`.
#[test]
fn a_chain_ending_in_an_inequality_takes_it_as_its_last_case() {
    let mut b = Builder::new();
    let n = b.param();
    let seventy = b.c(70);
    let last = b.ret(seventy);
    let zero = b.c(0);
    let none = b.ret(zero);
    let differs = b.vc(Binary::Ne, n, 7);
    let test = b.stmt(Stmt::If {
        condition: differs,
        then: vec![none],
        otherwise: Vec::new(),
    });
    let mut rest = vec![test, last];
    for value in [2, 1] {
        let result = b.c(value * 10);
        let exit = b.ret(result);
        let equal = b.vc(Binary::Eq, n, value);
        let id = b.stmt(Stmt::If {
            condition: equal,
            then: vec![exit],
            otherwise: mem::take(&mut rest),
        });
        rest = vec![id];
    }
    b.f.body = rest;
    let before = outcomes(&b.f);
    b.run(&mut [&mut Switches]);
    assert_eq!(outcomes(&b.f), before, "switches changed what it does");
    assert_eq!(switch_values(&b.f, b.f.body[0]), (vec![1, 2, 7], true));
}

/// `do { [if (n == 0) continue;] s = n; } while (s != 0)`, the
/// assignment of no block (as `common-arms` leaves what it moves): it
/// goes into the test, but not where a `continue` reaches the test
/// without it.
#[test]
fn an_assignment_a_continue_skips_stays_out_of_the_test() {
    for skips in [false, true] {
        let mut b = Builder::new();
        let n = b.param();
        let s = b.local();
        let lp = b.stmt(Stmt::Unreachable);
        let mut body = Vec::new();
        if skips {
            let none = b.vc(Binary::Eq, n, 0);
            let skip = b.stmt_here(Stmt::Continue(lp));
            body.push(b.stmt(Stmt::If {
                condition: none,
                then: vec![skip],
                otherwise: Vec::new(),
            }));
        }
        let value = b.read(n);
        let moved = b.f.add_stmt(Stmt::Assign {
            place: Place::Var(s),
            value,
        });
        body.push(moved);
        let condition = b.vc(Binary::Ne, s, 0);
        b.f.stmts[lp.0 as usize] = Stmt::DoWhile { body, condition };
        let result = b.read(s);
        let exit = b.ret(result);
        b.f.body = vec![lp, exit];
        b.run(&mut [&mut Conditions]);
        let Some(Stmt::DoWhile { body, .. }) = b.f.stmt(lp) else {
            panic!("not a do-while: {:?}", b.f.stmt(lp));
        };
        assert_eq!(body.contains(&moved), skips, "skips: {skips}");
    }
}

impl Builder {
    /// A local of 64 bits, untyped.
    fn wide_local(&mut self) -> VarId {
        let ty = self.f.types.intern(Type::Bits(64));
        self.f.add_var(Variable {
            kind: VarKind::Local,
            name: None,
            ty,
            evidence: Evidence::Default,
            origins: Vec::new(),
        })
    }

    /// `!(n <= k)` (signed).
    fn above(&mut self, n: VarId, k: u64) -> ExprId {
        let at_most = self.vc(Binary::SLe, n, k);
        self.f.add_expr(Expr::Unary(Unary::Not, at_most))
    }
}

/// `s = 0; if (guard(n)) { i = 0; do { s = s + 3; [i = i + 0;] i = i +
/// 1; } while ((int32_t)i < n); } return s [+ (int32_t)i];`, `i` of 64
/// bits (`get_directory_stack`'s inverted `for`), each part a block of its
/// own (the `if` its decision's, the loop its latch's): the `if`, the
/// start and the loop.
fn inverted(
    guard: impl FnOnce(&mut Builder, VarId) -> ExprId,
    written: bool,
    read_after: bool,
) -> (Builder, [StmtId; 3]) {
    let mut b = Builder::new();
    let n = b.param();
    let s = b.local();
    let i = b.wide_local();
    let zero = b.c(0);
    let clear = b.stmt(Stmt::Assign {
        place: Place::Var(s),
        value: zero,
    });
    let guard = guard(&mut b, n);
    b.block += 1;
    let decision = b.block;
    b.block += 1;
    let start = b.f.add_expr(Expr::Const(Bits::from_u64(64, 0)));
    let init = b.assign(i, start);
    b.block += 1;
    let add = b.vc(Binary::Add, s, 3);
    let mut body = vec![b.assign(s, add)];
    let ri = b.read(i);
    if written {
        let nothing = b.f.add_expr(Expr::Const(Bits::from_u64(64, 0)));
        let same = b.f.add_expr(Expr::Binary(Binary::Add, ri, nothing));
        body.push(b.assign(i, same));
    }
    let ri = b.read(i);
    let one = b.f.add_expr(Expr::Const(Bits::from_u64(64, 1)));
    let next = b.f.add_expr(Expr::Binary(Binary::Add, ri, one));
    body.push(b.assign(i, next));
    let ri = b.read(i);
    let low = b.f.add_expr(Expr::Extract {
        value: ri,
        offset: 0,
        width: 32,
    });
    let rn = b.read(n);
    let latch = b.f.add_expr(Expr::Binary(Binary::SLt, low, rn));
    let lp = b.stmt_here(Stmt::DoWhile {
        body,
        condition: latch,
    });
    let test = b.f.add_stmt(Stmt::If {
        condition: guard,
        then: vec![init, lp],
        otherwise: Vec::new(),
    });
    b.f.provenance
        .set_stmt(test, &[Origin::Block(BlockId(decision))]);
    let mut result = b.read(s);
    if read_after {
        let ri = b.read(i);
        let low = b.f.add_expr(Expr::Extract {
            value: ri,
            offset: 0,
            width: 32,
        });
        result = b.f.add_expr(Expr::Binary(Binary::Add, result, low));
    }
    let ret = b.ret(result);
    b.f.body = vec![clear, test, ret];
    (b, [test, init, lp])
}

/// Whether `id` is a read of a variable of type `int32_t`.
fn int32_read(b: &Builder, id: ExprId) -> bool {
    let Some(&Expr::Var(var)) = b.f.expr(id) else {
        return false;
    };
    b.f.types.get(b.f.var(var).unwrap().ty) == Some(&Type::Int(32))
}

#[test]
fn an_inverted_for_s_guard_and_start_become_its_for() {
    // if (!(n <= 0)) { i = 0; do { … } while ((int32_t)i < n); }: the guard
    // is the test of i = 0.
    let (mut b, [test, init, lp]) = inverted(|b, n| b.above(n, 0), false, false);
    assert_eq!(rewrite(&mut b), [(Rotated::Inverted, 1)]);
    assert!(b.f.body.iter().all(|&id| id != test), "the if went");
    assert_eq!(b.f.body.len(), 3, "s = 0, the for, the return");
    let (inits, condition, step) = for_parts(&b, lp);
    assert_eq!(inits, [init]);
    assert_eq!(step.len(), 1);
    assert_eq!(
        b.f.provenance.stmt(lp),
        &[Origin::Block(BlockId(2)), Origin::Block(BlockId(4))],
        "the guard's decision first, then the latch's"
    );
    assert!(
        b.f.provenance
            .stmt(init)
            .iter()
            .all(|origin| !matches!(origin, Origin::Block(_))),
        "the start names no block"
    );
    // Rule 6: `i` counts from 0 while `(int32_t)i < n`: an `int32_t`.
    let Some(&Expr::Binary(Binary::SLt, counter, _)) = b.f.expr(condition) else {
        panic!("{:?}", b.f.expr(condition));
    };
    assert!(int32_read(&b, counter), "{:?}", b.f.expr(counter));
}

#[test]
fn a_guard_other_than_the_first_test_or_a_start_read_after_keeps_the_if() {
    // if (!(n <= 1)) { i = 0; do … while ((int32_t)i < n); }: 1 < n is not
    // the test of i = 0.
    let (mut b, [test, ..]) = inverted(|b, n| b.above(n, 1), false, false);
    let rotated = rewrite(&mut b);
    assert!(
        rotated.iter().all(|&(r, _)| r != Rotated::Inverted),
        "{rotated:?}"
    );
    assert_eq!(b.f.body[1], test);
    // `i` read after the `if`: where the guard fails it is not 0.
    let (mut b, [test, ..]) = inverted(|b, n| b.above(n, 0), false, true);
    let rotated = rewrite(&mut b);
    assert!(
        rotated.iter().all(|&(r, _)| r != Rotated::Inverted),
        "{rotated:?}"
    );
    assert_eq!(b.f.body[1], test);
}

#[test]
fn a_counter_written_in_its_loop_stays_wide() {
    let (mut b, [.., lp]) = inverted(|b, n| b.above(n, 0), true, false);
    assert_eq!(rewrite(&mut b), [(Rotated::Inverted, 1)]);
    let (_, condition, _) = for_parts(&b, lp);
    let Some(&Expr::Binary(Binary::SLt, counter, _)) = b.f.expr(condition) else {
        panic!("{:?}", b.f.expr(condition));
    };
    assert!(matches!(b.f.expr(counter), Some(Expr::Extract { .. })));
}

/// `if (n <= 0) return 0; i = start; s = 0; do { s = s + 3; n = n - 1; i
/// = i + 1; } while (i < n); return s;`: a loop no counter counts (its
/// bound changes), whose first test the guard decides through `i = 0`.
fn shrinking(start: u64) -> (Builder, StmtId) {
    let mut b = Builder::new();
    let n = b.param();
    let (i, s) = (b.local(), b.local());
    let guard = not_positive(&mut b, n);
    let zero = b.c(0);
    let early = b.ret(zero);
    let test = b.stmt(Stmt::If {
        condition: guard,
        then: vec![early],
        otherwise: Vec::new(),
    });
    b.block += 1;
    let start = b.c(start);
    let init = b.assign(i, start);
    let zero = b.c(0);
    let clear = b.assign(s, zero);
    b.block += 1;
    let add = b.vc(Binary::Add, s, 3);
    let body = vec![b.assign(s, add), b.step(n, -1), b.step(i, 1)];
    let latch = b.vv(Binary::SLt, i, n);
    let lp = b.stmt_here(Stmt::DoWhile {
        body,
        condition: latch,
    });
    let rs = b.read(s);
    let ret = b.ret(rs);
    b.f.body = vec![test, init, clear, lp, ret];
    (b, lp)
}

#[test]
fn a_guard_decides_the_first_test_through_the_counter_s_start() {
    let (mut b, lp) = shrinking(0);
    assert_eq!(rewrite(&mut b), [(Rotated::Implied, 1)]);
    let (inits, _, _) = for_parts(&b, lp);
    assert_eq!(inits.len(), 1, "i = 0 went into the for");
    assert!(b.f.provenance.stmt(lp).contains(&Origin::Proved));
    // From 1, the first test is 1 < n: the guard does not decide it.
    let (mut b, lp) = shrinking(1);
    let rotated = rewrite(&mut b);
    assert!(
        rotated.iter().all(|&(r, _)| r != Rotated::Implied),
        "{rotated:?}"
    );
    assert!(matches!(b.f.stmt(lp), Some(Stmt::DoWhile { .. })));
}

/// `w = 9; s = 0; if (condition) { then } else { otherwise } return s +
/// w;` with `n` the parameter, `s` and `w` locals, each arm's statements a
/// block of their own: the `if`.
fn arms(
    condition: impl FnOnce(&mut Builder, VarId) -> ExprId,
    then: impl FnOnce(&mut Builder, [VarId; 3]) -> Vec<StmtId>,
    otherwise: impl FnOnce(&mut Builder, [VarId; 3]) -> Vec<StmtId>,
) -> (Builder, StmtId) {
    let mut b = Builder::new();
    let n = b.param();
    let (s, w) = (b.local(), b.local());
    let nine = b.c(9);
    let set = b.stmt(Stmt::Assign {
        place: Place::Var(w),
        value: nine,
    });
    let zero = b.c(0);
    let clear = b.assign(s, zero);
    let condition = condition(&mut b, n);
    b.block += 1;
    let then = then(&mut b, [n, s, w]);
    b.block += 1;
    let otherwise = otherwise(&mut b, [n, s, w]);
    let test = b.stmt(Stmt::If {
        condition,
        then,
        otherwise,
    });
    let sum = b.vv(Binary::Add, s, w);
    let ret = b.ret(sum);
    b.f.body = vec![set, clear, test, ret];
    (b, test)
}

/// `var = value`.
fn put(b: &mut Builder, var: VarId, value: u64) -> StmtId {
    let value = b.c(value);
    b.assign(var, value)
}

/// `var = n + 1`.
fn successor(b: &mut Builder, var: VarId, n: VarId) -> StmtId {
    let value = b.vc(Binary::Add, n, 1);
    b.assign(var, value)
}

/// Runs `common-arms`, checking it against the interpreter if `run`:
/// whether it changed the function.
fn share(b: &mut Builder, run: bool) -> bool {
    let before = run.then(|| outcomes(&b.f));
    let manager = b.run(&mut [&mut CommonArms]);
    if let Some(before) = before {
        assert_eq!(outcomes(&b.f), before, "common-arms changed what it does");
    }
    manager.stats().any(|(_, stats)| stats.changed > 0)
}

/// The arms of `if` statement `id`.
fn arms_of(b: &Builder, id: StmtId) -> (Vec<StmtId>, Vec<StmtId>) {
    let Some(Stmt::If {
        then, otherwise, ..
    }) = b.f.stmt(id)
    else {
        panic!("not an if: {:?}", b.f.stmt(id));
    };
    (then.clone(), otherwise.clone())
}

#[test]
fn statements_both_arms_begin_or_end_with_go_before_or_after_the_if() {
    // if (n <= 0) w = 0; else { w = 0; s = n + 1; } -> w = 0; if (!(n <=
    // 0)) s = n + 1;
    let mut hoisted = None;
    let mut kept = None;
    let (mut b, test) = arms(
        not_positive,
        |b, [_, _, w]| {
            let id = put(b, w, 0);
            hoisted = Some(id);
            vec![id]
        },
        |b, [n, s, w]| {
            let id = successor(b, s, n);
            kept = Some(id);
            vec![put(b, w, 0), id]
        },
    );
    assert!(share(&mut b, true));
    let hoisted = hoisted.unwrap();
    assert_eq!(b.f.body[2..4], [hoisted, test]);
    assert_eq!(arms_of(&b, test), (vec![kept.unwrap()], Vec::new()));
    let Some(&Stmt::If { condition, .. }) = b.f.stmt(test) else {
        unreachable!()
    };
    assert!(matches!(
        b.f.expr(condition),
        Some(Expr::Unary(Unary::Not, _))
    ));
    assert!(
        b.f.provenance
            .stmt(hoisted)
            .iter()
            .all(|origin| !matches!(origin, Origin::Block(_))),
        "a shared statement names no block"
    );

    // if (n <= 0) { s = 1; w = 5; } else { s = 2; w = 5; } -> w = 5 after.
    let mut sunk = None;
    let (mut b, test) = arms(
        not_positive,
        |b, [_, s, w]| {
            let id = put(b, w, 5);
            sunk = Some(id);
            vec![put(b, s, 1), id]
        },
        |b, [_, s, w]| vec![put(b, s, 2), put(b, w, 5)],
    );
    assert!(share(&mut b, true));
    assert_eq!(b.f.body[2..4], [test, sunk.unwrap()]);
    let (then, otherwise) = arms_of(&b, test);
    assert_eq!((then.len(), otherwise.len()), (1, 1));
}

#[test]
fn shared_statements_stay_where_moving_them_changes_what_runs() {
    // Both arms begin with n = 3, which the condition reads.
    let (mut b, _) = arms(
        not_positive,
        |b, [n, s, _]| vec![put(b, n, 3), put(b, s, 1)],
        |b, [n, s, _]| vec![put(b, n, 3), put(b, s, 2)],
    );
    assert!(!share(&mut b, true));

    // Arms that leave: their returns, and what precedes them, do not go
    // after the `if`.
    let leave = |b: &mut Builder, [_, s, w]: [VarId; 3], value| {
        let rw = b.read(w);
        vec![put(b, s, value), put(b, w, 5), b.ret(rw)]
    };
    let (mut b, _) = arms(
        not_positive,
        |b, vars| leave(b, vars, 1),
        |b, vars| leave(b, vars, 2),
    );
    assert!(!share(&mut b, true));

    // A call, or a store, both arms begin with stays after a condition
    // that loads (a global): it could change what the condition reads.
    let global = |b: &mut Builder| {
        let ty = b.f.types.intern(Type::Int(32));
        b.f.add_var(Variable {
            kind: VarKind::Global(0x5000),
            name: None,
            ty,
            evidence: Evidence::Declared,
            origins: Vec::new(),
        })
    };
    let call = |b: &mut Builder, n: VarId| {
        let int = b.f.types.intern(Type::Bits(32));
        let signature = b.f.types.intern(Type::Code(Signature {
            parameters: vec![int],
            returns: None,
            variadic: false,
        }));
        let argument = b.read(n);
        b.stmt_here(Stmt::Call {
            results: Vec::new(),
            call: Call {
                callee: Callee::Address(0x2000),
                arguments: vec![argument],
                signature,
                variadic: Vec::new(),
            },
        })
    };
    let store = |b: &mut Builder, n: VarId| {
        let address = b.f.add_expr(Expr::Const(Bits::from_u64(64, 0x6000)));
        let ty = b.f.types.intern(Type::Bits(32));
        let value = b.read(n);
        b.stmt_here(Stmt::Assign {
            place: Place::Memory { address, ty },
            value,
        })
    };
    for effect in [call, store] {
        let mut g = None;
        let (mut b, test) = arms(
            |b, _| {
                let var = global(b);
                g = Some(var);
                b.vc(Binary::SLe, var, 0)
            },
            |b, [n, s, _]| vec![effect(b, n), put(b, s, 1)],
            |b, [n, s, _]| vec![effect(b, n), put(b, s, 2)],
        );
        assert!(!share(&mut b, false));
        assert_eq!(arms_of(&b, test).0.len(), 2);
        // On the parameter alone, it goes before the `if`.
        let (mut b, test) = arms(
            not_positive,
            |b, [n, s, _]| vec![effect(b, n), put(b, s, 1)],
            |b, [n, s, _]| vec![effect(b, n), put(b, s, 2)],
        );
        assert!(share(&mut b, false));
        assert_eq!(arms_of(&b, test).0.len(), 1);
    }
}
