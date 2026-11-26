#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Pointer loops as array loops (the `array-loops` pass, then the loop
//! rules) on hand-built L2: a pointer stepped through a constant table, or
//! to an end the program computes, becomes an index, `for (i = 0; i < n;
//! i++) … p[i]`; a pointer read after a loop that leaves only by its test
//! reads `p + d·n`; a matrix walked by a row pointer beside its loop's
//! counter and a column pointer stepped first (from a constant below the
//! row's end) is indexed by both counters, but not where a `break` follows
//! the leading step; a count
//! bounded by a dominating test or computed by a logical shift of a
//! difference (or an arithmetic one, proved non-negative) is exact; a
//! pointer counting down is indexed from its end. Loops the pass must
//! leave (an access across two elements, a count whose multiple may wrap:
//! unbounded, bounded too loosely, of unknown sign) stay pointer loops.
//! Every rewrite is run against the function before it in the L2
//! interpreter, on a table in memory.

use core::cmp::Ordering;

use binbun_ast::interpret::{Outcome, run};
use binbun_ast::ir::{
    Expr, ExprId, Function, Origin, Place, Stmt, StmtId, VarId, VarKind, Variable,
};
use binbun_ast::types::{Evidence, Type, TypeId, Types};
use binbun_decompile::itanium::NONE;
use binbun_decompile::pass::{self, L2Env};
use binbun_decompile::structure::{ArrayLoops, Loops, Rotated};
use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Fuel, Manager, Pass};
use binbun_semantics::interpret::{Fault, Machine, Value};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_ssa::ir::BlockId;

const DECLARATIONS: Declarations = Declarations {
    registers: &[],
    intrinsics: &[],
    sites: &[],
};

/// Where the table is, and its size in bytes.
const TABLE: u64 = 0x5000;
const BYTES: u64 = 40;

/// A table of bytes at [`TABLE`] (byte `k` is `3k + 1`); everything else
/// faults.
struct Table;

impl Machine for Table {
    fn read(&mut self, _: RegisterId) -> Value {
        unreachable!("L2 holds registers in variables")
    }

    fn write(&mut self, _: RegisterId, _: Value) {
        unreachable!("L2 holds registers in variables")
    }

    fn load(&mut self, address: u64, size: u16) -> Result<Value, Fault> {
        let bytes = u64::from(size);
        if address < TABLE || address + bytes > TABLE + BYTES {
            return Err(Fault {
                address,
                write: false,
            });
        }
        let value = (0..bytes).fold(0u64, |value, k| {
            let byte = ((address - TABLE + k) * 3 + 1) & 0xff;
            value | byte << (8 * k)
        });
        Ok(Value::defined(Bits::from_u64(size * 8, value)))
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
    block: u32,
    int: TypeId,
    pointer: TypeId,
}

impl Builder {
    /// A function with a 32-bit result and `int32_t *` pointers.
    fn new() -> Self {
        let mut f = Function::new(0x1000, Types::new(64));
        let int = f.types.intern(Type::Int(32));
        let pointer = f.types.intern(Type::Pointer(Some(int)));
        f.returns = Some(int);
        Self {
            f,
            block: 0,
            int,
            pointer,
        }
    }

    fn local(&mut self, ty: TypeId) -> VarId {
        self.f.add_var(Variable {
            kind: VarKind::Local,
            name: None,
            ty,
            evidence: Evidence::Deduced,
            origins: Vec::new(),
        })
    }

    fn c(&mut self, width: u16, value: u64) -> ExprId {
        self.f.add_expr(Expr::Const(Bits::from_u64(width, value)))
    }

    fn read(&mut self, var: VarId) -> ExprId {
        self.f.add_expr(Expr::Var(var))
    }

    fn binary(&mut self, op: Binary, a: ExprId, b: ExprId) -> ExprId {
        self.f.add_expr(Expr::Binary(op, a, b))
    }

    /// A statement of a new block.
    fn stmt(&mut self, stmt: Stmt) -> StmtId {
        self.block += 1;
        let id = self.f.add_stmt(stmt);
        self.f
            .provenance
            .set_stmt(id, &[Origin::Block(BlockId(self.block))]);
        id
    }

    fn assign(&mut self, var: VarId, value: ExprId) -> StmtId {
        self.stmt(Stmt::Assign {
            place: Place::Var(var),
            value,
        })
    }

    /// `p = (int32_t *)TABLE`.
    fn start(&mut self, p: VarId) -> StmtId {
        let table = self.c(64, TABLE);
        let ty = self.pointer;
        let cast = self.f.add_expr(Expr::Cast { value: table, ty });
        self.assign(p, cast)
    }

    /// `p = p + 4`.
    fn step(&mut self, p: VarId) -> StmtId {
        let (rp, four) = (self.read(p), self.c(64, 4));
        let sum = self.binary(Binary::Add, rp, four);
        self.assign(p, sum)
    }

    /// `op(p, TABLE + end)`.
    fn test(&mut self, op: Binary, p: VarId, end: u64) -> ExprId {
        let (rp, bound) = (self.read(p), self.c(64, TABLE + end));
        self.binary(op, rp, bound)
    }

    /// `s = s + low32(*(T *)(p + offset))`, `T` of `bits`.
    fn add_load(&mut self, s: VarId, p: VarId, offset: u64, bits: u16) -> StmtId {
        let rp = self.read(p);
        let address = if offset == 0 {
            rp
        } else {
            let k = self.c(64, offset);
            self.binary(Binary::Add, rp, k)
        };
        let ty = if bits == 32 {
            self.int
        } else {
            self.f.types.intern(Type::Int(bits))
        };
        let mut loaded = self.f.add_expr(Expr::Load { address, ty });
        if bits != 32 {
            loaded = self.f.add_expr(Expr::Extract {
                value: loaded,
                offset: 0,
                width: 32,
            });
        }
        let rs = self.read(s);
        let sum = self.binary(Binary::Add, rs, loaded);
        self.assign(s, sum)
    }

    /// The low 32 bits of `*(T *)address` (zero-extended if narrower).
    fn low32(&mut self, address: ExprId, ty: TypeId) -> ExprId {
        let loaded = self.f.add_expr(Expr::Load { address, ty });
        match self.f.types.width(ty).unwrap().cmp(&32) {
            Ordering::Less => self.f.add_expr(Expr::Extend {
                signed: false,
                value: loaded,
                width: 32,
            }),
            Ordering::Greater => self.f.add_expr(Expr::Extract {
                value: loaded,
                offset: 0,
                width: 32,
            }),
            Ordering::Equal => loaded,
        }
    }

    /// Runs `passes` (the verifier after each change).
    fn run(&mut self, passes: &mut [&mut dyn Pass<Function, L2Env<'static>>]) {
        let env = L2Env {
            declarations: &DECLARATIONS,
            exceptions: &NONE,
            feeds: None,
        };
        let mut manager = Manager::new(Fuel::new(u64::MAX)).with_verifier(pass::verify);
        for pass in passes {
            manager.run(&mut **pass, &mut self.f, &env).unwrap();
        }
    }

    /// `array-loops` then the loop rules: loops rewritten, and what became
    /// of the `do`-`while`s.
    fn rewrite(&mut self) -> (usize, Vec<(Rotated, usize)>) {
        let (mut arrays, mut loops) = (ArrayLoops::default(), Loops::default());
        self.run(&mut [&mut arrays, &mut loops]);
        let rotated = loops.rotated().iter().map(|(&k, &v)| (k, v)).collect();
        (arrays.rewritten(), rotated)
    }
}

fn outcome(function: &Function) -> Outcome {
    run(function, &mut Table, &[], 0x800, 100_000)
}

/// `s = 0; p = (int32_t *)TABLE; do { <body>; p = p + 4; } while (p !=
/// TABLE + 40); return <result>;`: the loop.
fn summing(
    body: impl FnOnce(&mut Builder, VarId, VarId) -> Vec<StmtId>,
    result: impl FnOnce(&mut Builder, VarId, VarId) -> ExprId,
) -> (Builder, StmtId) {
    let mut b = Builder::new();
    let (int, pointer) = (b.int, b.pointer);
    let (s, p) = (b.local(int), b.local(pointer));
    let zero = b.c(32, 0);
    let mut top = vec![b.assign(s, zero), b.start(p)];
    let mut inner = body(&mut b, s, p);
    inner.push(b.step(p));
    let condition = b.test(Binary::Ne, p, BYTES);
    let lp = b.stmt(Stmt::DoWhile {
        body: inner,
        condition,
    });
    top.push(lp);
    let value = result(&mut b, s, p);
    top.push(b.stmt(Stmt::Return(Some(value))));
    b.f.body = top;
    (b, lp)
}

/// Whether `id` (or an expression under it) reads `var`.
fn reads(f: &Function, id: ExprId, var: VarId) -> bool {
    match f.expr(id) {
        Some(&Expr::Var(v)) => v == var,
        Some(node) => node.operands(f).any(|operand| reads(f, operand, var)),
        None => false,
    }
}

#[test]
fn a_pointer_loop_over_a_table_is_an_array_loop() {
    let (mut b, lp) = summing(|b, s, p| vec![b.add_load(s, p, 0, 32)], |b, s, _| b.read(s));
    let before = outcome(&b.f);
    assert!(matches!(before, Outcome::Returned(Some(_))), "{before:?}");
    assert_eq!(b.rewrite(), (1, vec![(Rotated::Proved, 1)]));
    assert_eq!(outcome(&b.f), before);
    // `for (i = 0; i < 10; i = i + 1) s = s + p[i];`
    let Some(Stmt::For {
        init,
        condition,
        step,
        body,
    }) = b.f.stmt(lp)
    else {
        panic!("{:?}", b.f.stmt(lp));
    };
    let Some(&Stmt::Assign {
        place: Place::Var(i),
        value,
    }) = b.f.stmt(init[0])
    else {
        panic!("{:?}", b.f.stmt(init[0]));
    };
    assert_eq!(b.f.expr(value), Some(&Expr::Const(Bits::from_u64(64, 0))));
    let Some(&Expr::Binary(Binary::ULt, counter, bound)) = b.f.expr(*condition) else {
        panic!("{:?}", b.f.expr(*condition));
    };
    assert_eq!(b.f.expr(counter), Some(&Expr::Var(i)));
    assert_eq!(b.f.expr(bound), Some(&Expr::Const(Bits::from_u64(64, 10))));
    assert!(
        matches!(b.f.stmt(step[0]), Some(&Stmt::Assign { place: Place::Var(v), .. }) if v == i)
    );
    // The load's address is `p + i·4`.
    let Some(&Stmt::Assign { value: sum, .. }) = b.f.stmt(body[0]) else {
        panic!();
    };
    let Some(&Expr::Binary(Binary::Add, _, loaded)) = b.f.expr(sum) else {
        panic!();
    };
    let Some(&Expr::Load { address, .. }) = b.f.expr(loaded) else {
        panic!("{:?}", b.f.expr(loaded));
    };
    let Some(&Expr::Binary(Binary::Add, base, scaled)) = b.f.expr(address) else {
        panic!("{:?}", b.f.expr(address));
    };
    assert!(matches!(b.f.expr(base), Some(Expr::Var(_))));
    let Some(&Expr::Binary(Binary::Mul, index, four)) = b.f.expr(scaled) else {
        panic!("{:?}", b.f.expr(scaled));
    };
    assert_eq!(b.f.expr(index), Some(&Expr::Var(i)));
    assert_eq!(b.f.expr(four), Some(&Expr::Const(Bits::from_u64(64, 4))));
}

#[test]
fn a_pointer_read_after_its_loop_is_the_base_plus_its_end() {
    // `return s + (int32_t)p`: `p` after the loop is `TABLE + 40`; the
    // loop leaves only by its test, at `i == 10`, so that is `p + 4·10`,
    // with no index.
    let (mut b, _) = summing(
        |b, s, p| vec![b.add_load(s, p, 0, 32)],
        |b, s, p| {
            let (rs, rp) = (b.read(s), b.read(p));
            let low = b.f.add_expr(Expr::Extract {
                value: rp,
                offset: 0,
                width: 32,
            });
            b.binary(Binary::Add, rs, low)
        },
    );
    let before = outcome(&b.f);
    assert!(matches!(before, Outcome::Returned(Some(_))), "{before:?}");
    assert_eq!(b.rewrite().0, 1);
    assert_eq!(outcome(&b.f), before);
    let Some(&Stmt::Return(Some(value))) = b.f.body.last().and_then(|&id| b.f.stmt(id)) else {
        panic!();
    };
    let index = VarId(u32::try_from(b.f.variables.len() - 1).unwrap());
    assert!(!reads(&b.f, value, index), "the exit value reads the index");
    assert!(
        reads(&b.f, value, VarId(1)),
        "the exit value reads no pointer"
    );
}

#[test]
fn a_loop_whose_access_crosses_elements_stays_a_pointer_loop() {
    // An 8-byte load at `p` spans two `int32_t` elements.
    let (mut b, lp) = summing(|b, s, p| vec![b.add_load(s, p, 0, 64)], |b, s, _| b.read(s));
    let before = outcome(&b.f);
    let (rewritten, _) = b.rewrite();
    assert_eq!(rewritten, 0);
    assert_eq!(outcome(&b.f), before);
    let Some(Stmt::DoWhile { condition, .. } | Stmt::For { condition, .. }) = b.f.stmt(lp) else {
        panic!("{:?}", b.f.stmt(lp));
    };
    let p = VarId(1);
    assert!(reads(&b.f, *condition, p), "still tests the pointer");
}

#[test]
fn a_step_followed_by_its_exit_test_counts_in_any_loop() {
    // `while (1) { s += *p; p = p + 4; if (p == TABLE + 40) break; s += p[-1]; }`
    // (the shape of bash's `reset_terminating_signals`: a read after the
    // step is the previous element).
    let mut b = Builder::new();
    let (int, pointer) = (b.int, b.pointer);
    let (s, p) = (b.local(int), b.local(pointer));
    let zero = b.c(32, 0);
    let mut top = vec![b.assign(s, zero), b.start(p)];
    let first = b.add_load(s, p, 0, 32);
    let step = b.step(p);
    let condition = b.test(Binary::Eq, p, BYTES);
    let one = b.c(1, 1);
    let lp = b.f.add_stmt(Stmt::While {
        condition: one,
        body: Vec::new(),
    });
    let leave = b.stmt(Stmt::Break(lp));
    let exit = b.stmt(Stmt::If {
        condition,
        then: vec![leave],
        otherwise: Vec::new(),
    });
    let rp = b.read(p);
    let four = b.c(64, 4);
    let previous = b.binary(Binary::Sub, rp, four);
    let ty = b.int;
    let loaded = b.f.add_expr(Expr::Load {
        address: previous,
        ty,
    });
    let rs = b.read(s);
    let sum = b.binary(Binary::Add, rs, loaded);
    let again = b.assign(s, sum);
    if let Some(Stmt::While { body, .. }) = b.f.stmts.get_mut(lp.0 as usize) {
        *body = vec![first, step, exit, again];
    }
    top.push(lp);
    let rs = b.read(s);
    top.push(b.stmt(Stmt::Return(Some(rs))));
    b.f.body = top;
    let before = outcome(&b.f);
    assert!(matches!(before, Outcome::Returned(Some(_))), "{before:?}");
    assert_eq!(b.rewrite().0, 1);
    assert_eq!(outcome(&b.f), before);
    let Some(&Stmt::If { condition, .. }) = b.f.stmt(exit) else {
        panic!();
    };
    let Some(&Expr::Binary(Binary::Eq, _, bound)) = b.f.expr(condition) else {
        panic!("{:?}", b.f.expr(condition));
    };
    assert_eq!(b.f.expr(bound), Some(&Expr::Const(Bits::from_u64(64, 10))));
}

/// A loop over `n` elements of `size` bytes from a parameter `x`, for
/// [`ranged`].
#[derive(Clone, Copy)]
struct Shape {
    size: u64,
    /// `n` 32-bit, zero-extended to 64 (else 64-bit).
    narrow: bool,
    /// Where `n` comes from: the second parameter (`None`), or computed
    /// from it, a pointer `y`, as `n = (y - x) op log2(size)`.
    shifted: Option<Binary>,
    /// The `if (n op k)`s (`if (k op n)` where the flag is set) around
    /// the loop, outermost first (`n` 32-bit where `narrow`, else
    /// 64-bit).
    guards: &'static [(Binary, u64, bool)],
    /// Counting down from `x + d·n` to `x`, reading `p[-1]`.
    down: bool,
}

impl Shape {
    const fn up(size: u64, narrow: bool, guards: &'static [(Binary, u64, bool)]) -> Self {
        Self {
            size,
            narrow,
            shifted: None,
            guards,
            down: false,
        }
    }
}

/// `f(x, n)` (or `f(x, y)`, `n` computed from `y`): `s = 0;` then, behind
/// the shape's guards, `e = x + d·n; p = x; do { s += low32(*p); p = p +
/// d; } while (p != e);` (counting down: `p = x + d·n; do { s +=
/// low32(p[-1]); p = p - d; } while (p != x);`), then `return s;`, with
/// `p` a pointer to `d`-byte integers: the function, the loop and `p`.
fn ranged(shape: Shape) -> (Builder, StmtId, VarId) {
    let Shape {
        size,
        narrow,
        shifted,
        guards,
        down,
    } = shape;
    let mut b = Builder::new();
    let bits = u16::try_from(size * 8).unwrap();
    let element = b.f.types.intern(Type::UInt(bits));
    let pointer = b.f.types.intern(Type::Pointer(Some(element)));
    let count_bits = if narrow { 32 } else { 64 };
    let wide = b.f.types.intern(Type::UInt(count_bits));
    let int = b.int;
    let start = b.local(pointer);
    let second = b.local(if shifted.is_some() { pointer } else { wide });
    for var in [start, second] {
        b.f.variables[var.0 as usize].kind = VarKind::Parameter;
        b.f.parameters.push(var);
    }
    let (total, cursor, end) = (b.local(int), b.local(pointer), b.local(pointer));
    let zero = b.c(32, 0);
    let mut top = vec![b.assign(total, zero)];
    let count = if let Some(op) = shifted {
        // `n = (y - x) op log2(d)`.
        let count = b.local(wide);
        let (ry, rx) = (b.read(second), b.read(start));
        let span = b.binary(Binary::Sub, ry, rx);
        let shift = b.c(64, u64::from(size.trailing_zeros()));
        let value = b.binary(op, span, shift);
        top.push(b.assign(count, value));
        count
    } else {
        second
    };
    let (rx, mut rn) = (b.read(start), b.read(count));
    if narrow {
        rn = b.f.add_expr(Expr::Extend {
            signed: false,
            value: rn,
            width: 64,
        });
    }
    let scaled = if size == 1 {
        rn
    } else {
        let bytes = b.c(64, size);
        b.binary(Binary::Mul, rn, bytes)
    };
    let bound = b.binary(Binary::Add, rx, scaled);
    let mut inner = if down {
        vec![b.assign(cursor, bound)]
    } else {
        let rx = b.read(start);
        vec![b.assign(end, bound), b.assign(cursor, rx)]
    };
    let mut rp = b.read(cursor);
    if down {
        let bytes = b.c(64, size);
        rp = b.binary(Binary::Sub, rp, bytes);
    }
    let loaded = b.low32(rp, element);
    let rs = b.read(total);
    let sum = b.binary(Binary::Add, rs, loaded);
    let add = b.assign(total, sum);
    let (rp, bytes) = (b.read(cursor), b.c(64, size));
    let next = b.binary(if down { Binary::Sub } else { Binary::Add }, rp, bytes);
    let step = b.assign(cursor, next);
    let (rp, re) = (b.read(cursor), b.read(if down { start } else { end }));
    let condition = b.binary(Binary::Ne, rp, re);
    let lp = b.stmt(Stmt::DoWhile {
        body: vec![add, step],
        condition,
    });
    inner.push(lp);
    for &(op, k, first) in guards.iter().rev() {
        let (rn, k) = (b.read(count), b.c(count_bits, k));
        let condition = if first {
            b.binary(op, k, rn)
        } else {
            b.binary(op, rn, k)
        };
        inner = vec![b.stmt(Stmt::If {
            condition,
            then: inner,
            otherwise: Vec::new(),
        })];
    }
    top.extend(inner);
    let rs = b.read(total);
    top.push(b.stmt(Stmt::Return(Some(rs))));
    b.f.body = top;
    (b, lp, cursor)
}

/// What `function` returns for `x = TABLE + 4` and each `n` (passed as
/// `y = x + size·n` where the second parameter is a pointer).
fn ranged_outcomes(function: &Function, counts: &[u64]) -> Vec<Outcome> {
    counts
        .iter()
        .map(|&n| {
            let x = Value::defined(Bits::from_u64(64, TABLE + 4));
            let second = function.var(VarId(1)).unwrap();
            let width = function.types.value_width(second.ty).unwrap_or(64);
            let n = if let Some(&Type::Pointer(Some(element))) = function.types.get(second.ty) {
                let size = function.types.width(element).unwrap() / 8;
                (TABLE + 4).wrapping_add(size.wrapping_mul(n))
            } else {
                n
            };
            let n = Value::defined(Bits::from_u64(width, n));
            run(function, &mut Table, &[x, n], 0x800, 100_000)
        })
        .collect()
}

#[test]
fn a_byte_loop_to_a_computed_end_counts_to_its_length() {
    // `for (p = x; p != x + n; p++)` over bytes: `p == x + n` is `i == n`
    // for every `i` (no bound on `n` needed).
    let (mut b, lp, p) = ranged(Shape::up(1, false, &[]));
    let counts = [1, 2, 7, 36, 37];
    let before = ranged_outcomes(&b.f, &counts);
    assert!(
        matches!(before[2], Outcome::Returned(Some(_))),
        "{before:?}"
    );
    assert_eq!(b.rewrite().0, 1);
    assert_eq!(ranged_outcomes(&b.f, &counts), before);
    let Some(&Stmt::DoWhile { condition, .. }) = b.f.stmt(lp) else {
        panic!("{:?}", b.f.stmt(lp));
    };
    let Some(&Expr::Binary(Binary::Ne, i, n)) = b.f.expr(condition) else {
        panic!("{:?}", b.f.expr(condition));
    };
    assert_eq!(b.f.expr(n), Some(&Expr::Var(VarId(1))), "the test reads n");
    assert!(!reads(&b.f, i, p));
}

#[test]
fn a_wider_step_to_an_unbounded_count_stays_a_pointer_loop() {
    // `p == x + 4·n` is `i ≡ n` modulo 2^62: with a 64-bit `n` and no
    // range, `i == n` could differ.
    let (mut b, lp, p) = ranged(Shape::up(4, false, &[]));
    let counts = [1, 2, 9, (1 << 62) + 1];
    let before = ranged_outcomes(&b.f, &counts);
    assert_eq!(before[3], before[0], "n = 2^62 + 1 runs once");
    assert_eq!(b.rewrite().0, 0);
    assert_eq!(ranged_outcomes(&b.f, &counts), before);
    let Some(&Stmt::DoWhile { condition, .. }) = b.f.stmt(lp) else {
        panic!("{:?}", b.f.stmt(lp));
    };
    assert!(reads(&b.f, condition, p));
}

#[test]
fn a_wider_step_to_a_guarded_narrow_count_is_an_array_loop() {
    // `n` zero-extended from 32 bits: `4·n` cannot wrap, and `if (n !=
    // 0)` gives the `do`'s first test `1 <= n`. The bound is an extension
    // of a variable, whose values are the variable's: the range analysis
    // counts it, and `n != 0` proves the first test (`if (n != 0) { …
    // for (i = 0; i < (uint64_t)n; i++) … p[i] … }`).
    let (mut b, lp, p) = ranged(Shape::up(4, true, &[(Binary::Ne, 0, false)]));
    let counts = [0, 1, 2, 9];
    let before = ranged_outcomes(&b.f, &counts);
    assert!(
        matches!(before[3], Outcome::Returned(Some(_))),
        "{before:?}"
    );
    assert_eq!(b.rewrite(), (1, vec![(Rotated::Proved, 1)]));
    assert_eq!(ranged_outcomes(&b.f, &counts), before);
    let Some(&Stmt::For { condition, .. }) = b.f.stmt(lp) else {
        panic!("{:?}", b.f.stmt(lp));
    };
    let Some(&Expr::Binary(Binary::ULt, _, bound)) = b.f.expr(condition) else {
        panic!("{:?}", b.f.expr(condition));
    };
    assert!(
        matches!(b.f.expr(bound), Some(Expr::Extend { signed: false, .. })),
        "the bound is `(uint64_t)n`"
    );
    assert!(!reads(&b.f, condition, p));
    assert!(reads(&b.f, condition, VarId(1)), "the test reads n");
}

/// Runs `shape`'s function through `array-loops` and the loop rules on
/// `counts`: the outcomes agree; whether the loop was rewritten, what its
/// test became, and what became of it.
fn rewritten(shape: Shape, counts: &[u64]) -> (bool, Builder, StmtId, Vec<(Rotated, usize)>) {
    let (mut b, lp, p) = ranged(shape);
    let before = ranged_outcomes(&b.f, counts);
    assert!(
        before
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Returned(Some(_)))),
        "{before:?}"
    );
    let (count, rotated) = b.rewrite();
    assert_eq!(ranged_outcomes(&b.f, counts), before);
    let Some(Stmt::DoWhile { condition, .. } | Stmt::For { condition, .. }) = b.f.stmt(lp) else {
        panic!("{:?}", b.f.stmt(lp));
    };
    assert_eq!(count == 1, !reads(&b.f, *condition, p));
    (count == 1, b, lp, rotated)
}

#[test]
fn a_dominating_test_bounds_a_wide_count() {
    // `if (n != 0) if (n < 1000)`: `4·n < 4000` cannot wrap, and `n >= 1`
    // holds at the `do`.
    let shape = Shape::up(
        4,
        false,
        &[(Binary::Ne, 0, false), (Binary::ULt, 1000, false)],
    );
    assert!(rewritten(shape, &[0, 1, 2, 9, 1000, (1 << 62) + 1]).0);
}

#[test]
fn a_bound_too_large_for_the_step_proves_nothing() {
    // `n < 2^62 + 2` still lets `4·n` wrap (`n = 2^62 + 1` runs once).
    let shape = Shape::up(
        4,
        false,
        &[(Binary::Ne, 0, false), (Binary::ULt, (1 << 62) + 2, false)],
    );
    let (array, ..) = rewritten(shape, &[1, 2, 9, (1 << 62) + 1]);
    assert!(!array);
}

#[test]
fn a_count_of_a_pointer_difference_cannot_wrap() {
    // `n = (y - x) >> 2` (logical): `4·n <= y - x`, below 2^64.
    let shape = Shape {
        shifted: Some(Binary::LShr),
        ..Shape::up(4, false, &[(Binary::Ne, 0, false)])
    };
    assert!(rewritten(shape, &[0, 1, 2, 9]).0);
}

#[test]
fn a_signed_count_of_a_pointer_difference_needs_its_sign() {
    // `n = (y - x) >> 2` (arithmetic) is negative where `y < x`: with
    // `n != 0` alone `4·n` may wrap; `n > 0` (signed) bounds it by
    // `(2^63 - 1) / 4`.
    let unproved = Shape {
        shifted: Some(Binary::AShr),
        ..Shape::up(4, false, &[(Binary::Ne, 0, false)])
    };
    assert!(!rewritten(unproved, &[1, 2, 9]).0);
    let proved = Shape {
        shifted: Some(Binary::AShr),
        ..Shape::up(4, false, &[(Binary::SLt, 0, true)])
    };
    assert!(rewritten(proved, &[0, 1, 2, 9]).0);
}

#[test]
fn a_loop_counting_down_is_indexed_from_its_end() {
    // `p = x + 4·n; do { s += p[-1]; p = p - 4; } while (p != x);` with
    // `n` 32-bit behind `if (n != 0)`: `p = x; for (i = n; …; i = i - 1)
    // s += p[i - 1];`.
    let shape = Shape {
        down: true,
        ..Shape::up(4, true, &[(Binary::Ne, 0, false)])
    };
    let (array, b, lp, rotated) = rewritten(shape, &[0, 1, 2, 9]);
    assert!(array);
    // `i = (uint64_t)n` is in `1..2^32` where `n != 0`: the first test is
    // proved.
    assert_eq!(rotated, [(Rotated::Proved, 1)]);
    let Some(Stmt::DoWhile { condition, .. } | Stmt::For { condition, .. }) = b.f.stmt(lp) else {
        panic!("{:?}", b.f.stmt(lp));
    };
    let Some(&Expr::Binary(_, a, z)) = b.f.expr(*condition) else {
        panic!("{:?}", b.f.expr(*condition));
    };
    let zero = Some(&Expr::Const(Bits::from_u64(64, 0)));
    assert!(b.f.expr(a) == zero || b.f.expr(z) == zero, "`i` against 0");
}

#[test]
fn a_loop_counting_down_a_wide_count_stays_a_pointer_loop() {
    // As above with a 64-bit `n`: `x + 4·n` may wrap.
    let shape = Shape {
        down: true,
        ..Shape::up(4, false, &[(Binary::Ne, 0, false)])
    };
    assert!(!rewritten(shape, &[1, 2, 9, (1 << 62) + 1]).0);
}

#[test]
fn a_stepped_parameter_is_the_array_from_its_entry_value() {
    // `f(x, n)`: `e = x + n; s = 0; do { s += *x; x = x + 1; } while (x !=
    // e); return s;`, the parameter `x` its own cursor. Reading `x` after
    // the loop (not rewritten: outside the loop's block) would refuse it.
    for read_after in [false, true] {
        let mut b = Builder::new();
        let byte = b.f.types.intern(Type::UInt(8));
        let pointer = b.f.types.intern(Type::Pointer(Some(byte)));
        let wide = b.f.types.intern(Type::UInt(64));
        let int = b.int;
        let (x, n) = (b.local(pointer), b.local(wide));
        for var in [x, n] {
            b.f.variables[var.0 as usize].kind = VarKind::Parameter;
            b.f.parameters.push(var);
        }
        let (total, end) = (b.local(int), b.local(pointer));
        let (rx, rn) = (b.read(x), b.read(n));
        let bound = b.binary(Binary::Add, rx, rn);
        let zero = b.c(32, 0);
        let mut inner = vec![b.assign(end, bound), b.assign(total, zero)];
        let rx = b.read(x);
        let loaded = b.f.add_expr(Expr::Load {
            address: rx,
            ty: byte,
        });
        let wider = b.f.add_expr(Expr::Extend {
            signed: false,
            value: loaded,
            width: 32,
        });
        let rs = b.read(total);
        let sum = b.binary(Binary::Add, rs, wider);
        let add = b.assign(total, sum);
        let (rx, one) = (b.read(x), b.c(64, 1));
        let next = b.binary(Binary::Add, rx, one);
        let step = b.assign(x, next);
        let (rx, re) = (b.read(x), b.read(end));
        let condition = b.binary(Binary::Ne, rx, re);
        let lp = b.stmt(Stmt::DoWhile {
            body: vec![add, step],
            condition,
        });
        inner.push(lp);
        // `if (n != 0) { … } [s += (int32_t)x;] return s;`
        let (rn, none) = (b.read(n), b.c(64, 0));
        let guard = b.binary(Binary::Ne, rn, none);
        let zero = b.c(32, 0);
        let mut top = vec![
            b.assign(total, zero),
            b.stmt(Stmt::If {
                condition: guard,
                then: inner,
                otherwise: Vec::new(),
            }),
        ];
        if read_after {
            let (rs, rx) = (b.read(total), b.read(x));
            let low = b.f.add_expr(Expr::Extract {
                value: rx,
                offset: 0,
                width: 32,
            });
            let sum = b.binary(Binary::Add, rs, low);
            top.push(b.assign(total, sum));
        }
        let rs = b.read(total);
        top.push(b.stmt(Stmt::Return(Some(rs))));
        b.f.body = top;
        let counts = [0, 1, 7, 36];
        let before = ranged_outcomes(&b.f, &counts);
        assert!(
            matches!(before[2], Outcome::Returned(Some(_))),
            "{before:?}"
        );
        assert_eq!(b.rewrite().0, usize::from(!read_after));
        assert_eq!(ranged_outcomes(&b.f, &counts), before);
        let Some(Stmt::DoWhile { condition, .. } | Stmt::For { condition, .. }) = b.f.stmt(lp)
        else {
            panic!("{:?}", b.f.stmt(lp));
        };
        assert_eq!(reads(&b.f, *condition, x), read_after);
    }
}

/// `total = 0; counter = 0; row = TABLE + 32; do { cell = row - 32; do {
/// cell = cell + 8; total = total + *(int32_t *)(cell - 8); } while (row
/// != cell); row = row + 4; counter = counter + 1; } while (counter !=
/// 2); return total;`: the columns of a 4×2 matrix, as compilers stride
/// through them (`for (x < 2) for (y < 4) s += a[y * 2 + x]`). With the
/// outer loop, the inner loop and the row pointer.
fn columns() -> (Builder, StmtId, StmtId, VarId) {
    let mut b = Builder::new();
    let (int, pointer) = (b.int, b.pointer);
    let (total, counter, row, cell) = (
        b.local(int),
        b.local(int),
        b.local(pointer),
        b.local(pointer),
    );
    let zero = b.c(32, 0);
    let zero_c = b.c(32, 0);
    let row_end = b.c(64, TABLE + 32);
    let mut top = vec![
        b.assign(total, zero),
        b.assign(counter, zero_c),
        b.assign(row, row_end),
    ];
    // cell = row - 32
    let (rq, span) = (b.read(row), b.c(64, 32));
    let start = b.binary(Binary::Sub, rq, span);
    let begin = b.assign(cell, start);
    // cell = cell + 8; total = total + *(int32_t *)(cell - 8)
    let (rp, eight) = (b.read(cell), b.c(64, 8));
    let stepped = b.binary(Binary::Add, rp, eight);
    let step = b.assign(cell, stepped);
    let (rp, eight) = (b.read(cell), b.c(64, 8));
    let back = b.binary(Binary::Sub, rp, eight);
    let ty = b.int;
    let loaded = b.low32(back, ty);
    let rs = b.read(total);
    let sum = b.binary(Binary::Add, rs, loaded);
    let add = b.assign(total, sum);
    let (rq, rp) = (b.read(row), b.read(cell));
    let more = b.binary(Binary::Ne, rq, rp);
    let inner = b.stmt(Stmt::DoWhile {
        body: vec![step, add],
        condition: more,
    });
    // row = row + 4; counter = counter + 1
    let (rq, four) = (b.read(row), b.c(64, 4));
    let next_q = b.binary(Binary::Add, rq, four);
    let q_step = b.assign(row, next_q);
    let (rc, one) = (b.read(counter), b.c(32, 1));
    let next_c = b.binary(Binary::Add, rc, one);
    let c_step = b.assign(counter, next_c);
    let (rc, two) = (b.read(counter), b.c(32, 2));
    let looping = b.binary(Binary::Ne, rc, two);
    let outer = b.stmt(Stmt::DoWhile {
        body: vec![begin, inner, q_step, c_step],
        condition: looping,
    });
    top.push(outer);
    let rs = b.read(total);
    top.push(b.stmt(Stmt::Return(Some(rs))));
    b.f.body = top;
    (b, outer, inner, row)
}

#[test]
fn a_matrix_walked_by_column_and_row_pointers_is_indexed_by_both_counters() {
    let (mut b, outer, inner, q) = columns();
    let before = outcome(&b.f);
    assert!(matches!(before, Outcome::Returned(Some(_))), "{before:?}");
    // The inner pointer: an index from its start 32 bytes below the row's
    // end, its step (first, then the reads of `p - 8`) last; the row
    // pointer: the outer counter scaled.
    let (rewritten, _) = b.rewrite();
    assert_eq!(rewritten, 2);
    assert_eq!(outcome(&b.f), before);
    let body = match b.f.stmt(outer) {
        Some(Stmt::DoWhile { body, .. } | Stmt::For { body, .. }) => body.clone(),
        other => panic!("{other:?}"),
    };
    let writes_q = |id: StmtId| matches!(b.f.stmt(id), Some(&Stmt::Assign { place: Place::Var(v), .. }) if v == q);
    assert!(
        !body.iter().any(|&id| writes_q(id)),
        "the row pointer still steps"
    );
    // The inner loop counts 4 elements of 8 bytes, its counter's step last.
    let Some(Stmt::For {
        condition, step, ..
    }) = b.f.stmt(inner)
    else {
        panic!("{:?}", b.f.stmt(inner));
    };
    let Some(&Expr::Binary(Binary::ULt, _, bound)) = b.f.expr(*condition) else {
        panic!("{:?}", b.f.expr(*condition));
    };
    assert_eq!(b.f.expr(bound), Some(&Expr::Const(Bits::from_u64(64, 4))));
    assert_eq!(step.len(), 1);
}

#[test]
fn a_leading_step_with_a_break_after_it_stays_a_pointer_loop() {
    // As above, but the inner body may leave by a `break` after its step:
    // the step cannot go last (the break would leave before it).
    let (mut b, _, inner, _) = columns();
    let Some(Stmt::DoWhile { body, .. }) = b.f.stmt(inner).cloned() else {
        panic!();
    };
    let leave = b.stmt(Stmt::Break(inner));
    let zero = b.c(32, 0);
    let never = b.f.add_expr(Expr::Binary(Binary::Ne, zero, zero));
    let guard = b.stmt(Stmt::If {
        condition: never,
        then: vec![leave],
        otherwise: Vec::new(),
    });
    if let Some(Stmt::DoWhile { body: inside, .. }) = b.f.stmts.get_mut(inner.0 as usize) {
        *inside = body.into_iter().chain([guard]).collect();
    }
    let before = outcome(&b.f);
    let (rewritten, _) = b.rewrite();
    assert_eq!(outcome(&b.f), before);
    // Only the row pointer, the outer counter scaled.
    assert_eq!(rewritten, 1);
    let Some(Stmt::DoWhile { body, .. }) = b.f.stmt(inner) else {
        panic!("{:?}", b.f.stmt(inner));
    };
    let p = VarId(3);
    assert!(
        matches!(b.f.stmt(body[0]), Some(&Stmt::Assign { place: Place::Var(v), .. }) if v == p),
        "the step moved"
    );
}
