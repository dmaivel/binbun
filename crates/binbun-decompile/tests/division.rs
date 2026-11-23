#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
#![allow(
    clippy::many_single_char_names,
    reason = "x, d, m, n, t as in the compilers' arithmetic"
)]

//! The division pass (`binbun_decompile::simplify::division`): GCC's
//! sequences for `x / d` (its `choose_multiplier`, unsigned and signed;
//! the multiply-high as the high half of a double-width product, or the
//! product shifted once), and Clang's sign correction, become
//! `udiv`/`sdiv` by `d` (powers of two excepted: compilers shift), and
//! `x - q * d` `urem`/`srem`:
//!
//! - at 8 bits for every divisor and at 16 for fifty (3 to 30, powers
//!   of ten, `2^k ± 1`, the largest), z3 finds no
//!   input where the sequence and the division differ (ignored by
//!   default, as the CPU oracles are: minutes; run with `--ignored`
//!   whenever the division pass changes);
//! - at 32 and 64 bits for a thousand divisors each (z3 needs minutes
//!   for one), the rewrite happens and the sequence computes the
//!   division from edge and random values.
//!
//! Sequences spread over variables (`loop_sum`'s shape) are rewritten
//! too; a multiplier one off, or a write between the parts, is refused.
//!
//! Needs `z3` on the `PATH` for the proofs (skipped with a notice
//! otherwise).

mod common;

use std::time::Instant;

use binbun_ast::ir::{Expr, ExprId, Function, Origin, Place, Stmt, VarId, VarKind, Variable};
use binbun_ast::types::{Evidence, Type, Types};
use binbun_decompile::itanium::NONE;
use binbun_decompile::pass::{self, L2Env};
use binbun_decompile::simplify::division::Divisions;
use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Fuel, Manager};
use binbun_semantics::interpret::{self, Value};
use binbun_semantics::ir::Binary;

use common::{Proofs, run_all};

const DECLARATIONS: Declarations = Declarations {
    registers: &[],
    intrinsics: &[],
    sites: &[],
};

/// GCC's `choose_multiplier(d, n, precision)`: the multiplier (up to
/// `n + 1` bits) and the post-shift.
fn choose_multiplier(d: u128, n: u32, precision: u32) -> (u128, u32) {
    let lgup = 128 - (d - 1).leading_zeros();
    let pow = n + lgup;
    let pow2 = n + lgup - precision;
    let mut low = (1u128 << pow) / d;
    let mut high = ((1u128 << pow) + (1u128 << pow2)) / d;
    let mut post = lgup;
    while post > 0 && (low >> 1) < (high >> 1) {
        low >>= 1;
        high >>= 1;
        post -= 1;
    }
    (high, post)
}

/// A function of one `width`-bit parameter returning `width` bits, and
/// a read of the parameter.
fn function(width: u16) -> (Function, ExprId) {
    let mut f = Function::new(0x1000, Types::new(64));
    let ty = f.types.intern(Type::Bits(width));
    let x = f.add_var(Variable {
        kind: VarKind::Parameter,
        name: None,
        ty,
        evidence: Evidence::Default,
        origins: Vec::new(),
    });
    f.parameters.push(x);
    f.returns = Some(ty);
    let read = f.add_expr(Expr::Var(x));
    (f, read)
}

/// Builds sequences in a function.
struct Seq<'a> {
    f: &'a mut Function,
    n: u16,
}

impl Seq<'_> {
    fn add(&mut self, expr: Expr) -> ExprId {
        self.f.add_expr(expr)
    }

    fn constant(&mut self, width: u16, value: u128) -> ExprId {
        self.add(Expr::Const(Bits::from_u128(width, value)))
    }

    fn binary(&mut self, op: Binary, a: ExprId, b: ExprId) -> ExprId {
        self.add(Expr::Binary(op, a, b))
    }

    fn shift(&mut self, op: Binary, a: ExprId, count: u32) -> ExprId {
        if count == 0 {
            return a;
        }
        let count = self.constant(self.n, u128::from(count));
        self.binary(op, a, count)
    }

    /// The high `n` bits of `a * m` at `2n` bits, `a` extended
    /// (`signed`), `m` an `n`-bit pattern extended the same way.
    fn mulhi(&mut self, a: ExprId, m: u128, signed: bool) -> ExprId {
        let wide = self.n * 2;
        let extended = self.add(Expr::Extend {
            signed,
            value: a,
            width: wide,
        });
        let m = Bits::from_u128(self.n, m);
        let m = if signed { m.sext(wide) } else { m.zext(wide) };
        let m = self.add(Expr::Const(m));
        let product = self.binary(Binary::Mul, extended, m);
        self.add(Expr::Extract {
            value: product,
            offset: self.n,
            width: self.n,
        })
    }

    /// The low `n` bits of a `2n`-bit product of `x` (extended) by `m`
    /// (an extended `n`-bit pattern) shifted right by `shift`.
    fn shifted_product(&mut self, x: ExprId, m: u128, signed: bool, shift: u32) -> ExprId {
        let wide = self.n * 2;
        let extended = self.add(Expr::Extend {
            signed,
            value: x,
            width: wide,
        });
        let m = Bits::from_u128(self.n, m);
        let m = self.add(Expr::Const(if signed {
            m.sext(wide)
        } else {
            m.zext(wide)
        }));
        let product = self.binary(Binary::Mul, extended, m);
        let count = self.add(Expr::Const(Bits::from_u64(wide, u64::from(shift))));
        let op = if signed { Binary::AShr } else { Binary::LShr };
        let shifted = self.binary(op, product, count);
        self.add(Expr::Extract {
            value: shifted,
            offset: 0,
            width: self.n,
        })
    }

    /// GCC's unsigned `x / d`; `shifted`: the multiply-high and
    /// post-shift as one shift of the product, where the multiplier fits
    /// (else `None`).
    fn unsigned(&mut self, x: ExprId, d: u128, shifted: bool) -> Option<ExprId> {
        let n = u32::from(self.n);
        let (m, post) = choose_multiplier(d, n, n);
        if m < 1 << n {
            if shifted {
                return Some(self.shifted_product(x, m, false, n + post));
            }
            let t = self.mulhi(x, m, false);
            return Some(self.shift(Binary::LShr, t, post));
        }
        if shifted {
            return None;
        }
        if d.is_multiple_of(2) {
            let pre = d.trailing_zeros();
            let (m, post) = choose_multiplier(d >> pre, n, n - pre);
            let shifted = self.shift(Binary::LShr, x, pre);
            let t = self.mulhi(shifted, m, false);
            return Some(self.shift(Binary::LShr, t, post));
        }
        let t = self.mulhi(x, m - (1 << n), false);
        let difference = self.binary(Binary::Sub, x, t);
        let half = self.shift(Binary::LShr, difference, 1);
        let sum = self.binary(Binary::Add, half, t);
        Some(self.shift(Binary::LShr, sum, post - 1))
    }

    /// GCC's signed `x / d` (`d > 0`); `clang`: the sign added as a
    /// logical shift; `shifted` as for [`Seq::unsigned`].
    fn signed(&mut self, x: ExprId, d: u128, clang: bool, shifted: bool) -> Option<ExprId> {
        let n = u32::from(self.n);
        let (m, post) = choose_multiplier(d, n, n - 1);
        let t = if m < 1 << (n - 1) {
            if shifted {
                self.shifted_product(x, m, true, n + post)
            } else {
                let t = self.mulhi(x, m, true);
                self.shift(Binary::AShr, t, post)
            }
        } else {
            if shifted {
                return None;
            }
            let t = self.mulhi(x, m, true);
            let t = self.binary(Binary::Add, t, x);
            self.shift(Binary::AShr, t, post)
        };
        Some(if clang {
            let sign = self.shift(Binary::LShr, x, n - 1);
            self.binary(Binary::Add, t, sign)
        } else {
            let sign = self.shift(Binary::AShr, x, n - 1);
            self.binary(Binary::Sub, t, sign)
        })
    }
}

/// Runs [`Divisions`] on `f`, whose body is set to `return root`: the
/// returned expression after it.
fn divide(f: &mut Function, root: ExprId) -> ExprId {
    let ret = f.add_stmt(Stmt::Return(Some(root)));
    f.body = vec![ret];
    run(f);
    let Some(Stmt::Return(Some(value))) = f.stmt(ret) else {
        unreachable!()
    };
    *value
}

fn run(f: &mut Function) {
    let mut manager = Manager::new(Fuel::new(u64::MAX)).with_verifier(pass::verify);
    let env = L2Env {
        declarations: &DECLARATIONS,
        exceptions: &NONE,
        feeds: None,
    };
    manager.run(&mut Divisions, f, &env).unwrap();
}

/// Whether `id` is `op(x, d)`.
fn is(f: &Function, id: ExprId, op: Binary, x: ExprId, d: u128) -> bool {
    let Some(&Expr::Binary(found, a, b)) = f.expr(id) else {
        return false;
    };
    let Some(&Expr::Const(bits)) = f.expr(b) else {
        return false;
    };
    found == op && a == x && bits.low_u128() == d
}

/// The divisors tried at `n` bits: 3 to `up_to`, powers of ten, 2^k ± 1,
/// the largest; not powers of two.
fn divisors(n: u32, up_to: u128) -> Vec<u128> {
    let mut list: Vec<u128> = (3..=up_to.min((1 << n) - 1)).collect();
    let mut ten = 10u128;
    while ten < 1 << (n - 1) {
        list.push(ten);
        ten *= 10;
    }
    for k in 4..n - 1 {
        list.extend([(1 << k) - 1, (1 << k) + 1]);
    }
    list.extend([(1 << (n - 1)) - 1, (1 << (n - 1)) - 3]);
    list.sort_unstable();
    list.dedup();
    list.retain(|d| !d.is_power_of_two());
    list
}

/// A sequence rewritten: a function of one parameter (`x`, read by
/// that expression) where `root` (the sequence) became `new`.
struct Case {
    label: String,
    f: Function,
    x: ExprId,
    root: ExprId,
    new: ExprId,
}

type Make = fn(&mut Seq<'_>, ExprId, u128) -> Option<ExprId>;

/// The compilers' forms of `x / d`: name, the division, the sequence.
const FORMS: [(&str, Binary, Make); 6] = [
    ("unsigned", Binary::UDiv, |s, x, d| s.unsigned(x, d, false)),
    ("unsigned-shifted", Binary::UDiv, |s, x, d| {
        s.unsigned(x, d, true)
    }),
    ("signed", Binary::SDiv, |s, x, d| {
        s.signed(x, d, false, false)
    }),
    ("signed-clang", Binary::SDiv, |s, x, d| {
        s.signed(x, d, true, false)
    }),
    ("signed-shifted", Binary::SDiv, |s, x, d| {
        s.signed(x, d, false, true)
    }),
    ("signed-shifted-clang", Binary::SDiv, |s, x, d| {
        s.signed(x, d, true, true)
    }),
];

/// Every form's quotient and remainder by every divisor of
/// [`divisors`]`(n, up_to)`, rewritten by [`Divisions`]; asserts each
/// became the division (remainder) by `d` of `x`.
fn cases(n: u16, up_to: u128) -> Vec<Case> {
    let bits = u32::from(n);
    let mut cases = Vec::new();
    let mut missed = Vec::new();
    for d in divisors(bits, up_to) {
        for (name, op, make) in FORMS {
            if op == Binary::SDiv && d >= 1 << (bits - 1) {
                continue;
            }
            for remainder in [false, true] {
                let (mut f, x) = function(n);
                let mut s = Seq { f: &mut f, n };
                let Some(q) = make(&mut s, x, d) else {
                    continue;
                };
                let (root, expected, sign) = if remainder {
                    let divisor = s.constant(n, d);
                    let times = s.binary(Binary::Mul, q, divisor);
                    let root = s.binary(Binary::Sub, x, times);
                    let rem = if op == Binary::UDiv {
                        Binary::URem
                    } else {
                        Binary::SRem
                    };
                    (root, rem, '%')
                } else {
                    (q, op, '/')
                };
                let new = divide(&mut f, root);
                let label = format!("{name} {n}-bit {sign} {d}");
                if is(&f, new, expected, x, d) {
                    cases.push(Case {
                        label,
                        f,
                        x,
                        root,
                        new,
                    });
                } else {
                    missed.push(label);
                }
            }
        }
    }
    assert!(missed.is_empty(), "not rewritten: {missed:?}");
    cases
}

#[test]
#[ignore = "z3 proofs of 2,056 rewrites, about 5 minutes on 8 cores: cargo test --release -p binbun-decompile --test division -- --ignored"]
fn small_widths_are_proved_for_every_divisor() {
    let start = Instant::now();
    let mut batches: Vec<Proofs> = Vec::new();
    for (n, up_to) in [(8u16, 255u128), (16, 30)] {
        for case in cases(n, up_to) {
            if batches.last().is_none_or(|batch| batch.count() >= 32) {
                batches.push(Proofs::default());
            }
            let batch = batches.last_mut().unwrap();
            batch.differ(case.label, &case.f, case.root, case.new, &[]);
        }
    }
    let built = start.elapsed();
    let Some(results) = run_all(&batches) else {
        return;
    };
    let count: usize = batches.iter().map(Proofs::count).sum();
    let failed: Vec<String> = results.into_iter().flat_map(|(failed, _)| failed).collect();
    println!(
        "{count} rewrites proved; built in {built:.2?}, proved in {:.2?}",
        start.elapsed().saturating_sub(built)
    );
    assert!(failed.is_empty(), "not proved: {failed:#?}");
}

/// The value of `id` (an expression of `f` over its parameter, read by
/// `x`) when the parameter is `value`.
fn eval(f: &Function, id: ExprId, x: ExprId, value: Bits) -> Bits {
    if id == x {
        return value;
    }
    let get = |operand: ExprId| Value::defined(eval(f, operand, x, value));
    let result = match *f.expr(id).unwrap() {
        Expr::Const(bits) => Value::defined(bits),
        Expr::Binary(op, a, b) => interpret::binary(op, get(a), get(b)),
        Expr::Extract {
            value: a,
            offset,
            width,
        } => interpret::extract(get(a), offset, width),
        Expr::Extend {
            signed,
            value: a,
            width,
        } => interpret::extend(signed, get(a), width),
        other @ (Expr::Undefined(..)
        | Expr::Var(_)
        | Expr::AddressOf(_)
        | Expr::Unary(..)
        | Expr::Flag(..)
        | Expr::Concat { .. }
        | Expr::Select { .. }
        | Expr::Lanes { .. }
        | Expr::Float { .. }
        | Expr::Cast { .. }
        | Expr::Load { .. }
        | Expr::Logical(..)
        | Expr::Call(_)
        | Expr::Exception { .. }
        | Expr::Assign { .. }) => panic!("not in a sequence: {other:?}"),
    };
    result.known().unwrap()
}

#[test]
fn large_widths_divide_from_edge_and_random_values() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut random = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut checked = 0;
    for (n, up_to) in [(32u16, 1000u128), (64, 1000)] {
        let cases = cases(n, up_to);
        for case in &cases {
            let Some(&Expr::Binary(_, _, divisor)) = case.f.expr(case.new) else {
                unreachable!()
            };
            let d = eval(&case.f, divisor, case.x, Bits::zero(n)).low_u128();
            let mut values: Vec<u128> = [0, 1, 2, d - 1, d, d + 1, 2 * d - 1, 2 * d]
                .into_iter()
                .chain([u128::MAX, u128::MAX - 1, u128::MAX - d, u128::MAX - d + 1])
                .chain([1 << (n - 1), (1 << (n - 1)) + 1, (1 << (n - 1)) - 1])
                .collect();
            values.extend((0..64).map(|_| u128::from(random())));
            for value in values {
                let value = Bits::from_u128(n, value);
                let sequence = eval(&case.f, case.root, case.x, value);
                let division = eval(&case.f, case.new, case.x, value);
                assert_eq!(
                    sequence,
                    division,
                    "{} at {:#x}",
                    case.label,
                    value.low_u128()
                );
                checked += 1;
            }
        }
    }
    println!("{checked} values checked");
}

#[test]
fn a_multiplier_one_off_is_refused() {
    // GCC's x / 7 at 32 bits, `x * 0x24924925 >> 32` with the add step,
    // with the multiplier one lower: no divisor's.
    for m in [0x2492_4924u128, 0x2492_4926] {
        let (mut f, x) = function(32);
        let mut s = Seq { f: &mut f, n: 32 };
        let t = s.mulhi(x, m, false);
        let difference = s.binary(Binary::Sub, x, t);
        let half = s.shift(Binary::LShr, difference, 1);
        let sum = s.binary(Binary::Add, half, t);
        let root = s.shift(Binary::LShr, sum, 2);
        assert_eq!(divide(&mut f, root), root);
    }
    // x / 10 is 0xcccccccd >> 35, x / 5 the same >> 34; >> 33 is no
    // divisor's.
    let (mut f, x) = function(32);
    let root = Seq { f: &mut f, n: 32 }.shifted_product(x, 0xcccc_cccd, false, 33);
    assert_eq!(divide(&mut f, root), root);
}

#[test]
fn a_quotient_stored_as_a_byte_is_its_low_bits() {
    // (x * 0xcccccccd >> 35) as a byte: the low 8 bits of x / 10.
    let (mut f, x) = function(32);
    let mut s = Seq { f: &mut f, n: 32 };
    let wide = s.shifted_product(x, 0xcccc_cccd, false, 35);
    let Some(&Expr::Extract { value: shifted, .. }) = s.f.expr(wide) else {
        unreachable!()
    };
    let byte = s.add(Expr::Extract {
        value: shifted,
        offset: 0,
        width: 8,
    });
    f.returns = Some(f.types.intern(Type::Bits(8)));
    let new = divide(&mut f, byte);
    let Some(&Expr::Extract {
        value: quotient,
        offset: 0,
        width: 8,
    }) = f.expr(new)
    else {
        panic!("not rewritten");
    };
    assert!(is(&f, quotient, Binary::UDiv, x, 10));
    for value in [0, 9, 10, 2559, 2560, 0xffff_ffff] {
        let value = Bits::from_u64(32, value);
        assert_eq!(eval(&f, byte, x, value), eval(&f, new, x, value));
    }
}

/// Adds a local of `width` bits.
fn local(f: &mut Function, width: u16) -> VarId {
    let ty = f.types.intern(Type::Bits(width));
    f.add_var(Variable {
        kind: VarKind::Local,
        name: None,
        ty,
        evidence: Evidence::Default,
        origins: Vec::new(),
    })
}

#[test]
fn sequences_in_variables_and_the_remainder() {
    // loop_sum's `x % 7`, as lowering leaves it:
    //   t = mul(zext.64(x), 0x24924925) >> 32   (64 bits)
    //   q = (((x - t) >> 1) + t) >> 2
    //   r = x - q * 7
    let (mut f, x) = function(32);
    let t = local(&mut f, 64);
    let q = local(&mut f, 32);
    let mut s = Seq { f: &mut f, n: 32 };
    let wide = s.add(Expr::Extend {
        signed: false,
        value: x,
        width: 64,
    });
    let m = s.add(Expr::Const(Bits::from_u64(64, 0x2492_4925)));
    let product = s.binary(Binary::Mul, wide, m);
    let thirty_two = s.add(Expr::Const(Bits::from_u64(64, 32)));
    let t_value = s.binary(Binary::LShr, product, thirty_two);
    let t_read = s.add(Expr::Var(t));
    let t_low = s.add(Expr::Extract {
        value: t_read,
        offset: 0,
        width: 32,
    });
    let difference = s.binary(Binary::Sub, x, t_low);
    let half = s.shift(Binary::LShr, difference, 1);
    let sum = s.binary(Binary::Add, half, t_low);
    let q_value = s.shift(Binary::LShr, sum, 2);
    let q_read = s.add(Expr::Var(q));
    let seven = s.constant(32, 7);
    let times = s.binary(Binary::Mul, q_read, seven);
    let r = s.binary(Binary::Sub, x, times);
    let assign_t = f.add_stmt(Stmt::Assign {
        place: Place::Var(t),
        value: t_value,
    });
    let assign_q = f.add_stmt(Stmt::Assign {
        place: Place::Var(q),
        value: q_value,
    });
    let ret = f.add_stmt(Stmt::Return(Some(r)));
    f.body = vec![assign_t, assign_q, ret];
    run(&mut f);
    let Some(&Stmt::Assign { value, .. }) = f.stmt(assign_q) else {
        unreachable!()
    };
    assert!(is(&f, value, Binary::UDiv, x, 7));
    let Some(&Stmt::Return(Some(value))) = f.stmt(ret) else {
        unreachable!()
    };
    assert!(is(&f, value, Binary::URem, x, 7));

    // A write to `x`'s variable between the multiply-high and its use:
    // the sequence no longer divides what the statement reads.
    let (mut f, x) = function(32);
    let Some(&Expr::Var(param)) = f.expr(x) else {
        unreachable!()
    };
    let t = local(&mut f, 32);
    let mut s = Seq { f: &mut f, n: 32 };
    let t_value = s.mulhi(x, 0xcccc_cccd, false);
    let t_read = s.add(Expr::Var(t));
    let root = s.shift(Binary::LShr, t_read, 3);
    let one = s.constant(32, 1);
    let bumped = s.binary(Binary::Add, x, one);
    let assign_t = f.add_stmt(Stmt::Assign {
        place: Place::Var(t),
        value: t_value,
    });
    let write_x = f.add_stmt(Stmt::Assign {
        place: Place::Var(param),
        value: bumped,
    });
    let ret = f.add_stmt(Stmt::Return(Some(root)));
    f.body = vec![assign_t, write_x, ret];
    run(&mut f);
    assert_eq!(f.stmt(ret), Some(&Stmt::Return(Some(root))));
}

#[test]
fn a_division_stands_for_the_sequence_it_replaces() {
    // `x % 7` in one tree, its nodes each from an instruction, the
    // dividend's read from one of its own.
    let (mut f, x) = function(32);
    let mut s = Seq { f: &mut f, n: 32 };
    let q = s.unsigned(x, 7, false).unwrap();
    let seven = s.constant(32, 7);
    let times = s.binary(Binary::Mul, q, seven);
    let r = s.binary(Binary::Sub, x, times);
    let dividend = 0x100;
    let mut sequence = Vec::new();
    for index in 0..f.exprs.len() {
        let id = ExprId(u32::try_from(index).unwrap());
        let address = if id == x {
            dividend
        } else {
            0x200 + u64::try_from(index).unwrap()
        };
        if id != x {
            sequence.push(address);
        }
        f.provenance.set_expr(id, &[Origin::Instruction(address)]);
    }
    let value = divide(&mut f, r);
    assert!(is(&f, value, Binary::URem, x, 7));
    let mut made: Vec<u64> = f
        .provenance
        .expr(value)
        .iter()
        .map(|origin| {
            let &Origin::Instruction(address) = origin else {
                panic!("{origin:?}");
            };
            address
        })
        .collect();
    made.sort_unstable();
    sequence.sort_unstable();
    // Every node of the sequence (the root's first), the dividend's not:
    // it stays, with its own.
    assert_eq!(made, sequence);
    assert_eq!(f.provenance.expr(x), &[Origin::Instruction(dividend)]);

    // Spread over variables: the assignments looked through are the
    // division's too.
    let (mut f, x) = function(32);
    let t = local(&mut f, 32);
    let mut s = Seq { f: &mut f, n: 32 };
    let t_value = s.mulhi(x, 0xcccc_cccd, false);
    let t_read = s.add(Expr::Var(t));
    let root = s.shift(Binary::LShr, t_read, 3);
    let assign_t = f.add_stmt(Stmt::Assign {
        place: Place::Var(t),
        value: t_value,
    });
    f.provenance
        .set_stmt(assign_t, &[Origin::Instruction(0x300)]);
    f.provenance
        .set_expr(t_value, &[Origin::Instruction(0x301)]);
    f.provenance.set_expr(root, &[Origin::Instruction(0x302)]);
    let ret = f.add_stmt(Stmt::Return(Some(root)));
    f.body = vec![assign_t, ret];
    run(&mut f);
    let Some(&Stmt::Return(Some(value))) = f.stmt(ret) else {
        unreachable!()
    };
    assert!(is(&f, value, Binary::UDiv, x, 10));
    assert_eq!(
        f.provenance.expr(value),
        &[0x302, 0x300, 0x301].map(Origin::Instruction)
    );
}
