#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The printed C means what L2 means: hand-built functions run in
//! binbun-ast's interpreter and, printed and compiled with GCC and Clang
//! at -O0 and -O2 (under two styles), on the same inputs, give the same
//! results.

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::slice;

use binbun_ast::interpret::{Outcome, run};
use binbun_ast::ir::{Arm, Expr, ExprId, Function, Stmt, StmtId, VarId};
use binbun_ast::types::{Aggregate, Field, Type, TypeId};
use binbun_print::style::{IntSpelling, Style};
use binbun_semantics::IntrinsicId;
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{Fault, Machine, Value};
use binbun_semantics::ir::{Binary, Flag, FloatOp, FloatOutput, Format, LaneOp, RegisterId, Unary};
use common::{Builder, Scratch, compilers, print, warnings};

/// Where the buffer a pointer parameter points to lies, for the
/// interpreter.
const BUFFER: u64 = 0x1000;

/// The buffer's bytes.
fn buffer() -> Vec<u8> {
    (0..64u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect()
}

struct Memory {
    bytes: Vec<u8>,
}

impl Machine for Memory {
    fn read(&mut self, _: RegisterId) -> Value {
        unreachable!()
    }

    fn write(&mut self, _: RegisterId, _: Value) {
        unreachable!()
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        let start = address.wrapping_sub(BUFFER);
        let end = start + u64::from(bytes);
        let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
            return Err(Fault {
                address,
                write: false,
            });
        };
        if address < BUFFER || end > self.bytes.len() {
            return Err(Fault {
                address,
                write: false,
            });
        }
        let slice = &self.bytes[start..end];
        Ok(Value::defined(Bits::from_le_bytes(bytes * 8, slice)))
    }

    fn store(&mut self, address: u64, _: Value) -> Result<(), Fault> {
        Err(Fault {
            address,
            write: true,
        })
    }

    fn intrinsic(&mut self, _: IntrinsicId, _: &[Value], _: &[u16]) -> Vec<Value> {
        unreachable!()
    }
}

/// A function to check: its parameters' widths (`None`: the pointer to
/// the buffer) and its result's width.
struct Case {
    f: Function,
    parameters: Vec<Option<u16>>,
    result: u16,
    /// For a float's bits: its width (any NaN equals any NaN: which NaN
    /// an operation gives is the architecture's business, not C's).
    float: Option<u16>,
}

/// Deterministic random numbers.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A random `width`-bit value, often small or near an edge.
    fn value(&mut self, width: u16) -> u64 {
        let raw = self.next();
        let value = match raw % 8 {
            0 => raw >> 60,
            1 => u64::MAX - (raw >> 61),
            2 => (raw >> 58) ^ (1u64 << (width.min(64) - 1)),
            _ => self.next(),
        };
        value & mask(width)
    }
}

fn mask(width: u16) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1 << width) - 1
    }
}

/// Edge values of a width: 0, 1, 2, all ones, the signed extremes, and
/// shift counts around the width.
fn edges(width: u16) -> Vec<u64> {
    let w = u64::from(width);
    let min = 1u64 << (width - 1);
    let mut values = vec![0, 1, 2, u64::MAX, min, min - 1, w - 1, w, w + 1, 7];
    for value in &mut values {
        *value &= mask(width);
    }
    values.dedup();
    values
}

/// The inputs of a case: edge combinations and random tuples.
fn inputs(parameters: &[Option<u16>], random: &mut Random) -> Vec<Vec<u64>> {
    let widths: Vec<u16> = parameters.iter().map(|p| p.unwrap_or(64)).collect();
    let mut out: Vec<Vec<u64>> = vec![Vec::new()];
    if widths.len() <= 2 {
        for &width in &widths {
            let edges = edges(width);
            out = out
                .into_iter()
                .flat_map(|prefix| {
                    edges.iter().map(move |&e| {
                        let mut row = prefix.clone();
                        row.push(e);
                        row
                    })
                })
                .collect();
        }
    } else {
        out.clear();
    }
    for _ in 0..120 {
        out.push(widths.iter().map(|&w| random.value(w)).collect());
    }
    out
}

/// Builds the cases.
struct Cases {
    cases: Vec<Case>,
}

const BINARY: [Binary; 21] = [
    Binary::Add,
    Binary::Sub,
    Binary::Mul,
    Binary::And,
    Binary::Or,
    Binary::Xor,
    Binary::UDiv,
    Binary::URem,
    Binary::SDiv,
    Binary::SRem,
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

const UNARY: [Unary; 7] = [
    Unary::Not,
    Unary::Neg,
    Unary::Popcount,
    Unary::LeadingZeros,
    Unary::TrailingZeros,
    Unary::ByteSwap,
    Unary::EvenParity8,
];

fn is_compare(op: Binary) -> bool {
    matches!(
        op,
        Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe | Binary::SLt | Binary::SLe
    )
}

impl Cases {
    fn name(&self, what: &str) -> String {
        format!("m{}_{what}", self.cases.len())
    }

    /// A function of parameters of types `types` whose body `body` builds
    /// the returned expression; the result's type is `result`.
    fn add(
        &mut self,
        what: &str,
        types: &[Type],
        result: Type,
        body: impl FnOnce(&mut Builder, &[VarId]) -> ExprId,
    ) {
        let mut b = Builder::new(0x1000 + self.cases.len() as u64 * 0x10, &self.name(what));
        let mut parameters = Vec::new();
        let mut widths = Vec::new();
        for ty in types {
            let id = b.ty(ty.clone());
            parameters.push(b.param(id));
            widths.push(match ty {
                Type::Pointer(_) => None,
                Type::Bits(_)
                | Type::Int(_)
                | Type::UInt(_)
                | Type::Char { .. }
                | Type::Bool(_)
                | Type::Float(_)
                | Type::Code(_)
                | Type::Struct(_)
                | Type::Union(_)
                | Type::Array { .. }
                | Type::Vector { .. }
                | Type::Enum(_) => Some(b.f.types.value_width(id).unwrap()),
            });
        }
        let returns = b.ty(result);
        b.f.returns = Some(returns);
        let value = body(&mut b, &parameters);
        let ret = b.ret(value);
        let f = b.done(vec![ret]);
        let result = f.types.value_width(returns).unwrap();
        self.cases.push(Case {
            f,
            parameters: widths,
            result,
            float: None,
        });
    }

    /// A function with a body of statements (`body` gives them).
    fn add_body(
        &mut self,
        what: &str,
        types: &[Type],
        result: Type,
        body: impl FnOnce(&mut Builder, &[VarId], TypeId) -> Vec<StmtId>,
    ) {
        let mut b = Builder::new(0x1000 + self.cases.len() as u64 * 0x10, &self.name(what));
        let mut parameters = Vec::new();
        let mut widths = Vec::new();
        for ty in types {
            let id = b.ty(ty.clone());
            parameters.push(b.param(id));
            // A pointer is the buffer's address.
            widths.push(if matches!(ty, Type::Pointer(_)) {
                None
            } else {
                Some(b.f.types.value_width(id).unwrap())
            });
        }
        let returns = b.ty(result);
        b.f.returns = Some(returns);
        let stmts = body(&mut b, &parameters, returns);
        let f = b.done(stmts);
        let result = f.types.value_width(returns).unwrap();
        self.cases.push(Case {
            f,
            parameters: widths,
            result,
            float: None,
        });
    }

    /// `op(a, b)` at `width` with parameters of `ty`; a comparison's bit
    /// zero-extended to 32.
    fn binary(&mut self, op: Binary, ty: Type, constant: Option<u64>) {
        let width = type_width(&ty);
        let result = if is_compare(op) {
            Type::Int(32)
        } else {
            ty.clone()
        };
        let types = if constant.is_some() {
            vec![ty]
        } else {
            vec![ty.clone(), ty]
        };
        self.add(&format!("{op:?}{width}"), &types, result, |b, p| {
            let a = b.read(p[0]);
            let c = match constant {
                Some(value) => b.c(width, value),
                None => b.read(p[1]),
            };
            let value = b.bin(op, a, c);
            if is_compare(op) {
                b.e(Expr::Extend {
                    signed: false,
                    value,
                    width: 32,
                })
            } else {
                value
            }
        });
    }

    /// `op(a, b)` on the low `width` bits of wider parameters, extended
    /// back (`signed`) to the parameters' width.
    fn narrow_binary(&mut self, op: Binary, wide: u16, width: u16, signed: bool) {
        let ty = if signed {
            Type::Int(wide)
        } else {
            Type::UInt(wide)
        };
        self.add(
            &format!("{op:?}{width}of{wide}"),
            &[ty.clone(), ty.clone()],
            ty,
            |b, p| {
                let x = b.read(p[0]);
                let y = b.read(p[1]);
                let a = b.e(Expr::Extract {
                    value: x,
                    offset: 0,
                    width,
                });
                let c = b.e(Expr::Extract {
                    value: y,
                    offset: 3,
                    width,
                });
                let value = b.bin(op, a, c);
                b.e(Expr::Extend {
                    signed,
                    value,
                    width: wide,
                })
            },
        );
    }

    fn unary(&mut self, op: Unary, wide: u16, width: u16) {
        if op == Unary::ByteSwap && !width.is_multiple_of(8) {
            return;
        }
        let ty = Type::UInt(wide);
        self.add(
            &format!("{op:?}{width}of{wide}"),
            slice::from_ref(&ty),
            ty.clone(),
            |b, p| {
                let x = b.read(p[0]);
                let a = if width == wide {
                    x
                } else {
                    b.e(Expr::Extract {
                        value: x,
                        offset: 0,
                        width,
                    })
                };
                let value = b.e(Expr::Unary(op, a));
                let out = if op == Unary::EvenParity8 { 1 } else { width };
                if out == wide {
                    value
                } else {
                    b.e(Expr::Extend {
                        signed: false,
                        value,
                        width: wide,
                    })
                }
            },
        );
    }

    fn flag(&mut self, op: Flag, width: u16) {
        let ty = Type::UInt(width);
        self.add(
            &format!("{op:?}{width}"),
            &[ty.clone(), ty, Type::Bool(1)],
            Type::Int(32),
            |b, p| {
                let x = b.read(p[0]);
                let y = b.read(p[1]);
                let carry = b.read(p[2]);
                let c = b.e(Expr::Extend {
                    signed: false,
                    value: carry,
                    width,
                });
                let value = b.e(Expr::Flag(op, x, y, c));
                b.e(Expr::Extend {
                    signed: false,
                    value,
                    width: 32,
                })
            },
        );
    }

    fn mul_high(&mut self, width: u16, signed: bool) {
        let ty = if signed {
            Type::Int(width)
        } else {
            Type::UInt(width)
        };
        self.add(
            &format!("mulh{width}"),
            &[ty.clone(), ty.clone()],
            ty,
            |b, p| {
                let x = b.read(p[0]);
                let y = b.read(p[1]);
                let a = b.e(Expr::Extend {
                    signed,
                    value: x,
                    width: width * 2,
                });
                let c = b.e(Expr::Extend {
                    signed,
                    value: y,
                    width: width * 2,
                });
                let product = b.bin(Binary::Mul, a, c);
                b.e(Expr::Extract {
                    value: product,
                    offset: width,
                    width,
                })
            },
        );
    }
}

fn type_width(ty: &Type) -> u16 {
    match ty {
        Type::Int(w) | Type::UInt(w) | Type::Bits(w) | Type::Bool(w) => *w,
        Type::Char { .. } => 8,
        Type::Enum(enumeration) => enumeration.width,
        Type::Float(_)
        | Type::Pointer(_)
        | Type::Code(_)
        | Type::Struct(_)
        | Type::Union(_)
        | Type::Array { .. }
        | Type::Vector { .. } => 64,
    }
}

/// Extensions, truncations and concatenations.
fn mixed(cases: &mut Cases) {
    cases.add("ext", &[Type::Int(64)], Type::UInt(64), |b, p| {
        let x = b.read(p[0]);
        let low = b.e(Expr::Extract {
            value: x,
            offset: 0,
            width: 8,
        });
        let sext = b.e(Expr::Extend {
            signed: true,
            value: low,
            width: 64,
        });
        let mid = b.e(Expr::Extract {
            value: x,
            offset: 8,
            width: 16,
        });
        let zext = b.e(Expr::Extend {
            signed: false,
            value: mid,
            width: 64,
        });
        let odd = b.e(Expr::Extract {
            value: x,
            offset: 3,
            width: 40,
        });
        let odd = b.e(Expr::Extend {
            signed: true,
            value: odd,
            width: 64,
        });
        let sum = b.bin(Binary::Add, sext, zext);
        b.bin(Binary::Xor, sum, odd)
    });
    cases.add(
        "concat",
        &[Type::UInt(32), Type::Int(16)],
        Type::UInt(64),
        |b, p| {
            let x = b.read(p[0]);
            let y = b.read(p[1]);
            let high = b.e(Expr::Extract {
                value: x,
                offset: 4,
                width: 20,
            });
            let part = b.e(Expr::Concat { high, low: y });
            let top = b.e(Expr::Extract {
                value: y,
                offset: 15,
                width: 1,
            });
            let all = b.e(Expr::Concat {
                high: top,
                low: part,
            });
            let pad = b.c(27, 0x05a5_a5a5);
            b.e(Expr::Concat {
                high: pad,
                low: all,
            })
        },
    );
}

/// Comparisons of narrow values, signed and unsigned.
fn comparisons(cases: &mut Cases) {
    cases.add(
        "compares",
        &[Type::Int(8), Type::UInt(8)],
        Type::Int(32),
        |b, p| {
            let x = b.read(p[0]);
            let y = b.read(p[1]);
            let mut bits = Vec::new();
            for op in [
                Binary::ULt,
                Binary::SLt,
                Binary::ULe,
                Binary::SLe,
                Binary::Eq,
            ] {
                bits.push(b.bin(op, x, y));
            }
            let mut acc = bits[0];
            for &bit in &bits[1..] {
                acc = b.e(Expr::Concat {
                    high: bit,
                    low: acc,
                });
            }
            b.e(Expr::Extend {
                signed: false,
                value: acc,
                width: 32,
            })
        },
    );
    cases.add(
        "add8cmp",
        &[Type::UInt(8), Type::UInt(8)],
        Type::Bool(1),
        |b, p| {
            let x = b.read(p[0]);
            let y = b.read(p[1]);
            let sum = b.bin(Binary::Add, x, y);
            b.bin(Binary::ULt, sum, x)
        },
    );
}

/// Selects, logic on conditions, and the most negative constants.
fn selects(cases: &mut Cases) {
    for ty in [Type::Int(32), Type::UInt(32), Type::Bits(32), Type::Int(16)] {
        let width = type_width(&ty);
        cases.add("select", &[ty.clone(), ty.clone()], ty.clone(), |b, p| {
            let x = b.read(p[0]);
            let y = b.read(p[1]);
            let less = b.bin(Binary::SLt, x, y);
            let diff = b.bin(Binary::Sub, y, x);
            let ult = b.bin(Binary::ULt, y, x);
            let inner = b.e(Expr::Select {
                condition: ult,
                then: x,
                otherwise: diff,
            });
            let picked = b.e(Expr::Select {
                condition: less,
                then: x,
                otherwise: inner,
            });
            let minus = b.c(width, u64::MAX);
            b.bin(Binary::Add, picked, minus)
        });
    }
    cases.add(
        "logic",
        &[Type::Int(32), Type::Int(32)],
        Type::Bool(1),
        |b, p| {
            let x = b.read(p[0]);
            let y = b.read(p[1]);
            let zero = b.c(32, 0);
            let negative = b.bin(Binary::SLt, x, zero);
            let nonzero = b.bin(Binary::Ne, y, zero);
            let below = b.bin(Binary::ULt, x, y);
            let both = b.bin(Binary::And, negative, nonzero);
            let either = b.bin(Binary::Or, both, below);
            let not = b.e(Expr::Unary(Unary::Not, either));
            b.bin(Binary::Xor, not, negative)
        },
    );
    cases.add(
        "minconst",
        &[Type::Int(32), Type::Int(64)],
        Type::Int(32),
        |b, p| {
            let x = b.read(p[0]);
            let y = b.read(p[1]);
            let min = b.c(32, 0x8000_0000);
            let min64 = b.c(64, 1 << 63);
            let eq = b.bin(Binary::Eq, x, min);
            let lt = b.bin(Binary::SLt, y, min64);
            let le = b.bin(Binary::SLe, min64, y);
            let both = b.bin(Binary::Xor, eq, lt);
            let both = b.bin(Binary::Or, both, le);
            let ext = b.e(Expr::Extend {
                signed: true,
                value: both,
                width: 32,
            });
            let big = b.c(32, 0xffff_fff0);
            let masked = b.bin(Binary::And, x, big);
            b.bin(Binary::Add, masked, ext)
        },
    );
}

/// Parameters of widths C has no type for, and loads from a buffer.
fn odd(cases: &mut Cases) {
    for (ty, what) in [
        (Type::UInt(24), "u24"),
        (Type::Int(24), "i24"),
        (Type::Int(12), "i12"),
    ] {
        for op in [
            Binary::Add,
            Binary::SLt,
            Binary::ULt,
            Binary::SDiv,
            Binary::LShr,
            Binary::AShr,
            Binary::Mul,
        ] {
            let result = if is_compare(op) {
                Type::Bool(1)
            } else {
                ty.clone()
            };
            cases.add(
                &format!("{what}{op:?}"),
                &[ty.clone(), ty.clone()],
                result,
                |b, p| {
                    let x = b.read(p[0]);
                    let y = b.read(p[1]);
                    b.bin(op, x, y)
                },
            );
        }
    }
    cases.add(
        "load",
        &[Type::Pointer(None), Type::UInt(64)],
        Type::UInt(32),
        |b, p| {
            let base = b.read(p[0]);
            let i = b.read(p[1]);
            let fifteen = b.c(64, 15);
            let index = b.bin(Binary::And, i, fifteen);
            let two = b.c(64, 2);
            let scaled = b.bin(Binary::Mul, index, two);
            let at = b.bin(Binary::Add, base, scaled);
            let u16_ty = b.uint(16);
            let small = b.e(Expr::Load {
                address: at,
                ty: u16_ty,
            });
            let four = b.c(64, 4);
            let at4 = b.bin(Binary::Add, base, four);
            let i32_ty = b.int(32);
            let word = b.e(Expr::Load {
                address: at4,
                ty: i32_ty,
            });
            let wide = b.e(Expr::Extend {
                signed: false,
                value: small,
                width: 32,
            });
            b.bin(Binary::Sub, word, wide)
        },
    );
    // On the `void *` itself: `*(uint32_t *)(a1 + 40 - (a2 & 7) - 3)`.
    cases.add(
        "voidsub",
        &[Type::Pointer(None), Type::UInt(64)],
        Type::UInt(32),
        |b, p| {
            let base = b.read(p[0]);
            let forty = b.c(64, 40);
            let end = b.bin(Binary::Add, base, forty);
            let i = b.read(p[1]);
            let seven = b.c(64, 7);
            let back = b.bin(Binary::And, i, seven);
            let at = b.bin(Binary::Sub, end, back);
            let minus = b.c(64, 3u64.wrapping_neg());
            let at = b.bin(Binary::Add, at, minus);
            let ty = b.uint(32);
            b.e(Expr::Load { address: at, ty })
        },
    );
}

/// Sums, differences and products of a literal whose unsigned value is
/// needed (compared, divided, shifted right, zero-extended): at 32 and 64
/// bits the literal printed unsigned, at 16 bits cast.
fn unsigned_literals(cases: &mut Cases) {
    for width in [16, 32, 64] {
        let ty = Type::Int(width);
        cases.add("ulit", &[ty.clone(), ty], Type::UInt(64), |b, p| {
            let wide = |b: &mut Builder, value| {
                if width_of(b, value) == 64 {
                    value
                } else {
                    b.ext(false, value, 64)
                }
            };
            let (x, fourteen, one) = (b.read(p[0]), b.c(width, 14), b.c(width, 1));
            let less = b.bin(Binary::Sub, x, fourteen);
            let below = b.bin(Binary::ULe, less, one);
            let (y, three, two) = (b.read(p[1]), b.c(width, 3), b.c(width, 2));
            let tripled = b.bin(Binary::Mul, y, three);
            let shifted = b.bin(Binary::LShr, tripled, two);
            let (five, x, seven) = (b.c(width, 5), b.read(p[0]), b.c(width, 7));
            let from = b.bin(Binary::Sub, five, x);
            let quotient = b.bin(Binary::UDiv, from, seven);
            let sum = b.bin(Binary::Add, shifted, quotient);
            let (y, nine) = (b.read(p[1]), b.c(width, 9));
            let next = b.bin(Binary::Add, y, nine);
            let (below, sum, next) = (wide(b, below), wide(b, sum), wide(b, next));
            let total = b.bin(Binary::Add, below, sum);
            b.bin(Binary::Xor, total, next)
        });
    }
}

/// Locals of each signedness (`uint32_t`, `int32_t`, untyped bits) read
/// by operations that need the other (signed and unsigned comparisons,
/// divisions, shifts, extensions, an equality across them, an unsigned
/// comparison and division of a sum with a literal): the value each reads
/// whatever the local's spelling.
fn signs(cases: &mut Cases) {
    let types = [Type::Int(32), Type::UInt(32)];
    cases.add_body("signs", &types, Type::UInt(64), |b, p, _| {
        let (uint, int, bits) = (b.uint(32), b.int(32), b.bits(32));
        let (unsigned, signed, untyped) = (b.local(uint), b.local(int), b.local(bits));
        let (first, second) = (b.read(p[0]), b.read(p[1]));
        let mut body = vec![b.assign(unsigned, first), b.assign(signed, second)];
        let first = b.read(p[0]);
        body.push(b.assign(untyped, first));
        let mut terms = Vec::new();
        for (op, left, right) in [
            (Binary::SLt, unsigned, signed),
            (Binary::ULt, signed, untyped),
            (Binary::SLe, untyped, unsigned),
            (Binary::Eq, unsigned, signed),
        ] {
            let (left, right) = (b.read(left), b.read(right));
            let bit = b.bin(op, left, right);
            terms.push(b.ext(false, bit, 64));
        }
        for (op, var, constant) in [
            (Binary::SDiv, unsigned, 7),
            (Binary::UDiv, signed, 100),
            (Binary::SRem, unsigned, 9),
            (Binary::AShr, unsigned, 3),
            (Binary::LShr, signed, 3),
        ] {
            let (read, constant) = (b.read(var), b.c(32, constant));
            let value = b.bin(op, read, constant);
            terms.push(b.ext(op == Binary::AShr, value, 64));
        }
        for (extend, var) in [(true, untyped), (false, signed), (true, unsigned)] {
            let value = b.read(var);
            terms.push(b.ext(extend, value, 64));
        }
        // `signed - 14U <= 1`, `(signed - 3U) / 100U`.
        let (value, fourteen, one) = (b.read(signed), b.c(32, 14), b.c(32, 1));
        let less = b.bin(Binary::Sub, value, fourteen);
        let below = b.bin(Binary::ULe, less, one);
        terms.push(b.ext(false, below, 64));
        let (value, three, hundred) = (b.read(signed), b.c(32, 3), b.c(32, 100));
        let less = b.bin(Binary::Sub, value, three);
        let quotient = b.bin(Binary::UDiv, less, hundred);
        terms.push(b.ext(false, quotient, 64));
        let mut total = terms[0];
        for (k, &term) in terms.iter().enumerate().skip(1) {
            let rotated = b.c(64, k as u64);
            let term = b.bin(Binary::Shl, term, rotated);
            total = b.bin(Binary::Xor, total, term);
        }
        body.push(b.ret(total));
        body
    });
}

/// Reads of a struct's fields narrower than the fields (the low half of a
/// 64-bit field at its offset, a byte of a pointer field, a byte inside a
/// 32-bit field) beside reads of the whole fields, through a pointer
/// typed as the struct.
fn parts(cases: &mut Cases) {
    let types = [Type::Pointer(None)];
    cases.add_body("parts", &types, Type::UInt(64), |b, p, _| {
        let (int32, int64, uint8, uint32) = (b.int(32), b.int(64), b.uint(8), b.uint(32));
        let char_ty = b.ty(Type::Char { signed: true });
        let chars = b.ty(Type::Pointer(Some(char_ty)));
        let int16 = b.int(16);
        let node = b.ty(Type::Struct(Aggregate {
            name: Some("node".into()),
            size: 32,
            fields: [(0, chars), (16, int64), (24, int32)]
                .into_iter()
                .map(|(offset, ty)| Field {
                    offset,
                    ty,
                    name: Some(format!("field_{offset:x}")),
                })
                .collect(),
        }));
        let to_node = b.ty(Type::Pointer(Some(node)));
        let s = b.local(to_node);
        let base = b.read(p[0]);
        let mut body = vec![b.assign(s, base)];
        let mut terms = Vec::new();
        for (offset, ty, signed) in [
            (16, uint32, false),
            (16, int64, true),
            (0, uint8, false),
            (24, int16, true),
            (25, uint8, false),
            (0, int64, false),
        ] {
            let base = b.read(s);
            let value = b.load_at(base, offset, ty);
            terms.push(if width_of(b, value) == 64 {
                value
            } else {
                b.ext(signed, value, 64)
            });
        }
        let mut total = terms[0];
        for (k, &term) in terms.iter().enumerate().skip(1) {
            let rotated = b.c(64, k as u64 * 7);
            let term = b.bin(Binary::Ror, term, rotated);
            total = b.bin(Binary::Xor, total, term);
        }
        body.push(b.ret(total));
        body
    });
}

/// An IEEE operation of one lane on `operands`, rounded as `rounding`
/// (a 2-bit constant) says.
fn float(
    b: &mut Builder,
    op: FloatOp,
    format: Format,
    rounding: u64,
    operands: &[ExprId],
) -> ExprId {
    let rounding = b.c(2, rounding);
    let first = operands[0];
    let operands = [
        first,
        *operands.get(1).unwrap_or(&first),
        *operands.get(2).unwrap_or(&first),
    ];
    b.e(Expr::Float {
        op,
        format,
        lanes: 1,
        output: FloatOutput::Value,
        rounding,
        operands,
    })
}

/// Float arithmetic on bits, the result's bits returned.
fn floats(cases: &mut Cases) {
    for (format, width) in [(Format::Double, 64), (Format::Single, 32)] {
        let ty = Type::UInt(width);
        for op in [
            FloatOp::Add,
            FloatOp::Sub,
            FloatOp::Mul,
            FloatOp::Div,
            FloatOp::Sqrt,
            FloatOp::MulAdd,
        ] {
            let arity = op.arity();
            let types = vec![ty.clone(); arity];
            cases.add(&format!("{op:?}f{width}"), &types, ty.clone(), |b, p| {
                let operands: Vec<ExprId> = p.iter().map(|&v| b.read(v)).collect();
                float(b, op, format, 0, &operands)
            });
            cases.cases.last_mut().unwrap().float = Some(width);
        }
        cases.add(
            &format!("compare{width}"),
            &[ty.clone(), ty.clone()],
            Type::UInt(8),
            |b, p| {
                let (x, y) = (b.read(p[0]), b.read(p[1]));
                let value = float(b, FloatOp::Compare { signaling: false }, format, 0, &[x, y]);
                b.e(Expr::Extend {
                    signed: false,
                    value,
                    width: 8,
                })
            },
        );
        for rounding in 0..4 {
            cases.add(
                &format!("round{width}r{rounding}"),
                slice::from_ref(&ty),
                ty.clone(),
                |b, p| {
                    let x = b.read(p[0]);
                    float(b, FloatOp::RoundToIntegral, format, rounding, &[x])
                },
            );
            cases.cases.last_mut().unwrap().float = Some(width);
            for signed in [true, false] {
                cases.add(
                    &format!("toint{width}r{rounding}"),
                    slice::from_ref(&ty),
                    Type::UInt(32),
                    |b, p| {
                        let x = b.read(p[0]);
                        float(
                            b,
                            FloatOp::ToInt { signed, width: 32 },
                            format,
                            rounding,
                            &[x],
                        )
                    },
                );
            }
        }
        for signed in [true, false] {
            cases.add(
                &format!("fromint{width}"),
                &[Type::Int(32)],
                ty.clone(),
                |b, p| {
                    let x = b.read(p[0]);
                    float(b, FloatOp::FromInt { signed }, format, 0, &[x])
                },
            );
            cases.cases.last_mut().unwrap().float = Some(width);
        }
    }
    cases.add("narrow", &[Type::UInt(64)], Type::UInt(32), |b, p| {
        let x = b.read(p[0]);
        float(b, FloatOp::Convert(Format::Single), Format::Double, 0, &[x])
    });
    cases.cases.last_mut().unwrap().float = Some(32);
    cases.add("widen", &[Type::UInt(32)], Type::UInt(64), |b, p| {
        let x = b.read(p[0]);
        float(b, FloatOp::Convert(Format::Double), Format::Single, 0, &[x])
    });
    cases.cases.last_mut().unwrap().float = Some(64);
}

/// A loop.
fn control(cases: &mut Cases) {
    cases.add_body(
        "popcount_loop",
        &[Type::UInt(32)],
        Type::Int(32),
        |b, p, int32| {
            let x = p[0];
            let count = b.local(int32);
            let zero = b.c(32, 0);
            let init = b.assign(count, zero);
            let one = b.c(32, 1);
            let value = b.read(x);
            let low = b.bin(Binary::And, value, one);
            let so_far = b.read(count);
            let sum = b.bin(Binary::Add, so_far, low);
            let add = b.assign(count, sum);
            let shifted = b.bin(Binary::LShr, value, one);
            let shift = b.assign(x, shifted);
            let nonzero = b.bin(Binary::Ne, value, zero);
            let looped = b.s(Stmt::While {
                condition: nonzero,
                body: vec![add, shift],
            });
            let ret = b.ret(so_far);
            vec![init, looped, ret]
        },
    );
}

/// An assignment expression on the right of a 1-bit `|`: L2 evaluates
/// both operands, so C must too (`|`, not `||`); `v` is read after.
fn assignments(cases: &mut Cases) {
    cases.add_body(
        "assign_under_or",
        &[Type::Int(32), Type::Int(32)],
        Type::Int(32),
        |b, p, int32| {
            // if (a < 0 | (v = b + 1) == 0) return v + 100; return v;
            let v = b.local(int32);
            let a = b.read(p[0]);
            let zero = b.c(32, 0);
            let negative = b.bin(Binary::SLt, a, zero);
            let read = b.read(p[1]);
            let one = b.c(32, 1);
            let sum = b.bin(Binary::Add, read, one);
            let assigned = b.e(Expr::Assign { var: v, value: sum });
            let wrapped = b.bin(Binary::Eq, assigned, zero);
            let either = b.bin(Binary::Or, negative, wrapped);
            let value = b.read(v);
            let hundred = b.c(32, 100);
            let more = b.bin(Binary::Add, value, hundred);
            let early = b.ret(more);
            let test = b.when(either, vec![early]);
            let late = b.ret(value);
            vec![test, late]
        },
    );
}

/// `continue` and `break` of an outer loop from an inner one.
fn nested(cases: &mut Cases) {
    cases.add_body(
        "nested",
        &[Type::Int(32), Type::Int(32)],
        Type::Int(32),
        |b, p, int32| {
            // for i in 0..a { for j in 0..b { if j == 3 continue outer; if i*j > 20 break outer; s += i ^ j } }
            let (rows, columns) = (p[0], p[1]);
            let (i, j, total) = (b.local(int32), b.local(int32), b.local(int32));
            let zero = b.c(32, 0);
            let s0 = b.assign(total, zero);
            let i0 = b.assign(i, zero);
            let outer = b.placeholder();
            let j0 = b.assign(j, zero);
            let inner = b.placeholder();
            let rj = b.read(j);
            let three = b.c(32, 3);
            let is3 = b.bin(Binary::Eq, rj, three);
            let cont = b.s(Stmt::Continue(outer));
            let if3 = b.s(Stmt::If {
                condition: is3,
                then: vec![cont],
                otherwise: vec![],
            });
            let ri = b.read(i);
            let prod = b.bin(Binary::Mul, ri, rj);
            let twenty = b.c(32, 20);
            let big = b.bin(Binary::SLt, twenty, prod);
            let brk = b.s(Stmt::Break(outer));
            let ifbig = b.s(Stmt::If {
                condition: big,
                then: vec![brk],
                otherwise: vec![],
            });
            let mixed = b.bin(Binary::Xor, ri, rj);
            let rs = b.read(total);
            let sum = b.bin(Binary::Add, rs, mixed);
            let acc = b.assign(total, sum);
            let one = b.c(32, 1);
            let jn = b.bin(Binary::Add, rj, one);
            let jstep = b.assign(j, jn);
            let seven = b.c(32, 7);
            let rc = b.read(columns);
            let and = b.bin(Binary::And, rc, seven);
            let jlt = b.bin(Binary::SLt, rj, and);
            b.set(
                inner,
                Stmt::For {
                    init: vec![],
                    condition: jlt,
                    step: vec![jstep],
                    body: vec![if3, ifbig, acc],
                },
            );
            let in_ = b.bin(Binary::Add, ri, one);
            let istep = b.assign(i, in_);
            let ra = b.read(rows);
            let and_a = b.bin(Binary::And, ra, seven);
            let ilt = b.bin(Binary::SLt, ri, and_a);
            b.set(
                outer,
                Stmt::For {
                    init: vec![i0],
                    condition: ilt,
                    step: vec![istep],
                    body: vec![j0, inner],
                },
            );
            let ret = b.ret(rs);
            vec![s0, outer, ret]
        },
    );
}

/// A switch with a fallthrough and a default sharing an arm.
fn switch(cases: &mut Cases) {
    cases.add_body("switch", &[Type::UInt(8)], Type::Int(32), |b, p, int32| {
        let x = p[0];
        let r = b.local(int32);
        let ten = b.c(32, 10);
        let r0 = b.assign(r, ten);
        let rx = b.read(x);
        let set = |b: &mut Builder, value: u64| {
            let c = b.c(32, value);
            let rr = b.read(r);
            let sum = b.bin(Binary::Add, rr, c);
            b.assign(r, sum)
        };
        let a1 = set(b, 1);
        let a2 = set(b, 100);
        let a3 = set(b, 1000);
        let arms = vec![
            Arm {
                values: vec![Bits::from_u64(8, 1), Bits::from_u64(8, 200)],
                default: false,
                body: vec![a1],
                fallthrough: true,
            },
            Arm {
                values: vec![Bits::from_u64(8, 2)],
                default: false,
                body: vec![a2],
                fallthrough: false,
            },
            Arm {
                values: vec![Bits::from_u64(8, 255)],
                default: true,
                body: vec![a3],
                fallthrough: false,
            },
        ];
        let sw = b.s(Stmt::Switch {
            scrutinee: rx,
            arms,
        });
        let rr = b.read(r);
        let ret = b.ret(rr);
        vec![r0, sw, ret]
    });
}

/// Two values of `width` bits (128, 256 or 512) made of two 64-bit
/// parameters' values, `a:b` and `b:a` repeated (their lanes are often
/// equal, often not).
fn vector_pair(b: &mut Builder, p: &[VarId], width: u16) -> (ExprId, ExprId) {
    let (first, second) = (b.read(p[0]), b.read(p[1]));
    let mut one = b.e(Expr::Concat {
        high: first,
        low: second,
    });
    let mut other = b.e(Expr::Concat {
        high: second,
        low: first,
    });
    while width_of(b, one) < width {
        let (high, low) = (one, other);
        one = b.e(Expr::Concat { high, low });
        other = b.e(Expr::Concat {
            high: low,
            low: high,
        });
    }
    (one, other)
}

/// The width of expression `id`.
fn width_of(b: &Builder, id: ExprId) -> u16 {
    b.f.width(id).unwrap()
}

/// `value` (a multiple of 64 bits) folded to 64 by the exclusive or of
/// its 64-bit parts; narrower, zero-extended.
fn fold(b: &mut Builder, value: ExprId) -> ExprId {
    let width = width_of(b, value);
    if width < 64 {
        return b.ext(false, value, 64);
    }
    let mut acc = b.bits_of(value, 0, 64);
    for part in 1..width / 64 {
        let next = b.bits_of(value, part * 64, 64);
        acc = b.bin(Binary::Xor, acc, next);
    }
    acc
}

/// A constant of `width` bits whose lanes of `lane` bits are `value(i)`.
fn lanes_constant(b: &mut Builder, width: u16, lane: u16, value: impl Fn(u16) -> u64) -> ExprId {
    let bits = (0..width / lane)
        .rev()
        .map(|index| Bits::from_u64(lane, value(index) & mask(lane)))
        .reduce(|high, low| high.concat(&low))
        .unwrap();
    b.e(Expr::Const(bits))
}

/// `op` on `lanes` lanes.
fn lanes(b: &mut Builder, lanes: u16, op: LaneOp, operands: &[ExprId]) -> ExprId {
    let first = operands[0];
    b.e(Expr::Lanes {
        lanes,
        op,
        operands: [
            first,
            *operands.get(1).unwrap_or(&first),
            *operands.get(2).unwrap_or(&first),
        ],
    })
}

/// Lane-wise operations at 128, 256 and 512 bits, and values wider than
/// 128 bits built, taken apart, loaded, compared and chosen between.
#[expect(clippy::too_many_lines, reason = "one case after another")]
fn vectors(cases: &mut Cases) {
    let pair = [Type::UInt(64), Type::UInt(64)];
    for (width, lane_widths) in [
        (128, &[8, 16, 32, 64][..]),
        (256, &[8, 16, 32, 64][..]),
        (512, &[32, 64][..]),
    ] {
        for &w in lane_widths {
            let n = width / w;
            let name = |what: &str| format!("v{width}x{w}{what}");
            for op in [
                Binary::Add,
                Binary::Sub,
                Binary::Mul,
                Binary::And,
                Binary::Or,
                Binary::Xor,
                Binary::Shl,
                Binary::LShr,
                Binary::AShr,
            ] {
                cases.add(&name(&format!("{op:?}")), &pair, Type::UInt(64), |b, p| {
                    let (x, y) = vector_pair(b, p, width);
                    let value = lanes(b, n, LaneOp::Binary(op), &[x, y]);
                    fold(b, value)
                });
            }
            for (what, count) in [("splat", None), ("each", Some(()))] {
                for op in [Binary::Shl, Binary::LShr, Binary::AShr] {
                    cases.add(
                        &name(&format!("{op:?}{what}")),
                        &pair,
                        Type::UInt(64),
                        |b, p| {
                            let (x, _) = vector_pair(b, p, width);
                            let counts = match count {
                                None => lanes_constant(b, width, w, |_| 3),
                                Some(()) => {
                                    lanes_constant(b, width, w, |i| u64::from(i) % u64::from(w))
                                }
                            };
                            let value = lanes(b, n, LaneOp::Binary(op), &[x, counts]);
                            fold(b, value)
                        },
                    );
                }
            }
            cases.add(&name("and_const"), &pair, Type::UInt(64), |b, p| {
                let (x, _) = vector_pair(b, p, width);
                let k = lanes_constant(b, width, w, |_| 0x0f0f_0f0f_0f0f_0f0f);
                let value = lanes(b, n, LaneOp::Binary(Binary::And), &[x, k]);
                fold(b, value)
            });
            for op in [Unary::Not, Unary::Neg] {
                cases.add(&name(&format!("{op:?}")), &pair, Type::UInt(64), |b, p| {
                    let (x, _) = vector_pair(b, p, width);
                    let value = lanes(b, n, LaneOp::Unary(op), &[x]);
                    fold(b, value)
                });
            }
            for op in [
                Binary::Eq,
                Binary::Ne,
                Binary::ULt,
                Binary::ULe,
                Binary::SLt,
                Binary::SLe,
            ] {
                // The mask packed, and spread back to lanes.
                cases.add(
                    &name(&format!("{op:?}bits")),
                    &pair,
                    Type::UInt(64),
                    |b, p| {
                        let (x, y) = vector_pair(b, p, width);
                        let value = lanes(b, n, LaneOp::Binary(op), &[x, y]);
                        fold(b, value)
                    },
                );
                cases.add(
                    &name(&format!("{op:?}lanes")),
                    &pair,
                    Type::UInt(64),
                    |b, p| {
                        let (x, y) = vector_pair(b, p, width);
                        let mask = lanes(b, n, LaneOp::Binary(op), &[x, y]);
                        let signed = LaneOp::Extend {
                            signed: true,
                            width: w,
                        };
                        let value = lanes(b, n, signed, &[mask]);
                        fold(b, value)
                    },
                );
            }
            cases.add(&name("movemask"), &pair, Type::UInt(64), |b, p| {
                let (x, y) = vector_pair(b, p, width);
                let mask = lanes(b, n, LaneOp::Binary(Binary::Eq), &[x, y]);
                let spread = LaneOp::Extend {
                    signed: true,
                    width: w,
                };
                let spread = lanes(b, n, spread, &[mask]);
                let signs = LaneOp::Extract {
                    offset: w - 1,
                    width: 1,
                };
                let value = lanes(b, n, signs, &[spread]);
                fold(b, value)
            });
            for offset in [w - 1, 3] {
                cases.add(
                    &name(&format!("bit{offset}")),
                    &pair,
                    Type::UInt(64),
                    |b, p| {
                        let (x, _) = vector_pair(b, p, width);
                        let bit = LaneOp::Extract { offset, width: 1 };
                        let value = lanes(b, n, bit, &[x]);
                        fold(b, value)
                    },
                );
            }
            cases.add(&name("masks"), &pair, Type::UInt(64), |b, p| {
                let (x, y) = vector_pair(b, p, width);
                let eq = lanes(b, n, LaneOp::Binary(Binary::Eq), &[x, y]);
                let lt = lanes(b, n, LaneOp::Binary(Binary::SLt), &[x, y]);
                let both = lanes(b, n, LaneOp::Binary(Binary::Or), &[eq, lt]);
                let same = lanes(b, n, LaneOp::Binary(Binary::Eq), &[both, lt]);
                let not = lanes(b, n, LaneOp::Unary(Unary::Not), &[same]);
                let bit = LaneOp::Extract {
                    offset: 3,
                    width: 1,
                };
                let third = lanes(b, n, bit, &[x]);
                let mixed = lanes(b, n, LaneOp::Binary(Binary::Xor), &[not, third]);
                let zext = LaneOp::Extend {
                    signed: false,
                    width: w,
                };
                let spread = lanes(b, n, zext, &[mixed]);
                let packed = fold(b, mixed);
                let spread = fold(b, spread);
                b.bin(Binary::Add, packed, spread)
            });
            if n <= 64 {
                // A mask from an integer's bits.
                cases.add(&name("from_bits"), &pair, Type::UInt(64), |b, p| {
                    let (x, y) = vector_pair(b, p, width);
                    let a = b.read(p[0]);
                    let mask = if n == 64 { a } else { b.bits_of(a, 0, n) };
                    let picked = lanes(b, n, LaneOp::Select, &[mask, x, y]);
                    let signed = LaneOp::Extend {
                        signed: true,
                        width: w,
                    };
                    let spread = lanes(b, n, signed, &[mask]);
                    let both = b.bin(Binary::Xor, picked, spread);
                    fold(b, both)
                });
            }
            cases.add(&name("min"), &pair, Type::UInt(64), |b, p| {
                let (x, y) = vector_pair(b, p, width);
                let less = lanes(b, n, LaneOp::Binary(Binary::ULt), &[x, y]);
                let value = lanes(b, n, LaneOp::Select, &[less, x, y]);
                fold(b, value)
            });
            if w >= 16 {
                cases.add(&name("narrow"), &pair, Type::UInt(64), |b, p| {
                    let (x, _) = vector_pair(b, p, width);
                    let low = LaneOp::Extract {
                        offset: 0,
                        width: w / 2,
                    };
                    let high = LaneOp::Extract {
                        offset: w / 2,
                        width: w / 2,
                    };
                    let low = lanes(b, n, low, &[x]);
                    let high = lanes(b, n, high, &[x]);
                    let both = b.e(Expr::Concat { high, low });
                    fold(b, both)
                });
            }
            if width < 512 && w < 64 {
                for signed in [false, true] {
                    cases.add(
                        &name(&format!("widen{signed}")),
                        &pair,
                        Type::UInt(64),
                        |b, p| {
                            let (x, _) = vector_pair(b, p, width);
                            let wider = LaneOp::Extend {
                                signed,
                                width: w * 2,
                            };
                            let value = lanes(b, n, wider, &[x]);
                            fold(b, value)
                        },
                    );
                }
            }
        }
    }
    wide(cases);
}

/// `p[0] + p[1]'s bits 8..24 + its bits 32..64`, each read as a lane of
/// `zext.512(concat(p[1], p[0]))` (a `zmm` register the 128-bit value was
/// written to): directly, and through the low half of a concatenation
/// of its low 256 bits under all ones.
fn wide_lanes(b: &mut Builder, p: &[VarId]) -> ExprId {
    let (first, second) = (b.read(p[0]), b.read(p[1]));
    let value = b.e(Expr::Concat {
        high: second,
        low: first,
    });
    let register = b.ext(false, value, 512);
    let lane0 = b.bits_of(register, 0, 64);
    let lane1 = b.bits_of(register, 72, 16);
    let lane1 = b.ext(false, lane1, 64);
    let half = b.bits_of(register, 0, 256);
    let ones = b.e(Expr::Const(Bits::ones(256)));
    let under = b.e(Expr::Concat {
        high: ones,
        low: half,
    });
    let part = b.bits_of(under, 0, 384);
    let lane2 = b.bits_of(part, 96, 32);
    let lane2 = b.ext(false, lane2, 64);
    let sum = b.bin(Binary::Add, lane0, lane1);
    b.bin(Binary::Add, sum, lane2)
}

#[test]
fn a_lane_of_a_wide_register_prints_as_its_element() {
    let mut b = Builder::new(0x1000, "lanes");
    let uint64 = b.uint(64);
    b.f.returns = Some(uint64);
    let p = [b.param(uint64), b.param(uint64)];
    let value = wide_lanes(&mut b, &p);
    let ret = b.ret(value);
    let f = b.done(vec![ret]);
    let (text, _) = print(&f, &Style::kr());
    let body = &text[text.find("lanes(").unwrap()..];
    // No vector of the register's lanes: the parameters' own bits.
    assert!(!body.contains("x4") && !body.contains("x8"), "{text}");
    assert!(body.contains("return a1 + "), "{text}");
}

/// Values wider than 128 bits as wholes: built, taken apart, extended,
/// bitwise, compared, chosen between, held in a variable and loaded.
#[expect(clippy::too_many_lines, reason = "one case after another")]
fn wide(cases: &mut Cases) {
    let pair = [Type::UInt(64), Type::UInt(64)];
    // A scalar in the low bits of a 512-bit register, the rest constant.
    cases.add("w512low", &pair, Type::UInt(64), |b, p| {
        let first = b.read(p[0]);
        let top = b.e(Expr::Const(Bits::ones(448)));
        let register = b.e(Expr::Concat {
            high: top,
            low: first,
        });
        let low = b.bits_of(register, 0, 128);
        let low = b.bits_of(low, 0, 64);
        let middle = b.bits_of(register, 8, 32);
        let middle = b.ext(false, middle, 64);
        b.bin(Binary::Sub, low, middle)
    });
    // Lanes of a 512-bit register a 128-bit value was written to, read
    // through its extension, a concatenation and an extraction.
    cases.add("w512lanes", &pair, Type::UInt(64), wide_lanes);
    // Lanes in order: four different 64-bit values, read back by position.
    cases.add("w256order", &pair, Type::UInt(64), |b, p| {
        let (first, second) = (b.read(p[0]), b.read(p[1]));
        let one = b.c(64, 1);
        let third = b.bin(Binary::Add, first, one);
        let fourth = b.bin(Binary::Sub, second, one);
        let low = b.e(Expr::Concat {
            high: second,
            low: first,
        });
        let high = b.e(Expr::Concat {
            high: fourth,
            low: third,
        });
        let whole = b.e(Expr::Concat { high, low });
        let three = b.c(64, 3);
        let mut acc = b.c(64, 0);
        for part in 0..4 {
            let lane = b.bits_of(whole, part * 64, 64);
            let scaled = b.bin(Binary::Mul, acc, three);
            acc = b.bin(Binary::Add, scaled, lane);
        }
        acc
    });
    // A broadcast: one byte concatenated 32 times.
    cases.add("w256splat", &pair, Type::UInt(64), |b, p| {
        let first = b.read(p[0]);
        let byte = b.bits_of(first, 8, 8);
        let mut splat = byte;
        for _ in 1..32 {
            splat = b.e(Expr::Concat {
                high: byte,
                low: splat,
            });
        }
        let (x, _) = vector_pair(b, p, 256);
        let sum = lanes(b, 32, LaneOp::Binary(Binary::Add), &[x, splat]);
        fold(b, sum)
    });
    for width in [256, 512] {
        cases.add(&format!("w{width}parts"), &pair, Type::UInt(64), |b, p| {
            let (x, y) = vector_pair(b, p, width);
            let k = lanes_constant(b, width, 64, |i| {
                0x0123_4567_89ab_cdef_u64.rotate_left(u32::from(i) * 8)
            });
            let mixed = b.bin(Binary::Xor, x, k);
            let not = b.e(Expr::Unary(Unary::Not, y));
            let both = b.bin(Binary::And, mixed, not);
            let mut acc = fold(b, both);
            for (offset, part) in [
                (32, 32),
                (72, 40),
                (width - 8, 8),
                (128, 128),
                (width - 128, 128),
            ] {
                let piece = b.bits_of(both, offset, part);
                let piece = if part == 128 {
                    fold(b, piece)
                } else {
                    b.ext(false, piece, 64)
                };
                acc = b.bin(Binary::Add, acc, piece);
            }
            if width == 512 {
                for offset in [0, 256] {
                    let half = b.bits_of(both, offset, 256);
                    let half = fold(b, half);
                    acc = b.bin(Binary::Sub, acc, half);
                }
            }
            acc
        });
        cases.add(
            &format!("w{width}compare"),
            &pair,
            Type::UInt(64),
            |b, p| {
                let (x, y) = vector_pair(b, p, width);
                let eq = b.bin(Binary::Eq, x, y);
                let ne = b.bin(Binary::Ne, x, x);
                let a = b.read(p[0]);
                let c = b.read(p[1]);
                let less = b.bin(Binary::ULt, a, c);
                let chosen = b.e(Expr::Select {
                    condition: less,
                    then: x,
                    otherwise: y,
                });
                let chosen = fold(b, chosen);
                let eq = b.ext(false, eq, 64);
                let ne = b.ext(false, ne, 64);
                let flags = b.bin(Binary::Or, eq, ne);
                b.bin(Binary::Add, chosen, flags)
            },
        );
        cases.add(&format!("w{width}extend"), &pair, Type::UInt(64), |b, p| {
            let (x, _) = vector_pair(b, p, 128);
            let a = b.read(p[0]);
            let wide_x = b.ext(false, x, width);
            let wide_a = b.ext(false, a, width);
            let both = b.bin(Binary::Or, wide_x, wide_a);
            let mut acc = fold(b, both);
            if width == 512 {
                let (half, _) = vector_pair(b, p, 256);
                let half = b.ext(false, half, 512);
                let top = b.bits_of(half, 256, 64);
                let folded = fold(b, half);
                acc = b.bin(Binary::Add, acc, folded);
                acc = b.bin(Binary::Add, acc, top);
            }
            acc
        });
        cases.add_body(
            &format!("w{width}variable"),
            &pair,
            Type::UInt(64),
            |b, p, _| {
                let bits = b.bits(width);
                let held = b.local(bits);
                let (x, y) = vector_pair(b, p, width);
                let first = b.assign(held, x);
                let a = b.read(p[0]);
                let c = b.read(p[1]);
                let less = b.bin(Binary::ULt, a, c);
                let second = b.assign(held, y);
                let test = b.when(less, vec![second]);
                let read = b.read(held);
                let folded = fold(b, read);
                let ret = b.ret(folded);
                vec![first, test, ret]
            },
        );
    }
    cases.add(
        "w256load",
        &[Type::Pointer(None), Type::UInt(64)],
        Type::UInt(64),
        |b, p| {
            let base = b.read(p[0]);
            let i = b.read(p[1]);
            let seven = b.c(64, 7);
            let index = b.bin(Binary::And, i, seven);
            let at = b.bin(Binary::Add, base, index);
            let bits = b.bits(256);
            let loaded = b.e(Expr::Load {
                address: at,
                ty: bits,
            });
            let x = b.read(p[1]);
            let count = b.ext(false, x, 256);
            let value = lanes(b, 8, LaneOp::Binary(Binary::Add), &[loaded, count]);
            fold(b, value)
        },
    );
}

fn cases() -> Vec<Case> {
    let mut cases = Cases { cases: Vec::new() };
    for width in [8, 16, 32, 64] {
        for op in BINARY {
            for ty in [Type::Int(width), Type::UInt(width)] {
                cases.binary(op, ty, None);
            }
            for constant in [7, mask(width), 1 << (width - 1), 3] {
                // `x <= max` and `x < min` always hold or never: C
                // compilers warn, and L2 should have folded them.
                let tautology = (op == Binary::ULe && constant == mask(width))
                    || (op == Binary::SLt && constant == 1 << (width - 1));
                if tautology {
                    continue;
                }
                cases.binary(op, Type::Int(width), Some(constant));
            }
        }
        for op in UNARY {
            cases.unary(op, width, width);
        }
        cases.binary(Binary::Add, Type::Bits(width), None);
        cases.binary(Binary::SLt, Type::Bits(width), None);
    }
    for (wide, width) in [(32, 5), (32, 24), (64, 40), (32, 1)] {
        for op in BINARY {
            if is_compare(op) {
                continue;
            }
            for signed in [false, true] {
                cases.narrow_binary(op, wide, width, signed);
            }
        }
        for op in UNARY {
            cases.unary(op, wide, width);
        }
    }
    for width in [8, 16, 32, 64] {
        for op in [
            Flag::AddCarry,
            Flag::AddOverflow,
            Flag::SubBorrow,
            Flag::SubOverflow,
            Flag::NibbleCarry,
        ] {
            cases.flag(op, width);
        }
    }
    for width in [8, 16, 32, 64] {
        cases.mul_high(width, false);
        cases.mul_high(width, true);
    }
    mixed(&mut cases);
    comparisons(&mut cases);
    unsigned_literals(&mut cases);
    signs(&mut cases);
    parts(&mut cases);
    selects(&mut cases);
    odd(&mut cases);
    floats(&mut cases);
    control(&mut cases);
    assignments(&mut cases);
    nested(&mut cases);
    switch(&mut cases);
    vectors(&mut cases);
    float_lanes(&mut cases);
    cases.cases
}

/// Constants of vectors of floats (their literals, `(f32x4){1.0f, …}`, and
/// where a lane is no number, their bits) assigned to a local of that
/// type: each lane's bits read back, the exclusive or of their 64-bit
/// parts with the first parameter.
fn float_lanes(cases: &mut Cases) {
    let pair = [Type::UInt(64), Type::UInt(64)];
    let cases_of: [(&str, Format, u16, [u64; 4]); 3] = [
        // 1, -0, the least denormal, the greatest float.
        (
            "f32x4",
            Format::Single,
            32,
            [0x3f80_0000, 0x8000_0000, 0x0000_0001, 0x7f7f_ffff],
        ),
        // A NaN: no literal.
        (
            "f32x4nan",
            Format::Single,
            32,
            [0x3f80_0000, 0x7fc0_0001, 0x4000_0000, 0x4040_0000],
        ),
        // 0.1 and -2.5.
        (
            "f64x2",
            Format::Double,
            64,
            [0x3fb9_9999_9999_999a, 0xc004_0000_0000_0000, 0, 0],
        ),
    ];
    for (what, format, bits, lanes) in cases_of {
        cases.add_body(what, &pair, Type::UInt(64), |b, p, _| {
            let element = b.ty(Type::Float(format));
            let count = 128 / bits;
            let ty = b.ty(Type::Vector {
                lanes: count,
                element,
            });
            let v = b.local(ty);
            let value = lanes_constant(b, 128, bits, |i| lanes[usize::from(i)]);
            let set = b.assign(v, value);
            let read = b.read(v);
            let folded = fold(b, read);
            let first = b.read(p[0]);
            let result = b.bin(Binary::Xor, folded, first);
            let ret = b.ret(result);
            vec![set, ret]
        });
    }
}

/// The C program: every case's function, then `main` printing each
/// result for each input, in hex.
fn program(cases: &[Case], inputs: &[Vec<Vec<u64>>], style: &Style) -> String {
    let mut text = String::from("#include <stdio.h>\n");
    for case in cases {
        text.push_str(&print(&case.f, style).0);
        text.push('\n');
    }
    let bytes: Vec<String> = buffer().iter().map(|b| format!("{b}")).collect();
    writeln!(
        text,
        "static unsigned char buffer[64] = {{{}}};",
        bytes.join(", ")
    )
    .unwrap();
    for (index, rows) in inputs.iter().enumerate() {
        let arity = cases[index].parameters.len();
        writeln!(
            text,
            "static const unsigned long long in_{index}[][{arity}] = {{"
        )
        .unwrap();
        for row in rows {
            let values: Vec<String> = row.iter().map(|v| format!("{v:#x}ULL")).collect();
            writeln!(text, "    {{{}}},", values.join(", ")).unwrap();
        }
        text.push_str("};\n");
    }
    text.push_str("int main(void) {\n");
    for (index, case) in cases.iter().enumerate() {
        let name = case.f.name.clone().unwrap();
        let arguments: Vec<String> = case
            .parameters
            .iter()
            .enumerate()
            .map(|(position, p)| match p {
                Some(_) => format!("row[{position}]"),
                None => "buffer".to_owned(),
            })
            .collect();
        writeln!(
            text,
            "    for (size_t i = 0; i < sizeof in_{index} / sizeof in_{index}[0]; i++) {{\n        const unsigned long long *row = in_{index}[i];\n        (void)row;\n        printf(\"%llx\\n\", (unsigned long long){name}({}));\n    }}",
            arguments.join(", ")
        )
        .unwrap();
    }
    text.push_str("    return 0;\n}\n");
    text
}

/// The value of a parameter of `width` bits for C: sign-extended when its
/// type is signed (the container's invariant).
fn interpret(case: &Case, row: &[u64]) -> u64 {
    let arguments: Vec<Value> = case
        .parameters
        .iter()
        .zip(row)
        .map(|(p, &v)| match p {
            Some(width) => Value::defined(Bits::from_u64(*width, v)),
            None => Value::defined(Bits::from_u64(64, BUFFER)),
        })
        .collect();
    let mut memory = Memory { bytes: buffer() };
    match run(&case.f, &mut memory, &arguments, 0x8000, 100_000) {
        Outcome::Returned(Some(value)) => value.bits.low_u64() & mask(case.result),
        other @ (Outcome::Returned(None)
        | Outcome::Call { .. }
        | Outcome::Trap(_)
        | Outcome::Fault(_)
        | Outcome::Escape { .. }
        | Outcome::Unreachable(_)
        | Outcome::Propagated(_)
        | Outcome::Undetermined
        | Outcome::OutOfFuel
        | Outcome::Malformed) => panic!("{}: {other:?} for {row:x?}", case.f.name.clone().unwrap()),
    }
}

#[test]
fn printed_c_means_what_l2_means() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped: no C compiler to check with");
        return;
    }
    let cases = cases();
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let inputs: Vec<Vec<Vec<u64>>> = cases
        .iter()
        .map(|case| inputs(&case.parameters, &mut random))
        .collect();
    let rows: Vec<Vec<Vec<u64>>> = cases
        .iter()
        .zip(&inputs)
        .map(|(case, rows)| rows.iter().map(|row| c_row(case, row)).collect())
        .collect();
    let expected: Vec<Vec<u64>> = cases
        .iter()
        .zip(&inputs)
        .map(|(case, rows)| rows.iter().map(|row| interpret(case, row)).collect())
        .collect();
    let scratch = Scratch::new("meaning");
    let mut runs = 0;
    let mut differences = Vec::new();
    let mut warning_count = 0;
    // Both integer spellings: fixed-width (every preset's) and C's own
    // names (whose 64-bit `long` must mean the same).
    for style in [
        Style::kr(),
        Style::llvm().with_int_spelling(IntSpelling::Plain),
    ] {
        scratch.write("meaning.c", &program(&cases, &rows, &style));
        for &compiler in &compilers {
            for opt in ["-O0", "-O2"] {
                let stderr = scratch
                    .compile(
                        compiler,
                        &[opt, "-o", "meaning", "-Wno-unused-function"],
                        &["meaning.c", "-lm"],
                    )
                    .unwrap_or_else(|e| panic!("{compiler} {opt}: {e}"));
                warning_count += warnings(&stderr);
                if warnings(&stderr) > 0 {
                    eprintln!("{compiler} {opt}:\n{stderr}");
                }
                let output = scratch.run("meaning");
                let mut lines = output.lines();
                for (index, case) in cases.iter().enumerate() {
                    for (row, &want) in inputs[index].iter().zip(&expected[index]) {
                        let got = u64::from_str_radix(lines.next().unwrap(), 16).unwrap()
                            & mask(case.result);
                        runs += 1;
                        if !same(case, got, want) {
                            differences.push(format!(
                                "{} {compiler} {opt}: {row:x?}: L2 {want:#x}, C {got:#x}",
                                case.f.name.clone().unwrap()
                            ));
                        }
                    }
                }
            }
        }
    }
    let total_inputs: usize = inputs.iter().map(Vec::len).sum();
    eprintln!(
        "meaning: {} functions, {total_inputs} inputs, {} compilers x 2 optimisation levels x 2 styles: {runs} runs, {} differences, {warning_count} warnings",
        cases.len(),
        compilers.len(),
        differences.len()
    );
    show(&differences, &cases);
    assert!(differences.is_empty(), "{} differences", differences.len());
    assert_eq!(warning_count, 0);
}

/// A row of inputs as C passes them: a parameter of a signed type C
/// holds sign-extended in its container.
fn c_row(case: &Case, row: &[u64]) -> Vec<u64> {
    row.iter()
        .zip(&case.parameters)
        .zip(case.f.parameters.iter())
        .map(|((&v, p), &var)| {
            let ty = case.f.var(var).unwrap().ty;
            match (p, case.f.types.get(ty)) {
                (Some(width), Some(Type::Int(_))) => Bits::from_u64(*width, v).sext(64).low_u64(),
                _ => v,
            }
        })
        .collect()
}

/// Whether C's result is L2's: equal, or both NaNs of a float result.
fn same(case: &Case, got: u64, want: u64) -> bool {
    let nan = |bits: u64, width: u16| {
        let (exponent, fraction) = if width == 64 { (0x7ff, 52) } else { (0xff, 23) };
        (bits >> fraction) & exponent == exponent && bits & ((1 << fraction) - 1) != 0
    };
    got == want || case.float.is_some_and(|w| nan(got, w) && nan(want, w))
}

/// The first differences, and the C of their functions.
fn show(differences: &[String], cases: &[Case]) {
    let mut shown = BTreeSet::new();
    for difference in differences.iter().take(400) {
        let name = difference.split(' ').next().unwrap().to_owned();
        if shown.insert(name.clone()) && shown.len() <= 12 {
            eprintln!("{difference}");
            let case = cases
                .iter()
                .find(|c| c.f.name.as_deref() == Some(&name))
                .unwrap();
            eprintln!("{}", print(&case.f, &Style::kr()).0);
        }
    }
}
