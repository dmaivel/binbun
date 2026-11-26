#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Copy propagation, dead code, narrowing and the rewrite pass on
//! hand-built L2: what each does, and where each must not (a write in
//! between, a store before a load, a value read twice, an undefined
//! value into a loop, a load's fault, a variable read whole, out of
//! fuel).

use std::fmt::Write as _;

use binbun_ast::ir::{
    Call, Callee, Expr, ExprId, Function, Logical, Origin, Place, Stmt, StmtId, VarId, VarKind,
    Variable,
};
use binbun_ast::types::{Evidence, Signature, Type, Types};
use binbun_decompile::itanium::NONE;
use binbun_decompile::pass::{self, Feeds, L2Env};
use binbun_decompile::simplify::coalesce::Coalesce;
use binbun_decompile::simplify::copies::{Narrow, Propagate, Prune};
use binbun_decompile::simplify::rules::Rewrite;
use binbun_decompile::simplify::sink::Sink;
use binbun_decompile::structure::Loops;
use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Fuel, Manager, Pass, Refusal};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_ssa::ir::{
    BlockId, Definition, Function as L1, Inst, InstId, Op, Type as L1Type, Unknown, Value,
    ValueInfo,
};

const DECLARATIONS: Declarations = Declarations {
    registers: &[],
    intrinsics: &[],
    sites: &[],
};

struct Builder {
    f: Function,
}

impl Builder {
    fn new() -> Self {
        Self {
            f: Function::new(0x1000, Types::new(64)),
        }
    }

    fn var(&mut self, kind: VarKind, width: u16) -> VarId {
        let ty = self.f.types.intern(Type::Bits(width));
        let id = self.f.add_var(Variable {
            kind,
            name: None,
            ty,
            evidence: Evidence::Default,
            origins: Vec::new(),
        });
        if kind == VarKind::Parameter {
            self.f.parameters.push(id);
        }
        id
    }

    fn e(&mut self, expr: Expr) -> ExprId {
        self.f.add_expr(expr)
    }

    fn c(&mut self, width: u16, value: u64) -> ExprId {
        self.e(Expr::Const(Bits::from_u64(width, value)))
    }

    fn read(&mut self, var: VarId) -> ExprId {
        self.e(Expr::Var(var))
    }

    fn bin(&mut self, op: Binary, a: ExprId, b: ExprId) -> ExprId {
        self.e(Expr::Binary(op, a, b))
    }

    fn load(&mut self, pointer: VarId, width: u16) -> ExprId {
        let address = self.read(pointer);
        let ty = self.f.types.intern(Type::Bits(width));
        self.e(Expr::Load { address, ty })
    }

    fn stmt(&mut self, stmt: Stmt) -> StmtId {
        self.f.add_stmt(stmt)
    }

    fn push(&mut self, stmt: Stmt) -> StmtId {
        let id = self.stmt(stmt);
        self.f.body.push(id);
        id
    }

    fn assign(&mut self, var: VarId, value: ExprId) -> StmtId {
        self.push(Stmt::Assign {
            place: Place::Var(var),
            value,
        })
    }

    fn ret(&mut self, value: ExprId) -> StmtId {
        let ty = self
            .f
            .types
            .intern(Type::Bits(self.f.width(value).unwrap()));
        self.f.returns = Some(ty);
        self.push(Stmt::Return(Some(value)))
    }

    /// Runs `passes` in order with `fuel` per node (verifier after each
    /// change): the refusals.
    fn run(
        &mut self,
        passes: &mut [&mut dyn Pass<Function, L2Env<'static>>],
        fuel: u64,
    ) -> Vec<Refusal> {
        let env = L2Env {
            declarations: &DECLARATIONS,
            exceptions: &NONE,
            feeds: None,
        };
        let mut manager = Manager::new(Fuel::new(fuel.saturating_mul(pass::size(&self.f))))
            .with_verifier(pass::verify);
        for pass in passes {
            manager.run(&mut **pass, &mut self.f, &env).unwrap();
        }
        manager
            .refusals()
            .iter()
            .map(|(_, refusal)| refusal.clone())
            .collect()
    }

    fn copies(&mut self) {
        let refusals = self.run(&mut [&mut Propagate, &mut Prune], 64);
        assert!(refusals.is_empty(), "{refusals:?}");
    }

    /// The text of expression `id`.
    fn text(&self, id: ExprId) -> String {
        let mut out = String::new();
        let mut work = vec![Err(id)];
        while let Some(item) = work.pop() {
            match item {
                Ok(text) => out.push_str(text),
                Err(id) => match *self.f.expr(id).unwrap() {
                    Expr::Const(bits) => write!(out, "{:#x}", bits.low_u128()).unwrap(),
                    Expr::Var(var) => write!(out, "v{}", var.0).unwrap(),
                    Expr::Binary(op, a, b) => {
                        write!(out, "{op:?}(").unwrap();
                        work.extend([Ok(")"), Err(b), Ok(", "), Err(a)]);
                    }
                    other @ (Expr::Undefined(..)
                    | Expr::Logical(..)
                    | Expr::AddressOf(_)
                    | Expr::Unary(..)
                    | Expr::Flag(..)
                    | Expr::Extract { .. }
                    | Expr::Concat { .. }
                    | Expr::Extend { .. }
                    | Expr::Select { .. }
                    | Expr::Lanes { .. }
                    | Expr::Float { .. }
                    | Expr::Cast { .. }
                    | Expr::Load { .. }
                    | Expr::Call(_)
                    | Expr::Exception { .. }
                    | Expr::Assign { .. }) => write!(out, "{other:?}").unwrap(),
                },
            }
        }
        out
    }

    fn returned(&self, id: StmtId) -> String {
        let Some(&Stmt::Return(Some(value))) = self.f.stmt(id) else {
            panic!("not a return");
        };
        self.text(value)
    }
}

#[test]
fn a_value_read_once_moves_into_its_reader_and_its_assignment_goes() {
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 32);
    let x = b.read(p);
    let one = b.c(32, 1);
    let sum = b.bin(Binary::Add, x, one);
    b.assign(v, sum);
    let read = b.read(v);
    let ret = b.ret(read);
    b.copies();
    assert_eq!(b.returned(ret), "Add(v0, 0x1)");
    assert_eq!(b.f.body, vec![ret]);
}

#[test]
fn a_copy_moves_into_every_reader() {
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 32);
    let x = b.read(p);
    b.assign(v, x);
    let (r1, r2) = (b.read(v), b.read(v));
    let sum = b.bin(Binary::Add, r1, r2);
    let ret = b.ret(sum);
    b.copies();
    assert_eq!(b.returned(ret), "Add(v0, v0)");
    assert_eq!(b.f.body, vec![ret]);
}

#[test]
fn a_constant_of_a_char_pointer_moves_into_every_reader_as_that_type() {
    // char *s = 0x2000; return s + s: each reader reads a `char *` (the
    // printer's string literal), with the constant's bits. Null stays a
    // number.
    for (value, typed) in [(0x2000, true), (0, false)] {
        let mut b = Builder::new();
        let character = b.f.types.intern(Type::Char { signed: true });
        let pointer = b.f.types.intern(Type::Pointer(Some(character)));
        let s = b.var(VarKind::Local, 64);
        b.f.variables[s.0 as usize].ty = pointer;
        let constant = b.c(64, value);
        b.assign(s, constant);
        let (r1, r2) = (b.read(s), b.read(s));
        let sum = b.bin(Binary::Add, r1, r2);
        let ret = b.ret(sum);
        b.copies();
        assert_eq!(b.f.body, vec![ret]);
        let Some(&Stmt::Return(Some(returned))) = b.f.stmt(ret) else {
            panic!("not a return");
        };
        let Some(&Expr::Binary(Binary::Add, left, right)) = b.f.expr(returned) else {
            panic!("not a sum");
        };
        for operand in [left, right] {
            let expr = *b.f.expr(operand).unwrap();
            if let Expr::Cast { value: inner, ty } = expr {
                assert!(typed, "null cast");
                assert_eq!(ty, pointer);
                assert_eq!(b.text(inner), format!("{value:#x}"));
            } else if let Expr::Const(bits) = expr {
                assert!(!typed, "constant without its type");
                assert_eq!(bits.low_u128(), u128::from(value));
            } else {
                panic!("{expr:?}");
            }
        }
    }
}

#[test]
fn a_saved_copy_put_back_leaves_no_self_assignment() {
    // v = p; p = v; return p
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 32);
    let x = b.read(p);
    b.assign(v, x);
    let saved = b.read(v);
    b.assign(p, saved);
    let read = b.read(p);
    let ret = b.ret(read);
    b.copies();
    assert_eq!(b.f.body, vec![ret]);
}

#[test]
fn a_load_read_once_moves_and_is_loaded_once() {
    // v = *p; *q = v  ->  *q = *p
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 64);
    let q = b.var(VarKind::Parameter, 64);
    let v = b.var(VarKind::Local, 32);
    let loaded = b.load(p, 32);
    b.assign(v, loaded);
    let address = b.read(q);
    let ty = b.f.types.intern(Type::Bits(32));
    let value = b.read(v);
    let store = b.push(Stmt::Assign {
        place: Place::Memory { address, ty },
        value,
    });
    b.copies();
    assert_eq!(b.f.body, vec![store]);
    let Some(&Stmt::Assign { value, .. }) = b.f.stmt(store) else {
        unreachable!()
    };
    assert!(matches!(b.f.expr(value), Some(Expr::Load { .. })));
}

#[test]
fn a_moved_loads_assignment_goes_without_dead_code() {
    // v = *p; *q = v  ->  *q = *p by propagation alone: no assignment of
    // an unknown value is left for dead code (which may run out of fuel)
    // to remove.
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 64);
    let q = b.var(VarKind::Parameter, 64);
    let v = b.var(VarKind::Local, 32);
    let loaded = b.load(p, 32);
    b.assign(v, loaded);
    let address = b.read(q);
    let ty = b.f.types.intern(Type::Bits(32));
    let value = b.read(v);
    let store = b.push(Stmt::Assign {
        place: Place::Memory { address, ty },
        value,
    });
    let refusals = b.run(&mut [&mut Propagate], 64);
    assert!(refusals.is_empty(), "{refusals:?}");
    assert_eq!(b.f.body, vec![store]);
    let Some(&Stmt::Assign { value, .. }) = b.f.stmt(store) else {
        unreachable!()
    };
    assert!(matches!(b.f.expr(value), Some(Expr::Load { .. })));
}

#[test]
fn a_load_does_not_move_where_it_may_not_be_evaluated() {
    // v = *p; return c == 0 && v == 1: `*p` there would be loaded only
    // when c == 0, so a fault would be lost; v stays. Without the `&&` it
    // moves (a_load_read_once_moves_and_is_loaded_once).
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 64);
    let c = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 32);
    let loaded = b.load(p, 32);
    let assign = b.assign(v, loaded);
    let (rc, zero) = (b.read(c), b.c(32, 0));
    let first = b.bin(Binary::Eq, rc, zero);
    let (rv, one) = (b.read(v), b.c(32, 1));
    let second = b.bin(Binary::Eq, rv, one);
    let both = b.e(Expr::Logical(Logical::And, first, second));
    let ret = b.ret(both);
    b.copies();
    assert_eq!(b.f.body, vec![assign, ret]);
    assert!(matches!(
        b.f.stmt(assign),
        Some(&Stmt::Assign { value, .. }) if matches!(b.f.expr(value), Some(Expr::Load { .. }))
    ));
    // A value that cannot fault moves in all the same.
    let mut b = Builder::new();
    let c = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 32);
    let (rc, two) = (b.read(c), b.c(32, 2));
    let sum = b.bin(Binary::Add, rc, two);
    b.assign(v, sum);
    let (rc, zero) = (b.read(c), b.c(32, 0));
    let first = b.bin(Binary::Eq, rc, zero);
    let (rv, one) = (b.read(v), b.c(32, 1));
    let second = b.bin(Binary::Eq, rv, one);
    let both = b.e(Expr::Logical(Logical::And, first, second));
    let ret = b.ret(both);
    b.copies();
    assert_eq!(b.f.body, vec![ret]);
}

#[test]
fn a_value_does_not_move_past_a_write_to_what_it_reads() {
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 32);
    let x = b.read(p);
    let one = b.c(32, 1);
    let sum = b.bin(Binary::Add, x, one);
    b.assign(v, sum);
    let zero = b.c(32, 0);
    b.assign(p, zero);
    let read = b.read(v);
    let ret = b.ret(read);
    b.copies();
    assert_eq!(b.returned(ret), "v1");
}

#[test]
fn a_value_read_twice_stays_in_its_variable() {
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 32);
    let x = b.read(p);
    let one = b.c(32, 1);
    let sum = b.bin(Binary::Add, x, one);
    b.assign(v, sum);
    let (r1, r2) = (b.read(v), b.read(v));
    let product = b.bin(Binary::Mul, r1, r2);
    let ret = b.ret(product);
    b.copies();
    assert_eq!(b.returned(ret), "Mul(v1, v1)");
}

impl Builder {
    /// `v = f(argument)`, `f` at 0x2000 taking and returning 32 bits.
    fn call(&mut self, v: VarId, argument: ExprId) -> StmtId {
        let int = self.f.types.intern(Type::Bits(32));
        let signature = self.f.types.intern(Type::Code(Signature {
            parameters: vec![int],
            returns: Some(int),
            variadic: false,
        }));
        self.push(Stmt::Call {
            results: vec![Place::Var(v)],
            call: Call {
                callee: Callee::Address(0x2000),
                arguments: vec![argument],
                signature,
                variadic: Vec::new(),
            },
        })
    }
}

#[test]
fn a_call_result_read_once_moves_into_its_reader() {
    // v = f(p); w = p + 1; return v + w  ->  return f(p) + (p + 1)
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let (v, sum_var) = (b.var(VarKind::Local, 32), b.var(VarKind::Local, 32));
    let argument = b.read(p);
    b.call(v, argument);
    let (read_p, one) = (b.read(p), b.c(32, 1));
    let sum = b.bin(Binary::Add, read_p, one);
    b.assign(sum_var, sum);
    let (rv, rw) = (b.read(v), b.read(sum_var));
    let total = b.bin(Binary::Add, rv, rw);
    let ret = b.ret(total);
    b.copies();
    assert_eq!(b.f.body, vec![ret]);
    let Some(&Stmt::Return(Some(value))) = b.f.stmt(ret) else {
        unreachable!()
    };
    let Some(&Expr::Binary(Binary::Add, call, _)) = b.f.expr(value) else {
        panic!("{}", b.returned(ret));
    };
    assert!(matches!(b.f.expr(call), Some(Expr::Call(_))));
}

#[test]
fn a_call_result_stays_past_a_store_beside_a_load_or_read_twice() {
    // v = f(p); *q = 0; return v: the call would move past the store.
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let pointer = b.var(VarKind::Parameter, 64);
    let v = b.var(VarKind::Local, 32);
    let argument = b.read(p);
    let call = b.call(v, argument);
    let address = b.read(pointer);
    let ty = b.f.types.intern(Type::Bits(32));
    let zero = b.c(32, 0);
    let store = b.push(Stmt::Assign {
        place: Place::Memory { address, ty },
        value: zero,
    });
    let read = b.read(v);
    let ret = b.ret(read);
    b.copies();
    assert_eq!(b.f.body, vec![call, store, ret]);

    // v = f(p); w = f(v); return w: the first call moves into the second
    // call's argument (made before it), and that into the return:
    // `return f(f(p))`.
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let (v, second_var) = (b.var(VarKind::Local, 32), b.var(VarKind::Local, 32));
    let argument = b.read(p);
    b.call(v, argument);
    let read = b.read(v);
    b.call(second_var, read);
    let read = b.read(second_var);
    let ret = b.ret(read);
    b.copies();
    assert_eq!(b.f.body, vec![ret]);
    let Some(&Stmt::Return(Some(outer))) = b.f.stmt(ret) else {
        unreachable!()
    };
    let Some(&Expr::Call(outer)) = b.f.expr(outer) else {
        panic!("{}", b.returned(ret));
    };
    let inner = b.f.call(outer).unwrap().arguments[0];
    assert!(matches!(b.f.expr(inner), Some(Expr::Call(_))));

    // v = f(p); w = g(v, *q); return w: C evaluates `*q` in either order
    // with `f`, which may change it; v stays.
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let pointer = b.var(VarKind::Parameter, 64);
    let (v, second_var) = (b.var(VarKind::Local, 32), b.var(VarKind::Local, 32));
    let argument = b.read(p);
    let first = b.call(v, argument);
    let read = b.read(v);
    let loaded = b.load(pointer, 32);
    let int = b.f.types.intern(Type::Bits(32));
    let signature = b.f.types.intern(Type::Code(Signature {
        parameters: vec![int, int],
        returns: Some(int),
        variadic: false,
    }));
    let second = b.push(Stmt::Call {
        results: vec![Place::Var(second_var)],
        call: Call {
            callee: Callee::Address(0x3000),
            arguments: vec![read, loaded],
            signature,
            variadic: Vec::new(),
        },
    });
    let read = b.read(second_var);
    let ret = b.ret(read);
    b.copies();
    assert_eq!(b.f.body, vec![first, ret]);
    let Some(&Stmt::Return(Some(value))) = b.f.stmt(ret) else {
        unreachable!()
    };
    let Some(&Expr::Call(moved)) = b.f.expr(value) else {
        panic!("{:?}", b.f.stmt(second));
    };
    let arguments = &b.f.call(moved).unwrap().arguments;
    assert_eq!(b.f.expr(arguments[0]), Some(&Expr::Var(v)));

    // v = f(p); return v * v: read twice, the call is made once.
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 32);
    let argument = b.read(p);
    let call = b.call(v, argument);
    let (r1, r2) = (b.read(v), b.read(v));
    let product = b.bin(Binary::Mul, r1, r2);
    let ret = b.ret(product);
    b.copies();
    assert_eq!(b.f.body, vec![call, ret]);
    assert_eq!(b.returned(ret), "Mul(v1, v1)");
}

#[test]
fn a_pure_assignment_sinks_past_a_call_to_its_use() {
    // a = p + 1; w = f(q); return a + w  ->  w = f(q); a = p + 1; …
    let mut b = Builder::new();
    let (p, input) = (b.var(VarKind::Parameter, 32), b.var(VarKind::Parameter, 32));
    let (a, result) = (b.var(VarKind::Local, 32), b.var(VarKind::Local, 32));
    let (read_p, one) = (b.read(p), b.c(32, 1));
    let sum = b.bin(Binary::Add, read_p, one);
    let pure = b.assign(a, sum);
    let argument = b.read(input);
    let call = b.call(result, argument);
    let (ra, rw) = (b.read(a), b.read(result));
    let total = b.bin(Binary::Add, ra, rw);
    let ret = b.ret(total);
    let refusals = b.run(&mut [&mut Sink], 64);
    assert!(refusals.is_empty(), "{refusals:?}");
    assert_eq!(b.f.body, vec![call, pure, ret]);
}

#[test]
fn a_pure_assignment_stays_before_what_reads_it_or_writes_what_it_reads() {
    // a = p + 1; w = f(a); return w: f reads a.
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let (a, result) = (b.var(VarKind::Local, 32), b.var(VarKind::Local, 32));
    let (read_p, one) = (b.read(p), b.c(32, 1));
    let sum = b.bin(Binary::Add, read_p, one);
    let pure = b.assign(a, sum);
    let argument = b.read(a);
    let call = b.call(result, argument);
    let read = b.read(result);
    let ret = b.ret(read);
    b.run(&mut [&mut Sink], 64);
    assert_eq!(b.f.body, vec![pure, call, ret]);

    // a = p + 1; p = f(q); return a + p: the call writes what a reads.
    let mut b = Builder::new();
    let (p, input) = (b.var(VarKind::Parameter, 32), b.var(VarKind::Parameter, 32));
    let a = b.var(VarKind::Local, 32);
    let (read_p, one) = (b.read(p), b.c(32, 1));
    let sum = b.bin(Binary::Add, read_p, one);
    let pure = b.assign(a, sum);
    let argument = b.read(input);
    let call = b.call(p, argument);
    let (ra, rp) = (b.read(a), b.read(p));
    let total = b.bin(Binary::Add, ra, rp);
    let ret = b.ret(total);
    b.run(&mut [&mut Sink], 64);
    assert_eq!(b.f.body, vec![pure, call, ret]);

    // a = 1; c = 2; return a + c: nothing but pure assignments to pass,
    // so they keep their order (no swapping back and forth).
    let mut b = Builder::new();
    let (a, other) = (b.var(VarKind::Local, 32), b.var(VarKind::Local, 32));
    let one = b.c(32, 1);
    let first = b.assign(a, one);
    let two = b.c(32, 2);
    let second = b.assign(other, two);
    let (ra, rc) = (b.read(a), b.read(other));
    let total = b.bin(Binary::Add, ra, rc);
    let ret = b.ret(total);
    b.run(&mut [&mut Sink], 64);
    assert_eq!(b.f.body, vec![first, second, ret]);
}

/// Whether statement `id` of `f` is a copy of a variable to itself (what
/// coalescing leaves of a copy).
fn self_copy(f: &Function, id: StmtId) -> bool {
    matches!(f.stmt(id), Some(&Stmt::Assign { place: Place::Var(to), value })
        if f.expr(value) == Some(&Expr::Var(to)))
}

#[test]
fn a_loop_carried_copy_is_coalesced() {
    // s = 0; while (1) { t = s + p; s = t; if (t == 10) break; } return t;
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let (s, t) = (b.var(VarKind::Local, 32), b.var(VarKind::Local, 32));
    let zero = b.c(32, 0);
    b.assign(s, zero);
    let (rs, rp) = (b.read(s), b.read(p));
    let sum = b.bin(Binary::Add, rs, rp);
    let add = b.stmt(Stmt::Assign {
        place: Place::Var(t),
        value: sum,
    });
    let rt = b.read(t);
    let copy = b.stmt(Stmt::Assign {
        place: Place::Var(s),
        value: rt,
    });
    let (rt, ten) = (b.read(t), b.c(32, 10));
    let done = b.bin(Binary::Eq, rt, ten);
    let forever = b.c(1, 1);
    let lp = b.f.add_stmt(Stmt::Unreachable);
    let leave = b.stmt(Stmt::Break(lp));
    let test = b.stmt(Stmt::If {
        condition: done,
        then: vec![leave],
        otherwise: vec![],
    });
    b.f.stmts[lp.0 as usize] = Stmt::While {
        condition: forever,
        body: vec![add, copy, test],
    };
    b.f.body.push(lp);
    let rt = b.read(t);
    b.ret(rt);
    let refusals = b.run(&mut [&mut Coalesce], 64);
    assert!(refusals.is_empty(), "{refusals:?}");
    assert!(self_copy(&b.f, copy), "{:?}", b.f.stmt(copy));
}

#[test]
fn copies_of_one_value_are_coalesced_and_different_values_are_not() {
    // a = p + 1; x = a; y = a; return x * y: all three hold one value.
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let a = b.var(VarKind::Local, 32);
    let (x, copy_y) = (b.var(VarKind::Local, 32), b.var(VarKind::Local, 32));
    let (read_p, one) = (b.read(p), b.c(32, 1));
    let sum = b.bin(Binary::Add, read_p, one);
    b.assign(a, sum);
    let ra = b.read(a);
    let first = b.assign(x, ra);
    let ra = b.read(a);
    let second = b.assign(copy_y, ra);
    let (rx, ry) = (b.read(x), b.read(copy_y));
    let product = b.bin(Binary::Mul, rx, ry);
    let ret = b.ret(product);
    b.run(&mut [&mut Coalesce], 64);
    assert!(self_copy(&b.f, first) && self_copy(&b.f, second));
    assert_eq!(b.returned(ret), "Mul(v1, v1)");

    // x = p; p = p + 1; return x * p: x keeps the old value while p, live
    // too, has the new one.
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let x = b.var(VarKind::Local, 32);
    let read_p = b.read(p);
    let copy = b.assign(x, read_p);
    let (read_p, one) = (b.read(p), b.c(32, 1));
    let sum = b.bin(Binary::Add, read_p, one);
    b.assign(p, sum);
    let (rx, rp) = (b.read(x), b.read(p));
    let product = b.bin(Binary::Mul, rx, rp);
    let ret = b.ret(product);
    let refusals = b.run(&mut [&mut Coalesce], 64);
    assert!(refusals.is_empty(), "{refusals:?}");
    assert!(!self_copy(&b.f, copy));
    assert_eq!(b.returned(ret), "Mul(v1, v0)");
}

/// `i = 0; if (i != n) { do { s = s + i; [n = n + 1;] i = i + 1; } while
/// (i != n); } return s;` with the `if` of block 1 and the loop of block
/// 2; the `if` and the loop.
fn counted(write_bound: bool) -> (Builder, StmtId, StmtId) {
    let mut b = Builder::new();
    let n = b.var(VarKind::Parameter, 32);
    let (i, s) = (b.var(VarKind::Local, 32), b.var(VarKind::Local, 32));
    let zero = b.c(32, 0);
    b.assign(i, zero);
    let (ri, rn) = (b.read(i), b.read(n));
    let guard = b.bin(Binary::Ne, ri, rn);
    let (ri, rn) = (b.read(i), b.read(n));
    let latch = b.bin(Binary::Ne, ri, rn);
    let (rs, ri) = (b.read(s), b.read(i));
    let sum = b.bin(Binary::Add, rs, ri);
    let add = b.stmt(Stmt::Assign {
        place: Place::Var(s),
        value: sum,
    });
    let (ri, one) = (b.read(i), b.c(32, 1));
    let next = b.bin(Binary::Add, ri, one);
    let step = b.stmt(Stmt::Assign {
        place: Place::Var(i),
        value: next,
    });
    let mut body = vec![add];
    if write_bound {
        let (rn, one) = (b.read(n), b.c(32, 1));
        let grown = b.bin(Binary::Add, rn, one);
        body.push(b.stmt(Stmt::Assign {
            place: Place::Var(n),
            value: grown,
        }));
    }
    body.push(step);
    let lp = b.stmt(Stmt::DoWhile {
        body,
        condition: latch,
    });
    b.f.provenance.set_stmt(lp, &[Origin::Block(BlockId(2))]);
    let test = b.push(Stmt::If {
        condition: guard,
        then: vec![lp],
        otherwise: vec![],
    });
    b.f.provenance.set_stmt(test, &[Origin::Block(BlockId(1))]);
    let rs = b.read(s);
    b.ret(rs);
    (b, test, lp)
}

#[test]
fn a_guarded_counted_loop_is_a_for_with_a_proved_less_than() {
    let (mut b, _, lp) = counted(false);
    let refusals = b.run(&mut [&mut Loops::default()], 64);
    assert!(refusals.is_empty(), "{refusals:?}");
    assert_eq!(b.f.body.len(), 2, "the init and the if went into the loop");
    assert_eq!(b.f.body.first(), Some(&lp));
    let Some(&Stmt::For { condition, .. }) = b.f.stmt(lp) else {
        panic!("{:?}", b.f.stmt(lp));
    };
    assert!(matches!(
        b.f.expr(condition),
        Some(Expr::Binary(Binary::ULt, ..))
    ));
    assert_eq!(
        b.f.provenance.stmt(lp),
        &[Origin::Block(BlockId(1)), Origin::Block(BlockId(2))]
    );
}

#[test]
fn an_exit_test_stays_not_equal_where_the_bound_changes_in_the_loop() {
    let (mut b, _, lp) = counted(true);
    b.run(&mut [&mut Loops::default()], 64);
    let Some(&Stmt::For { condition, .. }) = b.f.stmt(lp) else {
        panic!("{:?}", b.f.stmt(lp));
    };
    assert!(matches!(
        b.f.expr(condition),
        Some(Expr::Binary(Binary::Ne, ..))
    ));

    // A guard on another condition than the latch's: no de-inversion.
    let (mut b, test, lp) = counted(false);
    let Some(Stmt::If { condition, .. }) = b.f.stmt(test) else {
        unreachable!()
    };
    let (condition, zero) = (*condition, b.c(32, 0));
    let Some(&Expr::Binary(_, ri, _)) = b.f.expr(condition) else {
        unreachable!()
    };
    let other = b.bin(Binary::Ne, ri, zero);
    if let Some(Stmt::If { condition, .. }) = b.f.stmts.get_mut(test.0 as usize) {
        *condition = other;
    }
    b.run(&mut [&mut Loops::default()], 64);
    assert!(matches!(b.f.stmt(test), Some(Stmt::If { .. })));
    assert!(matches!(b.f.stmt(lp), Some(Stmt::DoWhile { .. })));
}

#[test]
fn a_load_does_not_move_past_a_store_and_is_kept_for_its_fault() {
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 64);
    let v = b.var(VarKind::Local, 32);
    let w = b.var(VarKind::Local, 32);
    let loaded = b.load(p, 32);
    b.assign(v, loaded);
    let address = b.read(p);
    let ty = b.f.types.intern(Type::Bits(32));
    let zero = b.c(32, 0);
    b.push(Stmt::Assign {
        place: Place::Memory { address, ty },
        value: zero,
    });
    let read = b.read(v);
    let ret = b.ret(read);
    // A load nothing reads: its fault stays.
    let unread = b.load(p, 32);
    let dead = b.stmt(Stmt::Assign {
        place: Place::Var(w),
        value: unread,
    });
    b.f.body.insert(0, dead);
    b.copies();
    assert_eq!(b.returned(ret), "v1");
    let Some(&Stmt::Expr(kept)) = b.f.stmt(b.f.body[0]) else {
        panic!("the unread load is gone: {:?}", b.f.body);
    };
    assert!(matches!(b.f.expr(kept), Some(Expr::Load { .. })));
}

#[test]
fn an_undefined_value_does_not_move_into_a_loop() {
    let mut b = Builder::new();
    let v = b.var(VarKind::Local, 32);
    let undefined = b.e(Expr::Undefined(
        32,
        Unknown::Call {
            address: 0x1000,
            register: RegisterId(2),
        },
        None,
    ));
    b.assign(v, undefined);
    let read = b.read(v);
    let zero = b.c(32, 0);
    let condition = b.bin(Binary::Ne, read, zero);
    let body = Vec::new();
    let looped = b.push(Stmt::While { condition, body });
    b.copies();
    let Some(&Stmt::While { condition, .. }) = b.f.stmt(looped) else {
        unreachable!()
    };
    assert_eq!(b.text(condition), "Ne(v0, 0x0)");
}

#[test]
fn a_variable_read_only_in_its_low_bits_is_narrowed() {
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 64);
    let x = b.read(p);
    let wide = b.e(Expr::Extend {
        signed: false,
        value: x,
        width: 64,
    });
    b.assign(v, wide);
    let read = b.read(v);
    let low = b.e(Expr::Extract {
        value: read,
        offset: 0,
        width: 32,
    });
    let ret = b.ret(low);
    let refusals = b.run(&mut [&mut Narrow, &mut Rewrite::default()], 64);
    assert_eq!(refusals, []);
    let Some(&Stmt::Assign {
        place: Place::Var(narrow),
        value,
    }) = b.f.stmt(b.f.body[0])
    else {
        unreachable!()
    };
    assert_eq!(b.f.types.value_width(b.f.var(narrow).unwrap().ty), Some(32));
    assert_eq!(b.text(value), "v0");
    assert_eq!(b.returned(ret), format!("v{}", narrow.0));

    // Read whole as well: not narrowed, but held at the 32 bits that
    // extend into it, each read extending it again.
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 64);
    let x = b.read(p);
    let wide = b.e(Expr::Extend {
        signed: false,
        value: x,
        width: 64,
    });
    b.assign(v, wide);
    let read = b.read(v);
    let ret = b.ret(read);
    let refusals = b.run(&mut [&mut Narrow, &mut Rewrite::default()], 64);
    assert_eq!(refusals, []);
    let Some(&Stmt::Assign {
        place: Place::Var(held),
        value,
    }) = b.f.stmt(b.f.body[0])
    else {
        unreachable!()
    };
    let held_ty = b.f.var(held).unwrap().ty;
    assert_eq!(b.f.types.get(held_ty), Some(&Type::UInt(32)));
    assert_eq!(b.text(value), "v0");
    let Some(&Stmt::Return(Some(returned))) = b.f.stmt(ret) else {
        unreachable!()
    };
    let Some(&Expr::Extend {
        signed: false,
        value: extended,
        width: 64,
    }) = b.f.expr(returned)
    else {
        panic!("not a zero extension: {}", b.text(returned));
    };
    assert_eq!(b.text(extended), format!("v{}", held.0));
}

#[test]
fn a_variable_assigned_extensions_is_held_narrow_only_where_all_are() {
    // Sign extensions, a constant that is one, and an undefined value:
    // held signed at the widest source (16 bits).
    let mut b = Builder::new();
    let byte = b.var(VarKind::Parameter, 8);
    let half = b.var(VarKind::Parameter, 16);
    let v = b.var(VarKind::Local, 64);
    for param in [byte, half] {
        let source = b.read(param);
        let wide = b.e(Expr::Extend {
            signed: true,
            value: source,
            width: 64,
        });
        b.assign(v, wide);
    }
    let minus_one = b.c(64, u64::MAX);
    b.assign(v, minus_one);
    let read = b.read(v);
    b.ret(read);
    b.run(&mut [&mut Narrow], 64);
    let Some(&Stmt::Assign {
        place: Place::Var(held),
        ..
    }) = b.f.stmt(b.f.body[0])
    else {
        unreachable!()
    };
    assert_ne!(held, v);
    let held_ty = b.f.var(held).unwrap().ty;
    assert_eq!(b.f.types.get(held_ty), Some(&Type::Int(16)));

    // Kept: a zero and a sign extension; a constant that is no extension
    // of the widest source; a value read as an address; an unknown value,
    // the architecture's or a call's leftover (held narrow, its high bits
    // would be chosen to extend the low ones).
    let kept = |build: &dyn Fn(&mut Builder, VarId, ExprId)| {
        let mut b = Builder::new();
        let p = b.var(VarKind::Parameter, 32);
        let v = b.var(VarKind::Local, 64);
        let x = b.read(p);
        let wide = b.e(Expr::Extend {
            signed: false,
            value: x,
            width: 64,
        });
        b.assign(v, wide);
        build(&mut b, v, x);
        let before = b.f.clone();
        b.run(&mut [&mut Narrow], 64);
        assert_eq!(b.f, before);
    };
    kept(&|b, v, x| {
        let signed = b.e(Expr::Extend {
            signed: true,
            value: x,
            width: 64,
        });
        b.assign(v, signed);
        let read = b.read(v);
        b.ret(read);
    });
    kept(&|b, v, _| {
        let big = b.c(64, 1 << 32);
        b.assign(v, big);
        let read = b.read(v);
        b.ret(read);
    });
    kept(&|b, v, _| {
        let address = b.read(v);
        let ty = b.f.types.intern(Type::Bits(32));
        let load = b.e(Expr::Load { address, ty });
        b.ret(load);
    });
    for unknown in [
        Unknown::Architecture {
            address: 0x1000,
            register: None,
            site: None,
        },
        Unknown::Call {
            address: 0x1000,
            register: RegisterId(2),
        },
    ] {
        kept(&|b, v, _| {
            let undefined = b.e(Expr::Undefined(64, unknown, None));
            b.assign(v, undefined);
            let read = b.read(v);
            b.ret(read);
        });
    }
}

#[test]
fn a_variable_read_whole_and_assigned_wide_is_kept() {
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 64);
    let v = b.var(VarKind::Local, 64);
    let x = b.read(p);
    b.assign(v, x);
    let read = b.read(v);
    b.ret(read);
    let before = b.f.clone();
    b.run(&mut [&mut Narrow], 64);
    assert_eq!(b.f, before);
}

#[test]
fn rules_rewrite_flag_conditions_and_keep_faults() {
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let q = b.var(VarKind::Parameter, 64);
    let x = b.read(p);
    let shift = b.c(32, 31);
    let sign = b.bin(Binary::LShr, x, shift);
    let zero = b.c(32, 0);
    let test = b.bin(Binary::Ne, sign, zero);
    let is_zero = b.bin(Binary::Eq, x, zero);
    let condition = b.bin(Binary::Or, test, is_zero);
    let then = vec![];
    let tested = b.push(Stmt::If {
        condition,
        then,
        otherwise: Vec::new(),
    });
    // Not the sign: shifted by 30.
    let thirty = b.c(32, 30);
    let other = b.bin(Binary::LShr, x, thirty);
    let other_test = b.bin(Binary::Ne, other, zero);
    let kept = b.push(Stmt::If {
        condition: other_test,
        then: vec![],
        otherwise: Vec::new(),
    });
    // `load * 0` is not 0: the load may fault.
    let loaded = b.load(q, 32);
    let product = b.bin(Binary::Mul, loaded, zero);
    let ret = b.ret(product);
    let refusals = b.run(&mut [&mut Rewrite::default()], 64);
    assert_eq!(refusals, []);
    let condition_of = |b: &Builder, id: StmtId| {
        let Some(&Stmt::If { condition, .. }) = b.f.stmt(id) else {
            unreachable!()
        };
        b.text(condition)
    };
    assert_eq!(condition_of(&b, tested), "SLe(v0, 0x0)");
    assert_eq!(condition_of(&b, kept), "Ne(LShr(v0, 0x1e), 0x0)");
    assert!(b.returned(ret).starts_with("Mul(Load"));
}

#[test]
fn out_of_fuel_the_passes_refuse_and_change_nothing() {
    let mut b = Builder::new();
    let p = b.var(VarKind::Parameter, 32);
    let v = b.var(VarKind::Local, 32);
    let x = b.read(p);
    b.assign(v, x);
    let read = b.read(v);
    let zero = b.c(32, 0);
    let sum = b.bin(Binary::Add, read, zero);
    b.ret(sum);
    let before = b.f.clone();
    let refusals = b.run(
        &mut [&mut Propagate, &mut Prune, &mut Rewrite::default()],
        0,
    );
    assert_eq!(refusals, vec![Refusal::OutOfFuel; 3]);
    assert_eq!(b.f, before);
}

/// The instruction origins at `addresses`.
fn at(addresses: &[u64]) -> Vec<Origin> {
    addresses.iter().copied().map(Origin::Instruction).collect()
}

#[test]
fn a_rewrite_stands_for_what_it_matched() {
    let mut b = Builder::new();
    // `p + 0` is `p`, a node kept (which may stand elsewhere): the
    // instructions of the `+ 0` go to the statement.
    let p = b.var(VarKind::Parameter, 32);
    let read = b.read(p);
    let zero = b.c(32, 0);
    let plus = b.bin(Binary::Add, read, zero);
    b.f.provenance.set_expr(zero, &at(&[0x20]));
    b.f.provenance.set_expr(plus, &at(&[0x24]));
    let kept = b.push(Stmt::Expr(plus));
    b.f.provenance.set_stmt(kept, &at(&[0x28]));
    // `1 + 2`, each node from an instruction: the 3 it folds to is from
    // the three.
    let one = b.c(32, 1);
    let two = b.c(32, 2);
    let sum = b.bin(Binary::Add, one, two);
    for (id, address) in [(one, 0x10), (two, 0x14), (sum, 0x18)] {
        b.f.provenance.set_expr(id, &at(&[address]));
    }
    let ret = b.ret(sum);
    let refusals = b.run(&mut [&mut Rewrite::default()], 64);
    assert_eq!(refusals, []);
    let Some(&Stmt::Return(Some(three))) = b.f.stmt(ret) else {
        unreachable!()
    };
    assert_eq!(b.text(three), "0x3");
    assert_eq!(b.f.provenance.expr(three), at(&[0x18, 0x10, 0x14]));
    assert_eq!(b.f.stmt(kept), Some(&Stmt::Expr(read)));
    assert_eq!(b.f.provenance.expr(read), &[]);
    assert_eq!(b.f.provenance.stmt(kept), at(&[0x28, 0x20, 0x24]));
}

/// An L1 function of three instructions: `one = 1` (0x10), `t = one +
/// one` (0x14), `u = t * one` (0x18); and `t`.
fn three_instructions() -> (L1, Value) {
    let mut l1 = L1::default();
    for (index, (op, address)) in [
        (Op::Const(Bits::from_u64(32, 1)), 0x10),
        (Op::Binary(Binary::Add, Value(0), Value(0)), 0x14),
        (Op::Binary(Binary::Mul, Value(1), Value(0)), 0x18),
    ]
    .into_iter()
    .enumerate()
    {
        let inst = InstId(u32::try_from(index).unwrap());
        l1.values.push(ValueInfo {
            ty: L1Type::Bits(32),
            definition: Definition::Result { inst, index: 0 },
        });
        l1.insts.push(Inst {
            op,
            results: vec![Value(inst.0)],
            address,
        });
    }
    (l1, Value(1))
}

/// Runs `passes` on `f` in `env` (the verifier after each change).
fn run_in<'e>(
    f: &mut Function,
    env: &L2Env<'e>,
    passes: &mut [&mut dyn Pass<Function, L2Env<'e>>],
) {
    let mut manager = Manager::new(Fuel::new(u64::MAX)).with_verifier(pass::verify);
    for pass in passes {
        manager.run(&mut **pass, f, env).unwrap();
    }
    assert_eq!(manager.refusals(), []);
}

#[test]
fn a_dead_assignment_gives_its_instructions_to_what_read_it() {
    let (l1, sum_value) = three_instructions();
    let feeds = Feeds::new(&l1);
    assert_eq!(feeds.readers(sum_value), [0x18]);
    let env = L2Env {
        declarations: &DECLARATIONS,
        exceptions: &NONE,
        feeds: Some(&feeds),
    };
    // `v = p + 1` (0x14, its value standing for nothing: as if lowering
    // had built it from a copy), `return v * 2` (the product 0x18): once
    // propagated, the dead assignment's instruction is the product's.
    // Built `tagged`, its value stands for 0x14 itself: the instruction
    // keeps its own node, the product only its own.
    for tagged in [false, true] {
        let mut b = Builder::new();
        let p = b.var(VarKind::Parameter, 32);
        let v = b.var(VarKind::Local, 32);
        let x = b.read(p);
        let one = b.c(32, 1);
        let sum = b.bin(Binary::Add, x, one);
        let assign = b.assign(v, sum);
        b.f.provenance.set_stmt(
            assign,
            &[Origin::Value(sum_value), Origin::Instruction(0x14)],
        );
        if tagged {
            b.f.provenance.set_expr(sum, &at(&[0x14]));
        }
        let read = b.read(v);
        let two = b.c(32, 2);
        let product = b.bin(Binary::Mul, read, two);
        b.f.provenance.set_expr(product, &at(&[0x18]));
        let ret = b.ret(product);
        run_in(&mut b.f, &env, &mut [&mut Propagate, &mut Prune]);
        assert_eq!(b.f.body, vec![ret]);
        assert_eq!(b.returned(ret), "Mul(Add(v0, 0x1), 0x2)");
        let Some(&Stmt::Return(Some(value))) = b.f.stmt(ret) else {
            unreachable!()
        };
        let expected: &[u64] = if tagged { &[0x18] } else { &[0x18, 0x14] };
        assert_eq!(b.f.provenance.expr(value), at(expected));
    }
}
