//! Hand-built functions covering the statements, memory accesses, calls
//! and escapes the printer handles, and the symbols they are named by.

use binbun_ast::ir::{Callee, Escape, Expr, ExprId, Function, Place, Stmt, StmtId, VarId, VarKind};
use binbun_ast::types::{Aggregate, Field, Type, TypeId};
use binbun_semantics::IntrinsicId;
use binbun_semantics::ir::{Binary, Trap};

use super::{Builder, arm};

/// A loop in a switch in a loop: `continue` and `break` of the outer
/// loop from the inner one, a fallthrough, a `goto`.
pub fn loops() -> Function {
    let mut b = Builder::new(0x1000, "loops");
    let int32 = b.int(32);
    b.f.returns = Some(int32);
    let limit = b.param(int32);
    let (i, j, total) = (b.local(int32), b.local(int32), b.local(int32));
    let zero = b.c(32, 0);
    let s0 = b.assign(total, zero);
    let i0 = b.assign(i, zero);
    let outer = b.placeholder();
    let switch = b.placeholder();
    let inner = inner_loop(&mut b, outer, j, total, limit);
    let (ri, rs, rn) = (b.read(i), b.read(total), b.read(limit));
    let leave = b.s(Stmt::Break(switch));
    let one = b.c(32, 1);
    let inc = b.bin(Binary::Add, rs, one);
    let bump = b.assign(total, inc);
    let hundred = b.c(32, 100);
    let big = b.bin(Binary::SLt, hundred, rs);
    let leave2 = b.s(Stmt::Break(switch));
    let if_big = b.when(big, vec![leave2]);
    let end = b.f.add_label();
    let go = b.s(Stmt::Goto(end));
    let three = b.c(32, 3);
    let low = b.bin(Binary::And, ri, three);
    let arms = vec![
        arm(&[0], 32, false, vec![inner, leave], false),
        arm(&[1], 32, false, vec![bump], true),
        arm(&[2], 32, false, vec![if_big], false),
        arm(&[], 32, true, vec![go], false),
    ];
    b.set(
        switch,
        Stmt::Switch {
            scrutinee: low,
            arms,
        },
    );
    let inext = b.bin(Binary::Add, ri, one);
    let istep = b.assign(i, inext);
    let ilt = b.bin(Binary::SLt, ri, rn);
    b.set(
        outer,
        Stmt::While {
            condition: ilt,
            body: vec![switch, istep],
        },
    );
    let label = b.s(Stmt::Label(end));
    let ret = b.ret(rs);
    b.done(vec![s0, i0, outer, label, ret])
}

/// `for (j = 0; j < limit; j++) { if (j == 5) continue outer; if (j == 7)
/// break outer; total += j; }`.
fn inner_loop(b: &mut Builder, outer: StmtId, j: VarId, total: VarId, limit: VarId) -> StmtId {
    let (rj, rs, rn) = (b.read(j), b.read(total), b.read(limit));
    let five = b.c(32, 5);
    let is5 = b.bin(Binary::Eq, rj, five);
    let cont = b.s(Stmt::Continue(outer));
    let if5 = b.when(is5, vec![cont]);
    let seven = b.c(32, 7);
    let is7 = b.bin(Binary::Eq, rj, seven);
    let brk = b.s(Stmt::Break(outer));
    let if7 = b.when(is7, vec![brk]);
    let sum = b.bin(Binary::Add, rs, rj);
    let acc = b.assign(total, sum);
    let one = b.c(32, 1);
    let jn = b.bin(Binary::Add, rj, one);
    let jstep = b.assign(j, jn);
    let zero = b.c(32, 0);
    let j0 = b.assign(j, zero);
    let jlt = b.bin(Binary::SLt, rj, rn);
    b.s(Stmt::For {
        init: vec![j0],
        condition: jlt,
        step: vec![jstep],
        body: vec![if5, if7, acc],
    })
}

/// `struct node { struct node *next; int32 value; uint8 data[4]; int16
/// int; }`, 24 bytes, and a pointer to it.
fn node(b: &mut Builder) -> TypeId {
    let int32 = b.int(32);
    let uint8 = b.uint(8);
    let int16 = b.int(16);
    let node = b.ty(Type::Struct(Aggregate {
        name: Some("node".into()),
        size: 24,
        fields: Vec::new(),
    }));
    let node_ptr = b.ty(Type::Pointer(Some(node)));
    let bytes = b.ty(Type::Array {
        element: uint8,
        length: Some(4),
    });
    let field = |offset, ty, name: &str| Field {
        offset,
        ty,
        name: Some(name.into()),
    };
    *b.f.types.aggregate_mut(node).unwrap() = Aggregate {
        name: Some("node".into()),
        size: 24,
        fields: vec![
            field(0, node_ptr, "next"),
            field(8, int32, "value"),
            field(12, bytes, "data"),
            field(16, int16, "int"),
        ],
    };
    node_ptr
}

/// Loads and stores through a struct pointer, a frame array and a
/// global; narrow arithmetic compared; signed against unsigned.
pub fn memory() -> Function {
    let mut b = Builder::new(0x2000, "memory");
    let (int32, uint32, uint8, int16) = (b.int(32), b.uint(32), b.uint(8), b.int(16));
    let node_ptr = node(&mut b);
    b.f.returns = Some(int32);
    let p = b.param(node_ptr);
    let frame_ty = b.ty(Type::Array {
        element: uint32,
        length: Some(4),
    });
    let frame = b.var(VarKind::Frame(-0x20), frame_ty, None);
    let global = b.var(VarKind::Global(0x40_4010), int32, None);
    let rp = b.read(p);
    let value = b.load_at(rp, 8, int32);
    let next = b.load_at(rp, 0, node_ptr);
    let next_value = b.load_at(next, 8, int32);
    let byte = b.load_at(rp, 14, uint8);
    let odd = b.load_at(rp, 16, int16);
    let base = b.e(Expr::AddressOf(frame));
    let four = b.c(64, 4);
    let slot = b.bin(Binary::Add, base, four);
    let as_u32 = b.cast(value, uint32);
    let store = b.s(Stmt::Assign {
        place: Place::Memory {
            address: slot,
            ty: uint32,
        },
        value: as_u32,
    });
    let sum = b.bin(Binary::Add, next_value, value);
    let to_global = b.s(Stmt::Assign {
        place: Place::Var(global),
        value: sum,
    });
    let both = carry_and_compares(&mut b, value, byte, odd);
    let trap = b.s(Stmt::Trap(Trap::Divide));
    let fault = b.s(Stmt::Expr(next_value));
    let check = b.s(Stmt::If {
        condition: both,
        then: vec![trap],
        otherwise: vec![fault],
    });
    let rg = b.read(global);
    let back = b.load_at(slot, 0, uint32);
    let back = b.cast(back, int32);
    let total = b.bin(Binary::Sub, rg, back);
    let ret = b.ret(total);
    b.done(vec![store, to_global, check, ret])
}

/// The carry of an 8-bit sum (compared with an operand), or `odd` below
/// `value` unsigned, and `odd` below `value` signed.
fn carry_and_compares(b: &mut Builder, value: ExprId, byte: ExprId, odd: ExprId) -> ExprId {
    let low8 = b.bits_of(value, 0, 8);
    let sum8 = b.bin(Binary::Add, low8, byte);
    let carry = b.bin(Binary::ULt, sum8, byte);
    let odd32 = b.ext(true, odd, 32);
    let unsigned_less = b.bin(Binary::ULt, odd32, value);
    let signed_less = b.bin(Binary::SLt, odd32, value);
    let either = b.bin(Binary::Or, carry, unsigned_less);
    b.bin(Binary::And, either, signed_less)
}

/// Calls by address (names from symbols that are not C identifiers),
/// with a split result, through a pointer, variadic, recursive, with a
/// second signature; intrinsics; locals whose names collide.
pub fn calls() -> Function {
    let mut b = Builder::new(0x3000, "calls@@GLIBC_2.2");
    let (int32, uint64, uint128) = (b.int(32), b.uint(64), b.uint(128));
    let void_ptr = b.ty(Type::Pointer(None));
    b.f.returns = Some(int32);
    let x = b.param(int32);
    let callback_ty = b.code(vec![int32], Some(int32), false);
    let f = b.param(callback_ty);
    let memcpy_local = b.var(VarKind::Local, void_ptr, Some("memcpy"));
    let int_local = b.var(VarKind::Local, int32, Some("int"));
    let rotl_local = b.var(VarKind::Local, uint64, Some("rotl"));
    let (lo, hi) = (b.local(uint64), b.local(uint64));
    let (p0, p1) = (b.local(int32), b.local(int32));
    let (rx, rf) = (b.read(x), b.read(f));
    let wide = b.ext(false, rx, 64);
    let as_ptr = b.cast(wide, void_ptr);
    let memcpy_ty = b.code(vec![void_ptr, void_ptr, uint64], Some(void_ptr), false);
    let c1 = b.call(
        Callee::Address(0x5000),
        vec![as_ptr, as_ptr, wide],
        memcpy_ty,
        vec![Place::Var(memcpy_local)],
    );
    let c2 = b.call(
        Callee::Address(0x6000),
        vec![rx],
        callback_ty,
        vec![Place::Var(int_local)],
    );
    let pair_ty = b.code(vec![uint64], Some(uint128), false);
    let c3 = b.call(
        Callee::Address(0x7000),
        vec![wide],
        pair_ty,
        vec![Place::Var(lo), Place::Var(hi)],
    );
    let c4 = b.call(
        Callee::Expr(rf),
        vec![rx],
        callback_ty,
        vec![Place::Var(int_local)],
    );
    let (fmt, rlo, rhi) = (b.read(memcpy_local), b.read(lo), b.read(hi));
    let printf_ty = b.code(vec![void_ptr], Some(int32), true);
    let c5 = b.call(
        Callee::Address(0x8000),
        vec![fmt, rx, rlo],
        printf_ty,
        vec![],
    );
    let own_ty = b.code(vec![int32, callback_ty], Some(int32), false);
    let c6 = b.call(
        Callee::Address(0x3000),
        vec![rx, rf],
        own_ty,
        vec![Place::Var(int_local)],
    );
    let zero = b.c(32, 0);
    let positive = b.bin(Binary::SLt, zero, rx);
    let c6 = b.when(positive, vec![c6]);
    let other_ty = b.code(vec![uint64, uint64], Some(uint64), false);
    let c7 = b.call(
        Callee::Address(0x6000),
        vec![rlo, rhi],
        other_ty,
        vec![Place::Var(rotl_local)],
    );
    let i1 = b.s(Stmt::Intrinsic {
        results: vec![Place::Var(p0), Place::Var(p1)],
        intrinsic: IntrinsicId(0),
        inputs: vec![rx],
    });
    let i2 = b.s(Stmt::Intrinsic {
        results: vec![Place::Var(rotl_local)],
        intrinsic: IntrinsicId(1),
        inputs: vec![],
    });
    let (r0, r1, ri, rr) = (
        b.read(p0),
        b.read(p1),
        b.read(int_local),
        b.read(rotl_local),
    );
    let s1 = b.bin(Binary::Add, r0, r1);
    let s2 = b.bin(Binary::Add, s1, ri);
    let low = b.bits_of(rr, 0, 32);
    let s3 = b.bin(Binary::Xor, s2, low);
    let ret = b.ret(s3);
    b.done(vec![c1, c2, c3, c4, c5, c6, c7, i1, i2, ret])
}

/// Every escape kind, each reached on its own path.
pub fn escapes() -> Function {
    let mut b = Builder::new(0x4000, "escapes");
    let (uint64, uint32, uint8) = (b.uint(64), b.uint(32), b.uint(8));
    let void_ptr = b.ty(Type::Pointer(None));
    b.f.returns = Some(uint64);
    let k = b.param(uint8);
    let p = b.param(void_ptr);
    let (r0, r1, v) = (b.local(uint64), b.local(uint64), b.local(uint32));
    let (rk, rp) = (b.read(k), b.read(p));
    let addr = b.cast(rp, uint64);
    let e0 = b.escape(Escape::UnresolvedJump, vec![addr], vec![]);
    let e1 = b.escape(Escape::ForeignJump, vec![addr], vec![]);
    let e2 = b.escape(Escape::OverlappingCode, vec![addr], vec![]);
    let e3 = b.escape(
        Escape::NonStandardCall,
        vec![addr, rk],
        vec![Place::Var(r0), Place::Var(r1)],
    );
    let e4 = b.escape(Escape::StackTrick, vec![rk], vec![]);
    let sixty = b.c(64, 60);
    let e5 = b.escape(Escape::SystemCall, vec![sixty, addr], vec![Place::Var(r0)]);
    let e6 = b.escape(Escape::Atomic, vec![rp], vec![Place::Var(v)]);
    let rv = b.read(v);
    let one = b.c(32, 1);
    let inc = b.bin(Binary::Add, rv, one);
    let e7 = b.escape(Escape::Atomic, vec![rp, inc], vec![]);
    let unreachable = b.s(Stmt::Unreachable);
    let bodies = [
        vec![e0],
        vec![e1],
        vec![e2],
        vec![e3],
        vec![e4],
        vec![e5],
        vec![e6, e7],
        vec![unreachable],
    ];
    let arms = bodies
        .into_iter()
        .zip(0u64..)
        .map(|(body, index)| arm(&[index], 8, index == 7, body, false))
        .collect();
    let switch = b.s(Stmt::Switch {
        scrutinee: rk,
        arms,
    });
    let (rr0, rr1) = (b.read(r0), b.read(r1));
    let sum = b.bin(Binary::Add, rr0, rr1);
    let ret = b.ret(sum);
    let zero = b.c(64, 0);
    let init0 = b.assign(r0, zero);
    let init1 = b.assign(r1, zero);
    b.done(vec![init0, init1, switch, ret])
}

/// Literals of 64 bits beside one of 32: one shifted past 32 bits, two
/// past 32 bits themselves, and a 32-bit one.
pub fn wide_literals() -> Function {
    let mut b = Builder::new(0x5800, "wide");
    let (word, uint32) = (b.uint(64), b.uint(32));
    b.f.returns = Some(word);
    let (x, y) = (b.param(word), b.param(uint32));
    let (dead, forty) = (b.c(64, 0xdead), b.c(64, 40));
    let shifted = b.bin(Binary::Shl, dead, forty);
    let (rx, high) = (b.read(x), b.c(64, 0xffff_ffff_0000_0000));
    let masked = b.bin(Binary::And, rx, high);
    let merged = b.bin(Binary::Or, shifted, masked);
    let big = b.c(64, 0x1_2345_6789);
    let sum = b.bin(Binary::Add, merged, big);
    let (ry, small) = (b.read(y), b.c(32, 0x12345));
    let narrow = b.bin(Binary::Add, ry, small);
    let widened = b.ext(false, narrow, 64);
    let total = b.bin(Binary::Xor, sum, widened);
    let ret = b.ret(total);
    b.done(vec![ret])
}

/// An `else if` chain with blocks of several statements, a `do` loop,
/// and a long expression to break.
pub fn branches() -> Function {
    let mut b = Builder::new(0x5000, "branches");
    let int64 = b.int(64);
    b.f.returns = Some(int64);
    let (x, y) = (b.param(int64), b.param(int64));
    let acc = b.local(int64);
    let (rx, ry, ra) = (b.read(x), b.read(y), b.read(acc));
    let zero = b.c(64, 0);
    let init = b.assign(acc, zero);
    let mut long = rx;
    for k in 1..12 {
        let c = b.c(64, k * 0x1234_5678);
        let term = b.bin(Binary::Mul, ry, c);
        long = b.bin(Binary::Add, long, term);
    }
    let a1 = b.assign(acc, long);
    let one = b.c(64, 1);
    let up = b.bin(Binary::Add, ra, one);
    let a2 = b.assign(acc, up);
    let down = b.bin(Binary::Sub, ra, rx);
    let a3 = b.assign(acc, down);
    let a4 = b.assign(acc, rx);
    let less = b.bin(Binary::SLt, rx, ry);
    let equal = b.bin(Binary::Eq, rx, ry);
    let inner = b.s(Stmt::If {
        condition: equal,
        then: vec![a3],
        otherwise: vec![a4],
    });
    let outer = b.s(Stmt::If {
        condition: less,
        then: vec![a1, a2],
        otherwise: vec![inner],
    });
    let ten = b.c(64, 10);
    let small = b.bin(Binary::ULt, ra, ten);
    let a5 = b.assign(acc, up);
    let again = b.s(Stmt::DoWhile {
        body: vec![a5],
        condition: small,
    });
    let ret = b.ret(ra);
    b.done(vec![init, outer, again, ret])
}

/// The symbols of the samples' callees and globals.
pub fn symbols(address: u64) -> Option<String> {
    match address {
        0x5000 => Some("memcpy".into()),
        0x6000 => Some("foo.cold".into()),
        0x7000 => Some("_ZN3foo3barEv".into()),
        0x8000 => Some("printf@plt".into()),
        0x40_4010 => Some("switch".into()),
        _ => None,
    }
}
