#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::similar_names,
    reason = "test helpers fail loudly"
)]

//! The L2 verifier's refusals, each naming the node that breaks the rule,
//! and the text form.

mod build;

use binbun_ast::ir::{
    Arm, Call, Callee, Escape, Expr, Logical, Name, NameOrigin, Node, Origin, Place, Stmt, VarId,
    VarKind,
};
use binbun_ast::text::print;
use binbun_ast::types::{Aggregate, Evidence, Field, Signature, Type};
use binbun_ast::verify::verify;
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Binary;
use binbun_semantics::{IntrinsicId, RegisterId};
use binbun_ssa::ir::Value;
use build::{Builder, DECLARATIONS};

/// The node `builder`'s function is refused at.
fn refused(builder: &Builder) -> Option<Node> {
    verify(&builder.f, &DECLARATIONS).unwrap_err().node
}

#[test]
fn undeclared_variable() {
    let mut b = Builder::new();
    let read = b.e(Expr::Var(VarId(7)));
    let eval = b.s(Stmt::Expr(read));
    b.f.body = vec![eval];
    assert_eq!(refused(&b), Some(Node::Expr(read)));

    // Assigned, not read.
    let mut b = Builder::new();
    let value = b.c(32, 0);
    let assign = b.assign(VarId(0), value);
    b.f.body = vec![assign];
    assert_eq!(refused(&b), Some(Node::Stmt(assign)));
}

#[test]
fn break_outside_its_loop() {
    // while (1) {}  break <that loop>;
    let mut b = Builder::new();
    let forever = b.c(1, 1);
    let spin = b.s(Stmt::While {
        condition: forever,
        body: vec![],
    });
    let leave = b.s(Stmt::Break(spin));
    b.f.body = vec![spin, leave];
    assert_eq!(refused(&b), Some(Node::Stmt(leave)));

    // continue of a switch around it.
    let mut b = Builder::new();
    let switch = b.f.add_stmt(Stmt::Unreachable);
    let next = b.s(Stmt::Continue(switch));
    let scrutinee = b.c(32, 0);
    b.f.stmts[switch.0 as usize] = Stmt::Switch {
        scrutinee,
        arms: vec![Arm {
            values: vec![],
            default: true,
            body: vec![next],
            fallthrough: false,
        }],
    };
    b.f.body = vec![switch];
    assert_eq!(refused(&b), Some(Node::Stmt(next)));
}

#[test]
fn labels_defined_once_and_gotos_to_defined_labels() {
    let mut b = Builder::new();
    let label = b.f.add_label();
    let first = b.s(Stmt::Label(label));
    let second = b.s(Stmt::Label(label));
    let forever = b.c(1, 1);
    let nested = b.s(Stmt::While {
        condition: forever,
        body: vec![second],
    });
    b.f.body = vec![first, nested];
    assert_eq!(refused(&b), Some(Node::Stmt(second)));

    let mut b = Builder::new();
    let label = b.f.add_label();
    let jump = b.s(Stmt::Goto(label));
    b.f.body = vec![jump];
    assert_eq!(refused(&b), Some(Node::Stmt(jump)));
}

#[test]
fn widths_must_agree() {
    // An operation of 32- and 8-bit operands.
    let mut b = Builder::new();
    let (wide, narrow) = (b.c(32, 1), b.c(8, 1));
    let sum = b.bin(Binary::Add, wide, narrow);
    let eval = b.s(Stmt::Expr(sum));
    b.f.body = vec![eval];
    assert_eq!(refused(&b), Some(Node::Expr(sum)));

    // An 8-bit value assigned to a 32-bit variable.
    let mut b = Builder::new();
    let int32 = b.int32;
    let x = b.local(int32);
    let narrow = b.c(8, 1);
    let assign = b.assign(x, narrow);
    b.f.body = vec![assign];
    assert_eq!(refused(&b), Some(Node::Stmt(assign)));

    // A 32-bit condition.
    let mut b = Builder::new();
    let condition = b.c(32, 1);
    let test = b.s(Stmt::If {
        condition,
        then: vec![],
        otherwise: vec![],
    });
    b.f.body = vec![test];
    assert_eq!(refused(&b), Some(Node::Stmt(test)));

    // A switch case of another width than the scrutinee.
    let mut b = Builder::new();
    let scrutinee = b.c(32, 1);
    let switch = b.s(Stmt::Switch {
        scrutinee,
        arms: vec![Arm {
            values: vec![Bits::from_u64(8, 1)],
            default: false,
            body: vec![],
            fallthrough: false,
        }],
    });
    b.f.body = vec![switch];
    assert_eq!(refused(&b), Some(Node::Stmt(switch)));
}

#[test]
fn switch_values_are_distinct() {
    let mut b = Builder::new();
    let scrutinee = b.c(32, 1);
    let arm = |value| Arm {
        values: vec![Bits::from_u64(32, value)],
        default: false,
        body: vec![],
        fallthrough: false,
    };
    let switch = b.s(Stmt::Switch {
        scrutinee,
        arms: vec![arm(1), arm(2), arm(1)],
    });
    b.f.body = vec![switch];
    assert_eq!(refused(&b), Some(Node::Stmt(switch)));
}

#[test]
fn one_effect_per_statement() {
    // v, v = pair(0): the same variable written twice.
    let mut b = Builder::new();
    let int32 = b.int32;
    let v = b.local(int32);
    let input = b.c(32, 0);
    let twice = b.s(Stmt::Intrinsic {
        results: vec![Place::Var(v), Place::Var(v)],
        intrinsic: IntrinsicId(0),
        inputs: vec![input],
    });
    b.f.body = vec![twice];
    assert_eq!(refused(&b), Some(Node::Stmt(twice)));

    // *(int32 *)*(int64 *)0x100 = f(): the callee may change the address.
    let mut b = Builder::new();
    let (int32, int64) = (b.int32, b.int64);
    let signature = b.code(vec![], Some(int32));
    let slot = b.c(64, 0x100);
    let address = b.e(Expr::Load {
        address: slot,
        ty: int64,
    });
    let call = b.s(Stmt::Call {
        results: vec![Place::Memory { address, ty: int32 }],
        call: Call {
            callee: Callee::Address(0x2000),
            arguments: vec![],
            signature,
            variadic: Vec::new(),
        },
    });
    b.f.body = vec![call];
    assert_eq!(refused(&b), Some(Node::Stmt(call)));

    // The same store at a constant address is fine.
    let constant = b.c(64, 0x100);
    b.f.stmts[call.0 as usize] = Stmt::Call {
        results: vec![Place::Memory {
            address: constant,
            ty: int32,
        }],
        call: Call {
            callee: Callee::Address(0x2000),
            arguments: vec![],
            signature,
            variadic: Vec::new(),
        },
    };
    assert_eq!(verify(&b.f, &DECLARATIONS), Ok(()));
}

#[test]
fn calls_in_expressions_are_in_an_order_c_fixes() {
    // v = x + f(x): one call, beside a local only.
    let mut b = Builder::new();
    let int32 = b.int32;
    let x = b.param(int32);
    let v = b.local(int32);
    let signature = b.code(vec![int32], Some(int32));
    let argument = b.read(x);
    let call = b.f.add_call(Call {
        callee: Callee::Address(0x2000),
        arguments: vec![argument],
        signature,
        variadic: Vec::new(),
    });
    let made = b.e(Expr::Call(call));
    let read = b.read(x);
    let sum = b.bin(Binary::Add, read, made);
    let assign = b.assign(v, sum);
    b.f.body = vec![assign];
    assert_eq!(verify(&b.f, &DECLARATIONS), Ok(()));
    let text = print(&b.f, &DECLARATIONS);
    assert!(text.contains("v1 = add(v0, (call 0x2000(v0) : "), "{text}");

    // f(x) + f(x) through one node: two calls.
    let twice = b.bin(Binary::Add, made, made);
    b.f.stmts[assign.0 as usize] = Stmt::Assign {
        place: Place::Var(v),
        value: twice,
    };
    assert_eq!(refused(&b), Some(Node::Stmt(assign)));

    // *(int32 *)0x100 + f(x): C may load before or after the call.
    let constant = b.c(64, 0x100);
    let loaded = b.e(Expr::Load {
        address: constant,
        ty: int32,
    });
    let beside = b.bin(Binary::Add, loaded, made);
    b.f.stmts[assign.0 as usize] = Stmt::Assign {
        place: Place::Var(v),
        value: beside,
    };
    assert_eq!(refused(&b), Some(Node::Stmt(assign)));

    // g(f(x)): the argument's call is made before the statement's.
    b.f.stmts[assign.0 as usize] = Stmt::Call {
        results: vec![],
        call: Call {
            callee: Callee::Address(0x3000),
            arguments: vec![made],
            signature,
            variadic: Vec::new(),
        },
    };
    assert_eq!(verify(&b.f, &DECLARATIONS), Ok(()));

    // g(f(x), *(int32 *)0x100): C may load before or after `f`.
    let two = b.code(vec![int32, int32], Some(int32));
    b.f.stmts[assign.0 as usize] = Stmt::Call {
        results: vec![],
        call: Call {
            callee: Callee::Address(0x3000),
            arguments: vec![made, loaded],
            signature: two,
            variadic: Vec::new(),
        },
    };
    assert_eq!(refused(&b), Some(Node::Stmt(assign)));

    // f(x) + h(x): two calls C does not order.
    let other = b.f.add_call(Call {
        callee: Callee::Address(0x5000),
        arguments: vec![argument],
        signature,
        variadic: Vec::new(),
    });
    let second = b.e(Expr::Call(other));
    let both = b.bin(Binary::Add, made, second);
    b.f.stmts[assign.0 as usize] = Stmt::Assign {
        place: Place::Var(v),
        value: both,
    };
    assert_eq!(refused(&b), Some(Node::Stmt(assign)));

    // A call that returns nothing has no value.
    let none = b.code(vec![], None);
    let void = b.f.add_call(Call {
        callee: Callee::Address(0x4000),
        arguments: vec![],
        signature: none,
        variadic: Vec::new(),
    });
    let valueless = b.e(Expr::Call(void));
    assert_eq!(refused(&b), Some(Node::Expr(valueless)));
}

#[test]
fn and_orders_the_calls_and_loads_of_its_operands() {
    let mut b = Builder::new();
    let int32 = b.int32;
    let x = b.param(int32);
    let signature = b.code(vec![int32], Some(int32));
    let argument = b.read(x);
    let call = |b: &mut Builder, address| {
        let id = b.f.add_call(Call {
            callee: Callee::Address(address),
            arguments: vec![argument],
            signature,
            variadic: Vec::new(),
        });
        b.e(Expr::Call(id))
    };
    let (f, h) = (call(&mut b, 0x2000), call(&mut b, 0x5000));
    let constant = b.c(64, 0x100);
    let loaded = b.e(Expr::Load {
        address: constant,
        ty: int32,
    });
    let zero = b.c(32, 0);
    let left = b.bin(Binary::Eq, f, zero);
    let test = |b: &mut Builder, condition| {
        let id = b.s(Stmt::If {
            condition,
            then: vec![],
            otherwise: vec![],
        });
        b.f.body = vec![id];
        (verify(&b.f, &DECLARATIONS).map_err(|e| e.node), id)
    };

    // f(x) == 0 && (h(x) == 0 && *(int32 *)0x100 == 0): `&&` orders the
    // calls, and the load after both.
    let called = b.bin(Binary::Eq, h, zero);
    let tested = b.bin(Binary::Eq, loaded, zero);
    let right = b.e(Expr::Logical(Logical::And, called, tested));
    let and = b.e(Expr::Logical(Logical::And, left, right));
    assert_eq!(test(&mut b, and).0, Ok(()));

    // f(x) == 0 && h(x) == *(int32 *)0x100: `&&` orders `h` after `f`,
    // but within its right operand C may load before or after `h`.
    let mixed = b.bin(Binary::Eq, h, loaded);
    let unordered = b.e(Expr::Logical(Logical::And, left, mixed));
    let (verdict, id) = test(&mut b, unordered);
    assert_eq!(verdict, Err(Some(Node::Stmt(id))));

    // f(x) == 0 && f(x) == 0 through one node: made twice.
    let again = b.e(Expr::Logical(Logical::And, left, left));
    let (verdict, id) = test(&mut b, again);
    assert_eq!(verdict, Err(Some(Node::Stmt(id))));
}

#[test]
fn assignment_expressions_are_in_conditions_in_an_order_c_fixes() {
    // if ((v = x + 1) != 0 && v < 9) {}: the read after `&&` is ordered.
    let mut b = Builder::new();
    let int32 = b.int32;
    let x = b.param(int32);
    let v = b.local(int32);
    let one = b.c(32, 1);
    let read_x = b.read(x);
    let value = b.bin(Binary::Add, read_x, one);
    let assign = b.e(Expr::Assign { var: v, value });
    let zero = b.c(32, 0);
    let test = b.bin(Binary::Ne, assign, zero);
    let after = b.op_c(Binary::ULt, v, 9);
    let both = b.e(Expr::Logical(Logical::And, test, after));
    let decision = b.s(Stmt::If {
        condition: both,
        then: vec![],
        otherwise: vec![],
    });
    b.f.body = vec![decision];
    assert_eq!(verify(&b.f, &DECLARATIONS), Ok(()));
    let text = print(&b.f, &DECLARATIONS);
    assert!(
        text.contains("ne((v1 = add(v0, 0x1:32)), 0x0:32)"),
        "{text}"
    );

    // (v = x + 1) + v: the read beside the assignment is unsequenced.
    let read_v = b.read(v);
    let beside = b.bin(Binary::Add, assign, read_v);
    let unordered = b.bin(Binary::Ne, beside, zero);
    b.f.stmts[decision.0 as usize] = Stmt::If {
        condition: unordered,
        then: vec![],
        otherwise: vec![],
    };
    assert_eq!(refused(&b), Some(Node::Stmt(decision)));

    // The read of `v` after `&&` shared with one before the assignment:
    // one node cannot be both.
    let early = b.op_c(Binary::ULt, v, 3);
    let first = b.e(Expr::Logical(Logical::And, early, test));
    let Expr::Binary(_, shared, _) = b.f.exprs[early.0 as usize] else {
        unreachable!()
    };
    let nine = b.c(32, 9);
    let again = b.bin(Binary::ULt, shared, nine);
    let chained = b.e(Expr::Logical(Logical::And, first, again));
    b.f.stmts[decision.0 as usize] = Stmt::If {
        condition: chained,
        then: vec![],
        otherwise: vec![],
    };
    assert_eq!(refused(&b), Some(Node::Stmt(decision)));

    // Outside a condition: `return (v = x + 1);`.
    b.f.stmts[decision.0 as usize] = Stmt::Return(Some(assign));
    b.f.returns = Some(int32);
    assert_eq!(refused(&b), Some(Node::Stmt(decision)));

    // To a variable in memory, or of another width.
    let mut b = Builder::new();
    let int32 = b.int32;
    let int64 = b.int64;
    let global = b.var(VarKind::Global(0x4000), int32);
    let value = b.c(32, 1);
    let stored = b.e(Expr::Assign { var: global, value });
    let wide = b.local(int64);
    let narrow = b.e(Expr::Assign { var: wide, value });
    assert_eq!(refused(&b), Some(Node::Expr(stored)));
    b.f.exprs[stored.0 as usize] = Expr::Const(Bits::from_u64(32, 0));
    assert_eq!(refused(&b), Some(Node::Expr(narrow)));
}

#[test]
fn variadic_types_fit_their_arguments() {
    // f(x, y) of `int32 f(int32, ...)`, y stated int32 by a format.
    let mut b = Builder::new();
    let (int32, int64) = (b.int32, b.int64);
    let x = b.param(int32);
    let mut signature = b.code(vec![int32], Some(int32));
    if let Some(Type::Code(code)) = b.f.types.get(signature).cloned() {
        signature = b.f.types.intern(Type::Code(Signature {
            variadic: true,
            ..code
        }));
    }
    let first = b.read(x);
    let second = b.read(x);
    let call = b.s(Stmt::Call {
        results: vec![],
        call: Call {
            callee: Callee::Address(0x2000),
            arguments: vec![first, second],
            signature,
            variadic: vec![int32],
        },
    });
    b.f.body = vec![call];
    assert_eq!(verify(&b.f, &DECLARATIONS), Ok(()));

    // A stated type of another width.
    let Stmt::Call { call: inner, .. } = &mut b.f.stmts[call.0 as usize] else {
        unreachable!()
    };
    inner.variadic = vec![int64];
    assert_eq!(refused(&b), Some(Node::Stmt(call)));

    // More stated types than variadic arguments.
    let Stmt::Call { call: inner, .. } = &mut b.f.stmts[call.0 as usize] else {
        unreachable!()
    };
    inner.variadic = vec![int32, int32];
    assert_eq!(refused(&b), Some(Node::Stmt(call)));
}

#[test]
fn text_form() {
    // The example of `binbun_ast::text`'s documentation.
    let mut b = Builder::new();
    let int32 = b.int32;
    let node = b.f.types.intern(Type::Struct(Aggregate::default()));
    let link = b.f.types.intern(Type::Pointer(Some(node)));
    *b.f.types.aggregate_mut(node).unwrap() = Aggregate {
        name: Some("node".into()),
        size: 16,
        fields: vec![
            Field {
                offset: 0,
                ty: link,
                name: Some("next".into()),
            },
            Field {
                offset: 8,
                ty: int32,
                name: Some("value".into()),
            },
        ],
    };
    let byte = b.f.types.intern(Type::UInt(8));
    let bytes = b.f.types.intern(Type::Array {
        element: byte,
        length: Some(72),
    });
    let n = b.param(int32);
    b.f.variables[n.0 as usize].name = Some(Name::new("n", NameOrigin::Debug));
    b.f.variables[n.0 as usize].evidence = Evidence::Deduced;
    b.f.variables[n.0 as usize].origins = vec![Origin::Register(RegisterId(0))];
    let i = b.local(int32);
    b.f.variables[i.0 as usize].origins = vec![Origin::Value(Value(12))];
    let total = b.var(VarKind::Global(0x40_4010), int32);
    b.f.variables[total.0 as usize].name = Some(Name::new("total", NameOrigin::Debug));
    b.f.variables[total.0 as usize].evidence = Evidence::Declared;
    b.var(VarKind::Frame(-0x48), bytes);
    b.f.name = Some("count".into());
    b.f.address = 0x40_1000;
    b.f.returns = Some(int32);
    b.f.returns_evidence = Evidence::Deduced;

    let init = b.set(i, 0);
    b.f.provenance
        .set_stmt(init, &[Origin::Instruction(0x40_1000)]);
    let lp = b.f.add_stmt(Stmt::Unreachable);
    let leave = b.s(Stmt::Break(lp));
    let address = b.e(Expr::AddressOf(total));
    let read_i = b.read(i);
    let store = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int32 },
        value: read_i,
    });
    let five = b.op_c(Binary::Eq, i, 5);
    let test = b.s(Stmt::If {
        condition: five,
        then: vec![leave],
        otherwise: vec![store],
    });
    let step = b.add_to(i, 1);
    let read_n = b.read(n);
    let less = b.bin(Binary::SLt, read_i, read_n);
    b.f.stmts[lp.0 as usize] = Stmt::While {
        condition: less,
        body: vec![test, step],
    };
    let done = b.ret(i);
    b.f.body = vec![init, lp, done];
    assert_eq!(verify(&b.f, &DECLARATIONS), Ok(()));
    assert_eq!(
        print(&b.f, &DECLARATIONS),
        r#"function 0x401000 "count" (v0) -> int32 deduced
  type t5 = struct "node" size 16 { 0: ptr(t5) "next", 8: int32 "value" }
  var v0 param int32 "n" deduced [rdi]
  var v1 local int32 default [%v12]
  var v2 global 0x404010 int32 "total" declared
  var v3 frame -0x48 array(uint8, 72) default
{
  s0: v1 = 0x0:32  ; @0x401000
  s1: while slt(v1, v0) {
    s4: if eq(v1, 0x5:32) {
      s2: break s1
    } else {
      s3: mem<int32>(&v2) = v1
    }
    s5: v1 = add(v1, 0x1:32)
  }
  s6: return v1
}
"#
    );
}

#[test]
fn atomic_escapes_are_one_load_or_one_store() {
    // A load with no result, a store with a result, and a 4-bit store.
    for (operands, results, width) in [(1, 0, 32), (2, 1, 32), (2, 0, 4)] {
        let mut b = Builder::new();
        let p = b.param(b.int64);
        let v = b.local(b.int32);
        let address = b.read(p);
        let value = b.c(width, 1);
        let escape = b.s(Stmt::Escape {
            kind: Escape::Atomic,
            operands: [address, value].into_iter().take(operands).collect(),
            results: [Place::Var(v)].into_iter().take(results).collect(),
        });
        b.f.body = vec![escape];
        assert_eq!(
            refused(&b),
            Some(Node::Stmt(escape)),
            "{operands} {results} {width}"
        );
    }
}

#[test]
fn logical_operands_are_one_bit() {
    for wide_left in [false, true] {
        let mut b = Builder::new();
        let int32 = b.int32;
        let x = b.param(int32);
        let bit = b.op_c(Binary::Eq, x, 0);
        let word = b.read(x);
        let (left, right) = if wide_left { (word, bit) } else { (bit, word) };
        let both = b.e(Expr::Logical(Logical::And, left, right));
        let test = b.s(Stmt::If {
            condition: both,
            then: vec![],
            otherwise: vec![],
        });
        b.f.body = vec![test];
        assert_eq!(refused(&b), Some(Node::Expr(both)), "{wide_left}");
    }
}
