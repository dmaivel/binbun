#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::similar_names,
    clippy::many_single_char_names,
    reason = "test helpers fail loudly; `b`, `s`, `i`, `t` are the program's names"
)]

//! Where locals are declared ([`Scopes`]): each in the innermost block
//! using it where no value flows in, at its first assignment, a `for`'s
//! counter in its header; never where a value would cross the
//! declaration or a `goto` would jump past it. Each function is checked
//! three ways: where the pass declares its locals, its C (as the printer
//! puts them, compiled by gcc and clang where present), and its runs on
//! L2's interpreter (which makes a local undefined at its declaration)
//! against the function before.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use binbun_ast::interpret::{Outcome, run};
use binbun_ast::ir::{
    Call, Callee, Expr, ExprId, Function, LabelId, Place, Stmt, StmtId, VarId, VarKind, Variable,
};
use binbun_ast::types::{Evidence, Signature, Type, TypeId, Types};
use binbun_ast::verify::verify;
use binbun_decompile::itanium::NONE;
use binbun_decompile::pass::{self as l2, L2Env};
use binbun_decompile::scopes::Scopes;
use binbun_print::c::{self, HEADER, Opaque};
use binbun_print::layout;
use binbun_print::style::{Placement, Style};
use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Fuel, Manager};
use binbun_semantics::interpret::{Fault, Machine, Value};
use binbun_semantics::ir::{Binary, RegisterId};

const DECLARATIONS: Declarations = Declarations {
    registers: &[],
    intrinsics: &[],
    sites: &[],
};

/// A function of 32-bit integers under construction.
struct B {
    f: Function,
    int: TypeId,
}

impl B {
    /// `f` with `parameters` parameters, returning an `int32_t`.
    fn new(parameters: usize) -> (Self, Vec<VarId>) {
        let mut types = Types::new(64);
        let int = types.intern(Type::Int(32));
        let mut f = Function::new(0x1000, types);
        f.name = Some("f".to_owned());
        f.returns = Some(int);
        let mut b = Self { f, int };
        let params = (0..parameters)
            .map(|_| {
                let id = b.var(VarKind::Parameter);
                b.f.parameters.push(id);
                id
            })
            .collect();
        (b, params)
    }

    fn var(&mut self, kind: VarKind) -> VarId {
        self.f.add_var(Variable {
            kind,
            name: None,
            ty: self.int,
            evidence: Evidence::Default,
            origins: Vec::new(),
        })
    }

    fn local(&mut self) -> VarId {
        self.var(VarKind::Local)
    }

    fn c(&mut self, value: u64) -> ExprId {
        self.f.add_expr(Expr::Const(Bits::from_u64(32, value)))
    }

    fn read(&mut self, var: VarId) -> ExprId {
        self.f.add_expr(Expr::Var(var))
    }

    fn bin(&mut self, op: Binary, a: ExprId, b: ExprId) -> ExprId {
        self.f.add_expr(Expr::Binary(op, a, b))
    }

    /// `var op value`.
    fn op(&mut self, op: Binary, var: VarId, value: u64) -> ExprId {
        let read = self.read(var);
        let constant = self.c(value);
        self.bin(op, read, constant)
    }

    /// `a op b` of two variables.
    fn vars(&mut self, op: Binary, a: VarId, b: VarId) -> ExprId {
        let a = self.read(a);
        let b = self.read(b);
        self.bin(op, a, b)
    }

    /// `value < var`, signed.
    fn gt(&mut self, var: VarId, value: u64) -> ExprId {
        let constant = self.c(value);
        let read = self.read(var);
        self.bin(Binary::SLt, constant, read)
    }

    fn s(&mut self, stmt: Stmt) -> StmtId {
        self.f.add_stmt(stmt)
    }

    fn assign(&mut self, var: VarId, value: ExprId) -> StmtId {
        self.s(Stmt::Assign {
            place: Place::Var(var),
            value,
        })
    }

    /// `var = constant`.
    fn set(&mut self, var: VarId, value: u64) -> StmtId {
        let value = self.c(value);
        self.assign(var, value)
    }

    /// `var = var + value`.
    fn step(&mut self, var: VarId, value: u64) -> StmtId {
        let sum = self.op(Binary::Add, var, value);
        self.assign(var, sum)
    }

    fn ret(&mut self, var: VarId) -> StmtId {
        let read = self.read(var);
        self.s(Stmt::Return(Some(read)))
    }

    fn when(&mut self, condition: ExprId, then: Vec<StmtId>, otherwise: Vec<StmtId>) -> StmtId {
        self.s(Stmt::If {
            condition,
            then,
            otherwise,
        })
    }

    fn label(&mut self) -> LabelId {
        self.f.add_label()
    }

    fn done(mut self, body: Vec<StmtId>) -> Function {
        self.f.body = body;
        verify(&self.f, &DECLARATIONS).unwrap();
        self.f
    }
}

/// Runs [`Scopes`] on `f` through a pass manager (with the verifier).
fn scopes(f: &mut Function) -> Changed {
    let mut manager = Manager::new(Fuel::new(u64::MAX)).with_verifier(l2::verify);
    let env = L2Env {
        declarations: &DECLARATIONS,
        exceptions: &NONE,
        feeds: None,
    };
    let changed = manager.run(&mut Scopes, f, &env).unwrap();
    assert_eq!(manager.refusals(), []);
    changed
}

/// Where `var` is declared: the statement, or `None` for the top.
fn declared_at(f: &Function, var: VarId) -> Option<StmtId> {
    f.declared
        .iter()
        .find(|(_, vars)| vars.contains(&var))
        .map(|(&at, _)| at)
}

/// `f` as C, locals placed as `placement` says.
fn c(f: &Function, placement: Placement) -> String {
    let style = Style::kr().with_declarations(placement);
    let printed = c::function(f, &DECLARATIONS, &style, &|_: u64| None, Opaque::Calls)
        .unwrap_or_else(|error| panic!("{error}"));
    layout::render(&printed.document, &style)
}

/// No memory and no registers.
struct NoMemory;

impl Machine for NoMemory {
    fn read(&mut self, _: RegisterId) -> Value {
        unreachable!("no registers")
    }

    fn write(&mut self, _: RegisterId, _: Value) {
        unreachable!("no registers")
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

fn outcome(f: &Function, arguments: &[u64]) -> Outcome {
    let arguments: Vec<Value> = arguments
        .iter()
        .map(|&value| Value::defined(Bits::from_u64(32, value)))
        .collect();
    run(f, &mut NoMemory, &arguments, 0x8000, 10_000)
}

/// Inputs for one or two parameters.
const INPUTS: [[u64; 2]; 6] = [[0, 0], [1, 0], [3, 1], [5, 7], [0xffff_ffff, 2], [9, 0]];

/// Places `before`'s declarations: they run as before on the inputs (no
/// value read across a declaration), and its C compiles. The function
/// after.
fn placed(before: &Function) -> Function {
    let mut after = before.clone();
    scopes(&mut after);
    let parameters = before.parameters.len();
    for input in INPUTS {
        let input = input.get(..parameters).unwrap_or_default();
        let expected = outcome(before, input);
        assert!(
            matches!(&expected, Outcome::Returned(Some(value)) if value.known().is_some()),
            "{expected:?}"
        );
        assert_eq!(
            expected,
            outcome(&after, input),
            "{input:?}\n{}",
            c(&after, Placement::Scoped)
        );
    }
    compiles(&c(&after, Placement::Scoped));
    after
}

/// The scratch directories made so far (one per compilation).
static FILES: AtomicUsize = AtomicUsize::new(0);

/// Compiles `text` with each compiler present (C11, binbun's flags).
fn compiles(text: &str) {
    let home = std::env::var_os("HOME").expect("HOME");
    let dir = PathBuf::from(home)
        .join(".cache/binbun-print-check")
        .join(format!(
            "scopes-{}-{}",
            std::process::id(),
            FILES.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("binbun_defs.h"), HEADER).unwrap();
    let name = "f.c";
    std::fs::write(dir.join(name), text).unwrap();
    for compiler in ["gcc", "clang"] {
        let Ok(output) = Command::new(compiler)
            .current_dir(&dir)
            .args(["-std=c11", "-fwrapv", "-fno-strict-aliasing", "-Wall"])
            .args(["-Wextra", "-fsyntax-only", name])
            .output()
        else {
            continue;
        };
        assert!(
            output.status.success(),
            "{compiler}: {}\n{text}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `s = 0; i = 0; while (i < p0) { [t = i * 3;] s = s + (t or i); i = i + 1; }
/// return s;` with its statements.
struct Loop {
    f: Function,
    s: VarId,
    t: Option<VarId>,
    zero: StmtId,
    body: Vec<StmtId>,
}

fn sum_loop(temporary: bool) -> Loop {
    let (mut b, params) = B::new(1);
    let s = b.local();
    let i = b.local();
    let t = temporary.then(|| b.local());
    let zero = b.set(s, 0);
    let start = b.set(i, 0);
    let mut body = Vec::new();
    let added = match t {
        Some(t) => {
            let triple = b.op(Binary::Mul, i, 3);
            body.push(b.assign(t, triple));
            t
        }
        None => i,
    };
    let sum = b.vars(Binary::Add, s, added);
    body.push(b.assign(s, sum));
    body.push(b.step(i, 1));
    let condition = b.vars(Binary::SLt, i, params[0]);
    let looped = b.s(Stmt::While {
        condition,
        body: body.clone(),
    });
    let back = b.ret(s);
    let f = b.done(vec![zero, start, looped, back]);
    Loop {
        f,
        s,
        t,
        zero,
        body,
    }
}

#[test]
fn an_accumulator_stays_before_its_loop() {
    let Loop { f, s, zero, .. } = sum_loop(false);
    let after = placed(&f);
    assert_eq!(declared_at(&after, s), Some(zero));
    let text = c(&after, Placement::Scoped);
    assert!(text.contains("    int32_t v1 = 0;\n"), "{text}");
    assert!(text.contains("    int32_t v2 = 0;\n"), "{text}");
    // Today's: all at the top.
    let top = c(&after, Placement::Top);
    assert!(top.contains("    int32_t v1;\n    int32_t v2;\n"), "{top}");
    assert_eq!(top, c(&f, Placement::Scoped));
}

#[test]
fn a_temporary_set_each_iteration_is_declared_in_the_loop() {
    let Loop { f, t, body, .. } = sum_loop(true);
    let t = t.unwrap();
    let after = placed(&f);
    assert_eq!(declared_at(&after, t), body.first().copied());
    let text = c(&after, Placement::Scoped);
    assert!(text.contains("        int32_t v3 = v2 * 3;\n"), "{text}");
}

#[test]
fn the_first_assignment_initializes_and_a_conditional_one_does_not() {
    // v = p0 + 1; return v;
    let (mut b, params) = B::new(1);
    let v = b.local();
    let sum = b.op(Binary::Add, params[0], 1);
    let first = b.assign(v, sum);
    let back = b.ret(v);
    let after = placed(&b.done(vec![first, back]));
    assert_eq!(declared_at(&after, v), Some(first));
    let text = c(&after, Placement::Scoped);
    assert!(text.contains("    int32_t v1 = a1 + 1;\n"), "{text}");
    assert!(!text.contains("int32_t v1;"), "{text}");

    // if (p0 == 7) return p0; if (p0 < 5) v = 1; else v = 2; return v:
    // declared before the second `if`, which may run either arm (before
    // the first statement, it would be at the top).
    let (mut b, params) = B::new(1);
    let v = b.local();
    let seven = b.op(Binary::Eq, params[0], 7);
    let leave = b.ret(params[0]);
    let early = b.when(seven, vec![leave], Vec::new());
    let one = b.set(v, 1);
    let two = b.set(v, 2);
    let test = b.op(Binary::SLt, params[0], 5);
    let branch = b.when(test, vec![one], vec![two]);
    let back = b.ret(v);
    let after = placed(&b.done(vec![early, branch, back]));
    assert_eq!(declared_at(&after, v), Some(branch));
    let text = c(&after, Placement::Scoped);
    assert!(text.contains("    int32_t v1;\n    if (a1 < 5)"), "{text}");
}

#[test]
fn a_call_as_the_first_statement_initializes() {
    // v = f(p0); return v; the call the body's first statement.
    let (mut b, params) = B::new(1);
    let v = b.local();
    let signature = b.f.types.intern(Type::Code(Signature {
        parameters: vec![b.int],
        returns: Some(b.int),
        variadic: false,
    }));
    let argument = b.read(params[0]);
    let call = b.s(Stmt::Call {
        results: vec![Place::Var(v)],
        call: Call {
            callee: Callee::Address(0x2000),
            arguments: vec![argument],
            signature,
            variadic: Vec::new(),
        },
    });
    let back = b.ret(v);
    // The interpreter stops at a call: the pass alone, and the C compiled.
    let mut after = b.done(vec![call, back]);
    scopes(&mut after);
    assert_eq!(declared_at(&after, v), Some(call));
    let text = c(&after, Placement::Scoped);
    assert!(text.contains("    int32_t v1 = sub_2000(a1);\n"), "{text}");
    assert!(!text.contains("int32_t v1;"), "{text}");
    compiles(&text);
}

#[test]
fn a_counter_only_its_for_uses_is_declared_in_the_header() {
    for used_after in [false, true] {
        // s = 0; for (i = 0; i < p0; i = i + 1) s = s + i; return s (or i).
        let (mut b, params) = B::new(1);
        let s = b.local();
        let i = b.local();
        let zero = b.set(s, 0);
        let init = b.set(i, 0);
        let step = b.step(i, 1);
        let sum = b.vars(Binary::Add, s, i);
        let add = b.assign(s, sum);
        let condition = b.vars(Binary::SLt, i, params[0]);
        let looped = b.s(Stmt::For {
            init: vec![init],
            condition,
            step: vec![step],
            body: vec![add],
        });
        let back = b.ret(if used_after { i } else { s });
        let after = placed(&b.done(vec![zero, looped, back]));
        let text = c(&after, Placement::Scoped);
        if used_after {
            // Used after the loop: declared before it, not in its header.
            assert_eq!(declared_at(&after, i), Some(looped));
            assert!(text.contains("    int32_t v2;\n    for (v2 = 0;"), "{text}");
        } else {
            assert_eq!(declared_at(&after, i), Some(init));
            assert!(
                text.contains("for (int32_t v2 = 0; v2 < a1; v2++)"),
                "{text}"
            );
        }
    }
}

#[test]
fn a_value_live_into_a_block_keeps_it_out() {
    // s = 0; i = 0; while (i < p0) { if (i > 2) s = s + t; t = i; i = i + 1; }
    // return s: `t` from the iteration before is read, so it is declared
    // outside the loop (at the top: its first read may see no value).
    let (mut b, params) = B::new(1);
    let s = b.local();
    let i = b.local();
    let t = b.local();
    let zero = b.set(s, 0);
    let start = b.set(i, 0);
    let sum = b.vars(Binary::Add, s, t);
    let add = b.assign(s, sum);
    let test = b.gt(i, 2);
    let late = b.when(test, vec![add], Vec::new());
    let read = b.read(i);
    let keep = b.assign(t, read);
    let step = b.step(i, 1);
    let condition = b.vars(Binary::SLt, i, params[0]);
    let looped = b.s(Stmt::While {
        condition,
        body: vec![late, keep, step],
    });
    let back = b.ret(s);
    let f = b.done(vec![zero, start, looped, back]);
    let after = placed(&f);
    assert_eq!(declared_at(&after, t), None);
    assert!(c(&after, Placement::Scoped).contains("    int32_t v3;\n"));

    // Declared in the loop's body anyway, the interpreter sees the value
    // read across the declaration: the check that verifies the pass's
    // placements would catch it.
    let mut wrong = after;
    wrong.declared.insert(late, vec![t]);
    verify(&wrong, &DECLARATIONS).unwrap();
    let found = outcome(&wrong, &[6]);
    assert_ne!(outcome(&f, &[6]), found);
    assert!(
        matches!(found, Outcome::Returned(Some(value)) if value.known().is_none()),
        "{found:?}"
    );

    // Assigned only where a condition holds, then read: at the top.
    let (mut b, params) = B::new(1);
    let v = b.local();
    let one = b.set(v, 1);
    let test = b.op(Binary::SLt, params[0], 5);
    let branch = b.when(test, vec![one], Vec::new());
    let back = b.ret(v);
    let mut after = b.done(vec![branch, back]);
    scopes(&mut after);
    assert_eq!(declared_at(&after, v), None);
}

#[test]
fn a_goto_into_the_block_keeps_it_out() {
    for jumps in [false, true] {
        // if (p0 > 0 && p1 > 0) goto l; if (p1 > 0) { t = p0 + 1; x = t;
        // l: x = p1; } else x = 0; return x: the goto enters the scope `t`
        // and `x` would have, past their declarations. Without it (`return
        // p0` in its place) they are declared there.
        let (mut b, params) = B::new(2);
        let t = b.local();
        let x = b.local();
        let l = b.label();
        let sum = b.op(Binary::Add, params[0], 1);
        let set = b.assign(t, sum);
        let read = b.read(t);
        let copy = b.assign(x, read);
        let at = b.s(Stmt::Label(l));
        let other = b.read(params[1]);
        let again = b.assign(x, other);
        let none = b.set(x, 0);
        let second = b.gt(params[1], 0);
        let inner = b.when(second, vec![set, copy, at, again], vec![none]);
        let first = b.gt(params[0], 0);
        let both = b.f.add_expr(Expr::Binary(Binary::And, first, second));
        let leave = if jumps {
            b.s(Stmt::Goto(l))
        } else {
            b.ret(params[0])
        };
        let early = b.when(both, vec![leave], Vec::new());
        let back = b.ret(x);
        let body = vec![early, inner, back];
        let after = placed(&b.done(body));
        if jumps {
            assert_eq!(declared_at(&after, t), None);
            assert_eq!(declared_at(&after, x), None);
        } else {
            assert_eq!(declared_at(&after, t), Some(set));
            assert_eq!(declared_at(&after, x), Some(inner));
        }
    }
}

#[test]
fn a_declaration_after_a_label_follows_an_empty_statement() {
    // if (p0 > 0) goto l; l: v = p1 + 1; return v: C17 has no
    // declaration right after a label.
    let (mut b, params) = B::new(2);
    let v = b.local();
    let l = b.label();
    let test = b.gt(params[0], 0);
    let jump = b.s(Stmt::Goto(l));
    let branch = b.when(test, vec![jump], Vec::new());
    let at = b.s(Stmt::Label(l));
    let sum = b.op(Binary::Add, params[1], 1);
    let set = b.assign(v, sum);
    let back = b.ret(v);
    let after = placed(&b.done(vec![branch, at, set, back]));
    assert_eq!(declared_at(&after, v), Some(set));
    let text = c(&after, Placement::Scoped);
    assert!(
        text.contains(":\n    ;\n    int32_t v2 = a2 + 1;\n"),
        "{text}"
    );
}

#[test]
fn a_declaring_arm_keeps_its_braces_and_breaks_an_else_if_chain() {
    // if (p0 > 0) { v = p0; return v; } else if (p0 < -5) { w = 1;
    // return w; } else { w = 2; return w; }: `v` declared in the first
    // arm, `w` before the nested `if`, the second arm's only statement,
    // which then is no `else if`.
    let (mut b, params) = B::new(1);
    let v = b.local();
    let w = b.local();
    let read = b.read(params[0]);
    let set = b.assign(v, read);
    let early = b.ret(v);
    let one = b.set(w, 1);
    let first = b.ret(w);
    let two = b.set(w, 2);
    let second = b.ret(w);
    let low = b.op(Binary::SLt, params[0], 0xffff_fffb);
    let nested = b.when(low, vec![one, first], vec![two, second]);
    let high = b.gt(params[0], 0);
    let outer = b.when(high, vec![set, early], vec![nested]);
    let after = placed(&b.done(vec![outer]));
    assert_eq!(declared_at(&after, v), Some(set));
    assert_eq!(declared_at(&after, w), Some(nested));
    let text = c(&after, Placement::Scoped);
    assert!(!text.contains("else if"), "{text}");
    assert!(text.contains("} else {\n        int32_t v2;\n"), "{text}");
}
