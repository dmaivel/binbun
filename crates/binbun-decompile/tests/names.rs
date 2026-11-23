#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Names from evidence ([`names::name`]) on hand-built L2: the function's
//! own declared parameter names over its callees', a callee's parameter
//! name passed most over one passed less, leading underscores dropped,
//! `for` counters by nesting, `result` for the one returned variable, and
//! debug information kept.

use binbun_ast::ir::{
    Call, Callee, Expr, ExprId, Function, Name, NameOrigin, Place, Stmt, StmtId, VarId, VarKind,
    Variable,
};
use binbun_ast::types::{Evidence, Signature, Type, TypeId, Types};
use binbun_decompile::names;
use binbun_decompile::prototype::{Prototype, Prototypes};
use binbun_semantics::bits::Bits;

/// Declarations naming parameters only: `f(__name)` (the function
/// itself, at 0x1000), `write(__fd, __buf)` at 0x2000, `puts(__s)` at
/// 0x3000.
struct Named;

impl Prototypes for Named {
    fn of(&self, _: u64, _: &mut Types) -> Option<Prototype> {
        None
    }

    fn parameter_names(&self, address: u64) -> Vec<Option<String>> {
        let names: &[&str] = match address {
            0x1000 => &["__name"],
            0x2000 => &["__fd", "__buf"],
            0x3000 => &["__s"],
            _ => &[],
        };
        names.iter().map(|name| Some((*name).to_owned())).collect()
    }
}

struct Builder {
    f: Function,
    int: TypeId,
}

impl Builder {
    fn new() -> Self {
        let mut types = Types::new(64);
        let int = types.intern(Type::Int(64));
        Self {
            f: Function::new(0x1000, types),
            int,
        }
    }

    fn var(&mut self, kind: VarKind) -> VarId {
        let id = self.f.add_var(Variable {
            kind,
            name: None,
            ty: self.int,
            evidence: Evidence::Default,
            origins: Vec::new(),
        });
        if kind == VarKind::Parameter {
            self.f.parameters.push(id);
        }
        id
    }

    fn read(&mut self, var: VarId) -> ExprId {
        self.f.add_expr(Expr::Var(var))
    }

    /// A call of the function at `address` passing `vars`.
    fn call(&mut self, address: u64, vars: &[VarId]) -> StmtId {
        let signature = self.f.types.intern(Type::Code(Signature {
            parameters: vec![self.int; vars.len()],
            returns: None,
            variadic: false,
        }));
        let arguments = vars.iter().map(|&var| self.read(var)).collect();
        self.f.add_stmt(Stmt::Call {
            results: Vec::new(),
            call: Call {
                callee: Callee::Address(address),
                arguments,
                signature,
                variadic: Vec::new(),
            },
        })
    }

    /// `for (; c; var = var + 1) { body }`.
    fn counted(&mut self, var: VarId, body: Vec<StmtId>) -> StmtId {
        let one = self.f.add_expr(Expr::Const(Bits::from_u64(64, 1)));
        let read = self.read(var);
        let sum = self
            .f
            .add_expr(Expr::Binary(binbun_semantics::ir::Binary::Add, read, one));
        let step = self.f.add_stmt(Stmt::Assign {
            place: Place::Var(var),
            value: sum,
        });
        let condition = self.read(var);
        self.f.add_stmt(Stmt::For {
            init: Vec::new(),
            condition,
            step: vec![step],
            body,
        })
    }

    fn name(&self, var: VarId) -> Option<(String, NameOrigin)> {
        let name = self.f.var(var)?.name.as_ref()?;
        Some((name.text.clone(), name.origin))
    }
}

#[test]
fn names_follow_the_strongest_evidence() {
    let mut b = Builder::new();
    let a1 = b.var(VarKind::Parameter);
    let (handle, text, debugged) = (
        b.var(VarKind::Local),
        b.var(VarKind::Local),
        b.var(VarKind::Local),
    );
    let (outer, inner, total) = (
        b.var(VarKind::Local),
        b.var(VarKind::Local),
        b.var(VarKind::Local),
    );
    b.f.variables[debugged.0 as usize].name = Some(Name::new("length", NameOrigin::Debug));
    // `handle` is passed as `fd` twice and as `buf` once; `a1` as `s`,
    // but the function's own declaration names it `name`; `debugged` as
    // `fd`, but debug information named it.
    let calls = [
        b.call(0x2000, &[handle, text]),
        b.call(0x2000, &[handle, handle]),
        b.call(0x3000, &[a1]),
        b.call(0x2000, &[debugged, text]),
    ];
    let deep = b.counted(inner, Vec::new());
    let shallow = b.counted(outer, vec![deep]);
    let returned = b.read(total);
    let ret = b.f.add_stmt(Stmt::Return(Some(returned)));
    b.f.body = calls.to_vec();
    b.f.body.extend([shallow, ret]);

    names::name(&mut b.f, &Named);

    let name = |text: &str, origin| Some((text.to_owned(), origin));
    assert_eq!(b.name(a1), name("name", NameOrigin::Declared));
    assert_eq!(b.name(handle), name("fd", NameOrigin::Argument));
    assert_eq!(b.name(text), name("buf", NameOrigin::Argument));
    assert_eq!(b.name(debugged), name("length", NameOrigin::Debug));
    assert_eq!(b.name(outer), name("i", NameOrigin::Counter));
    assert_eq!(b.name(inner), name("j", NameOrigin::Counter));
    assert_eq!(b.name(total), name("result", NameOrigin::Result));
}

#[test]
fn result_needs_one_returned_variable() {
    let mut b = Builder::new();
    let (x, y) = (b.var(VarKind::Local), b.var(VarKind::Local));
    let (rx, ry) = (b.read(x), b.read(y));
    let returns = [
        b.f.add_stmt(Stmt::Return(Some(rx))),
        b.f.add_stmt(Stmt::Return(Some(ry))),
    ];
    b.f.body = returns.to_vec();
    names::name(&mut b.f, &Named);
    assert_eq!(b.name(x), None);
    assert_eq!(b.name(y), None);
}

/// A function with more parameters than its declaration names (an
/// argument register a callee of unknown interface reads, after the
/// declared ones) takes the declared names for the leading parameters of
/// the declared types; not where those are not the declaration's.
#[test]
fn declared_names_name_the_declared_leading_parameters() {
    for (evidence, expected) in [
        (
            Evidence::Declared,
            Some(("name".to_owned(), NameOrigin::Declared)),
        ),
        (Evidence::Default, None),
    ] {
        let mut b = Builder::new();
        let (declared, extra) = (b.var(VarKind::Parameter), b.var(VarKind::Parameter));
        b.f.variables[declared.0 as usize].evidence = evidence;
        names::name(&mut b.f, &Named);
        assert_eq!(b.name(declared), expected, "{evidence:?}");
        assert_eq!(b.name(extra), None, "{evidence:?}");
    }
}
