//! L2, binbun's structured code: one function as an AST with binbun's
//! exact semantics (not C's), between L1 ([`binbun_ssa`]) and the C
//! printer, for every architecture.
//!
//! - [`types`]: the type table ([`Types`](types::Types), interned
//!   [`TypeId`](types::TypeId)s, structs that may be recursive) and
//!   [`Evidence`](types::Evidence).
//! - [`ir`]: the data model ([`Function`](ir::Function) with arenas of
//!   variables, expressions and statements; provenance in a side table).
//! - [`verify`]: checking the model's rules.
//! - [`interpret`]: running a function on concrete state, as L1 runs.
//! - [`text`]: a readable text form.
//!
//! # The model in brief
//!
//! Expressions are L0's operations (every width and signedness explicit,
//! arithmetic wrapping) over [`ExprId`](ir::ExprId)s, plus variable reads,
//! addresses of variables in memory, [`Cast`](ir::Expr::Cast)s (the same
//! bits seen as another type) and typed [`Load`](ir::Expr::Load)s; they
//! have no effects but for a [`Call`](ir::Expr::Call) (C's `f(x)` as a
//! value). Effects are statements, at most one per statement:
//! [`Assign`](ir::Stmt::Assign), [`Call`](ir::Stmt::Call) (its return value
//! split over any number of places, as for `rax:rdx`),
//! [`Intrinsic`](ir::Stmt::Intrinsic) and [`Escape`](ir::Stmt::Escape) (what
//! C cannot say); calls in an expression are made once each, in an order
//! C fixes, with no memory read beside any of them (C does not order the
//! two): `f(g(x), y)` with `y` a local, `g(x) && h(y)`
//! ([`verify::ordered`]).
//! Control is `if`, `while`, `do`-`while`, `for`, `switch`
//! (explicit fallthrough), `break`/`continue` naming the statement they
//! leave, labels and `goto` (into any block), `return`, `trap` and
//! `unreachable`. Conditions are 1-bit values.
//!
//! Nodes are only appended (a rewrite adds a node and repoints its user),
//! with one exception: a pass may retype a [`Load`](ir::Expr::Load) or a
//! [`Place::Memory`](ir::Place::Memory) in place when the new type has the
//! same width; the meaning, the users and the provenance stay.
//! Variables and the return type carry [`Evidence`](types::Evidence) for
//! their types ([`Function::returns_evidence`](ir::Function::returns_evidence)).
//!
//! # Use
//!
//! Build a function: make a [`Types`](types::Types) table and intern the
//! types, create the [`Function`](ir::Function), add variables, then
//! expressions (operands first) and statements, and list the top-level
//! statements in [`body`](ir::Function::body). Attach provenance with
//! [`Provenance::set_expr`](ir::Provenance::set_expr) and
//! [`set_stmt`](ir::Provenance::set_stmt). Then [`verify::verify`] it,
//! [`interpret::run`] it, and [`text::print`] it:
//!
//! ```
//! use binbun_ast::interpret::{self, Outcome};
//! use binbun_ast::ir::{Expr, Function, Name, NameOrigin, Place, Stmt, VarKind, Variable};
//! use binbun_ast::types::{Evidence, Type, Types};
//! use binbun_ast::{text, verify};
//! use binbun_semantics::Declarations;
//! use binbun_semantics::bits::Bits;
//! use binbun_semantics::interpret::{Fault, Machine, Value};
//! use binbun_semantics::ir::{Binary, RegisterId};
//!
//! // int count(int n) { i = 0; while (i < n) i = i + 1; return i; }
//! let mut types = Types::new(64);
//! let int = types.intern(Type::Int(32));
//! let mut f = Function::new(0x401000, types);
//! f.name = Some("count".into());
//! let variable = |kind, name: Option<&str>, evidence| Variable {
//!     kind,
//!     name: name.map(|text| Name::new(text, NameOrigin::Declared)),
//!     ty: int,
//!     evidence,
//!     origins: Vec::new(),
//! };
//! let n = f.add_var(variable(VarKind::Parameter, Some("n"), Evidence::Declared));
//! let i = f.add_var(variable(VarKind::Local, None, Evidence::Default));
//! f.parameters.push(n);
//! f.returns = Some(int);
//! f.returns_evidence = Evidence::Declared;
//!
//! let zero = f.add_expr(Expr::Const(Bits::from_u64(32, 0)));
//! let one = f.add_expr(Expr::Const(Bits::from_u64(32, 1)));
//! let (read_i, read_n) = (f.add_expr(Expr::Var(i)), f.add_expr(Expr::Var(n)));
//! let less = f.add_expr(Expr::Binary(Binary::SLt, read_i, read_n));
//! let next = f.add_expr(Expr::Binary(Binary::Add, read_i, one));
//! let init = f.add_stmt(Stmt::Assign { place: Place::Var(i), value: zero });
//! let step = f.add_stmt(Stmt::Assign { place: Place::Var(i), value: next });
//! let body = vec![step];
//! let lp = f.add_stmt(Stmt::While { condition: less, body });
//! let done = f.add_stmt(Stmt::Return(Some(read_i)));
//! f.body = vec![init, lp, done];
//!
//! const NONE: Declarations = Declarations { registers: &[], intrinsics: &[], sites: &[] };
//! assert_eq!(verify::verify(&f, &NONE), Ok(()));
//!
//! /// A machine without memory.
//! struct Empty;
//! impl Machine for Empty {
//!     fn read(&mut self, _: RegisterId) -> Value { unreachable!() }
//!     fn write(&mut self, _: RegisterId, _: Value) { unreachable!() }
//!     fn load(&mut self, address: u64, _: u16) -> Result<Value, Fault> {
//!         Err(Fault { address, write: false })
//!     }
//!     fn store(&mut self, address: u64, _: Value) -> Result<(), Fault> {
//!         Err(Fault { address, write: true })
//!     }
//! }
//! let five = Value::defined(Bits::from_u64(32, 5));
//! let outcome = interpret::run(&f, &mut Empty, &[five], 0x7fff_0000, 1000);
//! assert_eq!(outcome, Outcome::Returned(Some(five)));
//!
//! assert_eq!(
//!     text::print(&f, &NONE),
//!     "function 0x401000 \"count\" (v0) -> int32 declared
//!   var v0 param int32 \"n\" declared
//!   var v1 local int32 default
//! {
//!   s0: v1 = 0x0:32
//!   s2: while slt(v1, v0) {
//!     s1: v1 = add(v1, 0x1:32)
//!   }
//!   s3: return v1
//! }
//! "
//! );
//! ```

#![no_std]

extern crate alloc;

pub mod interpret;
pub mod ir;
pub mod text;
pub mod types;
pub mod verify;
