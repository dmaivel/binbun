//! Building L2 functions by hand, printing them, and compiling C in a
//! scratch directory under `~/.cache/binbun-print-check`.

#![allow(dead_code, reason = "each test file uses some of the helpers")]

pub mod samples;

use std::path::PathBuf;
use std::process::Command;

use binbun_ast::ir::{
    Arm, Call, Callee, Escape, Expr, ExprId, Function, Name, NameOrigin, Place, Stmt, StmtId,
    VarId, VarKind, Variable,
};
use binbun_ast::types::{Evidence, Signature, Type, TypeId, Types};
use binbun_print::c::{self, Counts, HEADER, Image};
use binbun_print::layout;
use binbun_print::style::Style;
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Binary;
use binbun_semantics::{Declarations, IntrinsicInfo, RegisterInfo};

/// One register; intrinsics `pair` (one 32-bit input, two 32-bit
/// outputs) and `rdtsc` (no input, one 64-bit output).
pub const DECLARATIONS: Declarations = Declarations {
    registers: &[RegisterInfo {
        name: "rdi",
        width: 64,
    }],
    intrinsics: &[
        IntrinsicInfo {
            name: "pair",
            inputs: &[32],
            outputs: &[32, 32],
            escapes: false,
            stores: true,
            opaque: false,
        },
        IntrinsicInfo {
            name: "rdtsc",
            inputs: &[],
            outputs: &[64],
            escapes: false,
            stores: true,
            opaque: false,
        },
    ],
    sites: &[],
};

/// A function under construction.
pub struct Builder {
    pub f: Function,
}

impl Builder {
    pub fn new(address: u64, name: &str) -> Self {
        let mut f = Function::new(address, Types::new(64));
        f.name = Some(name.to_owned());
        Self { f }
    }

    pub fn ty(&mut self, ty: Type) -> TypeId {
        self.f.types.intern(ty)
    }

    pub fn int(&mut self, width: u16) -> TypeId {
        self.ty(Type::Int(width))
    }

    pub fn uint(&mut self, width: u16) -> TypeId {
        self.ty(Type::UInt(width))
    }

    pub fn bits(&mut self, width: u16) -> TypeId {
        self.ty(Type::Bits(width))
    }

    pub fn var(&mut self, kind: VarKind, ty: TypeId, name: Option<&str>) -> VarId {
        self.f.add_var(Variable {
            kind,
            name: name.map(|name| Name::new(name, NameOrigin::Debug)),
            ty,
            evidence: Evidence::Default,
            origins: Vec::new(),
        })
    }

    pub fn local(&mut self, ty: TypeId) -> VarId {
        self.var(VarKind::Local, ty, None)
    }

    pub fn param(&mut self, ty: TypeId) -> VarId {
        let id = self.var(VarKind::Parameter, ty, None);
        self.f.parameters.push(id);
        id
    }

    pub fn code(
        &mut self,
        parameters: Vec<TypeId>,
        returns: Option<TypeId>,
        variadic: bool,
    ) -> TypeId {
        self.ty(Type::Code(Signature {
            parameters,
            returns,
            variadic,
        }))
    }

    pub fn e(&mut self, expr: Expr) -> ExprId {
        self.f.add_expr(expr)
    }

    pub fn c(&mut self, width: u16, value: u64) -> ExprId {
        self.e(Expr::Const(Bits::from_u64(width, value)))
    }

    pub fn read(&mut self, var: VarId) -> ExprId {
        self.e(Expr::Var(var))
    }

    pub fn bin(&mut self, op: Binary, a: ExprId, b: ExprId) -> ExprId {
        self.e(Expr::Binary(op, a, b))
    }

    pub fn s(&mut self, stmt: Stmt) -> StmtId {
        self.f.add_stmt(stmt)
    }

    pub fn assign(&mut self, var: VarId, value: ExprId) -> StmtId {
        self.s(Stmt::Assign {
            place: Place::Var(var),
            value,
        })
    }

    pub fn ret(&mut self, value: ExprId) -> StmtId {
        self.s(Stmt::Return(Some(value)))
    }

    /// `if (condition) then`.
    pub fn when(&mut self, condition: ExprId, then: Vec<StmtId>) -> StmtId {
        self.s(Stmt::If {
            condition,
            then,
            otherwise: Vec::new(),
        })
    }

    /// A load of `ty` at `address + offset`.
    pub fn load_at(&mut self, address: ExprId, offset: u64, ty: TypeId) -> ExprId {
        let address = if offset == 0 {
            address
        } else {
            let offset = self.c(64, offset);
            self.bin(Binary::Add, address, offset)
        };
        self.e(Expr::Load { address, ty })
    }

    /// `value` zero- or sign-extended (`signed`) to `width` bits.
    pub fn ext(&mut self, signed: bool, value: ExprId, width: u16) -> ExprId {
        self.e(Expr::Extend {
            signed,
            value,
            width,
        })
    }

    /// `width` bits of `value` from bit `offset`.
    pub fn bits_of(&mut self, value: ExprId, offset: u16, width: u16) -> ExprId {
        self.e(Expr::Extract {
            value,
            offset,
            width,
        })
    }

    /// `value`'s bits as type `ty`.
    pub fn cast(&mut self, value: ExprId, ty: TypeId) -> ExprId {
        self.e(Expr::Cast { value, ty })
    }

    /// A call of `callee` with `arguments` (of code type `signature`, no
    /// variadic argument's type stated), its result to `results`.
    pub fn call(
        &mut self,
        callee: Callee,
        arguments: Vec<ExprId>,
        signature: TypeId,
        results: Vec<Place>,
    ) -> StmtId {
        self.s(Stmt::Call {
            results,
            call: Call {
                callee,
                arguments,
                signature,
                variadic: Vec::new(),
            },
        })
    }

    /// An escape.
    pub fn escape(&mut self, kind: Escape, operands: Vec<ExprId>, results: Vec<Place>) -> StmtId {
        self.s(Stmt::Escape {
            kind,
            operands,
            results,
        })
    }

    /// A placeholder statement, overwritten by [`Builder::set`] once its
    /// body exists (for a loop a `break` names).
    pub fn placeholder(&mut self) -> StmtId {
        self.s(Stmt::Unreachable)
    }

    pub fn set(&mut self, id: StmtId, stmt: Stmt) {
        self.f.stmts[id.0 as usize] = stmt;
    }

    /// The finished function, checked by the verifier.
    pub fn done(self, body: Vec<StmtId>) -> Function {
        let mut f = self.f;
        f.body = body;
        binbun_ast::verify::verify(&f, &DECLARATIONS).unwrap();
        f
    }
}

/// `f` printed under `style`, with names and read-only data from `image`;
/// every conversion printed as planned.
pub fn print_with(f: &Function, style: &Style, image: &dyn Image) -> (String, Counts) {
    let printed =
        c::function(f, &DECLARATIONS, style, image, c::Opaque::Calls).unwrap_or_else(|e| {
            panic!(
                "{}: {e}\n{}",
                f.name.as_deref().unwrap_or("?"),
                binbun_ast::text::print(f, &DECLARATIONS)
            )
        });
    let text = layout::render(&printed.document, style);
    assert_eq!(
        printed.counts.unplanned, 0,
        "unplanned conversions:\n{text}"
    );
    (text, printed.counts)
}

/// `f` printed under `style`, without symbols.
pub fn print(f: &Function, style: &Style) -> (String, Counts) {
    print_with(f, style, &|_: u64| None)
}

/// The width of `long` under LP64 (64-bit Linux and macOS).
pub const LP64: u16 = 64;

/// The width of `long` under LLP64 (64-bit Windows).
pub const LLP64: u16 = 32;

/// [`samples::symbols`]' names on a platform whose `long` is `.0` bits
/// ([`LP64`], [`LLP64`]).
pub struct Platform(pub u16);

impl Image for Platform {
    fn symbol(&self, address: u64) -> Option<String> {
        samples::symbols(address)
    }

    fn read_only(&self, _: u64, _: u64) -> bool {
        false
    }

    fn constant(&self, _: u64, _: u64) -> Option<Vec<u8>> {
        None
    }

    fn string(&self, _: u64) -> Option<Vec<u8>> {
        None
    }

    fn long_width(&self) -> u16 {
        self.0
    }
}

/// The compilers present to check binbun's C with; none on Windows. The
/// checks compile C written for an LP64 program (`long` 64 bits, as
/// Linux's and macOS's are), LLP64 output included, on a host of the
/// same model: Windows' `long` is 32 bits, so there they would measure
/// the host's mismatch, not the C.
pub fn compilers() -> Vec<&'static str> {
    if cfg!(windows) {
        eprintln!("binbun's C is checked on LP64 hosts (Linux, macOS), not Windows");
        return Vec::new();
    }
    ["gcc", "clang"]
        .into_iter()
        .filter(|compiler| {
            Command::new(compiler)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .collect()
}

/// The flags the output is compiled with.
pub const FLAGS: &[&str] = &[
    "-std=c11",
    "-fwrapv",
    "-fno-strict-aliasing",
    "-Wall",
    "-Wextra",
];

/// A scratch directory under `~/.cache/binbun-print-check`, with `binbun_defs.h`
/// in it, removed when dropped.
pub struct Scratch {
    pub dir: PathBuf,
}

impl Scratch {
    pub fn new(name: &str) -> Self {
        let dir = std::env::home_dir()
            .expect("a home directory")
            .join(".cache/binbun-print-check")
            .join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("binbun_defs.h"), HEADER).unwrap();
        Self { dir }
    }

    pub fn write(&self, file: &str, text: &str) -> PathBuf {
        let path = self.dir.join(file);
        std::fs::write(&path, text).unwrap();
        path
    }

    /// Runs `compiler` with `FLAGS`, `extra` and `sources` in the
    /// directory: Ok(stderr) if it succeeded, Err(stderr) if not.
    pub fn compile(
        &self,
        compiler: &str,
        extra: &[&str],
        sources: &[&str],
    ) -> Result<String, String> {
        let output = Command::new(compiler)
            .current_dir(&self.dir)
            .args(FLAGS)
            .args(extra)
            .args(sources)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if output.status.success() {
            Ok(stderr)
        } else {
            Err(stderr)
        }
    }

    /// Runs a program built in the directory; its stdout.
    pub fn run(&self, program: &str) -> String {
        let output = Command::new(self.dir.join(program)).output().unwrap();
        assert!(output.status.success(), "{program} failed: {output:?}");
        String::from_utf8(output.stdout).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // BINBUN_C_KEEP=1 keeps the files to look at.
        if std::env::var_os("BINBUN_C_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// The number of warnings in a compiler's output.
pub fn warnings(stderr: &str) -> usize {
    stderr
        .lines()
        .filter(|line| line.contains("warning:"))
        .count()
}

/// A switch arm for `values` of `width` bits.
pub fn arm(values: &[u64], width: u16, default: bool, body: Vec<StmtId>, fallthrough: bool) -> Arm {
    Arm {
        values: values.iter().map(|&v| Bits::from_u64(width, v)).collect(),
        default,
        body,
        fallthrough,
    }
}
