//! Building L2 functions by hand, and a memory to run them on.

#![allow(dead_code, reason = "each test file uses some of the helpers")]

use std::collections::BTreeMap;

use binbun_ast::ir::{Expr, ExprId, Function, Place, Stmt, StmtId, VarId, VarKind, Variable};
use binbun_ast::types::{Evidence, Signature, Type, TypeId, Types};
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{Fault, Machine, Value};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_semantics::{Declarations, IntrinsicId, IntrinsicInfo, RegisterInfo};

/// One register, `rdi` (named in origins only); one intrinsic, `pair`,
/// from one 32-bit input to two 32-bit outputs.
pub const DECLARATIONS: Declarations = Declarations {
    registers: &[RegisterInfo {
        name: "rdi",
        width: 64,
    }],
    intrinsics: &[IntrinsicInfo {
        name: "pair",
        inputs: &[32],
        outputs: &[32, 32],
        escapes: false,
        stores: true,
        opaque: false,
    }],
    sites: &[],
};

/// Where the test memory ends: accesses at or past it fault.
pub const LIMIT: u64 = 0x1000;

/// The stack pointer on entry.
pub const STACK: u64 = 0x800;

pub const FUEL: u64 = 10_000;

/// A function under construction, with a few types interned.
pub struct Builder {
    pub f: Function,
    pub int8: TypeId,
    pub int16: TypeId,
    pub int32: TypeId,
    pub int64: TypeId,
    pub bool1: TypeId,
}

impl Builder {
    pub fn new() -> Self {
        let mut types = Types::new(64);
        let int8 = types.intern(Type::Int(8));
        let int16 = types.intern(Type::Int(16));
        let int32 = types.intern(Type::Int(32));
        let int64 = types.intern(Type::Int(64));
        let bool1 = types.intern(Type::Bool(1));
        Self {
            f: Function::new(0x1000, types),
            int8,
            int16,
            int32,
            int64,
            bool1,
        }
    }

    pub fn var(&mut self, kind: VarKind, ty: TypeId) -> VarId {
        self.f.add_var(Variable {
            kind,
            name: None,
            ty,
            evidence: Evidence::Default,
            origins: Vec::new(),
        })
    }

    pub fn local(&mut self, ty: TypeId) -> VarId {
        self.var(VarKind::Local, ty)
    }

    pub fn param(&mut self, ty: TypeId) -> VarId {
        let id = self.var(VarKind::Parameter, ty);
        self.f.parameters.push(id);
        id
    }

    pub fn code(&mut self, parameters: Vec<TypeId>, returns: Option<TypeId>) -> TypeId {
        self.f.types.intern(Type::Code(Signature {
            parameters,
            returns,
            variadic: false,
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

    /// `var op constant`, the constant as wide as the variable.
    pub fn op_c(&mut self, op: Binary, var: VarId, value: u64) -> ExprId {
        let read = self.read(var);
        let width = self.f.width(read).unwrap();
        let constant = self.c(width, value);
        self.bin(op, read, constant)
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

    /// `var = var + value`.
    pub fn add_to(&mut self, var: VarId, value: u64) -> StmtId {
        let sum = self.op_c(Binary::Add, var, value);
        self.assign(var, sum)
    }

    /// `var = constant`.
    pub fn set(&mut self, var: VarId, value: u64) -> StmtId {
        let width = self
            .f
            .types
            .value_width(self.f.var(var).unwrap().ty)
            .unwrap();
        let constant = self.c(width, value);
        self.assign(var, constant)
    }

    /// `return var`.
    pub fn ret(&mut self, var: VarId) -> StmtId {
        let read = self.read(var);
        self.s(Stmt::Return(Some(read)))
    }
}

/// A memory of bytes below [`LIMIT`] (0 where never written), and the
/// registers' values when the run starts (what `va_start` saves).
#[derive(Default)]
pub struct Memory {
    pub bytes: BTreeMap<u64, u8>,
    pub registers: BTreeMap<RegisterId, Value>,
}

impl Machine for Memory {
    fn read(&mut self, register: RegisterId) -> Value {
        self.registers[&register]
    }

    fn write(&mut self, _: RegisterId, _: Value) {
        unreachable!("L2 holds registers in variables")
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        if address + u64::from(bytes) > LIMIT {
            return Err(Fault {
                address,
                write: false,
            });
        }
        let mut buffer = [0u8; 8];
        for (offset, byte) in (0..u64::from(bytes)).zip(&mut buffer) {
            *byte = self.bytes.get(&(address + offset)).copied().unwrap_or(0);
        }
        Ok(defined(bytes * 8, u64::from_le_bytes(buffer)))
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        let bytes = u64::from(value.width() / 8);
        if address + bytes > LIMIT {
            return Err(Fault {
                address,
                write: true,
            });
        }
        for (offset, byte) in (0..bytes).zip(value.bits.low_u64().to_le_bytes()) {
            self.bytes.insert(address + offset, byte);
        }
        Ok(())
    }

    fn intrinsic(&mut self, _: IntrinsicId, inputs: &[Value], outputs: &[u16]) -> Vec<Value> {
        // `pair`: the input and its successor.
        let input = inputs[0].bits.low_u64();
        vec![defined(outputs[0], input), defined(outputs[1], input + 1)]
    }
}

pub fn defined(width: u16, value: u64) -> Value {
    Value::defined(Bits::from_u64(width, value))
}
