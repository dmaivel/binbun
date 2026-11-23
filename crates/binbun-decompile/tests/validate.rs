#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The checks of `validate` on hand-built L1/L2 pairs: each passes a
//! faithful L2 and catches a deliberately wrong one.

use std::collections::BTreeMap;

use binbun_ast::ir::{
    Call, Callee, Expr, ExprId, Function as Ast, LabelId, Logical, Origin, Place, Stmt, StmtId,
    VarId, VarKind, Variable,
};
use binbun_ast::types::{Evidence, Signature, Type as AstType, TypeId, Types};
use binbun_decompile::itanium::NONE;
use binbun_decompile::mapping::{CallSite, Mapping, Piece, Source};
use binbun_decompile::validate::{
    Hashed, Link, Mismatch, RETURN_ADDRESS, Report, Setup, differential, random_states,
    shaped_states, structure as check,
};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_semantics::{Declarations, RegisterInfo};
use binbun_ssa::ir::{
    self, Block, BlockId, Definition, Function, Inst, InstId, Op, State, Target, Terminator, Type,
    Unknown, ValueInfo,
};

/// The structure check where no exceptions are known.
fn structure(l1: &Function, l2: &Ast) -> Result<(), Mismatch> {
    check(l1, l2, &NONE)
}

/// `a`, `b` (32 bits), the stack pointer `sp`, and a flag `c`.
const DECLARATIONS: Declarations = Declarations {
    registers: &[
        RegisterInfo {
            name: "a",
            width: 32,
        },
        RegisterInfo {
            name: "b",
            width: 32,
        },
        RegisterInfo {
            name: "sp",
            width: 64,
        },
        RegisterInfo {
            name: "c",
            width: 1,
        },
    ],
    intrinsics: &[],
    sites: &[],
};

const A: RegisterId = RegisterId(0);
const B: RegisterId = RegisterId(1);
const SP: RegisterId = RegisterId(2);

/// Where the stored result goes.
const GLOBAL: u64 = 0x2000;

/// The callee of the call tests.
const CALLEE: u64 = 0x5000;

fn setup() -> Setup<'static> {
    Setup {
        declarations: &DECLARATIONS,
        stack_pointer: SP,
        link: Link::Stack { bytes: 8 },
        fixed: Vec::new(),
        fuel: 100,
        frame: 0x1000,
        shadow: 0,
    }
}

fn run(l1: &Function, l2: &Ast, mapping: &Mapping) -> Report {
    let setup = setup();
    let states = random_states(&setup, 64, 7);
    differential(l1, l2, mapping, &setup, &Hashed, &states)
}

fn whole(register: RegisterId, width: u16) -> Piece {
    Piece {
        register,
        offset: 0,
        width,
    }
}

// L1 by hand.

/// The entry state's types: the registers, then the memory.
const STATE: [Type; 5] = [
    Type::Bits(32),
    Type::Bits(32),
    Type::Bits(64),
    Type::Bits(1),
    Type::Memory,
];

struct L1 {
    f: Function,
    current: BlockId,
}

impl L1 {
    /// A function with its entry block (block 0) jumping to block 1, whose
    /// parameters are returned.
    fn new() -> (Self, [ir::Value; 5]) {
        let mut l1 = Self {
            f: Function {
                entry: 0x1000,
                ..Function::default()
            },
            current: BlockId(0),
        };
        let (_, entry) = l1.block(0x1000);
        let (first, parameters) = l1.block(0x1000);
        l1.terminate_in(BlockId(0), Terminator::Jump(target(first, &entry)));
        l1.current = first;
        (l1, parameters)
    }

    fn value(&mut self, ty: Type, definition: Definition) -> ir::Value {
        let id = ir::Value(u32::try_from(self.f.values.len()).unwrap());
        self.f.values.push(ValueInfo { ty, definition });
        id
    }

    fn block(&mut self, address: u64) -> (BlockId, [ir::Value; 5]) {
        let block = BlockId(u32::try_from(self.f.blocks.len()).unwrap());
        let parameters: Vec<ir::Value> = (0..)
            .zip(STATE)
            .map(|(index, ty)| self.value(ty, Definition::Parameter { block, index }))
            .collect();
        self.f.blocks.push(Block {
            address,
            end: address,
            parameters: parameters.clone(),
            insts: Vec::new(),
            terminator: Terminator::Open,
        });
        (block, parameters.try_into().unwrap())
    }

    /// Appends `op` to the current block with results of `types`.
    fn inst(&mut self, op: Op, types: &[Type]) -> Vec<ir::Value> {
        let inst = InstId(u32::try_from(self.f.insts.len()).unwrap());
        let results = (0..)
            .zip(types)
            .map(|(index, &ty)| self.value(ty, Definition::Result { inst, index }))
            .collect::<Vec<_>>();
        self.f.insts.push(Inst {
            op,
            results: results.clone(),
            address: 0x1000 + u64::from(inst.0) * 4,
        });
        self.f.blocks[self.current.0 as usize].insts.push(inst);
        results
    }

    fn pure(&mut self, op: Op, width: u16) -> ir::Value {
        self.inst(op, &[Type::Bits(width)])[0]
    }

    fn constant(&mut self, width: u16, value: u64) -> ir::Value {
        self.pure(Op::Const(Bits::from_u64(width, value)), width)
    }

    fn terminate_in(&mut self, block: BlockId, terminator: Terminator) {
        self.f.blocks[block.0 as usize].terminator = terminator;
    }

    fn terminate(&mut self, terminator: Terminator) {
        self.terminate_in(self.current, terminator);
    }

    /// Returns with `registers` (a, b, c; the stack pointer popped) and
    /// `memory`: the return address loaded from `sp`.
    fn ret(&mut self, sp: ir::Value, registers: [ir::Value; 3], memory: ir::Value) {
        let address = self.pure(
            Op::Load {
                memory,
                address: sp,
                bytes: 8,
                atomic: None,
            },
            64,
        );
        let eight = self.constant(64, 8);
        let popped = self.pure(Op::Binary(Binary::Add, sp, eight), 64);
        let [a, b, c] = registers;
        self.terminate(Terminator::Return {
            address,
            state: State {
                registers: vec![a, b, popped, c],
                memory,
            },
        });
    }
}

fn target(block: BlockId, arguments: &[ir::Value]) -> Target {
    Target {
        block,
        arguments: arguments.to_vec(),
    }
}

// L2 by hand.

struct L2 {
    f: Ast,
    int16: TypeId,
    int32: TypeId,
    int64: TypeId,
}

impl L2 {
    fn new() -> Self {
        let mut types = Types::new(64);
        let int16 = types.intern(AstType::Int(16));
        let int32 = types.intern(AstType::Int(32));
        let int64 = types.intern(AstType::Int(64));
        let mut f = Ast::new(0x1000, types);
        f.returns = Some(int32);
        Self {
            f,
            int16,
            int32,
            int64,
        }
    }

    fn var(&mut self, kind: VarKind, ty: TypeId) -> VarId {
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

    fn s(&mut self, stmt: Stmt) -> StmtId {
        self.f.add_stmt(stmt)
    }

    /// `mem<ty>(address) = value`.
    fn store(&mut self, address: u64, ty: TypeId, value: ExprId) -> StmtId {
        let address = self.c(64, address);
        self.s(Stmt::Assign {
            place: Place::Memory { address, ty },
            value,
        })
    }

    fn verified(self) -> Ast {
        binbun_ast::verify::verify(&self.f, &DECLARATIONS).unwrap();
        self.f
    }
}

// The differential check.

/// `f(a, b)`: stores `a - b` (32 bits) at [`GLOBAL`] and returns it.
fn subtract_l1() -> Function {
    let (mut l1, [a, b, sp, c, memory]) = L1::new();
    let difference = l1.pure(Op::Binary(Binary::Sub, a, b), 32);
    let address = l1.constant(64, GLOBAL);
    let memory = l1.inst(
        Op::Store {
            memory,
            address,
            value: difference,
            atomic: None,
        },
        &[Type::Memory],
    )[0];
    l1.ret(sp, [difference, b, c], memory);
    l1.f
}

fn subtract_mapping() -> Mapping {
    Mapping {
        parameters: vec![
            Source::Register(whole(A, 32)),
            Source::Register(whole(B, 32)),
        ],
        returns: vec![whole(A, 32)],
        ..Mapping::default()
    }
}

/// How the L2 of `subtract_l1` is built.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Faithful,
    SwappedOperands,
    /// The subtraction in 16 bits, zero-extended.
    Narrow,
    /// Only the low 2 bytes stored.
    NarrowStore,
    MissingStore,
}

fn subtract_l2(variant: Variant) -> Ast {
    let mut l2 = L2::new();
    let (int16, int32) = (l2.int16, l2.int32);
    let a = l2.var(VarKind::Parameter, int32);
    let b = l2.var(VarKind::Parameter, int32);
    let (x, y) = (l2.read(a), l2.read(b));
    let difference = match variant {
        Variant::Faithful | Variant::NarrowStore | Variant::MissingStore => {
            l2.bin(Binary::Sub, x, y)
        }
        Variant::SwappedOperands => l2.bin(Binary::Sub, y, x),
        Variant::Narrow => {
            let low_x = l2.e(Expr::Extract {
                value: x,
                offset: 0,
                width: 16,
            });
            let low_y = l2.e(Expr::Extract {
                value: y,
                offset: 0,
                width: 16,
            });
            let narrow = l2.bin(Binary::Sub, low_x, low_y);
            l2.e(Expr::Extend {
                signed: false,
                value: narrow,
                width: 32,
            })
        }
    };
    let mut body = Vec::new();
    match variant {
        Variant::MissingStore => {}
        Variant::NarrowStore => {
            let low = l2.e(Expr::Extract {
                value: difference,
                offset: 0,
                width: 16,
            });
            body.push(l2.store(GLOBAL, int16, low));
        }
        Variant::Faithful | Variant::SwappedOperands | Variant::Narrow => {
            body.push(l2.store(GLOBAL, int32, difference));
        }
    }
    body.push(l2.s(Stmt::Return(Some(difference))));
    l2.f.body = body;
    l2.verified()
}

#[test]
fn differential_passes_a_faithful_l2() {
    let report = run(
        &subtract_l1(),
        &subtract_l2(Variant::Faithful),
        &subtract_mapping(),
    );
    assert!(report.passed(), "{:?}", report.differences);
    assert_eq!(report.agreed, 64);
}

#[test]
fn differential_catches_swapped_operands() {
    let report = run(
        &subtract_l1(),
        &subtract_l2(Variant::SwappedOperands),
        &subtract_mapping(),
    );
    assert!(!report.passed());
    // Equal operands are the only states that agree.
    assert!(report.differences.len() > 48, "{report:?}");
}

#[test]
fn differential_catches_a_wrong_width() {
    let report = run(
        &subtract_l1(),
        &subtract_l2(Variant::Narrow),
        &subtract_mapping(),
    );
    assert!(!report.passed());
    assert!(
        report
            .differences
            .iter()
            .any(|difference| difference.message.starts_with("returns")),
        "{report:?}"
    );
}

#[test]
fn differential_catches_a_narrow_or_missing_store() {
    for variant in [Variant::NarrowStore, Variant::MissingStore] {
        let report = run(&subtract_l1(), &subtract_l2(variant), &subtract_mapping());
        assert!(!report.passed());
        assert!(
            report
                .differences
                .iter()
                .all(|difference| difference.message.starts_with("memory at 0x200")),
            "{report:?}"
        );
    }
}

#[test]
fn differential_refuses_a_mapping_of_the_wrong_width() {
    let mut mapping = subtract_mapping();
    mapping.parameters[1] = Source::Register(Piece {
        register: B,
        offset: 0,
        width: 16,
    });
    let report = run(&subtract_l1(), &subtract_l2(Variant::Faithful), &mapping);
    assert_eq!(report.differences.len(), 64);
    assert!(report.differences[0].message.starts_with("parameter 1"));
}

#[test]
fn differential_leaves_the_bits_above_declared_parameters_undefined() {
    // Declared 16-bit parameters in the 32-bit registers: the convention
    // leaves the bits above them unspecified, so the subtraction in 16
    // bits (a wrong width without the declaration) is faithful.
    let mut mapping = subtract_mapping();
    mapping.declared = vec![whole(A, 16), whole(B, 16)];
    let report = run(&subtract_l1(), &subtract_l2(Variant::Narrow), &mapping);
    assert!(report.passed(), "{:?}", report.differences);
    assert_eq!(report.agreed, 64);
}

/// `f(a)`: calls [`CALLEE`] with `a + 1` in `a` and its stack argument
/// (8 bytes at `sp + 8` in the callee: `b`, pushed), returns what it gives;
/// with `local`, first stores 0x1234 (8 bytes) at `sp - 8`. The callee's
/// entry stack pointer is `sp - 24`.
fn call_l1(local: bool) -> (Function, ir::Value) {
    let (mut l1, [a, b, sp, c, memory]) = L1::new();
    let one = l1.constant(32, 1);
    let argument = l1.pure(Op::Binary(Binary::Add, a, one), 32);
    let frame = l1.constant(64, 24);
    let below = l1.pure(Op::Binary(Binary::Sub, sp, frame), 64);
    let eight = l1.constant(64, 8);
    let slot = l1.pure(Op::Binary(Binary::Add, below, eight), 64);
    let wide = l1.pure(
        Op::Extend {
            signed: false,
            value: b,
            width: 64,
        },
        64,
    );
    let memory = l1.inst(
        Op::Store {
            memory,
            address: slot,
            value: wide,
            atomic: None,
        },
        &[Type::Memory],
    )[0];
    let memory = if local {
        let value = l1.constant(64, 0x1234);
        let eight = l1.constant(64, 8);
        let address = l1.pure(Op::Binary(Binary::Sub, sp, eight), 64);
        l1.inst(
            Op::Store {
                memory,
                address,
                value,
                atomic: None,
            },
            &[Type::Memory],
        )[0]
    } else {
        memory
    };
    let callee = l1.constant(64, CALLEE);
    let back = l1.constant(64, 0x1100);
    let results = l1.inst(
        Op::Call {
            target: callee,
            return_address: back,
            memory,
            registers: vec![argument, b, below, c],
            changes: vec![A],
        },
        &[Type::Memory, Type::Bits(32)],
    );
    l1.ret(sp, [results[1], b, c], results[0]);
    (l1.f, callee)
}

/// How `call_l2` treats the 24 bytes below the stack pointer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// Not a variable.
    Absent,
    /// A frame variable (an escaped frame) never written.
    Declared,
    /// A frame variable whose high 8 bytes get 0x1234.
    Stored,
}

/// L2 of `call_l1`: `return callee(a + one, b)` (with `one` `None`, its
/// first argument undefined).
fn call_l2(callee: ir::Value, one: Option<u64>, frame: Frame) -> Ast {
    let mut l2 = L2::new();
    let (int32, int64) = (l2.int32, l2.int64);
    let a = l2.var(VarKind::Parameter, int32);
    let b = l2.var(VarKind::Parameter, int32);
    let result = l2.var(VarKind::Local, int32);
    let mut body = Vec::new();
    if frame != Frame::Absent {
        let byte = l2.f.types.intern(AstType::UInt(8));
        let bytes = l2.f.types.intern(AstType::Array {
            element: byte,
            length: Some(24),
        });
        let buffer = l2.var(VarKind::Frame(-24), bytes);
        if frame == Frame::Stored {
            let start = l2.e(Expr::AddressOf(buffer));
            let sixteen = l2.c(64, 16);
            let address = l2.bin(Binary::Add, start, sixteen);
            let value = l2.c(64, 0x1234);
            body.push(l2.s(Stmt::Assign {
                place: Place::Memory { address, ty: int64 },
                value,
            }));
        }
    }
    let (x, y) = (l2.read(a), l2.read(b));
    let argument = match one {
        Some(one) => {
            let constant = l2.c(32, one);
            l2.bin(Binary::Add, x, constant)
        }
        None => l2.e(Expr::Undefined(
            32,
            Unknown::Call {
                address: 0x1000,
                register: B,
            },
            None,
        )),
    };
    let wide = l2.e(Expr::Extend {
        signed: false,
        value: y,
        width: 64,
    });
    let signature = l2.f.types.intern(AstType::Code(Signature {
        parameters: vec![int32, int64],
        returns: Some(int32),
        variadic: false,
    }));
    let call = l2.s(Stmt::Call {
        results: vec![Place::Var(result)],
        call: Call {
            callee: Callee::Address(CALLEE),
            arguments: vec![argument, wide],
            signature,
            variadic: Vec::new(),
        },
    });
    l2.f.provenance
        .set_stmt(call, &[Origin::Value(callee), Origin::Instruction(0x1000)]);
    let value = l2.read(result);
    let ret = l2.s(Stmt::Return(Some(value)));
    body.extend([call, ret]);
    l2.f.body = body;
    l2.verified()
}

fn call_mapping(callee: ir::Value) -> Mapping {
    Mapping {
        parameters: vec![
            Source::Register(whole(A, 32)),
            Source::Register(whole(B, 32)),
        ],
        returns: vec![whole(A, 32)],
        calls: BTreeMap::from([(
            callee,
            CallSite {
                arguments: vec![
                    Source::Register(whole(A, 32)),
                    Source::Stack {
                        offset: 8,
                        bytes: 8,
                    },
                ],
                results: vec![whole(A, 32)],
            },
        )]),
        dropped: Vec::new(),
        unnamed: Vec::new(),
        declared: Vec::new(),
    }
}

#[test]
fn differential_compares_call_arguments() {
    let (l1, callee) = call_l1(false);
    let report = run(
        &l1,
        &call_l2(callee, Some(1), Frame::Absent),
        &call_mapping(callee),
    );
    assert!(report.passed(), "{:?}", report.differences);
    assert_eq!(report.agreed, 64);
    let report = run(
        &l1,
        &call_l2(callee, Some(2), Frame::Absent),
        &call_mapping(callee),
    );
    assert_eq!(report.differences.len(), 64, "{report:?}");
    assert!(report.differences[0].message.starts_with("argument 0"));
    // An undefined argument where L1 passes a value is a difference.
    let report = run(
        &l1,
        &call_l2(callee, None, Frame::Absent),
        &call_mapping(callee),
    );
    assert_eq!(report.differences.len(), 64, "{report:?}");
    assert!(report.differences[0].message.starts_with("argument 0"));
    // Unless the register it comes from is dropped from the interface.
    let mut mapping = call_mapping(callee);
    mapping.dropped = vec![A];
    let report = run(&l1, &call_l2(callee, None, Frame::Absent), &mapping);
    assert!(report.passed(), "{:?}", report.differences);
    assert_eq!(report.agreed, 64);
}

#[test]
fn differential_catches_a_wrong_stack_argument() {
    let (l1, callee) = call_l1(false);
    let mut mapping = call_mapping(callee);
    mapping.calls.get_mut(&callee).unwrap().arguments[1] = Source::Stack {
        offset: 0,
        bytes: 8,
    };
    let report = run(&l1, &call_l2(callee, Some(1), Frame::Absent), &mapping);
    assert_eq!(report.differences.len(), 64, "{report:?}");
    assert!(report.differences[0].message.starts_with("argument 1"));
}

/// In an escaped frame, the bytes a call takes as stack arguments are L2's
/// call arguments, not stores; the frame's other bytes compare.
#[test]
fn differential_compares_an_escaped_frame_but_not_stack_arguments() {
    let (l1, callee) = call_l1(false);
    let report = run(
        &l1,
        &call_l2(callee, Some(1), Frame::Declared),
        &call_mapping(callee),
    );
    assert!(report.passed(), "{:?}", report.differences);
    let (l1, callee) = call_l1(true);
    let report = run(
        &l1,
        &call_l2(callee, Some(1), Frame::Stored),
        &call_mapping(callee),
    );
    assert!(report.passed(), "{:?}", report.differences);
    // Without the frame variable the store is dead to the caller...
    let report = run(
        &l1,
        &call_l2(callee, Some(1), Frame::Absent),
        &call_mapping(callee),
    );
    assert!(report.passed(), "{:?}", report.differences);
    // ...with it, a missing store is a difference.
    let report = run(
        &l1,
        &call_l2(callee, Some(1), Frame::Declared),
        &call_mapping(callee),
    );
    assert_eq!(report.differences.len(), 64, "{report:?}");
    assert!(report.differences[0].message.starts_with("memory at"));
}

// The structure check.

/// Blocks: 0 → 1; 1: `a == 0` ? 2 : 3; 2 → 3 (or with `looping`, 2 → 1);
/// 3 returns.
fn diamond_l1(looping: bool) -> Function {
    let (mut l1, parameters) = L1::new();
    let a = parameters[0];
    let zero = l1.constant(32, 0);
    let condition = l1.pure(Op::Binary(Binary::Eq, a, zero), 1);
    let (two, two_parameters) = l1.block(0x1010);
    let (three, three_parameters) = l1.block(0x1020);
    l1.terminate(Terminator::Branch {
        condition,
        then: target(two, &parameters),
        otherwise: target(three, &parameters),
    });
    l1.current = two;
    let back = if looping { BlockId(1) } else { three };
    l1.terminate(Terminator::Jump(target(back, &two_parameters)));
    l1.current = three;
    let [a3, b3, sp3, c3, memory3] = three_parameters;
    l1.ret(sp3, [a3, b3, c3], memory3);
    l1.f
}

/// Makes `stmt` stand for L1 block `block`.
fn tag(l2: &mut L2, stmt: StmtId, block: u32) -> StmtId {
    l2.f.provenance
        .set_stmt(stmt, &[Origin::Block(BlockId(block))]);
    stmt
}

/// What an L2 of [`diamond_l1`] is made of: labels `l0`–`l2` (for gotos
/// to blocks 1–3) and their statements, block 2's code (a store) and
/// block 1's condition.
struct Parts {
    labels: [LabelId; 3],
    statements: [StmtId; 3],
    code: StmtId,
    condition: ExprId,
}

/// An L2 of [`diamond_l1`], its body made by `body` from the [`Parts`].
fn diamond_l2(body: impl FnOnce(&mut L2, &Parts) -> Vec<StmtId>) -> Ast {
    let mut l2 = L2::new();
    let int32 = l2.int32;
    let a = l2.var(VarKind::Parameter, int32);
    let x = l2.read(a);
    let zero = l2.c(32, 0);
    let condition = l2.bin(Binary::Eq, x, zero);
    let labels = [l2.f.add_label(), l2.f.add_label(), l2.f.add_label()];
    let statements = labels.map(|label| l2.s(Stmt::Label(label)));
    let value = l2.read(a);
    let code = l2.store(GLOBAL, int32, value);
    tag(&mut l2, code, 2);
    let parts = Parts {
        labels,
        statements,
        code,
        condition,
    };
    l2.f.body = body(&mut l2, &parts);
    l2.verified()
}

/// `if (condition) then else otherwise`, block 1's decision.
fn decide(l2: &mut L2, condition: ExprId, then: Vec<StmtId>, otherwise: Vec<StmtId>) -> StmtId {
    let stmt = l2.s(Stmt::If {
        condition,
        then,
        otherwise,
    });
    tag(l2, stmt, 1)
}

/// `return a`, of no block.
fn early(l2: &mut L2) -> StmtId {
    let value = l2.read(l2.f.parameters[0]);
    l2.s(Stmt::Return(Some(value)))
}

/// `return a`, block 3.
fn ret(l2: &mut L2) -> StmtId {
    let stmt = early(l2);
    tag(l2, stmt, 3)
}

#[test]
fn structure_passes_goto_form_and_if() {
    let l1 = diamond_l1(false);
    // l0: if (c) goto l1; else goto l2;  l1: code; goto l2;  l2: return.
    let l2 = diamond_l2(|l2, parts| {
        let [s0, s1, s2] = parts.statements;
        let to1 = l2.s(Stmt::Goto(parts.labels[1]));
        let to2 = l2.s(Stmt::Goto(parts.labels[2]));
        let branch = decide(l2, parts.condition, vec![to1], vec![to2]);
        let again = l2.s(Stmt::Goto(parts.labels[2]));
        let r = ret(l2);
        vec![s0, branch, s1, parts.code, again, s2, r]
    });
    structure(&l1, &l2).unwrap();
    // if (c) { code } return: no labels.
    let l2 = diamond_l2(|l2, parts| {
        let branch = decide(l2, parts.condition, vec![parts.code], Vec::new());
        let r = ret(l2);
        vec![branch, r]
    });
    structure(&l1, &l2).unwrap();
}

#[test]
fn structure_catches_a_dropped_edge() {
    let l1 = diamond_l1(false);
    // The branch dropped: code; return. Both ways of block 1's branch
    // come to block 3, so L1 may go straight there (a decision with
    // nothing in either arm may be dropped), but not to block 2's code.
    let l2 = diamond_l2(|l2, parts| {
        let r = ret(l2);
        vec![parts.code, r]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert!(
        mismatch
            .message
            .contains("starts at block 2 where L1 starts at block 3"),
        "{mismatch}"
    );
    // Block 2 returns instead of going on to block 3.
    let l2 = diamond_l2(|l2, parts| {
        let early = early(l2);
        let branch = decide(l2, parts.condition, vec![parts.code, early], Vec::new());
        let r = ret(l2);
        vec![branch, r]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(2)), "{mismatch}");
    assert!(mismatch.message.contains("goes to the exit"), "{mismatch}");
    // Block 1's `else` dropped: block 3 is only reached through block 2.
    let l2 = diamond_l2(|l2, parts| {
        let r = ret(l2);
        let exit = early(l2);
        let branch = decide(l2, parts.condition, vec![parts.code, r], vec![exit]);
        vec![branch]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
}

#[test]
fn structure_catches_an_extra_edge() {
    let l1 = diamond_l1(false);
    // Block 2 decides too: if (c) { code; if (c) return; } return.
    let l2 = diamond_l2(|l2, parts| {
        let early = early(l2);
        let inner = l2.s(Stmt::If {
            condition: parts.condition,
            then: vec![early],
            otherwise: Vec::new(),
        });
        tag(l2, inner, 2);
        let branch = decide(l2, parts.condition, vec![parts.code, inner], Vec::new());
        let r = ret(l2);
        vec![branch, r]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(2)), "{mismatch}");
    assert!(
        mismatch.message.contains("L2 goes to the exit"),
        "{mismatch}"
    );
}

#[test]
fn structure_contracts_only_the_jumps_l2_has_nothing_of() {
    let l1 = diamond_l1(false);
    // Block 2 left nothing (`if (c) {} return`): going through it or not
    // is the same.
    let l2 = diamond_l2(|l2, parts| {
        let branch = decide(l2, parts.condition, Vec::new(), Vec::new());
        let r = ret(l2);
        vec![branch, r]
    });
    structure(&l1, &l2).unwrap();
    // Block 3 returns: L2 must have it (not go to the exit in its place).
    let l2 = diamond_l2(|l2, parts| {
        let branch = decide(l2, parts.condition, vec![parts.code], Vec::new());
        let r = early(l2);
        vec![branch, r]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
    assert!(
        mismatch.message.contains("L2 goes to the exit"),
        "{mismatch}"
    );
}

#[test]
fn structure_passes_a_while_loop_and_catches_a_lost_back_edge() {
    let l1 = diamond_l1(true);
    // while (c) { code } return.
    let l2 = diamond_l2(|l2, parts| {
        let looping = l2.s(Stmt::While {
            condition: parts.condition,
            body: vec![parts.code],
        });
        tag(l2, looping, 1);
        let r = ret(l2);
        vec![looping, r]
    });
    structure(&l1, &l2).unwrap();
    // The loop as an if: block 2 falls into block 3.
    let l2 = diamond_l2(|l2, parts| {
        let branch = decide(l2, parts.condition, vec![parts.code], Vec::new());
        let r = ret(l2);
        vec![branch, r]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(2)), "{mismatch}");
}

/// `while (1) { if (c) {} else { break; } code } return`, with or
/// without the `break`.
fn endless(l2: &mut L2, parts: &Parts, exits: bool) -> Vec<StmtId> {
    let looping = l2.s(Stmt::Unreachable);
    let otherwise = if exits {
        vec![l2.s(Stmt::Break(looping))]
    } else {
        Vec::new()
    };
    let branch = decide(l2, parts.condition, Vec::new(), otherwise);
    let always = l2.c(1, 1);
    l2.f.stmts[looping.0 as usize] = Stmt::While {
        condition: always,
        body: vec![branch, parts.code],
    };
    let r = ret(l2);
    vec![looping, r]
}

#[test]
fn structure_passes_an_endless_loop_and_catches_a_dropped_exit() {
    let l1 = diamond_l1(true);
    let l2 = diamond_l2(|l2, parts| endless(l2, parts, true));
    structure(&l1, &l2).unwrap();
    // Without the `break`, block 1 no longer goes to block 3.
    let l2 = diamond_l2(|l2, parts| endless(l2, parts, false));
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
    assert!(mismatch.message.contains("block 3"), "{mismatch}");
}

#[test]
fn structure_terminates_on_an_empty_endless_loop() {
    let l1 = diamond_l1(true);
    // while (1) {} code; return.
    let l2 = diamond_l2(|l2, parts| {
        let always = l2.c(1, 1);
        let looping = l2.s(Stmt::While {
            condition: always,
            body: Vec::new(),
        });
        let r = ret(l2);
        vec![looping, parts.code, r]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert!(
        mismatch.message.contains("starts at a loop of no block"),
        "{mismatch}"
    );
}

#[test]
fn structure_catches_a_block_deciding_twice() {
    let l1 = diamond_l1(false);
    // Block 1's decision twice: control comes back to block 1.
    let l2 = diamond_l2(|l2, parts| {
        let inner = decide(l2, parts.condition, vec![parts.code], Vec::new());
        let outer = decide(l2, parts.condition, vec![inner], Vec::new());
        let r = ret(l2);
        vec![outer, r]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
    assert!(
        mismatch.message.contains("L2 goes to block 1"),
        "{mismatch}"
    );
}

#[test]
fn structure_checks_each_copy_of_a_block_against_all_its_successors() {
    // `if (c) { code; return } return`: block 3 copied into the `then`.
    let l1 = diamond_l1(false);
    let l2 = diamond_l2(|l2, parts| {
        let copy = ret(l2);
        let branch = decide(l2, parts.condition, vec![parts.code, copy], Vec::new());
        let r = ret(l2);
        vec![branch, r]
    });
    structure(&l1, &l2).unwrap();
    // In the loop, block 1's decision copied after block 2, both of its
    // arms returning: each block is reached with all its successors
    // somewhere, but that entry into block 1 never goes back to block 2
    // (or past it, a jump, to block 1).
    let l1 = diamond_l1(true);
    let l2 = diamond_l2(|l2, parts| {
        let [one, two] = [ret(l2), ret(l2)];
        let copy = decide(l2, parts.condition, vec![one], vec![two]);
        let branch = decide(l2, parts.condition, vec![parts.code, copy], Vec::new());
        let r = ret(l2);
        vec![branch, r]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
    assert!(
        mismatch
            .message
            .contains("L1 goes to block 1 or block 2 where L2 does not"),
        "{mismatch}"
    );
}

/// Blocks: 0 → 1; 1: `a == 0` ? 2 : 3; 2 → 4; 3 → 4; 4 → 5; 5 returns.
fn exit_l1() -> Function {
    let (mut l1, parameters) = L1::new();
    let zero = l1.constant(32, 0);
    let condition = l1.pure(Op::Binary(Binary::Eq, parameters[0], zero), 1);
    let (two, two_parameters) = l1.block(0x1010);
    let (three, three_parameters) = l1.block(0x1020);
    let (four, four_parameters) = l1.block(0x1030);
    let (five, five_parameters) = l1.block(0x1040);
    l1.terminate(Terminator::Branch {
        condition,
        then: target(two, &parameters),
        otherwise: target(three, &parameters),
    });
    l1.terminate_in(two, Terminator::Jump(target(four, &two_parameters)));
    l1.terminate_in(three, Terminator::Jump(target(four, &three_parameters)));
    l1.terminate_in(four, Terminator::Jump(target(five, &four_parameters)));
    l1.current = five;
    let [a, b, sp, c, memory] = five_parameters;
    l1.ret(sp, [a, b, c], memory);
    l1.f
}

/// An L2 of [`exit_l1`]: `if (a == 0) { then } else { otherwise }`, the
/// arms made by `arms` from a maker of block `n`'s store and a maker of
/// returns (block 5's, or of no block).
fn exit_l2(
    arms: impl FnOnce(
        &mut L2,
        &dyn Fn(&mut L2, u32) -> StmtId,
        &dyn Fn(&mut L2, bool) -> StmtId,
    ) -> [Vec<StmtId>; 2],
) -> Ast {
    let mut l2 = L2::new();
    let int32 = l2.int32;
    let a = l2.var(VarKind::Parameter, int32);
    let x = l2.read(a);
    let zero = l2.c(32, 0);
    let condition = l2.bin(Binary::Eq, x, zero);
    let store = move |l2: &mut L2, block: u32| {
        let value = l2.read(a);
        let stmt = l2.store(GLOBAL, int32, value);
        tag(l2, stmt, block)
    };
    let exit = |l2: &mut L2, of_five: bool| {
        let stmt = early(l2);
        if of_five { tag(l2, stmt, 5) } else { stmt }
    };
    let [then, otherwise] = arms(&mut l2, &store, &exit);
    let branch = decide(&mut l2, condition, then, otherwise);
    l2.f.body = vec![branch];
    l2.verified()
}

#[test]
fn structure_contracts_a_jump_where_one_copy_has_nothing_of_it() {
    let l1 = exit_l1();
    // Blocks 4 and 5 copied into both arms; the `else`'s copy of block 4
    // folded away (block 3 had nothing either): that entry goes past it.
    let l2 = exit_l2(|l2, store, exit| {
        let then = vec![store(l2, 2), store(l2, 4), exit(l2, true)];
        [then, vec![exit(l2, true)]]
    });
    structure(&l1, &l2).unwrap();
    // Past a block that only jumps, never past one that returns.
    let l2 = exit_l2(|l2, store, exit| {
        let then = vec![store(l2, 2), store(l2, 4), exit(l2, true)];
        [then, vec![exit(l2, false)]]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
    assert!(
        mismatch
            .message
            .contains("L2 goes to the exit where L1 does not"),
        "{mismatch}"
    );
    // Both arms to block 2: nothing goes where block 3 leads.
    let l2 = exit_l2(|l2, store, exit| {
        let then = vec![store(l2, 2), exit(l2, true)];
        [then, vec![store(l2, 2), store(l2, 4), exit(l2, true)]]
    });
    let mismatch = structure(&l1, &l2).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
    assert!(
        mismatch
            .message
            .contains("L1 goes to block 4 or block 5 where L2 does not"),
        "{mismatch}"
    );
}

/// Blocks: 0 → 1; 1: `a == 0` ? 2 : 4; 2: `b == 0` ? 3 : 4; 3 and 4
/// return.
fn chain_l1() -> Function {
    let (mut l1, parameters) = L1::new();
    let zero = l1.constant(32, 0);
    let first = l1.pure(Op::Binary(Binary::Eq, parameters[0], zero), 1);
    let (two, two_parameters) = l1.block(0x1010);
    let (three, three_parameters) = l1.block(0x1020);
    let (four, four_parameters) = l1.block(0x1030);
    l1.terminate(Terminator::Branch {
        condition: first,
        then: target(two, &parameters),
        otherwise: target(four, &parameters),
    });
    l1.current = two;
    let zero = l1.constant(32, 0);
    let second = l1.pure(Op::Binary(Binary::Eq, two_parameters[1], zero), 1);
    l1.terminate(Terminator::Branch {
        condition: second,
        then: target(three, &two_parameters),
        otherwise: target(four, &two_parameters),
    });
    for (block, [a, b, sp, c, memory]) in [(three, three_parameters), (four, four_parameters)] {
        l1.current = block;
        l1.ret(sp, [a, b, c], memory);
    }
    l1.f
}

/// How an L2 of [`chain_l1`] merges its two decisions.
#[derive(Clone, Copy)]
struct Merged {
    op: Logical,
    /// The blocks the left and right operands stand for.
    blocks: [u32; 2],
    /// Whether the arms are swapped.
    swapped: bool,
}

/// `if (a == 0 && b == 0) return a; return b;` (block 3, then block 4),
/// as `merged` says.
fn chain_l2(merged: Merged) -> Ast {
    let mut l2 = L2::new();
    let int32 = l2.int32;
    let [a, b] = [0, 1].map(|_| l2.var(VarKind::Parameter, int32));
    let [left, right] = [a, b].map(|var| {
        let x = l2.read(var);
        let zero = l2.c(32, 0);
        l2.bin(Binary::Eq, x, zero)
    });
    let [left_block, right_block] = merged.blocks;
    l2.f.provenance
        .set_expr(right, &[Origin::Block(BlockId(right_block))]);
    let condition = l2.e(Expr::Logical(merged.op, left, right));
    let [first, second] = [(a, 3), (b, 4)].map(|(var, block)| {
        let value = l2.read(var);
        let stmt = l2.s(Stmt::Return(Some(value)));
        tag(&mut l2, stmt, block)
    });
    let (then, after) = if merged.swapped {
        (second, first)
    } else {
        (first, second)
    };
    let branch = l2.s(Stmt::If {
        condition,
        then: vec![then],
        otherwise: Vec::new(),
    });
    tag(&mut l2, branch, left_block);
    l2.f.body = vec![branch, after];
    l2.verified()
}

const AND: Merged = Merged {
    op: Logical::And,
    blocks: [1, 2],
    swapped: false,
};

#[test]
fn structure_splits_a_merged_and_into_its_blocks_decisions() {
    structure(&chain_l1(), &chain_l2(AND)).unwrap();
}

#[test]
fn structure_catches_a_wrong_merge() {
    let l1 = chain_l1();
    // `||`: block 1 goes to block 3 directly (an extra edge) and no longer
    // to block 4 (a dropped one).
    let or = Merged {
        op: Logical::Or,
        ..AND
    };
    let mismatch = structure(&l1, &chain_l2(or)).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
    assert!(
        mismatch.message.contains("L2 goes to block 3"),
        "{mismatch}"
    );
    // The arms swapped inside the merge: where `a` fails goes to block 3.
    let swapped = Merged {
        swapped: true,
        ..AND
    };
    let mismatch = structure(&l1, &chain_l2(swapped)).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
    assert!(
        mismatch.message.contains("L2 goes to block 3"),
        "{mismatch}"
    );
    // The operands' blocks swapped: block 2 decides first.
    let reversed = Merged {
        blocks: [2, 1],
        ..AND
    };
    let mismatch = structure(&l1, &chain_l2(reversed)).unwrap_err();
    assert!(
        mismatch
            .message
            .contains("starts at block 2 where L1 starts at block 1"),
        "{mismatch}"
    );
    // Both operands block 1's (one decision): block 2's is dropped.
    let one = Merged {
        blocks: [1, 1],
        ..AND
    };
    let mismatch = structure(&l1, &chain_l2(one)).unwrap_err();
    assert_eq!(mismatch.block, Some(BlockId(1)), "{mismatch}");
}

/// A pointer register `p` and the stack pointer, 64 bits each.
const POINTERS: Declarations = Declarations {
    registers: &[
        RegisterInfo {
            name: "p",
            width: 64,
        },
        RegisterInfo {
            name: "sp",
            width: 64,
        },
    ],
    intrinsics: &[],
    sites: &[],
};

/// A `char **` parameter (C's `argv`, bash's `strvec_len`) points, in
/// every shaped state, to a vector of pointers ended by a null one, each
/// to a string ended by a zero byte, all within the memory the state
/// sets: a loop scanning it ends, where random memory rarely holds
/// either terminator. The contents stay random: the states differ.
#[test]
fn shaped_states_give_a_vector_of_strings_its_terminators() {
    const P: RegisterId = RegisterId(0);
    let setup = Setup {
        declarations: &POINTERS,
        stack_pointer: RegisterId(1),
        ..setup()
    };
    let mut types = Types::new(64);
    let char = types.intern(AstType::Char { signed: true });
    let string = types.intern(AstType::Pointer(Some(char)));
    let vector = types.intern(AstType::Pointer(Some(string)));
    let mut l2 = Ast::new(0x1000, types);
    let p = l2.add_var(Variable {
        kind: VarKind::Parameter,
        name: None,
        ty: vector,
        evidence: Evidence::Declared,
        origins: Vec::new(),
    });
    l2.parameters.push(p);
    let mapping = Mapping {
        parameters: vec![Source::Register(Piece {
            register: P,
            offset: 0,
            width: 64,
        })],
        ..Mapping::default()
    };
    let states = shaped_states(&setup, &l2, &mapping, 8, 1);
    assert_eq!(states.len(), 8);
    let mut shapes = Vec::new();
    for state in &states {
        let memory: BTreeMap<u64, u8> = state
            .memory
            .iter()
            .flat_map(|(start, bytes)| (*start..).zip(bytes.iter().copied()))
            .collect();
        let word = |at: u64| -> u64 {
            let bytes: Vec<u8> = (at..at + 8).map(|a| memory[&a]).collect();
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let mut at = state.registers[0].bits.low_u64();
        let mut lengths = Vec::new();
        loop {
            let string = word(at);
            if string == 0 {
                break;
            }
            let length = (string..=string + 16)
                .position(|a| memory[&a] == 0)
                .expect("a string of more than 16 bytes");
            lengths.push(length);
            at += 8;
        }
        assert!(lengths.len() <= 16, "a vector of {} strings", lengths.len());
        shapes.push(lengths);
    }
    shapes.dedup();
    assert!(
        shapes.len() > 1,
        "every state has the same shape: {shapes:?}"
    );
}

/// Parameters with no shape (bits only, a pointer to nothing known) get
/// no shaped states: they stay the random states' alone.
#[test]
fn shaped_states_leave_untyped_parameters_random() {
    let mut types = Types::new(64);
    let bits = types.intern(AstType::Bits(32));
    let void = types.intern(AstType::Pointer(None));
    let mut l2 = Ast::new(0x1000, types);
    for ty in [bits, void] {
        let var = l2.add_var(Variable {
            kind: VarKind::Parameter,
            name: None,
            ty,
            evidence: Evidence::Default,
            origins: Vec::new(),
        });
        l2.parameters.push(var);
    }
    let mapping = Mapping {
        parameters: vec![
            Source::Register(Piece {
                register: A,
                offset: 0,
                width: 32,
            }),
            Source::Register(Piece {
                register: B,
                offset: 0,
                width: 32,
            }),
        ],
        ..Mapping::default()
    };
    assert_eq!(shaped_states(&setup(), &l2, &mapping, 8, 1), Vec::new());
}

/// A parameter `x`, the stack pointer and the link register `lr`, 64 bits
/// each.
const LINKED: Declarations = Declarations {
    registers: &[
        RegisterInfo {
            name: "x",
            width: 64,
        },
        RegisterInfo {
            name: "sp",
            width: 64,
        },
        RegisterInfo {
            name: "lr",
            width: 64,
        },
    ],
    intrinsics: &[],
    sites: &[],
};

/// The link register stays the return address in shaped states even
/// where L2 takes it as an integer parameter (AArch64's exact view keeps
/// x30 for the checks of a signed return address): the state is a call
/// that returns where L2's `return` goes, not one returning to a small
/// count. The other integer parameter is shaped.
#[test]
fn shaped_states_keep_the_link_register_the_return_address() {
    const X: RegisterId = RegisterId(0);
    const LR: RegisterId = RegisterId(2);
    let setup = Setup {
        declarations: &LINKED,
        stack_pointer: RegisterId(1),
        link: Link::Register(LR),
        ..setup()
    };
    let mut types = Types::new(64);
    let int = types.intern(AstType::UInt(64));
    let mut l2 = Ast::new(0x1000, types);
    let mut mapping = Mapping::default();
    for register in [X, LR] {
        let var = l2.add_var(Variable {
            kind: VarKind::Parameter,
            name: None,
            ty: int,
            evidence: Evidence::Default,
            origins: Vec::new(),
        });
        l2.parameters.push(var);
        mapping
            .parameters
            .push(Source::Register(whole(register, 64)));
    }
    let states = shaped_states(&setup, &l2, &mapping, 8, 1);
    assert_eq!(states.len(), 8);
    for state in &states {
        assert!(state.registers[0].bits.low_u64() <= 16, "{state:?}");
        assert_eq!(state.registers[2].bits.low_u64(), RETURN_ADDRESS);
        assert_eq!(state.return_address, RETURN_ADDRESS);
    }
}
