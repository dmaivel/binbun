#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The type solver's types ([`binbun_decompile::typing`]) on hand-built
//! L1, as lowering gives them to L2: accesses make pointers to what they
//! read, a value loaded through a loaded pointer makes a pointer to a
//! pointer, a signed compare of what is loaded types the target, an
//! access outranks a signed compare of the pointer, a compare types a
//! loop's counter and bound, and code with no evidence keeps `bits`.
//! Every result is checked against its L1 by structure and from random
//! states.

use binbun_ast::ir::{Function as Ast, VarId};
use binbun_ast::types::{Evidence, Type as L2Type};
use binbun_decompile::itanium::NONE;
use binbun_decompile::lower::{Context, Convention, Facts, lower_counted};
use binbun_decompile::validate::{Hashed, Link, Setup, differential, random_states, structure};
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Fuel, Manager};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_semantics::{Declarations, RegisterInfo};
use binbun_ssa::constant::NoMemory;
use binbun_ssa::ir::{
    self, Block, BlockId, Definition, Function, Inst, InstId, Op, State, Target, Terminator, Type,
    ValueInfo,
};
use binbun_ssa::pass::L1Env;

/// `x`, `y` (64 bits), the stack pointer `sp`, and a flag `c`.
const DECLARATIONS: Declarations = Declarations {
    registers: &[
        RegisterInfo {
            name: "x",
            width: 64,
        },
        RegisterInfo {
            name: "y",
            width: 64,
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

const X: RegisterId = RegisterId(0);
const Y: RegisterId = RegisterId(1);
const SP: RegisterId = RegisterId(2);
const LINK: Link = Link::Stack { bytes: 8 };

/// Arguments in `x` and `y`, the result in `x`.
fn convention() -> Convention {
    Convention {
        arguments: vec![X, Y],
        results: vec![X],
        ..Convention::default()
    }
}

/// `l1` lowered with the default context, typed by the solver, checked by
/// structure and from 64 random states.
fn lowered(l1: &Function) -> Ast {
    let convention = convention();
    let env = L1Env {
        declarations: &DECLARATIONS,
        memory: &NoMemory,
        stack_pointer: SP,
        arguments: &convention.arguments,
        return_slot: Some(0),
        thread_pointer: convention.thread_pointer,
    };
    let facts = Facts::of(&mut Manager::new(Fuel::new(0)), l1, &env);
    let context = Context::new(&DECLARATIONS, SP, LINK, &convention);
    let (l2, mapping, counts) = lower_counted(l1, &facts, &context).unwrap();
    structure(l1, &l2, &NONE).unwrap();
    let setup = Setup {
        declarations: &DECLARATIONS,
        stack_pointer: SP,
        link: LINK,
        fixed: Vec::new(),
        fuel: 1000,
        frame: 0x1000,
        shadow: 0,
    };
    let states = random_states(&setup, 64, 7);
    let report = differential(l1, &l2, &mapping, &setup, &Hashed, &states);
    assert!(report.passed(), "{report:?}");
    assert!(counts.typing.typed && !counts.typing.refused);
    l2
}

/// The type of `var`.
fn type_of(l2: &Ast, var: VarId) -> &L2Type {
    l2.types.get(l2.var(var).unwrap().ty).unwrap()
}

/// The type of the `index`th parameter.
fn parameter(l2: &Ast, index: usize) -> &L2Type {
    type_of(l2, l2.parameters[index])
}

/// What pointer type `ty` points to (`None`: `void *`).
fn target<'a>(l2: &'a Ast, ty: &L2Type) -> Option<&'a L2Type> {
    let &L2Type::Pointer(target) = ty else {
        panic!("{ty:?} is not a pointer");
    };
    target.map(|target| l2.types.get(target).unwrap())
}

// L1 by hand.

/// The state's types: the registers, then the memory.
const STATE: [Type; 5] = [
    Type::Bits(64),
    Type::Bits(64),
    Type::Bits(64),
    Type::Bits(1),
    Type::Memory,
];

struct L1 {
    f: Function,
    current: BlockId,
}

impl L1 {
    /// A function whose entry block (block 0) jumps to block 1.
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
        l1.terminate_in(BlockId(0), Terminator::Jump(target_of(first, &entry)));
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

    fn binary(&mut self, op: Binary, a: ir::Value, b: ir::Value, width: u16) -> ir::Value {
        self.pure(Op::Binary(op, a, b), width)
    }

    /// Truth value `value` zero-extended to 64 bits.
    fn widened(&mut self, value: ir::Value) -> ir::Value {
        self.pure(
            Op::Extend {
                signed: false,
                value,
                width: 64,
            },
            64,
        )
    }

    /// `bytes` loaded from `address`.
    fn load(&mut self, memory: ir::Value, address: ir::Value, bytes: u16) -> ir::Value {
        self.pure(
            Op::Load {
                memory,
                address,
                bytes,
                atomic: None,
            },
            bytes * 8,
        )
    }

    /// `value` stored at `address`: the memory after.
    fn store(&mut self, memory: ir::Value, address: ir::Value, value: ir::Value) -> ir::Value {
        self.inst(
            Op::Store {
                memory,
                address,
                value,
                atomic: None,
            },
            &[Type::Memory],
        )[0]
    }

    fn terminate_in(&mut self, block: BlockId, terminator: Terminator) {
        self.f.blocks[block.0 as usize].terminator = terminator;
    }

    fn terminate(&mut self, terminator: Terminator) {
        self.terminate_in(self.current, terminator);
    }

    /// Returns with `registers` (x, y, c; the stack pointer popped) and
    /// `memory`: the return address loaded from `sp`.
    fn ret(&mut self, sp: ir::Value, registers: [ir::Value; 3], memory: ir::Value) {
        let address = self.load(memory, sp, 8);
        let eight = self.constant(64, 8);
        let popped = self.binary(Binary::Add, sp, eight, 64);
        let [x, y, c] = registers;
        self.terminate(Terminator::Return {
            address,
            state: State {
                registers: vec![x, y, popped, c],
                memory,
            },
        });
    }
}

fn target_of(block: BlockId, arguments: &[ir::Value]) -> Target {
    Target {
        block,
        arguments: arguments.to_vec(),
    }
}

#[test]
fn an_access_makes_a_pointer_to_what_it_reads() {
    // *(y + 4) = *x (4 bytes): both point to 4 bytes nothing else types.
    let (mut l1, [x, y, sp, c, memory]) = L1::new();
    let value = l1.load(memory, x, 4);
    let four = l1.constant(64, 4);
    let address = l1.binary(Binary::Add, y, four, 64);
    let memory = l1.store(memory, address, value);
    l1.ret(sp, [x, y, c], memory);
    let l2 = lowered(&l1.f);
    assert_eq!(target(&l2, parameter(&l2, 0)), Some(&L2Type::Bits(32)));
    assert_eq!(target(&l2, parameter(&l2, 1)), Some(&L2Type::Bits(32)));
    let p = l2.var(l2.parameters[0]).unwrap();
    assert_eq!(p.evidence, Evidence::Deduced);
}

#[test]
fn a_signed_compare_of_what_is_loaded_types_the_target() {
    // return *x (4 bytes) < 0 (signed).
    let (mut l1, [x, y, sp, c, memory]) = L1::new();
    let value = l1.load(memory, x, 4);
    let zero = l1.constant(32, 0);
    let negative = l1.binary(Binary::SLt, value, zero, 1);
    let result = l1.widened(negative);
    l1.ret(sp, [result, y, c], memory);
    let l2 = lowered(&l1.f);
    assert_eq!(target(&l2, parameter(&l2, 0)), Some(&L2Type::Int(32)));
}

#[test]
fn a_loaded_pointer_is_a_pointer_to_a_pointer() {
    // *y = **x (8, then 4 bytes).
    let (mut l1, [x, y, sp, c, memory]) = L1::new();
    let inner = l1.load(memory, x, 8);
    let value = l1.load(memory, inner, 4);
    let memory = l1.store(memory, y, value);
    l1.ret(sp, [x, y, c], memory);
    let l2 = lowered(&l1.f);
    let pointer = target(&l2, parameter(&l2, 0)).unwrap();
    assert_eq!(target(&l2, pointer), Some(&L2Type::Bits(32)));
}

#[test]
fn an_access_outranks_a_signed_compare_of_the_pointer() {
    // *y = *x (4 bytes); return x < 0 (signed): the pointer kept.
    let (mut l1, [x, y, sp, c, memory]) = L1::new();
    let value = l1.load(memory, x, 4);
    let memory = l1.store(memory, y, value);
    let zero = l1.constant(64, 0);
    let negative = l1.binary(Binary::SLt, x, zero, 1);
    let result = l1.widened(negative);
    l1.ret(sp, [result, y, c], memory);
    let l2 = lowered(&l1.f);
    assert_eq!(target(&l2, parameter(&l2, 0)), Some(&L2Type::Bits(32)));
}

#[test]
fn a_compare_types_a_loops_counter_and_bound() {
    // i = 0; H(i): i = i + 1; i <u y ? H(i); return i (`x` an unused
    // parameter).
    let (mut l1, [_, y, sp, c, memory]) = L1::new();
    let zero = l1.constant(64, 0);
    let (header, [counter, hy, hsp, hc, hmemory]) = l1.block(0x1010);
    l1.terminate(Terminator::Jump(target_of(
        header,
        &[zero, y, sp, c, memory],
    )));
    l1.current = header;
    let one = l1.constant(64, 1);
    let next = l1.binary(Binary::Add, counter, one, 64);
    let below = l1.binary(Binary::ULt, next, hy, 1);
    let (exit, [result, xy, xsp, xc, xmemory]) = l1.block(0x1020);
    l1.terminate(Terminator::Branch {
        condition: below,
        then: target_of(header, &[next, hy, hsp, hc, hmemory]),
        otherwise: target_of(exit, &[next, hy, hsp, hc, hmemory]),
    });
    l1.current = exit;
    l1.ret(xsp, [result, xy, xc], xmemory);
    let l2 = lowered(&l1.f);
    assert_eq!(parameter(&l2, 1), &L2Type::UInt(64));
    let returns = l2.returns.and_then(|ty| l2.types.get(ty));
    assert_eq!(returns, Some(&L2Type::UInt(64)));
}

#[test]
fn code_with_no_evidence_keeps_bits() {
    // return x & 0xff: nothing says what `x` is.
    let (mut l1, [x, y, sp, c, memory]) = L1::new();
    let mask = l1.constant(64, 0xff);
    let masked = l1.binary(Binary::And, x, mask, 64);
    l1.ret(sp, [masked, y, c], memory);
    let l2 = lowered(&l1.f);
    let p = l2.var(l2.parameters[0]).unwrap();
    assert_eq!(type_of(&l2, l2.parameters[0]), &L2Type::Bits(64));
    assert_eq!(p.evidence, Evidence::Default);
}
