#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The frame in memory (`lower::frame`), on hand-built L1: the bytes
//! below the entry stack pointer are a frame struct of a field per slot
//! (named by its offset from the entry stack pointer, the bytes no slot
//! holds `unknown_…`, starting on the ABI's 16-byte grid); the bytes whose
//! address a call is passed at a declared parameter that states their
//! extent are a variable of that type of their own, but not for a callee
//! that declares nothing, nor where an address below them may reach them
//! by arithmetic. Every result is checked against its L1 by structure and
//! from random states.

use std::collections::BTreeSet;

use binbun_ast::ir::{Function as Ast, Origin, VarKind};
use binbun_ast::types::{Aggregate, Field, Signature, Type, Types};
use binbun_decompile::itanium::NONE;
use binbun_decompile::lower::{Context, Convention, Facts, lower};
use binbun_decompile::prototype::{Open, Prototype, Prototypes};
use binbun_decompile::validate::{Hashed, Link, Setup, differential, random_states, structure};
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Fuel, Manager};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_semantics::{Declarations, RegisterInfo};
use binbun_ssa::constant::NoMemory;
use binbun_ssa::ir::{
    self, Block, BlockId, Definition, Function, Inst, InstId, Op, State, Target, Terminator,
    Type as L1Type, ValueInfo,
};
use binbun_ssa::pass::L1Env;

/// Three 64-bit argument registers `a`, `b`, `c` (`a` the result) and the
/// stack pointer.
const DECLARATIONS: Declarations = Declarations {
    registers: &[
        RegisterInfo {
            name: "a",
            width: 64,
        },
        RegisterInfo {
            name: "b",
            width: 64,
        },
        RegisterInfo {
            name: "c",
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

const A: RegisterId = RegisterId(0);
const B: RegisterId = RegisterId(1);
const C: RegisterId = RegisterId(2);
const SP: RegisterId = RegisterId(3);
const LINK: Link = Link::Stack { bytes: 8 };

/// The state's types: the registers, then the memory.
const STATE: [L1Type; 5] = [
    L1Type::Bits(64),
    L1Type::Bits(64),
    L1Type::Bits(64),
    L1Type::Bits(64),
    L1Type::Memory,
];

/// `int fill(struct pair *)`, `struct pair { int64_t a, b; }`.
const FILL: u64 = 0x6000;
/// `int four(int64_t, int64_t, int64_t, int32_t)`: its last argument on
/// the stack.
const FOUR: u64 = 0x6100;
/// A function nothing is known about.
const UNKNOWN: u64 = 0x7000;

/// `struct pair`.
fn pair(types: &mut Types) -> binbun_ast::types::TypeId {
    let long = types.intern(Type::Int(64));
    types.intern(Type::Struct(Aggregate {
        name: Some("pair".to_owned()),
        size: 16,
        fields: vec![
            Field {
                offset: 0,
                ty: long,
                name: Some("a".to_owned()),
            },
            Field {
                offset: 8,
                ty: long,
                name: Some("b".to_owned()),
            },
        ],
    }))
}

/// [`FILL`]'s prototype.
struct Fill;

impl Prototypes for Fill {
    fn of(&self, address: u64, types: &mut Types) -> Option<Prototype> {
        let int = types.intern(Type::Int(32));
        let parameters = match address {
            FILL => {
                let pair = pair(types);
                vec![types.intern(Type::Pointer(Some(pair)))]
            }
            FOUR => {
                let long = types.intern(Type::Int(64));
                vec![long, long, long, int]
            }
            _ => return None,
        };
        Some(Prototype {
            name: Some(if address == FILL { "fill" } else { "four" }.to_owned()),
            signature: types.intern(Type::Code(Signature {
                parameters,
                returns: Some(int),
                variadic: false,
            })),
            returns_stated: true,
            own: false,
            open: Open::default(),
            noreturn: false,
            format: None,
            format_arg: Vec::new(),
            alloc_size: None,
            wide_result: None,
        })
    }
}

/// `l1` lowered, checked against it by structure and from 64 random
/// states.
fn lowered(l1: &Function) -> Ast {
    lowered_assuming(l1, false)
}

/// [`lowered`], under the reading view's assumption that no code steps
/// back from a stack address if `forward`.
fn lowered_assuming(l1: &Function, forward: bool) -> Ast {
    let convention = Convention {
        arguments: vec![A, B, C],
        results: vec![A],
        long: 64,
        ..Convention::default()
    };
    let functions = BTreeSet::from([0x1000]);
    let context = Context {
        prototypes: &Fill,
        functions: &functions,
        assume_forward_reach: forward,
        ..Context::new(&DECLARATIONS, SP, LINK, &convention)
    };
    let env = L1Env {
        declarations: &DECLARATIONS,
        memory: &NoMemory,
        stack_pointer: SP,
        arguments: &convention.arguments,
        return_slot: Some(0),
        thread_pointer: convention.thread_pointer,
    };
    let facts = Facts::of(&mut Manager::new(Fuel::new(0)), l1, &env);
    let (l2, mapping) = lower(l1, &facts, &context).unwrap();
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
    assert!(report.agreed > 0, "{report:?}");
    l2
}

/// L1 by hand: one block after the entry's.
struct L1 {
    f: Function,
    /// The entry values: `a`, `b`, `c`, `sp`, memory.
    entry: [ir::Value; 5],
}

impl L1 {
    /// A function whose entry block jumps to block 1 (the registers and
    /// memory as its parameters).
    fn new() -> Self {
        let mut l1 = Self {
            f: Function {
                entry: 0x1000,
                ..Function::default()
            },
            entry: [ir::Value(0); 5],
        };
        let entry = l1.block();
        l1.entry = l1.block();
        l1.f.blocks[0].terminator = Terminator::Jump(Target {
            block: BlockId(1),
            arguments: entry.to_vec(),
        });
        l1
    }

    fn block(&mut self) -> [ir::Value; 5] {
        let block = BlockId(u32::try_from(self.f.blocks.len()).unwrap());
        let parameters: Vec<ir::Value> = (0..)
            .zip(STATE)
            .map(|(index, ty)| self.value(ty, Definition::Parameter { block, index }))
            .collect();
        self.f.blocks.push(Block {
            address: 0x1000,
            end: 0x1000,
            parameters: parameters.clone(),
            insts: Vec::new(),
            terminator: Terminator::Open,
        });
        parameters.try_into().unwrap()
    }

    fn value(&mut self, ty: L1Type, definition: Definition) -> ir::Value {
        let id = ir::Value(u32::try_from(self.f.values.len()).unwrap());
        self.f.values.push(ValueInfo { ty, definition });
        id
    }

    fn inst(&mut self, op: Op, types: &[L1Type]) -> Vec<ir::Value> {
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
        self.f.blocks[1].insts.push(inst);
        results
    }

    fn pure(&mut self, op: Op) -> ir::Value {
        self.inst(op, &[L1Type::Bits(64)])[0]
    }

    fn constant(&mut self, value: u64) -> ir::Value {
        self.pure(Op::Const(Bits::from_u64(64, value)))
    }

    /// The entry stack pointer minus `offset`.
    fn below(&mut self, offset: u64) -> ir::Value {
        let sp = self.entry[3];
        let amount = self.constant(offset);
        self.pure(Op::Binary(Binary::Sub, sp, amount))
    }

    fn store(&mut self, memory: ir::Value, address: ir::Value, value: ir::Value) -> ir::Value {
        self.inst(
            Op::Store {
                memory,
                address,
                value,
                atomic: None,
            },
            &[L1Type::Memory],
        )[0]
    }

    fn load(&mut self, memory: ir::Value, address: ir::Value) -> ir::Value {
        self.pure(Op::Load {
            memory,
            address,
            bytes: 8,
            atomic: None,
        })
    }

    /// `target(argument)` on a frame of 0x30 bytes (the call's push at
    /// entry−0x38), after `memory`: the memory after it.
    fn call(&mut self, memory: ir::Value, target: u64, argument: ir::Value) -> ir::Value {
        let [_, b, c, _, _] = self.entry;
        let pushed = self.below(0x38);
        let back = self.constant(0x1100);
        let memory = self.store(memory, pushed, back);
        let target = self.constant(target);
        self.inst(
            Op::Call {
                target,
                return_address: back,
                memory,
                registers: vec![argument, b, c, pushed],
                changes: vec![A],
            },
            &[L1Type::Memory, L1Type::Bits(64)],
        )[0]
    }

    /// Returns `value` in `a`, the memory `memory`.
    fn finish(mut self, memory: ir::Value, value: ir::Value) -> Function {
        let [_, b, c, sp, _] = self.entry;
        let address = self.load(memory, sp);
        self.f.blocks[1].terminator = Terminator::Return {
            address,
            state: State {
                registers: vec![value, b, c, sp],
                memory,
            },
        };
        self.f
    }
}

/// `target(sp − 0x20)` with the 8 bytes at entry−0x20 written before and
/// read after (and, where `indexed`, the 8 bytes at entry−0x30 plus `8·c`
/// added in: an address below reaching the bytes by arithmetic).
fn passing(target: u64, indexed: bool) -> Function {
    let mut l1 = L1::new();
    let [_, b, c, _, memory] = l1.entry;
    let buffer = l1.below(0x20);
    let memory = l1.store(memory, buffer, b);
    let memory = l1.call(memory, target, buffer);
    let second = l1.below(0x18);
    let mut value = l1.load(memory, second);
    if indexed {
        let base = l1.below(0x30);
        let eight = l1.constant(8);
        let scaled = l1.pure(Op::Binary(Binary::Mul, c, eight));
        let element = l1.pure(Op::Binary(Binary::Add, base, scaled));
        let loaded = l1.load(memory, element);
        value = l1.pure(Op::Binary(Binary::Add, value, loaded));
    }
    l1.finish(memory, value)
}

#[test]
fn the_frame_is_a_struct_of_its_slots_named_by_offset() {
    // *(sp − 0x20) = b; *(int32_t *)(sp − 0x14) = c; unknown(sp − 0x20);
    // return *(sp − 0x20).
    let mut l1 = L1::new();
    let [_, b, c, _, memory] = l1.entry;
    let buffer = l1.below(0x20);
    let memory = l1.store(memory, buffer, b);
    let low = l1.inst(
        Op::Extract {
            value: c,
            offset: 0,
            width: 32,
        },
        &[L1Type::Bits(32)],
    )[0];
    let int = l1.below(0x14);
    let memory = l1.store(memory, int, low);
    let memory = l1.call(memory, UNKNOWN, buffer);
    let value = l1.load(memory, buffer);
    let l2 = lowered(&l1.finish(memory, value));
    assert_eq!(l2.promoted, []);
    let [frame] = l2.frames.as_slice() else {
        panic!("one frame struct: {:?}", l2.frames);
    };
    let variable = l2.var(*frame).unwrap();
    // Its slots span entry−0x20..−0x10, and the callee given its address
    // may write on from there, up to the entry stack pointer; it starts
    // on the 16-byte grid of the canonical frame address (entry + 8),
    // taking the 8 bytes below.
    assert_eq!(variable.kind, VarKind::Frame(-0x28));
    let Some(Type::Struct(aggregate)) = l2.types.get(variable.ty) else {
        panic!("not a struct");
    };
    assert_eq!(aggregate.name, None);
    assert_eq!(aggregate.size, 40);
    let fields: Vec<(u64, Option<u64>, &str)> = aggregate
        .fields
        .iter()
        .map(|field| {
            (
                field.offset,
                l2.types.width(field.ty),
                field.name.as_deref().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        fields,
        [
            (0, Some(64), "unknown_m28"),
            (8, Some(64), "at_m20"),
            (16, Some(32), "unknown_m18"),
            (20, Some(32), "at_m14"),
            (24, Some(128), "unknown_m10"),
        ]
    );
}

#[test]
fn a_declared_extent_promotes_the_bytes_an_undeclared_callee_does_not() {
    // fill(&pair); return pair.b: a `struct pair` of its own.
    let l2 = lowered(&passing(FILL, false));
    let [promoted] = l2.promoted.as_slice() else {
        panic!("one promoted object: {:?}", l2.promoted);
    };
    let variable = l2.var(*promoted).unwrap();
    assert_eq!(variable.kind, VarKind::Frame(-0x20));
    assert!(matches!(
        l2.types.get(variable.ty),
        Some(Type::Struct(aggregate)) if aggregate.name.as_deref() == Some("pair")
    ));
    assert_eq!(l2.frames, []);
    // unknown(&bytes): nothing says how far the callee reaches, so the
    // bytes stay the frame struct's.
    let l2 = lowered(&passing(UNKNOWN, false));
    assert_eq!(l2.promoted, []);
    assert_eq!(l2.frames.len(), 1);
}

#[test]
fn arithmetic_from_an_address_below_keeps_the_bytes_in_the_frame() {
    // fill(&pair) as above, but `*(sp − 0x30 + 8·c)` is read too: that
    // address may reach the pair, so it is no object of its own; the
    // frame struct holds the slots and the arithmetic stays on its bytes.
    let l2 = lowered(&passing(FILL, true));
    assert_eq!(l2.promoted, []);
    let [frame] = l2.frames.as_slice() else {
        panic!("one frame struct: {:?}", l2.frames);
    };
    let variable = l2.var(*frame).unwrap();
    let Some(Type::Struct(aggregate)) = l2.types.get(variable.ty) else {
        panic!("not a struct");
    };
    let names: Vec<&str> = aggregate
        .fields
        .iter()
        .filter_map(|field| field.name.as_deref())
        .filter(|name| name.starts_with("at_"))
        .collect();
    assert_eq!(names, ["at_m20", "at_m18"]);
}

/// The type of field `name` of the one frame struct of `l2`.
fn frame_field(l2: &Ast, name: &str) -> Type {
    let [frame] = l2.frames.as_slice() else {
        panic!("one frame struct: {:?}", l2.frames);
    };
    let variable = l2.var(*frame).unwrap();
    let Some(Type::Struct(aggregate)) = l2.types.get(variable.ty) else {
        panic!("not a struct");
    };
    let field = aggregate
        .fields
        .iter()
        .find(|field| field.name.as_deref() == Some(name))
        .unwrap();
    l2.types.get(field.ty).unwrap().clone()
}

#[test]
fn a_slot_also_accessed_in_parts_is_a_field_of_its_whole_accesses() {
    // *(sp − 0x20) = b; *(uint8_t *)(sp − 0x20) = c;
    // *(int32_t *)(sp − 0x14) = c; unknown(sp − 0x20);
    // return *(sp − 0x20): the 8-byte slot is a 64-bit field the byte
    // store writes a part of, not 8 bytes.
    let build = |whole: bool| {
        let mut l1 = L1::new();
        let [_, b, c, _, memory] = l1.entry;
        let buffer = l1.below(0x20);
        let memory = if whole {
            l1.store(memory, buffer, b)
        } else {
            memory
        };
        let byte = l1.inst(
            Op::Extract {
                value: c,
                offset: 0,
                width: 8,
            },
            &[L1Type::Bits(8)],
        )[0];
        let memory = l1.store(memory, buffer, byte);
        let low = l1.inst(
            Op::Extract {
                value: c,
                offset: 0,
                width: 32,
            },
            &[L1Type::Bits(32)],
        )[0];
        let int = l1.below(0x14);
        let memory = l1.store(memory, int, low);
        let memory = l1.call(memory, UNKNOWN, buffer);
        let value = if whole { l1.load(memory, buffer) } else { b };
        lowered(&l1.finish(memory, value))
    };
    let field = frame_field(&build(true), "at_m20");
    assert!(
        matches!(field, Type::Bits(64) | Type::Int(64) | Type::UInt(64)),
        "{field:?}"
    );
    // Only the byte: a field of its width.
    let field = frame_field(&build(false), "at_m20");
    assert!(
        matches!(
            field,
            Type::Bits(8) | Type::Int(8) | Type::UInt(8) | Type::Char { .. }
        ),
        "{field:?}"
    );
}

/// The names of the slots' fields (`at_…`) of the one frame struct of
/// `l2`.
fn frame_slots(l2: &Ast) -> Vec<String> {
    let [frame] = l2.frames.as_slice() else {
        panic!("one frame struct: {:?}", l2.frames);
    };
    let variable = l2.var(*frame).unwrap();
    let Some(Type::Struct(aggregate)) = l2.types.get(variable.ty) else {
        panic!("not a struct");
    };
    aggregate
        .fields
        .iter()
        .filter_map(|field| field.name.clone())
        .filter(|name| name.starts_with("at_"))
        .collect()
}

#[test]
fn assuming_no_step_back_keeps_the_slots_below_an_address_passed_out_of_memory() {
    // *(sp − 0x30) = b; *(sp − 0x20) = c; unknown(sp − 0x20);
    // return *(sp − 0x30) + *(sp − 0x20).
    let mut l1 = L1::new();
    let [_, b, c, _, memory] = l1.entry;
    let below = l1.below(0x30);
    let memory = l1.store(memory, below, b);
    let buffer = l1.below(0x20);
    let memory = l1.store(memory, buffer, c);
    let memory = l1.call(memory, UNKNOWN, buffer);
    let kept = l1.load(memory, below);
    let passed = l1.load(memory, buffer);
    let value = l1.pure(Op::Binary(Binary::Add, kept, passed));
    let l1 = l1.finish(memory, value);
    // The callee may step back from its address (`container_of`) to the
    // slot below: both are the frame struct's.
    assert_eq!(frame_slots(&lowered(&l1)), ["at_m30", "at_m20"]);
    // Assumed not to: the slot below is a local, the frame struct holds
    // only the bytes from the address passed up.
    let l2 = lowered_assuming(&l1, true);
    assert_eq!(frame_slots(&l2), ["at_m20"]);
    assert!(
        l2.variables
            .iter()
            .any(|variable| variable.kind == VarKind::Local
                && variable.origins.contains(&Origin::Slot(-0x30))),
        "no local of the slot below"
    );
}

#[test]
fn the_functions_own_step_back_keeps_the_slots_below_in_memory() {
    // *(sp − 0x30) = b; *(sp − 0x20) = c; unknown(sp − 0x20);
    // return *(sp − 0x20 − c): the function's own code may read below
    // the address it passed, which no assumption about the callee rules
    // out: the slot below stays the frame struct's.
    let mut l1 = L1::new();
    let [_, b, c, _, memory] = l1.entry;
    let below = l1.below(0x30);
    let memory = l1.store(memory, below, b);
    let buffer = l1.below(0x20);
    let memory = l1.store(memory, buffer, c);
    let memory = l1.call(memory, UNKNOWN, buffer);
    let back = l1.pure(Op::Binary(Binary::Sub, buffer, c));
    let value = l1.load(memory, back);
    let l2 = lowered_assuming(&l1.finish(memory, value), true);
    assert_eq!(frame_slots(&l2), ["at_m30", "at_m20"]);
}

#[test]
fn a_slot_written_whole_and_read_in_part_is_a_local() {
    // *(sp − 0x30) = b; four(a, b, c, (int32_t)*(sp − 0x30)): a slot
    // written whole and read in part as a call's stack argument (pushed
    // as 8 bytes, passed as 4) is a variable, the argument its bits, in no
    // memory.
    let mut l1 = L1::new();
    let [a, b, _, _, memory] = l1.entry;
    let slot = l1.below(0x30);
    let memory = l1.store(memory, slot, b);
    let memory = l1.call(memory, FOUR, a);
    let l2 = lowered(&l1.finish(memory, b));
    assert!(
        !l2.variables
            .iter()
            .any(|variable| matches!(variable.kind, VarKind::Frame(offset) if offset < 0)),
        "a frame variable below the entry"
    );
}

#[test]
fn a_slot_of_its_own_written_in_parts_has_the_type_of_its_whole_accesses() {
    // *(sp − 0x20) = b; *(uint8_t *)(sp − 0x20) = c; return *(sp − 0x20):
    // no address is taken, so the slot is a variable of its own; of two
    // shapes, it lives in memory, as wide as its whole accesses, not 8
    // bytes.
    let mut l1 = L1::new();
    let [_, b, c, _, memory] = l1.entry;
    let slot = l1.below(0x20);
    let memory = l1.store(memory, slot, b);
    let byte = l1.inst(
        Op::Extract {
            value: c,
            offset: 0,
            width: 8,
        },
        &[L1Type::Bits(8)],
    )[0];
    let memory = l1.store(memory, slot, byte);
    let value = l1.load(memory, slot);
    let l2 = lowered(&l1.finish(memory, value));
    assert_eq!(l2.frames, []);
    let variable = l2
        .variables
        .iter()
        .find(|variable| variable.kind == VarKind::Frame(-0x20))
        .expect("the slot's variable");
    let ty = l2.types.get(variable.ty).unwrap();
    assert!(
        matches!(ty, Type::Bits(64) | Type::Int(64) | Type::UInt(64)),
        "{ty:?}"
    );
}
