#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Lowering's constant addresses (`lower::emit::data`) on hand-built L1:
//! an access inside a named object is its variable (whole, or at its
//! address plus an offset in an array of the accessed elements), a
//! computed `char *` argument pointing to a string is that string's
//! variable, a computed function entry passed on is the function; an
//! immediate in a position-independent image, a store into read-only
//! memory, and a pointer passed where no `char *` is declared stay
//! numbers. A constant base plus an index whose values keep the access in
//! data no object names is an element of a table there (as is an access at
//! a constant address inside it); one whose index nothing bounds, or whose
//! bytes reach a named object, stays address arithmetic. Every result is
//! checked against its L1 by structure and from random states.

use binbun_ast::ir::{Callee, Expr, ExprId, Function as Ast, Place, Stmt, VarId, VarKind};
use binbun_ast::types::{Signature, Type, Types};
use binbun_decompile::data::{Data, Object};
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
use std::collections::BTreeSet;

/// `a` and `b` (64 bits, arguments; `a` the result) and the stack
/// pointer.
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
            name: "sp",
            width: 64,
        },
    ],
    intrinsics: &[],
    sites: &[],
};

const A: RegisterId = RegisterId(0);
const B: RegisterId = RegisterId(1);
const SP: RegisterId = RegisterId(2);
const LINK: Link = Link::Stack { bytes: 8 };

/// The state's types: the registers, then the memory.
const STATE: [L1Type; 4] = [
    L1Type::Bits(64),
    L1Type::Bits(64),
    L1Type::Bits(64),
    L1Type::Memory,
];

/// The named objects: 4 writable bytes at 0x3010, 16 at 0x3020, 4
/// read-only at 0x4000.
const OBJECTS: [Object; 3] = [
    Object {
        start: 0x3010,
        size: 4,
        read_only: false,
    },
    Object {
        start: 0x3020,
        size: 16,
        read_only: false,
    },
    Object {
        start: 0x4000,
        size: 4,
        read_only: true,
    },
];

/// The function whose entry is a constant [`calling`] returns (above 32
/// bits: a return of a constant that fits 32 bits is 32 bits wide).
const FUNCTION: u64 = 0x1_0000_7000;

/// A position-independent image: data from 0x3000 to 0x6000 (read-only
/// from 0x4000), the objects, and the string "hi" at 0x5010.
struct Image;

impl Data for Image {
    fn object(&self, address: u64) -> Option<Object> {
        OBJECTS
            .iter()
            .find(|object| object.holds(address, 1))
            .copied()
    }

    fn data(&self, address: u64, bytes: u64) -> Option<bool> {
        (address >= 0x3000 && address + bytes <= 0x6000).then_some(address >= 0x4000)
    }

    fn string(&self, address: u64) -> Option<u64> {
        (address == 0x5010).then_some(2)
    }

    fn constant(&self, address: u64, bytes: u64) -> Option<Vec<u8>> {
        let bytes = usize::try_from(bytes).ok()?;
        (address == 0x5010).then(|| b"hi\0".get(..bytes).map(<[u8]>::to_vec))?
    }

    fn relocatable(&self) -> bool {
        true
    }
}

/// `void put(char *, char *)` at 0x6000.
struct Put;

impl Prototypes for Put {
    fn of(&self, address: u64, types: &mut Types) -> Option<Prototype> {
        if address != 0x6000 {
            return None;
        }
        let character = types.intern(Type::Char { signed: true });
        let string = types.intern(Type::Pointer(Some(character)));
        Some(Prototype {
            name: Some("put".to_owned()),
            signature: types.intern(Type::Code(Signature {
                parameters: vec![string, string],
                returns: None,
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

fn convention() -> Convention {
    Convention {
        arguments: vec![A, B],
        results: vec![A],
        ..Convention::default()
    }
}

/// `l1` lowered with the image's data, checked against it by structure
/// and from 64 random states.
fn lowered(l1: &Function) -> Ast {
    let convention = convention();
    let functions = BTreeSet::from([0x1000, FUNCTION]);
    let context = Context {
        data: &Image,
        prototypes: &Put,
        functions: &functions,
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
}

impl L1 {
    /// A function whose entry block jumps to block 1 (the registers and
    /// memory as its parameters).
    fn new() -> (Self, [ir::Value; 4]) {
        let mut l1 = Self {
            f: Function {
                entry: 0x1000,
                ..Function::default()
            },
        };
        let entry = l1.block();
        let parameters = l1.block();
        l1.f.blocks[0].terminator = Terminator::Jump(Target {
            block: BlockId(1),
            arguments: entry.to_vec(),
        });
        (l1, parameters)
    }

    fn block(&mut self) -> [ir::Value; 4] {
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

    fn pure(&mut self, op: Op, width: u16) -> ir::Value {
        self.inst(op, &[L1Type::Bits(width)])[0]
    }

    /// An immediate.
    fn constant(&mut self, width: u16, value: u64) -> ir::Value {
        self.pure(Op::Const(Bits::from_u64(width, value)), width)
    }

    /// `base + offset`, computed (as a program-counter-relative address
    /// is).
    fn computed(&mut self, base: u64, offset: u64) -> ir::Value {
        let base = self.constant(64, base);
        let offset = self.constant(64, offset);
        self.pure(Op::Binary(Binary::Add, base, offset), 64)
    }

    fn load(&mut self, memory: ir::Value, address: ir::Value, bytes: u16) -> ir::Value {
        let op = Op::Load {
            memory,
            address,
            bytes,
            atomic: None,
        };
        self.pure(op, bytes * 8)
    }

    fn store(&mut self, memory: ir::Value, address: ir::Value, value: ir::Value) -> ir::Value {
        let op = Op::Store {
            memory,
            address,
            value,
            atomic: None,
        };
        self.inst(op, &[L1Type::Memory])[0]
    }

    /// Returns `a` (with `b`; the stack pointer `sp` popped) and `memory`:
    /// the return address loaded from `sp`.
    fn ret(&mut self, a: ir::Value, b: ir::Value, sp: ir::Value, memory: ir::Value) {
        let address = self.load(memory, sp, 8);
        let eight = self.constant(64, 8);
        let popped = self.pure(Op::Binary(Binary::Add, sp, eight), 64);
        self.f.blocks[1].terminator = Terminator::Return {
            address,
            state: State {
                registers: vec![a, b, popped],
                memory,
            },
        };
    }
}

/// `x = A; A = 7; y = B[2]; z = *(0x3010); *(0x4000) = 7; return x + y +
/// z`, the addresses of `A`, `B` and the read-only object computed, the
/// last load's an immediate.
fn accessing() -> Function {
    let (mut l1, [_, b, sp, memory]) = L1::new();
    let first = l1.computed(0x3000, 0x10);
    let x = l1.load(memory, first, 4);
    let seven = l1.constant(32, 7);
    let memory = l1.store(memory, first, seven);
    let element = l1.computed(0x3000, 0x28);
    let y = l1.load(memory, element, 4);
    let immediate = l1.constant(64, 0x3010);
    let z = l1.load(memory, immediate, 4);
    let read_only = l1.computed(0x3000, 0x1000);
    let memory = l1.store(memory, read_only, seven);
    let sum = l1.pure(Op::Binary(Binary::Add, x, y), 32);
    let sum = l1.pure(Op::Binary(Binary::Add, sum, z), 32);
    let wide = l1.pure(
        Op::Extend {
            signed: false,
            value: sum,
            width: 64,
        },
        64,
    );
    l1.ret(wide, b, sp, memory);
    l1.f
}

/// `put(<0x5010 computed>, <0x5010 immediate>); return <FUNCTION
/// computed>` (or `immediate`).
fn calling(immediate: bool) -> Function {
    let (mut l1, [_, _, sp, memory]) = L1::new();
    let computed = l1.computed(0x5000, 0x10);
    let number = l1.constant(64, 0x5010);
    let eight = l1.constant(64, 8);
    let pushed = l1.pure(Op::Binary(Binary::Sub, sp, eight), 64);
    let back = l1.constant(64, 0x1100);
    let memory = l1.store(memory, pushed, back);
    let target = l1.constant(64, 0x6000);
    let results = l1.inst(
        Op::Call {
            target,
            return_address: back,
            memory,
            registers: vec![computed, number, pushed],
            changes: vec![A],
        },
        &[L1Type::Memory, L1Type::Bits(64)],
    );
    let function = if immediate {
        l1.constant(64, FUNCTION)
    } else {
        l1.computed(FUNCTION, 0)
    };
    l1.ret(function, number, sp, results[0]);
    l1.f
}

/// `p = 0x3100 + (b & 7) * 4; *p = *p | 2; x = *(0x3108); y = *(0x3200 +
/// b * 4); z = *(0x3008 + (b & 7) * 8); return x + y + z`, every base
/// computed: the first a table of 8 elements (`x` its element 2), `y`'s
/// index unbounded, `z`'s bytes reaching the named object at 0x3010.
fn indexing() -> Function {
    let (mut l1, [_, b, sp, memory]) = L1::new();
    let seven = l1.constant(64, 7);
    let four = l1.constant(64, 4);
    let masked = l1.pure(Op::Binary(Binary::And, b, seven), 64);
    let scaled = l1.pure(Op::Binary(Binary::Mul, masked, four), 64);
    let table = l1.computed(0x3100, 0);
    let element = l1.pure(Op::Binary(Binary::Add, table, scaled), 64);
    let old = l1.load(memory, element, 4);
    let two = l1.constant(32, 2);
    let new = l1.pure(Op::Binary(Binary::Or, old, two), 32);
    let memory = l1.store(memory, element, new);
    let inside = l1.computed(0x3100, 8);
    let x = l1.load(memory, inside, 4);
    let unbounded = l1.pure(Op::Binary(Binary::Mul, b, four), 64);
    let other = l1.computed(0x3200, 0);
    let far = l1.pure(Op::Binary(Binary::Add, other, unbounded), 64);
    let y = l1.load(memory, far, 4);
    let before = l1.computed(0x3008, 0);
    let eight = l1.constant(64, 8);
    let again = l1.pure(Op::Binary(Binary::Mul, masked, eight), 64);
    let overlapping = l1.pure(Op::Binary(Binary::Add, before, again), 64);
    let z = l1.load(memory, overlapping, 4);
    let sum = l1.pure(Op::Binary(Binary::Add, x, y), 32);
    let sum = l1.pure(Op::Binary(Binary::Add, sum, z), 32);
    let wide = l1.pure(
        Op::Extend {
            signed: false,
            value: sum,
            width: 64,
        },
        64,
    );
    l1.ret(wide, b, sp, memory);
    l1.f
}

/// The variable at `address` of `l2`.
fn global(l2: &Ast, address: u64) -> VarId {
    let index = l2
        .variables
        .iter()
        .position(|variable| variable.kind == VarKind::Global(address))
        .unwrap_or_else(|| panic!("no variable at {address:#x}"));
    VarId(u32::try_from(index).unwrap())
}

/// The expressions of `l2` that are loads at `address`'s expression.
fn loads_at(l2: &Ast, address: impl Fn(&Ast, ExprId) -> bool) -> usize {
    l2.exprs
        .iter()
        .filter(|expr| matches!(expr, Expr::Load { address: at, .. } if address(l2, *at)))
        .count()
}

/// Whether expression `id` is the constant `value`.
fn constant(l2: &Ast, id: ExprId, value: u64) -> bool {
    matches!(l2.expr(id), Some(Expr::Const(bits)) if bits.low_u64() == value)
}

/// The value `l2` returns.
fn returned(l2: &Ast) -> ExprId {
    l2.stmts
        .iter()
        .find_map(|stmt| {
            if let Stmt::Return(value) = stmt {
                *value
            } else {
                None
            }
        })
        .unwrap()
}

#[test]
fn accesses_inside_named_objects_are_their_variables() {
    let l2 = lowered(&accessing());
    // The whole of `A`: its variable, read and written.
    let whole = global(&l2, 0x3010);
    assert!(l2.exprs.contains(&Expr::Var(whole)));
    assert!(l2.stmts.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { place: Place::Var(var), .. } if *var == whole
    )));
    // An element of `B`: its address plus 8, `B` an array of 4 of them.
    let array = global(&l2, 0x3020);
    let ty = l2.var(array).unwrap().ty;
    let &Type::Array { element, length } = l2.types.get(ty).unwrap() else {
        panic!("B is {:?}", l2.types.get(ty));
    };
    assert_eq!((l2.types.width(element), length), (Some(32), Some(4)));
    let into_array = |l2: &Ast, at: ExprId| {
        matches!(l2.expr(at), Some(&Expr::Binary(Binary::Add, base, offset))
            if l2.expr(base) == Some(&Expr::AddressOf(array)) && constant(l2, offset, 8))
    };
    assert_eq!(loads_at(&l2, into_array), 1);
}

#[test]
fn immediates_and_read_only_stores_stay_addresses() {
    let l2 = lowered(&accessing());
    // An immediate in a position-independent image is not its address.
    assert_eq!(loads_at(&l2, |l2, at| constant(l2, at, 0x3010)), 1);
    // A store into read-only memory faults: no variable.
    assert!(
        l2.variables
            .iter()
            .all(|variable| variable.kind != VarKind::Global(0x4000))
    );
    assert!(l2.stmts.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { place: Place::Memory { address, .. }, .. } if constant(&l2, *address, 0x4000)
    )));
}

#[test]
fn computed_strings_and_functions_are_variables_and_functions() {
    let l2 = lowered(&calling(false));
    let call = l2
        .stmts
        .iter()
        .find_map(|stmt| {
            if let Stmt::Call { call, .. } = stmt {
                Some(call)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(call.callee, Callee::Address(0x6000));
    // The computed address: "hi" and its NUL, as `char`s.
    let string = global(&l2, 0x5010);
    assert_eq!(l2.expr(call.arguments[0]), Some(&Expr::AddressOf(string)));
    let ty = l2.var(string).unwrap().ty;
    let &Type::Array { element, length } = l2.types.get(ty).unwrap() else {
        panic!("the string is {:?}", l2.types.get(ty));
    };
    assert_eq!(l2.types.get(element), Some(&Type::Char { signed: true }));
    assert_eq!(length, Some(3));
    // The immediate stays a number.
    assert!(constant(&l2, call.arguments[1], 0x5010));
    // The function's entry, returned: the function, as code.
    let returned = returned(&l2);
    let Some(&Expr::Cast { value, ty }) = l2.expr(returned) else {
        panic!("returns {:?}", l2.expr(returned));
    };
    assert!(constant(&l2, value, FUNCTION));
    assert!(matches!(l2.types.get(ty), Some(Type::Code(_))));
}

#[test]
fn an_immediate_function_entry_stays_a_number() {
    let l2 = lowered(&calling(true));
    assert!(constant(&l2, returned(&l2), FUNCTION));
}

/// Whether `l2` has `a + b` with `a` matching `left` and `b` `right`.
fn sum(l2: &Ast, left: impl Fn(ExprId) -> bool, right: impl Fn(ExprId) -> bool) -> bool {
    l2.exprs
        .iter()
        .any(|expr| matches!(*expr, Expr::Binary(Binary::Add, a, b) if left(a) && right(b)))
}

#[test]
fn a_bounded_index_into_unnamed_data_is_a_tables_element() {
    let l2 = lowered(&indexing());
    // The table: 8 elements of 32 bits, from the base to the last byte the
    // index reaches.
    let table = global(&l2, 0x3100);
    let ty = l2.var(table).unwrap().ty;
    let &Type::Array { element, length } = l2.types.get(ty).unwrap() else {
        panic!("the table is {:?}", l2.types.get(ty));
    };
    assert_eq!((l2.types.width(element), length), (Some(32), Some(8)));
    let at_table = |id: ExprId| l2.expr(id) == Some(&Expr::AddressOf(table));
    // The indexed address: the table's address plus the index, a count of
    // elements (the base is no number any more), for the load and the
    // store alike.
    let scaled = |id: ExprId| matches!(l2.expr(id), Some(&Expr::Binary(Binary::Mul, _, four)) if constant(&l2, four, 4));
    assert!(sum(&l2, at_table, scaled));
    // The constant address inside it: its element at offset 8, no
    // variable of its own.
    assert!(sum(&l2, at_table, |id| constant(&l2, id, 8)));
    assert!(
        l2.variables
            .iter()
            .all(|variable| variable.kind != VarKind::Global(0x3108))
    );
}

#[test]
fn unbounded_and_overlapping_indices_stay_address_arithmetic() {
    let l2 = lowered(&indexing());
    for base in [0x3200, 0x3008] {
        // No variable at the base: an index nothing bounds may reach any
        // byte, and the one at 0x3008 reaches the named object at 0x3010.
        assert!(
            l2.variables
                .iter()
                .all(|variable| variable.kind != VarKind::Global(base)),
            "a variable at {base:#x}"
        );
        let at_base = |id: ExprId| constant(&l2, id, base);
        let any = |_: ExprId| true;
        assert!(
            sum(&l2, at_base, any) || sum(&l2, any, at_base),
            "no {base:#x} + index"
        );
    }
    // Nor is the named object a variable of these accesses.
    assert!(
        l2.variables
            .iter()
            .all(|variable| variable.kind != VarKind::Global(0x3010))
    );
}
