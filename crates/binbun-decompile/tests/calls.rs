#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The arguments of calls whose callee does not declare them all
//! (`lower::calls`), on hand-built L1: a declared format string that
//! parses gives them exactly, with their types; otherwise (no format, an
//! unknown callee, a format refused) every argument register up to the
//! last one the call may pass something in, a caller's untouched entry
//! value included (its parameter passed on in place), a value undefined on
//! every path left out. Every result is checked against its L1 by
//! structure and from random states.

use std::collections::{BTreeMap, BTreeSet};

use binbun_ast::ir::{Call, Function as Ast, Stmt};
use binbun_ast::types::{Signature, Type, Types};
use binbun_decompile::data::{Data, Object};
use binbun_decompile::format::Family;
use binbun_decompile::itanium::NONE;
use binbun_decompile::lower::{Context, Convention, Facts, Found, Interface, interface, lower};
use binbun_decompile::mapping::{Piece, Source};
use binbun_decompile::prototype::{AllocSize, Format, Open, Prototype, Prototypes};
use binbun_decompile::typing::{FieldType, FunctionTypes, Schemes};
use binbun_decompile::validate::{Hashed, Link, Setup, differential, random_states, structure};
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Fuel, Manager};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_semantics::{Declarations, RegisterInfo};
use binbun_ssa::constant::NoMemory;
use binbun_ssa::ir::{
    self, Block, BlockId, Definition, Function, Inst, InstId, Op, State, Target, Terminator,
    Type as L1Type, Unknown, ValueInfo,
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

/// `int put(char *, ...)`, `printf`-like.
const PUT: u64 = 0x6000;
/// A function nothing is known about.
const UNKNOWN: u64 = 0x7000;
/// Another function nothing is known about.
const OTHER: u64 = 0x7200;
/// `char *translate(char *)`, its result a translation of its argument's
/// format (`format_arg(1)`, as `gettext`).
const TRANSLATE: u64 = 0x7100;
/// The read-only strings: `"%d"`, and `"%1$d"` (positional: refused).
const STRINGS: [(u64, &[u8]); 2] = [(0x5000, b"%d\0"), (0x5010, b"%1$d\0")];

/// An image at a fixed address, read-only data from 0x5000 to 0x6000
/// holding [`STRINGS`].
struct Image;

impl Data for Image {
    fn object(&self, _: u64) -> Option<Object> {
        None
    }

    fn data(&self, address: u64, bytes: u64) -> Option<bool> {
        (address >= 0x5000 && address + bytes <= 0x6000).then_some(true)
    }

    fn string(&self, address: u64) -> Option<u64> {
        let (_, bytes) = STRINGS.iter().find(|(start, _)| *start == address)?;
        Some(bytes.len() as u64 - 1)
    }

    fn constant(&self, address: u64, bytes: u64) -> Option<Vec<u8>> {
        let (start, string) = STRINGS
            .iter()
            .find(|(start, string)| (*start..*start + string.len() as u64).contains(&address))?;
        let from = usize::try_from(address - start).unwrap();
        string
            .get(from..from + usize::try_from(bytes).unwrap())
            .map(<[u8]>::to_vec)
    }

    fn relocatable(&self) -> bool {
        false
    }
}

/// [`PUT`]'s prototype, its first parameter a `printf` format string, and
/// [`TRANSLATE`]'s.
struct Put;

impl Prototypes for Put {
    fn of(&self, address: u64, types: &mut Types) -> Option<Prototype> {
        let character = types.intern(Type::Char { signed: true });
        let string = types.intern(Type::Pointer(Some(character)));
        if address == TRANSLATE {
            return Some(Prototype {
                name: Some("translate".to_owned()),
                signature: types.intern(Type::Code(Signature {
                    parameters: vec![string],
                    returns: Some(string),
                    variadic: false,
                })),
                returns_stated: true,
                own: false,
                open: Open::default(),
                noreturn: false,
                format: None,
                format_arg: vec![0],
                alloc_size: None,
                wide_result: None,
            });
        }
        if address != PUT {
            return None;
        }
        let int = types.intern(Type::Int(32));
        Some(Prototype {
            name: Some("put".to_owned()),
            signature: types.intern(Type::Code(Signature {
                parameters: vec![string],
                returns: Some(int),
                variadic: true,
            })),
            returns_stated: true,
            own: false,
            open: Open::default(),
            noreturn: false,
            format: Some(Format {
                family: Family::Printf,
                string: 0,
                list: false,
            }),
            format_arg: Vec::new(),
            alloc_size: None,
            wide_result: None,
        })
    }
}

/// `l1` lowered, checked against it by structure and from 64 random
/// states.
fn lowered(l1: &Function) -> Ast {
    let convention = Convention {
        arguments: vec![A, B, C],
        results: vec![A],
        long: 64,
        ..Convention::default()
    };
    let functions = BTreeSet::from([0x1000]);
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

/// What `c` holds at the call.
#[derive(Clone, Copy, Debug)]
enum Third {
    /// The caller's entry value, untouched.
    Entry,
    /// An undefined value (as after another call that changes it).
    Undefined,
}

/// L1 by hand: one block after the entry's.
struct L1 {
    f: Function,
}

impl L1 {
    /// A function whose entry block jumps to block 1 (the registers and
    /// memory as its parameters).
    fn new() -> (Self, [ir::Value; 5]) {
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
}

/// `return target(first, b, c)`: `first` an immediate, `b` the caller's
/// entry value untouched, `c` as `third` says.
fn calling(target: u64, first: u64, third: Third) -> Function {
    passing(target, first, |l1, b, c| {
        let third = match third {
            Third::Entry => c,
            Third::Undefined => l1.pure(Op::Undefined(
                Unknown::Call {
                    address: 0x1000,
                    register: C,
                },
                Vec::new(),
            )),
        };
        [b, third]
    })
}

/// `return target(first, second, third)`: `first` an immediate, the
/// others what `rest` makes of the caller's entry values of `b` and `c`.
fn passing(
    target: u64,
    first: u64,
    rest: impl FnOnce(&mut L1, ir::Value, ir::Value) -> [ir::Value; 2],
) -> Function {
    let (mut l1, [_, b, c, sp, memory]) = L1::new();
    let first = l1.constant(first);
    let [second, third] = rest(&mut l1, b, c);
    let eight = l1.constant(8);
    let pushed = l1.pure(Op::Binary(Binary::Sub, sp, eight));
    let back = l1.constant(0x1100);
    let memory = l1.inst(
        Op::Store {
            memory,
            address: pushed,
            value: back,
            atomic: None,
        },
        &[L1Type::Memory],
    )[0];
    let target = l1.constant(target);
    let results = l1.inst(
        Op::Call {
            target,
            return_address: back,
            memory,
            registers: vec![first, second, third, pushed],
            changes: vec![A],
        },
        &[L1Type::Memory, L1Type::Bits(64)],
    );
    let address = l1.pure(Op::Load {
        memory: results[0],
        address: sp,
        bytes: 8,
        atomic: None,
    });
    let popped = l1.pure(Op::Binary(Binary::Add, sp, eight));
    l1.f.blocks[1].terminator = Terminator::Return {
        address,
        state: State {
            registers: vec![results[1], b, c, popped],
            memory: results[0],
        },
    };
    l1.f
}

/// The one call of `l2`.
fn call(l2: &Ast) -> &Call {
    calls(l2).next().unwrap()
}

/// The calls of `l2`'s call statements.
fn calls(l2: &Ast) -> impl Iterator<Item = &Call> {
    l2.stmts.iter().filter_map(|stmt| {
        if let Stmt::Call { call, .. } = stmt {
            Some(call)
        } else {
            None
        }
    })
}

/// `put(translate(message), b, c)`: `b` and `c` the caller's entry values
/// untouched.
fn translating(message: u64) -> Function {
    let (mut l1, [_, b, c, sp, memory]) = L1::new();
    let eight = l1.constant(8);
    let pushed = l1.pure(Op::Binary(Binary::Sub, sp, eight));
    let mut memory = memory;
    let mut first = l1.constant(message);
    for (target, back) in [(TRANSLATE, 0x1100), (PUT, 0x1200)] {
        let back = l1.constant(back);
        memory = l1.inst(
            Op::Store {
                memory,
                address: pushed,
                value: back,
                atomic: None,
            },
            &[L1Type::Memory],
        )[0];
        let target = l1.constant(target);
        let results = l1.inst(
            Op::Call {
                target,
                return_address: back,
                memory,
                registers: vec![first, b, c, pushed],
                changes: vec![A],
            },
            &[L1Type::Memory, L1Type::Bits(64)],
        );
        memory = results[0];
        first = results[1];
    }
    let address = l1.pure(Op::Load {
        memory,
        address: sp,
        bytes: 8,
        atomic: None,
    });
    let popped = l1.pure(Op::Binary(Binary::Add, sp, eight));
    l1.f.blocks[1].terminator = Terminator::Return {
        address,
        state: State {
            registers: vec![first, b, c, popped],
            memory,
        },
    };
    l1.f
}

/// The widths of `l2`'s parameters.
fn parameters(l2: &Ast) -> Vec<u16> {
    l2.parameters
        .iter()
        .map(|&parameter| {
            let ty = l2.var(parameter).unwrap().ty;
            l2.types.value_width(ty).unwrap()
        })
        .collect()
}

/// `unknown(1, b, c); return other(2, b, c)`, [`UNKNOWN`] changing `a`
/// and `c`: what `other` gets in `c` is what `unknown` left there.
fn leaving() -> Function {
    let (mut l1, [_, b, c, sp, memory]) = L1::new();
    let eight = l1.constant(8);
    let pushed = l1.pure(Op::Binary(Binary::Sub, sp, eight));
    let mut memory = memory;
    let mut third = c;
    let mut result = c;
    for (target, first, back) in [(UNKNOWN, 1, 0x1100), (OTHER, 2, 0x1200)] {
        let first = l1.constant(first);
        let back = l1.constant(back);
        memory = l1.inst(
            Op::Store {
                memory,
                address: pushed,
                value: back,
                atomic: None,
            },
            &[L1Type::Memory],
        )[0];
        let target = l1.constant(target);
        let results = l1.inst(
            Op::Call {
                target,
                return_address: back,
                memory,
                registers: vec![first, b, third, pushed],
                changes: vec![A, C],
            },
            &[L1Type::Memory, L1Type::Bits(64), L1Type::Bits(64)],
        );
        memory = results[0];
        result = results[1];
        third = results[2];
    }
    let address = l1.pure(Op::Load {
        memory,
        address: sp,
        bytes: 8,
        atomic: None,
    });
    let popped = l1.pure(Op::Binary(Binary::Add, sp, eight));
    l1.f.blocks[1].terminator = Terminator::Return {
        address,
        state: State {
            registers: vec![result, b, third, popped],
            memory,
        },
    };
    l1.f
}

#[test]
fn a_register_another_call_leaves_is_no_argument() {
    // unknown(1, b, c): `c` is the caller's entry value, passed on.
    // other(2, b, <what unknown left in c>): nothing other could use is
    // in `c`, so it takes two arguments, not a third printed as a value.
    let l2 = lowered(&leaving());
    let counts: Vec<usize> = calls(&l2).map(|call| call.arguments.len()).collect();
    assert_eq!(counts, [3, 2]);
}

#[test]
fn an_untouched_entry_value_is_passed_on_an_undefined_one_is_not() {
    // unknown(1, b, c): `b` and `c` may be the caller's parameters passed
    // on in place, so both are arguments (and its parameters).
    let l2 = lowered(&calling(UNKNOWN, 1, Third::Entry));
    assert_eq!(call(&l2).arguments.len(), 3);
    assert_eq!(parameters(&l2), [64, 64, 64]);
    // unknown(1, b, <undefined>): nothing the callee could use is in `c`.
    let l2 = lowered(&calling(UNKNOWN, 1, Third::Undefined));
    assert_eq!(call(&l2).arguments.len(), 2);
    assert_eq!(parameters(&l2), [64, 64]);
}

#[test]
fn a_parsed_format_string_gives_the_arguments_and_their_types() {
    // put("%d", b, c): one `int` after the format, `b` forwarded in place
    // (its low 32 bits); `c` is no argument and no parameter.
    let l2 = lowered(&calling(PUT, 0x5000, Third::Entry));
    let parsed = call(&l2);
    assert_eq!(parsed.arguments.len(), 2);
    let int = l2
        .types
        .iter()
        .find(|(_, ty)| **ty == Type::Int(32))
        .unwrap()
        .0;
    assert_eq!(parsed.variadic, [int]);
    assert_eq!(parameters(&l2), [64, 32]);
    // put("%1$d", b, c): refused, so every register the call may pass
    // something in.
    let l2 = lowered(&calling(PUT, 0x5010, Third::Entry));
    let refused = call(&l2);
    assert_eq!(refused.arguments.len(), 3);
    assert_eq!(refused.variadic, []);
    assert_eq!(parameters(&l2), [64, 64, 64]);
}

#[test]
fn a_translated_format_string_gives_its_messages_arguments() {
    // put(translate("%d"), b, c): the translation keeps the message's
    // conversions, so one `int` after the format, as for put("%d", b, c).
    let l2 = lowered(&translating(0x5000));
    let put = calls(&l2).nth(1).unwrap();
    assert_eq!(put.arguments.len(), 2);
    let int = l2
        .types
        .iter()
        .find(|(_, ty)| **ty == Type::Int(32))
        .unwrap()
        .0;
    assert_eq!(put.variadic, [int]);
    assert_eq!(parameters(&l2), [64, 32]);
    // put(translate("%1$d"), b, c): the message is refused, so is the
    // translation: every register the call may pass something in.
    let l2 = lowered(&translating(0x5010));
    let put = calls(&l2).nth(1).unwrap();
    assert_eq!(put.arguments.len(), 3);
    assert_eq!(put.variadic, []);
    assert_eq!(parameters(&l2), [64, 64, 64]);
}

/// A function of the program with no prototype, taking `a`, `b` and `c`.
const TAKES_THREE: u64 = 0x7300;

/// [`Put`]'s prototypes, and for the function lowered (at 0x1000) a
/// declaration that is not its own, as the type library's for the name
/// a definition is exported under: `int f(char *, …)` with so many
/// `char *` parameters.
struct Declared(usize);

impl Prototypes for Declared {
    fn of(&self, address: u64, types: &mut Types) -> Option<Prototype> {
        if address != 0x1000 {
            return Put.of(address, types);
        }
        let character = types.intern(Type::Char { signed: true });
        let string = types.intern(Type::Pointer(Some(character)));
        let int = types.intern(Type::Int(32));
        Some(Prototype {
            name: Some("f".to_owned()),
            signature: types.intern(Type::Code(Signature {
                parameters: vec![string; self.0],
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

/// What lowering finds of `l1` with `prototypes`, [`TAKES_THREE`] a
/// function of the program with its interface.
fn found(l1: &Function, prototypes: &dyn Prototypes) -> Found {
    let convention = Convention {
        arguments: vec![A, B, C],
        results: vec![A],
        long: 64,
        ..Convention::default()
    };
    let whole = |register| Piece {
        register,
        offset: 0,
        width: 64,
    };
    let interfaces = BTreeMap::from([(
        TAKES_THREE,
        Interface {
            parameters: [A, B, C].map(|r| Source::Register(whole(r))).to_vec(),
            returns: vec![whole(A)],
            ..Interface::default()
        },
    )]);
    let functions = BTreeSet::from([0x1000, TAKES_THREE]);
    let context = Context {
        data: &Image,
        prototypes,
        functions: &functions,
        interfaces: &interfaces,
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
    interface(l1, &facts, &context).unwrap()
}

#[test]
fn a_declared_function_reads_its_declared_parameters_not_what_it_passes_on() {
    // `int f(void)`, declared so by a declaration not its own, does
    // `return takes_three(1, b, c)` with `b` and `c` as it found them: it
    // reads neither, it only passes them on to a function of the program,
    // whose interface says whether they are read.
    let passed_on = found(&calling(TAKES_THREE, 1, Third::Entry), &Declared(0));
    assert_eq!(passed_on.reads, BTreeSet::new());
    assert_eq!(passed_on.opaque, BTreeSet::new());
    assert_eq!(passed_on.passed_on, BTreeSet::from([B, C]));
    assert_eq!(passed_on.undeclared, BTreeSet::from([TAKES_THREE]));
    // `int f(char *)` does `return put("%1$d", b, c)` (a format that does
    // not count the arguments): `a` is its declared parameter, `b` and
    // `c` go past the named parameter of a variadic prototype as found.
    let forwarded = found(&calling(PUT, 0x5010, Third::Entry), &Declared(1));
    assert_eq!(forwarded.reads, BTreeSet::from([A]));
    assert_eq!(forwarded.forwarded, BTreeSet::from([B, C]));
}

#[test]
fn a_declaration_not_its_own_says_what_a_function_takes_but_for_what_it_moves() {
    // `int f(void)`: `b` and `c` passed on in place are no parameters the
    // declaration places, nor anything the body does more with.
    let in_place = found(&calling(TAKES_THREE, 1, Third::Entry), &Declared(0));
    assert_eq!(in_place.declared_reads, Some(BTreeSet::new()));
    assert_eq!(in_place.own_reads, None);
    // `return takes_three(1, c, b)`: each passed in the other's register,
    // which its code put there.
    let moved = found(&passing(TAKES_THREE, 1, |_, b, c| [c, b]), &Declared(0));
    assert_eq!(moved.declared_reads, Some(BTreeSet::from([B, C])));
    // `int f(char *)`: the declared parameter's register too.
    let declared = found(&calling(TAKES_THREE, 1, Third::Entry), &Declared(1));
    assert_eq!(declared.declared_reads, Some(BTreeSet::from([A])));
    // No declaration: none.
    let none = found(&calling(TAKES_THREE, 1, Third::Entry), &Put);
    assert_eq!(none.declared_reads, None);
}

/// `l1` lowered with [`TAKES_THREE`] a function of the program with its
/// interface and no scheme (as one later in a cycle of calls), its
/// signature in the program's table `first` at its first parameter.
fn without_scheme(l1: &Function, first: FieldType) -> Ast {
    let convention = Convention {
        arguments: vec![A, B, C],
        results: vec![A],
        long: 64,
        ..Convention::default()
    };
    let whole = |register| Piece {
        register,
        offset: 0,
        width: 64,
    };
    let interfaces = BTreeMap::from([(
        TAKES_THREE,
        Interface {
            parameters: [A, B, C].map(|r| Source::Register(whole(r))).to_vec(),
            returns: vec![whole(A)],
            ..Interface::default()
        },
    )]);
    let mut schemes = Schemes::new();
    let signature = FunctionTypes {
        parameters: vec![(Source::Register(whole(A)), first)],
        returns: None,
    };
    schemes.settle_signatures(
        BTreeMap::from([(TAKES_THREE, signature)]),
        &BTreeMap::new(),
        64,
    );
    let functions = BTreeSet::from([0x1000, TAKES_THREE]);
    let context = Context {
        data: &Image,
        prototypes: &Put,
        functions: &functions,
        interfaces: &interfaces,
        schemes: &schemes,
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
    let (l2, _) = lower(l1, &facts, &context).unwrap();
    structure(l1, &l2, &NONE).unwrap();
    l2
}

#[test]
fn a_call_no_scheme_types_takes_its_callees_signature() {
    // return takes_three(0x5000, b, c): no scheme of the callee reaches
    // the call, but the program's signature has its first parameter a
    // `char *`: the call declares it so (where it said only 64 bits).
    let l1 = calling(TAKES_THREE, 0x5000, Third::Entry);
    let string = FieldType::Pointer(Some(Type::Char { signed: true }));
    let l2 = without_scheme(&l1, string);
    let signature = l2.types.signature(call(&l2).signature).unwrap();
    let first = l2.types.get(signature.parameters[0]);
    let Some(&Type::Pointer(Some(target))) = first else {
        panic!("{first:?}");
    };
    assert_eq!(l2.types.get(target), Some(&Type::Char { signed: true }));
    // A signature that says only the width leaves it bits.
    let l2 = without_scheme(&l1, FieldType::Scalar(Type::Bits(64)));
    let signature = l2.types.signature(call(&l2).signature).unwrap();
    assert_eq!(l2.types.get(signature.parameters[0]), Some(&Type::Bits(64)));
}

/// `void *grab(uint64_t)`, declared to allocate as many bytes as its
/// argument (`alloc_size(1)`).
const GRAB: u64 = 0x7400;
/// A function of the program with no prototype.
const WRAPPER: u64 = 0x7500;

/// [`GRAB`]'s prototype, then [`Put`]'s.
struct Allocates;

impl Prototypes for Allocates {
    fn of(&self, address: u64, types: &mut Types) -> Option<Prototype> {
        if address != GRAB {
            return Put.of(address, types);
        }
        let size = types.intern(Type::UInt(64));
        let any = types.intern(Type::Pointer(None));
        Some(Prototype {
            name: Some("grab".to_owned()),
            signature: types.intern(Type::Code(Signature {
                parameters: vec![size],
                returns: Some(any),
                variadic: false,
            })),
            returns_stated: true,
            own: false,
            open: Open::default(),
            noreturn: false,
            format: None,
            format_arg: Vec::new(),
            alloc_size: Some(AllocSize {
                size: 0,
                count: None,
            }),
            wide_result: None,
        })
    }
}

/// `return target(a)`, `a` the caller's entry value (`entry`), or 16.
fn allocating(target: u64, entry: bool) -> Function {
    let (mut l1, [a, b, c, sp, memory]) = L1::new();
    let size = if entry { a } else { l1.constant(16) };
    let eight = l1.constant(8);
    let pushed = l1.pure(Op::Binary(Binary::Sub, sp, eight));
    let back = l1.constant(0x1100);
    let memory = l1.inst(
        Op::Store {
            memory,
            address: pushed,
            value: back,
            atomic: None,
        },
        &[L1Type::Memory],
    )[0];
    let target = l1.constant(target);
    let results = l1.inst(
        Op::Call {
            target,
            return_address: back,
            memory,
            registers: vec![size, b, c, pushed],
            changes: vec![A],
        },
        &[L1Type::Memory, L1Type::Bits(64)],
    );
    let address = l1.pure(Op::Load {
        memory: results[0],
        address: sp,
        bytes: 8,
        atomic: None,
    });
    let popped = l1.pure(Op::Binary(Binary::Add, sp, eight));
    l1.f.blocks[1].terminator = Terminator::Return {
        address,
        state: State {
            registers: vec![results[1], b, c, popped],
            memory: results[0],
        },
    };
    l1.f
}

/// The context of the allocation tests: [`Allocates`]'s prototypes, and
/// [`WRAPPER`] a function of the program with `interface`.
fn with_wrapper<T>(interface: Interface, f: impl FnOnce(&Context<'_>) -> T) -> T {
    let convention = Convention {
        arguments: vec![A, B, C],
        results: vec![A],
        long: 64,
        ..Convention::default()
    };
    let interfaces = BTreeMap::from([(WRAPPER, interface)]);
    let functions = BTreeSet::from([0x1000, WRAPPER]);
    let context = Context {
        data: &Image,
        prototypes: &Allocates,
        functions: &functions,
        interfaces: &interfaces,
        ..Context::new(&DECLARATIONS, SP, LINK, &convention)
    };
    f(&context)
}

/// `l1`'s facts.
fn facts_of(l1: &Function) -> Facts {
    let env = L1Env {
        declarations: &DECLARATIONS,
        memory: &NoMemory,
        stack_pointer: SP,
        arguments: &[A, B, C],
        return_slot: Some(0),
        thread_pointer: None,
    };
    Facts::of(&mut Manager::new(Fuel::new(0)), l1, &env)
}

/// `WRAPPER`'s interface: `a` in, `a` out, allocating as many bytes as
/// `a` where `allocates`.
fn wrapper(allocates: bool) -> Interface {
    let whole = Piece {
        register: A,
        offset: 0,
        width: 64,
    };
    Interface {
        parameters: vec![Source::Register(whole)],
        returns: vec![whole],
        alloc_size: allocates.then_some(AllocSize {
            size: 0,
            count: None,
        }),
        ..Interface::default()
    }
}

#[test]
fn a_function_returning_an_allocation_of_its_parameter_is_an_allocator() {
    // `return grab(a)`: an allocator of `a` bytes, its own parameter 0.
    let l1 = allocating(GRAB, true);
    let found = with_wrapper(wrapper(false), |context| {
        interface(&l1, &facts_of(&l1), context).unwrap()
    });
    let size = Some(AllocSize {
        size: 0,
        count: None,
    });
    assert_eq!(found.interface.unwrap().alloc_size, size);
    // So is one returning an allocator wrapper's result (callees first).
    let l1 = allocating(WRAPPER, true);
    let found = with_wrapper(wrapper(true), |context| {
        interface(&l1, &facts_of(&l1), context).unwrap()
    });
    assert_eq!(found.interface.unwrap().alloc_size, size);
    // `return grab(16)`: a fixed size, no parameter of its own.
    let l1 = allocating(GRAB, false);
    let found = with_wrapper(wrapper(false), |context| {
        interface(&l1, &facts_of(&l1), context).unwrap()
    });
    assert_eq!(found.interface.unwrap().alloc_size, None);
    // `return wrapper(a)` where the wrapper is not one: none.
    let l1 = allocating(WRAPPER, true);
    let found = with_wrapper(wrapper(false), |context| {
        interface(&l1, &facts_of(&l1), context).unwrap()
    });
    assert_eq!(found.interface.unwrap().alloc_size, None);
}

#[test]
fn an_allocator_returns_void_and_its_callers_calls_take_its_size() {
    // `return wrapper(a)`: the call returns `void *` (any object's), as a
    // declared allocator's does.
    let l1 = allocating(WRAPPER, true);
    let l2 = with_wrapper(wrapper(true), |context| {
        lower(&l1, &facts_of(&l1), context).unwrap().0
    });
    let signature = l2.types.signature(call(&l2).signature).unwrap();
    let returns = signature.returns.and_then(|ty| l2.types.get(ty));
    assert_eq!(returns, Some(&Type::Pointer(None)));
    // The function itself, an allocator too, returns `void *`.
    let own = l2.returns.and_then(|ty| l2.types.get(ty));
    assert_eq!(own, Some(&Type::Pointer(None)));
    // Not an allocator: the result stays as wide as it is.
    let l2 = with_wrapper(wrapper(false), |context| {
        lower(&l1, &facts_of(&l1), context).unwrap().0
    });
    let signature = l2.types.signature(call(&l2).signature).unwrap();
    let returns = signature.returns.and_then(|ty| l2.types.get(ty));
    assert_ne!(returns, Some(&Type::Pointer(None)));
}
