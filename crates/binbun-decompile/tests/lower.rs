#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Lowering on hand-built L1: variables out of SSA (interfering values of
//! one register apart, a loop counter one variable, the budget), callee-
//! saved saves and restores gone, a jump table as a switch, malformed
//! input refused, a call on a stack other than the frame a stack trick,
//! the thread pointer an environment variable unless the function changes
//! it, the type solver's types on parameters and the return value, the
//! class every caller passes below the body's own operations. Every result
//! is checked against its L1 by structure and from random states.

use binbun_ast::ir::{Escape, Function as Ast, Origin, Place, Stmt, StmtId, VarKind};
use binbun_ast::types::{Evidence, Type as L2Type};
use binbun_decompile::itanium::NONE;
use binbun_decompile::lower::{
    Context, Convention, Counts, Facts, FloatControl, LowerError, lower, lower_counted,
};
use binbun_decompile::mapping::{Mapping, Piece, Source};
use binbun_decompile::typing::Class;
use binbun_decompile::validate::{Hashed, Link, Setup, differential, random_states, structure};
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Fuel, Manager};
use binbun_semantics::ir::{Binary, RegisterId, Unary};
use binbun_semantics::{Declarations, RegisterInfo};
use binbun_ssa::constant::NoMemory;
use binbun_ssa::ir::{
    self, Block, BlockId, Definition, Function, Inst, InstId, Op, State, Target, Terminator, Type,
    ValueInfo,
};
use binbun_ssa::pass::L1Env;
use binbun_typeinfer::Atom;

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
const LINK: Link = Link::Stack { bytes: 8 };

/// Arguments and results in `a`; `b` kept by callees.
fn convention() -> Convention {
    Convention {
        arguments: vec![A],
        results: vec![A],
        callee_saved: vec![B],
        ..Convention::default()
    }
}

/// `l1`'s analyses under `convention`, as a pass manager gives them (no
/// memory known).
fn facts(l1: &Function, convention: &Convention) -> Facts {
    let env = L1Env {
        declarations: &DECLARATIONS,
        memory: &NoMemory,
        stack_pointer: SP,
        arguments: &convention.arguments,
        return_slot: Some(0),
        thread_pointer: convention.thread_pointer,
    };
    Facts::of(&mut Manager::new(Fuel::new(0)), l1, &env)
}

/// Lowers `l1` (with `budget`) and checks the result against it: the
/// structure check and 64 random states.
fn lowered(l1: &Function, budget: u64) -> (Ast, Mapping, Counts) {
    lowered_under(l1, budget, &convention())
}

/// [`lowered`] under `convention`.
fn lowered_under(l1: &Function, budget: u64, convention: &Convention) -> (Ast, Mapping, Counts) {
    let context = Context {
        budget,
        ..Context::new(&DECLARATIONS, SP, LINK, convention)
    };
    checked(l1, &context, convention)
}

/// `l1` lowered under `context`, checked by structure and from 64 random
/// states.
fn checked(
    l1: &Function,
    context: &Context<'_>,
    convention: &Convention,
) -> (Ast, Mapping, Counts) {
    let (l2, mapping, counts) = lower_counted(l1, &facts(l1, convention), context).unwrap();
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
    (l2, mapping, counts)
}

// L1 by hand.

/// The state's types: the registers, then the memory.
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
        let popped = self.binary(Binary::Add, sp, eight, 64);
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

/// `a` counted from 0 while below 10 (`H(counter): next = counter + 1;
/// next < 10 ? H(next)`), then returned: `next`, or (`old`) the `counter`
/// it came from.
fn counting(old: bool) -> Function {
    let (mut l1, [_, kept, stack, flag, memory]) = L1::new();
    let zero = l1.constant(32, 0);
    let (header, [counter, hb, hsp, hc, hmemory]) = l1.block(0x1010);
    l1.terminate(Terminator::Jump(target(
        header,
        &[zero, kept, stack, flag, memory],
    )));
    l1.current = header;
    let one = l1.constant(32, 1);
    let next = l1.binary(Binary::Add, counter, one, 32);
    let ten = l1.constant(32, 10);
    let below = l1.binary(Binary::ULt, next, ten, 1);
    let (exit, [result, xb, xsp, xc, xmemory]) = l1.block(0x1020);
    let returned = if old { counter } else { next };
    l1.terminate(Terminator::Branch {
        condition: below,
        then: target(header, &[next, hb, hsp, hc, hmemory]),
        otherwise: target(exit, &[returned, hb, hsp, hc, hmemory]),
    });
    l1.current = exit;
    l1.ret(xsp, [result, xb, xc], xmemory);
    l1.f
}

/// The variables an assignment writes.
fn assigned(l2: &Ast) -> Vec<binbun_ast::ir::VarId> {
    let mut vars: Vec<_> = l2
        .stmts
        .iter()
        .filter_map(|stmt| {
            if let Stmt::Assign {
                place: Place::Var(var),
                ..
            } = stmt
            {
                Some(*var)
            } else {
                None
            }
        })
        .collect();
    vars.sort_unstable();
    vars.dedup();
    vars
}

#[test]
fn a_loop_counter_is_one_variable() {
    let (l2, _, counts) = lowered(&counting(false), Context::BUDGET);
    assert_eq!((counts.values, counts.variables, counts.copies), (2, 1, 1));
    assert_eq!(assigned(&l2).len(), 1);
}

#[test]
fn an_unchanged_result_on_one_joined_path_is_not_an_inferred_parameter() {
    for path in 0..3 {
        let (mut l1, [a, b, sp, c, memory]) = L1::new();
        let one = l1.constant(32, 1);
        let other = match path {
            0 => a,
            1 => l1.constant(32, 2),
            _ => l1.binary(Binary::Add, a, one, 32),
        };
        let (left, lp) = l1.block(0x1010);
        let (right, rp) = l1.block(0x1020);
        let (join, [result, jb, jsp, jc, jm]) = l1.block(0x1030);
        l1.terminate(Terminator::Branch {
            condition: c,
            then: target(left, &[one, b, sp, c, memory]),
            otherwise: target(right, &[other, b, sp, c, memory]),
        });
        l1.terminate_in(left, Terminator::Jump(target(join, &lp)));
        l1.terminate_in(right, Terminator::Jump(target(join, &rp)));
        l1.current = join;
        l1.ret(jsp, [result, jb, jc], jm);
        let mut non_argument = convention();
        non_argument.arguments.clear();
        let (l2, mapping, _) = lowered_under(&l1.f, Context::BUDGET, &non_argument);
        assert_eq!(l2.returns.is_none(), path == 0);
        let mut expected = Vec::new();
        if path == 2 {
            expected.push(Source::Register(Piece {
                register: A,
                offset: 0,
                width: 32,
            }));
        }
        expected.push(Source::Register(Piece {
            register: RegisterId(3),
            offset: 0,
            width: 1,
        }));
        assert_eq!(mapping.parameters, expected);
        if path == 0 {
            // AArch64's x0 is both a parameter and a result register:
            // returning its entry value on one path can be intentional.
            let (l2, mapping, _) = lowered(&l1.f, Context::BUDGET);
            assert!(l2.returns.is_some());
            assert_eq!(
                mapping.parameters,
                vec![
                    Source::Register(Piece {
                        register: A,
                        offset: 0,
                        width: 32
                    }),
                    Source::Register(Piece {
                        register: RegisterId(3),
                        offset: 0,
                        width: 1
                    }),
                ]
            );
        }
    }
}

#[test]
fn interfering_values_of_one_register_stay_apart() {
    // `i` is still live (returned) where `n` is defined: two variables,
    // the back edge copies `n` into `i`'s.
    let (l2, _, counts) = lowered(&counting(true), Context::BUDGET);
    assert_eq!((counts.values, counts.variables), (2, 2));
    assert_eq!(assigned(&l2).len(), 2);
}

#[test]
fn past_the_budget_each_value_keeps_its_variable() {
    let (_, _, counts) = lowered(&counting(false), 0);
    assert!(counts.over_budget);
    assert_eq!((counts.values, counts.variables), (2, 2));
}

#[test]
fn a_branch_on_flags_stands_for_their_instructions() {
    // `jne` after `cmp a, 5`: the zero flag of `a - 5`, negated, is the
    // condition `a != 5`. It stands for the constants, the subtraction,
    // the flag and the negation (none of them a node of its own); the
    // `if` for the branch, its block's last instruction.
    let (mut l1, [a, b, sp, c, memory]) = L1::new();
    let five = l1.constant(32, 5);
    let difference = l1.binary(Binary::Sub, a, five, 32);
    let zero = l1.constant(32, 0);
    let flag = l1.binary(Binary::Eq, difference, zero, 1);
    let not = l1.pure(Op::Unary(Unary::Not, flag), 1);
    let branch = l1.current;
    let (then, [ta, tb, tsp, tc, tmemory]) = l1.block(0x1100);
    let (otherwise, [_, ob, osp, oc, omemory]) = l1.block(0x1200);
    l1.terminate(Terminator::Branch {
        condition: not,
        then: target(then, &[a, b, sp, c, memory]),
        otherwise: target(otherwise, &[a, b, sp, c, memory]),
    });
    l1.f.blocks[branch.0 as usize].end = 0x1014;
    l1.current = then;
    l1.ret(tsp, [ta, tb, tc], tmemory);
    l1.current = otherwise;
    let one = l1.constant(32, 1);
    l1.ret(osp, [one, ob, oc], omemory);
    let (l2, _, _) = lowered(&l1.f, Context::BUDGET);
    let address = |value: ir::Value| match l1.f.value(value).unwrap().definition {
        Definition::Result { inst, .. } => l1.f.inst(inst).unwrap().address,
        Definition::Parameter { .. } => unreachable!(),
    };
    let (id, condition) = (0u32..)
        .zip(&l2.stmts)
        .find_map(|(id, stmt)| {
            if let &Stmt::If { condition, .. } = stmt {
                Some((StmtId(id), condition))
            } else {
                None
            }
        })
        .unwrap();
    assert!(
        l2.provenance
            .stmt(id)
            .contains(&Origin::Instruction(0x1014))
    );
    let mut made: Vec<u64> = l2
        .provenance
        .expr(condition)
        .iter()
        .filter_map(|origin| {
            if let Origin::Instruction(address) = *origin {
                Some(address)
            } else {
                None
            }
        })
        .collect();
    made.sort_unstable();
    let mut expected: Vec<u64> = [five, difference, zero, flag, not].map(address).to_vec();
    expected.sort_unstable();
    assert_eq!(made, expected);
}

#[test]
fn the_solver_types_from_l1() {
    // return a >> 31 (arithmetic): `a` is demanded signed, the shift gives
    // a signed value, which is returned.
    let (mut l1, [a, b, sp, c, memory]) = L1::new();
    let shift = l1.constant(32, 31);
    let signed = l1.binary(Binary::AShr, a, shift, 32);
    l1.ret(sp, [signed, b, c], memory);
    let (l2, _, counts) = lowered(&l1.f, Context::BUDGET);
    assert!(counts.typing.typed && !counts.typing.refused);
    let parameter = l2.var(l2.parameters[0]).unwrap();
    assert_eq!(l2.types.get(parameter.ty), Some(&L2Type::Int(32)));
    assert_eq!(parameter.evidence, Evidence::Deduced);
    assert_eq!(
        l2.returns.and_then(|ty| l2.types.get(ty)),
        Some(&L2Type::Int(32))
    );
    assert_eq!(l2.returns_evidence, Evidence::Deduced);
}

/// The type of the first parameter of `l1` lowered with every caller
/// passing a signed 32-bit integer in `a` (the top-down specialisation).
fn specialised_parameter(l1: &Function) -> L2Type {
    let convention = convention();
    let specialised = [(
        Source::Register(Piece {
            register: A,
            offset: 0,
            width: 32,
        }),
        Class::Scalar(Atom::Signed(32)),
    )];
    let context = Context {
        specialised: &specialised,
        ..Context::new(&DECLARATIONS, SP, LINK, &convention)
    };
    let (l2, _, _) = checked(l1, &context, &convention);
    let parameter = l2.var(l2.parameters[0]).unwrap();
    l2.types.get(parameter.ty).unwrap().clone()
}

#[test]
fn callers_agreement_types_a_parameter_below_the_bodys_own_operations() {
    // return a + 1: nothing in the body says what `a` is; its callers do.
    let (mut l1, [a, b, sp, c, memory]) = L1::new();
    let one = l1.constant(32, 1);
    let next = l1.binary(Binary::Add, a, one, 32);
    l1.ret(sp, [next, b, c], memory);
    assert_eq!(specialised_parameter(&l1.f), L2Type::Int(32));
    // return a / 3 (unsigned): the body's division outranks its callers.
    let (mut l1, [a, b, sp, c, memory]) = L1::new();
    let three = l1.constant(32, 3);
    let quotient = l1.binary(Binary::UDiv, a, three, 32);
    l1.ret(sp, [quotient, b, c], memory);
    assert_eq!(specialised_parameter(&l1.f), L2Type::UInt(32));
}

#[test]
fn callee_saved_saves_and_restores_disappear() {
    // push b; pop b; return 7.
    let (mut l1, [_, b, sp, c, memory]) = L1::new();
    let eight = l1.constant(64, 8);
    let slot = l1.binary(Binary::Sub, sp, eight, 64);
    let memory = l1.inst(
        Op::Store {
            memory,
            address: slot,
            value: b,
            atomic: None,
        },
        &[Type::Memory],
    )[0];
    let restored = l1.pure(
        Op::Load {
            memory,
            address: slot,
            bytes: 4,
            atomic: None,
        },
        32,
    );
    let seven = l1.constant(32, 7);
    l1.ret(sp, [seven, restored, c], memory);
    let (l2, mapping, _) = lowered(&l1.f, Context::BUDGET);
    assert_eq!(l2.parameters, []);
    assert_eq!(mapping.parameters, []);
    assert!(
        l2.stmts
            .iter()
            .all(|stmt| !matches!(stmt, Stmt::Assign { .. }))
    );
    assert!(
        l2.variables
            .iter()
            .all(|var| !var.origins.contains(&Origin::Slot(-8)))
    );
}

#[test]
fn a_narrow_use_of_a_block_parameter_leaves_the_bits_it_kept_unused() {
    // a = low16(a) < 0 ? high16(a):1 : high16(a):2 (each arm a narrower
    // write keeping the high bits, joined in a block parameter); return
    // zext(low16(joined)). Only `a`'s low 16 bits are read: a 16-bit
    // parameter, its high bits (through the join) unused.
    let (mut l1, [a, b, sp, c, memory]) = L1::new();
    let low = l1.pure(
        Op::Extract {
            value: a,
            offset: 0,
            width: 16,
        },
        16,
    );
    let high = l1.pure(
        Op::Extract {
            value: a,
            offset: 16,
            width: 16,
        },
        16,
    );
    let zero = l1.constant(16, 0);
    let negative = l1.binary(Binary::SLt, low, zero, 1);
    let (then, [_, tb, tsp, tc, tmemory]) = l1.block(0x1010);
    let (otherwise, [_, eb, esp, ec, ememory]) = l1.block(0x1020);
    let (join, [joined, jb, jsp, jc, jmemory]) = l1.block(0x1030);
    l1.terminate(Terminator::Branch {
        condition: negative,
        then: target(then, &[a, b, sp, c, memory]),
        otherwise: target(otherwise, &[a, b, sp, c, memory]),
    });
    for (block, value, kept, stack, flag, memory) in [
        (then, 1, tb, tsp, tc, tmemory),
        (otherwise, 2, eb, esp, ec, ememory),
    ] {
        l1.current = block;
        let written = l1.constant(16, value);
        let whole = l1.pure(Op::Concat { high, low: written }, 32);
        l1.terminate(Terminator::Jump(target(
            join,
            &[whole, kept, stack, flag, memory],
        )));
    }
    l1.current = join;
    let part = l1.pure(
        Op::Extract {
            value: joined,
            offset: 0,
            width: 16,
        },
        16,
    );
    let result = l1.pure(
        Op::Extend {
            signed: false,
            value: part,
            width: 32,
        },
        32,
    );
    l1.ret(jsp, [result, jb, jc], jmemory);
    let (_, mapping, _) = lowered(&l1.f, Context::BUDGET);
    assert_eq!(
        mapping.parameters,
        [Source::Register(Piece {
            register: A,
            offset: 0,
            width: 16,
        })]
    );
}

#[test]
fn a_jump_table_becomes_a_switch() {
    // goto *(0x2000 + (a & 1) * 0x10): return 1 or 2.
    let (mut l1, [a, b, sp, c, memory]) = L1::new();
    let one = l1.constant(32, 1);
    let bit = l1.binary(Binary::And, a, one, 32);
    let wide = l1.pure(
        Op::Extend {
            signed: false,
            value: bit,
            width: 64,
        },
        64,
    );
    let stride = l1.constant(64, 0x10);
    let scaled = l1.binary(Binary::Mul, wide, stride, 64);
    let base = l1.constant(64, 0x2000);
    let address = l1.binary(Binary::Add, base, scaled, 64);
    let (first, [_, b0, sp0, c0, m0]) = l1.block(0x2000);
    let (second, [_, b1, sp1, c1, m1]) = l1.block(0x2010);
    l1.terminate(Terminator::IndirectJump {
        address,
        targets: vec![
            target(first, &[a, b, sp, c, memory]),
            target(second, &[a, b, sp, c, memory]),
        ],
    });
    l1.current = first;
    let r0 = l1.constant(32, 1);
    l1.ret(sp0, [r0, b0, c0], m0);
    l1.current = second;
    let r1 = l1.constant(32, 2);
    l1.ret(sp1, [r1, b1, c1], m1);
    let (l2, _, _) = lowered(&l1.f, Context::BUDGET);
    let arms = l2
        .stmts
        .iter()
        .find_map(|stmt| {
            if let Stmt::Switch { arms, .. } = stmt {
                Some(arms)
            } else {
                None
            }
        })
        .unwrap();
    let values: Vec<u64> = arms
        .iter()
        .flat_map(|arm| arm.values.iter().map(Bits::low_u64))
        .collect();
    assert_eq!(values, [0x2000, 0x2010]);
    let default = arms.iter().find(|arm| arm.default).unwrap();
    assert!(matches!(
        l2.stmt(default.body[0]),
        Some(Stmt::Escape {
            kind: Escape::UnresolvedJump,
            ..
        })
    ));
    assert!(
        l2.variables
            .iter()
            .all(|var| !matches!(var.kind, VarKind::Frame(_)) || var.kind == VarKind::Frame(0))
    );
}

#[test]
fn malformed_input_is_refused() {
    let convention = convention();
    let context = Context::new(&DECLARATIONS, SP, LINK, &convention);
    // A block still open.
    let mut open = counting(false);
    open.blocks[2].terminator = Terminator::Open;
    assert!(matches!(
        lower(&open, &facts(&open, &convention), &context),
        Err(LowerError::Malformed(_))
    ));
    // A computed jump whose two targets start at one address.
    let (mut l1, [a, b, sp, c, memory]) = L1::new();
    let address = l1.pure(
        Op::Extend {
            signed: false,
            value: a,
            width: 64,
        },
        64,
    );
    let (first, [_, b0, sp0, c0, m0]) = l1.block(0x2000);
    let (second, [_, b1, sp1, c1, m1]) = l1.block(0x2000);
    l1.terminate(Terminator::IndirectJump {
        address,
        targets: vec![
            target(first, &[a, b, sp, c, memory]),
            target(second, &[a, b, sp, c, memory]),
        ],
    });
    l1.current = first;
    l1.ret(sp0, [a, b0, c0], m0);
    l1.current = second;
    l1.ret(sp1, [a, b1, c1], m1);
    assert!(matches!(
        lower(&l1.f, &facts(&l1.f, &convention), &context),
        Err(LowerError::Malformed(_))
    ));
}

/// Where `calling` makes its call: the stack pointer before the call's
/// push of its return address.
#[derive(Clone, Copy, Debug)]
enum Top {
    /// Loaded from memory (a stack switched to).
    Loaded,
    /// 16 bytes above the entry stack pointer (`pop; pop; call`): the push
    /// writes the caller's frame.
    Caller,
    /// Below the entry stack pointer by `a & 0x7f0` (`alloca`).
    Alloca,
    /// As `Alloca`, saved in a slot of the frame and loaded back.
    Restored,
}

/// `if (c) { push the return address at top - 8; a = f(a) on that stack }
/// return a;`, with the stack pointer `top` as `how` says.
fn calling(how: Top) -> Function {
    let (mut l1, entry) = L1::new();
    let (call, [a, b, sp, c, memory]) = l1.block(0x1010);
    let (exit, [xa, xb, xsp, xc, xmemory]) = l1.block(0x1020);
    l1.terminate(Terminator::Branch {
        condition: entry[3],
        then: target(call, &entry),
        otherwise: target(exit, &entry),
    });
    l1.current = exit;
    l1.ret(xsp, [xa, xb, xc], xmemory);
    l1.current = call;
    let load = |l1: &mut L1, memory, address| {
        l1.pure(
            Op::Load {
                memory,
                address,
                bytes: 8,
                atomic: None,
            },
            64,
        )
    };
    let mut memory = memory;
    let top = match how {
        Top::Loaded => {
            let address = l1.constant(64, 0x5000);
            load(&mut l1, memory, address)
        }
        Top::Caller => {
            let sixteen = l1.constant(64, 16);
            l1.binary(Binary::Add, sp, sixteen, 64)
        }
        Top::Alloca | Top::Restored => {
            let mask = l1.constant(32, 0x7f0);
            let size = l1.binary(Binary::And, a, mask, 32);
            let size = l1.pure(
                Op::Extend {
                    signed: false,
                    value: size,
                    width: 64,
                },
                64,
            );
            let top = l1.binary(Binary::Sub, sp, size, 64);
            if matches!(how, Top::Restored) {
                let sixteen = l1.constant(64, 16);
                let slot = l1.binary(Binary::Sub, sp, sixteen, 64);
                memory = l1.inst(
                    Op::Store {
                        memory,
                        address: slot,
                        value: top,
                        atomic: None,
                    },
                    &[Type::Memory],
                )[0];
                load(&mut l1, memory, slot)
            } else {
                top
            }
        }
    };
    let eight = l1.constant(64, 8);
    let pushed = l1.binary(Binary::Sub, top, eight, 64);
    let back = l1.constant(64, 0x1100);
    let memory = l1.inst(
        Op::Store {
            memory,
            address: pushed,
            value: back,
            atomic: None,
        },
        &[Type::Memory],
    )[0];
    let callee = l1.constant(64, 0x3000);
    let results = l1.inst(
        Op::Call {
            target: callee,
            return_address: back,
            memory,
            registers: vec![a, b, pushed, c],
            changes: vec![A],
        },
        &[Type::Memory, Type::Bits(32)],
    );
    l1.ret(sp, [results[1], b, c], results[0]);
    l1.f
}

#[test]
fn a_call_on_a_stack_other_than_the_frame_is_a_stack_trick() {
    // Each lowered and checked from random states (`lowered`): without the
    // escape, L1's push of the return address is a write L2 does not make.
    for (how, trick) in [
        (Top::Loaded, true),
        (Top::Caller, true),
        (Top::Alloca, false),
        (Top::Restored, false),
    ] {
        let (l2, _, _) = lowered(&calling(how), Context::BUDGET);
        let escapes: Vec<usize> = l2
            .stmts
            .iter()
            .enumerate()
            .filter(|(_, stmt)| {
                matches!(
                    stmt,
                    Stmt::Escape {
                        kind: Escape::StackTrick,
                        ..
                    }
                )
            })
            .map(|(index, _)| index)
            .collect();
        let call = l2
            .stmts
            .iter()
            .position(|stmt| matches!(stmt, Stmt::Call { .. }))
            .unwrap();
        let expected: Vec<usize> = if trick { vec![call - 1] } else { Vec::new() };
        assert_eq!(escapes, expected, "{how:?}");
    }
}

/// `return *(a: 32 bits)(zext(b) + 0x28)`, under a convention whose thread
/// pointer is `b`; with `changes`, `b` is incremented on the way out.
fn thread_relative(changes: bool) -> Function {
    let (mut l1, [_, b, sp, c, memory]) = L1::new();
    let wide = l1.pure(
        Op::Extend {
            signed: false,
            value: b,
            width: 64,
        },
        64,
    );
    let offset = l1.constant(64, 0x28);
    let address = l1.binary(Binary::Add, wide, offset, 64);
    let loaded = l1.pure(
        Op::Load {
            memory,
            address,
            bytes: 4,
            atomic: None,
        },
        32,
    );
    let kept = if changes {
        let one = l1.constant(32, 1);
        l1.binary(Binary::Add, b, one, 32)
    } else {
        b
    };
    l1.ret(sp, [loaded, kept, c], memory);
    l1.f
}

#[test]
fn the_thread_pointer_is_the_environment_unless_the_function_changes_it() {
    // `lowered_under` runs the differential check: L2's environment
    // variable must read `b`'s entry value for the loads to agree.
    let convention = Convention {
        thread_pointer: Some(B),
        callee_saved: Vec::new(),
        ..convention()
    };
    let (l2, mapping, _) = lowered_under(&thread_relative(false), Context::BUDGET, &convention);
    assert_eq!(l2.parameters, []);
    assert_eq!(mapping.parameters, []);
    let environment: Vec<_> = l2
        .variables
        .iter()
        .filter(|var| matches!(var.kind, VarKind::Environment(_)))
        .map(|var| var.kind)
        .collect();
    assert_eq!(environment, [VarKind::Environment(B)]);
    // Changed (`wrfsbase`, a thread switch): its entry value is an input
    // like any other, a parameter.
    let (l2, mapping, _) = lowered_under(&thread_relative(true), Context::BUDGET, &convention);
    assert_eq!(l2.parameters.len(), 1);
    assert_eq!(
        mapping.parameters,
        [Source::Register(Piece {
            register: B,
            offset: 0,
            width: 32,
        })]
    );
    assert!(
        l2.variables
            .iter()
            .all(|var| !matches!(var.kind, VarKind::Environment(_)))
    );
}

/// `return extract(b, 13, 2)` (a rounding mode), under a convention whose
/// floating-point control register is `b` with 6 status bits; on the way
/// out `b` is or-ed with flag `c` zero-extended to `flags` bits, then to
/// 32 (none: left as it was).
fn rounding(flags: Option<u16>) -> Function {
    let (mut l1, [_, b, sp, c, memory]) = L1::new();
    let mode = l1.pure(
        Op::Extract {
            value: b,
            offset: 13,
            width: 2,
        },
        2,
    );
    let result = l1.pure(
        Op::Extend {
            signed: false,
            value: mode,
            width: 32,
        },
        32,
    );
    let left = match flags {
        Some(width) => {
            let raised = l1.pure(
                Op::Extend {
                    signed: false,
                    value: c,
                    width,
                },
                width,
            );
            let wide = l1.pure(
                Op::Extend {
                    signed: false,
                    value: raised,
                    width: 32,
                },
                32,
            );
            l1.binary(Binary::Or, b, wide, 32)
        }
        None => b,
    };
    l1.ret(sp, [result, left, c], memory);
    l1.f
}

#[test]
fn a_float_control_register_is_the_environment_while_its_controls_are_kept() {
    let convention = Convention {
        float_control: vec![FloatControl {
            register: B,
            status_bits: 6,
            default: 0x1f80,
        }],
        callee_saved: Vec::new(),
        ..convention()
    };
    // Left as it was, or with status flags raised: the environment.
    for flags in [None, Some(6)] {
        let (l2, mapping, _) = lowered_under(&rounding(flags), Context::BUDGET, &convention);
        assert_eq!(mapping.parameters, [], "{flags:?}");
        let environment: Vec<_> = l2
            .variables
            .iter()
            .filter(|var| matches!(var.kind, VarKind::Environment(_)))
            .map(|var| var.kind)
            .collect();
        assert_eq!(environment, [VarKind::Environment(B)], "{flags:?}");
    }
    // A control bit set too (bit 6): the function changes the controls,
    // and its entry value is a parameter.
    let (l2, mapping, _) = lowered_under(&rounding(Some(7)), Context::BUDGET, &convention);
    assert_eq!(mapping.parameters.len(), 1);
    assert!(
        l2.variables
            .iter()
            .all(|var| !matches!(var.kind, VarKind::Environment(_)))
    );
}
