//! Constant propagation on functions built from small L0 programs.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_semantics::bits::Bits;
use binbun_semantics::build::Builder;
use binbun_semantics::core::pass::{Changed, Fuel, Manager};
use binbun_semantics::ir::{Binary, Declarations, LaneOp, RegisterId, RegisterInfo, View};
use binbun_ssa::constant::{Constants, FoldBranches, Lattice, NoMemory, propagate};
use binbun_ssa::graph::Dominators;
use binbun_ssa::pass::{L1Env, verify};
use binbun_ssa::{
    BlockId, CallEffect, Code, Environment, Function, Instruction, Terminator, build,
};

const REGISTERS: [RegisterInfo; 2] = [
    RegisterInfo {
        name: "a",
        width: 64,
    },
    RegisterInfo {
        name: "b",
        width: 64,
    },
];
const DECLARATIONS: Declarations = Declarations {
    registers: &REGISTERS,
    intrinsics: &[],
    sites: &[],
};
const A: View = View {
    register: RegisterId(0),
    offset: 0,
    width: 64,
};
const B: View = View {
    register: RegisterId(1),
    offset: 0,
    width: 64,
};

/// Nothing calls anything.
struct Nothing;

impl Environment for Nothing {
    fn call(&self, _: u64, _: Option<u64>) -> CallEffect {
        CallEffect::default()
    }
    fn system_call(&self, _: u64) -> CallEffect {
        CallEffect::default()
    }
    fn jump_targets(&self, _: u64) -> Vec<u64> {
        Vec::new()
    }

    fn jump_returns(&self, _: u64) -> bool {
        true
    }
}

/// An instruction at `address` whose semantics `body` builds.
fn inst(address: u64, body: impl FnOnce(&mut Builder)) -> Instruction {
    let mut b = Builder::new();
    body(&mut b);
    Instruction {
        address,
        next: address + 1,
        semantics: b.finish().unwrap(),
    }
}

fn set(b: &mut Builder, view: View, value: u64) {
    let constant = b.constant(64, value);
    b.write(view, constant);
}

/// `if register <op> value { jump target }`.
fn branch(b: &mut Builder, view: View, op: Binary, value: u64, target: u64) {
    let current = b.read(view);
    let constant = b.constant(64, value);
    let condition = b.binary(op, current, constant);
    b.begin_if(condition);
    let to = b.constant(64, target);
    b.jump(to);
    b.end_if();
}

fn returning(address: u64) -> Instruction {
    inst(address, |b| {
        let to = b.read(B);
        b.ret(to);
    })
}

fn function(blocks: Vec<Vec<Instruction>>) -> Function {
    let code = Code {
        entry: 0x10,
        blocks,
    };
    build(&code, &DECLARATIONS, &Nothing).unwrap()
}

/// The environment of these functions: no memory, `a` as the stack
/// pointer, no arguments.
const ENV: L1Env<'static> = L1Env {
    declarations: &DECLARATIONS,
    memory: &NoMemory,
    stack_pointer: RegisterId(0),
    arguments: &[],
    return_slot: None,
    thread_pointer: None,
};

/// Runs [`FoldBranches`] on `f` under a verifying manager; whether it
/// changed `f`, and the constants the manager holds after it.
fn fold(f: &mut Function) -> (Changed, Constants) {
    let mut manager = Manager::new(Fuel::new(1000)).with_verifier(verify);
    let changed = manager.run(&mut FoldBranches, f, &ENV).unwrap();
    assert_eq!(manager.stats().next().unwrap().1.refused, 0);
    let constants = manager.analysis::<Constants>(f, &ENV);
    (changed, (*constants).clone())
}

/// What propagation knows about register `index` at the (one) return.
fn at_return(f: &Function, index: usize) -> Lattice {
    let constants = propagate(f, &NoMemory);
    let state = f
        .blocks
        .iter()
        .find_map(|b| match &b.terminator {
            Terminator::Return { state, .. } => Some(state),
            Terminator::Jump(_)
            | Terminator::Branch { .. }
            | Terminator::Invoke { .. }
            | Terminator::IndirectJump { .. }
            | Terminator::Leave { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => None,
        })
        .unwrap();
    constants.lattice(state.registers[index])
}

#[test]
fn values_equal_on_every_path_are_constant() {
    // 10: a = 5; 11: if b == 0 goto 20; 12: a = 5; 20: return
    let f = function(vec![
        vec![
            inst(0x10, |b| set(b, A, 5)),
            inst(0x11, |b| branch(b, B, Binary::Eq, 0, 0x20)),
        ],
        vec![Instruction {
            next: 0x20,
            ..inst(0x12, |b| set(b, A, 5))
        }],
        vec![returning(0x20)],
    ]);
    assert_eq!(at_return(&f, 0), Lattice::Constant(Bits::from_u64(64, 5)));
}

#[test]
fn a_branch_on_a_constant_takes_one_side() {
    // 10: a = 1; b = 0; 11: if b == 0 goto 20; 12: a = 2; 20: return
    let f = function(vec![
        vec![
            inst(0x10, |b| {
                set(b, A, 1);
                set(b, B, 0);
            }),
            inst(0x11, |b| branch(b, B, Binary::Eq, 0, 0x20)),
        ],
        vec![Instruction {
            next: 0x20,
            ..inst(0x12, |b| set(b, A, 2))
        }],
        vec![returning(0x20)],
    ]);
    assert_eq!(at_return(&f, 0), Lattice::Constant(Bits::from_u64(64, 1)));
    let constants = propagate(&f, &NoMemory);
    let skipped = f.blocks.iter().position(|b| b.address == 0x12).unwrap();
    assert!(!constants.reachable(BlockId(u32::try_from(skipped).unwrap())));
}

#[test]
fn folding_a_constant_branch_leaves_only_the_side_it_takes() {
    // 10: a = 1; b = 0; 11: if b == 0 goto 20; 12: a = 2; 20: return,
    // and 13: if b != 0 goto 20 (never), behind 20's other predecessor.
    let mut f = function(vec![
        vec![
            inst(0x10, |b| {
                set(b, A, 1);
                set(b, B, 0);
            }),
            inst(0x11, |b| branch(b, B, Binary::Eq, 0, 0x20)),
        ],
        vec![Instruction {
            next: 0x20,
            ..inst(0x12, |b| set(b, A, 2))
        }],
        vec![returning(0x20)],
    ]);
    let block_at = |f: &Function, address| {
        BlockId(u32::try_from(f.blocks.iter().position(|b| b.address == address).unwrap()).unwrap())
    };
    let skipped = block_at(&f, 0x12);
    assert!(Dominators::new(&f).reachable(skipped));
    let (changed, constants) = fold(&mut f);
    assert_eq!(changed, Changed::Yes);
    // Following the graph from the entry no longer reaches 0x12; the
    // result still verifies (the manager checked) and means the same.
    assert!(!Dominators::new(&f).reachable(skipped));
    assert_eq!(at_return(&f, 0), Lattice::Constant(Bits::from_u64(64, 1)));
    // The constants it preserves are those of the folded function.
    assert_eq!(constants, propagate(&f, &NoMemory));
    // A varying condition is left alone.
    let mut g = function(vec![
        vec![inst(0x10, |b| branch(b, B, Binary::Eq, 0, 0x20))],
        vec![Instruction {
            next: 0x20,
            ..inst(0x11, |b| set(b, A, 2))
        }],
        vec![returning(0x20)],
    ]);
    assert_eq!(fold(&mut g).0, Changed::No);
}

#[test]
fn a_loop_counter_varies_and_untouched_values_stay_constant() {
    // 10: a = 0; b = 7; 11: a += 1; 12: if a != 10 goto 11; 13: return
    let f = function(vec![
        vec![inst(0x10, |b| {
            set(b, A, 0);
            set(b, B, 7);
        })],
        vec![
            inst(0x11, |b| {
                let a = b.read(A);
                let one = b.constant(64, 1);
                let sum = b.binary(Binary::Add, a, one);
                b.write(A, sum);
            }),
            inst(0x12, |b| branch(b, A, Binary::Ne, 10, 0x11)),
        ],
        vec![returning(0x13)],
    ]);
    assert_eq!(at_return(&f, 0), Lattice::Varies);
    assert_eq!(at_return(&f, 1), Lattice::Constant(Bits::from_u64(64, 7)));
}

/// The low half of `b`.
const LOW_B: View = View {
    register: RegisterId(1),
    offset: 0,
    width: 32,
};

/// `a = op(b, b)` lane by lane over the 4 byte lanes of `b`'s low half,
/// each lane's 1-bit answer sign-extended to its byte (SSE's `pcmpeqb`,
/// `pcmpgtb`), and `b = b <scalar> b` there, zero-extended; each operand
/// read on its own, as an instruction reads its two (one register).
fn with_itself(lane: Binary, scalar: Binary) -> Function {
    function(vec![
        vec![inst(0x10, |b| {
            let (x, y) = (b.read(LOW_B), b.read(LOW_B));
            let answers = b.lanes(LaneOp::Binary(lane), 4, &[x, y]);
            let extend = LaneOp::Extend {
                signed: true,
                width: 8,
            };
            let mask = b.lanes(extend, 4, &[answers]);
            let mask = b.zext(mask, 64);
            b.write(A, mask);
            let (x, y) = (b.read(LOW_B), b.read(LOW_B));
            let same = b.binary(scalar, x, y);
            let same = b.zext(same, 64);
            b.write(B, same);
        })],
        vec![returning(0x11)],
    ])
}

#[test]
fn an_operation_of_a_value_with_itself_is_the_constant_it_always_gives() {
    // `pcmpeqb x, x` is all ones and `xor x, x` 0, whatever `x` holds.
    let f = with_itself(Binary::Eq, Binary::Xor);
    let ones = Bits::from_u64(64, 0xffff_ffff);
    assert_eq!(at_return(&f, 0), Lattice::Constant(ones));
    assert_eq!(at_return(&f, 1), Lattice::Constant(Bits::zero(64)));
    // `pcmpgtb x, x` and `sub x, x` are 0.
    let f = with_itself(Binary::SLt, Binary::Sub);
    assert_eq!(at_return(&f, 0), Lattice::Constant(Bits::zero(64)));
    assert_eq!(at_return(&f, 1), Lattice::Constant(Bits::zero(64)));
    // Of two values that may differ, nothing is known.
    let f = function(vec![
        vec![inst(0x10, |b| {
            let (x, y) = (b.read(A), b.read(B));
            let differ = b.binary(Binary::Xor, x, y);
            b.write(B, differ);
        })],
        vec![returning(0x11)],
    ]);
    assert_eq!(at_return(&f, 1), Lattice::Varies);
}
