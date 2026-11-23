//! The stack's escape through intrinsics: an intrinsic whose inputs may
//! escape takes a stack address passed to it as escaping; one that does
//! not (a keyed hash, such as a pointer authentication code computed with
//! the stack pointer as modifier) leaves the frame private, so a slot is
//! still forwarded past a call. And the assumption that the stack, the
//! caller's return address and the thread pointer plus a constant are
//! canonical, which folds L0's checks of those addresses (and of what a
//! fixed import slot holds) and no others; and the reading view's, that
//! every address dereferenced is, which folds the checks that guard an
//! access and no others.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_semantics::bits::Bits;
use binbun_semantics::build::Builder;
use binbun_semantics::core::pass::{Changed, Fuel, Manager};
use binbun_semantics::ir::{
    Binary, Declarations, IntrinsicId, IntrinsicInfo, RegisterId, RegisterInfo, Trap, View,
};
use binbun_ssa::constant::{ReadOnly, propagate};
use binbun_ssa::graph::Dominators;
use binbun_ssa::pass::{L1Env, verify};
use binbun_ssa::stack::{AssumeCanonical, AssumeDereferenced, Stack, TailJumps};
use binbun_ssa::{
    BlockId, CallEffect, Code, Environment, Function, Instruction, Op, Terminator, build,
};

const REGISTERS: [RegisterInfo; 2] = [
    RegisterInfo {
        name: "sp",
        width: 64,
    },
    RegisterInfo {
        name: "lr",
        width: 64,
    },
];

/// `hash` is a keyed hash of its inputs (its output cannot give them
/// back); `keep` may keep them.
const INTRINSICS: [IntrinsicInfo; 2] = [
    IntrinsicInfo {
        name: "hash",
        inputs: &[64, 64],
        outputs: &[64],
        escapes: false,
        stores: true,
        opaque: false,
    },
    IntrinsicInfo {
        name: "keep",
        inputs: &[64, 64],
        outputs: &[64],
        escapes: true,
        stores: true,
        opaque: false,
    },
];
const DECLARATIONS: Declarations = Declarations {
    registers: &REGISTERS,
    intrinsics: &INTRINSICS,
    sites: &[],
};
const SP: View = View {
    register: RegisterId(0),
    offset: 0,
    width: 64,
};
const LR: View = View {
    register: RegisterId(1),
    offset: 0,
    width: 64,
};

/// A call changes nothing but memory (and returns).
struct Calls;

impl Environment for Calls {
    fn call(&self, _: u64, _: Option<u64>) -> CallEffect {
        CallEffect {
            returns: true,
            ..CallEffect::default()
        }
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

/// No memory is known.
struct Nothing;

impl ReadOnly for Nothing {
    fn read(&self, _: u64, _: u16) -> Option<Bits> {
        None
    }
}

fn instruction(address: u64, body: impl FnOnce(&mut Builder)) -> Instruction {
    let mut b = Builder::new();
    body(&mut b);
    Instruction {
        address,
        next: address + 1,
        semantics: b.finish().unwrap(),
    }
}

/// `lr = intrinsic(lr, sp)` (as `paciasp`), `sp -= 16`, `[sp + 8] = lr`, a
/// call, then `lr = [sp + 8]` and a return.
fn function(intrinsic: IntrinsicId) -> Function {
    let code = Code {
        entry: 0x10,
        blocks: vec![
            vec![
                instruction(0x10, |b| {
                    let lr = b.read(LR);
                    let sp = b.read(SP);
                    let signed = b.intrinsic(intrinsic, &[lr, sp], &[64]);
                    b.write(LR, signed[0]);
                }),
                instruction(0x11, |b| {
                    let sp = b.read(SP);
                    let sixteen = b.constant(64, 16);
                    let sp = b.binary(Binary::Sub, sp, sixteen);
                    b.write(SP, sp);
                    let eight = b.constant(64, 8);
                    let slot = b.binary(Binary::Add, sp, eight);
                    let lr = b.read(LR);
                    b.store(slot, lr);
                }),
                instruction(0x12, |b| {
                    let target = b.constant(64, 0x100);
                    let back = b.constant(64, 0x13);
                    b.call(target, back);
                }),
            ],
            vec![
                instruction(0x13, |b| {
                    let sp = b.read(SP);
                    let eight = b.constant(64, 8);
                    let slot = b.binary(Binary::Add, sp, eight);
                    let lr = b.load(slot, 8);
                    b.write(LR, lr);
                }),
                instruction(0x14, |b| {
                    let lr = b.read(LR);
                    b.ret(lr);
                }),
            ],
        ],
    };
    build(&code, &DECLARATIONS, &Calls).unwrap()
}

/// Whether the load of the slot is forwarded from its store, and whether
/// the frame escapes.
fn analysed(intrinsic: IntrinsicId) -> (bool, bool) {
    let function = function(intrinsic);
    let constants = propagate(&function, &Nothing);
    let stack = Stack::new(&function, &DECLARATIONS, &constants, SP.register, &[]);
    let load = function
        .insts
        .iter()
        .find(|inst| matches!(inst.op, Op::Load { .. }))
        .unwrap();
    let loaded = load.results[0];
    (stack.resolve(&function, loaded) != loaded, stack.escaped())
}

#[test]
fn a_keyed_hash_of_the_stack_pointer_keeps_the_frame_private() {
    assert_eq!(analysed(IntrinsicId(0)), (true, false));
}

#[test]
fn an_intrinsic_that_may_keep_its_inputs_lets_the_stack_pointer_escape() {
    assert_eq!(analysed(IntrinsicId(1)), (false, true));
}

/// `if (sext(x[0..48]) != x) trap stack` (L0's canonical check, as `push`
/// makes it).
fn check(b: &mut Builder, x: binbun_semantics::ir::ExprId) {
    check_or(b, x, Trap::Stack);
}

/// `if (sext(x[0..48]) != x) trap` with `trap` (`#GP` for an access not
/// based on the stack pointer).
fn check_or(b: &mut Builder, x: binbun_semantics::ir::ExprId, trap: Trap) {
    let low = b.extract(x, 0, 48);
    let extended = b.sext(low, 64);
    let bad = b.binary(Binary::Ne, extended, x);
    b.begin_if(bad);
    b.trap(trap);
    b.end_if();
}

/// Checks of `sp - 8`, of `lr + 0x28` (no stack address; the thread
/// pointer plus a constant where `lr` is the thread pointer), of what is
/// loaded at `lr + 0x58` (an address read from the thread's block, no
/// constant offset from it) and of the return address at `[sp]`, which
/// the function returns to.
fn checks() -> Function {
    let code = Code {
        entry: 0x10,
        blocks: vec![vec![
            instruction(0x10, |b| {
                let sp = b.read(SP);
                let eight = b.constant(64, 8);
                let below = b.binary(Binary::Sub, sp, eight);
                check(b, below);
            }),
            instruction(0x11, |b| {
                let lr = b.read(LR);
                let offset = b.constant(64, 0x28);
                let field = b.binary(Binary::Add, lr, offset);
                check(b, field);
            }),
            instruction(0x12, |b| {
                let lr = b.read(LR);
                let offset = b.constant(64, 0x58);
                let field = b.binary(Binary::Add, lr, offset);
                let loaded = b.load(field, 8);
                check(b, loaded);
            }),
            instruction(0x13, |b| {
                let sp = b.read(SP);
                let back = b.load(sp, 8);
                check(b, back);
                b.ret(back);
            }),
        ]],
    };
    build(&code, &DECLARATIONS, &Calls).unwrap()
}

/// How many stack traps can still be reached after [`AssumeCanonical`]
/// with `return_slot` and `thread_pointer` (run by a verifying manager),
/// and how many branches it folded.
fn assumed(return_slot: Option<i64>, thread_pointer: Option<RegisterId>) -> (usize, usize) {
    let branches = |f: &Function| {
        f.blocks
            .iter()
            .filter(|block| matches!(block.terminator, Terminator::Branch { .. }))
            .count()
    };
    let mut f = checks();
    let before = branches(&f);
    let env = L1Env {
        declarations: &DECLARATIONS,
        memory: &Nothing,
        stack_pointer: SP.register,
        arguments: &[],
        return_slot,
        thread_pointer,
    };
    let mut manager = Manager::new(Fuel::new(1000)).with_verifier(verify);
    let changed = manager.run(&mut AssumeCanonical, &mut f, &env).unwrap();
    let folded = before - branches(&f);
    assert_eq!(changed, Changed::from(folded > 0));
    let reachable = Dominators::new(&f);
    let traps = f
        .blocks
        .iter()
        .enumerate()
        .filter(|&(index, block)| {
            reachable.reachable(BlockId(u32::try_from(index).unwrap()))
                && block.terminator == Terminator::Trap(Trap::Stack)
        })
        .count();
    (traps, folded)
}

#[test]
fn only_checks_of_the_stack_the_return_address_and_the_thread_block_are_assumed_canonical() {
    // Before: four checks, four reachable traps.
    assert_eq!(assumed(Some(0), None).0 + assumed(Some(0), None).1, 4);
    // The stack address and the caller's return address fold; `lr`'s
    // checks stay.
    assert_eq!(assumed(Some(0), None), (2, 2));
    // Without a return slot (the return address in a register), only the
    // stack address folds.
    assert_eq!(assumed(None, None), (3, 1));
    // With `lr` the thread pointer, `lr + 0x28` folds too, but not what is
    // loaded from the thread's block.
    assert_eq!(assumed(Some(0), Some(LR.register)), (1, 3));
}

/// The slot 0x5000 holds a fixed address (a fixed import's slot).
struct Slots;

impl ReadOnly for Slots {
    fn read(&self, _: u64, _: u16) -> Option<Bits> {
        None
    }

    fn fixed_address(&self, address: u64, bytes: u16) -> bool {
        address == 0x5000 && bytes == 8
    }
}

/// How many branches the pass `pass` (run by a verifying manager over
/// `memory`, no return slot or thread pointer) folds in `f`.
fn folds(
    pass: &mut dyn binbun_semantics::core::pass::Pass<Function, L1Env<'static>>,
    mut f: Function,
    memory: &'static dyn ReadOnly,
) -> usize {
    let branches = |f: &Function| {
        f.blocks
            .iter()
            .filter(|block| matches!(block.terminator, Terminator::Branch { .. }))
            .count()
    };
    let before = branches(&f);
    let env = L1Env {
        declarations: &DECLARATIONS,
        memory,
        stack_pointer: SP.register,
        arguments: &[],
        return_slot: None,
        thread_pointer: None,
    };
    let mut manager = Manager::new(Fuel::new(1000)).with_verifier(verify);
    manager.run(pass, &mut f, &env).unwrap();
    before - branches(&f)
}

#[test]
fn what_a_fixed_import_slot_holds_is_assumed_canonical_and_no_other_slot() {
    let loads = || {
        let code = Code {
            entry: 0x10,
            blocks: vec![vec![
                instruction(0x10, |b| {
                    let slot = b.constant(64, 0x5000);
                    let target = b.load(slot, 8);
                    check_or(b, target, Trap::Protection);
                }),
                instruction(0x11, |b| {
                    let slot = b.constant(64, 0x6000);
                    let target = b.load(slot, 8);
                    check_or(b, target, Trap::Protection);
                }),
                instruction(0x12, |b| {
                    let sp = b.read(SP);
                    let back = b.load(sp, 8);
                    b.ret(back);
                }),
            ]],
        };
        build(&code, &DECLARATIONS, &Calls).unwrap()
    };
    assert_eq!(folds(&mut AssumeCanonical, loads(), &Slots), 1);
    assert_eq!(folds(&mut AssumeCanonical, loads(), &Nothing), 0);
}

/// Checks of `lr + k`: guarding a load, a store and a return to it (which
/// fold under the reading view's assumption); followed by no access; by
/// an access only in the next instruction; by an access of another
/// address; and the program's own test of the same form, whose other way
/// does not trap (which do not fold).
fn guards() -> Function {
    let field = |b: &mut Builder, k: u64| {
        let lr = b.read(LR);
        let offset = b.constant(64, k);
        b.binary(Binary::Add, lr, offset)
    };
    let code = Code {
        entry: 0x10,
        blocks: vec![vec![
            instruction(0x10, |b| {
                let x = field(b, 0);
                check_or(b, x, Trap::Protection);
                b.load(x, 8);
            }),
            instruction(0x11, |b| {
                let x = field(b, 8);
                check_or(b, x, Trap::Protection);
                let zero = b.constant(64, 0);
                b.store(x, zero);
            }),
            instruction(0x12, |b| {
                let x = field(b, 16);
                check_or(b, x, Trap::Protection);
            }),
            instruction(0x13, |b| {
                let x = field(b, 24);
                check_or(b, x, Trap::Protection);
            }),
            instruction(0x14, |b| {
                let x = field(b, 24);
                b.load(x, 8);
            }),
            instruction(0x15, |b| {
                let x = field(b, 32);
                check_or(b, x, Trap::Protection);
                let sp = b.read(SP);
                b.load(sp, 8);
            }),
            instruction(0x16, |b| {
                let x = field(b, 40);
                let low = b.extract(x, 0, 48);
                let extended = b.sext(low, 64);
                let tagged = b.binary(Binary::Ne, extended, x);
                b.begin_if(tagged);
                let zero = b.constant(64, 0);
                b.store(x, zero);
                b.end_if();
                b.load(x, 8);
            }),
            instruction(0x17, |b| {
                let x = field(b, 48);
                check_or(b, x, Trap::Protection);
                b.ret(x);
            }),
        ]],
    };
    build(&code, &DECLARATIONS, &Calls).unwrap()
}

#[test]
fn the_reading_view_assumes_only_checks_that_guard_an_access() {
    // The exact assumption folds none of these (no stack address).
    assert_eq!(folds(&mut AssumeCanonical, guards(), &Nothing), 0);
    let mut pass = AssumeDereferenced::default();
    assert_eq!(folds(&mut pass, guards(), &Nothing), 3);
    assert_eq!(pass.folded().len(), 3);
}

/// As [`Calls`], but a computed jump leaves the function (recovery found
/// no table for it).
struct Leaving;

impl Environment for Leaving {
    fn call(&self, site: u64, target: Option<u64>) -> CallEffect {
        Calls.call(site, target)
    }
    fn system_call(&self, site: u64) -> CallEffect {
        Calls.system_call(site)
    }
    fn jump_targets(&self, _: u64) -> Vec<u64> {
        Vec::new()
    }
    fn jump_returns(&self, _: u64) -> bool {
        true
    }
    fn jump_leaves(&self, _: u64) -> Option<bool> {
        Some(true)
    }
}

/// `before(b)`, then a jump to the pointer loaded from 0x6000: a jump
/// through a function pointer; how [`TailJumps`] with the return address
/// at `[sp]` (`link` `None`) or in `lr`, and callees keeping `kept`,
/// leaves it: `(tail calls, unresolved)`.
fn tail_jump(
    link: Option<RegisterId>,
    kept: &[RegisterId],
    before: impl FnOnce(&mut Builder),
) -> (usize, usize) {
    let code = Code {
        entry: 0x10,
        blocks: vec![vec![
            instruction(0x10, before),
            instruction(0x11, |b| {
                let slot = b.constant(64, 0x6000);
                let target = b.load(slot, 8);
                b.jump(target);
            }),
        ]],
    };
    let mut f = build(&code, &DECLARATIONS, &Leaving).unwrap();
    let env = L1Env {
        declarations: &DECLARATIONS,
        memory: &Nothing,
        stack_pointer: SP.register,
        arguments: &[],
        return_slot: link.is_none().then_some(0),
        thread_pointer: None,
    };
    let mut manager = Manager::new(Fuel::new(1000)).with_verifier(verify);
    let mut pass = TailJumps::new(link, kept.to_vec());
    manager.run(&mut pass, &mut f, &env).unwrap();
    let leaves = f
        .blocks
        .iter()
        .filter(|block| matches!(block.terminator, Terminator::Leave { .. }))
        .count();
    let unresolved = f
        .blocks
        .iter()
        .filter(|block| matches!(&block.terminator, Terminator::IndirectJump { targets, .. } if targets.is_empty()))
        .count();
    assert_eq!(pass.counts(), (leaves, unresolved));
    (leaves, unresolved)
}

#[test]
fn a_jump_through_a_pointer_is_a_tail_call_only_as_the_abi_makes_one() {
    // The stack at its entry height, the return address untouched: a
    // tail call, whether the return address is on the stack or in `lr`.
    assert_eq!(tail_jump(None, &[], |_| {}), (1, 0));
    assert_eq!(tail_jump(Some(LR.register), &[], |_| {}), (1, 0));
    // The frame still up: a jump within code no convention describes.
    let frame_up = |b: &mut Builder| {
        let sp = b.read(SP);
        let sixteen = b.constant(64, 16);
        let below = b.binary(Binary::Sub, sp, sixteen);
        b.write(SP, below);
    };
    assert_eq!(tail_jump(None, &[], frame_up), (0, 1));
    // The return address overwritten, on the stack or in `lr`.
    let overwritten = |b: &mut Builder| {
        let sp = b.read(SP);
        let zero = b.constant(64, 0);
        b.store(sp, zero);
    };
    assert_eq!(tail_jump(None, &[], overwritten), (0, 1));
    let changed = |b: &mut Builder| {
        let zero = b.constant(64, 0);
        b.write(LR, zero);
    };
    assert_eq!(tail_jump(Some(LR.register), &[], changed), (0, 1));
    // A change of `lr` says nothing where the return address is on the
    // stack, unless callees keep `lr`: then the code jumped to would hand
    // the caller a changed register.
    assert_eq!(tail_jump(None, &[], changed), (1, 0));
    assert_eq!(tail_jump(None, &[LR.register], changed), (0, 1));
    // Saved and restored through the frame, it is kept.
    let saved = |b: &mut Builder| {
        let sp = b.read(SP);
        let eight = b.constant(64, 8);
        let slot = b.binary(Binary::Sub, sp, eight);
        let lr = b.read(LR);
        b.store(slot, lr);
        let zero = b.constant(64, 0);
        b.write(LR, zero);
        let back = b.load(slot, 8);
        b.write(LR, back);
    };
    assert_eq!(tail_jump(None, &[LR.register], saved), (1, 0));
    // Saved, and restored on one path only: where the paths meet, `lr`
    // holds its entry value either way.
    let restored_on_one_path = |b: &mut Builder| {
        let sp = b.read(SP);
        let eight = b.constant(64, 8);
        let slot = b.binary(Binary::Sub, sp, eight);
        let lr = b.read(LR);
        b.store(slot, lr);
        let flag = b.constant(64, 0x7008);
        let flag = b.load(flag, 8);
        let zero = b.constant(64, 0);
        let taken = b.binary(Binary::Ne, flag, zero);
        b.begin_if(taken);
        b.write(LR, zero);
        let back = b.load(slot, 8);
        b.write(LR, back);
        b.end_if();
    };
    assert_eq!(
        tail_jump(None, &[LR.register], restored_on_one_path),
        (1, 0)
    );
    // Not restored on that path: the paths meet with `lr` changed.
    let changed_on_one_path = |b: &mut Builder| {
        let flag = b.constant(64, 0x7008);
        let flag = b.load(flag, 8);
        let zero = b.constant(64, 0);
        let taken = b.binary(Binary::Ne, flag, zero);
        b.begin_if(taken);
        b.write(LR, zero);
        b.end_if();
    };
    assert_eq!(tail_jump(None, &[LR.register], changed_on_one_path), (0, 1));
    // The frame escapes (another slot's address is stored), and a store
    // goes to an address not known: the save slot, no object's, is still
    // the save, so `lr` reads its entry value back.
    let escaped = |overwrite: bool| {
        move |b: &mut Builder| {
            let sp = b.read(SP);
            let eight = b.constant(64, 8);
            let slot = b.binary(Binary::Sub, sp, eight);
            let lr = b.read(LR);
            b.store(slot, lr);
            let thirty_two = b.constant(64, 32);
            let local = b.binary(Binary::Sub, sp, thirty_two);
            let global = b.constant(64, 0x7000);
            b.store(global, local);
            let pointer = b.load(global, 8);
            let zero = b.constant(64, 0);
            b.store(pointer, zero);
            if overwrite {
                // The function's own store of something else to the slot.
                b.store(slot, zero);
            }
            b.write(LR, zero);
            let back = b.load(slot, 8);
            b.write(LR, back);
        }
    };
    assert_eq!(tail_jump(None, &[LR.register], escaped(false)), (1, 0));
    assert_eq!(tail_jump(None, &[LR.register], escaped(true)), (0, 1));
}
