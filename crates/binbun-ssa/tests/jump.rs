//! Jump tables whose index only its width bounds (no guard), on functions
//! built from small L0 programs.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_semantics::bits::Bits;
use binbun_semantics::build::Builder;
use binbun_semantics::ir::{Binary, Declarations, ExprId, RegisterId, RegisterInfo, Unary, View};
use binbun_ssa::constant::{ReadOnly, propagate};
use binbun_ssa::jump::{self, Bound, Facts, Table};
use binbun_ssa::stack::Stack;
use binbun_ssa::{
    BlockId, CallEffect, Code, Environment, Function, Instruction, Terminator, build,
};

const REGISTERS: [RegisterInfo; 2] = [
    RegisterInfo {
        name: "sp",
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
const SP: RegisterId = RegisterId(0);
const B: View = View {
    register: RegisterId(1),
    offset: 0,
    width: 64,
};

/// Where the table starts.
const TABLE: u64 = 0x2000;

/// Nothing calls anything; no jump is known.
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

/// Four 8-byte entries at [`TABLE`] (0x100, 0x200, 0x300, 0x400); no
/// other memory is known.
struct Four;

impl ReadOnly for Four {
    fn read(&self, address: u64, bytes: u16) -> Option<Bits> {
        let index = address.checked_sub(TABLE)? / 8;
        (bytes == 8 && address.is_multiple_of(8) && index < 4)
            .then(|| Bits::from_u64(64, (index + 1) * 0x100))
    }
}

/// A function at 0x10 of one instruction: reads a byte at `b`, makes
/// the index of an 8-byte table at [`TABLE`] from it with `index`, and
/// jumps to the entry.
fn switch(index: impl FnOnce(&mut Builder, ExprId) -> ExprId) -> Function {
    let mut b = Builder::new();
    let at = b.read(B);
    let byte = b.load(at, 1);
    let wide = b.zext(byte, 64);
    let index = index(&mut b, wide);
    let eight = b.constant(64, 8);
    let offset = b.binary(Binary::Mul, index, eight);
    let table = b.constant(64, TABLE);
    let entry = b.binary(Binary::Add, table, offset);
    let target = b.load(entry, 8);
    b.jump(target);
    let code = Code {
        entry: 0x10,
        blocks: vec![vec![Instruction {
            address: 0x10,
            next: 0x11,
            semantics: b.finish().unwrap(),
        }]],
    };
    build(&code, &DECLARATIONS, &Nothing).unwrap()
}

fn table(function: &Function) -> Option<Table> {
    let constants = propagate(function, &Four);
    let stack = Stack::new(function, &DECLARATIONS, &constants, SP, &[]);
    let block = function
        .blocks
        .iter()
        .position(|b| matches!(b.terminator, Terminator::IndirectJump { .. }))
        .unwrap();
    let facts = Facts {
        function,
        constants: &constants,
        stack: &stack,
    };
    jump::targets(facts, &Four, BlockId(u32::try_from(block).unwrap()), 4096)
}

/// A byte zero-extended bounds the index to 0..=255; the entries are read
/// in index order until memory is not known, each with where it was read.
#[test]
fn a_zero_extended_byte_bounds_the_index_by_its_width() {
    let found = table(&switch(|_, wide| wide)).unwrap();
    assert_eq!(found.bound, Bound::Width);
    let entries: Vec<(u64, Vec<u64>)> = found
        .entries
        .into_iter()
        .map(|e| (e.target, e.reads))
        .collect();
    assert_eq!(
        entries,
        [
            (0x100, vec![TABLE]),
            (0x200, vec![TABLE + 8]),
            (0x300, vec![TABLE + 16]),
            (0x400, vec![TABLE + 24]),
        ]
    );
}

/// The index is the byte put through something other than indexing
/// arithmetic (its negation reads the table backwards): the byte's width
/// says nothing about where the entries are, so nothing is known.
#[test]
fn a_byte_put_through_other_operations_bounds_nothing() {
    assert_eq!(table(&switch(|b, wide| b.unary(Unary::Neg, wide))), None);
}
