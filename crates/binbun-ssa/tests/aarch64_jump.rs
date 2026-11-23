//! Jump tables in AArch64 code, as GCC and Clang compile switches: the
//! instructions lifted by `binbun-aarch64-lift`, built into L1, and the
//! table found by [`jump::targets`]: byte, halfword and word offset tables
//! bounded by the unsigned guards `b.hi`, `b.ls` and `b.hs` (the flags of a
//! `cmp` as AArch64 sets them), one bounded only by its index's width, and
//! none for a signed guard.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_aarch64::decode;
use binbun_aarch64_lift::registers::SP;
use binbun_aarch64_lift::{AARCH64, lift};
use binbun_semantics::bits::Bits;
use binbun_ssa::constant::{ReadOnly, propagate};
use binbun_ssa::jump::{self, Bound, Table};
use binbun_ssa::stack::Stack;
use binbun_ssa::{BlockId, CallEffect, Code, Environment, Instruction, Terminator, build};

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

/// Read-only memory at 0x2000: the tables (byte offsets at 0x2000,
/// halfwords at 0x2010, words at 0x2020, bytes at 0x2030), zeros up to
/// 0x2200.
struct Tables(Vec<u8>);

const DATA: u64 = 0x2000;

impl Tables {
    fn new() -> Self {
        let mut bytes = vec![0; 0x200];
        bytes[..4].copy_from_slice(&[0, 2, 1, 3]);
        for (i, half) in [1u16, 0, 3, 5, 7].into_iter().enumerate() {
            bytes[0x10 + 2 * i..0x12 + 2 * i].copy_from_slice(&half.to_le_bytes());
        }
        // Offsets from the table (0x2020) to 0x109c, 0x1094, 0x1098.
        for (i, target) in [0x109c_i64, 0x1094, 0x1098].into_iter().enumerate() {
            let offset = i32::try_from(target - 0x2020).unwrap();
            bytes[0x20 + 4 * i..0x24 + 4 * i].copy_from_slice(&offset.to_le_bytes());
        }
        bytes[0x30..0x34].copy_from_slice(&[0, 2, 4, 2]);
        Self(bytes)
    }
}

impl ReadOnly for Tables {
    fn read(&self, address: u64, bytes: u16) -> Option<Bits> {
        let start = usize::try_from(address.checked_sub(DATA)?).ok()?;
        let read = self.0.get(start..start + usize::from(bytes))?;
        let mut value = [0u8; 8];
        value.get_mut(..read.len())?.copy_from_slice(read);
        Some(Bits::from_u64(bytes * 8, u64::from_le_bytes(value)))
    }
}

/// The table of the function at the first address of `blocks`, whose
/// blocks are given as their instructions' addresses and words.
fn table(blocks: &[&[(u64, u32)]]) -> Option<Table> {
    let code = Code {
        entry: blocks[0][0].0,
        blocks: blocks
            .iter()
            .map(|block| {
                block
                    .iter()
                    .map(|&(address, word)| Instruction {
                        address,
                        next: address + 4,
                        semantics: lift(&decode(word).unwrap(), address).unwrap(),
                    })
                    .collect()
            })
            .collect(),
    };
    let function = build(&code, &AARCH64, &Nothing).unwrap();
    let memory = Tables::new();
    let constants = propagate(&function, &memory);
    let stack = Stack::new(&function, &AARCH64, &constants, SP, &[]);
    let block = function
        .blocks
        .iter()
        .position(|b| matches!(b.terminator, Terminator::IndirectJump { .. }))
        .unwrap();
    let facts = jump::Facts {
        function: &function,
        constants: &constants,
        stack: &stack,
    };
    jump::targets(facts, &memory, BlockId(u32::try_from(block).unwrap()), 4096)
}

fn targets(table: &Table) -> Vec<u64> {
    table.entries.iter().map(|entry| entry.target).collect()
}

/// The jump of a byte table, from `at` + 8: `adrp`+`add` (`add`, the low
/// bits) to the table, the byte at the index `w0`, added sign-extended and
/// times 4 to the base `adr` (`adr x3, at + 0x20`) gives.
const fn bytes(at: u64, add: u32) -> [(u64, u32); 6] {
    [
        (at + 0x8, 0xb000_0001),  // adrp x1, 0x2000
        (at + 0xc, add),          // add x1, x1, #lo
        (at + 0x10, 0x3860_4822), // ldrb w2, [x1, w0, uxtw]
        (at + 0x14, 0x1000_0063), // adr x3, at + 0x20
        (at + 0x18, 0x8b22_8862), // add x2, x3, w2, sxtb #2
        (at + 0x1c, 0xd61f_0040), // br x2
    ]
}

/// GCC: `cmp w0, #3; b.hi default`, then a byte table: the not-taken side
/// bounds the index to 0..=3.
#[test]
fn a_byte_table_guarded_by_b_hi() {
    let guard = [(0x1000, 0x7100_0c1f), (0x1004, 0x5400_0108)]; // cmp w0, #3; b.hi 0x1024
    let jump = bytes(0x1000, 0x9100_0021); // add x1, x1, #0
    let found = table(&[&guard, &jump, &[(0x1024, 0xd65f_03c0)]]).unwrap();
    assert_eq!(found.bound, Bound::Guard);
    assert_eq!(targets(&found), [0x1020, 0x1028, 0x1024, 0x102c]);
    let reads: Vec<Vec<u64>> = found.entries.into_iter().map(|e| e.reads).collect();
    assert_eq!(reads, [[DATA], [DATA + 1], [DATA + 2], [DATA + 3]]);
}

/// Clang: `cmp w0, #4; b.ls table`, the jump on the taken side; a table
/// of halfwords at 0x2010, times 4 from `adr`'s base.
#[test]
fn a_halfword_table_guarded_by_b_ls() {
    let guard = [(0x1040, 0x7100_101f), (0x1044, 0x5400_0049)]; // cmp w0, #4; b.ls 0x104c
    let default = [(0x1048, 0xd65f_03c0)];
    let jump = [
        (0x104c, 0xb000_0008), // adrp x8, 0x2000
        (0x1050, 0x9100_4108), // add x8, x8, #0x10
        (0x1054, 0x1000_0089), // adr x9, 0x1064
        (0x1058, 0x7860_590a), // ldrh w10, [x8, w0, uxtw #1]
        (0x105c, 0x8b0a_0929), // add x9, x9, x10, lsl #2
        (0x1060, 0xd61f_0120), // br x9
    ];
    let found = table(&[&guard, &default, &jump]).unwrap();
    assert_eq!(found.bound, Bound::Guard);
    assert_eq!(targets(&found), [0x1068, 0x1064, 0x1070, 0x1078, 0x1080]);
}

/// `cmp w0, #3; b.hs default`; a table of words, offsets from the table
/// itself, sign-extended.
#[test]
fn a_word_table_relative_to_itself_guarded_by_b_hs() {
    let guard = [(0x1080, 0x7100_0c1f), (0x1084, 0x5400_00c2)]; // cmp w0, #3; b.hs 0x109c
    let jump = [
        (0x1088, 0xb000_0001), // adrp x1, 0x2000
        (0x108c, 0x9100_8021), // add x1, x1, #0x20
        (0x1090, 0xb8a0_5822), // ldrsw x2, [x1, w0, uxtw #2]
        (0x1094, 0x8b02_0021), // add x1, x1, x2
        (0x1098, 0xd61f_0020), // br x1
    ];
    let found = table(&[&guard, &jump, &[(0x109c, 0xd65f_03c0)]]).unwrap();
    assert_eq!(found.bound, Bound::Guard);
    assert_eq!(targets(&found), [0x109c, 0x1094, 0x1098]);
}

/// No guard: the index is a byte loaded (`ldrb w0, [x0]`), whose width
/// bounds it to 0..=255. The byte read from the table is not the index:
/// every entry is read from the table at 0x2030 + index.
#[test]
fn a_loaded_byte_bounds_a_table_by_its_width() {
    let mut code = vec![(0x10c0, 0x3940_0000)]; // ldrb w0, [x0]
    code.extend_from_slice(&bytes(0x10bc, 0x9100_c021)); // add x1, x1, #0x30
    let found = table(&[&code]).unwrap();
    assert_eq!(found.bound, Bound::Width);
    assert_eq!(found.entries.len(), 256);
    assert_eq!(
        targets(&found)[..5],
        [0x10dc, 0x10e4, 0x10ec, 0x10e4, 0x10dc]
    );
    for (index, entry) in (0u64..).zip(&found.entries) {
        assert_eq!(entry.reads, [DATA + 0x30 + index]);
    }
}

/// `cmp w0, #3; b.gt default` bounds the index only as a signed number
/// (negative indices pass), and the byte read from the table must not be
/// taken for a narrow index: no table.
#[test]
fn a_signed_guard_bounds_nothing() {
    let guard = [(0x1100, 0x7100_0c1f), (0x1104, 0x5400_010c)]; // cmp w0, #3; b.gt 0x1124
    let jump = bytes(0x1100, 0x9100_0021); // add x1, x1, #0
    assert_eq!(table(&[&guard, &jump, &[(0x1124, 0xd65f_03c0)]]), None);
}
