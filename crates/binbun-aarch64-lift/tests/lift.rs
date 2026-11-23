//! The lifted instructions run in the L0 interpreter on edge values and
//! compared with Arm's pseudocode written out here (`AddWithCarry`,
//! `ShiftReg`, `ExtendReg`, `ConditionHolds`, `MemAtomic`, the addressing
//! modes, and the operand rules of the integer groups: a condition operand,
//! an omitted zero register, flags an immediate selects); every sampled
//! word of the covered encodings lifts, verifies and round-trips through
//! the text form.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::BTreeMap;

use binbun_aarch64::decode;
use binbun_aarch64_lift::registers::{AARCH64, BTYPE, C, N, SP, V, Z, x};
use binbun_aarch64_lift::{LiftError, lift};
use binbun_semantics::Bits;
use binbun_semantics::interpret::{Fault, Machine, Outcome, Value, run};
use binbun_semantics::ir::{IntrinsicId, RegisterId, Stmt, Trap};
use binbun_semantics::text::{parse, print};
use binbun_semantics::verify::verify;
use xtask::aarchmrs::Package;

/// Where the instructions are lifted.
const ADDRESS: u64 = 0x0000_7f12_3456_7000;

/// Arm's AARCHMRS package, for the encodings' fixed bits.
const PACKAGE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../third_party/aarchmrs/AARCHMRS_OPENSOURCE_A_profile_FAT-2026-09.tar.gz"
);

/// Registers, and memory as Linux's EL0 sees it: addresses translated with
/// their top byte ignored (cleared where bit 55 is clear), the upper
/// (kernel) half faulting, every other byte not written yet a hash of its
/// address.
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    registers: Vec<u128>,
    memory: BTreeMap<u64, u8>,
    /// The exclusive monitor: the block a load exclusive marked (address,
    /// bytes), cleared by any store exclusive.
    monitor: Option<(u64, u64)>,
}

fn initial(address: u64) -> u8 {
    let mixed = (address ^ 0x9e37_79b9_7f4a_7c15).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    (mixed >> 56).to_le_bytes()[0]
}

/// The physical address of `address` (translation is the identity but for
/// top-byte-ignore), or `None` in the kernel half.
fn translate(address: u64) -> Option<u64> {
    if address >> 55 & 1 == 1 {
        None
    } else {
        Some(address & 0x00ff_ffff_ffff_ffff)
    }
}

impl State {
    fn new() -> Self {
        let registers = AARCH64
            .registers
            .iter()
            .enumerate()
            .map(|(i, info)| {
                let value = 0x1111_1111_1111_1111_u128.wrapping_mul(i as u128 + 1);
                if info.width == 128 {
                    value
                } else {
                    value & ((1 << info.width) - 1)
                }
            })
            .collect();
        Self {
            registers,
            memory: BTreeMap::new(),
            monitor: None,
        }
    }

    fn get(&self, id: RegisterId) -> u64 {
        u64::try_from(self.registers[usize::from(id.0)]).unwrap()
    }

    fn set(&mut self, id: RegisterId, value: u64) {
        self.registers[usize::from(id.0)] = u128::from(value);
    }

    fn byte(&self, address: u64) -> u8 {
        self.memory
            .get(&address)
            .copied()
            .unwrap_or_else(|| initial(address))
    }

    fn read(&self, address: u64, bytes: u64) -> u64 {
        (0..bytes).rev().fold(0, |value, i| {
            (value << 8) | u64::from(self.byte(address.wrapping_add(i)))
        })
    }

    fn write(&mut self, address: u64, bytes: u64, value: u64) {
        for i in 0..bytes {
            self.memory.insert(
                address.wrapping_add(i),
                value.to_le_bytes()[usize::try_from(i).unwrap()],
            );
        }
    }
}

impl Machine for State {
    fn read(&mut self, register: RegisterId) -> Value {
        let width = AARCH64.info(register).unwrap().width;
        Value::defined(Bits::from_u128(
            width,
            self.registers[usize::from(register.0)],
        ))
    }

    fn write(&mut self, register: RegisterId, value: Value) {
        let bits = value.known().expect("the dozen write defined values");
        self.registers[usize::from(register.0)] = bits.low_u128();
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        let Some(physical) = translate(address) else {
            return Err(Fault {
                address,
                write: false,
            });
        };
        let bytes: Vec<u8> = (0..u64::from(bytes))
            .map(|i| self.byte(physical.wrapping_add(i)))
            .collect();
        Ok(Value::defined(Bits::from_le_bytes(
            u16::try_from(bytes.len() * 8).unwrap(),
            &bytes,
        )))
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        let Some(physical) = translate(address) else {
            return Err(Fault {
                address,
                write: true,
            });
        };
        let bits = value.known().expect("stores of defined values");
        for (i, byte) in bits.to_le_bytes().enumerate() {
            self.memory.insert(physical.wrapping_add(i as u64), byte);
        }
        Ok(())
    }

    /// A local exclusive monitor: a store exclusive passes if it is the
    /// block the last load exclusive marked.
    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[Value],
        _outputs: &[u16],
    ) -> Vec<Value> {
        let name = AARCH64.intrinsic(intrinsic).unwrap().name;
        let input = |i: usize| inputs[i].known().unwrap().low_u64();
        match name {
            "exclusive_load" => {
                self.monitor = Some((input(0), input(1)));
                Vec::new()
            }
            "exclusive_store" => {
                let passes = self.monitor.take() == Some((input(0), input(1)));
                vec![Value::defined(Bits::from_bool(!passes))]
            }
            _ => Vec::new(),
        }
    }
}

/// Lifts `word` at [`ADDRESS`] and runs it on `state`.
fn execute(word: u32, state: &mut State) -> Outcome {
    let instruction = decode(word).unwrap_or_else(|e| panic!("{word:#010x}: {e:?}"));
    let semantics = lift(&instruction, ADDRESS).unwrap_or_else(|e| panic!("{word:#010x}: {e:?}"));
    verify(&semantics, &AARCH64).unwrap();
    run(&semantics, state)
}

/// Values at the edges of 32- and 64-bit arithmetic.
const EDGES: [u64; 12] = [
    0,
    1,
    2,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
    0x0123_4567_89ab_cdef,
];

fn mask(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

fn signed(value: u64, bits: u32) -> i128 {
    let value = i128::from(value & mask(bits));
    if value >> (bits - 1) == 1 {
        value - (1 << bits)
    } else {
        value
    }
}

/// Arm's `AddWithCarry`: the result and N, Z, C, V.
fn add_with_carry(first: u64, second: u64, carry: bool, bits: u32) -> (u64, [bool; 4]) {
    let unsigned =
        u128::from(first & mask(bits)) + u128::from(second & mask(bits)) + u128::from(carry);
    let total = signed(first, bits) + signed(second, bits) + i128::from(carry);
    let result = u64::try_from(unsigned & u128::from(mask(bits))).unwrap();
    let negative = result >> (bits - 1) == 1;
    let zero = result == 0;
    let carry_out = u128::from(result) != unsigned;
    let overflow = signed(result, bits) != total;
    (result, [negative, zero, carry_out, overflow])
}

/// Arm's `ShiftReg` for shift type `kind` (LSL, LSR, ASR, ROR).
fn shift_reg(value: u64, kind: u32, amount: u32, bits: u32) -> u64 {
    let value = value & mask(bits);
    let result = match kind {
        0 => value << amount,
        1 => value >> amount,
        2 => u64::try_from((signed(value, bits) >> amount) & i128::from(mask(bits))).unwrap(),
        _ if amount == 0 => value,
        _ => (value >> amount) | (value << (bits - amount)),
    };
    result & mask(bits)
}

fn flags(state: &State) -> [bool; 4] {
    [N, Z, C, V].map(|id| state.get(id) == 1)
}

fn set_flags(state: &mut State, nzcv: u64) {
    for (i, id) in [N, Z, C, V].into_iter().enumerate() {
        state.set(id, (nzcv >> (3 - i)) & 1);
    }
}

#[test]
fn subs_immediate_is_add_with_carry_of_the_complement() {
    let immediates = [(0, 0), (1, 0), (0xfff, 0), (1, 1), (0xfff, 1)];
    for sf in [0, 1] {
        let bits = if sf == 1 { 64 } else { 32 };
        for &a in &EDGES {
            for (imm12, shift) in immediates {
                // subs x3, x5, #imm12{, lsl #12}
                let word = (sf << 31) | 0x7100_0000 | (shift << 22) | (imm12 << 10) | (5 << 5) | 3;
                let mut state = State::new();
                state.set(x(5), a);
                state.set(x(3), 0xdead_beef_dead_beef);
                let mut expected = state.clone();
                let operand = u64::from(imm12) << (12 * shift);
                let (result, nzcv) = add_with_carry(a, !operand, true, bits);
                expected.set(x(3), result);
                for (id, flag) in [N, Z, C, V].into_iter().zip(nzcv) {
                    expected.set(id, u64::from(flag));
                }
                expected.set(BTYPE, 0);
                assert_eq!(execute(word, &mut state), Outcome::Next, "{word:#010x}");
                assert_eq!(state, expected, "{word:#010x} on {a:#x}");
            }
        }
    }
}

#[test]
fn compare_discards_the_result_and_subs_reads_the_stack_pointer() {
    // cmp x1, #0x5 (subs xzr, x1, #0x5): only the flags change.
    let mut state = State::new();
    state.set(x(1), 5);
    let mut expected = state.clone();
    set_flags(&mut expected, 0b0110);
    expected.set(BTYPE, 0);
    assert_eq!(execute(0xf100_143f, &mut state), Outcome::Next);
    assert_eq!(state, expected);
    // subs w3, wsp, #0x1: register 31 as the first source is the stack
    // pointer, the 32-bit result zero-extended.
    let mut state = State::new();
    state.set(SP, 0xffff_0000_0000_0000);
    execute(0x7100_07e3, &mut state);
    assert_eq!(state.get(x(3)), 0xffff_ffff);
    assert_eq!(flags(&state), [true, false, false, false]);
}

#[test]
fn add_and_orr_shift_their_last_operand() {
    for sf in [0u32, 1] {
        let bits = if sf == 1 { 64 } else { 32 };
        for kind in 0..4u32 {
            for amount in [0, 1, 7, bits - 1] {
                for &a in &EDGES {
                    for &b in &EDGES {
                        // add/orr x0, x1, x2, <shift> #amount (ADD has no
                        // ROR).
                        let operands = (kind << 22) | (2 << 16) | (amount << 10) | (1 << 5);
                        let mut state = State::new();
                        state.set(x(1), a);
                        state.set(x(2), b);
                        state.set(BTYPE, 3);
                        let shifted = shift_reg(b, kind, amount, bits);
                        if kind != 3 {
                            let word = (sf << 31) | 0x0b00_0000 | operands;
                            let mut expected = state.clone();
                            let (sum, _) = add_with_carry(a, shifted, false, bits);
                            expected.set(x(0), sum);
                            expected.set(BTYPE, 0);
                            let mut run_state = state.clone();
                            execute(word, &mut run_state);
                            assert_eq!(run_state, expected, "{word:#010x} {a:#x} {b:#x}");
                        }
                        let word = (sf << 31) | 0x2a00_0000 | operands;
                        let mut expected = state.clone();
                        expected.set(x(0), (a & mask(bits)) | shifted);
                        expected.set(BTYPE, 0);
                        execute(word, &mut state);
                        assert_eq!(state, expected, "{word:#010x} {a:#x} {b:#x}");
                    }
                }
            }
        }
    }
}

#[test]
fn register_31_is_the_zero_register_for_add_and_orr() {
    // mov x0, x1 (orr x0, xzr, x1) and add x7, xzr, x2.
    let mut state = State::new();
    state.set(SP, 0x1234);
    execute(0xaa01_03e0, &mut state);
    assert_eq!(state.get(x(0)), state.get(x(1)));
    execute(0x8b02_03e7, &mut state);
    assert_eq!(state.get(x(7)), state.get(x(2)));
    // add xzr, x1, x2 writes nothing.
    let mut state = State::new();
    let before = state.clone();
    execute(0x8b02_003f, &mut state);
    assert_eq!(state.registers[..31], before.registers[..31]);
    assert_eq!(state.get(SP), before.get(SP));
}

/// Runs `word` (a memory access based on x1) with x1 = `base`.
fn memory_case(word: u32, base: u64, state: &mut State) -> Outcome {
    state.set(x(1), base);
    execute(word, state)
}

#[test]
fn loads_address_modes_and_writeback() {
    let base = 0x0000_5555_0000_1000;
    // (word, bytes, address loaded, base afterwards)
    let cases: [(u32, u64, u64, u64); 6] = [
        // ldr x0, [x1, #0x8]
        (0xf940_0420, 8, base + 8, base),
        // ldr w0, [x1, #0x4]
        (0xb940_0420, 4, base + 4, base),
        // ldr x0, [x1, #0x10]!
        (0xf841_0c20, 8, base + 16, base + 16),
        // ldr w0, [x1], #-0x4
        (0xb85f_c420, 4, base, base - 4),
        // ldr x0, [x1], #0xff
        (0xf84f_f420, 8, base, base + 0xff),
        // ldr x0, [x1, #-0x100]!
        (0xf850_0c20, 8, base - 0x100, base - 0x100),
    ];
    for (word, bytes, address, after) in cases {
        let mut state = State::new();
        state.write(address, 8, 0x8877_6655_4433_2211);
        assert_eq!(memory_case(word, base, &mut state), Outcome::Next);
        let loaded = 0x8877_6655_4433_2211 & mask(u32::try_from(bytes * 8).unwrap());
        assert_eq!(state.get(x(0)), loaded, "{word:#010x}");
        assert_eq!(state.get(x(1)), after, "{word:#010x}");
    }
}

#[test]
fn stores_and_pairs() {
    let base = 0x0000_5555_0000_2000;
    // str w0, [x1, #0x8]: 4 bytes, the rest untouched.
    let mut state = State::new();
    state.set(x(0), 0xaabb_ccdd_1122_3344);
    memory_case(0xb900_0820, base, &mut state);
    assert_eq!(state.read(base + 8, 4), 0x1122_3344);
    assert_eq!(state.byte(base + 12), initial(base + 12));
    // stp x29, x30, [x1, #-0x10]!: x29 at the lower address.
    let mut state = State::new();
    state.set(x(29), 0x2929);
    state.set(x(30), 0x3030);
    assert_eq!(memory_case(0xa9bf_783d, base, &mut state), Outcome::Next);
    assert_eq!(state.read(base - 16, 8), 0x2929);
    assert_eq!(state.read(base - 8, 8), 0x3030);
    assert_eq!(state.get(x(1)), base - 16);
    // ldp x29, x30, [x1], #0x10 takes them back and restores the base.
    state.set(x(29), 0);
    state.set(x(30), 0);
    assert_eq!(execute(0xa8c1_783d, &mut state), Outcome::Next);
    assert_eq!((state.get(x(29)), state.get(x(30))), (0x2929, 0x3030));
    assert_eq!(state.get(x(1)), base);
    // ldp w2, w3, [x1, #0x8]: 32-bit halves, zero-extended.
    let mut state = State::new();
    state.write(base + 8, 8, 0x8000_0001_ffff_fffe);
    memory_case(0x2941_0c22, base, &mut state);
    assert_eq!(
        (state.get(x(2)), state.get(x(3))),
        (0xffff_fffe, 0x8000_0001)
    );
    // stp w2, w3, [x1], #-0x8
    let mut state = State::new();
    state.set(x(2), 0x1_0000_0002);
    state.set(x(3), 0x3);
    memory_case(0x28bf_0c22, base, &mut state);
    assert_eq!(state.read(base, 8), 0x3_0000_0002);
    assert_eq!(state.get(x(1)), base - 8);
}

#[test]
fn stack_pointer_bases_must_be_aligned() {
    // str x0, [sp, #0x8] and stp x29, x30, [sp, #-0x10]!: SP is checked
    // before the offset is added; a fault has no effect.
    for word in [0xf900_07e0, 0xa9bf_7bfd] {
        for (sp, aligned) in [
            (0x7ff0_0000_1000, true),
            (0x7ff0_0000_1008, false),
            (0x7ff0_0000_1001, false),
        ] {
            let mut state = State::new();
            state.set(SP, sp);
            let before = state.clone();
            let outcome = execute(word, &mut state);
            if aligned {
                assert_eq!(outcome, Outcome::Next, "{word:#010x} {sp:#x}");
            } else {
                assert_eq!(outcome, Outcome::Trap(Trap::Stack), "{word:#010x} {sp:#x}");
                assert_eq!(
                    state, before,
                    "{word:#010x}: effects of a faulting instruction"
                );
            }
        }
    }
    // An x register base is not checked.
    let mut state = State::new();
    assert_eq!(
        memory_case(0xf940_0420, 0x5555_0000_1003, &mut state),
        Outcome::Next
    );
}

#[test]
fn data_addresses_keep_their_tag_for_the_machine() {
    // ldr x0, [x1, #0x8]! with a tag in x1: the machine is asked for the
    // tagged address (which it translates), the writeback keeps the tag.
    let tagged = 0x5a00_5555_0000_1000;
    let mut state = State::new();
    state.write(0x5555_0000_1008, 8, 0x0102_0304_0506_0708);
    assert_eq!(memory_case(0xf840_8c20, tagged, &mut state), Outcome::Next);
    assert_eq!(state.get(x(0)), 0x0102_0304_0506_0708);
    assert_eq!(state.get(x(1)), tagged + 8);
    // The address the machine faults on is the tagged one.
    let mut state = State::new();
    let outcome = memory_case(0xf940_0420, 0x7f80_0000_0000_0000, &mut state);
    assert_eq!(
        outcome,
        Outcome::Fault(Fault {
            address: 0x7f80_0000_0000_0008,
            write: false
        })
    );
}

/// Arm's `ConditionHolds` for `cond` and flags `nzcv` (N = bit 3).
fn condition_holds(cond: u32, nzcv: u64) -> bool {
    let [n, z, c, v] = [3, 2, 1, 0].map(|bit| (nzcv >> bit) & 1 == 1);
    let result = match cond >> 1 {
        0 => z,
        1 => c,
        2 => n,
        3 => v,
        4 => c && !z,
        5 => n == v,
        6 => n == v && !z,
        _ => true,
    };
    if cond & 1 == 1 && cond != 15 {
        !result
    } else {
        result
    }
}

#[test]
fn conditional_branches_test_their_condition() {
    for cond in 0..16 {
        for nzcv in 0..16 {
            // b.<cond> .+0x40
            let word = 0x5400_0000 | (0x10 << 5) | cond;
            let mut state = State::new();
            set_flags(&mut state, nzcv);
            let expected = if condition_holds(cond, nzcv) {
                Outcome::Transfer(ADDRESS + 0x40)
            } else {
                Outcome::Next
            };
            assert_eq!(
                execute(word, &mut state),
                expected,
                "cond {cond} nzcv {nzcv:04b}"
            );
        }
    }
    // A backward target.
    let mut state = State::new();
    set_flags(&mut state, 0b0100);
    assert_eq!(
        execute(0x54ff_ffe0, &mut state),
        Outcome::Transfer(ADDRESS - 4)
    );
}

#[test]
fn compare_and_branch_tests_the_operand_width() {
    // cbz w0, .+0x8 and cbz x0, .+0x8
    for (word, value, taken) in [
        (0x3400_0040, 0x1_0000_0000, true),
        (0xb400_0040, 0x1_0000_0000, false),
        (0xb400_0040, 0, true),
        (0x3400_0040, 0x8000_0000, false),
    ] {
        let mut state = State::new();
        state.set(x(0), value);
        let expected = if taken {
            Outcome::Transfer(ADDRESS + 8)
        } else {
            Outcome::Next
        };
        assert_eq!(
            execute(word, &mut state),
            expected,
            "{word:#010x} {value:#x}"
        );
    }
}

#[test]
fn branches_calls_and_returns() {
    // b .-0x8000000 (the farthest back)
    let mut state = State::new();
    assert_eq!(
        execute(0x1600_0000, &mut state),
        Outcome::Transfer(ADDRESS - 0x800_0000)
    );
    // bl .+0x1000: x30 is the next instruction, btype 0.
    let mut state = State::new();
    state.set(BTYPE, 2);
    let mut expected = state.clone();
    expected.set(x(30), ADDRESS + 4);
    expected.set(BTYPE, 0);
    assert_eq!(
        execute(0x9400_0400, &mut state),
        Outcome::Transfer(ADDRESS + 0x1000)
    );
    assert_eq!(state, expected);
    // ret (x30) and ret x1: the target's top byte is ignored where bit 55
    // is clear, kept where it is set.
    for (word, register) in [(0xd65f_03c0, 30), (0xd65f_0020, 1)] {
        for (target, landed) in [
            (0x5a00_0003_0000_0000, 0x3_0000_0000),
            (0x28c9_c287_7fff_ffff, 0x28c9_c287_7fff_ffff),
            (0x0000_7f00_0000_1234, 0x0000_7f00_0000_1234),
        ] {
            let mut state = State::new();
            state.set(x(register), target);
            assert_eq!(
                execute(word, &mut state),
                Outcome::Transfer(landed),
                "{word:#010x}"
            );
        }
    }
    // BTYPE is written before the return, which ends the instruction for
    // L1.
    let semantics = lift(&decode(0xd65f_03c0).unwrap(), ADDRESS).unwrap();
    let btype = semantics
        .body
        .iter()
        .position(|stmt| matches!(stmt, Stmt::Write { view, .. } if view.register == BTYPE));
    let ret = semantics
        .body
        .iter()
        .position(|stmt| matches!(stmt, Stmt::Return { .. }));
    assert!(btype.unwrap() < ret.unwrap(), "{semantics:?}");
}

#[test]
fn adrp_computes_the_page() {
    // adrp x0, page + 0x1000 and adrp x7, page - 0x1_0000_0000 (the lowest
    // offset), from the page of the instruction (ADDRESS + 0x123 is not
    // a page start).
    for (word, offset) in [(0xb000_0000_u32, 0x1000_i64), (0x9080_0007, -0x1_0000_0000)] {
        let instruction = decode(word).unwrap();
        let semantics = lift(&instruction, ADDRESS + 0x124).unwrap();
        let mut state = State::new();
        assert_eq!(run(&semantics, &mut state), Outcome::Next);
        let register = word & 31;
        let page = (ADDRESS + 0x124) & !0xfff;
        assert_eq!(
            state.get(x(u8::try_from(register).unwrap())),
            page.wrapping_add_signed(offset),
            "{word:#010x}"
        );
    }
}

/// Arm's `ExtendReg` for the 3-bit `option` (UXTB..SXTX) and `amount`.
fn extend_reg(value: u64, option: u32, amount: u32, bits: u32) -> u64 {
    let size = (8 << (option & 3)).min(bits);
    let low = value & mask(size);
    let extended = if option & 4 == 0 {
        low
    } else {
        u64::try_from(signed(low, size) & i128::from(mask(bits))).unwrap()
    };
    (extended << amount) & mask(bits)
}

#[test]
fn extended_registers_are_extend_reg() {
    for sf in [0u32, 1] {
        let bits = if sf == 1 { 64 } else { 32 };
        for option in 0..8 {
            for amount in 0..5 {
                for &a in &EDGES {
                    for &b in &EDGES {
                        // add x0, x1, w2/x2, <extend> #amount (an X
                        // register for UXTX and SXTX).
                        let word = (sf << 31)
                            | 0x0b20_0000
                            | (2 << 16)
                            | (option << 13)
                            | (amount << 10)
                            | (1 << 5);
                        let mut state = State::new();
                        state.set(x(1), a);
                        state.set(x(2), b);
                        let (sum, _) =
                            add_with_carry(a, extend_reg(b, option, amount, bits), false, bits);
                        execute(word, &mut state);
                        assert_eq!(state.get(x(0)), sum, "{word:#010x} {a:#x} {b:#x}");
                    }
                }
            }
        }
    }
}

#[test]
fn movk_replaces_the_halfword_its_shift_names() {
    for sf in [0u32, 1] {
        let bits = if sf == 1 { 64 } else { 32 };
        for hw in 0..bits / 16 {
            // An immediate of 0 says nothing of the place: the field does.
            for imm16 in [0u64, 0xabcd] {
                let word =
                    (sf << 31) | 0x7280_0000 | (hw << 21) | (u32::try_from(imm16).unwrap() << 5);
                let mut state = State::new();
                state.set(x(0), u64::MAX);
                execute(word, &mut state);
                let place = 16 * hw;
                // The other bits keep their ones.
                let expected = (!(0xffff << place) | (imm16 << place)) & mask(bits);
                assert_eq!(state.get(x(0)), expected, "{word:#010x}");
            }
        }
    }
}

#[test]
fn selects_and_conditional_compares_test_their_condition() {
    for cond in 0..16 {
        for nzcv in 0..16 {
            let holds = condition_holds(cond, nzcv);
            // csinc x0, x1, x2, <cond>
            let mut state = State::new();
            set_flags(&mut state, nzcv);
            state.set(x(1), 10);
            state.set(x(2), 20);
            execute(0x9a82_0420 | (cond << 12), &mut state);
            assert_eq!(state.get(x(0)), if holds { 10 } else { 21 }, "cond {cond}");
            // ccmp x1, x2, #0b1010, <cond>: the flags of cmp x1, x2 where
            // the condition holds, else 0b1010.
            for (a, b) in [(5, 5), (3, 7), (0x8000_0000_0000_0000, 1)] {
                let mut state = State::new();
                set_flags(&mut state, nzcv);
                state.set(x(1), a);
                state.set(x(2), b);
                execute(0xfa42_002a | (cond << 12), &mut state);
                let expected = if holds {
                    add_with_carry(a, !b, true, 64).1
                } else {
                    [true, false, true, false]
                };
                assert_eq!(flags(&state), expected, "cond {cond} nzcv {nzcv:04b}");
            }
        }
    }
}

#[test]
fn rmif_writes_the_flags_its_mask_selects() {
    for mask_bits in 0..16u32 {
        for rotation in [0u32, 3, 63] {
            // rmif x1, #rotation, #mask
            let word = 0xba00_0420 | (rotation << 15) | mask_bits;
            let mut state = State::new();
            set_flags(&mut state, 0b0110);
            state.set(x(1), 0x0123_4567_89ab_cdef);
            execute(word, &mut state);
            let source = 0x0123_4567_89ab_cdef_u64.rotate_right(rotation);
            let expected: Vec<bool> = (0..4)
                .map(|i| {
                    let bit = 3 - i;
                    if mask_bits >> bit & 1 == 1 {
                        source >> bit & 1 == 1
                    } else {
                        0b0110 >> bit & 1 == 1
                    }
                })
                .collect();
            assert_eq!(flags(&state).to_vec(), expected, "{word:#010x}");
        }
    }
}

#[test]
fn irg_without_a_mask_register_reads_the_zero_register() {
    // irg x0, x1 (Rm = 31 is not written): every tag is excluded under the
    // execution context, so the tag is 0.
    let mut state = State::new();
    state.set(x(1), 0x0a00_7f00_1234_5678);
    assert_eq!(execute(0x9adf_1020, &mut state), Outcome::Next);
    assert_eq!(state.get(x(0)), 0x0000_7f00_1234_5678);
}

#[test]
fn covered_encodings_lift_verify_and_round_trip() {
    // Random words of every A64 encoding (its fixed bits from AARCHMRS, the
    // rest random): whatever decodes and has semantics lifts.
    let package = Package::read(PACKAGE).unwrap();
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut lifted = BTreeMap::new();
    let mut failures = Vec::new();
    for (_, encoding) in package.a64.encodings() {
        // Half the words with should-be bits as specified, half with them
        // free.
        let held = fixed_bits(encoding, true);
        let free = fixed_bits(encoding, false);
        for sample in 0..200 {
            let (mask, value) = if sample % 2 == 0 { held } else { free };
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let word = (u32::try_from(seed >> 32).unwrap() & !mask) | value;
            let Ok(instruction) = decode(word) else {
                continue;
            };
            match lift(&instruction, ADDRESS) {
                Ok(semantics) => {
                    *lifted.entry(instruction.encoding().name()).or_insert(0) += 1;
                    if let Err(error) = verify(&semantics, &AARCH64) {
                        failures.push(format!("{word:#010x}: does not verify: {error}"));
                    }
                    let text = print(&semantics, &AARCH64);
                    if parse(&text, &AARCH64).as_ref() != Ok(&semantics) {
                        failures.push(format!("{word:#010x}: text does not round-trip:\n{text}"));
                    }
                }
                Err(LiftError::Unsupported) => {}
                Err(error) => failures.push(format!("{word:#010x}: {error:?}")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(lifted.len(), COVERED, "{lifted:?}");
}

/// Encodings with semantics: the first dozen operations' 37, the integer
/// data-processing groups' 154, the control and system groups' 117 and the
/// general-purpose loads and stores' 314, the SIMD and floating-point
/// registers' loads and stores' 79 and their moves' 23 (`fmov`, `movi` and
/// vector `orr`), and scalar floating-point instructions' 192: arithmetic
/// (`fadd`, `fsub`, `fmul`, `fdiv`, `fnmul`, `fmadd`, `fmsub`, `fnmadd`,
/// `fnmsub`, `fabs`, `fneg`, `fsqrt`, `fmax`, `fmin`, `fmaxnm`,
/// `fminnm`), compares and selects (`fcmp`, `fcmpe`, `fccmp`, `fccmpe`,
/// `fcsel`) and conversions (`fcvt`, `frint` n, p, m, z, a, x, i, `scvtf`
/// and `ucvtf`, `fcvtzs` and `fcvtzu` to integers and fixed-point,
/// `fcvtns`, `fcvtnu`, `fcvtas`, `fcvtau`, `fcvtps`, `fcvtpu`, `fcvtms`,
/// `fcvtmu`).
const COVERED: usize = 916;

/// The bits every word of `encoding` has: mask and value. Should-be bits
/// are held at their specified values (other values are CONSTRAINED
/// UNPREDICTABLE, and most such words do not decode as the encoding) if
/// `should_be`, else left free.
fn fixed_bits(encoding: &xtask::aarchmrs::Instruction, should_be: bool) -> (u32, u32) {
    let (mut mask, mut value) = (0, 0);
    for field in &encoding.encoding.fields {
        let free = if should_be {
            0
        } else {
            field.should_be_mask.value()
        };
        mask |= u32::try_from((field.value.mask() & !free) << field.start).unwrap();
        value |= u32::try_from((field.value.value() & !free) << field.start).unwrap();
    }
    (mask, value)
}

/// The low `bits` of `value` zero- or sign-extended to `width` bits.
fn extended(value: u64, bits: u32, signed_: bool, width: u32) -> u64 {
    let value = if signed_ {
        i64::try_from(signed(value, bits)).unwrap().cast_unsigned()
    } else {
        value & mask(bits)
    };
    value & mask(width)
}

#[test]
fn loads_zero_and_sign_extend() {
    let base = 0x0000_5555_0000_3000_u64;
    // (word, bytes, offset, sign-extending, destination width)
    let cases: [(u32, u32, i64, bool, u32); 8] = [
        (0x3940_0420, 1, 1, false, 32), // ldrb w0, [x1, #1]
        (0x3980_0420, 1, 1, true, 64),  // ldrsb x0, [x1, #1]
        (0x39c0_0420, 1, 1, true, 32),  // ldrsb w0, [x1, #1]
        (0x7940_0420, 2, 2, false, 32), // ldrh w0, [x1, #2]
        (0x7980_0420, 2, 2, true, 64),  // ldrsh x0, [x1, #2]
        (0xb980_0420, 4, 4, true, 64),  // ldrsw x0, [x1, #4]
        (0x78df_f020, 2, -1, true, 32), // ldursh w0, [x1, #-1]
        (0xf840_8820, 8, 8, false, 64), // ldtr x0, [x1, #8]
    ];
    for (word, bytes, offset, signed_, width) in cases {
        for value in [0x0102_0304_0506_0708_u64, 0xf0e0_d0c0_b0a0_9080] {
            let mut state = State::new();
            let address = base.wrapping_add_signed(offset);
            state.write(address, 8, value);
            assert_eq!(memory_case(word, base, &mut state), Outcome::Next);
            let expected = extended(value, bytes * 8, signed_, width);
            assert_eq!(state.get(x(0)), expected, "{word:#010x} {value:#x}");
            assert_eq!(state.get(x(1)), base, "{word:#010x}");
        }
    }
}

#[test]
fn register_offsets_extend_and_shift() {
    let base = 0x0000_5555_0001_0000_u64;
    // (word, offset register values)
    let cases: [(u32, [u64; 2]); 4] = [
        // ldr x0, [x1, x2, lsl #3]
        (0xf862_7820, [5, u64::MAX]),
        // ldr w0, [x1, w2, sxtw #2]
        (0xb862_d820, [0xdead_beef_ffff_fffe, 0x1_0000_0003]),
        // ldrb w0, [x1, w2, uxtw]
        (0x3862_4820, [u64::MAX, 0x8000_0000]),
        // ldrh w0, [x1, x2, sxtx #1]
        (0x7862_f820, [u64::MAX - 7, 3]),
    ];
    for (word, offsets) in cases {
        let size = word >> 30;
        let option = (word >> 13) & 7;
        let shift = if (word >> 12) & 1 == 1 { size } else { 0 };
        for offset in offsets {
            let mut state = State::new();
            state.set(x(2), offset);
            // A register offset is `ExtendReg` to 64 bits.
            let address = base.wrapping_add(extend_reg(offset, option, shift, 64));
            state.write(address, 8, 0x8877_6655_4433_2211);
            assert_eq!(memory_case(word, base, &mut state), Outcome::Next);
            let loaded = 0x8877_6655_4433_2211 & mask(8 << size);
            assert_eq!(state.get(x(0)), loaded, "{word:#010x} {offset:#x}");
        }
    }
    // str x0, [x1, x2, sxtx]: 64-bit offset, unshifted.
    let mut state = State::new();
    state.set(x(0), 0x0123_4567_89ab_cdef);
    state.set(x(2), 16_u64.wrapping_neg());
    assert_eq!(memory_case(0xf822_e820, base, &mut state), Outcome::Next);
    assert_eq!(state.read(base - 16, 8), 0x0123_4567_89ab_cdef);
}

#[test]
fn literal_loads_read_at_the_label() {
    // ldr x0, #0x100 and ldrsw x0, #-0x8 (from the instruction's address).
    let mut state = State::new();
    state.write(ADDRESS + 0x100, 8, 0x8000_0000_0000_0001);
    assert_eq!(execute(0x5800_0800, &mut state), Outcome::Next);
    assert_eq!(state.get(x(0)), 0x8000_0000_0000_0001);
    state.write(ADDRESS - 8, 4, 0x8000_0002);
    assert_eq!(execute(0x98ff_ffc0, &mut state), Outcome::Next);
    assert_eq!(state.get(x(0)), 0xffff_ffff_8000_0002);
    // prfm pldl1keep, [x1] changes nothing, even through a faulting base.
    let mut state = State::new();
    state.set(x(1), 0xff00_0000_0000_0000);
    state.set(BTYPE, 0);
    let before = state.clone();
    assert_eq!(execute(0xf980_0020, &mut state), Outcome::Next);
    assert_eq!(state, before);
}

#[test]
fn ldpsw_sign_extends_each_word() {
    // ldpsw x2, x3, [x1, #8]
    let base = 0x0000_5555_0000_4000;
    let mut state = State::new();
    state.write(base + 8, 8, 0x8000_0001_7fff_fffe);
    assert_eq!(memory_case(0x6941_0c22, base, &mut state), Outcome::Next);
    assert_eq!(
        (state.get(x(2)), state.get(x(3))),
        (0x7fff_fffe, 0xffff_ffff_8000_0001)
    );
}

#[test]
fn a_load_into_its_base_suppresses_the_writeback() {
    // ldrsw x1, [x1], #4: CONSTRAINED UNPREDICTABLE (WBOVERLAPLD); binbun
    // keeps the loaded value (WBSUPPRESS).
    let base = 0x0000_5555_0000_5000;
    let mut state = State::new();
    state.write(base, 4, 0x8765_4321);
    assert_eq!(memory_case(0xb880_4421, base, &mut state), Outcome::Next);
    assert_eq!(state.get(x(1)), 0xffff_ffff_8765_4321);
}

#[test]
fn ordered_exclusive_and_atomic_accesses_stay_in_16_bytes() {
    // (word, bytes): ldar x0, [x1]; ldaxr x0, [x1]; ldadd x2, x0, [x1];
    // cas x0, x2, [x1]; stlr w0, [x1]; ldaxp x4, x5, [x1]; casp x4, x5,
    // x6, x7, [x1]; ldaddh w2, w0, [x1]; stxr w3, x2, [x1], whose monitor
    // fails (no load exclusive) after the alignment check.
    let cases: [(u32, u64); 9] = [
        (0xc8df_fc20, 8),
        (0xc85f_fc20, 8),
        (0xf822_0020, 8),
        (0xc8a0_7c22, 8),
        (0x889f_fc20, 4),
        (0xc87f_9424, 16),
        (0x4824_7c26, 16),
        (0x7822_0020, 2),
        (0xc803_7c22, 8),
    ];
    let base = 0x0000_5555_0000_6000;
    for (word, bytes) in cases {
        for offset in 0..16 {
            let mut state = State::new();
            state.set(x(1), base + offset);
            let before = state.clone();
            let outcome = execute(word, &mut state);
            if offset + bytes > 16 {
                assert_eq!(
                    outcome,
                    Outcome::Trap(Trap::Alignment),
                    "{word:#010x} +{offset}"
                );
                assert_eq!(
                    state, before,
                    "{word:#010x}: effects of a faulting instruction"
                );
            } else {
                assert_eq!(outcome, Outcome::Next, "{word:#010x} +{offset}");
            }
        }
    }
    // A plain load is never checked: ldur x0, [x1, #9].
    let mut state = State::new();
    assert_eq!(memory_case(0xf840_9020, base, &mut state), Outcome::Next);
}

#[test]
fn store_exclusive_stores_only_when_the_monitor_passes() {
    let base = 0x0000_5555_0000_7000;
    let mut state = State::new();
    state.set(x(1), base);
    state.set(x(2), 0x0123_4567_89ab_cdef);
    let original = state.read(base, 8);
    // stxr w3, x2, [x1] with no load exclusive: status 1, nothing stored.
    assert_eq!(execute(0xc803_7c22, &mut state), Outcome::Next);
    assert_eq!((state.get(x(3)), state.read(base, 8)), (1, original));
    // ldxr x0, [x1] marks the block; the store then happens, status 0.
    assert_eq!(execute(0xc85f_7c20, &mut state), Outcome::Next);
    assert_eq!(state.get(x(0)), original);
    assert_eq!(state.monitor, Some((base, 8)));
    assert_eq!(execute(0xc803_7c22, &mut state), Outcome::Next);
    assert_eq!(state.get(x(3)), 0);
    assert_eq!(state.read(base, 8), 0x0123_4567_89ab_cdef);
    // The monitor is cleared: a second store fails.
    state.set(x(2), 0);
    assert_eq!(execute(0xc803_7c22, &mut state), Outcome::Next);
    assert_eq!(
        (state.get(x(3)), state.read(base, 8)),
        (1, 0x0123_4567_89ab_cdef)
    );
    // ldaxp x4, x5, [x1]: one 16-byte block, x4 from the lower address.
    state.write(base, 8, 0x1111);
    state.write(base + 8, 8, 0x2222);
    assert_eq!(execute(0xc87f_9424, &mut state), Outcome::Next);
    assert_eq!((state.get(x(4)), state.get(x(5))), (0x1111, 0x2222));
    assert_eq!(state.monitor, Some((base, 16)));
}

/// Arm's `MemAtomic` operations by `opc`, on `bits`-bit values.
fn mem_atomic(opc: u32, old: u64, operand: u64, bits: u32) -> u64 {
    let (old, operand) = (old & mask(bits), operand & mask(bits));
    let (signed_old, signed_operand) = (signed(old, bits), signed(operand, bits));
    let new = match opc {
        0 => old.wrapping_add(operand),
        1 => old & !operand,
        2 => old ^ operand,
        3 => old | operand,
        4 => {
            if signed_old > signed_operand {
                old
            } else {
                operand
            }
        }
        5 => {
            if signed_old < signed_operand {
                old
            } else {
                operand
            }
        }
        6 => old.max(operand),
        _ => old.min(operand),
    };
    new & mask(bits)
}

#[test]
fn atomics_combine_the_old_value_with_the_operand() {
    let base = 0x0000_5555_0000_8000;
    // ld<op> x2, x0, [x1] (opc in bits 12..15) and ld<op>h w2, w0, [x1].
    for (template, bits) in [(0xf822_0020_u32, 64), (0x7822_0020, 16)] {
        for opc in 0..8 {
            let word = template | opc << 12;
            for old in EDGES {
                for operand in [0, 1, 0x8000, 0x8000_0000_0000_0000, u64::MAX] {
                    let mut state = State::new();
                    state.write(base, 8, old);
                    state.set(x(2), operand);
                    assert_eq!(memory_case(word, base, &mut state), Outcome::Next);
                    let new = mem_atomic(opc, old, operand, bits);
                    let label = format!("{word:#010x} {old:#x} {operand:#x}");
                    assert_eq!(state.get(x(0)), old & mask(bits), "{label}");
                    assert_eq!(state.read(base, u64::from(bits / 8)), new, "{label}");
                }
            }
        }
    }
    // stadd x2, [x1] (ldadd into the zero register) writes no register.
    let mut state = State::new();
    state.write(base, 8, 5);
    state.set(x(2), 3);
    let x0 = state.get(x(0));
    assert_eq!(memory_case(0xf822_003f, base, &mut state), Outcome::Next);
    assert_eq!((state.read(base, 8), state.get(x(0))), (8, x0));
    // swpb w2, w0, [x1]
    let mut state = State::new();
    state.write(base, 2, 0x1234);
    state.set(x(2), 0xffff_ffab);
    assert_eq!(memory_case(0x3822_8020, base, &mut state), Outcome::Next);
    assert_eq!((state.get(x(0)), state.read(base, 2)), (0x34, 0x12ab));
}

#[test]
fn compare_and_swap_writes_only_on_a_match() {
    let base = 0x0000_5555_0000_9000;
    // cas x0, x2, [x1]: x0 gets the old value either way.
    for (memory, expected, stored) in [(7, 7, 9), (8, 7, 8)] {
        let mut state = State::new();
        state.write(base, 8, memory);
        state.set(x(0), expected);
        state.set(x(2), 9);
        assert_eq!(memory_case(0xc8a0_7c22, base, &mut state), Outcome::Next);
        assert_eq!((state.get(x(0)), state.read(base, 8)), (memory, stored));
    }
    // casp x4, x5, x6, x7, [x1]: the pair x5:x4 against 16 bytes, x4 at
    // the lower address.
    for matches in [true, false] {
        let mut state = State::new();
        state.write(base, 8, 0x44);
        state.write(base + 8, 8, 0x55);
        state.set(x(4), 0x44);
        state.set(x(5), if matches { 0x55 } else { 0x56 });
        state.set(x(6), 0x66);
        state.set(x(7), 0x77);
        assert_eq!(memory_case(0x4824_7c26, base, &mut state), Outcome::Next);
        assert_eq!((state.get(x(4)), state.get(x(5))), (0x44, 0x55));
        let memory = (state.read(base, 8), state.read(base + 8, 8));
        assert_eq!(memory, if matches { (0x66, 0x77) } else { (0x44, 0x55) });
    }
}

/// The accesses, ordering intrinsics and atomic blocks of `body`, in order.
fn accesses(body: &[Stmt], names: &mut Vec<&'static str>) {
    for statement in body {
        match statement {
            Stmt::Load { .. } => names.push("load"),
            Stmt::Store { .. } => names.push("store"),
            Stmt::Intrinsic { intrinsic, .. } => {
                names.push(AARCH64.intrinsic(*intrinsic).unwrap().name);
            }
            Stmt::Atomic(inner) => {
                names.push("atomic");
                accesses(inner, names);
                names.push("end");
            }
            Stmt::If {
                then, otherwise, ..
            } => {
                accesses(then, names);
                accesses(otherwise, names);
            }
            Stmt::Loop(inner) => accesses(inner, names),
            Stmt::Read { .. }
            | Stmt::Write { .. }
            | Stmt::Break
            | Stmt::Trap(_)
            | Stmt::Jump { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::SystemCall => {}
        }
    }
}

#[test]
fn acquire_follows_and_release_precedes_the_access() {
    let cases: [(u32, &[&str]); 7] = [
        // ldar x0, [x1]; stlr w0, [x1]
        (0xc8df_fc20, &["load", "acquire"]),
        (0x889f_fc20, &["release", "store"]),
        // ldxr x0, [x1]; stlxr w3, x2, [x1]
        (0xc85f_7c20, &["load", "exclusive_load"]),
        (0xc803_fc22, &["release", "exclusive_store", "store"]),
        // ldaddal x2, x0, [x1]; stadd x2, [x1]; ldaddal x2, xzr, [x1]
        (
            0xf8e2_0020,
            &["atomic", "release", "load", "store", "acquire", "end"],
        ),
        (0xf822_003f, &["atomic", "load", "store", "end"]),
        (0xf8e2_003f, &["atomic", "release", "load", "store", "end"]),
    ];
    for (word, expected) in cases {
        let semantics = lift(&decode(word).unwrap(), ADDRESS).unwrap();
        let mut names = Vec::new();
        accesses(&semantics.body, &mut names);
        assert_eq!(names, expected, "{word:#010x}");
    }
}
