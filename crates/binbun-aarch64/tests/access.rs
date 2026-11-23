//! Operand access, memory accesses, implicit registers and condition flags
//! of representative instructions.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_aarch64::operand::{Register, RegisterClass};
use binbun_aarch64::{Access, FlagSet, Flags, Instruction, MemoryAccess, MemoryKind, decode};

use Access::{Read as R, ReadWrite as B, Write as W};

fn instruction(word: u32, text: &str) -> Instruction {
    let instruction = decode(word).unwrap();
    assert_eq!(instruction.display(0).to_string().replace('\t', " "), text);
    instruction
}

/// Checks the access of each operand of `word` (whose text is `text`).
fn assert_access(word: u32, text: &str, expected: &[Access]) {
    let instruction = instruction(word, text);
    assert_eq!(instruction.access().as_slice(), expected, "{text}");
    assert_eq!(instruction.operands().len(), expected.len(), "{text}");
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "compared with `Instruction::memory`"
)]
fn memory(kind: MemoryKind, size: u32) -> Option<MemoryAccess> {
    Some(MemoryAccess { kind, size })
}

fn x(number: u8) -> Register {
    Register::new(RegisterClass::X, number)
}

#[test]
fn destinations_are_written_and_kept_parts_read() {
    assert_access(0x8b02_0020, "add x0, x1, x2", &[W, R, R]);
    // The zero register as destination is still written.
    assert_access(0x8b02_003f, "add xzr, x1, x2", &[W, R, R]);
    // CMP (SUBS to xzr) reads its first operand.
    assert_access(0xf100_107f, "cmp x3, #0x4", &[R, R]);
    assert_access(0xf240_001f, "tst x0, #0x1", &[R, R]);
    // MOVK and BFI keep the bits they do not replace.
    assert_access(0xf2a0_0025, "movk x5, #0x1, lsl #16", &[B, R, R]);
    assert_access(0x331d_0ce6, "bfi w6, w7, #3, #4", &[B, R, R, R]);
    // Accumulators and hash state.
    assert_access(0x4ea8_94e6, "mla v6.4s, v7.4s, v8.4s", &[B, R, R]);
    assert_access(0x4e82_9420, "sdot v0.4s, v1.16b, v2.16b", &[B, R, R]);
    assert_access(0x4e28_4820, "aese v0.16b, v1.16b", &[B, R]);
    // XTN writes all of Vd; XTN2 its upper half only.
    assert_access(0x0e21_28a4, "xtn v4.8b, v5.8h", &[W, R]);
    assert_access(0x4e21_28a4, "xtn2 v4.16b, v5.8h", &[B, R]);
    // SVE ADR's vector address operand computes addresses only.
    let adr = instruction(0x04a2_a020, "adr z0.s, [z1.s, z2.s]");
    assert_eq!(adr.access().as_slice(), &[W, R]);
    assert_eq!(adr.memory(), None);
}

#[test]
fn predication_decides_whether_the_destination_is_read() {
    // Merging keeps inactive elements, zeroing does not.
    assert_access(0x0496_a020, "abs z0.s, p0/m, z1.s", &[B, R, R]);
    assert_access(0x0490_2462, "movprfx z2.s, p1/z, z3.s", &[W, R, R]);
    assert_access(0x0491_2462, "movprfx z2.s, p1/m, z3.s", &[B, R, R]);
    // A predicate-setting compare writes its predicate and the flags.
    let cmpeq = instruction(0x2404_a861, "cmpeq p1.b, p2/z, z3.b, z4.b");
    assert_eq!(cmpeq.access().as_slice(), &[W, R, R, R]);
    assert_eq!(cmpeq.flags().written, FlagSet::NZCV);
}

#[test]
fn loads_and_stores() {
    let ldr = instruction(0xf841_0528, "ldr x8, [x9], #0x10");
    assert_eq!(ldr.access().as_slice(), &[W, R]);
    assert_eq!(ldr.memory(), memory(MemoryKind::Load, 8));
    let stp = instruction(0xa9be_2fea, "stp x10, x11, [sp, #-0x20]!");
    assert_eq!(stp.access().as_slice(), &[R, R, W]);
    assert_eq!(stp.memory(), memory(MemoryKind::Store, 16));
    // Narrow and sign-extending loads access the narrow size.
    assert_eq!(
        instruction(0x3865_6883, "ldrb w3, [x4, x5]").memory(),
        memory(MemoryKind::Load, 1)
    );
    assert_eq!(
        instruction(0xb980_0041, "ldrsw x1, [x2]").memory(),
        memory(MemoryKind::Load, 4)
    );
    assert_eq!(
        instruction(0x5800_0040, "ldr x0, 0x8").memory(),
        memory(MemoryKind::Load, 8)
    );
    assert_eq!(
        instruction(0xad40_04c0, "ldp q0, q1, [x6]").memory(),
        memory(MemoryKind::Load, 32)
    );
    let prfm = instruction(0xf980_0160, "prfm pldl1keep, [x11]");
    assert_eq!(prfm.access().as_slice(), &[R, R]);
    assert_eq!(prfm.memory(), memory(MemoryKind::Prefetch, 0));
}

#[test]
fn structure_loads_size_and_partial_writes() {
    // A single-lane load keeps the other lanes.
    let lane = instruction(0x0d40_9000, "ld1 { v0.s }[1], [x0]");
    assert_eq!(lane.access().as_slice(), &[B, R]);
    assert_eq!(lane.memory(), memory(MemoryKind::Load, 4));
    let pair = instruction(0x4c40_a021, "ld1 { v1.16b, v2.16b }, [x1]");
    assert_eq!(pair.access().as_slice(), &[W, R]);
    assert_eq!(pair.memory(), memory(MemoryKind::Load, 32));
    // LD1R loads one element and replicates it.
    let replicate = instruction(0x4d40_c443, "ld1r { v3.8h }, [x2]");
    assert_eq!(replicate.memory(), memory(MemoryKind::Load, 2));
    // SVE sizes depend on the vector length.
    let ld1b = instruction(0xa400_ac87, "ld1b { z7.b }, p3/z, [x4]");
    assert_eq!(ld1b.access().as_slice(), &[W, R, R]);
    assert_eq!(ld1b.memory(), memory(MemoryKind::Load, 0));
}

#[test]
fn exclusives_and_atomics() {
    let ldxr = instruction(0x885f_7dac, "ldxr w12, [x13]");
    assert_eq!(ldxr.memory(), memory(MemoryKind::LoadExclusive, 4));
    // The status register of a store exclusive is written.
    let stxr = instruction(0xc80e_7e0f, "stxr w14, x15, [x16]");
    assert_eq!(stxr.access().as_slice(), &[W, R, W]);
    assert_eq!(stxr.memory(), memory(MemoryKind::StoreExclusive, 8));
    // CAS returns the old value in the compare register.
    let cas = instruction(0xc8b1_7e72, "cas x17, x18, [x19]");
    assert_eq!(cas.access().as_slice(), &[B, R, B]);
    assert_eq!(cas.memory(), memory(MemoryKind::Atomic, 8));
    let casp = instruction(0x4834_7f16, "casp x20, x21, x22, x23, [x24]");
    assert_eq!(casp.access().as_slice(), &[B, B, R, R, B]);
    assert_eq!(casp.memory(), memory(MemoryKind::Atomic, 16));
    let ldadd = instruction(0xb821_0062, "ldadd w1, w2, [x3]");
    assert_eq!(ldadd.access().as_slice(), &[R, W, B]);
    assert_eq!(ldadd.memory(), memory(MemoryKind::Atomic, 4));
    assert_access(0xb821_007f, "stadd w1, [x3]", &[R, B]);
    // LDG merges the tag into the address register.
    let ldg = instruction(0xd960_00e6, "ldg x6, [x7]");
    assert_eq!(ldg.access().as_slice(), &[B, R]);
    assert_eq!(ldg.memory(), memory(MemoryKind::LoadTag, 16));
    assert_eq!(
        instruction(0xd920_0928, "stg x8, [x9]").memory(),
        memory(MemoryKind::StoreTag, 16)
    );
}

#[test]
fn memory_copy_and_set() {
    let prologue = instruction(0x1d01_0440, "cpyp [x0]!, [x1]!, x2!");
    assert_eq!(prologue.access().as_slice(), &[W, R, B]);
    assert_eq!(prologue.memory(), memory(MemoryKind::Copy, 0));
    // The prologue chooses the algorithm and records it in the flags; the
    // main stage reads it back.
    assert_eq!(
        prologue.flags(),
        Flags {
            read: FlagSet::NONE,
            written: FlagSet::NZCV
        }
    );
    let main = instruction(0x1d41_0440, "cpym [x0]!, [x1]!, x2!");
    assert_eq!(main.flags().read, FlagSet::N | FlagSet::C);
    assert_eq!(main.flags().written, FlagSet::NONE);
    let setp = instruction(0x19c5_0483, "setp [x3]!, x4!, x5");
    assert_eq!(setp.access().as_slice(), &[W, B, R]);
    assert_eq!(setp.memory(), memory(MemoryKind::Store, 0));
}

#[test]
fn flags_follow_conditions_and_flag_setting_forms() {
    let flags = |word, text| instruction(word, text).flags();
    assert_eq!(
        flags(0x5400_0040, "b.eq 0x8"),
        Flags {
            read: FlagSet::Z,
            written: FlagSet::NONE
        }
    );
    assert_eq!(
        flags(0x9a82_8020, "csel x0, x1, x2, hi").read,
        FlagSet::C | FlagSet::Z
    );
    assert_eq!(
        flags(0x1e64_bc62, "fcsel d2, d3, d4, lt").read,
        FlagSet::N | FlagSet::V
    );
    assert_eq!(
        flags(0xba02_0020, "adcs x0, x1, x2"),
        Flags {
            read: FlagSet::C,
            written: FlagSet::NZCV
        }
    );
    // CCMP tests `ne` and sets all four flags.
    assert_eq!(
        flags(0xfa41_1804, "ccmp x0, #0x1, #0x4, ne"),
        Flags {
            read: FlagSet::Z,
            written: FlagSet::NZCV
        }
    );
    assert_eq!(flags(0x1e61_2000, "fcmp d0, d1").written, FlagSet::NZCV);
    // RMIF writes the flags its mask selects (#5: Z and V).
    assert_eq!(
        flags(0xba01_8405, "rmif x0, #0x3, #0x5").written,
        FlagSet::Z | FlagSet::V
    );
    assert_eq!(
        flags(0x3a00_082d, "setf8 w1").written,
        FlagSet::N | FlagSet::Z | FlagSet::V
    );
    assert_eq!(
        flags(0xd500_401f, "cfinv"),
        Flags {
            read: FlagSet::C,
            written: FlagSet::C
        }
    );
    // Only NZCV among the system registers carries the flags.
    assert_eq!(flags(0xd51b_4200, "msr NZCV, x0").written, FlagSet::NZCV);
    assert_eq!(flags(0xd53b_4201, "mrs x1, NZCV").read, FlagSet::NZCV);
    assert_eq!(flags(0xd53b_d049, "mrs x9, TPIDR_EL0"), Flags::NONE);
    assert_eq!(flags(0x8b02_0020, "add x0, x1, x2"), Flags::NONE);
}

#[test]
fn system_registers_and_operations() {
    assert_access(0xd51b_4200, "msr NZCV, x0", &[W, R]);
    assert_access(0xd53b_d049, "mrs x9, TPIDR_EL0", &[W, R]);
    assert_access(0xd50b_742a, "dc zva, x10", &[R, R]);
}

#[test]
fn implicit_registers() {
    let implicit = |word, text| instruction(word, text).implicit();
    assert_eq!(implicit(0x9400_0010, "bl 0x40").writes, &[x(30)]);
    assert_eq!(implicit(0xd63f_00e0, "blr x7").writes, &[x(30)]);
    // RET without an operand returns to x30; with one, it is the operand.
    assert_eq!(implicit(0xd65f_03c0, "ret").reads, &[x(30)]);
    assert_eq!(implicit(0xd65f_00a0, "ret x5").reads, []);
    let sp = Register::new(RegisterClass::Xsp, 31);
    let paciasp = implicit(0xd503_233f, "paciasp");
    assert_eq!(
        (paciasp.reads, paciasp.writes),
        (&[x(30), sp][..], &[x(30)][..])
    );
    // LD64B writes x(t+1)..x(t+7) besides its operand xt.
    let ld64b = instruction(0xf83f_d062, "ld64b x2, [x3]");
    assert_eq!(
        ld64b.implicit().writes,
        &(3..10).map(x).collect::<Vec<_>>()[..]
    );
    assert_eq!(ld64b.memory(), memory(MemoryKind::Load, 64));
    let st64bv = instruction(0xf820_b082, "st64bv x0, x2, [x4]");
    assert_eq!(st64bv.access().as_slice(), &[W, R, W]);
    assert_eq!(
        st64bv.implicit().reads,
        &(3..10).map(x).collect::<Vec<_>>()[..]
    );
    // First-fault loads update FFR.
    let ffr = Register::new(RegisterClass::Ffr, 0);
    let ldff1b = implicit(0xa406_70a8, "ldff1b { z8.b }, p4/z, [x5, x6]");
    assert_eq!((ldff1b.reads, ldff1b.writes), (&[ffr][..], &[ffr][..]));
}

#[test]
fn sme_array_and_tiles() {
    // Outer products accumulate into the tile.
    assert_access(
        0x8081_2000,
        "fmopa za0.s, p0/m, p1/m, z0.s, z1.s",
        &[B, R, R, R, R],
    );
    assert_access(0xc008_00ff, "zero {za}", &[W]);
    // Merging moves into and out of tile slices.
    assert_access(0xc080_0040, "mov za0h.s[w12, 0], p0/m, z2.s", &[B, R, R]);
    assert_access(0xc082_2423, "mov z3.s, p1/m, za0h.s[w13, 1]", &[B, R, R]);
    // ADD (array results) writes the sum; ADD (array accumulators) adds.
    assert_access(
        0xc122_1810,
        "add za.s[w8, 0, vgx2], { z0.s, z1.s }, z2.s",
        &[W, R, R],
    );
    assert_access(
        0xc1a0_1c10,
        "add za.s[w8, 0, vgx2], { z0.s, z1.s }",
        &[B, R],
    );
    let ldr = instruction(0xe11f_8000, "ldr zt0, [x0]");
    assert_eq!(ldr.access().as_slice(), &[W, R]);
    assert_eq!(ldr.memory(), memory(MemoryKind::Load, 64));
}
