//! Words to check: per instruction family with semantics, a base word
//! and, per field that changes the semantics, the values to try
//! (every value of small fields; edges of immediates: 0, 1, the largest,
//! the sign boundary, all ones; registers 0, a middle one, 31 for SP or the
//! zero register, and equal registers where overlap matters). The words are
//! the cross product; words that do not decode, or decode to an encoding
//! without semantics, are the caller's to skip.

/// A field: its lowest bit, its width and the values tried.
pub type Field = (u32, u32, &'static [u32]);

/// One family of encodings.
#[derive(Clone, Copy, Debug)]
pub struct Family {
    /// What it covers.
    pub name: &'static str,
    /// The word with every swept field 0.
    pub base: u32,
    /// The swept fields.
    pub fields: &'static [Field],
    /// Whether the result depends on the instruction's address (PC-relative
    /// forms), so it is checked at several.
    pub pc_relative: bool,
}

const REGISTER_PAIR: &[u32] = &[1, 31];
const DESTINATION: &[u32] = &[0, 31];
const SF: Field = (31, 1, &[0, 1]);

/// Every condition field value (B.cond, BC.cond, CSEL, CCMP) or CB<cc>
/// comparison.
const CONDITIONS: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// The families of the first dozen operations lifted (13 operations, 37
/// encodings), then those of the integer data-processing groups (`dpimm`,
/// `dpreg`), the base ISA's control and system instructions, and the
/// general-purpose loads and stores.
pub const FAMILIES: [Family; 65] = [
    Family {
        name: "ADD (shifted register)",
        base: 0x0b00_0000,
        fields: &[
            SF,
            (22, 2, &[0, 1, 2, 3]),
            (16, 5, &[0, 2, 31]),
            (10, 6, &[0, 1, 13, 31, 32, 63]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "SUBS (immediate)",
        base: 0x7100_0000,
        fields: &[
            SF,
            (22, 1, &[0, 1]),
            (10, 12, &[0, 1, 5, 0x7ff, 0x800, 0xfff]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "ORR (shifted register)",
        base: 0x2a00_0000,
        fields: &[
            SF,
            (22, 2, &[0, 1, 2, 3]),
            (16, 5, &[2, 31]),
            (10, 6, &[0, 1, 31, 32, 63]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDR/STR (immediate, unsigned offset)",
        base: 0xb900_0000,
        fields: &[
            (30, 2, &[2, 3]),
            (22, 2, &[0, 1]),
            (10, 12, &[0, 1, 0x800, 0xfff]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 1, 31]),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDR/STR (immediate, pre- and post-index)",
        base: 0xb800_0400,
        fields: &[
            (30, 2, &[2, 3]),
            (22, 2, &[0, 1]),
            (11, 1, &[0, 1]),
            (12, 9, &[0, 1, 8, 0xff, 0x100, 0x1f8, 0x1ff]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 1, 31]),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDP/STP (post-index, signed offset, pre-index)",
        base: 0x2800_0000,
        fields: &[
            (30, 2, &[0, 2]),
            (23, 2, &[1, 2, 3]),
            (22, 1, &[0, 1]),
            (15, 7, &[0, 1, 0x3f, 0x40, 0x7e, 0x7f]),
            (10, 5, &[1, 30, 31]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 1, 31]),
        ],
        pc_relative: false,
    },
    Family {
        name: "ADRP",
        base: 0x9000_0000,
        fields: &[
            (29, 2, &[0, 1, 2, 3]),
            (5, 19, &[0, 1, 0x3_ffff, 0x4_0000, 0x7_ffff]),
            (0, 5, DESTINATION),
        ],
        pc_relative: true,
    },
    Family {
        name: "B, BL",
        base: 0x1400_0000,
        fields: &[
            (31, 1, &[0, 1]),
            (0, 26, &[0, 1, 0x1ff_ffff, 0x200_0000, 0x3ff_ffff]),
        ],
        pc_relative: true,
    },
    Family {
        name: "B.cond",
        base: 0x5400_0000,
        fields: &[
            (5, 19, &[2, 0x3_ffff, 0x4_0000, 0x7_ffff]),
            (
                0,
                4,
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            ),
        ],
        pc_relative: true,
    },
    Family {
        name: "CBZ",
        base: 0x3400_0000,
        fields: &[
            SF,
            (5, 19, &[2, 0x3_ffff, 0x4_0000, 0x7_ffff]),
            (0, 5, &[0, 31]),
        ],
        pc_relative: true,
    },
    Family {
        name: "RET",
        base: 0xd65f_0000,
        fields: &[(5, 5, &[0, 1, 16, 17, 30, 31])],
        pc_relative: true,
    },
    Family {
        name: "ADD, ADDS, SUB, SUBS (immediate)",
        base: 0x1100_0000,
        fields: &[
            SF,
            (30, 1, &[0, 1]),
            (29, 1, &[0, 1]),
            (22, 1, &[0, 1]),
            (10, 12, &[0, 1, 0x7ff, 0x800, 0xfff]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "ADDS, SUB, SUBS (shifted register)",
        base: 0x0b00_0000,
        fields: &[
            SF,
            (30, 1, &[0, 1]),
            (29, 1, &[0, 1]),
            (22, 2, &[0, 1, 2, 3]),
            (16, 5, &[2, 31]),
            (10, 6, &[0, 1, 31, 63]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "ADD, ADDS, SUB, SUBS (extended register)",
        base: 0x0b20_0000,
        fields: &[
            SF,
            (30, 1, &[0, 1]),
            (29, 1, &[0, 1]),
            (16, 5, &[2]),
            (13, 3, &[0, 1, 2, 3, 4, 5, 6, 7]),
            (10, 3, &[0, 1, 4]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "ADC, ADCS, SBC, SBCS",
        base: 0x1a00_0000,
        fields: &[
            SF,
            (30, 1, &[0, 1]),
            (29, 1, &[0, 1]),
            (16, 5, &[2, 31]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "AND, ORR, EOR, ANDS (immediate)",
        base: 0x1200_0000,
        fields: &[
            SF,
            (29, 2, &[0, 1, 2, 3]),
            (22, 1, &[0, 1]),
            (16, 6, &[0, 1, 32, 63]),
            (10, 6, &[0, 1, 30, 31, 32, 62, 63]),
            (5, 5, &[1]),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "logical (shifted register)",
        base: 0x0a00_0000,
        fields: &[
            SF,
            (29, 2, &[0, 1, 2, 3]),
            (22, 2, &[0, 1, 2, 3]),
            (21, 1, &[0, 1]),
            (16, 5, &[2]),
            (10, 6, &[0, 1, 31, 63]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0]),
        ],
        pc_relative: false,
    },
    Family {
        name: "MOVN, MOVZ, MOVK",
        base: 0x1280_0000,
        fields: &[
            SF,
            (29, 2, &[0, 2, 3]),
            (21, 2, &[0, 1, 2, 3]),
            (5, 16, &[0, 1, 0x8000, 0xffff]),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "SBFM, BFM, UBFM",
        base: 0x1300_0000,
        fields: &[
            SF,
            (29, 2, &[0, 1, 2]),
            (22, 1, &[0, 1]),
            (16, 6, &[0, 1, 7, 31, 32, 63]),
            (10, 6, &[0, 1, 7, 15, 31, 32, 63]),
            (5, 5, &[1]),
            (0, 5, &[0, 1]),
        ],
        pc_relative: false,
    },
    Family {
        name: "EXTR",
        base: 0x1380_0000,
        fields: &[
            SF,
            (22, 1, &[0, 1]),
            (16, 5, &[1, 2]),
            (10, 6, &[0, 1, 31, 32, 63]),
            (5, 5, &[1]),
            (0, 5, &[0]),
        ],
        pc_relative: false,
    },
    Family {
        name: "ADR",
        base: 0x1000_0000,
        fields: &[
            (29, 2, &[0, 1, 2, 3]),
            (5, 19, &[0, 1, 0x3_ffff, 0x4_0000, 0x7_ffff]),
            (0, 5, DESTINATION),
        ],
        pc_relative: true,
    },
    Family {
        name: "CSEL, CSINC, CSINV, CSNEG",
        base: 0x1a80_0000,
        fields: &[
            SF,
            (30, 1, &[0, 1]),
            (10, 2, &[0, 1]),
            (12, 4, CONDITIONS),
            (16, 5, &[2, 31]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0]),
        ],
        pc_relative: false,
    },
    Family {
        name: "CCMN, CCMP (register)",
        base: 0x3a40_0000,
        fields: &[
            SF,
            (30, 1, &[0, 1]),
            (12, 4, CONDITIONS),
            (16, 5, &[2, 31]),
            (5, 5, &[1]),
            (0, 4, &[0, 5, 10, 15]),
        ],
        pc_relative: false,
    },
    Family {
        name: "CCMN, CCMP (immediate)",
        base: 0x3a40_0800,
        fields: &[
            SF,
            (30, 1, &[0, 1]),
            (12, 4, CONDITIONS),
            (16, 5, &[0, 1, 31]),
            (5, 5, &[1, 31]),
            (0, 4, &[0, 5, 15]),
        ],
        pc_relative: false,
    },
    Family {
        // RBIT, REV16, REV32/REV, REV, CLZ, CLS, CTZ, ABS. CNT (opcode 7)
        // is left out: Sail's `BitCount` takes isla past the 24 GB limit
        // (the CPU oracle checks it).
        name: "data processing (1 source)",
        base: 0x5ac0_0000,
        fields: &[
            SF,
            (10, 6, &[0, 1, 2, 3, 4, 5, 6, 8]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "data processing (2 source)",
        base: 0x1ac0_0000,
        fields: &[
            SF,
            // UDIV, SDIV, LSLV, LSRV, ASRV, RORV, CRC32B, CRC32CB, SMAX,
            // UMAX, SMIN, UMIN. CRC32H/W/X and CRC32CH/CW/CX are left out:
            // sail's `Poly32Mod2` branches on every data bit, 2^16 to 2^64
            // paths (the CPU oracle checks them).
            (10, 6, &[2, 3, 8, 9, 10, 11, 16, 20, 24, 25, 26, 27]),
            (16, 5, &[2, 31]),
            (5, 5, &[1]),
            (0, 5, &[0]),
        ],
        pc_relative: false,
    },
    Family {
        name: "data processing (3 source)",
        base: 0x1b00_0000,
        fields: &[
            SF,
            (21, 3, &[0, 1, 2, 5, 6]),
            (15, 1, &[0, 1]),
            (16, 5, &[2]),
            (10, 5, &[3, 31]),
            (5, 5, &[1]),
            (0, 5, &[0]),
        ],
        pc_relative: false,
    },
    Family {
        name: "SMAX, SMIN, UMAX, UMIN (immediate)",
        base: 0x11c0_0000,
        fields: &[
            SF,
            (18, 4, &[0, 1, 2, 3]),
            (10, 8, &[0, 1, 0x7f, 0x80, 0xff]),
            (5, 5, &[1]),
            (0, 5, &[0]),
        ],
        pc_relative: false,
    },
    Family {
        name: "RMIF",
        base: 0xba00_0400,
        fields: &[
            (15, 6, &[0, 1, 31, 63]),
            (
                0,
                4,
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            ),
            (5, 5, REGISTER_PAIR),
        ],
        pc_relative: false,
    },
    Family {
        name: "SETF8, SETF16",
        base: 0x3a00_080d,
        fields: &[(14, 1, &[0, 1]), (5, 5, REGISTER_PAIR)],
        pc_relative: false,
    },
    Family {
        name: "BR, BLR",
        base: 0xd61f_0000,
        fields: &[(21, 1, &[0, 1]), (5, 5, &[0, 16, 30, 31])],
        pc_relative: false,
    },
    Family {
        name: "TBZ, TBNZ",
        base: 0x3600_0000,
        fields: &[
            (31, 1, &[0, 1]),
            (24, 1, &[0, 1]),
            (19, 5, &[0, 31]),
            (5, 14, &[2, 0x2000]),
            (0, 5, &[0, 31]),
        ],
        pc_relative: true,
    },
    Family {
        name: "CBNZ",
        base: 0x3500_0000,
        fields: &[SF, (5, 19, &[2, 0x4_0000]), (0, 5, &[0, 31])],
        pc_relative: true,
    },
    Family {
        name: "BC.cond",
        base: 0x5400_0010,
        fields: &[(5, 19, &[2, 0x4_0000]), (0, 4, CONDITIONS)],
        pc_relative: true,
    },
    Family {
        name: "CB<cc> (register)",
        base: 0x7400_0000,
        fields: &[
            SF,
            (21, 3, &[0, 1, 2, 3, 4, 5, 6, 7]),
            (16, 5, &[1, 31]),
            (5, 9, &[2, 0x1ff]),
        ],
        pc_relative: true,
    },
    Family {
        name: "CBB<cc>, CBH<cc>",
        base: 0x7400_8000,
        fields: &[
            (14, 1, &[0, 1]),
            (21, 3, &[0, 1, 2, 3, 4, 5, 6, 7]),
            (16, 5, &[1, 31]),
            (5, 9, &[2]),
        ],
        pc_relative: true,
    },
    Family {
        name: "CB<cc> (immediate)",
        base: 0x7500_0000,
        fields: &[
            SF,
            (21, 3, &[0, 1, 2, 3, 4, 5, 6, 7]),
            (15, 6, &[0, 1, 63]),
            (5, 9, &[2]),
        ],
        pc_relative: true,
    },
    Family {
        name: "PAC*, AUT*, XPAC* (data processing)",
        base: 0xdac1_0000,
        fields: &[
            (
                10,
                6,
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
            ),
            (5, 5, &[1, 31]),
            (0, 5, &[0, 31]),
        ],
        pc_relative: false,
    },
    Family {
        // ESB (0x10) is left out: Sail's error synchronization (FEAT_RAS)
        // takes isla past the 16 GB limit in under a minute. The CPU oracle
        // checks it.
        name: "hints (NOP, WFE, PACIASP, BTI, CHKFEAT, ...)",
        base: 0xd503_201f,
        fields: &[(
            5,
            7,
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 0x11, 0x12, 0x13, 0x14, 0x16, 0x18, 0x19,
                0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x22, 0x24, 0x26, 0x28, 0x23, 0x7f,
            ],
        )],
        pc_relative: false,
    },
    Family {
        name: "BRAA, BLRAA, RETAA and their forms",
        base: 0xd61f_0800,
        fields: &[
            (24, 1, &[0, 1]),
            (21, 2, &[0, 1, 2]),
            (10, 1, &[0, 1]),
            (5, 5, &[1, 30, 31]),
            (0, 5, &[1, 31]),
        ],
        pc_relative: false,
    },
    Family {
        name: "SVC, BRK, HLT",
        base: 0xd400_0000,
        fields: &[(21, 3, &[0, 1, 2]), (5, 16, &[0, 0xffff]), (0, 2, &[0, 1])],
        pc_relative: false,
    },
    Family {
        name: "UDF",
        base: 0x0000_0000,
        fields: &[(0, 16, &[0, 0xffff])],
        pc_relative: false,
    },
    Family {
        name: "CLREX, DSB, DMB, ISB, SB",
        base: 0xd503_301f,
        fields: &[(5, 3, &[2, 4, 5, 6, 7]), (8, 4, &[0, 4, 5, 9, 11, 15])],
        pc_relative: false,
    },
    Family {
        name: "DSB (nXS)",
        base: 0xd503_323f,
        fields: &[(10, 2, &[0, 1, 2, 3])],
        pc_relative: false,
    },
    Family {
        name: "CFINV, XAFLAG, AXFLAG",
        base: 0xd500_401f,
        fields: &[(5, 3, &[0, 1, 2])],
        pc_relative: false,
    },
    Family {
        // TCO (op1 3, op2 4) is left out: FEAT_MTE is not in the context.
        name: "MSR (immediate)",
        base: 0xd500_401f,
        fields: &[
            (16, 3, &[0, 3]),
            (5, 3, &[1, 2, 3, 5, 6, 7]),
            (8, 4, &[0, 1, 15]),
        ],
        pc_relative: false,
    },
    Family {
        // NZCV, DAIF, DIT, SSBS, TPIDR_EL0, TPIDRRO_EL0, CTR_EL0,
        // DCZID_EL0, CNTFRQ_EL0, CNTPCT_EL0, SCTLR_EL1, PMCR_EL0. Not:
        // FPCR and FPSR (unmapped), TCO (no FEAT_MTE), the counters (the
        // count is the system's), and the ID registers (Linux emulates
        // their EL0 reads after the trap Sail takes).
        name: "MRS, MSR (register)",
        base: 0xd510_0000,
        fields: &[
            (21, 1, &[0, 1]),
            (
                5,
                15,
                &[
                    0x5a10, 0x5a11, 0x5a15, 0x5a16, 0x5e82, 0x5e83, 0x5801, 0x5807, 0x5f00, 0x5f01,
                    0x4080, 0x5ce0,
                ],
            ),
            (0, 5, &[0, 31]),
        ],
        pc_relative: false,
    },
    Family {
        // DC ZVA, CVAC, CVAU, CVAP, CVADP, CIVAC, IC IVAU; TLBI VMALLE1,
        // IC IALLU, DC IVAC (not EL0's).
        name: "SYS",
        base: 0xd508_0001,
        fields: &[(
            5,
            14,
            &[
                0x1ba1, 0x1bd1, 0x1bd9, 0x1be1, 0x1be9, 0x1bf1, 0x1ba9, 0x0438, 0x03a8, 0x03b1,
            ],
        )],
        pc_relative: false,
    },
    // Loads and stores: sizes, opc (store, load, sign-extending to 64 or
    // 32 bits, PRFM), immediates' edges, SP and the zero register, and a
    // transfer register equal to the base where writeback overlaps.
    Family {
        name: "LDR/STR B/H/SB/SH/SW, PRFM (immediate, unsigned offset)",
        base: 0x3900_0000,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (22, 2, &[0, 1, 2, 3]),
            (10, 12, &[0, 1, 0xfff]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDR/STR all sizes (immediate, pre- and post-index)",
        base: 0x3800_0400,
        fields: &[
            (30, 2, &[0, 1, 2]),
            (22, 2, &[0, 1, 2, 3]),
            (11, 1, &[0, 1]),
            (12, 9, &[1, 0x1ff]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 1, 31]),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDUR/STUR, PRFUM, LDTR/STTR (unscaled, unprivileged)",
        base: 0x3800_0000,
        fields: &[
            (10, 2, &[0, 2]),
            (30, 2, &[0, 1, 2, 3]),
            (22, 2, &[0, 1, 2, 3]),
            (12, 9, &[1, 0x1ff]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDR/STR, PRFM, RPRFM (register offset)",
        base: 0x3820_0800,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (22, 2, &[0, 1, 2, 3]),
            (16, 5, &[2, 31]),
            (13, 3, &[2, 3, 6, 7]),
            (12, 1, &[0, 1]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 0x18]),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDR, LDRSW, PRFM (literal)",
        base: 0x1800_0000,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (5, 19, &[0, 1, 0x3_ffff, 0x4_0000, 0x7_ffff]),
            (0, 5, DESTINATION),
        ],
        pc_relative: true,
    },
    Family {
        name: "LDNP/STNP",
        base: 0x2800_0000,
        fields: &[
            (30, 2, &[0, 2]),
            (22, 1, &[0, 1]),
            (15, 7, &[0, 1, 0x40, 0x7f]),
            (10, 5, &[1, 31]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDPSW (post-index, signed offset, pre-index)",
        base: 0x6840_0000,
        fields: &[
            (23, 2, &[1, 2, 3]),
            (15, 7, &[0, 1, 0x40, 0x7f]),
            (10, 5, &[1, 31]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDAR/STLR, LDLAR/STLLR",
        base: 0x089f_7c00,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (22, 1, &[0, 1]),
            (15, 1, &[0, 1]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 1, 31]),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDXR/STXR, LDAXR/STLXR",
        base: 0x081f_7c00,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (22, 1, &[0, 1]),
            (15, 1, &[0, 1]),
            (16, 5, &[2, 31]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 2, 31]),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDXP/STXP, LDAXP/STLXP",
        base: 0x8820_0000,
        fields: &[
            (30, 1, &[0, 1]),
            (22, 1, &[0, 1]),
            (15, 1, &[0, 1]),
            (16, 5, &[3, 31]),
            (10, 5, &[2, 31]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0]),
        ],
        pc_relative: false,
    },
    // The ordering bits are invisible to the check (intrinsics without
    // outputs); the operations, sizes and register overlaps are not.
    Family {
        name: "LDADD, LDCLR, LDEOR, LDSET, LD{S,U}{MAX,MIN} (and ST<op>)",
        base: 0x3820_0000,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (23, 1, &[0, 1]),
            (22, 1, &[1]),
            (12, 3, &[0, 1, 2, 3, 4, 5, 6, 7]),
            (16, 5, &[2]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "SWP",
        base: 0x3820_8000,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (23, 1, &[0, 1]),
            (22, 1, &[0, 1]),
            (16, 5, &[2]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 2, 31]),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDAPR (and B/H)",
        base: 0x38bf_c000,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "CAS (and B/H)",
        base: 0x08a0_7c00,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (22, 1, &[0, 1]),
            (15, 1, &[0]),
            (16, 5, &[0, 2, 31]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 2, 31]),
        ],
        pc_relative: false,
    },
    Family {
        name: "CASP",
        base: 0x0820_7c00,
        fields: &[
            (30, 1, &[0, 1]),
            (22, 1, &[0, 1]),
            (15, 1, &[0]),
            (16, 5, &[0, 2, 30]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 4, 30]),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDAPUR/STLUR (and B/H/SB/SH/SW)",
        base: 0x1900_0000,
        fields: &[
            (30, 2, &[0, 1, 2, 3]),
            (22, 2, &[0, 1, 2, 3]),
            (12, 9, &[0, 1, 0xf, 0x1ff]),
            (5, 5, REGISTER_PAIR),
            (0, 5, DESTINATION),
        ],
        pc_relative: false,
    },
    Family {
        name: "LDAPR/STLR (writeback)",
        base: 0x9980_0800,
        fields: &[
            (30, 1, &[0, 1]),
            (22, 1, &[0, 1]),
            (5, 5, REGISTER_PAIR),
            (0, 5, &[0, 1, 31]),
        ],
        pc_relative: false,
    },
];

/// The words of `family`: its base with every combination of the fields'
/// values.
pub fn words(family: &Family) -> Vec<u32> {
    let mut words = vec![family.base];
    for &(low, width, values) in family.fields {
        let mask = u32::MAX >> (32 - width.clamp(1, 32));
        words = words
            .iter()
            .flat_map(|&word| {
                values
                    .iter()
                    .map(move |&value| (word & !(mask << low)) | ((value & mask) << low))
            })
            .collect();
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_the_cross_product_of_the_fields() {
        let family = Family {
            name: "test",
            base: 0xf000_0000,
            fields: &[(0, 2, &[1, 3]), (4, 1, &[0, 1])],
            pc_relative: false,
        };
        assert_eq!(
            words(&family),
            [0xf000_0001, 0xf000_0011, 0xf000_0003, 0xf000_0013]
        );
        // Values are cut to the field.
        let wide = Family {
            fields: &[(0, 2, &[7])],
            ..family
        };
        assert_eq!(words(&wide), [0xf000_0003]);
    }
}
