//! Decode-time UNDEFINED checks, written by hand.
//!
//! AARCHMRS gives each encoding's fixed bits and field conditions but not its
//! decode pseudocode (`decode` is null), so the checks that make some field
//! values UNDEFINED (`if shift == '11' then UNDEFINED;`) are missing. They are
//! restated here: each [`Constraint`] selects encodings and says, from the
//! values of named fields, when a word is rejected. The generator enumerates
//! the fields' values (holding the encoding's fixed bits), turns the rejected
//! ones into mask/value tests (or a bit table indexed by the fields when the
//! tests would be many, as for register overlaps) and compiles them into the
//! decoder (`checks.rs`).
//!
//! Two kinds of rejection:
//! - [`Kind::Undefined`]: the pseudocode says UNDEFINED.
//! - [`Kind::Unpredictable`]: the pseudocode says CONSTRAINED UNPREDICTABLE
//!   (should-be bits not as specified, overlapping registers) and LLVM
//!   rejects the word; binbun follows LLVM for validity. Where LLVM accepts
//!   such words (the should-be bits of `FCMP* #0.0` and `STXR`) they
//!   decode.
//!
//! Reserved values that AARCHMRS does encode (an arrangement missing from a
//! value-named `Choice`) are derived mechanically in `reserved.rs`; this
//! table holds the rest. Each entry's comment names the pseudocode check it
//! reflects (Arm ARM decode pseudocode). The entries were found by comparing
//! the decoder with LLVM 22 over every encoding, random words and real code
//! (`crates/binbun-aarch64/tests/oracle.rs`).

use Select::{AllExcept, Names, Suffixes};

/// Which encodings a [`Constraint`] applies to.
#[derive(Debug, Clone, Copy)]
pub enum Select {
    /// Encodings with these names.
    Names(&'static [&'static str]),
    /// Encodings whose name ends with one of these suffixes, e.g.
    /// `_addsub_shift` for every shifted-register add or subtract.
    Suffixes(&'static [&'static str]),
    /// Every encoding but these.
    AllExcept(&'static [&'static str]),
}

/// What a rejection means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// UNDEFINED in the decode pseudocode.
    Undefined,
    /// CONSTRAINED UNPREDICTABLE, rejected as LLVM rejects it.
    Unpredictable,
}

/// What a [`Constraint`] tests.
#[derive(Debug, Clone, Copy)]
pub enum Check {
    /// The values of `fields` (in order) make the word rejected when `when`
    /// holds.
    Fields {
        fields: &'static [&'static str],
        when: fn(&[u64]) -> bool,
    },
    /// The encoding's should-be bits do not have their specified values.
    ShouldBe,
}

/// One decode-time check.
#[derive(Debug, Clone, Copy)]
pub struct Constraint {
    pub kind: Kind,
    /// The encodings it applies to; each must have every field it reads.
    pub select: Select,
    pub check: Check,
}

impl Select {
    pub fn selects(&self, name: &str) -> bool {
        match self {
            Self::Names(names) => names.contains(&name),
            Self::Suffixes(suffixes) => suffixes.iter().any(|suffix| name.ends_with(suffix)),
            Self::AllExcept(names) => !names.contains(&name),
        }
    }
}

const fn undefined(
    select: Select,
    fields: &'static [&'static str],
    when: fn(&[u64]) -> bool,
) -> Constraint {
    Constraint {
        kind: Kind::Undefined,
        select,
        check: Check::Fields { fields, when },
    }
}

const fn unpredictable(
    select: Select,
    fields: &'static [&'static str],
    when: fn(&[u64]) -> bool,
) -> Constraint {
    Constraint {
        kind: Kind::Unpredictable,
        select,
        check: Check::Fields { fields, when },
    }
}

/// Bit `n` of `value`.
const fn bit(value: u64, n: u32) -> u64 {
    (value >> n) & 1
}

/// Whether `DecodeBitMasks(immN, imms, immr, TRUE)` is UNDEFINED:
/// `len = HighestSetBit(immN:NOT(imms))` below 1, or `imms` with all of the
/// element's `levels` bits set (a mask of all ones).
fn bit_masks_reserved(n: u64, imms: u64) -> bool {
    let combined = (n << 6) | (!imms & 0x3f);
    if combined < 2 {
        return true;
    }
    let len = combined.ilog2();
    let levels = (1 << len) - 1;
    imms & levels == levels
}

pub const CONSTRAINTS: &[Constraint] = &[
    // Should-be bits: "CONSTRAINED UNPREDICTABLE" when not as specified.
    // LLVM rejects them everywhere but in these encodings.
    Constraint {
        kind: Kind::Unpredictable,
        select: AllExcept(&[
            "FCMPE_DZ_floatcmp",
            "FCMPE_HZ_floatcmp",
            "FCMPE_SZ_floatcmp",
            "FCMP_DZ_floatcmp",
            "FCMP_HZ_floatcmp",
            "FCMP_SZ_floatcmp",
            "STLXRB_SR32_ldstexclr",
            "STLXRH_SR32_ldstexclr",
            "STLXR_SR32_ldstexclr",
            "STLXR_SR64_ldstexclr",
            "STXRB_SR32_ldstexclr",
            "STXRH_SR32_ldstexclr",
            "STXR_SR32_ldstexclr",
            "STXR_SR64_ldstexclr",
        ]),
        check: Check::ShouldBe,
    },
    // AddSubShiftedReg: if shift == '11' then UNDEFINED;
    undefined(Suffixes(&["_addsub_shift"]), &["shift"], |f| f[0] == 0b11),
    // AddSub/Logical shifted register: if sf == '0' && imm6<5> == '1' then UNDEFINED;
    undefined(
        Suffixes(&["_addsub_shift", "_log_shift"]),
        &["sf", "imm6"],
        |f| f[0] == 0 && bit(f[1], 5) == 1,
    ),
    // AddSubExtendedReg: if shift > 4 then UNDEFINED;  (shift = UInt(imm3))
    undefined(Suffixes(&["_addsub_ext"]), &["imm3"], |f| f[0] > 4),
    // Bitfield: if sf == '0' && (N != '0' || immr<5> != '0' || imms<5> != '0') then UNDEFINED;
    undefined(Suffixes(&["_32M_bitfield"]), &["immr", "imms"], |f| {
        bit(f[0], 5) == 1 || bit(f[1], 5) == 1
    }),
    // LogicalImmediate: DecodeBitMasks(N, imms, immr, TRUE) is UNDEFINED for a
    // reserved element size or an all-ones element.
    undefined(Suffixes(&["_log_imm"]), &["N", "imms"], |f| {
        bit_masks_reserved(f[0], f[1])
    }),
    // SVE bitwise immediate: DecodeBitMasks(imm13<12>, imm13<5:0>, imm13<11:6>, TRUE).
    undefined(
        Names(&["and_z_zi_", "dupm_z_i_", "eor_z_zi_", "orr_z_zi_"]),
        &["imm13"],
        |f| bit_masks_reserved(bit(f[0], 12), f[0] & 0x3f),
    ),
    // Load/store register offset: if option<1> == '0' then UNDEFINED; // sub-word index
    undefined(Suffixes(&["_ldst_regoff"]), &["option"], |f| {
        bit(f[0], 1) == 0
    }),
    // Float/fixed-point conversion: if sf == '0' && scale<5> == '0' then UNDEFINED;
    undefined(Suffixes(&["_float2fix"]), &["sf", "scale"], |f| {
        f[0] == 0 && bit(f[1], 5) == 0
    }),
    // CASP: if Rs<0> == '1' then UNDEFINED; if Rt<0> == '1' then UNDEFINED;
    undefined(
        Suffixes(&["_comswappr", "_rcwcomswappr", "_comswappr_unpriv"]),
        &["Rs", "Rt"],
        |f| bit(f[0], 0) == 1 || bit(f[1], 0) == 1,
    ),
    // MRRS/MSRR: if Rt<0> == '1' then UNDEFINED;
    undefined(
        Names(&["MRRS_RS_systemmovepr", "MSRR_SR_systemmovepr"]),
        &["Rt"],
        |f| bit(f[0], 0) == 1,
    ),
    // SYSP: if Rt<0> == '1' && Rt != '11111' then UNDEFINED;
    undefined(Names(&["SYSP_CR_syspairinstrs"]), &["Rt"], |f| {
        bit(f[0], 0) == 1 && f[0] != 0b11111
    }),
    // LD64B/ST64B*: if Rt<4:3> == '11' || Rt<0> == '1' then UNDEFINED;
    undefined(
        Names(&[
            "LD64B_64L_memop",
            "ST64B_64L_memop",
            "ST64BV_64_memop",
            "ST64BV0_64_memop",
            "LDA64B_64L_memop",
            "STL64B_64L_memop",
            "STL64BV_64_memop",
            "STL64BV0_64_memop",
        ]),
        &["Rt"],
        |f| f[0] >> 3 == 0b11 || bit(f[0], 0) == 1,
    ),
    // 128-bit atomics: if Rt == '11111' then UNDEFINED; if Rt2 == '11111' then UNDEFINED;
    undefined(Suffixes(&["_memop_128"]), &["Rt", "Rt2"], |f| {
        f[0] == 0b11111 || f[1] == 0b11111
    }),
    // CPYF*, CPY*, SET*: if sz != '00' then UNDEFINED;
    undefined(
        Suffixes(&["_CPY_memcms", "_SET_memcms", "_memset_go"]),
        &["sz"],
        |f| f[0] != 0,
    ),
    // CPYF*/CPY*: if s == n || s == d || n == d || d == 31 || s == 31 then
    // CONSTRAINED UNPREDICTABLE (MOPSOVERLAP31); LLVM also accepts n == 31.
    unpredictable(Suffixes(&["_CPY_memcms"]), &["Rd", "Rs", "Rn"], |f| {
        let (d, s, n) = (f[0], f[1], f[2]);
        s == n || s == d || n == d || d == 31 || s == 31
    }),
    // SET*: if s == n || s == d || n == d || d == 31 then CONSTRAINED UNPREDICTABLE;
    unpredictable(Suffixes(&["_SET_memcms"]), &["Rd", "Rs", "Rn"], |f| {
        let (d, s, n) = (f[0], f[1], f[2]);
        s == n || s == d || n == d || d == 31
    }),
    // SETGO*: if n == d || d == 31 then CONSTRAINED UNPREDICTABLE;
    unpredictable(Suffixes(&["_memset_go"]), &["Rd", "Rn"], |f| {
        f[0] == f[1] || f[0] == 31
    }),
    // Load pair, load exclusive pair: if memop == MemOp_LOAD && t == t2 then
    // CONSTRAINED UNPREDICTABLE (LDPOVERLAP);
    unpredictable(
        Names(&[
            "LDAXP_LP32_ldstexclp",
            "LDAXP_LP64_ldstexclp",
            "LDXP_LP32_ldstexclp",
            "LDXP_LP64_ldstexclp",
            "LDNP_32_ldstnapair_offs",
            "LDNP_64_ldstnapair_offs",
            "LDNP_D_ldstnapair_offs",
            "LDNP_Q_ldstnapair_offs",
            "LDNP_S_ldstnapair_offs",
            "LDTNP_64_ldstnapair_offs",
            "LDTNP_Q_ldstnapair_offs",
            "LDPSW_64_ldstpair_off",
            "LDPSW_64_ldstpair_post",
            "LDPSW_64_ldstpair_pre",
            "LDP_32_ldstpair_off",
            "LDP_32_ldstpair_post",
            "LDP_32_ldstpair_pre",
            "LDP_64_ldstpair_off",
            "LDP_64_ldstpair_post",
            "LDP_64_ldstpair_pre",
            "LDP_D_ldstpair_off",
            "LDP_D_ldstpair_post",
            "LDP_D_ldstpair_pre",
            "LDP_Q_ldstpair_off",
            "LDP_Q_ldstpair_post",
            "LDP_Q_ldstpair_pre",
            "LDP_S_ldstpair_off",
            "LDP_S_ldstpair_post",
            "LDP_S_ldstpair_pre",
            "LDTP_64_ldstpair_off",
            "LDTP_64_ldstpair_post",
            "LDTP_64_ldstpair_pre",
            "LDTP_Q_ldstpair_off",
            "LDTP_Q_ldstpair_post",
            "LDTP_Q_ldstpair_pre",
        ]),
        &["Rt", "Rt2"],
        |f| f[0] == f[1],
    ),
    // Pair with writeback: if wback && (t == n || t2 == n) && n != 31 then
    // CONSTRAINED UNPREDICTABLE (WBOVERLAPLD, WBOVERLAPST);
    unpredictable(
        Names(&[
            "LDPSW_64_ldstpair_post",
            "LDPSW_64_ldstpair_pre",
            "LDP_32_ldstpair_post",
            "LDP_32_ldstpair_pre",
            "LDP_64_ldstpair_post",
            "LDP_64_ldstpair_pre",
            "LDTP_64_ldstpair_post",
            "LDTP_64_ldstpair_pre",
            "STP_32_ldstpair_post",
            "STP_32_ldstpair_pre",
            "STP_64_ldstpair_post",
            "STP_64_ldstpair_pre",
            "STTP_64_ldstpair_post",
            "STTP_64_ldstpair_pre",
            "STGP_64_ldstpair_post",
            "STGP_64_ldstpair_pre",
        ]),
        &["Rt", "Rt2", "Rn"],
        |f| (f[0] == f[2] || f[1] == f[2]) && f[2] != 31,
    ),
    // Load register with writeback: if wback && n == t && n != 31 then
    // CONSTRAINED UNPREDICTABLE (WBOVERLAPLD); LLVM accepts the 64-bit
    // sign-extending loads (LDRSB, LDRSH, LDRSW to X) and stores.
    unpredictable(
        Names(&[
            "LDRB_32_ldst_immpost",
            "LDRB_32_ldst_immpre",
            "LDRH_32_ldst_immpost",
            "LDRH_32_ldst_immpre",
            "LDRSB_32_ldst_immpost",
            "LDRSB_32_ldst_immpre",
            "LDRSH_32_ldst_immpost",
            "LDRSH_32_ldst_immpre",
            "LDR_32_ldst_immpost",
            "LDR_32_ldst_immpre",
            "LDR_64_ldst_immpost",
            "LDR_64_ldst_immpre",
            "LDRAA_64W_ldst_pac",
            "LDRAB_64W_ldst_pac",
        ]),
        &["Rt", "Rn"],
        |f| f[0] == f[1] && f[1] != 31,
    ),
    // FMLA/FMLS/FMUL/FMULX (by element): if sz:L == '11' then UNDEFINED;
    undefined(
        Suffixes(&["_asimdelem_R_SD", "_asisdelem_R_SD"]),
        &["sz", "L"],
        |f| f[0] == 1 && f[1] == 1,
    ),
    // FCMLA (by element): if (size == '01' && H == '1' && Q == '0') ||
    // (size == '10' && L == '1') then UNDEFINED;
    undefined(
        Names(&["FCMLA_advsimd_elt"]),
        &["size", "H", "Q", "L"],
        |f| (f[0] == 0b01 && f[1] == 1 && f[2] == 0) || (f[0] == 0b10 && f[3] == 1),
    ),
    // SDOT/UDOT: if size != '10' then UNDEFINED;
    undefined(
        Names(&[
            "SDOT_asimdelem_D",
            "UDOT_asimdelem_D",
            "SDOT_asimdsame2_D",
            "UDOT_asimdsame2_D",
        ]),
        &["size"],
        |f| f[0] != 0b10,
    ),
    // FAMAX/FAMIN/FSCALE: if sz:Q == '10' then UNDEFINED;  (size = '1':sz)
    undefined(
        Names(&[
            "FAMAX_asimdsame_only",
            "FAMIN_asimdsame_only",
            "FSCALE_asimdsame_only",
        ]),
        &["size", "Q"],
        |f| f[0] == 0b11 && f[1] == 0,
    ),
    // SSHLL/USHLL: if immh<3> == '1' then UNDEFINED;
    undefined(
        Names(&["SSHLL_asimdshf_L", "USHLL_asimdshf_L"]),
        &["immh"],
        |f| bit(f[0], 3) == 1,
    ),
    // Scalar saturating shift right narrow: if immh<3> == '1' then UNDEFINED;
    undefined(
        Names(&[
            "SQRSHRN_asisdshf_N",
            "SQRSHRUN_asisdshf_N",
            "SQSHRN_asisdshf_N",
            "SQSHRUN_asisdshf_N",
            "UQRSHRN_asisdshf_N",
            "UQSHRN_asisdshf_N",
        ]),
        &["immh"],
        |f| bit(f[0], 3) == 1,
    ),
    // Scalar fixed-point conversion: if immh IN {'000x'} then UNDEFINED;
    // ('0000' is another encoding)
    undefined(
        Names(&[
            "FCVTZS_asisdshf_C",
            "FCVTZU_asisdshf_C",
            "SCVTF_asisdshf_C",
            "UCVTF_asisdshf_C",
        ]),
        &["immh"],
        |f| f[0] >> 1 == 0,
    ),
    // EXT: if Q == '0' && imm4<3> == '1' then UNDEFINED;
    undefined(Names(&["EXT_asimdext_only"]), &["Q", "imm4"], |f| {
        f[0] == 0 && bit(f[1], 3) == 1
    }),
    // SVE add/subtract/copy immediate: if size:sh == '001' then UNDEFINED;
    undefined(
        Names(&[
            "add_z_zi_",
            "cpy_z_o_i_",
            "cpy_z_p_i_",
            "dup_z_i_",
            "sqadd_z_zi_",
            "sqsub_z_zi_",
            "sub_z_zi_",
            "subr_z_zi_",
            "uqadd_z_zi_",
            "uqsub_z_zi_",
        ]),
        &["size", "sh"],
        |f| f[0] == 0 && f[1] == 1,
    ),
    // SVE shift by immediate: if tszh:tszl == '0000' then UNDEFINED;
    undefined(
        Names(&[
            "asr_z_p_zi_",
            "asr_z_zi_",
            "asrd_z_p_zi_",
            "lsl_z_p_zi_",
            "lsl_z_zi_",
            "lsr_z_p_zi_",
            "lsr_z_zi_",
            "sli_z_zzi_",
            "sqshl_z_p_zi_",
            "sqshlu_z_p_zi_",
            "sri_z_zzi_",
            "srshr_z_p_zi_",
            "srsra_z_zi_",
            "ssra_z_zi_",
            "uqshl_z_p_zi_",
            "urshr_z_p_zi_",
            "ursra_z_zi_",
            "usra_z_zi_",
            "xar_z_zzi_",
            "psel_p_ppi_",
            "rshrnb_z_zi_",
            "rshrnt_z_zi_",
            "shrnb_z_zi_",
            "shrnt_z_zi_",
            "sqrshrnb_z_zi_",
            "sqrshrnt_z_zi_",
            "sqrshrunb_z_zi_",
            "sqrshrunt_z_zi_",
            "sqshrnb_z_zi_",
            "sqshrnt_z_zi_",
            "sqshrunb_z_zi_",
            "sqshrunt_z_zi_",
            "sshllb_z_zi_",
            "sshllt_z_zi_",
            "uqrshrnb_z_zi_",
            "uqrshrnt_z_zi_",
            "uqshrnb_z_zi_",
            "uqshrnt_z_zi_",
            "ushllb_z_zi_",
            "ushllt_z_zi_",
        ]),
        &["tszh", "tszl"],
        |f| f[0] == 0 && f[1] == 0,
    ),
    // SVE saturating extract narrow: case tszh:tszl of '001', '010', '100'
    // select the size, otherwise UNDEFINED;
    undefined(
        Names(&[
            "sqxtnb_z_zz_",
            "sqxtnt_z_zz_",
            "sqxtunb_z_zz_",
            "sqxtunt_z_zz_",
            "uqxtnb_z_zz_",
            "uqxtnt_z_zz_",
        ]),
        &["tszh", "tszl"],
        |f| !matches!((f[0] << 2) | f[1], 0b001 | 0b010 | 0b100),
    ),
    // SVE DUP (indexed), DUPQ: if tsz == '0...0' then UNDEFINED;
    undefined(Names(&["dup_z_zi_", "dupq_z_zi_"]), &["tsz"], |f| f[0] == 0),
    // SME2 multi-vector shift right narrow: if tsize == '00' then UNDEFINED;
    undefined(
        Names(&[
            "sqrshr_z_mz4_",
            "sqrshrn_z_mz4_",
            "sqrshru_z_mz4_",
            "sqrshrun_z_mz4_",
            "sqshrn_z_mz2_",
            "sqshrun_z_mz2_",
            "uqrshr_z_mz4_",
            "uqrshrn_z_mz4_",
            "uqshrn_z_mz2_",
        ]),
        &["tsize"],
        |f| f[0] == 0,
    ),
    // SVE operations on one element size, e.g. URECPE (.S):
    // if size != '10' then UNDEFINED;
    undefined(
        Names(&[
            "urecpe_z_p_z_m",
            "urecpe_z_p_z_z",
            "ursqrte_z_p_z_m",
            "ursqrte_z_p_z_z",
        ]),
        &["size"],
        |f| f[0] != 0b10,
    ),
    // HISTSEG (.B): if size != '00' then UNDEFINED;
    undefined(Names(&["histseg_z_zz_"]), &["size"], |f| f[0] != 0b00),
    // REVW, SXTW, UXTW (.D): if size != '11' then UNDEFINED;
    undefined(
        Names(&[
            "revw_z_z_m",
            "revw_z_z_z",
            "sxtw_z_p_z_m",
            "sxtw_z_p_z_z",
            "uxtw_z_p_z_m",
            "uxtw_z_p_z_z",
        ]),
        &["size"],
        |f| f[0] != 0b11,
    ),
    // LUTI4 (four registers, 16-bit): if size != '01' then UNDEFINED;
    undefined(Names(&["luti4_mz4_ztz_4"]), &["size"], |f| f[0] != 0b01),
    // LUTI4 (four registers, two table vectors): if size != '00' then UNDEFINED;
    undefined(
        Names(&["luti4_mz4_ztmz2_1", "luti4_mz4_ztmz2_4"]),
        &["size"],
        |f| f[0] != 0b00,
    ),
];
