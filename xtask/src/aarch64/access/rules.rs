//! The hand-written knowledge behind `access.rs`: which operands an
//! instruction reads and writes beyond what the operand names say, what
//! memory it accesses, the registers it uses without naming them and the
//! condition flags it reads and writes. Each rule names the forms it applies
//! to by encoding-name patterns (`*` matches any text, `|` separates
//! alternatives, case is ignored: SVE and SME encodings have lower-case
//! names) and says which Arm behaviour it reflects.

/// Whether `name` matches `pattern`: `|`-separated globs, ASCII case
/// ignored.
pub fn matches(pattern: &str, name: &str) -> bool {
    pattern
        .split('|')
        .any(|glob| glob_matches(glob.as_bytes(), name.as_bytes()))
}

/// Whether the slot key `key` matches the glob `glob` (keys contain `|`, so
/// key patterns have no alternatives).
pub fn matches_key(glob: &str, key: &str) -> bool {
    glob_matches(glob.as_bytes(), key.as_bytes())
}

fn glob_matches(glob: &[u8], name: &[u8]) -> bool {
    match glob.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|skip| {
            name.get(skip..)
                .is_some_and(|tail| glob_matches(rest, tail))
        }),
        Some((first, rest)) => name.split_first().is_some_and(|(head, tail)| {
            head.eq_ignore_ascii_case(first) && glob_matches(rest, tail)
        }),
    }
}

/// How an operand is accessed, as a rule states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Read,
    Write,
    ReadWrite,
    /// Read and written when one of the fields is not 0, written otherwise.
    ReadWriteIf(&'static [&'static str]),
}

/// Forms whose destination register (an operand named `<…d>`) is also
/// read: the instruction keeps part of it or accumulates into it. Forms
/// whose syntax shows that already (`<Zdn>`, `<Zda>`, a `/M` predicate) need
/// no entry.
pub const READS_DESTINATION: &[(&str, &str)] = &[
    ("MOVK_*", "MOVK replaces one halfword and keeps the others"),
    (
        "BFM_*",
        "BFM (BFI, BFXIL, BFC) replaces a bit field and keeps the bits around it",
    ),
    (
        "PACIA_*|PACIB_*|PACDA_*|PACDB_*|PACIZA_*|PACIZB_*|PACDZA_*|PACDZB_*|\
         AUTIA_*|AUTIB_*|AUTDA_*|AUTDB_*|AUTIZA_*|AUTIZB_*|AUTDZA_*|AUTDZB_*|\
         XPACI_*|XPACD_*",
        "pointer authentication signs, authenticates or strips the pointer in Xd in place",
    ),
    (
        "MLA_asimd*|MLS_asimd*|SABA_asimd*|UABA_asimd*|SABAL_asimd*|UABAL_asimd*|\
         SADALP_asimd*|UADALP_asimd*|SMLAL_asimd*|SMLSL_asimd*|UMLAL_asimd*|UMLSL_asimd*|\
         SQDMLAL_asi*|SQDMLSL_asi*|SQRDMLAH_asi*|SQRDMLSH_asi*",
        "Advanced SIMD integer multiply-accumulate and absolute-difference-accumulate: Vd += …",
    ),
    (
        "SSRA_asi*|USRA_asi*|SRSRA_asi*|URSRA_asi*|SUQADD_asi*|USQADD_asi*",
        "Advanced SIMD shift-and-accumulate and saturating accumulate: Vd += …",
    ),
    (
        "SLI_*|SRI_*",
        "shift-and-insert keeps the destination bits the shifted value does not cover",
    ),
    (
        "BIF_*|BIT_*|BSL_*",
        "bitwise insert and select: BIF and BIT keep Vd's bits where the mask says, BSL \
         takes its mask from Vd",
    ),
    (
        "FMLA_asi*|FMLS_asi*|FMLAL_asi*|FMLSL_asi*|FMLAL2_asi*|FMLSL2_asi*|FMLALB_asi*|\
         FMLALT_asi*|FMLALLBB_asi*|FMLALLBT_asi*|FMLALLTB_asi*|FMLALLTT_asi*|BFMLAL_asi*|\
         FCMLA_a*|FDOT_asi*|BFDOT_asi*|SDOT_asi*|UDOT_asi*|USDOT_asi*|SUDOT_asi*|\
         SMMLA_asi*|UMMLA_asi*|USMMLA_asi*|BFMMLA_asi*|FMMLA_asi*",
        "Advanced SIMD floating-point and dot-product multiply-accumulate: Vd += …",
    ),
    (
        "INS_asimdins_*",
        "INS (MOV to an element) replaces one element and keeps the others",
    ),
    (
        "FMOV_V64I_float2int",
        "FMOV Vd.D[1], Xn writes the upper half of Vd and keeps the lower",
    ),
    (
        "TBX_*|tbx_z_zz_|tbxq_z_zz_",
        "TBX and TBXQ keep the destination element where the index is out of range",
    ),
    (
        "ORR_asimdimm_*|BIC_asimdimm_*",
        "ORR and BIC (vector, immediate) combine the immediate with Vd",
    ),
    (
        "AESE_*|AESD_*|SHA1C_*|SHA1P_*|SHA1M_*|SHA1SU0_*|SHA1SU1_*|SHA256H_*|SHA256H2_*|\
         SHA256SU0_*|SHA256SU1_*|SHA512H_*|SHA512H2_*|SHA512SU0_*|SHA512SU1_*|SM3TT*|\
         SM3PARTW*|SM4E_*",
        "AES rounds and SHA/SM3/SM4 hash updates transform the state held in the destination",
    ),
    (
        "addhnt_*|raddhnt_*|subhnt_*|rsubhnt_*|shrnt_*|rshrnt_*|sqshrnt_*|sqrshrnt_*|\
         uqshrnt_*|uqrshrnt_*|sqshrunt_*|sqrshrunt_*|sqxtnt_*|uqxtnt_*|sqxtunt_*|\
         fcvtnt_*|fcvtxnt_*|bfcvtnt_*",
        "SVE2 narrowing (top) forms write the odd elements of Zd and keep the even ones",
    ),
    (
        "eorbt_*|eortb_*",
        "EORBT and EORTB write the even (odd) elements of Zd and keep the others",
    ),
    (
        "sclamp_*|uclamp_*|fclamp_*|bfclamp_*",
        "CLAMP clamps the elements of Zd between Zn and Zm",
    ),
];

/// Forms whose destination is also read when one of the fields is not 0:
/// (form pattern, fields, behaviour).
pub const READS_DESTINATION_IF: &[(&str, &[&str], &str)] = &[
    (
        "*_asimdmisc_N|*_asimdshf_N|*_asimddiff_N|BFCVTN_asimdmisc_4S|FCVTN_asimdsame2_H",
        &["Q"],
        "Advanced SIMD narrowing forms (Arm's `_N` encodings and the narrowing conversions) \
         write the upper half of Vd and keep the lower when Q is 1: the `2` forms (XTN2, \
         SHRN2, ADDHN2, FCVTN2, …)",
    ),
    (
        "pmov_z_pi_h",
        &["i1"],
        "PMOV (to vector) writes portion i of Zd, zeroing the rest only for portion 0",
    ),
    (
        "pmov_z_pi_s",
        &["i2"],
        "PMOV (to vector) writes portion i of Zd, zeroing the rest only for portion 0",
    ),
    (
        "pmov_z_pi_d",
        &["i3h", "i3l"],
        "PMOV (to vector) writes portion i of Zd, zeroing the rest only for portion 0",
    ),
];

/// Groups whose memory accesses all depend on the vector length (SVE and
/// SME), unless `MEMORY_SIZES` fixes them.
pub const VECTOR_LENGTH_GROUPS: &str = "sve/*|sme/*";

/// Operands the instruction accesses otherwise than its operand names say:
/// (form pattern, slot key pattern, access, behaviour). The first match
/// wins; form patterns also match alias forms (`ENCODING__alias`).
pub const SLOT_RULES: &[(&str, &[&str], Rule, &str)] = &[
    (
        "CHKFEAT_*",
        &["X16"],
        Rule::ReadWrite,
        "CHKFEAT clears the bits of X16 naming enabled features",
    ),
    (
        "MRS_RS_*|SYSL_*|TSTART_*|TTEST_*",
        &["<Xt>", "{<Xt>}"],
        Rule::Write,
        "MRS, SYSL (and its aliases GCSPOPM, GCSSS2), TSTART and TTEST write their result to Xt",
    ),
    (
        "MRRS_*",
        &["<Xt>", "<Xt+1>"],
        Rule::Write,
        "MRRS writes the register pair",
    ),
    (
        "MSR_SR_*|MSRR_*",
        &["(<systemreg>*"],
        Rule::Write,
        "MSR and MSRR write the system register",
    ),
    (
        "MSR_SI_*",
        &["<pstatefield>"],
        Rule::Write,
        "MSR (immediate) writes the PSTATE field",
    ),
    (
        "CAS*|RCWCAS*|RCWSCAS*",
        &["<Ws>", "<Xs>", "<W(s+1)>", "<X(s+1)>"],
        Rule::ReadWrite,
        "compare and swap compares with Rs and returns the old memory value in it",
    ),
    (
        "CAS*|RCWCAS*|RCWSCAS*",
        &["<Wt>", "<Xt>", "<W(t+1)>", "<X(t+1)>"],
        Rule::Read,
        "compare and swap stores Rt if the comparison succeeds",
    ),
    (
        "LDCLRP*|LDSETP*|SWPP*|RCWCLRP*|RCWSETP*|RCWSWPP*|RCWSCLRP*|RCWSSETP*|RCWSSWPP*",
        &["<Xt1>", "<Xt2>"],
        Rule::ReadWrite,
        "128-bit atomics take the operand from Xt1:Xt2 and return the old memory value in it",
    ),
    (
        "LDG_*",
        &["<Xt>"],
        Rule::ReadWrite,
        "LDG inserts the loaded allocation tag into the address in Xt",
    ),
    (
        "ST64BV_*|ST64BV0_*",
        &["<Xs>"],
        Rule::Write,
        "ST64BV and ST64BV0 write the status result to Xs",
    ),
    (
        "*",
        &["<Xn>!"],
        Rule::ReadWrite,
        "memory copy and set count down the size register",
    ),
    (
        "CPY*",
        &["[<Xd>]!"],
        Rule::Write,
        "memory copy stores to the destination buffer",
    ),
    (
        "CPY*",
        &["[<Xs>]!"],
        Rule::Read,
        "memory copy loads from the source buffer",
    ),
    (
        "zero_za*|zero_zt*",
        &["*"],
        Rule::Write,
        "ZERO writes zeros to the tiles, slices or ZT0",
    ),
    (
        "movt_zt_z_",
        &["ZT0*"],
        Rule::ReadWrite,
        "MOVT (vector to table) replaces one 128-bit part of ZT0 and keeps the rest",
    ),
    (
        "add_za_zzv_*|add_za_zzw_*|sub_za_zzv_*|sub_za_zzw_*",
        &["ZA*"],
        Rule::Write,
        "ADD and SUB (array results) write Zn + Zm to the ZA vectors without accumulating",
    ),
    (
        "mova_za*_z*|mova_za_mz*",
        &["ZA*"],
        Rule::Write,
        "MOVA into ZA array vectors writes them without reading them",
    ),
    (
        "mova_za*_z*|mova_za_mz*",
        &["<ZAd>*", "{ZA0*", "ZA0*"],
        Rule::Write,
        "MOVA into tile slices, unpredicated, writes them without reading them",
    ),
    (
        "movaz_*",
        &["<ZAn>*", "ZA0*", "ZA*"],
        Rule::ReadWrite,
        "MOVAZ reads the ZA slices and zeroes them",
    ),
    (
        "adr_z_az_*",
        &["[*"],
        Rule::Read,
        "ADR's vector address operand computes an address and accesses no memory",
    ),
];

/// Kinds of memory access, by encoding name pattern; the first match wins.
/// Every encoding with a memory operand (`[…]`) or a literal load needs one.
pub const MEMORY_KINDS: &[(&str, &str, &str)] = &[
    ("PRF*|RPRFM_*", "Prefetch", "prefetch hints access no data"),
    ("CPY*_memcms", "Copy", "memory copy (FEAT_MOPS)"),
    (
        "SET*_memcms|SET*_memset_go",
        "Store",
        "memory set (FEAT_MOPS) stores a byte value",
    ),
    (
        "LDXR*|LDAXR*|LDXP_*|LDAXP_*|LDTXR*|LDATXR*",
        "LoadExclusive",
        "load exclusive sets the exclusive monitor",
    ),
    (
        "STXR*|STLXR*|STXP_*|STLXP_*|STTXR*|STLTXR*",
        "StoreExclusive",
        "store exclusive stores only if the monitor holds",
    ),
    (
        "CAS*|SWP*|RCW*|LDADD*|LDCLR*|LDEOR*|LDSET*|LDSMAX*|LDSMIN*|LDUMAX*|LDUMIN*|\
         LDTADD*|LDTCLR*|LDTSET*|LDFADD*|LDFMAX*|LDFMIN*|LDBF*|STFADD*|STFMAX*|STFMIN*|\
         STBF*",
        "Atomic",
        "atomic read-modify-write (FEAT_LSE, LSE128, LSFE, RCW, LSUI)",
    ),
    (
        "LDG_*|LDGM_*",
        "LoadTag",
        "LDG and LDGM load allocation tags",
    ),
    (
        "STG_*|ST2G_*|STGM_*",
        "StoreTag",
        "STG, ST2G and STGM store allocation tags only",
    ),
    (
        "LD*",
        "Load",
        "loads, including literal, structure, SVE and SME loads",
    ),
    (
        "ST*|GCSST*",
        "Store",
        "stores, including STZG and STGP, which also store tags",
    ),
];

/// Fixed access sizes in bytes, by encoding name pattern, where the
/// operands do not say it.
pub const MEMORY_SIZES: &[(&str, u32, &str)] = &[
    (
        "LD64B_*|LDA64B_*|ST64B_*|STL64B_*|ST64BV_*|ST64BV0_*",
        64,
        "single-copy atomic 64-byte loads and stores",
    ),
    ("ldr_zt_*|str_zt_*", 64, "ZT0 is 512 bits"),
    ("LDG_*|STG_*|STZG_*|STGP_*", 16, "one 16-byte tag granule"),
    ("ST2G_*|STZ2G_*", 32, "two tag granules"),
    ("ld1rqb_*|ld1rqh_*|ld1rqw_*|ld1rqd_*", 16, "one quadword"),
    ("ld1rob_*|ld1roh_*|ld1row_*|ld1rod_*", 32, "one octaword"),
    ("ld1rb_*|ld1rsb_*", 1, "one byte, replicated"),
    ("ld1rh_*|ld1rsh_*", 2, "one halfword, replicated"),
    ("ld1rw_*|ld1rsw_*", 4, "one word, replicated"),
    ("ld1rd_*", 8, "one doubleword, replicated"),
    ("LDPSW_*", 8, "two words"),
    ("LDRSW_*_loadlit", 4, "one word"),
];

/// Encodings whose access size depends on the vector length, on the
/// implementation or on a register: size 0.
pub const MEMORY_UNSIZED: &str =
    "PRF*|RPRFM_*|CPY*_memcms|SET*_memcms|SET*_memset_go|LDGM_*|STGM_*|STZGM_*";

/// Registers of an `IMPLICIT` rule: `X30`, `SP` or `FFR`, or a run of
/// general registers after a field, `X(Rt+1..Rt+7)`, alone in its list.
pub type Registers = &'static [&'static str];

/// Registers used without being operands: (form pattern, condition on the
/// word or `true`, reads, writes, behaviour).
pub const IMPLICIT: &[(&str, &str, Registers, Registers, &str)] = &[
    (
        "LD64B_*|LDA64B_*",
        "true",
        &[],
        &["X(Rt+1..Rt+7)"],
        "LD64B loads eight consecutive registers from Xt",
    ),
    (
        "ST64B_*|STL64B_*|ST64BV_*|ST64BV0_*",
        "true",
        &["X(Rt+1..Rt+7)"],
        &[],
        "ST64B, ST64BV and ST64BV0 store eight consecutive registers from Xt",
    ),
    (
        "BL_*|BLR_*|BLRAA_*|BLRAAZ_*|BLRAB_*|BLRABZ_*",
        "true",
        &[],
        &["X30"],
        "branch with link writes the return address to X30",
    ),
    (
        "RET_64R_*",
        "Rn == 30",
        &["X30"],
        &[],
        "RET without an operand returns to X30",
    ),
    (
        "RETAA_*|RETAB_*|RETAASPPC*|RETABSPPC*",
        "true",
        &["X30", "SP"],
        &[],
        "authenticated returns authenticate X30 with SP as the modifier",
    ),
    (
        "ERETAA_*|ERETAB_*",
        "true",
        &["SP"],
        &[],
        "authenticated exception returns use SP as the modifier",
    ),
    (
        "PACIASP_*|PACIBSP_*|AUTIASP_*|AUTIBSP_*|PACIASPPC_*|PACIBSPPC_*|PACNBIASPPC_*|\
         PACNBIBSPPC_*|AUTIASPPC*|AUTIBSPPC*",
        "true",
        &["X30", "SP"],
        &["X30"],
        "sign or authenticate X30 with SP as the modifier",
    ),
    (
        "PACIAZ_*|PACIBZ_*|AUTIAZ_*|AUTIBZ_*|XPACLRI_*",
        "true",
        &["X30"],
        &["X30"],
        "sign, authenticate or strip X30 in place",
    ),
    (
        "PACIA1716_*|PACIB1716_*|AUTIA1716_*|AUTIB1716_*",
        "true",
        &["X17", "X16"],
        &["X17"],
        "sign or authenticate X17 with X16 as the modifier",
    ),
    (
        "PACIA171615_*|PACIB171615_*|AUTIA171615_*|AUTIB171615_*",
        "true",
        &["X17", "X16", "X15"],
        &["X17"],
        "sign or authenticate X17 with X16 and X15 as the modifiers",
    ),
    (
        "ldff1*|ldnf1*",
        "true",
        &["FFR"],
        &["FFR"],
        "first-fault and non-fault loads clear the FFR elements from the first element not loaded",
    ),
    (
        "rdffr_*|rdffrs_*",
        "true",
        &["FFR"],
        &[],
        "RDFFR reads the first-fault register",
    ),
    (
        "setffr_*|wrffr_*",
        "true",
        &[],
        &["FFR"],
        "SETFFR and WRFFR write the first-fault register",
    ),
];

/// Condition flags beyond those a condition reads (every encoding with a
/// `cond` field reads the flags its condition tests: `b.cond`, `bc.cond`,
/// the conditional selects and compares, `flt`): (form pattern, read,
/// written, behaviour). `mask` writes the flags RMIF's mask selects; `nzcv`
/// reads or writes all four when the system register is NZCV. The first
/// match wins.
pub const FLAGS: &[(&str, &str, &str, &str)] = &[
    (
        "CCMN_*|CCMP_*|FCCMP_*|FCCMPE_*",
        "",
        "NZCV",
        "conditional compares set the flags (to the comparison or to #nzcv)",
    ),
    (
        "ADC_*|SBC_*",
        "C",
        "",
        "add and subtract with carry read the carry",
    ),
    (
        "ADCS_*|SBCS_*",
        "C",
        "NZCV",
        "add and subtract with carry read the carry and set the flags",
    ),
    (
        "ADDS_*|SUBS_*|ANDS_*|BICS_*|SUBPS_*|FCMP_*|FCMPE_*|FCMTL_*_floatcmp|\
         FCMTLMG_*_floatcmp",
        "",
        "NZCV",
        "flag-setting arithmetic, logic and compares",
    ),
    (
        "FJCVTZS_*",
        "",
        "NZCV",
        "FJCVTZS sets Z when the conversion is exact and clears N, C and V",
    ),
    (
        "RCW*",
        "",
        "NZCV",
        "read-check-write atomics (FEAT_THE) set the flags from the check",
    ),
    (
        "CPYP*_memcms|CPYFP*_memcms|SETP*_memcms|SETGP*_memcms|SETGOP*_memset_go",
        "",
        "NZCV",
        "the memory copy and set prologues record the algorithm option (and copy direction) \
         in the flags",
    ),
    (
        "CPYM*_memcms|CPYE*_memcms|CPYFM*_memcms|CPYFE*_memcms",
        "NC",
        "",
        "the main and epilogue copy stages check the option in C and, for option B, take \
         the direction from N",
    ),
    (
        "SET*_memcms|SET*_memset_go",
        "C",
        "",
        "the main and epilogue set stages check the option in C",
    ),
    (
        "SETF8_*|SETF16_*",
        "",
        "NZV",
        "SETF8 and SETF16 set N, Z and V",
    ),
    ("RMIF_*", "", "mask", "RMIF sets the flags its mask selects"),
    ("CFINV_*", "C", "C", "CFINV inverts the carry"),
    (
        "AXFLAG_*",
        "ZCV",
        "NZCV",
        "AXFLAG converts Arm comparison flags to the alternative format from Z, C and V",
    ),
    (
        "XAFLAG_*",
        "ZC",
        "NZCV",
        "XAFLAG converts alternative-format flags back from Z and C",
    ),
    ("MRS_RS_*", "nzcv", "", "MRS reads NZCV"),
    ("MSR_SR_*", "", "nzcv", "MSR writes NZCV"),
    (
        "ands_*|bics_*|eors_*|nands_*|nors_*|orns_*|orrs_*|brkas_*|brkbs_*|brkns_*|\
         brkpas_*|brkpbs_*|pfirst_*|pnext_*|ptest_*|ptrues_*|rdffrs_*|cmp*_p_p_*|\
         while*|match_*|nmatch_*",
        "",
        "NZCV",
        "SVE predicate-setting forms set the flags from the predicate result",
    ),
    (
        "ctermeq_*|ctermne_*",
        "C",
        "NV",
        "CTERMEQ and CTERMNE set N and V from the comparison and the carry",
    ),
];
