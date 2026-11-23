//! System instructions: register names by access, generic names, PSTATE
//! fields and the register operands of system operations, as LLVM 22
//! writes them.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_aarch64::operand::SystemRegister;
use binbun_aarch64::{Operand, decode};

fn text(word: u32) -> String {
    decode(word).unwrap().display(0x1000).to_string()
}

#[test]
fn writes_system_instructions_as_llvm_does() {
    // Texts LLVM 22 writes for these words (C API, every feature, hex
    // immediates), unless noted.
    let cases = [
        (0xd53b_d040, "mrs\tx0, TPIDR_EL0"),
        (0xd51b_4200, "msr\tNZCV, x0"),
        // An array register, DBGBVR<n>_EL1.
        (0xd530_0480, "mrs\tx0, DBGBVR4_EL1"),
        (0xd510_0480, "msr\tDBGBVR4_EL1, x0"),
        // No name: the generic form.
        (0xd533_01c0, "mrs\tx0, S2_3_C0_C1_6"),
        // MRRS names registers as MRS does; Rt + 1 of x30 is xzr.
        (0xd578_201e, "mrrs\tx30, xzr, TTBR0_EL1"),
        // TLBI with an optional register leaves out xzr; one that takes a
        // register writes xzr; one that takes none is SYS with a register.
        (0xd508_811f, "tlbi\tvmalle1os"),
        (0xd508_8101, "tlbi\tvmalle1os, x1"),
        (0xd508_873f, "tlbi\tvae1, xzr"),
        (0xd508_8701, "sys\t#0x0, c8, c7, #0x0, x1"),
        // TLBIP always writes its pair.
        (0xd548_813f, "tlbip\tvae1os, xzr, xzr"),
        (0xd548_813e, "tlbip\tvae1os, x30, xzr"),
        (0xd548_801e, "sysp\t#0x0, c8, c0, #0x0, x30, xzr"),
        // Arm's syntax; LLVM 22 writes `sysp` without FeatureXS.
        (0xd548_9122, "tlbip\tvae1osnxs, x2, x3"),
        (0xd52b_773f, "gcspopm"),
        (0xd528_c305, "gicr\tx5, cdia"),
        // PSTATE fields: the value is CRm, or CRm<0> where CRm<3:1>
        // selects the field; no field is the register form.
        (0xd500_41bf, "msr\tSPSel, #0x1"),
        (0xd501_431f, "msr\tPM, #0x1"),
        (0xd503_417f, "msr\tS0_3_C4_C1_3, xzr"),
        (0xd503_477f, "smstart"),
    ];
    for (word, expected) in cases {
        assert_eq!(text(word), expected, "{word:08x}");
    }
}

#[test]
fn register_names_depend_on_the_access() {
    // S3_1_C12_C0_3 reads as ICC_HAPR_EL1 and writes as ICV_HAPR_EL1 in
    // LLVM 22; S2_1_C1_C0_4 (TRCOSLAR, a name LLVM has and Arm's 2026-09
    // tables do not) has a name only when written.
    assert_eq!(text(0xd539_c063), "mrs\tx3, ICC_HAPR_EL1");
    assert_eq!(text(0xd519_c063), "msr\tICV_HAPR_EL1, x3");
    assert_eq!(text(0xd531_1083), "mrs\tx3, S2_1_C1_C0_4");
    assert_eq!(text(0xd511_1083), "msr\tTRCOSLAR, x3");
    let operands = decode(0xd539_c063).unwrap().operands();
    assert_eq!(
        operands.as_slice()[1],
        Operand::SystemRegister(SystemRegister {
            encoding: 0xce03,
            name: Some("ICC_HAPR_EL1"),
        })
    );
}
