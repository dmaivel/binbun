// Pointer authentication (FEAT_PAuth with FEAT_PAuth2, FEAT_FPAC and
// FEAT_FPACCOMBINE, as qemu -cpu max and sail-arm's v9.4 have them) under
// the execution context: EL0, 48-bit virtual addresses in both halves
// (`TCR_EL1.T0SZ` = `T1SZ` = 16), Linux's `TBI0` = 1, `TBID0` = 0 and
// `TBI1` = `TBID1` = 1 (`TCR_MTE_FLAGS`), keys enabled. Bit 55 selects the
// half; the PAC field is bits 54:48, and bits 63:56 too for an upper-half
// instruction pointer, whose top byte is not ignored (`TBID1`); a data
// pointer's top byte is ignored, and kept, in both halves. The code itself
// is `compute_pac` (Arm's `ComputePAC` with the process's key); key 0 to 3
// is IA, IB, DA, DB.

// The top byte an upper-half pointer keeps (Arm's `EffectiveTBI`): a data
// pointer's (`data` = 1: keys DA and DB, XPACD), not an instruction
// pointer's.
fn upper_tag(data: Op) -> Op {
    if data == 1 {
        0xff00_0000_0000_0000
    } else {
        0
    }
}

// AddPAC: the code of the pointer with its PAC field made copies of bit
// 55, XORed into the field (FEAT_PAuth2: a pointer whose field was not all
// copies of bit 55 is signed alike, its field corrupted by the XOR).
fn add_pac(ptr: Op, modifier: Op, key: Op) -> Op {
    let upper = bit(ptr, 55);
    let kept = upper_tag(key >= 2);
    let extended = if upper == 1 {
        ptr | (0xffff_0000_0000_0000 ^ kept)
    } else {
        ptr & 0xff00_ffff_ffff_ffff
    };
    let code = intrinsic("compute_pac", extended, fit(modifier, 64), fit(key, 3));
    if upper == 1 {
        ptr ^ (code & (0xff7f_0000_0000_0000 ^ kept))
    } else {
        ptr ^ (code & 0x007f_0000_0000_0000)
    }
}

// Auth: the code is recomputed on the pointer with its PAC field made
// copies of bit 55 and XORed out of the field; a field then not all copies
// of bit 55 fails, and with FEAT_FPAC (and FEAT_FPACCOMBINE for the
// combined branches and returns) the failure faults.
fn auth(ptr: Op, modifier: Op, key: Op) -> Op {
    let upper = bit(ptr, 55);
    let kept = upper_tag(key >= 2);
    let original = if upper == 1 {
        ptr | (0xffff_0000_0000_0000 ^ kept)
    } else {
        ptr & 0xff00_ffff_ffff_ffff
    };
    let code = intrinsic("compute_pac", original, fit(modifier, 64), fit(key, 3));
    let result = if upper == 1 {
        ptr ^ (code & (0xff7f_0000_0000_0000 ^ kept))
    } else {
        ptr ^ (code & 0x007f_0000_0000_0000)
    };
    let failed = if upper == 1 {
        ((result | kept) >> 48) != 0xffff
    } else {
        bits(result, 48, 7) != 0
    };
    if failed {
        trap(AUTHENTICATION);
    }
    result
}

// Strip: the PAC field made copies of bit 55 (the top byte kept where it
// is ignored: in the lower half, and in the upper half for `data` = 1).
fn strip(ptr: Op, data: Op) -> Op {
    if bit(ptr, 55) == 1 {
        ptr | (0xffff_0000_0000_0000 ^ upper_tag(data))
    } else {
        ptr & 0xff00_ffff_ffff_ffff
    }
}

// PACIA: `d` signed with key IA, modifier `n` (or SP).
#[operation(PACIA)]
fn pacia(d: Op, n: Op) {
    d = add_pac(d, n, 0);
}

// PACIZA: modifier 0.
#[encoding(PACIZA_64Z_dp_1src)]
fn paciza(d: Op) {
    d = add_pac(d, 0, 0);
}

// PACIASP: x30 with modifier SP.
#[encoding(PACIASP_HI_hints)]
fn paciasp() {
    x30 = add_pac(x30, sp, 0);
}

// PACIAZ: x30 with modifier 0.
#[encoding(PACIAZ_HI_hints)]
fn paciaz() {
    x30 = add_pac(x30, 0, 0);
}

// PACIA1716: x17 with modifier x16.
#[encoding(PACIA1716_HI_hints)]
fn pacia1716() {
    x17 = add_pac(x17, x16, 0);
}

// PACIB and its forms: as PACIA with key IB.
#[operation(PACIB)]
fn pacib(d: Op, n: Op) {
    d = add_pac(d, n, 1);
}

#[encoding(PACIZB_64Z_dp_1src)]
fn pacizb(d: Op) {
    d = add_pac(d, 0, 1);
}

#[encoding(PACIBSP_HI_hints)]
fn pacibsp() {
    x30 = add_pac(x30, sp, 1);
}

#[encoding(PACIBZ_HI_hints)]
fn pacibz() {
    x30 = add_pac(x30, 0, 1);
}

#[encoding(PACIB1716_HI_hints)]
fn pacib1716() {
    x17 = add_pac(x17, x16, 1);
}

// PACDA, PACDZA: key DA.
#[operation(PACDA)]
fn pacda(d: Op, n: Op) {
    d = add_pac(d, n, 2);
}

#[encoding(PACDZA_64Z_dp_1src)]
fn pacdza(d: Op) {
    d = add_pac(d, 0, 2);
}

// PACDB, PACDZB: key DB.
#[operation(PACDB)]
fn pacdb(d: Op, n: Op) {
    d = add_pac(d, n, 3);
}

#[encoding(PACDZB_64Z_dp_1src)]
fn pacdzb(d: Op) {
    d = add_pac(d, 0, 3);
}

// AUTIA: `d` authenticated with key IA, modifier `n` (or SP).
#[operation(AUTIA)]
fn autia(d: Op, n: Op) {
    d = auth(d, n, 0);
}

#[encoding(AUTIZA_64Z_dp_1src)]
fn autiza(d: Op) {
    d = auth(d, 0, 0);
}

#[encoding(AUTIASP_HI_hints)]
fn autiasp() {
    x30 = auth(x30, sp, 0);
}

#[encoding(AUTIAZ_HI_hints)]
fn autiaz() {
    x30 = auth(x30, 0, 0);
}

#[encoding(AUTIA1716_HI_hints)]
fn autia1716() {
    x17 = auth(x17, x16, 0);
}

// AUTIB and its forms: key IB.
#[operation(AUTIB)]
fn autib(d: Op, n: Op) {
    d = auth(d, n, 1);
}

#[encoding(AUTIZB_64Z_dp_1src)]
fn autizb(d: Op) {
    d = auth(d, 0, 1);
}

#[encoding(AUTIBSP_HI_hints)]
fn autibsp() {
    x30 = auth(x30, sp, 1);
}

#[encoding(AUTIBZ_HI_hints)]
fn autibz() {
    x30 = auth(x30, 0, 1);
}

#[encoding(AUTIB1716_HI_hints)]
fn autib1716() {
    x17 = auth(x17, x16, 1);
}

// AUTDA, AUTDZA: key DA.
#[operation(AUTDA)]
fn autda(d: Op, n: Op) {
    d = auth(d, n, 2);
}

#[encoding(AUTDZA_64Z_dp_1src)]
fn autdza(d: Op) {
    d = auth(d, 0, 2);
}

// AUTDB, AUTDZB: key DB.
#[operation(AUTDB)]
fn autdb(d: Op, n: Op) {
    d = auth(d, n, 3);
}

#[encoding(AUTDZB_64Z_dp_1src)]
fn autdzb(d: Op) {
    d = auth(d, 0, 3);
}

// XPACI, XPACD: the PAC field of an instruction or data pointer stripped.
#[encoding(XPACI_64Z_dp_1src)]
fn xpaci(d: Op) {
    d = strip(d, 0);
}

#[encoding(XPACD_64Z_dp_1src)]
fn xpacd(d: Op) {
    d = strip(d, 1);
}

// XPACLRI: x30 stripped.
#[encoding(XPACLRI_HI_hints)]
fn xpaclri() {
    x30 = strip(x30, 0);
}

// BRAA, BRAAZ, BRAB, BRABZ: BR to `n` authenticated with modifier `m` (or
// 0); BTYPE 01.
#[encoding(BRAA_64P_branch_reg)]
fn braa(n: Op, m: Op) {
    let target = auth(n, m, 0);
    btype = 1;
    jump(target);
}

#[encoding(BRAAZ_64_branch_reg)]
fn braaz(n: Op) {
    let target = auth(n, 0, 0);
    btype = 1;
    jump(target);
}

#[encoding(BRAB_64P_branch_reg)]
fn brab(n: Op, m: Op) {
    let target = auth(n, m, 1);
    btype = 1;
    jump(target);
}

#[encoding(BRABZ_64_branch_reg)]
fn brabz(n: Op) {
    let target = auth(n, 0, 1);
    btype = 1;
    jump(target);
}

// BLRAA, BLRAAZ, BLRAB, BLRABZ: BLR likewise; BTYPE 10.
#[encoding(BLRAA_64P_branch_reg)]
fn blraa(n: Op, m: Op) {
    let target = auth(n, m, 0);
    btype = 2;
    x30 = next();
    call(target);
}

#[encoding(BLRAAZ_64_branch_reg)]
fn blraaz(n: Op) {
    let target = auth(n, 0, 0);
    btype = 2;
    x30 = next();
    call(target);
}

#[encoding(BLRAB_64P_branch_reg)]
fn blrab(n: Op, m: Op) {
    let target = auth(n, m, 1);
    btype = 2;
    x30 = next();
    call(target);
}

#[encoding(BLRABZ_64_branch_reg)]
fn blrabz(n: Op) {
    let target = auth(n, 0, 1);
    btype = 2;
    x30 = next();
    call(target);
}

// RETAA, RETAB: RET to x30 authenticated with modifier SP.
#[encoding(RETAA_64E_branch_reg)]
fn retaa() {
    ret(auth(x30, sp, 0));
}

#[encoding(RETAB_64E_branch_reg)]
fn retab() {
    ret(auth(x30, sp, 1));
}
