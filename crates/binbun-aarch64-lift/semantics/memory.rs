// Loads and stores. A memory operand reads or writes the bytes the
// instruction accesses; `load(m, offset, bits)` and `store(m, offset,
// value)` access part of it, at a byte offset. The runtime computes its
// address (base, offset, pre- or post-indexing, the SP alignment check) and
// writes the base back when the entry completes. The unprivileged forms
// (LDTR, STTR, ...) run at EL0, where Arm's `AArch64.CheckUnprivileged`
// leaves them ordinary accesses.

// LDR, LDRB, LDRH (immediate, register, unscaled, unprivileged): the bytes
// zero-extended into `t`. LDR and LDUR of a SIMD and floating-point register
// (`b` to `q`): the bytes into it, the bits above cleared.
#[operation(
    LDR_imm_gen,
    LDR_reg_gen,
    LDUR_gen,
    LDTR,
    LDRB_imm,
    LDRB_reg,
    LDURB,
    LDTRB,
    LDRH_imm,
    LDRH_reg,
    LDURH,
    LDTRH,
    LDR_imm_fpsimd,
    LDR_reg_fpsimd,
    LDUR_fpsimd
)]
fn load_register(t: Op, m: Op) {
    t = zext(m, width(t));
}

// LDRSB, LDRSH, LDRSW (immediate, register, unscaled, unprivileged): the
// bytes sign-extended into `t`.
#[operation(
    LDRSB_imm, LDRSB_reg, LDURSB, LDTRSB, LDRSH_imm, LDRSH_reg, LDURSH, LDTRSH, LDRSW_imm,
    LDRSW_reg, LDURSW, LDTRSW
)]
fn load_signed(t: Op, m: Op) {
    t = sext(m, width(t));
}

// STR, STRB, STRH (immediate, register, unscaled, unprivileged): the low
// bytes of `t`. STR and STUR of a SIMD and floating-point register: its
// bytes.
#[operation(
    STR_imm_gen,
    STR_reg_gen,
    STUR_gen,
    STTR,
    STRB_imm,
    STRB_reg,
    STURB,
    STTRB,
    STRH_imm,
    STRH_reg,
    STURH,
    STTRH,
    STR_imm_fpsimd,
    STR_reg_fpsimd,
    STUR_fpsimd
)]
fn store_register(t: Op, m: Op) {
    m = trunc(t, width(m));
}

// LDR (literal): `t` from the label's address, a general-purpose or a SIMD
// and floating-point register (`s`, `d`, `q`).
#[operation(LDR_lit_gen, LDR_lit_fpsimd)]
fn load_literal(t: Op, label: Op) {
    t = load(label, 0, width(t));
}

// LDRSW (literal): a word from the label's address, sign-extended.
#[operation(LDRSW_lit)]
fn load_literal_signed(t: Op, label: Op) {
    t = sext(load(label, 0, 32), 64);
}

// PRFM (immediate, register, literal), PRFUM: hints, which never fault and
// change nothing a program can see (Arm's `Hint_Prefetch`; no SP alignment
// check for a prefetch), so the address is not computed.
#[operation(PRFM_imm, PRFM_reg, PRFM_lit, PRFUM)]
fn prefetch(_operation: Op, _address: Op) {}

// RPRFM: a range prefetch hint, as PRFM.
#[operation(RPRFM_reg)]
fn range_prefetch(_operation: Op, _metadata: Op, _address: Op) {}

// LDP, LDNP (the non-temporal hint changes nothing a program sees): signed
// offset, pre- and post-index; `t1` from the lower address. Two accesses,
// one per register, as without FEAT_LSE2 (the order does not matter: a
// fault leaves no effect either way). General-purpose or SIMD and
// floating-point registers (`s`, `d`, `q`).
#[operation(LDP_gen, LDNP_gen, LDP_fpsimd, LDNP_fpsimd)]
fn ldp(t1: Op, t2: Op, m: Op) {
    let first = load(m, 0, width(t1));
    let second = load(m, width(t1) / 8, width(t2));
    t1 = first;
    t2 = second;
}

// LDPSW: two words, each sign-extended, `t1` from the lower address.
#[operation(LDPSW)]
fn ldpsw(t1: Op, t2: Op, m: Op) {
    let first = load(m, 0, 32);
    let second = load(m, 4, 32);
    t1 = sext(first, 64);
    t2 = sext(second, 64);
}

// STP, STNP: signed offset, pre- and post-index; `t1` to the lower
// address, two accesses as for LDP; general-purpose or SIMD and
// floating-point registers.
#[operation(STP_gen, STNP_gen, STP_fpsimd, STNP_fpsimd)]
fn stp(t1: Op, t2: Op, m: Op) {
    store(m, 0, t1);
    store(m, width(t1) / 8, t2);
}
