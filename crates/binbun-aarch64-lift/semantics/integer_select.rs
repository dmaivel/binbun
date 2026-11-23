// Conditional select and compare, and the flag manipulation of FEAT_FlagM
// in the data-processing groups (RMIF, SETF8, SETF16). `cond()` is
// `ConditionHolds` of the encoding's condition; the aliases (CSET, CSETM,
// CINC, CINV, CNEG) are their own-syntax encodings, with the condition
// inverted as Arm encodes them.

// CSEL: n where the condition holds, else m.
#[operation(CSEL)]
fn csel(d: Op, n: Op, m: Op) {
    d = if cond() { n } else { m };
}

// CSINC, and CSET, CINC: n where the condition holds, else m + 1.
#[operation(CSINC)]
fn csinc(d: Op, n: Op, m: Op) {
    d = if cond() { n } else { m + 1 };
}

// CSINV, and CSETM, CINV: n where the condition holds, else NOT(m).
#[operation(CSINV)]
fn csinv(d: Op, n: Op, m: Op) {
    d = if cond() { n } else { !m };
}

// CSNEG, and CNEG: n where the condition holds, else -m.
#[operation(CSNEG)]
fn csneg(d: Op, n: Op, m: Op) {
    d = if cond() { n } else { -m };
}

// The flags `nzcv` (an immediate) where the condition does not hold.
fn int_nzcv_unless(holds: Op, n: Op, z: Op, c: Op, v: Op, nzcv: Op) {
    N = if holds { n } else { (nzcv >> 3) & 1 };
    Z = if holds { z } else { (nzcv >> 2) & 1 };
    C = if holds { c } else { (nzcv >> 1) & 1 };
    V = if holds { v } else { nzcv & 1 };
}

// Where the condition holds, the flags of AddWithCarry(n, NOT(m), 1)
// (those of CMP); else `nzcv`.
fn int_ccmp(n: Op, m: Op, nzcv: Op) {
    let holds = cond();
    let r = n - m;
    int_nzcv_unless(holds, msb(r), r == 0, n >= m, sub_of(n, m, 0), nzcv);
}

// Where the condition holds, the flags of AddWithCarry(n, m, 0) (those of
// CMN); else `nzcv`.
fn int_ccmn(n: Op, m: Op, nzcv: Op) {
    let holds = cond();
    let r = n + m;
    int_nzcv_unless(
        holds,
        msb(r),
        r == 0,
        add_cf(n, m, 0),
        add_of(n, m, 0),
        nzcv,
    );
}

// CCMP (immediate).
#[operation(CCMP_imm)]
fn ccmp_immediate(n: Op, imm: Op, nzcv: Op) {
    int_ccmp(n, imm, nzcv);
}

// CCMP (register).
#[operation(CCMP_reg)]
fn ccmp_register(n: Op, m: Op, nzcv: Op) {
    int_ccmp(n, m, nzcv);
}

// CCMN (immediate).
#[operation(CCMN_imm)]
fn ccmn_immediate(n: Op, imm: Op, nzcv: Op) {
    int_ccmn(n, imm, nzcv);
}

// CCMN (register).
#[operation(CCMN_reg)]
fn ccmn_register(n: Op, m: Op, nzcv: Op) {
    int_ccmn(n, m, nzcv);
}

// RMIF: n rotated right by `shift`; each flag `mask` selects (N bit 3, Z
// bit 2, C bit 1, V bit 0) takes the bit of the same place, the others are
// unchanged.
#[operation(RMIF)]
fn rmif(n: Op, shift: Op, mask: Op) {
    let t = ror(n, shift);
    if (mask >> 3) & 1 != 0 {
        N = bit(t, 3);
    }
    if (mask >> 2) & 1 != 0 {
        Z = bit(t, 2);
    }
    if (mask >> 1) & 1 != 0 {
        C = bit(t, 1);
    }
    if mask & 1 != 0 {
        V = bit(t, 0);
    }
}

// SETF8, SETF16 (`sz`, bit 14): N the bit at `msb` = 7 or 15, Z whether
// bits `msb`..0 are zero, V the bit above `msb` XOR that bit; C unchanged.
#[operation(SETF)]
fn setf(n: Op) {
    let top = (8 << field(14, 1)) - 1;
    N = bit(n, top);
    Z = bits(n, 0, top + 1) == 0;
    V = bit(n, top + 1) ^ bit(n, top);
}
