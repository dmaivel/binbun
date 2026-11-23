// Multiply, divide, minimum and maximum (FEAT_CSSC).

// MADD, and MUL: a + n * m.
#[operation(MADD)]
fn madd(d: Op, n: Op, m: Op, a: Op) {
    d = a + n * m;
}

// MSUB, and MNEG: a - n * m.
#[operation(MSUB)]
fn msub(d: Op, n: Op, m: Op, a: Op) {
    d = a - n * m;
}

// SMADDL, and SMULL: a + SInt(n) * SInt(m), 32-bit factors.
#[operation(SMADDL)]
fn smaddl(d: Op, n: Op, m: Op, a: Op) {
    d = a + sext(n, 64) * sext(m, 64);
}

// SMSUBL, and SMNEGL: a - SInt(n) * SInt(m).
#[operation(SMSUBL)]
fn smsubl(d: Op, n: Op, m: Op, a: Op) {
    d = a - sext(n, 64) * sext(m, 64);
}

// UMADDL, and UMULL: a + UInt(n) * UInt(m).
#[operation(UMADDL)]
fn umaddl(d: Op, n: Op, m: Op, a: Op) {
    d = a + zext(n, 64) * zext(m, 64);
}

// UMSUBL, and UMNEGL: a - UInt(n) * UInt(m).
#[operation(UMSUBL)]
fn umsubl(d: Op, n: Op, m: Op, a: Op) {
    d = a - zext(n, 64) * zext(m, 64);
}

// SMULH: bits 127..64 of SInt(n) * SInt(m).
#[operation(SMULH)]
fn smulh(d: Op, n: Op, m: Op) {
    d = bits(sext(n, 128) * sext(m, 128), 64, 64);
}

// UMULH: bits 127..64 of UInt(n) * UInt(m).
#[operation(UMULH)]
fn umulh(d: Op, n: Op, m: Op) {
    d = bits(zext(n, 128) * zext(m, 128), 64, 64);
}

// UDIV: rounded towards zero; 0 for a zero divisor.
#[operation(UDIV)]
fn udiv_int(d: Op, n: Op, m: Op) {
    d = if m == 0 { 0 } else { udiv(n, m) };
}

// SDIV: rounded towards zero (the most negative value divided by -1 is
// itself, the quotient modulo 2^datasize); 0 for a zero divisor.
#[operation(SDIV)]
fn sdiv_int(d: Op, n: Op, m: Op) {
    d = if m == 0 { 0 } else { sdiv(n, m) };
}

// SMAX (immediate; the immediate sign-extended): Max(SInt(n), SInt(imm)).
#[operation(SMAX_imm)]
fn smax_immediate(d: Op, n: Op, imm: Op) {
    d = if sgt(n, imm) { n } else { imm };
}

// SMAX (register): Max(SInt(n), SInt(m)).
#[operation(SMAX_reg)]
fn smax_register(d: Op, n: Op, m: Op) {
    d = if sgt(n, m) { n } else { m };
}

// SMIN (immediate): Min(SInt(n), SInt(imm)).
#[operation(SMIN_imm)]
fn smin_immediate(d: Op, n: Op, imm: Op) {
    d = if slt(n, imm) { n } else { imm };
}

// SMIN (register): Min(SInt(n), SInt(m)).
#[operation(SMIN_reg)]
fn smin_register(d: Op, n: Op, m: Op) {
    d = if slt(n, m) { n } else { m };
}

// UMAX (immediate; the immediate zero-extended): Max(UInt(n), UInt(imm)).
#[operation(UMAX_imm)]
fn umax_immediate(d: Op, n: Op, imm: Op) {
    d = if n > imm { n } else { imm };
}

// UMAX (register): Max(UInt(n), UInt(m)).
#[operation(UMAX_reg)]
fn umax_register(d: Op, n: Op, m: Op) {
    d = if n > m { n } else { m };
}

// UMIN (immediate): Min(UInt(n), UInt(imm)).
#[operation(UMIN_imm)]
fn umin_immediate(d: Op, n: Op, imm: Op) {
    d = if n < imm { n } else { imm };
}

// UMIN (register): Min(UInt(n), UInt(m)).
#[operation(UMIN_reg)]
fn umin_register(d: Op, n: Op, m: Op) {
    d = if n < m { n } else { m };
}
