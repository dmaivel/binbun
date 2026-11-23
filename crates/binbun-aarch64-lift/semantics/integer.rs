// Integer data processing: add and subtract, logical operations, move wide
// immediates, PC-relative addresses. Parameters are the operands of the
// encoding's own syntax (`subs xzr, x1, #0x5` for `cmp x1, #0x5`); a
// register written with a shift or extension is the shifted or extended
// value (Arm's `ShiftReg`, `ExtendReg`), an immediate the value as written,
// shifted (`#0x5, lsl #12`), a logical immediate the value `DecodeBitMasks`
// gives. `N`, `Z`, `C`, `V` are the condition flags. Immediate and
// register forms are separate entries (an immediate is known when
// lifting), sharing helpers.

// The flags of a result: N its sign, Z whether it is zero.
fn int_nz(r: Op) {
    N = msb(r);
    Z = r == 0;
}

// AddWithCarry(x, y, 0) with its flags: the carry and signed overflow out
// of x + y.
fn int_adds(x: Op, y: Op) {
    let r = x + y;
    int_nz(r);
    C = add_cf(x, y, 0);
    V = add_of(x, y, 0);
    r
}

// AddWithCarry(x, NOT(y), 1) with its flags. Its carry out is 1 unless the
// subtraction borrows (x >= y, unsigned); its overflow is the
// subtraction's signed overflow.
fn int_subs(x: Op, y: Op) {
    let r = x - y;
    int_nz(r);
    C = x >= y;
    V = sub_of(x, y, 0);
    r
}

// AddWithCarry(x, y, carry) with its flags.
fn int_add_with_carry(x: Op, y: Op, carry: Op) {
    let r = x + y + zext(carry, width(x));
    int_nz(r);
    C = add_cf(x, y, carry);
    V = add_of(x, y, carry);
    r
}

// The flags of a logical result: N and Z from it, C and V cleared.
fn int_logical_flags(r: Op) {
    int_nz(r);
    C = 0;
    V = 0;
    r
}

// ADD (immediate), and MOV (to or from SP): AddWithCarry(n, imm, 0), the
// flags unchanged.
#[operation(ADD_addsub_imm)]
fn add_immediate(d: Op, n: Op, imm: Op) {
    d = n + imm;
}

// ADD (shifted register, extended register).
#[operation(ADD_addsub_shift, ADD_addsub_ext)]
fn add_register(d: Op, n: Op, m: Op) {
    d = n + m;
}

// ADDS (immediate), and CMN.
#[operation(ADDS_addsub_imm)]
fn adds_immediate(d: Op, n: Op, imm: Op) {
    d = int_adds(n, imm);
}

// ADDS (shifted register, extended register), and CMN.
#[operation(ADDS_addsub_shift, ADDS_addsub_ext)]
fn adds_register(d: Op, n: Op, m: Op) {
    d = int_adds(n, m);
}

// SUB (immediate), and MOV: AddWithCarry(n, NOT(imm), 1), the flags
// unchanged.
#[operation(SUB_addsub_imm)]
fn sub_immediate(d: Op, n: Op, imm: Op) {
    d = n - imm;
}

// SUB (shifted register, extended register), and NEG.
#[operation(SUB_addsub_shift, SUB_addsub_ext)]
fn sub_register(d: Op, n: Op, m: Op) {
    d = n - m;
}

// SUBS (immediate), and CMP.
#[operation(SUBS_addsub_imm)]
fn subs_immediate(d: Op, n: Op, imm: Op) {
    d = int_subs(n, imm);
}

// SUBS (shifted register, extended register), and CMP, NEGS.
#[operation(SUBS_addsub_shift, SUBS_addsub_ext)]
fn subs_register(d: Op, n: Op, m: Op) {
    d = int_subs(n, m);
}

// ADC: AddWithCarry(n, m, PSTATE.C).
#[operation(ADC)]
fn adc(d: Op, n: Op, m: Op) {
    d = n + m + zext(C, width(n));
}

// ADCS: AddWithCarry(n, m, PSTATE.C) with its flags.
#[operation(ADCS)]
fn adcs(d: Op, n: Op, m: Op) {
    let carry = C;
    d = int_add_with_carry(n, m, carry);
}

// SBC, and NGC: AddWithCarry(n, NOT(m), PSTATE.C).
#[operation(SBC)]
fn sbc(d: Op, n: Op, m: Op) {
    d = n + !m + zext(C, width(n));
}

// SBCS, and NGCS: AddWithCarry(n, NOT(m), PSTATE.C) with its flags.
#[operation(SBCS)]
fn sbcs(d: Op, n: Op, m: Op) {
    let carry = C;
    d = int_add_with_carry(n, !m, carry);
}

// AND (immediate).
#[operation(AND_log_imm)]
fn and_immediate(d: Op, n: Op, imm: Op) {
    d = n & imm;
}

// AND (shifted register).
#[operation(AND_log_shift)]
fn and_register(d: Op, n: Op, m: Op) {
    d = n & m;
}

// ANDS (immediate), and TST.
#[operation(ANDS_log_imm)]
fn ands_immediate(d: Op, n: Op, imm: Op) {
    d = int_logical_flags(n & imm);
}

// ANDS (shifted register), and TST.
#[operation(ANDS_log_shift)]
fn ands_register(d: Op, n: Op, m: Op) {
    d = int_logical_flags(n & m);
}

// BIC (shifted register).
#[operation(BIC_log_shift)]
fn bic(d: Op, n: Op, m: Op) {
    d = n & !m;
}

// BICS (shifted register): as ANDS, with m inverted.
#[operation(BICS)]
fn bics(d: Op, n: Op, m: Op) {
    d = int_logical_flags(n & !m);
}

// ORR (immediate), and MOV (bitmask immediate).
#[operation(ORR_log_imm)]
fn orr_immediate(d: Op, n: Op, imm: Op) {
    d = n | imm;
}

// ORR (shifted register), and MOV (register).
#[operation(ORR_log_shift)]
fn orr_register(d: Op, n: Op, m: Op) {
    d = n | m;
}

// ORN (shifted register), and MVN.
#[operation(ORN_log_shift)]
fn orn(d: Op, n: Op, m: Op) {
    d = n | !m;
}

// EOR (immediate).
#[operation(EOR_log_imm)]
fn eor_immediate(d: Op, n: Op, imm: Op) {
    d = n ^ imm;
}

// EOR (shifted register).
#[operation(EOR_log_shift)]
fn eor_register(d: Op, n: Op, m: Op) {
    d = n ^ m;
}

// EON (shifted register).
#[operation(EON)]
fn eon(d: Op, n: Op, m: Op) {
    d = n ^ !m;
}

// MOVZ, and MOV (wide immediate): the immediate, shifted.
#[operation(MOVZ)]
fn movz(d: Op, imm: Op) {
    d = imm;
}

// MOVN, and MOV (inverted wide immediate): NOT of the shifted immediate.
#[operation(MOVN)]
fn movn(d: Op, imm: Op) {
    d = imm ^ 0xffff_ffff_ffff_ffff;
}

// MOVK: the immediate replaces the 16 bits at `pos` = hw * 16 (`hw`, bits
// 22..21, is the shift written), the other bits kept.
#[operation(MOVK)]
fn movk(d: Op, imm: Op) {
    let kept = (0xffff << (field(21, 2) * 16)) ^ 0xffff_ffff_ffff_ffff;
    d = (d & kept) | imm;
}

// ADR: the instruction's address plus the offset.
#[operation(ADR)]
fn adr(d: Op, label: Op) {
    d = label;
}
