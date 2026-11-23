// Branches and PC-relative addresses. A label is the address it names (the
// instruction's address, or its 4 KiB page for ADRP, plus the offset);
// targets have their top byte ignored by the runtime, as Arm's `BranchTo`
// does at EL0 under Linux. BTYPE is 0 after an instruction unless its
// entry sets it (`BTypeNext`; no page is guarded, so BR is always 01).

// ADRP: the page of the instruction plus the label's page offset.
#[operation(ADRP)]
fn adrp(d: Op, label: Op) {
    d = label;
}

// B.
#[operation(B_uncond)]
fn b(label: Op) {
    jump(label);
}

// BL: x30 holds the address of the next instruction.
#[operation(BL)]
fn bl(label: Op) {
    x30 = next();
    call(label);
}

// B.cond: `ConditionHolds(cond)`, the encoding's condition.
#[operation(B_cond)]
fn b_cond(label: Op) {
    if cond() {
        jump(label);
    }
}

// BC.cond: as B.cond (the hint that the branch behaves consistently has no
// architectural effect).
#[operation(BC_cond)]
fn bc_cond(label: Op) {
    if cond() {
        jump(label);
    }
}

// CBZ.
#[operation(CBZ)]
fn cbz(t: Op, label: Op) {
    if t == 0 {
        jump(label);
    }
}

// CBNZ.
#[operation(CBNZ)]
fn cbnz(t: Op, label: Op) {
    if t != 0 {
        jump(label);
    }
}

// TBZ: bit `b` of `t` (a `w` register for bits below 32) clear.
#[operation(TBZ)]
fn tbz(t: Op, b: Op, label: Op) {
    if bit(t, b) == 0 {
        jump(label);
    }
}

// TBNZ: bit `b` of `t` set.
#[operation(TBNZ)]
fn tbnz(t: Op, b: Op, label: Op) {
    if bit(t, b) == 1 {
        jump(label);
    }
}

// CB<cc> and its relatives: `ConditionHolds(cond)` on the flags of
// `AddWithCarry(a, NOT(b), 1)`, which are not written.
fn compare_branch(a: Op, b: Op, label: Op) {
    let r = a - b;
    if holds(msb(r), r == 0, a >= b, sub_of(a, b, 0)) {
        jump(label);
    }
}

// CB<cc> (register).
#[operation(CBcc_regs)]
fn cb_registers(t: Op, m: Op, label: Op) {
    compare_branch(t, m, label);
}

// CB<cc> (immediate): the unsigned 6-bit immediate at the register's width.
#[operation(CBcc_imm)]
fn cb_immediate(t: Op, imm: Op, label: Op) {
    compare_branch(t, imm, label);
}

// CBB<cc>: the low bytes, extended as the condition's signedness wants
// (which compares them as bytes: the flags of the byte subtraction).
#[operation(CBBcc_regs)]
fn cbb(t: Op, m: Op, label: Op) {
    compare_branch(bits(t, 0, 8), bits(m, 0, 8), label);
}

// CBH<cc>: the low halfwords, likewise.
#[operation(CBHcc_regs)]
fn cbh(t: Op, m: Op, label: Op) {
    compare_branch(bits(t, 0, 16), bits(m, 0, 16), label);
}

// BR: BTYPE 01.
#[operation(BR)]
fn br(n: Op) {
    btype = 1;
    jump(n);
}

// BLR: x30 holds the address of the next instruction (`n` is read first);
// BTYPE 10.
#[operation(BLR)]
fn blr(n: Op) {
    btype = 2;
    x30 = next();
    call(n);
}

// RET: to `n` (x30 when the syntax omits it).
#[operation(RET)]
fn ret_register(n: Op) {
    ret(n);
}

// SVC: the supervisor call (Linux: the system call in x8).
#[operation(SVC)]
fn svc(imm: Op) {
    system_call();
}

// BRK: the breakpoint exception.
#[operation(BRK)]
fn brk(imm: Op) {
    trap(BRK);
}

// HLT: halting debug is not allowed at EL0 under Linux (`EDSCR.HDE` is 0),
// so HLT is UNDEFINED.
#[operation(HLT)]
fn hlt(imm: Op) {
    trap(UNDEFINED);
}

// UDF: permanently UNDEFINED.
#[operation(UDF_perm_undef)]
fn udf(imm: Op) {
    trap(UNDEFINED);
}
