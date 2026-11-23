// Moves, address computation, exchange, the stack, and conditional moves
// and sets.

#[iclass(MOV)]
fn mov(dst: Op, src: Op) {
    dst = src;
}

// The address at the address size, fitted to the operand size.
#[iclass(LEA)]
fn lea(dst: Op, address: Op) {
    dst = fit(address, osz);
}

#[iclass(MOVZX)]
fn movzx(dst: Op, src: Op) {
    dst = zext(src, osz);
}

#[iclass(MOVSX, MOVSXD)]
fn movsx(dst: Op, src: Op) {
    dst = sext(src, osz);
}

#[iclass(XCHG)]
fn xchg(a: Op, b: Op) {
    let old = a;
    a = b;
    b = old;
}

#[iform(NOP_90)]
fn nop() {}

// Multi-byte NOPs, and the reserved-NOP opcodes (0F 0D and 0F 18 to 0F 1F
// where they are not hints): they access nothing, not even their memory
// operand. ENDBR and PAUSE do nothing a program can see.
#[iform(
    NOP_GPRv_0F18r0,
    NOP_GPRv_0F18r1,
    NOP_GPRv_0F18r2,
    NOP_GPRv_0F18r3,
    NOP_GPRv_0F18r4,
    NOP_GPRv_0F18r5,
    NOP_GPRv_0F18r6,
    NOP_GPRv_0F18r7,
    NOP_GPRv_0F1F,
    NOP_MEMv_0F18r4,
    NOP_MEMv_0F18r5,
    NOP_MEMv_0F18r6,
    NOP_MEMv_0F18r7,
    NOP_MEMv_0F1F
)]
fn nop1(_operand: Op) {}

#[iform(
    NOP_GPRv_GPRv_0F0D,
    NOP_GPRv_GPRv_0F19,
    NOP_GPRv_GPRv_0F1A,
    NOP_GPRv_GPRv_0F1B,
    NOP_GPRv_GPRv_0F1C,
    NOP_GPRv_GPRv_0F1D,
    NOP_GPRv_GPRv_0F1E,
    NOP_GPRv_MEM_0F1B,
    NOP_GPRv_MEMv_0F1A,
    NOP_MEMv_GPRv_0F19,
    NOP_MEMv_GPRv_0F1C,
    NOP_MEMv_GPRv_0F1D,
    NOP_MEMv_GPRv_0F1E
)]
fn nop2(_a: Op, _b: Op) {}

#[iclass(ENDBR32, ENDBR64, PAUSE)]
fn hint() {}

// Prefetches are hints: they never fault and change nothing a program can
// see, so the address operand is not accessed.
#[iclass(
    PREFETCHT0,
    PREFETCHT1,
    PREFETCHT2,
    PREFETCHNTA,
    PREFETCHW,
    PREFETCHWT1,
    PREFETCH_EXCLUSIVE,
    PREFETCH_RESERVED
)]
fn prefetch(_address: Op) {}

#[iclass(PUSH)]
fn push_value(src: Op) {
    push(src);
}

// The stack pointer moves before the destination is written, so `pop rsp`
// leaves the popped value in rsp.
#[iclass(POP)]
fn pop_value(dst: Op) {
    dst = pop();
}

// LEAVE: the stack pointer gets the frame pointer, then the frame pointer
// is popped (`saved`, at the old frame pointer). The stack pointer is the
// stack address size's, whatever the operand size.
#[iclass(LEAVE)]
fn leave(saved: Op, bp: Op, sp: Op) {
    if osz == ssz {
        sp = bp + osz / 8;
    } else if ssz == 64 {
        rsp = rbp + osz / 8;
    } else {
        esp = ebp + osz / 8;
    }
    bp = saved;
}

// A 32-bit CMOVcc writes its destination (clearing the upper half) even if
// the condition does not hold.
#[iclass(
    CMOVO, CMOVNO, CMOVB, CMOVNB, CMOVZ, CMOVNZ, CMOVBE, CMOVNBE, CMOVS, CMOVNS, CMOVP, CMOVNP,
    CMOVL, CMOVNL, CMOVLE, CMOVNLE
)]
fn cmovcc(dst: Op, src: Op) {
    dst = if cond() { src } else { dst };
}

#[iclass(
    SETO, SETNO, SETB, SETNB, SETZ, SETNZ, SETBE, SETNBE, SETS, SETNS, SETP, SETNP, SETL, SETNL,
    SETLE, SETNLE
)]
fn setcc(dst: Op) {
    dst = zext(cond(), 8);
}

// LAHF and SAHF: AH is SF:ZF:0:AF:0:PF:1:CF.
#[iclass(LAHF)]
fn lahf(ah: Op) {
    ah =
        zext(sf, 8) << 7 | zext(zf, 8) << 6 | zext(af, 8) << 4 | zext(pf, 8) << 2 | 2 | zext(cf, 8);
}

#[iclass(SAHF)]
fn sahf(ah: Op) {
    sf = bit(ah, 7);
    zf = bit(ah, 6);
    af = bit(ah, 4);
    pf = bit(ah, 2);
    cf = bit(ah, 0);
}

// CLC, STC, CLD, STD: XED's records set or clear the flag.
#[iclass(CLC, STC, CLD, STD)]
fn set_flag() {}

#[iclass(CMC)]
fn cmc() {
    cf = !cf;
}
