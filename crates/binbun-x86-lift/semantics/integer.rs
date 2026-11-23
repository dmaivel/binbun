// Integer arithmetic, logic, shifts and multiplication.
//
// The semantics language: a strict subset of Rust syntax, parsed by `cargo
// xtask codegen` and never compiled (see `xtask/src/lift/mod.rs`).
// Parameters are the instruction's operands in XED's order, without the
// flags register, the instruction pointer and the stack operands; `osz` is
// the operand size in bits. Flags XED says are set, cleared or left
// undefined are filled in unless an entry computes them.
// Each `undefined()` is a site (`crate::site`) named after the entry and
// the output it is assigned to (`shrd.of`); where it is not assigned to an
// operand, flag or register, a last argument names it: `undefined("dst")`.
//
// `cargo fmt` does not see these files: format them with
// `rustfmt --edition 2024 crates/binbun-x86-lift/semantics/*.rs`.

#[iclass(ADD, ADD_LOCK)]
fn add(dst: Op, src: Op) {
    dst = addition(dst, src);
}

// `a + b`, setting the flags as ADD does.
fn addition(a: Op, b: Op) -> Op {
    let r = a + b;
    cf = add_cf(a, b, 0);
    of = add_of(a, b, 0);
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    af = aux_carry(a, b, r);
    r
}

#[iclass(ADC, ADC_LOCK)]
fn adc(dst: Op, src: Op) {
    let carry = zext(cf, osz);
    let r = dst + src + carry;
    cf = add_cf(dst, src, carry);
    of = add_of(dst, src, carry);
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    af = aux_carry(dst, src, r);
    dst = r;
}

#[iclass(SUB, SUB_LOCK)]
fn sub(dst: Op, src: Op) {
    dst = subtract(dst, src);
}

// `a - b`, setting the flags as CMP does.
fn subtract(a: Op, b: Op) -> Op {
    let r = a - b;
    cf = sub_cf(a, b, 0);
    of = sub_of(a, b, 0);
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    af = aux_carry(a, b, r);
    r
}

#[iclass(SBB, SBB_LOCK)]
fn sbb(dst: Op, src: Op) {
    let borrow = zext(cf, osz);
    let r = dst - src - borrow;
    cf = sub_cf(dst, src, borrow);
    of = sub_of(dst, src, borrow);
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    af = aux_carry(dst, src, r);
    dst = r;
}

#[iclass(CMP)]
fn cmp(a: Op, b: Op) {
    subtract(a, b);
}

#[iclass(INC, INC_LOCK)]
fn inc(dst: Op) {
    let r = dst + 1;
    of = add_of(dst, 1, 0);
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    af = aux_carry(dst, 1, r);
    dst = r;
}

#[iclass(DEC, DEC_LOCK)]
fn dec(dst: Op) {
    let r = dst - 1;
    of = sub_of(dst, 1, 0);
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    af = aux_carry(dst, 1, r);
    dst = r;
}

#[iclass(NEG, NEG_LOCK)]
fn neg(dst: Op) {
    let r = -dst;
    cf = dst != 0;
    of = sub_of(0, dst, 0);
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    af = aux_carry(0, dst, r);
    dst = r;
}

#[iclass(NOT, NOT_LOCK)]
fn not(dst: Op) {
    dst = !dst;
}

// AND, OR, XOR and TEST clear OF and CF and leave AF undefined (XED).
#[iclass(AND, AND_LOCK)]
fn and(dst: Op, src: Op) {
    let r = dst & src;
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    dst = r;
}

#[iclass(OR, OR_LOCK)]
fn or(dst: Op, src: Op) {
    let r = dst | src;
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    dst = r;
}

#[iclass(XOR, XOR_LOCK)]
fn xor(dst: Op, src: Op) {
    let r = dst ^ src;
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
    dst = r;
}

#[iclass(TEST)]
fn test(a: Op, b: Op) {
    let r = a & b;
    sf = msb(r);
    zf = r == 0;
    pf = parity8(r);
}

// Shifts: the count is masked to 5 bits (6 for 64-bit operands); a count
// of 0 leaves the flags alone but still writes the destination (a 32-bit
// destination's upper half is cleared; measured). CF is undefined for
// counts of the operand size or more (only 8- and 16-bit operands have
// those: the masked count is below 32 or 64), OF for counts other than 1,
// AF always (SDM).
#[iclass(SHL)]
fn shl(dst: Op, count: Op) {
    let n = fit(count, osz) & if osz == 64 { 63 } else { 31 };
    let r = dst << n;
    if n != 0 {
        let carry = bit(dst, osz - n);
        cf = if osz <= 16 {
            if n < osz { carry } else { undefined() }
        } else {
            carry
        };
        of = if n == 1 { msb(r) ^ cf } else { undefined() };
        sf = msb(r);
        zf = r == 0;
        pf = parity8(r);
        af = undefined();
    }
    dst = r;
}

#[iclass(SHR)]
fn shr(dst: Op, count: Op) {
    let n = fit(count, osz) & if osz == 64 { 63 } else { 31 };
    let r = dst >> n;
    if n != 0 {
        let carry = bit(dst, n - 1);
        cf = if osz <= 16 {
            if n < osz { carry } else { undefined() }
        } else {
            carry
        };
        of = if n == 1 { msb(dst) } else { undefined() };
        sf = msb(r);
        zf = r == 0;
        pf = parity8(r);
        af = undefined();
    }
    dst = r;
}

#[iclass(SAR)]
fn sar(dst: Op, count: Op) {
    let n = fit(count, osz) & if osz == 64 { 63 } else { 31 };
    let r = sar(dst, n);
    if n != 0 {
        cf = if n < osz { bit(dst, n - 1) } else { msb(dst) };
        of = if n == 1 { 0 } else { undefined() };
        sf = msb(r);
        zf = r == 0;
        pf = parity8(r);
        af = undefined();
    }
    dst = r;
}

// Two- and three-operand IMUL: the low half of the signed product; CF and
// OF say whether it lost bits. SF, ZF, AF and PF are undefined (XED).
#[iform(IMUL_GPRv_GPRv, IMUL_GPRv_MEMv)]
fn imul2(dst: Op, src: Op) {
    let product = sext(dst, osz * 2) * sext(src, osz * 2);
    let r = trunc(product, osz);
    cf = sext(r, osz * 2) != product;
    of = cf;
    dst = r;
}

#[iform(
    IMUL_GPRv_GPRv_IMMb,
    IMUL_GPRv_GPRv_IMMz,
    IMUL_GPRv_MEMv_IMMb,
    IMUL_GPRv_MEMv_IMMz
)]
fn imul3(dst: Op, src: Op, factor: Op) {
    let product = sext(src, osz * 2) * sext(factor, osz * 2);
    let r = trunc(product, osz);
    cf = sext(r, osz * 2) != product;
    of = cf;
    dst = r;
}

// One-operand MUL and IMUL: the double-width product in AX (bytes) or
// rDX:rAX; CF and OF say whether the high half is needed.
#[iform(MUL_GPR8, MUL_MEMb)]
fn mul8(src: Op, al: Op, ax: Op) {
    let product = zext(al, 16) * zext(src, 16);
    cf = bits(product, 8, 8) != 0;
    of = cf;
    ax = product;
}

#[iform(MUL_GPRv, MUL_MEMv)]
fn mul(src: Op, lo: Op, hi: Op) {
    let product = zext(lo, osz * 2) * zext(src, osz * 2);
    cf = bits(product, osz, osz) != 0;
    of = cf;
    lo = trunc(product, osz);
    hi = bits(product, osz, osz);
}

#[iform(IMUL_GPR8, IMUL_MEMb)]
fn imul8(src: Op, al: Op, ax: Op) {
    let product = sext(al, 16) * sext(src, 16);
    cf = sext(trunc(product, 8), 16) != product;
    of = cf;
    ax = product;
}

#[iform(IMUL_GPRv, IMUL_MEMv)]
fn imul1(src: Op, lo: Op, hi: Op) {
    let product = sext(lo, osz * 2) * sext(src, osz * 2);
    let r = trunc(product, osz);
    cf = sext(r, osz * 2) != product;
    of = cf;
    lo = r;
    hi = bits(product, osz, osz);
}

// DIV and IDIV: #DE for a zero divisor or a quotient that does not fit;
// the quotient truncates toward zero and the remainder has the dividend's
// sign. All flags are undefined.
#[iform(DIV_GPR8, DIV_MEMb)]
fn div8(src: Op, ax: Op) {
    let divisor = zext(src, 16);
    if divisor == 0 {
        trap(DE);
    }
    let quotient = udiv(ax, divisor);
    if bits(quotient, 8, 8) != 0 {
        trap(DE);
    }
    ax = concat(trunc(urem(ax, divisor), 8), trunc(quotient, 8));
}

#[iform(DIV_GPRv, DIV_MEMv)]
fn div(src: Op, lo: Op, hi: Op) {
    let divisor = zext(src, osz * 2);
    if divisor == 0 {
        trap(DE);
    }
    let dividend = concat(hi, lo);
    let quotient = udiv(dividend, divisor);
    if bits(quotient, osz, osz) != 0 {
        trap(DE);
    }
    lo = trunc(quotient, osz);
    hi = trunc(urem(dividend, divisor), osz);
}

#[iform(IDIV_GPR8, IDIV_MEMb)]
fn idiv8(src: Op, ax: Op) {
    let divisor = sext(src, 16);
    if divisor == 0 {
        trap(DE);
    }
    let quotient = sdiv(ax, divisor);
    if sext(trunc(quotient, 8), 16) != quotient {
        trap(DE);
    }
    ax = concat(trunc(srem(ax, divisor), 8), trunc(quotient, 8));
}

#[iform(IDIV_GPRv, IDIV_MEMv)]
fn idiv(src: Op, lo: Op, hi: Op) {
    let divisor = sext(src, osz * 2);
    if divisor == 0 {
        trap(DE);
    }
    let dividend = concat(hi, lo);
    let quotient = sdiv(dividend, divisor);
    if sext(trunc(quotient, osz), osz * 2) != quotient {
        trap(DE);
    }
    lo = trunc(quotient, osz);
    hi = trunc(srem(dividend, divisor), osz);
}

// CBW, CWDE, CDQE: the low half of rAX, sign-extended.
#[iclass(CBW, CWDE, CDQE)]
fn widen(dst: Op, src: Op) {
    dst = sext(src, osz);
}

// CWD, CDQ, CQO: rDX filled with rAX's sign.
#[iclass(CWD, CDQ, CQO)]
fn widen_into(hi: Op, lo: Op) {
    hi = sar(lo, osz - 1);
}

// Rotates: the count is masked like a shift's; RCL and RCR rotate through
// CF (an operand-size-plus-one-bit rotation). A masked count of 0 leaves
// the flags alone but still writes the destination. OF is undefined for
// counts other than 1 (SDM).
#[iclass(ROL)]
fn rotate_left(dst: Op, count: Op) {
    let n = fit(count, osz) & if osz == 64 { 63 } else { 31 };
    let r = rol(dst, n);
    if n != 0 {
        cf = bit(r, 0);
        of = if n == 1 { msb(r) ^ cf } else { undefined() };
    }
    dst = r;
}

#[iclass(ROR)]
fn rotate_right(dst: Op, count: Op) {
    let n = fit(count, osz) & if osz == 64 { 63 } else { 31 };
    let r = ror(dst, n);
    if n != 0 {
        cf = msb(r);
        of = if n == 1 {
            msb(r) ^ bit(r, osz - 2)
        } else {
            undefined()
        };
    }
    dst = r;
}

#[iclass(RCL)]
fn rotate_carry_left(dst: Op, count: Op) {
    let n = fit(count, osz) & if osz == 64 { 63 } else { 31 };
    let rotated = rol(concat(cf, dst), n);
    let r = trunc(rotated, osz);
    if n != 0 {
        cf = msb(rotated);
        of = if n == 1 { msb(r) ^ cf } else { undefined() };
    }
    dst = r;
}

#[iclass(RCR)]
fn rotate_carry_right(dst: Op, count: Op) {
    let n = fit(count, osz) & if osz == 64 { 63 } else { 31 };
    let rotated = ror(concat(cf, dst), n);
    let r = trunc(rotated, osz);
    if n != 0 {
        of = if n == 1 { msb(dst) ^ cf } else { undefined() };
        cf = msb(rotated);
    }
    dst = r;
}

// SHLD and SHRD shift the destination, filling from the source. Counts
// past the operand size (16-bit operands only) leave the result and flags
// undefined (SDM); the result's site is the destination's (`undefined("dst")`).
#[iclass(SHLD)]
fn shld(dst: Op, src: Op, count: Op) {
    let n = fit(count, osz) & if osz == 64 { 63 } else { 31 };
    let shifted = bits(concat(dst, src) << n, osz, osz);
    let r = if osz == 16 {
        if n <= osz { shifted } else { undefined("dst") }
    } else {
        shifted
    };
    if n != 0 {
        let carry = bit(dst, osz - n);
        cf = if osz == 16 {
            if n <= osz { carry } else { undefined() }
        } else {
            carry
        };
        of = if n == 1 {
            msb(r) ^ msb(dst)
        } else {
            undefined()
        };
        sf = msb(r);
        zf = r == 0;
        pf = parity8(r);
        af = undefined();
    }
    dst = r;
}

#[iclass(SHRD)]
fn shrd(dst: Op, src: Op, count: Op) {
    let n = fit(count, osz) & if osz == 64 { 63 } else { 31 };
    let shifted = trunc(concat(src, dst) >> n, osz);
    let r = if osz == 16 {
        if n <= osz { shifted } else { undefined("dst") }
    } else {
        shifted
    };
    if n != 0 {
        let carry = bit(dst, n - 1);
        cf = if osz == 16 {
            if n <= osz { carry } else { undefined() }
        } else {
            carry
        };
        of = if n == 1 {
            msb(r) ^ msb(dst)
        } else {
            undefined()
        };
        sf = msb(r);
        zf = r == 0;
        pf = parity8(r);
        af = undefined();
    }
    dst = r;
}

// XADD: the destination gets the sum, the source the old destination.
#[iclass(XADD, XADD_LOCK)]
fn xadd(dst: Op, src: Op) {
    let r = addition(dst, src);
    src = dst;
    dst = r;
}

// CMPXCHG compares the accumulator with the destination (flags as CMP). If
// equal, the destination gets the source; otherwise the accumulator gets
// the destination. A memory destination is then written back unchanged; a
// register one is not written at all (a 32-bit one keeps its upper half;
// measured).
#[iclass(CMPXCHG, CMPXCHG_LOCK)]
fn cmpxchg(dst: Op, src: Op, acc: Op) {
    if subtract(acc, dst) == 0 {
        dst = src;
    } else {
        acc = dst;
        dst = dst;
    }
}

// CMPXCHG8B and CMPXCHG16B compare edx:eax (rdx:rax) with memory; if
// equal, memory gets ecx:ebx (rcx:rbx), otherwise the pair gets memory,
// which is written back unchanged. The runtime checks CMPXCHG16B's
// alignment (XED's REQUIRES_ALIGNMENT).
#[iclass(CMPXCHG8B, CMPXCHG8B_LOCK, CMPXCHG16B, CMPXCHG16B_LOCK)]
fn cmpxchg_pair(mem: Op, hi: Op, lo: Op, new_hi: Op, new_lo: Op) {
    let half = if osz == 64 { 64 } else { 32 };
    let equal = mem == concat(hi, lo);
    zf = equal;
    if equal {
        mem = concat(new_hi, new_lo);
    } else {
        lo = trunc(mem, half);
        hi = bits(mem, half, half);
        mem = mem;
    }
}

#[iform(CMPXCHG_GPR8_GPR8, CMPXCHG_GPRv_GPRv)]
fn cmpxchg_register(dst: Op, src: Op, acc: Op) {
    if subtract(acc, dst) == 0 {
        dst = src;
    } else {
        acc = dst;
    }
}

// BSF and BSR leave the destination unchanged for a zero source (the SDM
// says undefined; the processors leave it).
#[iclass(BSF)]
fn bsf(dst: Op, src: Op) {
    zf = src == 0;
    if src != 0 {
        dst = ctz(src);
    }
}

#[iclass(BSR)]
fn bsr(dst: Op, src: Op) {
    zf = src == 0;
    if src != 0 {
        dst = osz - 1 - clz(src);
    }
}

#[iclass(TZCNT)]
fn tzcnt(dst: Op, src: Op) {
    let n = ctz(src);
    cf = src == 0;
    zf = n == 0;
    dst = n;
}

#[iclass(LZCNT)]
fn lzcnt(dst: Op, src: Op) {
    let n = clz(src);
    cf = src == 0;
    zf = n == 0;
    dst = n;
}

#[iclass(POPCNT)]
fn popcnt(dst: Op, src: Op) {
    zf = src == 0;
    dst = popcount(src);
}

// BT, BTS, BTR, BTC with a register or immediate offset, taken modulo the
// operand size. (With a memory base and a register offset, the offset
// addresses a bit string past the operand; those forms are not covered.)
#[iform(BT_GPRv_GPRv, BT_GPRv_IMMb, BT_MEMv_IMMb)]
fn bt(base: Op, offset: Op) {
    cf = bit(base, fit(offset, osz) & (osz - 1));
}

#[iform(BTS_GPRv_GPRv, BTS_GPRv_IMMb, BTS_MEMv_IMMb, BTS_LOCK_MEMv_IMMb)]
fn bts(base: Op, offset: Op) {
    let n = fit(offset, osz) & (osz - 1);
    cf = bit(base, n);
    base = base | (fit(1, osz) << n);
}

#[iform(BTR_GPRv_GPRv, BTR_GPRv_IMMb, BTR_MEMv_IMMb, BTR_LOCK_MEMv_IMMb)]
fn btr(base: Op, offset: Op) {
    let n = fit(offset, osz) & (osz - 1);
    cf = bit(base, n);
    base = base & !(fit(1, osz) << n);
}

#[iform(BTC_GPRv_GPRv, BTC_GPRv_IMMb, BTC_MEMv_IMMb, BTC_LOCK_MEMv_IMMb)]
fn btc(base: Op, offset: Op) {
    let n = fit(offset, osz) & (osz - 1);
    cf = bit(base, n);
    base = base ^ (fit(1, osz) << n);
}

// BSWAP of a 16-bit operand is undefined (SDM).
#[iclass(BSWAP)]
fn byte_swap(dst: Op) {
    dst = if osz == 16 { undefined() } else { bswap(dst) };
}

#[iclass(MOVBE)]
fn movbe(dst: Op, src: Op) {
    dst = bswap(src);
}

// BMI1, BMI2 and ADX.
#[iclass(ANDN)]
fn andn(dst: Op, a: Op, b: Op) {
    let r = !a & b;
    sf = msb(r);
    zf = r == 0;
    dst = r;
}

#[iclass(BLSI)]
fn blsi(dst: Op, src: Op) {
    let r = src & -src;
    cf = src != 0;
    sf = msb(r);
    zf = r == 0;
    dst = r;
}

#[iclass(BLSMSK)]
fn blsmsk(dst: Op, src: Op) {
    let r = src ^ (src - 1);
    cf = src == 0;
    sf = msb(r);
    dst = r;
}

#[iclass(BLSR)]
fn blsr(dst: Op, src: Op) {
    let r = src & (src - 1);
    cf = src == 0;
    sf = msb(r);
    zf = r == 0;
    dst = r;
}

// BEXTR: `length` bits from bit `start` (both from the control operand);
// bits past the operand are 0.
#[iclass(BEXTR)]
fn bextr(dst: Op, src: Op, control: Op) {
    let start = bits(control, 0, 8);
    let length = bits(control, 8, 8);
    let r = (src >> start) & ((fit(1, osz) << length) - 1);
    zf = r == 0;
    dst = r;
}

// BZHI: the bits from `index` up cleared; CF says the index was past the
// operand.
#[iclass(BZHI)]
fn bzhi(dst: Op, src: Op, index: Op) {
    let n = bits(index, 0, 8);
    let r = src & ((fit(1, osz) << n) - 1);
    cf = n >= osz;
    sf = msb(r);
    zf = r == 0;
    dst = r;
}

#[iclass(SHLX)]
fn shlx(dst: Op, src: Op, count: Op) {
    dst = src << (count & if osz == 64 { 63 } else { 31 });
}

#[iclass(SHRX)]
fn shrx(dst: Op, src: Op, count: Op) {
    dst = src >> (count & if osz == 64 { 63 } else { 31 });
}

#[iclass(SARX)]
fn sarx(dst: Op, src: Op, count: Op) {
    dst = sar(src, count & if osz == 64 { 63 } else { 31 });
}

#[iclass(RORX)]
fn rorx(dst: Op, src: Op, count: Op) {
    dst = ror(src, fit(count, osz) & if osz == 64 { 63 } else { 31 });
}

// MULX: rDX times the source, unsigned, flags untouched; if both
// destinations are one register it gets the high half.
#[iclass(MULX)]
fn mulx(hi: Op, lo: Op, src: Op, multiplier: Op) {
    let product = zext(multiplier, osz * 2) * zext(src, osz * 2);
    lo = trunc(product, osz);
    hi = bits(product, osz, osz);
}

#[iclass(ADCX)]
fn adcx(dst: Op, src: Op) {
    let carry = zext(cf, osz);
    cf = add_cf(dst, src, carry);
    dst = dst + src + carry;
}

#[iclass(ADOX)]
fn adox(dst: Op, src: Op) {
    let carry = zext(of, osz);
    of = add_cf(dst, src, carry);
    dst = dst + src + carry;
}
