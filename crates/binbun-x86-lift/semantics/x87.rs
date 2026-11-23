// The x87 floating-point unit: x86's rules around L0's IEEE operations on
// the 80-bit extended format.
//
// State: the physical registers `fpr0`-`fpr7`; `st(i)` is physical
// register (TOP + i) mod 8. `ftw` has a bit per physical register (in use);
// `fsw` holds the exception flags IE, DE, ZE, OE, UE, PE (bits 0 to 5), the
// stack fault SF (6), the error summary ES (7) and busy B (15); TOP and the
// condition codes C0-C3 are registers of their own. The control word `fcw`
// has the exception masks (bits 0 to 5), the precision (8 and 9: 24, -, 53
// or 64 bits) and the rounding (10 and 11, in the order of L0's rounding
// operand).
//
// - Stack faults: reading an empty register underflows, pushing onto a
//   full one (st(7) in use) overflows; both raise IE and SF, with C1 0 for
//   underflow and 1 for overflow. Masked, the instruction goes on with the
//   QNaN indefinite as the value; unmasked, nothing else changes.
// - An unmasked invalid-operation, denormal-operand or divide-by-zero
//   exception leaves the destination and the stack as they were. An
//   unmasked overflow or underflow on a register result stores it with the
//   exponent adjusted by 24576 (tiny results raise UE even when exact); on a
//   store to memory nothing is written and nothing popped.
// - An unmasked exception does not fault at the instruction: it sets ES and
//   B, and the next waiting x87 instruction raises #MF (`x87_wait`).
//   FNINIT, FNCLEX, FNSTSW, FNSTCW, FNSTENV, FNSAVE, FXSAVE, FXRSTOR and the
//   8087/287 no-ops do not wait; FNOP, FWAIT and FLDCW do (measured).
// - DE: a denormal operand, unless an operand is a NaN or unsupported or
//   the operation raises IE or ZE (measured). Stores (FST, FIST, FISTTP,
//   FBSTP) do not raise it, and FLD of a denormal single or double loads
//   it even with DE unmasked (measured).
// - A store to memory that does not happen (an unmasked exception) still
//   accesses the destination on the E-cores, which fault if the page is
//   not there; the P-cores do not (measured). L0 cannot leave a fault
//   undefined, so it follows the E-cores, where it is checked (`probe`).
// - C1 is 1 if the result was rounded up (its magnitude increased).
// - Unnormals, pseudo-NaNs and pseudo-infinities are invalid operands;
//   pseudo-denormals are denormals (their value is that of exponent 1).
// - NaNs: an operation with NaN operands gives the QNaN of a QNaN operand
//   over an SNaN, else the one with the larger significand (positive if
//   they are equal); invalid operations on numbers give the indefinite.
// - Precision control rounds the significand of FADD, FSUB, FMUL, FDIV
//   (and their variants) and FSQRT to 24 or 53 bits, keeping the exponent
//   range; tiny results are denormalized first and rounded at the same
//   significand bit. The reserved precision 1 is 64 bits.
//
// L0 computes an operation on operands scaled near 1 (where nothing
// overflows or underflows), rounded as the control word says and toward
// zero; `x87_round` puts the exponent back and does x86's rounding at the
// precision, the overflow and underflow responses and C1 exactly.
//
// Not modelled: the last-instruction and last-data pointers and the last
// opcode (`undefined()` in the environment and state images).

// ---- The format.

fn x87_unsupported(x: Op) {
    bits(x, 64, 15) != 0 && bit(x, 63) == 0
}

fn x87_nan(x: Op) {
    bits(x, 64, 15) == 0x7fff && bit(x, 63) == 1 && bits(x, 0, 63) != 0
}

fn x87_snan(x: Op) {
    x87_nan(x) && bit(x, 62) == 0
}

fn x87_infinity(x: Op) {
    bits(x, 64, 15) == 0x7fff && bits(x, 0, 64) == 0x8000_0000_0000_0000
}

fn x87_zero(x: Op) {
    bits(x, 0, 79) == 0
}

// A denormal or pseudo-denormal.
fn x87_denormal(x: Op) {
    bits(x, 64, 15) == 0 && bits(x, 0, 64) != 0
}

// Sign (1 bit), biased exponent (32 bits, the low 15 kept), significand.
fn x87_pack(sign: Op, exponent: Op, significand: Op) {
    concat(concat(sign, trunc(exponent, 15)), significand)
}

// The QNaN floating-point indefinite: negative, quiet, payload 0.
fn x87_indefinite() {
    concat(zext(0xffff, 16), zext(0xc000_0000_0000_0000, 64))
}

fn x87_one() {
    concat(zext(0x3fff, 16), zext(0x8000_0000_0000_0000, 64))
}

fn x87_quiet(x: Op) {
    x | (1 << 62)
}

fn x87_no() {
    zext(0, 1)
}

// The true exponent of a finite nonzero number (32 bits): that of its
// significand normalized.
fn x87_true_exponent(x: Op) {
    let e = zext(bits(x, 64, 15), 32);
    e + zext(e == 0, 32) - 16383 - trunc(clz(bits(x, 0, 64)), 32)
}

fn x87_normalized(x: Op) {
    bits(x, 0, 64) << clz(bits(x, 0, 64))
}

// A finite nonzero number scaled to the true exponent `e` (32 bits).
fn x87_scaled(x: Op, e: Op) {
    x87_pack(bit(x, 79), zext(16383, 32) + e, x87_normalized(x))
}

fn x87_floor(d: Op) {
    if slt(d, zext(0, 32) - 100) {
        zext(0, 32) - 100
    } else {
        d
    }
}

// The x87 NaN of an operation on `a` and `b`, one of them a NaN.
fn x87_propagate(a: Op, b: Op) {
    let qa = x87_quiet(a);
    let qb = x87_quiet(b);
    let larger = if bits(qa, 0, 64) > bits(qb, 0, 64) {
        qa
    } else if bits(qb, 0, 64) > bits(qa, 0, 64) {
        qb
    } else if bit(a, 79) == 0 {
        qa
    } else {
        qb
    };
    if x87_snan(a) {
        if x87_snan(b) {
            larger
        } else if x87_nan(b) {
            qb
        } else {
            qa
        }
    } else if x87_nan(a) {
        if x87_nan(b) && !x87_snan(b) {
            larger
        } else {
            qa
        }
    } else {
        qb
    }
}

// A single (32) or double (64) `x` in the 80-bit format: NaNs keep their
// payload and stay signalling.
fn x87_extend(x: Op, w: Op) {
    if w == 80 {
        x
    } else if is_nan(x, w) {
        concat(
            concat(msb(x), zext(0xffff, 16)),
            zext(bits(x, 0, fraction(w)), 63) << (63 - fraction(w)),
        )
    } else {
        fcvt(x, 80, 0)
    }
}

fn x87_source_denormal(x: Op, w: Op) {
    if w == 80 {
        x87_denormal(x)
    } else {
        is_denormal(x, w)
    }
}

// The exception flags, in the status word's order.
fn x87_flags(ie: Op, de: Op, ze: Op, oe: Op, ue: Op, pe: Op) {
    concat(concat(concat(pe, ue), concat(oe, ze)), concat(de, ie))
}

// ---- The stack.

// Whether st(i) is empty (never for i = 8, which is no register).
fn x87_empty(i: Op) {
    if i < 8 {
        bit(ftw, ftop + i) == 0
    } else {
        x87_no()
    }
}

fn x87_tag(i: Op) {
    ftw = ftw | (zext(1, 8) << zext(ftop + i, 8));
}

fn x87_free(i: Op) {
    ftw = ftw & !(zext(1, 8) << zext(ftop + i, 8));
}

fn x87_push() {
    fpush();
    x87_tag(0);
}

fn x87_pop() {
    x87_free(0);
    fpop();
}

// A waiting instruction first raises #MF for a pending unmasked exception.
fn x87_wait() {
    if bit(fsw, 7) == 1 {
        trap(MF);
    }
}

// ---- Exceptions and outcomes.

// The flags whose exceptions are unmasked (defined where masked).
fn x87_unmasked(flags: Op) {
    let u = zext(0, 6);
    for i in 0..6 {
        u = u
            | (zext(
                if bit(fcw, i) == 1 {
                    x87_no()
                } else {
                    bit(flags, i)
                },
                6,
            ) << i);
    }
    u
}

// Records exceptions `flags` and a stack fault `fault`: ES and B if one is
// unmasked.
fn x87_raise(flags: Op, fault: Op) {
    let summary = x87_unmasked(flags) != 0;
    fsw = fsw
        | zext(flags, 16)
        | (zext(fault, 16) << 6)
        | (zext(summary, 16) << 7)
        | (zext(summary, 16) << 15);
}

// ES and B after the control word or the status word is loaded: set if an
// exception flag is set and unmasked, else clear.
fn x87_summarize() {
    let summary = (bits(fsw, 0, 6) & !bits(fcw, 0, 6)) != 0;
    fsw = (fsw & 0x7f) | (zext(summary, 16) << 7) | (zext(summary, 16) << 15);
}

// What an instruction does: whether it stores its value (and pops),
// the exceptions, the stack fault, C1 and the 80-bit value (or a narrower
// one in the low bits). 89 bits.
fn x87_outcome(store: Op, flags: Op, fault: Op, up: Op, value: Op) {
    concat(concat(concat(up, fault), concat(flags, store)), value)
}

fn x87_stores(o: Op) {
    bit(o, 80) == 1
}

fn x87_report(o: Op) {
    x87_raise(bits(o, 81, 6), bit(o, 87));
    c1 = bit(o, 88);
}

// A stack fault (C1: 0 underflow, 1 overflow); masked, `value` is stored.
fn x87_stack_fault(up: Op, value: Op) {
    x87_outcome(bit(fcw, 0), zext(1, 6), zext(1, 1), up, value)
}

fn x87_underflow() {
    x87_stack_fault(zext(0, 1), x87_indefinite())
}

fn x87_overflow() {
    x87_stack_fault(zext(1, 1), x87_indefinite())
}

// The outcome of an operation with a register destination: unmasked
// invalid-operation, denormal or divide-by-zero exceptions stop it, and
// only they are reported.
fn x87_complete(flags: Op, value: Op, up: Op) {
    let stop = bits(x87_unmasked(flags), 0, 3) != 0;
    let reported = if stop { flags & 7 } else { flags };
    x87_outcome(!stop, reported, x87_no(), up && !stop, value)
}

// The same with a memory destination: an unmasked overflow or underflow
// also stops it (C1 clear, PE not reported).
fn x87_complete_store(flags: Op, value: Op, up: Op) {
    let u = x87_unmasked(flags);
    let pre = bits(u, 0, 3) != 0;
    let post = bits(u, 3, 2) != 0;
    let stop = pre || post;
    let reported = if pre {
        flags & 7
    } else if post {
        flags & 0x1f
    } else {
        flags
    };
    x87_outcome(!stop, reported, x87_no(), up && !stop, value)
}

// ---- Rounding.

// Drops the low `k` bits (0 to 128, 32 bits) of the 64-bit significand
// `t`, below which more nonzero bits follow if `sticky`, rounding as `rc`
// says for a number of sign `sign`: concat(inexact, up, the kept bits plus
// up (65 bits)).
fn x87_round_bits(t: Op, k: Op, sticky: Op, sign: Op, rc: Op) {
    let w = concat(t, zext(0, 128)) >> zext(k, 192);
    let kept = bits(w, 128, 64);
    let half = bit(w, 127) == 1;
    let rest = bits(w, 0, 127) != 0 || sticky == 1;
    let inexact = half || rest;
    let up = (rc == 0 && half && (rest || bit(kept, 0) == 1))
        || (rc == 1 && sign == 1 && inexact)
        || (rc == 2 && sign == 0 && inexact);
    concat(concat(inexact, up), zext(kept, 65) + zext(up, 65))
}

// The result of an operation that L0 computed on scaled operands: `r`
// rounded as `rc` says (inexact if `ri`), `t` rounded toward zero (inexact
// if `ti`), nonzero numbers whose true exponent is `e0` (32 bits) more than
// their exponent field says. Rounded to the precision `pc`, with x86's
// overflow and underflow responses for a register destination:
// concat(C1, PE, UE, OE, value).
//
// Tiny means below the smallest normal number after rounding to the
// precision with an unbounded exponent. A masked tiny result is
// denormalized and rounded at the precision's last significand bit.
fn x87_round(r: Op, ri: Op, t: Op, ti: Op, e0: Op, rc: Op, pc: Op) {
    let sign = bit(t, 79);
    let et = e0 + zext(bits(t, 64, 15), 32) - 16383;
    let ts = bits(t, 0, 64);
    let drop = if pc == 0 {
        zext(40, 32)
    } else if pc == 2 {
        zext(11, 32)
    } else {
        zext(0, 32)
    };
    let full = drop == 0;
    // At 24 or 53 bits: from the truncated significand and the sticky bit.
    let n = x87_round_bits(ts, drop, ti, sign, rc);
    let wide = bits(n, 0, 65) << zext(drop, 65);
    let carry = bit(wide, 64);
    let ep = et + zext(carry, 32);
    let psig = bits(wide, 0, 64) | (zext(carry, 64) << 63);
    // At 64 bits: L0's rounding.
    let er = e0 + zext(bits(r, 64, 15), 32) - 16383;
    let eu = if full { er } else { ep };
    let su = if full { bits(r, 0, 64) } else { psig };
    let iu = if full { ri == 1 } else { bit(n, 66) == 1 };
    let uu = if full { r != t } else { bit(n, 65) == 1 };
    let over = sgt(eu, zext(16383, 32));
    let tiny = slt(eu, zext(0, 32) - 16382);
    let oe_unmasked = bit(fcw, 3) == 0;
    let ue_unmasked = bit(fcw, 4) == 0;
    let to_infinity = rc == 0 || (rc == 1 && sign == 1) || (rc == 2 && sign == 0);
    let infinity = x87_pack(sign, zext(0x7fff, 32), zext(0x8000_0000_0000_0000, 64));
    let largest = x87_pack(sign, zext(0x7ffe, 32), !zext(0, 64) << zext(drop, 64));
    let shift = zext(0, 32) - 16382 - et;
    let k = drop + shift;
    let d = x87_round_bits(
        ts,
        if sgt(k, zext(128, 32)) {
            zext(128, 32)
        } else {
            k
        },
        ti,
        sign,
        rc,
    );
    let dsig = bits(bits(d, 0, 65) << zext(drop, 65), 0, 64);
    let denormal = x87_pack(sign, zext(bit(dsig, 63), 32), dsig);
    // Unmasked, the exponent is adjusted by 24576; a result still out of
    // range (only FSCALE's) is an infinity or a zero of its sign whatever
    // the rounding, inexact, C1 set for the infinity (measured).
    let huge = over && oe_unmasked && sgt(eu - 24576, zext(16383, 32));
    let vanishing = tiny && ue_unmasked && slt(eu + 24576, zext(0, 32) - 16382);
    let value = if huge {
        infinity
    } else if vanishing {
        concat(sign, zext(0, 79))
    } else if over {
        if oe_unmasked {
            x87_pack(sign, eu + 16383 - 24576, su)
        } else if to_infinity {
            infinity
        } else {
            largest
        }
    } else if tiny {
        if ue_unmasked {
            x87_pack(sign, eu + 16383 + 24576, su)
        } else {
            denormal
        }
    } else {
        x87_pack(sign, eu + 16383, su)
    };
    let masked_tiny = tiny && !ue_unmasked;
    let ue = tiny && (ue_unmasked || bit(d, 66) == 1);
    let pe = if (over && !oe_unmasked) || huge || vanishing {
        over || tiny
    } else if masked_tiny {
        bit(d, 66) == 1
    } else {
        iu
    };
    let rounded_up = if huge {
        huge
    } else if vanishing {
        x87_no()
    } else if over && !oe_unmasked {
        to_infinity
    } else if masked_tiny {
        bit(d, 65) == 1
    } else {
        uu
    };
    concat(concat(concat(rounded_up, pe), concat(ue, over)), value)
}

// ---- Arithmetic.

// The arithmetic operation `op` (add, sub, mul, div) on 80-bit `a` and `b`
// for a register destination; `denormal`: a source operand is a denormal.
fn x87_arith(op: Op, a: Op, b: Op, denormal: Op) {
    let rc = bits(fcw, 10, 2);
    let unsupported = x87_unsupported(a) || x87_unsupported(b);
    let nan = x87_nan(a) || x87_nan(b);
    let za = x87_zero(a);
    let zb = x87_zero(b);
    let zeros = if op >= mul() { za || zb } else { za && zb };
    // Infinities and zeros: exact, or invalid, or a division by zero.
    let special = x87_infinity(a) || x87_infinity(b) || zeros;
    let s = farith(op, a, b, rc);
    let ss = status(farith(op, a, b, rc));
    // Scaled: a sum by the larger exponent (a much smaller operand only
    // counts as a sticky bit, which 2^-100 gives as well), a product or
    // quotient each to [1, 2).
    let ea = x87_true_exponent(a);
    let eb = x87_true_exponent(b);
    let a_larger = zb || (!za && sge(ea, eb));
    let e0 = if op <= sub() {
        if a_larger { ea } else { eb }
    } else if op == mul() {
        ea + eb
    } else {
        ea - eb
    };
    let xa = if za {
        a
    } else if op <= sub() {
        x87_scaled(a, x87_floor(ea - e0))
    } else {
        x87_scaled(a, zext(0, 32))
    };
    let xb = if zb {
        b
    } else if op <= sub() {
        x87_scaled(b, x87_floor(eb - e0))
    } else {
        x87_scaled(b, zext(0, 32))
    };
    let r = farith(op, xa, xb, rc);
    let ri = bit(status(farith(op, xa, xb, rc)), 4);
    let t = farith(op, xa, xb, 3);
    let ti = bit(status(farith(op, xa, xb, 3)), 4);
    let rounded = x87_round(r, ri, t, ti, e0, rc, bits(fcw, 8, 2));
    let exact_zero = x87_zero(t);
    let invalid = unsupported || x87_snan(a) || x87_snan(b) || (!nan && special && bit(ss, 0) == 1);
    let zero_divide = !unsupported && !nan && special && bit(ss, 1) == 1;
    let de = denormal && !unsupported && !nan && !invalid && !zero_divide;
    let computed = !unsupported && !nan && !special && !exact_zero;
    let value = if unsupported {
        x87_indefinite()
    } else if nan {
        x87_propagate(a, b)
    } else if special {
        if bit(ss, 0) == 1 { x87_indefinite() } else { s }
    } else if exact_zero {
        r
    } else {
        bits(rounded, 0, 80)
    };
    let post = if computed {
        bits(rounded, 80, 3)
    } else {
        zext(0, 3)
    };
    x87_complete(
        concat(post, concat(zero_divide, concat(de, invalid))),
        value,
        computed && bit(rounded, 83) == 1,
    )
}

// `op` on st(ia) (`a`) and `b` (`wb` bits: a single, double or 80-bit
// number, st(ib) if ib < 8); `reversed`: b op a.
fn x87_binary(op: Op, a: Op, b: Op, wb: Op, ia: Op, ib: Op, reversed: Op) {
    let y = x87_extend(b, wb);
    let denormal = x87_denormal(a) || x87_source_denormal(b, wb);
    let first = if reversed == 1 { y } else { a };
    let second = if reversed == 1 { a } else { y };
    let o = x87_arith(op, first, second, denormal);
    if x87_empty(ia) || x87_empty(ib) {
        x87_underflow()
    } else {
        o
    }
}

// The same with a 16- or 32-bit integer `b` (in memory).
fn x87_integer_binary(op: Op, a: Op, b: Op, reversed: Op) {
    x87_binary(op, a, itof(b, 80, 0), 80, 0, 8, reversed)
}

#[iclass(FADD)]
fn fadd(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(
        add(),
        dst,
        src,
        width(src),
        stack_index(dst),
        stack_index(src),
        0,
    );
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
    }
}

#[iclass(FSUB)]
fn fsub(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(
        sub(),
        dst,
        src,
        width(src),
        stack_index(dst),
        stack_index(src),
        0,
    );
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
    }
}

#[iclass(FSUBR)]
fn fsubr(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(
        sub(),
        dst,
        src,
        width(src),
        stack_index(dst),
        stack_index(src),
        1,
    );
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
    }
}

#[iclass(FMUL)]
fn fmul(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(
        mul(),
        dst,
        src,
        width(src),
        stack_index(dst),
        stack_index(src),
        0,
    );
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
    }
}

#[iclass(FDIV)]
fn fdiv(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(
        div(),
        dst,
        src,
        width(src),
        stack_index(dst),
        stack_index(src),
        0,
    );
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
    }
}

#[iclass(FDIVR)]
fn fdivr(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(
        div(),
        dst,
        src,
        width(src),
        stack_index(dst),
        stack_index(src),
        1,
    );
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
    }
}

#[iclass(FADDP)]
fn faddp(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(add(), dst, src, 80, stack_index(dst), 0, 0);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
        x87_pop();
    }
}

#[iclass(FSUBP)]
fn fsubp(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(sub(), dst, src, 80, stack_index(dst), 0, 0);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
        x87_pop();
    }
}

#[iclass(FSUBRP)]
fn fsubrp(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(sub(), dst, src, 80, stack_index(dst), 0, 1);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
        x87_pop();
    }
}

#[iclass(FMULP)]
fn fmulp(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(mul(), dst, src, 80, stack_index(dst), 0, 0);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
        x87_pop();
    }
}

#[iclass(FDIVP)]
fn fdivp(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(div(), dst, src, 80, stack_index(dst), 0, 0);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
        x87_pop();
    }
}

#[iclass(FDIVRP)]
fn fdivrp(dst: Op, src: Op) {
    x87_wait();
    let o = x87_binary(div(), dst, src, 80, stack_index(dst), 0, 1);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(stack_index(dst));
        x87_pop();
    }
}

#[iclass(FIADD)]
fn fiadd(dst: Op, src: Op) {
    x87_wait();
    let o = x87_integer_binary(add(), dst, src, 0);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(0);
    }
}

#[iclass(FISUB)]
fn fisub(dst: Op, src: Op) {
    x87_wait();
    let o = x87_integer_binary(sub(), dst, src, 0);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(0);
    }
}

#[iclass(FISUBR)]
fn fisubr(dst: Op, src: Op) {
    x87_wait();
    let o = x87_integer_binary(sub(), dst, src, 1);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(0);
    }
}

#[iclass(FIMUL)]
fn fimul(dst: Op, src: Op) {
    x87_wait();
    let o = x87_integer_binary(mul(), dst, src, 0);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(0);
    }
}

#[iclass(FIDIV)]
fn fidiv(dst: Op, src: Op) {
    x87_wait();
    let o = x87_integer_binary(div(), dst, src, 0);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(0);
    }
}

#[iclass(FIDIVR)]
fn fidivr(dst: Op, src: Op) {
    x87_wait();
    let o = x87_integer_binary(div(), dst, src, 1);
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_tag(0);
    }
}

// FSQRT: scaled to [1, 4) with an even exponent; the precision applies.
fn x87_sqrt(a: Op) {
    let rc = bits(fcw, 10, 2);
    let unsupported = x87_unsupported(a);
    let nan = x87_nan(a);
    let special = x87_infinity(a) || x87_zero(a) || bit(a, 79) == 1;
    let s = fsqrt(a, rc);
    let ss = status(fsqrt(a, rc));
    let e = x87_true_exponent(a);
    let odd = zext(bit(e, 0), 32);
    let xa = x87_scaled(a, odd);
    let r = fsqrt(xa, rc);
    let ri = bit(status(fsqrt(xa, rc)), 4);
    let t = fsqrt(xa, 3);
    let ti = bit(status(fsqrt(xa, 3)), 4);
    let rounded = x87_round(r, ri, t, ti, sar(e - odd, 1), rc, bits(fcw, 8, 2));
    let invalid = unsupported || x87_snan(a) || (!nan && special && bit(ss, 0) == 1);
    let de = x87_denormal(a) && !unsupported && !invalid;
    let computed = !unsupported && !nan && !special;
    let value = if unsupported {
        x87_indefinite()
    } else if nan {
        x87_quiet(a)
    } else if special {
        if bit(ss, 0) == 1 { x87_indefinite() } else { s }
    } else {
        bits(rounded, 0, 80)
    };
    let post = if computed {
        bits(rounded, 80, 3)
    } else {
        zext(0, 3)
    };
    x87_complete(
        concat(post, concat(x87_no(), concat(de, invalid))),
        value,
        computed && bit(rounded, 83) == 1,
    )
}

#[iclass(FSQRT)]
fn fsqrt_x87(x: Op) {
    x87_wait();
    let o = if x87_empty(0) {
        x87_underflow()
    } else {
        x87_sqrt(x)
    };
    x87_report(o);
    if x87_stores(o) {
        x = bits(o, 0, 80);
        x87_tag(0);
    }
}

// FRNDINT: to an integer as the rounding control says (not the precision).
fn x87_round_integral(x: Op) {
    let rc = bits(fcw, 10, 2);
    let r = fround(x, rc);
    let inexact = bit(status(fround(x, rc)), 4) == 1;
    let unsupported = x87_unsupported(x);
    let nan = x87_nan(x);
    let invalid = unsupported || x87_snan(x);
    let pe = !unsupported && !nan && inexact;
    let value = if unsupported {
        x87_indefinite()
    } else if nan {
        x87_quiet(x)
    } else {
        r
    };
    let de = x87_denormal(x) && !unsupported;
    x87_complete(
        x87_flags(invalid, de, x87_no(), x87_no(), x87_no(), pe),
        value,
        pe && r != fround(x, 3),
    )
}

#[iclass(FRNDINT)]
fn frndint(x: Op) {
    x87_wait();
    let o = if x87_empty(0) {
        x87_underflow()
    } else {
        x87_round_integral(x)
    };
    x87_report(o);
    if x87_stores(o) {
        x = bits(o, 0, 80);
        x87_tag(0);
    }
}

// FSCALE: a × 2^n, n = b truncated (beyond ±2^16 every result is the same
// overflow or underflow). One rounding, at 64 bits.
fn x87_scale(a: Op, b: Op) {
    let rc = bits(fcw, 10, 2);
    let unsupported = x87_unsupported(a) || x87_unsupported(b);
    let nan = x87_nan(a) || x87_nan(b);
    let za = x87_zero(a);
    let ia = x87_infinity(a);
    let ib = x87_infinity(b);
    let special = za || ia || ib;
    let special_invalid = (za && ib && bit(b, 79) == 0) || (ia && ib && bit(b, 79) == 1);
    let exact = if za || ia {
        a
    } else if bit(b, 79) == 1 {
        concat(bit(a, 79), zext(0, 79))
    } else {
        x87_pack(
            bit(a, 79),
            zext(0x7fff, 32),
            zext(0x8000_0000_0000_0000, 64),
        )
    };
    let n = if bits(b, 64, 15) >= 0x400f {
        if bit(b, 79) == 1 {
            zext(0, 32) - 65536
        } else {
            zext(65536, 32)
        }
    } else {
        ftoi(b, 32, 3)
    };
    let m = x87_scaled(a, zext(0, 32));
    let rounded = x87_round(
        m,
        x87_no(),
        m,
        x87_no(),
        x87_true_exponent(a) + n,
        rc,
        zext(3, 2),
    );
    let invalid = unsupported || x87_snan(a) || x87_snan(b) || (!nan && special && special_invalid);
    let de = (x87_denormal(a) || x87_denormal(b)) && !unsupported && !nan && !invalid;
    let computed = !unsupported && !nan && !special;
    let value = if unsupported {
        x87_indefinite()
    } else if nan {
        x87_propagate(a, b)
    } else if special {
        if special_invalid {
            x87_indefinite()
        } else {
            exact
        }
    } else {
        bits(rounded, 0, 80)
    };
    let post = if computed {
        bits(rounded, 80, 3)
    } else {
        zext(0, 3)
    };
    x87_complete(
        concat(post, concat(x87_no(), concat(de, invalid))),
        value,
        computed && bit(rounded, 83) == 1,
    )
}

#[iclass(FSCALE)]
fn fscale(a: Op, b: Op) {
    x87_wait();
    let o = if x87_empty(0) || x87_empty(1) {
        x87_underflow()
    } else {
        x87_scale(a, b)
    };
    x87_report(o);
    if x87_stores(o) {
        a = bits(o, 0, 80);
        x87_tag(0);
    }
}

// FPREM (`nearest` 0: the quotient truncated) and FPREM1 (1: rounded to
// nearest even): exact, from the significands as integers. An exponent
// difference d of 64 or more reduces partially, by 2^(d - N) multiples of
// b with N = 32 + (d mod 32), and sets C2. concat(C3, C2, C0, outcome)
// with C1 in the outcome: the low three quotient bits are C0, C3, C1.
fn x87_remainder(a: Op, b: Op, nearest: Op) {
    let unsupported = x87_unsupported(a) || x87_unsupported(b);
    let nan = x87_nan(a) || x87_nan(b);
    let special_invalid = x87_infinity(a) || x87_zero(b);
    let keep = x87_zero(a) || x87_infinity(b);
    let ea = x87_true_exponent(a);
    let eb = x87_true_exponent(b);
    let d = ea - eb;
    let partial = sge(d, zext(64, 32));
    let de_ = if partial { (d & 31) | 32 } else { d };
    let small = if nearest == 1 {
        slt(de_, zext(0, 32) - 1)
    } else {
        slt(de_, zext(0, 32))
    };
    let num = zext(x87_normalized(a), 128) << zext(de_ + 1, 128);
    let den = zext(x87_normalized(b), 128) << 1;
    let q = udiv(num, den);
    let r = urem(num, den);
    let up = if nearest == 1 {
        !partial && ((r << 1) > den || ((r << 1) == den && bit(q, 0) == 1))
    } else {
        x87_no()
    };
    let rm = if up { den - r } else { r };
    let qq = q + zext(up, 128);
    let sign = bit(a, 79) ^ up;
    let tv = utof(rm, 80, 0);
    let t = x87_pack(sign, zext(bits(tv, 64, 15), 32), bits(tv, 0, 64));
    let rounded = x87_round(
        t,
        x87_no(),
        t,
        x87_no(),
        ea - de_ - 64,
        bits(fcw, 10, 2),
        zext(3, 2),
    );
    // An unchanged st(0) is still a result: a denormal one is tiny (UE
    // unmasked: normalized with the exponent adjusted; measured).
    let unchanged = x87_scaled(a, zext(0, 32));
    let same = x87_round(
        unchanged,
        x87_no(),
        unchanged,
        x87_no(),
        ea,
        bits(fcw, 10, 2),
        zext(3, 2),
    );
    let invalid = unsupported || x87_snan(a) || x87_snan(b) || (!nan && special_invalid);
    let de = (x87_denormal(a) || x87_denormal(b)) && !unsupported && !nan && !invalid;
    let valid = !unsupported && !nan && !special_invalid;
    let computed = valid && !keep && !small;
    let kept = valid && !x87_zero(a) && (keep || small);
    let zero = rm == 0;
    let value = if unsupported {
        x87_indefinite()
    } else if nan {
        x87_propagate(a, b)
    } else if special_invalid {
        x87_indefinite()
    } else if kept {
        bits(same, 0, 80)
    } else if keep || small {
        a
    } else if zero {
        concat(bit(a, 79), zext(0, 79))
    } else {
        bits(rounded, 0, 80)
    };
    let quotient = if computed && !partial {
        trunc(qq, 3)
    } else {
        zext(0, 3)
    };
    let post = if computed && !zero {
        bits(rounded, 80, 3)
    } else if kept {
        bits(same, 80, 3)
    } else {
        zext(0, 3)
    };
    let o = x87_complete(
        concat(post, concat(x87_no(), concat(de, invalid))),
        value,
        bit(quotient, 0),
    );
    concat(
        concat(
            concat(valid, bit(quotient, 1)),
            concat(computed && partial, bit(quotient, 2)),
        ),
        o,
    )
}

// Reports FPREM's or FPREM1's outcome: C0 and C3 get quotient bits only
// when a remainder is computed (NaN, unsupported or invalid operands and
// stack faults leave them alone), C2 is set only for a partial remainder
// (measured).
fn x87_remainder_report(r: Op, empty: Op) {
    let o = if empty {
        x87_underflow()
    } else {
        bits(r, 0, 89)
    };
    x87_report(o);
    let quotient = x87_stores(o) && !empty && bit(r, 92) == 1;
    c0 = if quotient { bit(r, 89) } else { c0 };
    c2 = quotient && bit(r, 90) == 1;
    c3 = if quotient { bit(r, 91) } else { c3 };
    o
}

#[iclass(FPREM)]
fn fprem(a: Op, b: Op) {
    x87_wait();
    let empty = x87_empty(0) || x87_empty(1);
    let o = x87_remainder_report(x87_remainder(a, b, 0), empty);
    if x87_stores(o) {
        a = bits(o, 0, 80);
        x87_tag(0);
    }
}

#[iclass(FPREM1)]
fn fprem1(a: Op, b: Op) {
    x87_wait();
    let empty = x87_empty(0) || x87_empty(1);
    let o = x87_remainder_report(x87_remainder(a, b, 1), empty);
    if x87_stores(o) {
        a = bits(o, 0, 80);
        x87_tag(0);
    }
}

// FXTRACT: st(0) becomes the significand (exponent 0) and the exponent is
// pushed below it; a zero gives -infinity (divide by zero), an infinity
// +infinity.
#[iclass(FXTRACT)]
fn fxtract(a: Op, b: Op) {
    x87_wait();
    let empty = x87_empty(0);
    let full = !x87_empty(7);
    let unsupported = x87_unsupported(a);
    let nan = x87_nan(a);
    let zero = x87_zero(a);
    let infinity = x87_infinity(a);
    let invalid = unsupported || x87_snan(a);
    let ze = zero;
    let de = x87_denormal(a) && !unsupported;
    let significand = if unsupported {
        x87_indefinite()
    } else if nan {
        x87_quiet(a)
    } else if zero || infinity {
        a
    } else {
        x87_scaled(a, zext(0, 32))
    };
    let exponent = if unsupported {
        x87_indefinite()
    } else if nan {
        x87_quiet(a)
    } else if zero {
        concat(zext(0xffff, 16), zext(0x8000_0000_0000_0000, 64))
    } else if infinity {
        concat(zext(0x7fff, 16), zext(0x8000_0000_0000_0000, 64))
    } else {
        itof(x87_true_exponent(a), 80, 0)
    };
    let o = if empty {
        x87_underflow()
    } else if full {
        x87_overflow()
    } else {
        x87_complete(
            x87_flags(invalid, de, ze, x87_no(), x87_no(), x87_no()),
            significand,
            x87_no(),
        )
    };
    x87_report(o);
    if x87_stores(o) {
        let fault = empty || full;
        x87_push();
        a = if fault { x87_indefinite() } else { significand };
        b = if fault { x87_indefinite() } else { exponent };
        x87_tag(1);
    }
}

// ---- Loads and stores.

// FLD: a single or double is converted exactly (an SNaN raises IE and is
// quieted, a denormal raises DE, which does not stop the load even
// unmasked: measured); an 80-bit value or register is copied as it is. An
// empty source register underflows before a full stack overflows
// (measured).
fn x87_load(x: Op, w: Op, i: Op) {
    let y = x87_extend(x, w);
    let invalid = if w == 80 {
        x87_no()
    } else {
        is_nan(x, w) && bit(x, fraction(w) - 1) == 0
    };
    let de = if w == 80 { x87_no() } else { is_denormal(x, w) };
    let value = if invalid { x87_quiet(y) } else { y };
    let flags = x87_flags(invalid, de, x87_no(), x87_no(), x87_no(), x87_no());
    let stop = bit(x87_unmasked(flags), 0) == 1;
    if x87_empty(i) {
        x87_underflow()
    } else if !x87_empty(7) {
        x87_overflow()
    } else {
        x87_outcome(!stop, flags, x87_no(), x87_no(), value)
    }
}

#[iclass(FLD)]
fn fld(dst: Op, src: Op) {
    x87_wait();
    let o = x87_load(src, width(src), stack_index(src));
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

// A value pushed without exceptions: FILD, FBLD, the constants.
fn x87_exact_push(value: Op) {
    if !x87_empty(7) {
        x87_overflow()
    } else {
        x87_outcome(zext(1, 1), zext(0, 6), x87_no(), x87_no(), value)
    }
}

#[iclass(FILD)]
fn fild(dst: Op, src: Op) {
    x87_wait();
    let o = x87_exact_push(itof(src, 80, 0));
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

// FBLD: 18 packed decimal digits and a sign (bit 79; bits 72 to 78 are
// ignored). A digit above 9 counts with its binary value.
#[iclass(FBLD)]
fn fbld(dst: Op, src: Op) {
    x87_wait();
    let n = zext(0, 64);
    for i in 0..18 {
        n = n * 10 + zext(bits(src, 4 * (17 - i), 4), 64);
    }
    let o = x87_exact_push(itof(n, 80, 0) | (zext(bit(src, 79), 80) << 79));
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

// A constant: the 64-bit significand rounded down `s`, and whether it
// rounds up to nearest; rounding up gives s + 1, down and toward zero s.
fn x87_constant(e: Op, s: Op, nearest_up: Op) {
    let rc = bits(fcw, 10, 2);
    let up = if nearest_up == 1 {
        rc == 0 || rc == 2
    } else {
        rc == 2
    };
    x87_exact_push(concat(zext(e, 16), zext(s, 64) + zext(up, 64)))
}

#[iclass(FLD1)]
fn fld1(dst: Op) {
    x87_wait();
    let o = x87_exact_push(x87_one());
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

#[iclass(FLDZ)]
fn fldz(dst: Op) {
    x87_wait();
    let o = x87_exact_push(zext(0, 80));
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

#[iclass(FLDPI)]
fn fldpi(dst: Op) {
    x87_wait();
    let o = x87_constant(0x4000, 0xc90f_daa2_2168_c234, 1);
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

#[iclass(FLDL2T)]
fn fldl2t(dst: Op) {
    x87_wait();
    let o = x87_constant(0x4000, 0xd49a_784b_cd1b_8afe, 0);
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

#[iclass(FLDL2E)]
fn fldl2e(dst: Op) {
    x87_wait();
    let o = x87_constant(0x3fff, 0xb8aa_3b29_5c17_f0bb, 1);
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

#[iclass(FLDLG2)]
fn fldlg2(dst: Op) {
    x87_wait();
    let o = x87_constant(0x3ffd, 0x9a20_9a84_fbcf_f798, 1);
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

#[iclass(FLDLN2)]
fn fldln2(dst: Op) {
    x87_wait();
    let o = x87_constant(0x3ffe, 0xb172_17f7_d1cf_79ab, 1);
    x87_report(o);
    if x87_stores(o) {
        x87_push();
        dst = bits(o, 0, 80);
    }
}

// FST to a single or double: rounded as the control word says (not the
// precision). An SNaN raises IE and is quieted, a NaN keeps the top of its
// payload; to an 80-bit place the value is copied.
fn x87_narrow(x: Op, w: Op) {
    let rc = bits(fcw, 10, 2);
    let r = fcvt(x, w, rc);
    let s = status(fcvt(x, w, rc));
    let unsupported = x87_unsupported(x);
    let nan = x87_nan(x);
    let number = !unsupported && !nan;
    let invalid = unsupported || x87_snan(x);
    let quieted = concat(
        concat(bit(x, 79), zext((1 << exponent(w)) - 1, exponent(w))),
        bits(x, 63 - fraction(w), fraction(w)) | (1 << (fraction(w) - 1)),
    );
    let value = if unsupported {
        zext(indefinite(w), w)
    } else if nan {
        quieted
    } else {
        r
    };
    // Tiny: a denormal or zero result from a nonzero number, or one that
    // rounded up to the smallest normal number.
    let tiny =
        number && !x87_zero(x) && (is_denormal(r, w) || bits(r, 0, w - 1) == 0 || bit(s, 3) == 1);
    let ue = if bit(fcw, 4) == 0 {
        tiny
    } else {
        number && bit(s, 3) == 1
    };
    x87_complete_store(
        x87_flags(
            invalid,
            x87_no(),
            x87_no(),
            number && bit(s, 2) == 1,
            ue,
            number && bit(s, 4) == 1,
        ),
        zext(value, 80),
        number && r != fcvt(x, w, 3),
    )
}

fn x87_store(x: Op, w: Op) {
    let o = if w == 80 {
        x87_outcome(zext(1, 1), zext(0, 6), x87_no(), x87_no(), x)
    } else {
        x87_narrow(x, w)
    };
    let indefinite_w = if w == 80 {
        x87_indefinite()
    } else {
        zext(indefinite(w), 80)
    };
    if x87_empty(0) {
        x87_stack_fault(x87_no(), indefinite_w)
    } else {
        o
    }
}

#[iclass(FST)]
fn fst(dst: Op, src: Op) {
    x87_wait();
    if stack_index(dst) == 8 {
        probe(dst);
    }
    let o = x87_store(src, width(dst));
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, width(dst));
        if stack_index(dst) < 8 {
            x87_tag(stack_index(dst));
        }
    }
}

#[iclass(FSTP)]
fn fstp(dst: Op, src: Op) {
    x87_wait();
    if stack_index(dst) == 8 {
        probe(dst);
    }
    let o = x87_store(src, width(dst));
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, width(dst));
        if stack_index(dst) < 8 {
            x87_tag(stack_index(dst));
        }
        x87_pop();
    }
}

// FSTPNCE (D9 D8+i, undocumented): FSTP st(i) without the stack fault: an
// empty st(0) is only popped (measured).
#[iclass(FSTPNCE)]
fn fstpnce(dst: Op, src: Op) {
    x87_wait();
    if !x87_empty(0) {
        dst = src;
        x87_tag(stack_index(dst));
    }
    x87_pop();
    c1 = 0;
}

// FIST and FISTTP (`rc` 3): to a `w`-bit integer; out of range, a NaN or
// an infinity raise IE and give the integer indefinite (the most negative
// integer).
fn x87_integer(x: Op, w: Op, rc: Op) {
    let r = ftoi(x, w, rc);
    let s = status(ftoi(x, w, rc));
    let unsupported = x87_unsupported(x);
    let invalid = unsupported || bit(s, 0) == 1;
    let pe = !invalid && bit(s, 4) == 1;
    let value = if invalid { zext(1 << (w - 1), w) } else { r };
    let o = x87_complete_store(
        x87_flags(invalid, x87_no(), x87_no(), x87_no(), x87_no(), pe),
        zext(value, 80),
        pe && r != ftoi(x, w, 3),
    );
    if x87_empty(0) {
        x87_stack_fault(x87_no(), zext(1 << (w - 1), 80))
    } else {
        o
    }
}

#[iclass(FIST)]
fn fist(dst: Op, src: Op) {
    x87_wait();
    probe(dst);
    let o = x87_integer(src, width(dst), bits(fcw, 10, 2));
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, width(dst));
    }
}

#[iclass(FISTP)]
fn fistp(dst: Op, src: Op) {
    x87_wait();
    probe(dst);
    let o = x87_integer(src, width(dst), bits(fcw, 10, 2));
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, width(dst));
        x87_pop();
    }
}

#[iclass(FISTTP)]
fn fisttp(dst: Op, src: Op) {
    x87_wait();
    probe(dst);
    let o = x87_integer(src, width(dst), zext(3, 2));
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, width(dst));
        x87_pop();
    }
}

// FBSTP: rounded to an integer, stored as 18 packed decimal digits with
// the sign; 10^18 or more, a NaN or an infinity give the packed decimal
// indefinite (the same bits as the 80-bit one).
#[iclass(FBSTP)]
fn fbstp(dst: Op, src: Op) {
    x87_wait();
    probe(dst);
    let rc = bits(fcw, 10, 2);
    let n = ftoi(src, 64, rc);
    let s = status(ftoi(src, 64, rc));
    let magnitude = if msb(n) == 1 { 0 - n } else { n };
    let invalid = x87_unsupported(src) || bit(s, 0) == 1 || magnitude > 999_999_999_999_999_999;
    let digits = zext(0, 72);
    let rest = magnitude;
    for i in 0..18 {
        digits = digits | (zext(urem(rest, 10), 72) << (4 * i));
        rest = udiv(rest, 10);
    }
    let pe = !invalid && bit(s, 4) == 1;
    let value = if invalid {
        x87_indefinite()
    } else {
        concat(concat(bit(src, 79), zext(0, 7)), digits)
    };
    let o = if x87_empty(0) {
        x87_underflow()
    } else {
        x87_complete_store(
            x87_flags(invalid, x87_no(), x87_no(), x87_no(), x87_no(), pe),
            value,
            pe && n != ftoi(src, 64, 3),
        )
    };
    x87_report(o);
    if x87_stores(o) {
        dst = bits(o, 0, 80);
        x87_pop();
    }
}

// ---- Comparisons.

// Compares a with b: concat(flags, C3, C2, C0); C3 C2 C0 are 000 for
// greater, 001 less, 100 equal, 111 unordered. `quiet`: only SNaNs (and
// unsupported operands) raise IE, else any NaN.
fn x87_compare(a: Op, b: Op, denormal: Op, quiet: Op) {
    let unsupported = x87_unsupported(a) || x87_unsupported(b);
    let nan = x87_nan(a) || x87_nan(b);
    let loud = if quiet == 1 {
        x87_snan(a) || x87_snan(b)
    } else {
        nan
    };
    let invalid = unsupported || loud;
    let c = fcmp(a, b);
    let unordered = unsupported || nan;
    let less = !unordered && bit(c, 0) == 1;
    let equal = !unordered && bit(c, 1) == 1;
    let de = denormal && !unordered;
    concat(
        x87_flags(invalid, de, x87_no(), x87_no(), x87_no(), x87_no()),
        concat(concat(equal || unordered, unordered), less || unordered),
    )
}

// st(0) (`a`) compared with `b` (`wb` bits, st(ib) if ib < 8):
// concat(SF, flags, proceed (pop), conditions). A stack fault gives
// unordered, masked or not (measured); an unmasked exception does not pop.
fn x87_comparison(a: Op, b: Op, wb: Op, ib: Op, quiet: Op) {
    let y = x87_extend(b, wb);
    let empty = x87_empty(0) || x87_empty(ib);
    let r = x87_compare(a, y, x87_denormal(a) || x87_source_denormal(b, wb), quiet);
    let flags = if empty { zext(1, 6) } else { bits(r, 3, 6) };
    let stop = x87_unmasked(flags) != 0;
    let conditions = if empty { zext(7, 3) } else { bits(r, 0, 3) };
    concat(concat(empty, flags), concat(!stop, conditions))
}

fn x87_set_conditions(r: Op) {
    x87_raise(bits(r, 4, 6), bit(r, 10));
    c0 = bit(r, 0);
    c2 = bit(r, 1);
    c3 = bit(r, 2);
    c1 = 0;
}

// FCOMI and FUCOMI leave C1 alone unless there is a stack fault
// (measured).
fn x87_set_flags(r: Op) {
    x87_raise(bits(r, 4, 6), bit(r, 10));
    cf = bit(r, 0);
    pf = bit(r, 1);
    zf = bit(r, 2);
    c1 = if bit(r, 10) == 1 { x87_no() } else { c1 };
}

#[iclass(FCOM)]
fn fcom(a: Op, b: Op) {
    x87_wait();
    x87_set_conditions(x87_comparison(a, b, width(b), stack_index(b), 0));
}

#[iclass(FCOMP)]
fn fcomp(a: Op, b: Op) {
    x87_wait();
    let r = x87_comparison(a, b, width(b), stack_index(b), 0);
    x87_set_conditions(r);
    if bit(r, 3) == 1 {
        x87_pop();
    }
}

#[iclass(FCOMPP)]
fn fcompp(a: Op, b: Op) {
    x87_wait();
    let r = x87_comparison(a, b, 80, 1, 0);
    x87_set_conditions(r);
    if bit(r, 3) == 1 {
        x87_pop();
        x87_pop();
    }
}

#[iclass(FUCOM)]
fn fucom(a: Op, b: Op) {
    x87_wait();
    x87_set_conditions(x87_comparison(a, b, 80, stack_index(b), 1));
}

#[iclass(FUCOMP)]
fn fucomp(a: Op, b: Op) {
    x87_wait();
    let r = x87_comparison(a, b, 80, stack_index(b), 1);
    x87_set_conditions(r);
    if bit(r, 3) == 1 {
        x87_pop();
    }
}

#[iclass(FUCOMPP)]
fn fucompp(a: Op, b: Op) {
    x87_wait();
    let r = x87_comparison(a, b, 80, 1, 1);
    x87_set_conditions(r);
    if bit(r, 3) == 1 {
        x87_pop();
        x87_pop();
    }
}

#[iclass(FICOM)]
fn ficom(a: Op, b: Op) {
    x87_wait();
    x87_set_conditions(x87_comparison(a, itof(b, 80, 0), 80, 8, 0));
}

#[iclass(FICOMP)]
fn ficomp(a: Op, b: Op) {
    x87_wait();
    let r = x87_comparison(a, itof(b, 80, 0), 80, 8, 0);
    x87_set_conditions(r);
    if bit(r, 3) == 1 {
        x87_pop();
    }
}

// FTST: st(0) compared with +0.0.
#[iclass(FTST)]
fn ftst(x: Op) {
    x87_wait();
    x87_set_conditions(x87_comparison(x, zext(0, 80), 80, 8, 0));
    x = x;
}

#[iclass(FCOMI)]
fn fcomi(a: Op, b: Op) {
    x87_wait();
    x87_set_flags(x87_comparison(a, b, 80, stack_index(b), 0));
}

#[iclass(FCOMIP)]
fn fcomip(a: Op, b: Op) {
    x87_wait();
    let r = x87_comparison(a, b, 80, stack_index(b), 0);
    x87_set_flags(r);
    if bit(r, 3) == 1 {
        x87_pop();
    }
}

#[iclass(FUCOMI)]
fn fucomi(a: Op, b: Op) {
    x87_wait();
    x87_set_flags(x87_comparison(a, b, 80, stack_index(b), 1));
}

#[iclass(FUCOMIP)]
fn fucomip(a: Op, b: Op) {
    x87_wait();
    let r = x87_comparison(a, b, 80, stack_index(b), 1);
    x87_set_flags(r);
    if bit(r, 3) == 1 {
        x87_pop();
    }
}

// FXAM: the class in C3 C2 C0 (000 unsupported, 001 NaN, 010 normal, 011
// infinity, 100 zero, 101 empty, 110 denormal) and the sign in C1.
#[iclass(FXAM)]
fn fxam(x: Op) {
    x87_wait();
    let empty = x87_empty(0);
    let e = bits(x, 64, 15);
    let unsupported = x87_unsupported(x);
    let nan = x87_nan(x);
    let infinity = x87_infinity(x);
    let zero = x87_zero(x);
    let denormal = x87_denormal(x);
    let normal = !unsupported && e != 0 && e != 0x7fff;
    c3 = empty || (!empty && (zero || denormal));
    c2 = !empty && (normal || infinity || denormal);
    c0 = empty || (!empty && (nan || infinity));
    c1 = bit(x, 79);
    x = x;
}

// ---- Other register operations.

#[iclass(FXCH)]
fn fxch(a: Op, b: Op) {
    x87_wait();
    let ea = x87_empty(0);
    let eb = x87_empty(stack_index(b));
    let fault = ea || eb;
    x87_raise(zext(fault, 6), fault);
    c1 = 0;
    if !fault || bit(fcw, 0) == 1 {
        let va = if ea { x87_indefinite() } else { a };
        let vb = if eb { x87_indefinite() } else { b };
        a = vb;
        b = va;
        x87_tag(0);
        x87_tag(stack_index(b));
    }
}

// FCHS and FABS change the sign bit of anything, NaNs and unsupported
// values included.
#[iclass(FCHS)]
fn fchs(x: Op) {
    x87_wait();
    let empty = x87_empty(0);
    x87_raise(zext(empty, 6), empty);
    c1 = 0;
    if !empty || bit(fcw, 0) == 1 {
        x = if empty {
            x87_indefinite()
        } else {
            concat(!bit(x, 79), bits(x, 0, 79))
        };
        x87_tag(0);
    }
}

#[iclass(FABS)]
fn fabs(x: Op) {
    x87_wait();
    let empty = x87_empty(0);
    x87_raise(zext(empty, 6), empty);
    c1 = 0;
    if !empty || bit(fcw, 0) == 1 {
        x = if empty {
            x87_indefinite()
        } else {
            concat(x87_no(), bits(x, 0, 79))
        };
        x87_tag(0);
    }
}

// FCMOVcc: an empty st(0) or source is a stack fault whatever the
// condition. C1 is cleared only by a stack fault (measured).
#[iclass(FCMOVB, FCMOVBE, FCMOVE, FCMOVNB, FCMOVNBE, FCMOVNE, FCMOVNU, FCMOVU)]
fn fcmov(dst: Op, src: Op) {
    x87_wait();
    let empty = x87_empty(0) || x87_empty(stack_index(src));
    x87_raise(zext(empty, 6), empty);
    c1 = if empty { x87_no() } else { c1 };
    if empty {
        if bit(fcw, 0) == 1 {
            dst = x87_indefinite();
            x87_tag(0);
        }
    } else if cond() {
        dst = src;
    }
}

#[iclass(FINCSTP)]
fn fincstp() {
    x87_wait();
    ftop = ftop + 1;
    c1 = 0;
}

#[iclass(FDECSTP)]
fn fdecstp() {
    x87_wait();
    ftop = ftop - 1;
    c1 = 0;
}

#[iclass(FFREE)]
fn ffree(r: Op) {
    x87_wait();
    x87_free(stack_index(r));
}

#[iclass(FFREEP)]
fn ffreep(r: Op) {
    x87_wait();
    x87_free(stack_index(r));
    x87_pop();
}

// ---- Control and status.

#[iclass(FNOP, FWAIT)]
fn fnop() {
    x87_wait();
}

// The 8087 and 80287 instructions FENI, FDISI and FSETPM do nothing (and
// do not wait).
#[iclass(FENI8087_NOP, FDISI8087_NOP, FSETPM287_NOP)]
fn fnop_8087() {}

// The whole status word: B, C3, TOP, C2, C1, C0, ES, SF, the flags.
fn x87_status_word() {
    fsw | (zext(c0, 16) << 8)
        | (zext(c1, 16) << 9)
        | (zext(c2, 16) << 10)
        | (zext(ftop, 16) << 11)
        | (zext(c3, 16) << 14)
}

// The full tag word: two bits per physical register: 00 valid, 01 zero,
// 10 special (NaN, infinity, denormal, unsupported), 11 empty.
fn x87_tag_word() {
    let w = zext(0, 16);
    for i in 0..8 {
        let x = st(i);
        let e = bits(x, 64, 15);
        let tag = if bit(ftw, ftop + i) == 0 {
            zext(3, 2)
        } else if x87_zero(x) {
            zext(1, 2)
        } else if e == 0 || e == 0x7fff || bit(x, 63) == 0 {
            zext(2, 2)
        } else {
            zext(0, 2)
        };
        w = w | (zext(tag, 16) << (zext(ftop + i, 16) << 1));
    }
    w
}

#[iclass(FNSTSW)]
fn fnstsw(dst: Op) {
    dst = x87_status_word();
}

#[iclass(FNSTCW)]
fn fnstcw(dst: Op) {
    dst = fcw;
}

// FLDCW: bit 6 reads as 1, bits 13 to 15 as 0. A flag the new masks
// unmask is pending (ES).
#[iclass(FLDCW)]
fn fldcw(src: Op) {
    x87_wait();
    fcw = (src & 0x1f3f) | 0x40;
    x87_summarize();
}

#[iclass(FNCLEX)]
fn fnclex() {
    fsw = 0;
}

fn x87_initialize() {
    fcw = 0x37f;
    fsw = 0;
    ftop = 0;
    ftw = 0;
    c0 = 0;
    c1 = 0;
    c2 = 0;
    c3 = 0;
}

#[iclass(FNINIT)]
fn fninit() {
    x87_initialize();
}

// The environment: the control, status and tag words, then the
// last-instruction and last-data pointers and the last opcode (not
// modelled). 28 bytes (`long`, each word in 32 bits, the upper halves
// ffff) or 14.
fn x87_environment(long: Op) {
    if long == 1 {
        concat(
            undefined(128, "pointers"),
            concat(
                concat(zext(0xffff, 16), x87_tag_word()),
                concat(
                    concat(zext(0xffff, 16), x87_status_word()),
                    concat(zext(0xffff, 16), fcw),
                ),
            ),
        )
    } else {
        concat(
            undefined(64, "pointers"),
            concat(x87_tag_word(), concat(x87_status_word(), fcw)),
        )
    }
}

// Loads the control and status words: control word bit 6 reads as 1 and
// bits 13 to 15 as 0, and ES and B say whether an exception flag is
// unmasked, whatever the image says (measured).
fn x87_load_words(control: Op, status: Op) {
    fcw = (control & 0x1f3f) | 0x40;
    fsw = status & 0x7f;
    ftop = bits(status, 11, 3);
    c0 = bit(status, 8);
    c1 = bit(status, 9);
    c2 = bit(status, 10);
    c3 = bit(status, 14);
    x87_summarize();
}

// The full tag word loaded: only empty (11) or not counts.
fn x87_load_environment(control: Op, status: Op, tags: Op) {
    x87_load_words(control, status);
    let used = zext(0, 8);
    for k in 0..8 {
        used = used | (zext(bits(tags, 2 * k, 2) != 3, 8) << k);
    }
    ftw = used;
}

// FNSTENV then masks every exception, which clears ES and B (measured).
#[iclass(FNSTENV)]
fn fnstenv(dst: Op) {
    dst = x87_environment(width(dst) == 224);
    fcw = fcw | 0x3f;
    x87_summarize();
}

#[iclass(FLDENV)]
fn fldenv(src: Op) {
    x87_wait();
    let step = if width(src) == 224 { 32 } else { 16 };
    x87_load_environment(
        bits(src, 0, 16),
        bits(src, step, 16),
        bits(src, 2 * step, 16),
    );
}

// FNSAVE: the environment and st(0) to st(7), then FNINIT.
#[iclass(FNSAVE)]
fn fnsave(dst: Op) {
    let long = width(dst) == 864;
    let base = if long { 28 } else { 14 };
    store_part(dst, 0, x87_environment(long));
    for i in 0..8 {
        store_part(dst, base + 10 * i, st(i));
    }
    x87_initialize();
}

#[iclass(FRSTOR)]
fn frstor(src: Op) {
    x87_wait();
    let long = width(src) == 864;
    let step = if long { 4 } else { 2 };
    let base = if long { 28 } else { 14 };
    x87_load_environment(
        load_part(src, 0, 2),
        load_part(src, step, 2),
        load_part(src, 2 * step, 2),
    );
    for i in 0..8 {
        set_st(i, load_part(src, base + 10 * i, 10));
    }
}

// FXSAVE: the control word, status word, abridged tag word, MXCSR and its
// mask (ffff), st(0) to st(7) in 16 bytes each, xmm0 to xmm15; bytes 416
// to 511 are not written, but FXSAVE and FXRSTOR access all 512 (a missing
// page faults; measured). FXSAVE64 differs only in the pointers.
#[iclass(FXSAVE, FXSAVE64)]
fn fxsave(dst: Op) {
    probe(dst);
    store_part(dst, 0, fcw);
    store_part(dst, 2, x87_status_word());
    store_part(dst, 4, concat(zext(0, 8), ftw));
    store_part(dst, 6, undefined(144, "pointers"));
    store_part(dst, 24, mxcsr);
    store_part(dst, 28, zext(0xffff, 32));
    for i in 0..8 {
        store_part(dst, 32 + 16 * i, zext(st(i), 128));
    }
    store_part(dst, 160, trunc(zmm0, 128));
    store_part(dst, 176, trunc(zmm1, 128));
    store_part(dst, 192, trunc(zmm2, 128));
    store_part(dst, 208, trunc(zmm3, 128));
    store_part(dst, 224, trunc(zmm4, 128));
    store_part(dst, 240, trunc(zmm5, 128));
    store_part(dst, 256, trunc(zmm6, 128));
    store_part(dst, 272, trunc(zmm7, 128));
    store_part(dst, 288, trunc(zmm8, 128));
    store_part(dst, 304, trunc(zmm9, 128));
    store_part(dst, 320, trunc(zmm10, 128));
    store_part(dst, 336, trunc(zmm11, 128));
    store_part(dst, 352, trunc(zmm12, 128));
    store_part(dst, 368, trunc(zmm13, 128));
    store_part(dst, 384, trunc(zmm14, 128));
    store_part(dst, 400, trunc(zmm15, 128));
}

fn x87_xmm(old: Op, new: Op) {
    concat(bits(old, 128, 384), new)
}

// FXRSTOR: #GP if the image's MXCSR sets a bit outside the mask (ffff).
#[iclass(FXRSTOR, FXRSTOR64)]
fn fxrstor(src: Op) {
    probe(src);
    let m = load_part(src, 24, 4);
    if (m & 0xffff_0000) != 0 {
        trap(GP);
    }
    x87_load_words(load_part(src, 0, 2), load_part(src, 2, 2));
    ftw = load_part(src, 4, 1);
    mxcsr = m;
    for i in 0..8 {
        set_st(i, load_part(src, 32 + 16 * i, 10));
    }
    zmm0 = x87_xmm(zmm0, load_part(src, 160, 16));
    zmm1 = x87_xmm(zmm1, load_part(src, 176, 16));
    zmm2 = x87_xmm(zmm2, load_part(src, 192, 16));
    zmm3 = x87_xmm(zmm3, load_part(src, 208, 16));
    zmm4 = x87_xmm(zmm4, load_part(src, 224, 16));
    zmm5 = x87_xmm(zmm5, load_part(src, 240, 16));
    zmm6 = x87_xmm(zmm6, load_part(src, 256, 16));
    zmm7 = x87_xmm(zmm7, load_part(src, 272, 16));
    zmm8 = x87_xmm(zmm8, load_part(src, 288, 16));
    zmm9 = x87_xmm(zmm9, load_part(src, 304, 16));
    zmm10 = x87_xmm(zmm10, load_part(src, 320, 16));
    zmm11 = x87_xmm(zmm11, load_part(src, 336, 16));
    zmm12 = x87_xmm(zmm12, load_part(src, 352, 16));
    zmm13 = x87_xmm(zmm13, load_part(src, 368, 16));
    zmm14 = x87_xmm(zmm14, load_part(src, 384, 16));
    zmm15 = x87_xmm(zmm15, load_part(src, 400, 16));
}

// ---- Transcendentals: values from approximate intrinsics.

// The outcome of a transcendental of `x` whose intrinsic gave `v` and its
// status `s` (IE, DE, ZE, OE, UE, PE, C1), unless `known`: then the exact
// result is `exact` (invalid if `exact_invalid`). NaNs and unsupported
// operands are exact; DE is the semantics'.
fn x87_transcendental(x: Op, v: Op, s: Op, known: Op, exact: Op, exact_invalid: Op) {
    let unsupported = x87_unsupported(x);
    let nan = x87_nan(x);
    let invalid = unsupported || x87_snan(x) || (!nan && known && exact_invalid);
    let computed = !unsupported && !nan && !known;
    let de = x87_denormal(x) && !unsupported && !invalid;
    let value = if unsupported || (known && exact_invalid && !nan) {
        x87_indefinite()
    } else if nan {
        x87_quiet(x)
    } else if known {
        exact
    } else {
        v
    };
    let flags = if computed {
        (bits(s, 0, 6) & 0x3d) | (zext(de, 6) << 1)
    } else {
        x87_flags(invalid, de, x87_no(), x87_no(), x87_no(), x87_no())
    };
    x87_complete(flags, value, computed && bit(s, 6) == 1)
}

// |x| at 2^63 or more (finite): FSIN, FCOS, FSINCOS and FPTAN set C2 and
// change nothing else.
fn x87_far(x: Op) {
    !x87_unsupported(x) && bits(x, 64, 15) >= 0x403e && bits(x, 64, 15) != 0x7fff
}

#[iclass(F2XM1)]
fn f2xm1(x: Op) {
    x87_wait();
    let (v, s) = intrinsic("f2xm1", x, fcw);
    let o = if x87_empty(0) {
        x87_underflow()
    } else {
        x87_transcendental(x, v, s, x87_zero(x), x, x87_no())
    };
    x87_report(o);
    if x87_stores(o) {
        x = bits(o, 0, 80);
        x87_tag(0);
    }
}

#[iclass(FSIN)]
fn fsin(x: Op) {
    x87_wait();
    let (v, s) = intrinsic("fsin", x, fcw);
    let empty = x87_empty(0);
    let out = !empty && x87_far(x);
    let o = if empty {
        x87_underflow()
    } else {
        x87_transcendental(x, v, s, x87_zero(x) || x87_infinity(x), x, x87_infinity(x))
    };
    c2 = out;
    if out {
        c1 = 0;
    } else {
        x87_report(o);
        if x87_stores(o) {
            x = bits(o, 0, 80);
            x87_tag(0);
        }
    }
}

#[iclass(FCOS)]
fn fcos(x: Op) {
    x87_wait();
    let (v, s) = intrinsic("fcos", x, fcw);
    let empty = x87_empty(0);
    let out = !empty && x87_far(x);
    let o = if empty {
        x87_underflow()
    } else {
        x87_transcendental(
            x,
            v,
            s,
            x87_zero(x) || x87_infinity(x),
            x87_one(),
            x87_infinity(x),
        )
    };
    c2 = out;
    if out {
        c1 = 0;
    } else {
        x87_report(o);
        if x87_stores(o) {
            x = bits(o, 0, 80);
            x87_tag(0);
        }
    }
}

// FPTAN: st(0) becomes the tangent and 1.0 is pushed (a NaN or invalid
// result is pushed instead of 1.0).
#[iclass(FPTAN)]
fn fptan(a: Op, b: Op) {
    x87_wait();
    let (v, s) = intrinsic("fptan", a, fcw);
    let empty = x87_empty(0);
    let full = !x87_empty(7);
    let fault = empty || full;
    let out = !fault && x87_far(a);
    let o = if empty {
        x87_underflow()
    } else if full {
        x87_overflow()
    } else {
        x87_transcendental(a, v, s, x87_zero(a) || x87_infinity(a), a, x87_infinity(a))
    };
    let pushed = if fault || x87_unsupported(a) || x87_nan(a) || x87_infinity(a) {
        bits(o, 0, 80)
    } else {
        x87_one()
    };
    c2 = out;
    if out {
        c1 = 0;
    } else {
        x87_report(o);
        if x87_stores(o) {
            x87_push();
            b = bits(o, 0, 80);
            a = pushed;
            x87_tag(1);
        }
    }
}

// FSINCOS: st(0) becomes the sine and the cosine is pushed.
#[iclass(FSINCOS)]
fn fsincos(a: Op, b: Op) {
    x87_wait();
    let (sine, cosine, s) = intrinsic("fsincos", a, fcw);
    let empty = x87_empty(0);
    let full = !x87_empty(7);
    let fault = empty || full;
    let out = !fault && x87_far(a);
    let known = x87_zero(a) || x87_infinity(a);
    let o = if empty {
        x87_underflow()
    } else if full {
        x87_overflow()
    } else {
        x87_transcendental(a, sine, s, known, a, x87_infinity(a))
    };
    let c = x87_transcendental(a, cosine, s, known, x87_one(), x87_infinity(a));
    c2 = out;
    if out {
        c1 = 0;
    } else {
        x87_report(o);
        if x87_stores(o) {
            x87_push();
            b = bits(o, 0, 80);
            a = if fault {
                bits(o, 0, 80)
            } else {
                bits(c, 0, 80)
            };
            x87_tag(1);
        }
    }
}

// A transcendental of st(0) (`a`) and st(1) (`b`) written to st(1), then a
// pop: the exact cases as in `x87_transcendental`.
fn x87_transcendental2(
    a: Op,
    b: Op,
    v: Op,
    s: Op,
    known: Op,
    exact: Op,
    exact_invalid: Op,
    exact_zero_divide: Op,
) {
    let unsupported = x87_unsupported(a) || x87_unsupported(b);
    let nan = x87_nan(a) || x87_nan(b);
    let invalid = unsupported || x87_snan(a) || x87_snan(b) || (!nan && known && exact_invalid);
    let ze = !unsupported && !nan && known && !exact_invalid && exact_zero_divide;
    let computed = !unsupported && !nan && !known;
    let de = (x87_denormal(a) || x87_denormal(b)) && !unsupported && !nan && !invalid && !ze;
    let value = if unsupported || (known && exact_invalid && !nan) {
        x87_indefinite()
    } else if nan {
        x87_propagate(a, b)
    } else if known {
        exact
    } else {
        v
    };
    let flags = if computed {
        (bits(s, 0, 6) & 0x3d) | (zext(de, 6) << 1)
    } else {
        x87_flags(invalid, de, ze, x87_no(), x87_no(), x87_no())
    };
    let o = x87_complete(flags, value, computed && bit(s, 6) == 1);
    if x87_empty(0) || x87_empty(1) {
        x87_underflow()
    } else {
        o
    }
}

fn x87_signed_zero(sign: Op) {
    concat(sign, zext(0, 79))
}

fn x87_signed_infinity(sign: Op) {
    x87_pack(sign, zext(0x7fff, 32), zext(0x8000_0000_0000_0000, 64))
}

// FPATAN: st(1) = arctan(st(1) / st(0)), then a pop. Every number pair has
// a result (no invalid operation): all from the intrinsic.
#[iclass(FPATAN)]
fn fpatan(a: Op, b: Op) {
    x87_wait();
    let (v, s) = intrinsic("fpatan", a, b, fcw);
    let o = x87_transcendental2(a, b, v, s, x87_no(), v, x87_no(), x87_no());
    x87_report(o);
    if x87_stores(o) {
        b = bits(o, 0, 80);
        x87_tag(1);
        x87_pop();
    }
}

// FYL2X: st(1) = st(1) × log2(st(0)), then a pop. Exact: a negative st(0)
// (invalid), zeros and infinities of either, st(0) = 1.
#[iclass(FYL2X)]
fn fyl2x(a: Op, b: Op) {
    x87_wait();
    let (v, s) = intrinsic("fyl2x", a, b, fcw);
    let sb = bit(b, 79);
    let xz = x87_zero(a);
    let xi = x87_infinity(a);
    let xn = bit(a, 79) == 1 && !xz;
    let one = bits(a, 0, 80) == x87_one();
    let yz = x87_zero(b);
    let yi = x87_infinity(b);
    let below_one = bits(a, 64, 15) < 0x3fff;
    let known = xn || xz || xi || yz || yi || one;
    let exact_invalid = xn || (xz && yz) || (xi && yz) || (one && yi);
    let zero_result = (one && !yi) || (yz && !xz && !xi);
    let zero_sign = if one { sb } else { sb ^ below_one };
    let infinity_sign = if xz {
        !sb
    } else if xi {
        sb
    } else {
        sb ^ below_one
    };
    let exact = if zero_result {
        x87_signed_zero(zero_sign)
    } else {
        x87_signed_infinity(infinity_sign)
    };
    let o = x87_transcendental2(a, b, v, s, known, exact, exact_invalid, xz && !yz && !yi);
    x87_report(o);
    if x87_stores(o) {
        b = bits(o, 0, 80);
        x87_tag(1);
        x87_pop();
    }
}

// FYL2XP1: st(1) = st(1) × log2(st(0) + 1), then a pop. Exact where |st(0)|
// < 1 and st(0) or st(1) is a zero or st(1) an infinity.
#[iclass(FYL2XP1)]
fn fyl2xp1(a: Op, b: Op) {
    x87_wait();
    let (v, s) = intrinsic("fyl2xp1", a, b, fcw);
    let xz = x87_zero(a);
    let yz = x87_zero(b);
    let yi = x87_infinity(b);
    let small = bits(a, 64, 15) < 0x3fff;
    let known = small && (xz || yz || yi);
    let sign = bit(a, 79) ^ bit(b, 79);
    let exact = if xz || yz {
        x87_signed_zero(sign)
    } else {
        x87_signed_infinity(sign)
    };
    let o = x87_transcendental2(a, b, v, s, known, exact, xz && yi, x87_no());
    x87_report(o);
    if x87_stores(o) {
        b = bits(o, 0, 80);
        x87_tag(1);
        x87_pop();
    }
}
