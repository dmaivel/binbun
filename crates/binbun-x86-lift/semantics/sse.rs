// SSE and AVX floating point: x86's rules around L0's IEEE operations.
//
// MXCSR: the exception flags IE, DE, ZE, OE, UE, PE (bits 0 to 5, sticky);
// DAZ (6): denormal operands count as zeros; the exceptions' masks (7 to
// 12); the rounding (13 and 14, in the order of L0's rounding operand);
// FTZ (15): with underflow masked, tiny results become zeros. An unmasked
// exception the instruction raises faults (#XM) before it writes anything.

// The arithmetic operations of `farith`.
fn add() {
    0
}

fn sub() {
    1
}

fn mul() {
    2
}

fn div() {
    3
}

// Fraction and exponent widths of the `w`-bit format.
fn fraction(w: Op) {
    if w == 16 {
        10
    } else if w == 32 {
        23
    } else {
        52
    }
}

fn exponent(w: Op) {
    if w == 16 {
        5
    } else if w == 32 {
        8
    } else {
        11
    }
}

fn is_nan(x: Op, w: Op) {
    bits(x, fraction(w), exponent(w)) == (1 << exponent(w)) - 1 && bits(x, 0, fraction(w)) != 0
}

fn is_denormal(x: Op, w: Op) {
    bits(x, fraction(w), exponent(w)) == 0 && bits(x, 0, fraction(w)) != 0
}

fn quiet(x: Op, w: Op) {
    x | (1 << (fraction(w) - 1))
}

fn is_snan(x: Op, w: Op) {
    is_nan(x, w) && bit(x, fraction(w) - 1) == 0
}

// The zero of `x`'s sign.
fn signed_zero(x: Op, w: Op) {
    x & (1 << (w - 1))
}

// The QNaN floating-point indefinite: negative, quiet, payload 0.
fn indefinite(w: Op) {
    ((1 << (exponent(w) + 2)) - 1) << (fraction(w) - 1)
}

// The `w`-bit lanes of `a` with DAZ applied: denormals as zeros of their
// sign.
fn sse_daz(a: Op, w: Op) {
    let daz = bit(mxcsr, 6) == 1;
    lanes(
        width(a) / w,
        if daz && is_denormal(a, w) {
            signed_zero(a, w)
        } else {
            a
        },
    )
}

// The exceptions `raised` (6 bits, in MXCSR's order): #XM if one is
// unmasked, else their flags set.
fn sse_raise(raised: Op) {
    if (raised & !bits(mxcsr, 7, 6)) != 0 {
        trap(XM);
    }
    mxcsr = mxcsr | zext(raised, 32);
}

// MXCSR's exceptions (6 bits) of `n` lanes from L0's exceptions `s` (5
// bits per lane) and a bit per lane: a denormal operand, a result flushed
// to zero, a tiny result.
//
// - With underflow unmasked, a tiny result raises UE even if exact.
// - FTZ's flush raises UE and PE.
fn sse_flags(s: Op, denormal: Op, flush: Op, tiny: Op, n: Op) {
    let strict = bit(mxcsr, 11) == 0;
    let raised = zext(0, 6);
    for i in 0..n {
        let e = bits(s, i * 5, 5);
        let underflow = bit(e, 3) | bit(flush, i) | (strict & bit(tiny, i));
        raised = raised
            | zext(bit(e, 0), 6)
            | (zext(bit(denormal, i), 6) << 1)
            | (zext(bits(e, 1, 2), 6) << 2)
            | (zext(underflow, 6) << 4)
            | (zext(bit(e, 4) | bit(flush, i), 6) << 5);
    }
    raised
}

// x86's result of an operation on the `w`-bit lanes of `x`, `y` and `z`
// (DAZ applied; an operation with fewer operands repeats one) whose IEEE
// result is `r`, with exceptions `s`; MXCSR's flags set, or #XM.
//
// - DE: a denormal operand (after DAZ), unless an operand is a NaN or the
//   lane raises invalid or divide-by-zero (which take precedence).
// - Tiny: rounded with an unbounded exponent, below the smallest normal
//   number (x86 detects tininess after rounding, as IEEE 754 defines it):
//   a subnormal result, or one L0 says underflowed (a result that rounded
//   up to the smallest normal number can be tiny).
// - FTZ (with underflow masked) makes a tiny result a zero of its sign.
// - A NaN operand gives itself quieted (the first in operand order); a NaN
//   from numbers is the indefinite.
fn sse_finish(x: Op, y: Op, z: Op, r: Op, s: Op, w: Op) {
    let n = width(r) / w;
    let ftz = bit(mxcsr, 15) == 1 && bit(mxcsr, 11) == 1;
    let denormal = lanes(
        n,
        (is_denormal(x, w) || is_denormal(y, w) || is_denormal(z, w))
            && !(is_nan(x, w) || is_nan(y, w) || is_nan(z, w))
            && bits(s, 0, 2) == 0,
    );
    let tiny = lanes(n, is_denormal(r, w) || bit(s, 3) == 1);
    let flush = lanes(n, ftz && tiny);
    let value = lanes(
        n,
        if is_nan(x, w) {
            quiet(x, w)
        } else if is_nan(y, w) {
            quiet(y, w)
        } else if is_nan(z, w) {
            quiet(z, w)
        } else if is_nan(r, w) {
            indefinite(w)
        } else if flush {
            signed_zero(r, w)
        } else {
            r
        },
    );
    sse_raise(sse_flags(s, denormal, flush, tiny, n));
    value
}

// An SSE arithmetic operation (`op`: add, sub, mul, div) on the `w`-bit
// lanes of `a` and `b`: x86's result, with MXCSR's flags set, or #XM.
fn sse_arith(op: Op, a: Op, b: Op, w: Op) {
    let n = width(a) / w;
    let rc = bits(mxcsr, 13, 2);
    let x = sse_daz(a, w);
    let y = sse_daz(b, w);
    sse_finish(
        x,
        y,
        y,
        lanes(n, farith(op, x, y, rc)),
        lanes(n, status(farith(op, x, y, rc))),
        w,
    )
}

// A VEX scalar operation: the low `w` bits from `op`, the rest of the
// first source's 128 bits kept.
fn vex_scalar(op: Op, a: Op, b: Op, w: Op) {
    concat(bits(a, w, 128 - w), sse_arith(op, bits(a, 0, w), b, w))
}

// Square roots of the `w`-bit lanes of `a`.
fn sse_sqrt(a: Op, w: Op) {
    let n = width(a) / w;
    let rc = bits(mxcsr, 13, 2);
    let x = sse_daz(a, w);
    sse_finish(
        x,
        x,
        x,
        lanes(n, fsqrt(x, rc)),
        lanes(n, status(fsqrt(x, rc))),
        w,
    )
}

// IE for each lane of `s` (L0's exceptions) that raised invalid, DE for
// each with a denormal operand among `x` and `y` and no NaN: the
// exceptions of comparisons.
fn sse_compare_flags(x: Op, y: Op, s: Op, w: Op) {
    let n = width(x) / w;
    let denormal = lanes(
        n,
        (is_denormal(x, w) || is_denormal(y, w)) && !(is_nan(x, w) || is_nan(y, w)),
    );
    let raised = zext(0, 6);
    for i in 0..n {
        raised = raised | zext(bit(s, i * 5), 6) | (zext(bit(denormal, i), 6) << 1);
    }
    sse_raise(raised);
}

// MIN and MAX (`greater` 0 or 1) of the `w`-bit lanes of `a` and `b`: the
// first if it is less (greater), else the second, also when either is a
// NaN (returned as it is) or both are zeros. A signalling comparison:
// invalid for any NaN. With DAZ a denormal result is returned as the zero
// it counts as (measured).
fn sse_minmax(a: Op, b: Op, greater: Op, w: Op) {
    let n = width(a) / w;
    let x = sse_daz(a, w);
    let y = sse_daz(b, w);
    let relation = lanes(n, fcmps(x, y));
    sse_compare_flags(x, y, lanes(n, status(fcmps(x, y))), w);
    lanes(
        n,
        if bit(relation, greater * 2) == 1 {
            x
        } else {
            y
        },
    )
}

// CMPPS and the like: a mask per lane, all ones where the predicate
// `imm & mask` holds. Predicates 0 to 3 are equal, less, less or equal,
// unordered; 4 to 7 their negations; 8 adds or removes unordered from the
// relation; 16 (VEX) changes quiet to signalling and back. Predicates 1,
// 2, 5, 6, 9, 10, 13, 14 are signalling (invalid for any NaN, not only a
// signalling one).
fn sse_cmp(a: Op, b: Op, imm: Op, mask: Op, w: Op) {
    let n = width(a) / w;
    let x = sse_daz(a, w);
    let y = sse_daz(b, w);
    let p = imm & mask;
    let base = bits(p, 0, 2);
    let relations = if base == 0 {
        zext(2, 4)
    } else if base == 1 {
        zext(1, 4)
    } else if base == 2 {
        zext(3, 4)
    } else {
        zext(8, 4)
    };
    let holds = relations ^ sext(bit(p, 2), 4) ^ (zext(bit(p, 3), 4) << 3);
    let signalling = (base == 1 || base == 2) ^ (bit(p, 4) == 1);
    let s = if signalling {
        lanes(n, status(fcmps(x, y)))
    } else {
        lanes(n, status(fcmp(x, y)))
    };
    sse_compare_flags(x, y, s, w);
    lanes(n, sext((fcmp(x, y) & holds) != 0, w))
}

// COMISS and UCOMISS (`signalling` 1 or 0): ZF, PF, CF = 111 unordered,
// 000 greater, 001 less, 100 equal.
fn sse_comis(a: Op, b: Op, signalling: Op, w: Op) {
    let x = sse_daz(bits(a, 0, w), w);
    let y = sse_daz(b, w);
    let relation = fcmp(x, y);
    let s = if signalling == 1 {
        status(fcmps(x, y))
    } else {
        status(fcmp(x, y))
    };
    sse_compare_flags(x, y, s, w);
    zf = bit(relation, 1) | bit(relation, 3);
    pf = bit(relation, 3);
    cf = bit(relation, 0) | bit(relation, 3);
}

// The `w`-bit float lanes of `a` as `iw`-bit integers, rounded as `rc`
// says: IE and the integer indefinite (the sign bit alone) for a NaN or a
// value out of range, else PE if inexact. No DE: a denormal is a number
// that rounds to 0 (or ±1).
fn sse_ftoi(a: Op, w: Op, iw: Op, rc: Op) {
    let n = width(a) / w;
    let x = sse_daz(a, w);
    let r = lanes(n, ftoi(x, iw, rc));
    let s = lanes(n, status(ftoi(x, iw, rc)));
    let raised = zext(0, 6);
    for i in 0..n {
        let invalid = bit(s, i * 5);
        raised = raised | zext(invalid, 6) | (zext(bit(s, i * 5 + 4) & !invalid, 6) << 5);
    }
    sse_raise(raised);
    lanes(n, if bit(s, 0) == 1 { 1 << (iw - 1) } else { r })
}

// The `iw`-bit integer lanes of `a` as `w`-bit floats: PE if inexact.
fn sse_itof(a: Op, iw: Op, w: Op) {
    let n = width(a) / iw;
    let rc = bits(mxcsr, 13, 2);
    let s = lanes(n, status(itof(a, w, rc)));
    let raised = zext(0, 6);
    for i in 0..n {
        raised = raised | (zext(bit(s, i * 5 + 4), 6) << 5);
    }
    sse_raise(raised);
    lanes(n, itof(a, w, rc))
}

// A NaN of the `from`-bit format in the `to`-bit format, quieted: its sign
// and the high bits of its payload (in lanes).
fn sse_nan_widen(x: Op, from: Op, to: Op) {
    let z = zext(x, to);
    ((z >> (from - 1)) << (to - 1))
        | (((1 << (exponent(to) + 1)) - 1) << (fraction(to) - 1))
        | ((z & ((1 << fraction(from)) - 1)) << (fraction(to) - fraction(from)))
}

fn sse_nan_narrow(x: Op, from: Op, to: Op) {
    (trunc(x >> (from - 1), to) << (to - 1))
        | (((1 << (exponent(to) + 1)) - 1) << (fraction(to) - 1))
        | (trunc(x >> (fraction(from) - fraction(to)), to) & ((1 << fraction(to)) - 1))
}

// The `from`-bit float lanes of `a` in the wider `to`-bit format (exact):
// IE for a signalling NaN; with `sse` 1, DAZ applies and a denormal raises
// DE (with 0, as F16C does, neither).
fn sse_widen(a: Op, from: Op, to: Op, sse: Op) {
    let n = width(a) / from;
    let x = if sse == 1 { sse_daz(a, from) } else { a };
    let s = lanes(n, status(fcvt(x, to, 0)));
    let denormal = lanes(n, sse == 1 && is_denormal(x, from));
    let raised = zext(0, 6);
    for i in 0..n {
        raised = raised | zext(bit(s, i * 5), 6) | (zext(bit(denormal, i), 6) << 1);
    }
    sse_raise(raised);
    lanes(
        n,
        if is_nan(x, from) {
            sse_nan_widen(x, from, to)
        } else {
            fcvt(x, to, 0)
        },
    )
}

// The `from`-bit float lanes of `a` in the narrower `to`-bit format,
// rounded as `rc` says, with the rules of `sse_finish` (`ftz` 0 ignores
// FTZ): the exceptions raised (6 bits, MXCSR's order) above the result.
fn sse_narrow_raised(a: Op, from: Op, to: Op, rc: Op, ftz: Op) {
    let n = width(a) / from;
    let x = sse_daz(a, from);
    let r = lanes(n, fcvt(x, to, rc));
    let s = lanes(n, status(fcvt(x, to, rc)));
    let flushing = ftz == 1 && bit(mxcsr, 15) == 1 && bit(mxcsr, 11) == 1;
    let denormal = lanes(n, is_denormal(x, from));
    let tiny = lanes(n, is_denormal(r, to) || bit(s, 3) == 1);
    let flush = lanes(n, flushing && tiny);
    let value = lanes(
        n,
        if is_nan(x, from) {
            sse_nan_narrow(x, from, to)
        } else if flush {
            signed_zero(r, to)
        } else {
            r
        },
    );
    concat(sse_flags(s, denormal, flush, tiny, n), value)
}

fn sse_narrow(a: Op, from: Op, to: Op, rc: Op, ftz: Op) {
    let r = sse_narrow_raised(a, from, to, rc, ftz);
    sse_raise(bits(r, width(r) - 6, 6));
    bits(r, 0, width(r) - 6)
}

// ROUNDPS and the like: the `w`-bit lanes of `a` rounded to integers as
// `imm` says: bits 1:0 the rounding, bit 2 MXCSR's instead, bit 3 no PE.
// IE for a signalling NaN; no DE.
fn sse_round(a: Op, imm: Op, w: Op) {
    let n = width(a) / w;
    let x = sse_daz(a, w);
    let rc = if bit(imm, 2) == 1 {
        bits(mxcsr, 13, 2)
    } else {
        bits(imm, 0, 2)
    };
    let s = lanes(n, status(fround(x, rc)));
    let raised = zext(0, 6);
    for i in 0..n {
        raised = raised | zext(bit(s, i * 5), 6) | (zext(bit(s, i * 5 + 4) & !bit(imm, 3), 6) << 5);
    }
    sse_raise(raised);
    lanes(
        n,
        if is_nan(x, w) {
            quiet(x, w)
        } else {
            fround(x, rc)
        },
    )
}

// Lanes `odd`, `odd + 2`, `odd + 4`, ... of the `w`-bit lanes of `a`.
fn sse_alternate(a: Op, w: Op, odd: Op) {
    let r = bits(a, odd * w, w);
    for j in 1..width(a) / w / 2 {
        r = concat(bits(a, (2 * j + odd) * w, w), r);
    }
    r
}

// The lanes of `even` and `odd` interleaved: even's first.
fn sse_interleave(even: Op, odd: Op, w: Op) {
    let r = concat(bits(odd, 0, w), bits(even, 0, w));
    for j in 1..width(even) / w {
        r = concat(concat(bits(odd, j * w, w), bits(even, j * w, w)), r);
    }
    r
}

// For HADD and HSUB: per 128-bit block, the lanes `odd`, `odd + 2`, ... of
// `a`'s block, then those of `b`'s.
fn sse_pairs(a: Op, b: Op, w: Op, odd: Op) {
    let x = sse_alternate(a, w, odd);
    let y = sse_alternate(b, w, odd);
    let r = concat(bits(y, 0, 64), bits(x, 0, 64));
    for k in 1..width(a) / 128 {
        r = concat(concat(bits(y, k * 64, 64), bits(x, k * 64, 64)), r);
    }
    r
}

fn sse_horizontal(op: Op, a: Op, b: Op, w: Op) {
    sse_arith(op, sse_pairs(a, b, w, 0), sse_pairs(a, b, w, 1), w)
}

// ADDSUBPS: even lanes subtract, odd lanes add.
fn sse_addsub(a: Op, b: Op, w: Op) {
    let even = sse_arith(sub(), sse_alternate(a, w, 0), sse_alternate(b, w, 0), w);
    let odd = sse_arith(add(), sse_alternate(a, w, 1), sse_alternate(b, w, 1), w);
    sse_interleave(even, odd, w)
}

// DPPS, per 128-bit block: the products of the lanes `imm` bits 7:4
// select (+0.0 for the others), summed in pairs, each operation rounded
// with its own exceptions; the sum in the lanes bits 3:0 select, +0.0 in
// the others. The order of the operands decides which NaN a sum of two
// gives; measured, it is not the SDM's (p0 + p1) + (p2 + p3) and differs
// between result lanes: lanes 0 and 1 get (p1 + p0) + (p3 + p2), lanes 2
// and 3 get (p3 + p2) + (p1 + p0).
fn sse_dpps(a: Op, b: Op, imm: Op) {
    let n = width(a) / 32;
    let x = if bit(imm, 4) == 1 { bits(a, 0, 32) } else { 0 };
    let y = if bit(imm, 4) == 1 { bits(b, 0, 32) } else { 0 };
    for i in 1..n {
        let select = bit(imm, 4 + i - i / 4 * 4) == 1;
        x = concat(if select { bits(a, i * 32, 32) } else { 0 }, x);
        y = concat(if select { bits(b, i * 32, 32) } else { 0 }, y);
    }
    let p = sse_arith(mul(), x, y, 32);
    let t = sse_arith(add(), sse_alternate(p, 32, 1), sse_alternate(p, 32, 0), 32);
    let low = sse_arith(add(), sse_alternate(t, 32, 0), sse_alternate(t, 32, 1), 32);
    let high = sse_arith(add(), sse_alternate(t, 32, 1), sse_alternate(t, 32, 0), 32);
    let sums = concat(high, low);
    let r = if bit(imm, 0) == 1 {
        bits(low, 0, 32)
    } else {
        0
    };
    for i in 1..n {
        let k = i / 4;
        let at = (i - k * 4) / 2 * width(low) + k * 32;
        r = concat(
            if bit(imm, i - k * 4) == 1 {
                bits(sums, at, 32)
            } else {
                0
            },
            r,
        );
    }
    r
}

// DPPD: the same with two lanes, imm bits 5:4 and 1:0; lane 0 gets
// p0 + p1, lane 1 p1 + p0 (measured).
fn sse_dppd(a: Op, b: Op, imm: Op) {
    let x = concat(
        if bit(imm, 5) == 1 { bits(a, 64, 64) } else { 0 },
        if bit(imm, 4) == 1 { bits(a, 0, 64) } else { 0 },
    );
    let y = concat(
        if bit(imm, 5) == 1 { bits(b, 64, 64) } else { 0 },
        if bit(imm, 4) == 1 { bits(b, 0, 64) } else { 0 },
    );
    let p = sse_arith(mul(), x, y, 64);
    let low = sse_arith(add(), bits(p, 0, 64), bits(p, 64, 64), 64);
    let high = sse_arith(add(), bits(p, 64, 64), bits(p, 0, 64), 64);
    concat(
        if bit(imm, 1) == 1 { high } else { 0 },
        if bit(imm, 0) == 1 { low } else { 0 },
    )
}

// A fused multiply-add on the `w`-bit lanes of `a`, `b`, `c` (DAZ
// applied): `xa` × `b` + `zc` rounded once, where `xa` and `zc` are `a`
// and `c` with the instruction's negations.
//
// With a NaN operand, invalid is raised only for a signalling NaN: 0 × ∞
// plus a quiet NaN is not invalid (IEEE 754 leaves it open).
fn sse_fma_with(x: Op, y: Op, z: Op, xa: Op, zc: Op, w: Op) {
    let n = width(x) / w;
    let rc = bits(mxcsr, 13, 2);
    let s = lanes(n, status(fma(xa, y, zc, rc)));
    let nan = lanes(n, is_nan(x, w) || is_nan(y, w) || is_nan(z, w));
    let signalling = lanes(n, is_snan(x, w) || is_snan(y, w) || is_snan(z, w));
    sse_finish(
        x,
        y,
        z,
        lanes(n, fma(xa, y, zc, rc)),
        lanes(n, if nan { zext(signalling, 5) } else { s }),
        w,
    )
}

// ±(a × b) ± c: `na` 1 negates the product, `nc` 1 the addend.
fn sse_fma(a: Op, b: Op, c: Op, na: Op, nc: Op, w: Op) {
    let n = width(a) / w;
    let x = sse_daz(a, w);
    let y = sse_daz(b, w);
    let z = sse_daz(c, w);
    sse_fma_with(
        x,
        y,
        z,
        lanes(n, x ^ (na << (w - 1))),
        lanes(n, z ^ (nc << (w - 1))),
        w,
    )
}

// VFMADDSUB (`odd_sub` 0) and VFMSUBADD (1): a × b − c in the even lanes
// and a × b + c in the odd ones, or the reverse.
fn sse_fmaddsub(a: Op, b: Op, c: Op, odd_sub: Op, w: Op) {
    let n = width(a) / w;
    let x = sse_daz(a, w);
    let y = sse_daz(b, w);
    let z = sse_daz(c, w);
    let even = lanes(n, z ^ ((1 - odd_sub) << (w - 1)));
    let odd = lanes(n, z ^ (odd_sub << (w - 1)));
    let zc = sse_interleave(sse_alternate(even, w, 0), sse_alternate(odd, w, 1), w);
    sse_fma_with(x, y, z, x, zc, w)
}

// RCPPS and RSQRTPS approximate (the bits differ between processor
// models): an intrinsic per 32-bit lane. MXCSR is neither used nor changed.
fn sse_rcp(a: Op) {
    let r = intrinsic("rcp", bits(a, 0, 32));
    for i in 1..width(a) / 32 {
        r = concat(intrinsic("rcp", bits(a, i * 32, 32)), r);
    }
    r
}

fn sse_rsqrt(a: Op) {
    let r = intrinsic("rsqrt", bits(a, 0, 32));
    for i in 1..width(a) / 32 {
        r = concat(intrinsic("rsqrt", bits(a, i * 32, 32)), r);
    }
    r
}

#[iclass(ADDPS, ADDSS)]
fn addps(dst: Op, src: Op) {
    dst = sse_arith(add(), dst, src, 32);
}

#[iclass(ADDPD, ADDSD)]
fn addpd(dst: Op, src: Op) {
    dst = sse_arith(add(), dst, src, 64);
}

#[iclass(SUBPS, SUBSS)]
fn subps(dst: Op, src: Op) {
    dst = sse_arith(sub(), dst, src, 32);
}

#[iclass(SUBPD, SUBSD)]
fn subpd(dst: Op, src: Op) {
    dst = sse_arith(sub(), dst, src, 64);
}

#[iclass(MULPS, MULSS)]
fn mulps(dst: Op, src: Op) {
    dst = sse_arith(mul(), dst, src, 32);
}

#[iclass(MULPD, MULSD)]
fn mulpd(dst: Op, src: Op) {
    dst = sse_arith(mul(), dst, src, 64);
}

#[iclass(DIVPS, DIVSS)]
fn divps(dst: Op, src: Op) {
    dst = sse_arith(div(), dst, src, 32);
}

#[iclass(DIVPD, DIVSD)]
fn divpd(dst: Op, src: Op) {
    dst = sse_arith(div(), dst, src, 64);
}

#[iclass(VADDPS)]
fn vaddps(dst: Op, a: Op, b: Op) {
    dst = sse_arith(add(), a, b, 32);
}

#[iclass(VADDPD)]
fn vaddpd(dst: Op, a: Op, b: Op) {
    dst = sse_arith(add(), a, b, 64);
}

#[iclass(VSUBPS)]
fn vsubps(dst: Op, a: Op, b: Op) {
    dst = sse_arith(sub(), a, b, 32);
}

#[iclass(VSUBPD)]
fn vsubpd(dst: Op, a: Op, b: Op) {
    dst = sse_arith(sub(), a, b, 64);
}

#[iclass(VMULPS)]
fn vmulps(dst: Op, a: Op, b: Op) {
    dst = sse_arith(mul(), a, b, 32);
}

#[iclass(VMULPD)]
fn vmulpd(dst: Op, a: Op, b: Op) {
    dst = sse_arith(mul(), a, b, 64);
}

#[iclass(VDIVPS)]
fn vdivps(dst: Op, a: Op, b: Op) {
    dst = sse_arith(div(), a, b, 32);
}

#[iclass(VDIVPD)]
fn vdivpd(dst: Op, a: Op, b: Op) {
    dst = sse_arith(div(), a, b, 64);
}

#[iclass(VADDSS)]
fn vaddss(dst: Op, a: Op, b: Op) {
    dst = vex_scalar(add(), a, b, 32);
}

#[iclass(VADDSD)]
fn vaddsd(dst: Op, a: Op, b: Op) {
    dst = vex_scalar(add(), a, b, 64);
}

#[iclass(VSUBSS)]
fn vsubss(dst: Op, a: Op, b: Op) {
    dst = vex_scalar(sub(), a, b, 32);
}

#[iclass(VSUBSD)]
fn vsubsd(dst: Op, a: Op, b: Op) {
    dst = vex_scalar(sub(), a, b, 64);
}

#[iclass(VMULSS)]
fn vmulss(dst: Op, a: Op, b: Op) {
    dst = vex_scalar(mul(), a, b, 32);
}

#[iclass(VMULSD)]
fn vmulsd(dst: Op, a: Op, b: Op) {
    dst = vex_scalar(mul(), a, b, 64);
}

#[iclass(VDIVSS)]
fn vdivss(dst: Op, a: Op, b: Op) {
    dst = vex_scalar(div(), a, b, 32);
}

#[iclass(VDIVSD)]
fn vdivsd(dst: Op, a: Op, b: Op) {
    dst = vex_scalar(div(), a, b, 64);
}

#[iclass(SQRTPS, SQRTSS)]
fn sqrtps(dst: Op, src: Op) {
    dst = sse_sqrt(src, 32);
}

#[iclass(SQRTPD, SQRTSD)]
fn sqrtpd(dst: Op, src: Op) {
    dst = sse_sqrt(src, 64);
}

#[iclass(VSQRTPS)]
fn vsqrtps(dst: Op, src: Op) {
    dst = sse_sqrt(src, 32);
}

#[iclass(VSQRTPD)]
fn vsqrtpd(dst: Op, src: Op) {
    dst = sse_sqrt(src, 64);
}

#[iclass(VSQRTSS)]
fn vsqrtss(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 32, 96), sse_sqrt(b, 32));
}

#[iclass(VSQRTSD)]
fn vsqrtsd(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 64, 64), sse_sqrt(b, 64));
}

#[iclass(MINPS, MINSS)]
fn minps(dst: Op, src: Op) {
    dst = sse_minmax(dst, src, 0, 32);
}

#[iclass(MINPD, MINSD)]
fn minpd(dst: Op, src: Op) {
    dst = sse_minmax(dst, src, 0, 64);
}

#[iclass(VMINPS)]
fn vminps(dst: Op, a: Op, b: Op) {
    dst = sse_minmax(a, b, 0, 32);
}

#[iclass(VMINPD)]
fn vminpd(dst: Op, a: Op, b: Op) {
    dst = sse_minmax(a, b, 0, 64);
}

#[iclass(VMINSS)]
fn vminss(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 32, 96), sse_minmax(bits(a, 0, 32), b, 0, 32));
}

#[iclass(VMINSD)]
fn vminsd(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 64, 64), sse_minmax(bits(a, 0, 64), b, 0, 64));
}

#[iclass(MAXPS, MAXSS)]
fn maxps(dst: Op, src: Op) {
    dst = sse_minmax(dst, src, 1, 32);
}

#[iclass(MAXPD, MAXSD)]
fn maxpd(dst: Op, src: Op) {
    dst = sse_minmax(dst, src, 1, 64);
}

#[iclass(VMAXPS)]
fn vmaxps(dst: Op, a: Op, b: Op) {
    dst = sse_minmax(a, b, 1, 32);
}

#[iclass(VMAXPD)]
fn vmaxpd(dst: Op, a: Op, b: Op) {
    dst = sse_minmax(a, b, 1, 64);
}

#[iclass(VMAXSS)]
fn vmaxss(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 32, 96), sse_minmax(bits(a, 0, 32), b, 1, 32));
}

#[iclass(VMAXSD)]
fn vmaxsd(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 64, 64), sse_minmax(bits(a, 0, 64), b, 1, 64));
}

// Legacy SSE comparisons take predicates 0 to 7 (imm bits 2:0).
#[iclass(CMPPS, CMPSS)]
fn cmpps(dst: Op, src: Op, imm: Op) {
    dst = sse_cmp(dst, src, imm, 7, 32);
}

#[iclass(CMPPD, CMPSD_XMM)]
fn cmppd(dst: Op, src: Op, imm: Op) {
    dst = sse_cmp(dst, src, imm, 7, 64);
}

#[iclass(VCMPPS)]
fn vcmpps(dst: Op, a: Op, b: Op, imm: Op) {
    dst = sse_cmp(a, b, imm, 31, 32);
}

#[iclass(VCMPPD)]
fn vcmppd(dst: Op, a: Op, b: Op, imm: Op) {
    dst = sse_cmp(a, b, imm, 31, 64);
}

#[iclass(VCMPSS)]
fn vcmpss(dst: Op, a: Op, b: Op, imm: Op) {
    dst = concat(bits(a, 32, 96), sse_cmp(bits(a, 0, 32), b, imm, 31, 32));
}

#[iclass(VCMPSD)]
fn vcmpsd(dst: Op, a: Op, b: Op, imm: Op) {
    dst = concat(bits(a, 64, 64), sse_cmp(bits(a, 0, 64), b, imm, 31, 64));
}

#[iclass(COMISS, VCOMISS)]
fn comiss(a: Op, b: Op) {
    sse_comis(a, b, 1, 32);
}

#[iclass(COMISD, VCOMISD)]
fn comisd(a: Op, b: Op) {
    sse_comis(a, b, 1, 64);
}

#[iclass(UCOMISS, VUCOMISS)]
fn ucomiss(a: Op, b: Op) {
    sse_comis(a, b, 0, 32);
}

#[iclass(UCOMISD, VUCOMISD)]
fn ucomisd(a: Op, b: Op) {
    sse_comis(a, b, 0, 64);
}

#[iclass(RCPPS, RCPSS, VRCPPS)]
fn rcpps(dst: Op, src: Op) {
    dst = sse_rcp(src);
}

#[iclass(RSQRTPS, RSQRTSS, VRSQRTPS)]
fn rsqrtps(dst: Op, src: Op) {
    dst = sse_rsqrt(src);
}

#[iclass(VRCPSS)]
fn vrcpss(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 32, 96), sse_rcp(b));
}

#[iclass(VRSQRTSS)]
fn vrsqrtss(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 32, 96), sse_rsqrt(b));
}

#[iclass(ROUNDPS, ROUNDSS, VROUNDPS)]
fn roundps(dst: Op, src: Op, imm: Op) {
    dst = sse_round(src, imm, 32);
}

#[iclass(ROUNDPD, ROUNDSD, VROUNDPD)]
fn roundpd(dst: Op, src: Op, imm: Op) {
    dst = sse_round(src, imm, 64);
}

#[iclass(VROUNDSS)]
fn vroundss(dst: Op, a: Op, b: Op, imm: Op) {
    dst = concat(bits(a, 32, 96), sse_round(b, imm, 32));
}

#[iclass(VROUNDSD)]
fn vroundsd(dst: Op, a: Op, b: Op, imm: Op) {
    dst = concat(bits(a, 64, 64), sse_round(b, imm, 64));
}

#[iclass(CVTDQ2PS, VCVTDQ2PS)]
fn cvtdq2ps(dst: Op, src: Op) {
    dst = sse_itof(src, 32, 32);
}

#[iclass(CVTDQ2PD, VCVTDQ2PD)]
fn cvtdq2pd(dst: Op, src: Op) {
    dst = sse_itof(src, 32, 64);
}

#[iclass(CVTSI2SS)]
fn cvtsi2ss(dst: Op, src: Op) {
    dst = sse_itof(src, width(src), 32);
}

#[iclass(CVTSI2SD)]
fn cvtsi2sd(dst: Op, src: Op) {
    dst = sse_itof(src, width(src), 64);
}

#[iclass(VCVTSI2SS)]
fn vcvtsi2ss(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 32, 96), sse_itof(b, width(b), 32));
}

#[iclass(VCVTSI2SD)]
fn vcvtsi2sd(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 64, 64), sse_itof(b, width(b), 64));
}

#[iclass(CVTPS2DQ, VCVTPS2DQ)]
fn cvtps2dq(dst: Op, src: Op) {
    dst = sse_ftoi(src, 32, 32, bits(mxcsr, 13, 2));
}

#[iclass(CVTTPS2DQ, VCVTTPS2DQ)]
fn cvttps2dq(dst: Op, src: Op) {
    dst = sse_ftoi(src, 32, 32, 3);
}

// Two or four doubles to as many integers in the low half or whole of an
// xmm register (the rest zero).
#[iclass(CVTPD2DQ, VCVTPD2DQ)]
fn cvtpd2dq(dst: Op, src: Op) {
    dst = zext(sse_ftoi(src, 64, 32, bits(mxcsr, 13, 2)), 128);
}

#[iclass(CVTTPD2DQ, VCVTTPD2DQ)]
fn cvttpd2dq(dst: Op, src: Op) {
    dst = zext(sse_ftoi(src, 64, 32, 3), 128);
}

#[iclass(CVTSS2SI, VCVTSS2SI)]
fn cvtss2si(dst: Op, src: Op) {
    dst = sse_ftoi(src, 32, width(dst), bits(mxcsr, 13, 2));
}

#[iclass(CVTTSS2SI, VCVTTSS2SI)]
fn cvttss2si(dst: Op, src: Op) {
    dst = sse_ftoi(src, 32, width(dst), 3);
}

#[iclass(CVTSD2SI, VCVTSD2SI)]
fn cvtsd2si(dst: Op, src: Op) {
    dst = sse_ftoi(src, 64, width(dst), bits(mxcsr, 13, 2));
}

#[iclass(CVTTSD2SI, VCVTTSD2SI)]
fn cvttsd2si(dst: Op, src: Op) {
    dst = sse_ftoi(src, 64, width(dst), 3);
}

#[iclass(CVTPS2PD, VCVTPS2PD, CVTSS2SD)]
fn cvtps2pd(dst: Op, src: Op) {
    dst = sse_widen(src, 32, 64, 1);
}

#[iclass(VCVTSS2SD)]
fn vcvtss2sd(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 64, 64), sse_widen(b, 32, 64, 1));
}

#[iclass(CVTPD2PS, VCVTPD2PS)]
fn cvtpd2ps(dst: Op, src: Op) {
    dst = zext(sse_narrow(src, 64, 32, bits(mxcsr, 13, 2), 1), 128);
}

#[iclass(CVTSD2SS)]
fn cvtsd2ss(dst: Op, src: Op) {
    dst = sse_narrow(src, 64, 32, bits(mxcsr, 13, 2), 1);
}

#[iclass(VCVTSD2SS)]
fn vcvtsd2ss(dst: Op, a: Op, b: Op) {
    dst = concat(
        bits(a, 32, 96),
        sse_narrow(b, 64, 32, bits(mxcsr, 13, 2), 1),
    );
}

// F16C: half-precision denormals are converted (no DAZ, no DE).
#[iclass(VCVTPH2PS)]
fn vcvtph2ps(dst: Op, src: Op) {
    dst = sse_widen(src, 16, 32, 0);
}

// F16C: rounded as imm bits 1:0 say, or as MXCSR says with bit 2; FTZ
// does not apply, DAZ does. Measured: a fault on the memory destination
// takes precedence over #XM, so the destination is written (and undone by
// the fault) before the exceptions are raised.
#[iclass(VCVTPS2PH)]
fn vcvtps2ph(dst: Op, src: Op, imm: Op) {
    let rc = if bit(imm, 2) == 1 {
        bits(mxcsr, 13, 2)
    } else {
        bits(imm, 0, 2)
    };
    let r = sse_narrow_raised(src, 32, 16, rc, 0);
    dst = bits(r, 0, width(r) - 6);
    sse_raise(bits(r, width(r) - 6, 6));
}

#[iclass(ADDSUBPS)]
fn addsubps(dst: Op, src: Op) {
    dst = sse_addsub(dst, src, 32);
}

#[iclass(ADDSUBPD)]
fn addsubpd(dst: Op, src: Op) {
    dst = sse_addsub(dst, src, 64);
}

#[iclass(VADDSUBPS)]
fn vaddsubps(dst: Op, a: Op, b: Op) {
    dst = sse_addsub(a, b, 32);
}

#[iclass(VADDSUBPD)]
fn vaddsubpd(dst: Op, a: Op, b: Op) {
    dst = sse_addsub(a, b, 64);
}

#[iclass(HADDPS)]
fn haddps(dst: Op, src: Op) {
    dst = sse_horizontal(add(), dst, src, 32);
}

#[iclass(HADDPD)]
fn haddpd(dst: Op, src: Op) {
    dst = sse_horizontal(add(), dst, src, 64);
}

#[iclass(VHADDPS)]
fn vhaddps(dst: Op, a: Op, b: Op) {
    dst = sse_horizontal(add(), a, b, 32);
}

#[iclass(VHADDPD)]
fn vhaddpd(dst: Op, a: Op, b: Op) {
    dst = sse_horizontal(add(), a, b, 64);
}

#[iclass(HSUBPS)]
fn hsubps(dst: Op, src: Op) {
    dst = sse_horizontal(sub(), dst, src, 32);
}

#[iclass(HSUBPD)]
fn hsubpd(dst: Op, src: Op) {
    dst = sse_horizontal(sub(), dst, src, 64);
}

#[iclass(VHSUBPS)]
fn vhsubps(dst: Op, a: Op, b: Op) {
    dst = sse_horizontal(sub(), a, b, 32);
}

#[iclass(VHSUBPD)]
fn vhsubpd(dst: Op, a: Op, b: Op) {
    dst = sse_horizontal(sub(), a, b, 64);
}

#[iclass(DPPS)]
fn dpps(dst: Op, src: Op, imm: Op) {
    dst = sse_dpps(dst, src, imm);
}

#[iclass(VDPPS)]
fn vdpps(dst: Op, a: Op, b: Op, imm: Op) {
    dst = sse_dpps(a, b, imm);
}

#[iclass(DPPD)]
fn dppd(dst: Op, src: Op, imm: Op) {
    dst = sse_dppd(dst, src, imm);
}

#[iclass(VDPPD)]
fn vdppd(dst: Op, a: Op, b: Op, imm: Op) {
    dst = sse_dppd(a, b, imm);
}

// LDMXCSR: #GP if a reserved bit (outside MXCSR_MASK, 0xffff here) is set.
#[iclass(LDMXCSR, VLDMXCSR)]
fn ldmxcsr(src: Op, control: Op) {
    if (src & 0xffff0000) != 0 {
        trap(GP);
    }
    control = src;
}

#[iclass(STMXCSR, VSTMXCSR)]
fn stmxcsr(dst: Op, control: Op) {
    dst = control;
}

#[iclass(VFMADD132PS)]
fn vfmadd132ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(dst, c, b, 0, 0, 32);
}

#[iclass(VFMADD132PD)]
fn vfmadd132pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(dst, c, b, 0, 0, 64);
}

#[iclass(VFMADD132SS)]
fn vfmadd132ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(bits(dst, 0, 32), c, b, 0, 0, 32));
}

#[iclass(VFMADD132SD)]
fn vfmadd132sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(bits(dst, 0, 64), c, b, 0, 0, 64));
}

#[iclass(VFMADD213PS)]
fn vfmadd213ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, dst, c, 0, 0, 32);
}

#[iclass(VFMADD213PD)]
fn vfmadd213pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, dst, c, 0, 0, 64);
}

#[iclass(VFMADD213SS)]
fn vfmadd213ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(b, bits(dst, 0, 32), c, 0, 0, 32));
}

#[iclass(VFMADD213SD)]
fn vfmadd213sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(b, bits(dst, 0, 64), c, 0, 0, 64));
}

#[iclass(VFMADD231PS)]
fn vfmadd231ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, c, dst, 0, 0, 32);
}

#[iclass(VFMADD231PD)]
fn vfmadd231pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, c, dst, 0, 0, 64);
}

#[iclass(VFMADD231SS)]
fn vfmadd231ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(b, c, bits(dst, 0, 32), 0, 0, 32));
}

#[iclass(VFMADD231SD)]
fn vfmadd231sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(b, c, bits(dst, 0, 64), 0, 0, 64));
}

#[iclass(VFMSUB132PS)]
fn vfmsub132ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(dst, c, b, 0, 1, 32);
}

#[iclass(VFMSUB132PD)]
fn vfmsub132pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(dst, c, b, 0, 1, 64);
}

#[iclass(VFMSUB132SS)]
fn vfmsub132ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(bits(dst, 0, 32), c, b, 0, 1, 32));
}

#[iclass(VFMSUB132SD)]
fn vfmsub132sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(bits(dst, 0, 64), c, b, 0, 1, 64));
}

#[iclass(VFMSUB213PS)]
fn vfmsub213ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, dst, c, 0, 1, 32);
}

#[iclass(VFMSUB213PD)]
fn vfmsub213pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, dst, c, 0, 1, 64);
}

#[iclass(VFMSUB213SS)]
fn vfmsub213ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(b, bits(dst, 0, 32), c, 0, 1, 32));
}

#[iclass(VFMSUB213SD)]
fn vfmsub213sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(b, bits(dst, 0, 64), c, 0, 1, 64));
}

#[iclass(VFMSUB231PS)]
fn vfmsub231ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, c, dst, 0, 1, 32);
}

#[iclass(VFMSUB231PD)]
fn vfmsub231pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, c, dst, 0, 1, 64);
}

#[iclass(VFMSUB231SS)]
fn vfmsub231ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(b, c, bits(dst, 0, 32), 0, 1, 32));
}

#[iclass(VFMSUB231SD)]
fn vfmsub231sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(b, c, bits(dst, 0, 64), 0, 1, 64));
}

#[iclass(VFNMADD132PS)]
fn vfnmadd132ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(dst, c, b, 1, 0, 32);
}

#[iclass(VFNMADD132PD)]
fn vfnmadd132pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(dst, c, b, 1, 0, 64);
}

#[iclass(VFNMADD132SS)]
fn vfnmadd132ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(bits(dst, 0, 32), c, b, 1, 0, 32));
}

#[iclass(VFNMADD132SD)]
fn vfnmadd132sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(bits(dst, 0, 64), c, b, 1, 0, 64));
}

#[iclass(VFNMADD213PS)]
fn vfnmadd213ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, dst, c, 1, 0, 32);
}

#[iclass(VFNMADD213PD)]
fn vfnmadd213pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, dst, c, 1, 0, 64);
}

#[iclass(VFNMADD213SS)]
fn vfnmadd213ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(b, bits(dst, 0, 32), c, 1, 0, 32));
}

#[iclass(VFNMADD213SD)]
fn vfnmadd213sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(b, bits(dst, 0, 64), c, 1, 0, 64));
}

#[iclass(VFNMADD231PS)]
fn vfnmadd231ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, c, dst, 1, 0, 32);
}

#[iclass(VFNMADD231PD)]
fn vfnmadd231pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, c, dst, 1, 0, 64);
}

#[iclass(VFNMADD231SS)]
fn vfnmadd231ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(b, c, bits(dst, 0, 32), 1, 0, 32));
}

#[iclass(VFNMADD231SD)]
fn vfnmadd231sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(b, c, bits(dst, 0, 64), 1, 0, 64));
}

#[iclass(VFNMSUB132PS)]
fn vfnmsub132ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(dst, c, b, 1, 1, 32);
}

#[iclass(VFNMSUB132PD)]
fn vfnmsub132pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(dst, c, b, 1, 1, 64);
}

#[iclass(VFNMSUB132SS)]
fn vfnmsub132ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(bits(dst, 0, 32), c, b, 1, 1, 32));
}

#[iclass(VFNMSUB132SD)]
fn vfnmsub132sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(bits(dst, 0, 64), c, b, 1, 1, 64));
}

#[iclass(VFNMSUB213PS)]
fn vfnmsub213ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, dst, c, 1, 1, 32);
}

#[iclass(VFNMSUB213PD)]
fn vfnmsub213pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, dst, c, 1, 1, 64);
}

#[iclass(VFNMSUB213SS)]
fn vfnmsub213ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(b, bits(dst, 0, 32), c, 1, 1, 32));
}

#[iclass(VFNMSUB213SD)]
fn vfnmsub213sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(b, bits(dst, 0, 64), c, 1, 1, 64));
}

#[iclass(VFNMSUB231PS)]
fn vfnmsub231ps(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, c, dst, 1, 1, 32);
}

#[iclass(VFNMSUB231PD)]
fn vfnmsub231pd(dst: Op, b: Op, c: Op) {
    dst = sse_fma(b, c, dst, 1, 1, 64);
}

#[iclass(VFNMSUB231SS)]
fn vfnmsub231ss(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 32, 96), sse_fma(b, c, bits(dst, 0, 32), 1, 1, 32));
}

#[iclass(VFNMSUB231SD)]
fn vfnmsub231sd(dst: Op, b: Op, c: Op) {
    dst = concat(bits(dst, 64, 64), sse_fma(b, c, bits(dst, 0, 64), 1, 1, 64));
}

#[iclass(VFMADDSUB132PS)]
fn vfmaddsub132ps(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(dst, c, b, 0, 32);
}

#[iclass(VFMADDSUB132PD)]
fn vfmaddsub132pd(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(dst, c, b, 0, 64);
}

#[iclass(VFMADDSUB213PS)]
fn vfmaddsub213ps(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(b, dst, c, 0, 32);
}

#[iclass(VFMADDSUB213PD)]
fn vfmaddsub213pd(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(b, dst, c, 0, 64);
}

#[iclass(VFMADDSUB231PS)]
fn vfmaddsub231ps(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(b, c, dst, 0, 32);
}

#[iclass(VFMADDSUB231PD)]
fn vfmaddsub231pd(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(b, c, dst, 0, 64);
}

#[iclass(VFMSUBADD132PS)]
fn vfmsubadd132ps(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(dst, c, b, 1, 32);
}

#[iclass(VFMSUBADD132PD)]
fn vfmsubadd132pd(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(dst, c, b, 1, 64);
}

#[iclass(VFMSUBADD213PS)]
fn vfmsubadd213ps(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(b, dst, c, 1, 32);
}

#[iclass(VFMSUBADD213PD)]
fn vfmsubadd213pd(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(b, dst, c, 1, 64);
}

#[iclass(VFMSUBADD231PS)]
fn vfmsubadd231ps(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(b, c, dst, 1, 32);
}

#[iclass(VFMSUBADD231PD)]
fn vfmsubadd231pd(dst: Op, b: Op, c: Op) {
    dst = sse_fmaddsub(b, c, dst, 1, 64);
}
