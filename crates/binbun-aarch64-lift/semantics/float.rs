// Scalar floating-point arithmetic: Arm's shared pseudocode (FPUnpack,
// FPProcessNaNs, FPRound, FPProcessException and the operations built on
// them) around L0's IEEE operations, in every FPCR state.
//
// FPCR: FIZ (bit 0, FEAT_AFP) takes denormal inputs as zeros; AH (1) is
// the alternative handling of NaNs, denormals and tiny results; NEP (2)
// merges a scalar result into the bits of a register; FZ16 (19) flushes
// half-precision denormals to zero, FZ (24) single and double ones; RMode
// (22 and 23) is the rounding; DN (25) gives the default NaN for any NaN;
// AHP (26) is the alternative half-precision format of conversions. FPSR's
// cumulative flags are IOC, DZC, OFC, UFC, IXC (bits 0 to 4, the order of
// L0's exceptions) and IDC (7). binbun's context traps no floating-point
// exception: FPCR's trap enables are zero (they read as zero where an
// implementation has no trapping), so each exception sets its flag.

// The operations of `farith`.
fn fp_add() {
    0
}

fn fp_sub() {
    1
}

fn fp_mul() {
    2
}

fn fp_div() {
    3
}

// Fraction and exponent widths of the `w`-bit format.
fn fp_fraction(w: Op) {
    if w == 16 {
        10
    } else if w == 32 {
        23
    } else {
        52
    }
}

fn fp_exponent(w: Op) {
    if w == 16 {
        5
    } else if w == 32 {
        8
    } else {
        11
    }
}

fn fp_is_nan(x: Op, w: Op) {
    bits(x, fp_fraction(w), fp_exponent(w)) == (1 << fp_exponent(w)) - 1
        && bits(x, 0, fp_fraction(w)) != 0
}

fn fp_is_snan(x: Op, w: Op) {
    fp_is_nan(x, w) && bit(x, fp_fraction(w) - 1) == 0
}

fn fp_is_qnan(x: Op, w: Op) {
    fp_is_nan(x, w) && bit(x, fp_fraction(w) - 1) == 1
}

fn fp_is_denormal(x: Op, w: Op) {
    bits(x, fp_fraction(w), fp_exponent(w)) == 0 && bits(x, 0, fp_fraction(w)) != 0
}

fn fp_is_zero(x: Op, w: Op) {
    bits(x, 0, w - 1) == 0
}

fn fp_is_infinity(x: Op, w: Op) {
    bits(x, 0, w - 1) == ((1 << fp_exponent(w)) - 1) << fp_fraction(w)
}

// The zero of `x`'s sign.
fn fp_signed_zero(x: Op, w: Op) {
    x & (1 << (w - 1))
}

// The infinity of `x`'s sign.
fn fp_signed_infinity(x: Op, w: Op) {
    fp_signed_zero(x, w) | (((1 << fp_exponent(w)) - 1) << fp_fraction(w))
}

fn fp_quiet(x: Op, w: Op) {
    x | (1 << (fp_fraction(w) - 1))
}

// L0's rounding (0 nearest, 1 down, 2 up, 3 toward zero) of FPCR.RMode
// (Arm's 0 RN, 1 RP, 2 RM, 3 RZ): its two bits swapped.
fn fp_rounding() {
    concat(bit(fpcr, 22), bit(fpcr, 23))
}

fn fp_ah() {
    bit(fpcr, 1)
}

// FPDefaultNaN: quiet, payload 0, negative with AH.
fn fp_default_nan(w: Op) {
    (zext(fp_ah(), w) << (w - 1)) | (((1 << (fp_exponent(w) + 1)) - 1) << (fp_fraction(w) - 1))
}

// Whether FPUnpack takes a `w`-bit denormal as a zero: FZ16 (half
// precision); FIZ, or FZ without AH (single, double).
fn fp_flushes_input(w: Op) {
    if w == 16 {
        bit(fpcr, 19)
    } else {
        bit(fpcr, 0) | (bit(fpcr, 24) & !fp_ah())
    }
}

// Whether FPRound flushes a tiny `w`-bit result to zero: FZ16, or FZ.
fn fp_flushes_output(w: Op) {
    if w == 16 {
        bit(fpcr, 19)
    } else {
        bit(fpcr, 24)
    }
}

// FPUnpack: `x`, or the zero of its sign if it is a denormal taken as one.
fn fp_unpack(x: Op, w: Op) {
    if fp_flushes_input(w) == 1 && fp_is_denormal(x, w) {
        fp_signed_zero(x, w)
    } else {
        x
    }
}

// FPUnpack's input denormal exception: FZ without AH taking a single or
// double denormal as a zero (FIZ alone raises none).
fn fp_input_denormal(x: Op, w: Op) {
    if w == 16 {
        zext(0, 1)
    } else {
        bit(fpcr, 24) & !fp_ah() & fp_is_denormal(x, w)
    }
}

// FPProcessDenorms: with AH, a single or double denormal operand (after
// FPUnpack) raises input denormal.
fn fp_denormal_operand(x: Op, w: Op) {
    if w == 16 {
        zext(0, 1)
    } else {
        fp_ah() & fp_is_denormal(x, w)
    }
}

// FPProcessNaN: a NaN quieted, or the default NaN with DN.
fn fp_process_nan(x: Op, w: Op) {
    if bit(fpcr, 25) == 1 {
        fp_default_nan(w)
    } else {
        fp_quiet(x, w)
    }
}

// FPProcessNaNs (one of `a` and `b` a NaN): the first signalling NaN, else
// the first NaN; with AH, the first if both are NaNs.
fn fp_nans(a: Op, b: Op, w: Op) {
    if fp_is_snan(a, w) || (fp_is_nan(a, w) && (fp_ah() == 1 || !fp_is_snan(b, w))) {
        fp_process_nan(a, w)
    } else {
        fp_process_nan(b, w)
    }
}

// FPNeg: the sign inverted, but a NaN's with AH.
fn fp_neg(x: Op, w: Op) {
    if fp_ah() == 1 && fp_is_nan(x, w) {
        x
    } else {
        x ^ (1 << (w - 1))
    }
}

// Sets FPSR's flags: `raised` (5 bits: IOC, DZC, OFC, UFC, IXC) and IDC.
fn fp_raise(raised: Op, idc: Op) {
    fpsr = fpsr | zext(raised, 32) | (zext(idc, 32) << 7);
}

// FPRound of a nonzero exact result, from L0's: `r` rounded as FPCR says
// with exceptions `s`, `z` rounded toward zero with exceptions `zs`;
// `flush` whether FZ or FZ16 applies. The exceptions (5 bits, L0's order)
// above the `w`-bit result.
//
// - Without AH a result is tiny if the exact one is below the smallest
//   normal number (tininess before rounding): then it rounded toward zero
//   to a denormal, or to zero, inexactly. With FZ it becomes the zero of
//   its sign, raising underflow alone; else underflow is raised if it is
//   inexact.
// - With AH a result is tiny after rounding, as in IEEE 754 and L0: a
//   denormal, or one L0 says underflowed. With FZ it becomes the zero of
//   its sign, raising underflow and inexact; else L0's exceptions.
fn fp_round(r: Op, s: Op, z: Op, zs: Op, w: Op, flush: Op) {
    let ah = fp_ah() == 1;
    let before = fp_is_denormal(z, w) || (fp_is_zero(z, w) && bit(zs, 4) == 1);
    let after = fp_is_denormal(r, w) || bit(s, 3) == 1;
    let flushed = flush == 1 && (if ah { after } else { before });
    let underflow = flushed
        || (if ah {
            bit(s, 3) == 1
        } else {
            before && bit(s, 4) == 1
        });
    let inexact = if flushed { ah } else { bit(s, 4) == 1 };
    concat(
        concat(inexact, concat(underflow, bits(s, 0, 3))),
        if flushed { fp_signed_zero(r, w) } else { r },
    )
}

// The result of an operation whose operands `a` and `b` (as written) may
// be NaNs, from its rounded result `rounded` (`fp_round`'s): FPSR's flags
// set, with IDC if `idc`.
//
// - A NaN operand: FPProcessNaNs; invalid for a signalling NaN.
// - A NaN from numbers: the default NaN.
fn fp_finish(a: Op, b: Op, rounded: Op, idc: Op, w: Op) {
    let nan = fp_is_nan(a, w) || fp_is_nan(b, w);
    let r = bits(rounded, 0, w);
    fp_raise(
        if nan {
            zext(fp_is_snan(a, w) || fp_is_snan(b, w), 5)
        } else {
            bits(rounded, w, 5)
        },
        idc,
    );
    if nan {
        fp_nans(a, b, w)
    } else if fp_is_nan(r, w) {
        fp_default_nan(w)
    } else {
        r
    }
}

// FPAdd, FPSub, FPMul and FPDiv (`op`: fp_add, fp_sub, fp_mul, fp_div) of
// `w`-bit `a` and `b`. FPProcessDenorms applies unless an operand is a
// NaN, and for FPDiv only if the divisor is not a zero.
fn fp_arith(op: Op, a: Op, b: Op, w: Op) {
    let x = fp_unpack(a, w);
    let y = fp_unpack(b, w);
    let rm = fp_rounding();
    let rounded = fp_round(
        farith(op, x, y, rm),
        status(farith(op, x, y, rm)),
        farith(op, x, y, 3),
        status(farith(op, x, y, 3)),
        w,
        fp_flushes_output(w),
    );
    let counted = if op == fp_div() {
        !fp_is_zero(y, w)
    } else {
        zext(1, 1)
    };
    let idc = fp_input_denormal(a, w)
        || fp_input_denormal(b, w)
        || ((fp_denormal_operand(x, w) || fp_denormal_operand(y, w))
            && !(fp_is_nan(a, w) || fp_is_nan(b, w))
            && counted);
    fp_finish(a, b, rounded, idc, w)
}

// The `v` register written with a scalar result `value`: above it the
// bits of `merged` (a register's 128 bits) with FPCR.NEP (Arm's
// IsMerging), else zeros.
fn fp_merge(value: Op, merged: Op) {
    let w = width(value);
    if bit(fpcr, 2) == 1 {
        concat(bits(merged, w, 128 - w), value)
    } else {
        zext(value, 128)
    }
}

// FADD (scalar): FPAdd, merged into n's register.
#[operation(FADD_float)]
fn fadd(d: Op, n: Op, m: Op) {
    write_whole(d, fp_merge(fp_arith(fp_add(), n, m, width(d)), whole(n)));
}

// FSUB (scalar): FPSub, merged into n's register.
#[operation(FSUB_float)]
fn fsub(d: Op, n: Op, m: Op) {
    write_whole(d, fp_merge(fp_arith(fp_sub(), n, m, width(d)), whole(n)));
}

// FMUL (scalar): FPMul, merged into n's register.
#[operation(FMUL_float)]
fn fmul(d: Op, n: Op, m: Op) {
    write_whole(d, fp_merge(fp_arith(fp_mul(), n, m, width(d)), whole(n)));
}

// FDIV (scalar): FPDiv, merged into n's register.
#[operation(FDIV_float)]
fn fdiv(d: Op, n: Op, m: Op) {
    write_whole(d, fp_merge(fp_arith(fp_div(), n, m, width(d)), whole(n)));
}

// FNMUL (scalar): FPNeg of FPMul, merged into n's register.
#[operation(FNMUL_float)]
fn fnmul(d: Op, n: Op, m: Op) {
    let w = width(d);
    write_whole(
        d,
        fp_merge(fp_neg(fp_arith(fp_mul(), n, m, w), w), whole(n)),
    );
}

// FPProcessNaNs3 (one of the addend `a`, `n` and `m` a NaN): the first
// signalling NaN, else the first NaN, in that order; with AH, `n` if it
// and another are NaNs, `m` if it and `a` are.
fn fp_nans3(a: Op, n: Op, m: Op, w: Op) {
    let ah = fp_ah() == 1;
    fp_process_nan(
        if ah && fp_is_nan(n, w) && (fp_is_nan(a, w) || fp_is_nan(m, w)) {
            n
        } else if ah && fp_is_nan(m, w) && fp_is_nan(a, w) {
            m
        } else if fp_is_snan(a, w) {
            a
        } else if fp_is_snan(n, w) {
            n
        } else if fp_is_snan(m, w) {
            m
        } else if fp_is_nan(a, w) {
            a
        } else if fp_is_nan(n, w) {
            n
        } else {
            m
        },
        w,
    )
}

// FPMulAdd: `a` plus the product of `n` and `m`, rounded once.
//
// - A NaN operand: FPProcessNaNs3; invalid for a signalling NaN. Without
//   AH, a quiet NaN addend with an infinity times a zero gives the
//   default NaN and invalid.
// - FPProcessDenorms3 applies unless an operand is a NaN or the operation
//   is invalid.
fn fp_mul_add(a: Op, n: Op, m: Op, w: Op) {
    let xa = fp_unpack(a, w);
    let xn = fp_unpack(n, w);
    let xm = fp_unpack(m, w);
    let rm = fp_rounding();
    let rounded = fp_round(
        fma(xn, xm, xa, rm),
        status(fma(xn, xm, xa, rm)),
        fma(xn, xm, xa, 3),
        status(fma(xn, xm, xa, 3)),
        w,
        fp_flushes_output(w),
    );
    let r = bits(rounded, 0, w);
    let nan = fp_is_nan(a, w) || fp_is_nan(n, w) || fp_is_nan(m, w);
    let special = fp_ah() == 0
        && fp_is_qnan(a, w)
        && ((fp_is_infinity(xn, w) && fp_is_zero(xm, w))
            || (fp_is_zero(xn, w) && fp_is_infinity(xm, w)));
    let idc = fp_input_denormal(a, w)
        || fp_input_denormal(n, w)
        || fp_input_denormal(m, w)
        || ((fp_denormal_operand(xa, w)
            || fp_denormal_operand(xn, w)
            || fp_denormal_operand(xm, w))
            && !nan
            && bit(rounded, w) == 0);
    fp_raise(
        if nan {
            zext(
                special || fp_is_snan(a, w) || fp_is_snan(n, w) || fp_is_snan(m, w),
                5,
            )
        } else {
            bits(rounded, w, 5)
        },
        idc,
    );
    if special {
        fp_default_nan(w)
    } else if nan {
        fp_nans3(a, n, m, w)
    } else if fp_is_nan(r, w) {
        fp_default_nan(w)
    } else {
        r
    }
}

// FMADD: FPMulAdd(a, n, m), merged into a's register.
#[operation(FMADD_float)]
fn fmadd(d: Op, n: Op, m: Op, a: Op) {
    write_whole(d, fp_merge(fp_mul_add(a, n, m, width(d)), whole(a)));
}

// FMSUB: FPMulAdd(a, FPNeg(n), m), merged into a's register.
#[operation(FMSUB_float)]
fn fmsub(d: Op, n: Op, m: Op, a: Op) {
    let w = width(d);
    write_whole(d, fp_merge(fp_mul_add(a, fp_neg(n, w), m, w), whole(a)));
}

// FNMADD: FPMulAdd(FPNeg(a), FPNeg(n), m), merged into a's register.
#[operation(FNMADD_float)]
fn fnmadd(d: Op, n: Op, m: Op, a: Op) {
    let w = width(d);
    write_whole(
        d,
        fp_merge(fp_mul_add(fp_neg(a, w), fp_neg(n, w), m, w), whole(a)),
    );
}

// FNMSUB: FPMulAdd(FPNeg(a), n, m), merged into a's register.
#[operation(FNMSUB_float)]
fn fnmsub(d: Op, n: Op, m: Op, a: Op) {
    let w = width(d);
    write_whole(d, fp_merge(fp_mul_add(fp_neg(a, w), n, m, w), whole(a)));
}

// FABS (scalar): FPAbs, the sign cleared but a NaN's with AH; merged into
// d's register.
#[operation(FABS_float)]
fn fabs(d: Op, n: Op) {
    let w = width(d);
    write_whole(
        d,
        fp_merge(
            if fp_ah() == 1 && fp_is_nan(n, w) {
                n
            } else {
                n & ((1 << (w - 1)) - 1)
            },
            whole(d),
        ),
    );
}

// FNEG (scalar): FPNeg, merged into d's register.
#[operation(FNEG_float)]
fn fneg(d: Op, n: Op) {
    let w = width(d);
    write_whole(d, fp_merge(fp_neg(n, w), whole(d)));
}

// FPSqrt: a NaN operand as FPProcessNaN; a zero itself; +infinity itself;
// a negative number the default NaN and invalid; else the root rounded
// (never tiny or huge), and FPProcessDenorm.
fn fp_sqrt(a: Op, w: Op) {
    let x = fp_unpack(a, w);
    let rm = fp_rounding();
    let r = fsqrt(x, rm);
    let nan = fp_is_nan(a, w);
    let idc = fp_input_denormal(a, w) || (fp_denormal_operand(x, w) && bit(x, w - 1) == 0);
    fp_raise(
        if nan {
            zext(fp_is_snan(a, w), 5)
        } else {
            status(fsqrt(x, rm))
        },
        idc,
    );
    if nan {
        fp_process_nan(a, w)
    } else if fp_is_nan(r, w) {
        fp_default_nan(w)
    } else {
        r
    }
}

// FSQRT (scalar): FPSqrt, merged into d's register.
#[operation(FSQRT_float)]
fn fsqrt_float(d: Op, n: Op) {
    write_whole(d, fp_merge(fp_sqrt(n, width(d)), whole(d)));
}

// FPMax (`max` 1) or FPMin (0) of `a` and `b`, with the alternative
// handling if `alt` (FPCR.AH for FMAX and FMIN; never for FMAXNM and
// FMINNM).
//
// - With `alt`, zeros of opposite signs give the second; a NaN operand
//   gives the second (as FPUnpack takes it) and invalid, without
//   FPProcessNaNs or FPProcessDenorms.
// - Else a NaN operand: FPProcessNaNs, invalid for a signalling NaN.
// - Else the greater (lesser) of the operands as FPUnpack takes them, the
//   second if they are equal; of two zeros, +0.0 unless both are -0.0
//   (-0.0 if either is), and FPProcessDenorms. The value goes through
//   FPRound, which flushes a denormal to zero (raising underflow and
//   inexact) with AH and FZ, unless `alt` (which clears FZ and FZ16).
fn fp_max_min(a: Op, b: Op, max: Op, alt: Op, w: Op) {
    let x = fp_unpack(a, w);
    let y = fp_unpack(b, w);
    let nan = fp_is_nan(a, w) || fp_is_nan(b, w);
    let opposite_zeros =
        alt == 1 && fp_is_zero(x, w) && fp_is_zero(y, w) && bit(x, w - 1) != bit(y, w - 1);
    let alt_nan = alt == 1 && nan;
    let relation = fcmp(x, y);
    let first = if max == 1 {
        bit(relation, 2) == 1
    } else {
        bit(relation, 0) == 1
    };
    let chosen = if fp_is_zero(x, w) && fp_is_zero(y, w) {
        if max == 1 { x & y } else { x | y }
    } else if first {
        x
    } else {
        y
    };
    let rounded = fp_round(
        chosen,
        zext(0, 5),
        chosen,
        zext(0, 5),
        w,
        fp_flushes_output(w) & !alt,
    );
    let idc = fp_input_denormal(a, w)
        || fp_input_denormal(b, w)
        || ((fp_denormal_operand(x, w) || fp_denormal_operand(y, w)) && !nan && !opposite_zeros);
    fp_raise(
        if opposite_zeros {
            zext(0, 5)
        } else if alt_nan {
            zext(1, 5)
        } else if nan {
            zext(fp_is_snan(a, w) || fp_is_snan(b, w), 5)
        } else {
            bits(rounded, w, 5)
        },
        idc,
    );
    if opposite_zeros || alt_nan {
        y
    } else if nan {
        fp_nans(a, b, w)
    } else {
        bits(rounded, 0, w)
    }
}

// FPMaxNum (`max` 1) and FPMinNum (0): unless both are NaNs with AH, a
// quiet NaN operand with the other not one becomes -infinity (+infinity),
// then FPMax (FPMin) without the alternative handling.
fn fp_max_min_number(a: Op, b: Op, max: Op, w: Op) {
    let both = fp_ah() == 1 && fp_is_nan(a, w) && fp_is_nan(b, w);
    let infinity = if max == 1 {
        fp_signed_infinity(zext(1 << (w - 1), w), w)
    } else {
        fp_signed_infinity(zext(0, w), w)
    };
    fp_max_min(
        if !both && fp_is_qnan(a, w) && !fp_is_qnan(b, w) {
            infinity
        } else {
            a
        },
        if !both && !fp_is_qnan(a, w) && fp_is_qnan(b, w) {
            infinity
        } else {
            b
        },
        max,
        zext(0, 1),
        w,
    )
}

// FMAX (scalar): FPMax, merged into n's register.
#[operation(FMAX_float)]
fn fmax(d: Op, n: Op, m: Op) {
    write_whole(
        d,
        fp_merge(fp_max_min(n, m, 1, fp_ah(), width(d)), whole(n)),
    );
}

// FMIN (scalar): FPMin, merged into n's register.
#[operation(FMIN_float)]
fn fmin(d: Op, n: Op, m: Op) {
    write_whole(
        d,
        fp_merge(fp_max_min(n, m, 0, fp_ah(), width(d)), whole(n)),
    );
}

// FMAXNM (scalar): FPMaxNum, merged into n's register.
#[operation(FMAXNM_float)]
fn fmaxnm(d: Op, n: Op, m: Op) {
    write_whole(d, fp_merge(fp_max_min_number(n, m, 1, width(d)), whole(n)));
}

// FMINNM (scalar): FPMinNum, merged into n's register.
#[operation(FMINNM_float)]
fn fminnm(d: Op, n: Op, m: Op) {
    write_whole(d, fp_merge(fp_max_min_number(n, m, 0, width(d)), whole(n)));
}
