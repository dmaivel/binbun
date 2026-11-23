// Scalar floating-point conversions: between precisions (FPConvert), to
// integral values (FPRoundInt), to and from integers and fixed-point
// numbers (FPToFixed, FixedToFP). Helpers are in float.rs.

// 2^k in the `w`-bit format (k a normal exponent, known at lift time).
fn fp_power_of_two(k: Op, w: Op) {
    ((1 << (fp_exponent(w) - 1)) - 1 + k) << fp_fraction(w)
}

// `x` rounded to an integral value, ties away from zero (FPRounding_TIEAWAY,
// which L0 has not): to nearest, but a tie (x minus its truncation is ±0.5)
// is the truncation plus ±1 (exact: x has a bit worth 0.5).
fn fp_round_away(x: Op, w: Op) {
    let t = fround(x, 3);
    if bits(fsub(x, t, 0), 0, w - 1) == fp_power_of_two(0 - 1, w) {
        fadd(t, (x & (1 << (w - 1))) | fp_power_of_two(0, w), 0)
    } else {
        fround(x, 0)
    }
}

// FPConvertNaN: a NaN of the `from`-bit format in the `to`-bit one: its
// sign, quiet, the high bits of its payload.
fn fp_convert_nan(x: Op, from: Op, to: Op) {
    let ones = ((1 << (fp_exponent(to) + 1)) - 1) << (fp_fraction(to) - 1);
    if to > from {
        ((zext(x, to) >> (from - 1)) << (to - 1))
            | ones
            | ((zext(x, to) & ((1 << fp_fraction(from)) - 1))
                << (fp_fraction(to) - fp_fraction(from)))
    } else {
        (trunc(x >> (from - 1), to) << (to - 1))
            | ones
            | (trunc(x >> (fp_fraction(from) - fp_fraction(to)), to) & ((1 << fp_fraction(to)) - 1))
    }
}

// FPConvert of the `from`-bit `a` to the `to`-bit format, rounded as FPCR
// says (FPUnpackCV and FPRoundCV: FZ16 does not apply).
//
// - AHP (FPCR bit 26) is the alternative half-precision format: an
//   exponent of all ones is a normal number (2^16 times 1.f), and there
//   are no infinities or NaNs. To it, a NaN becomes the zero of its sign
//   and an infinity the largest magnitude of its sign, both invalid; a
//   result past the largest magnitude is invalid and the largest
//   magnitude. Results from 2^16 are those of half the value in IEEE
//   half precision with the exponent one more.
// - A NaN: FPConvertNaN, or the default NaN with DN; invalid for a
//   signalling NaN.
// - A number: FPRoundCV, then FPProcessDenorm.
fn fp_convert(a: Op, from: Op, to: Op) {
    let rm = fp_rounding();
    let sign = zext(bit(a, from - 1), to) << (to - 1);
    let alt_out = if to == 16 { bit(fpcr, 26) } else { zext(0, 1) };
    let alt_in = if from == 16 {
        bit(fpcr, 26)
    } else {
        zext(0, 1)
    };
    let x = if from == 16 { a } else { fp_unpack(a, from) };
    let nan = fp_is_nan(a, from) && alt_in == 0;
    let infinite = fp_is_infinity(a, from) && alt_in == 0;
    // An alternative half-precision number from 2^16: half of it, exactly.
    let big = alt_in == 1 && bits(a, 10, 5) == 31;
    let source = if big { a - (1 << 10) } else { x };
    let r = fcvt(source, to, rm);
    let s = status(fcvt(source, to, rm));
    // Half the value, for alternative half-precision results from 2^16.
    let halved = fcvt(source - (1 << fp_fraction(from)), to, rm);
    let halved_s = status(fcvt(source - (1 << fp_fraction(from)), to, rm));
    let rounded = if to > from {
        concat(zext(0, 5), if big { r + (1 << fp_fraction(to)) } else { r })
    } else {
        fp_round(
            r,
            s,
            fcvt(source, to, 3),
            status(fcvt(source, to, 3)),
            to,
            if to == 16 { zext(0, 1) } else { bit(fpcr, 24) },
        )
    };
    let alt_big = alt_out == 1 && bit(s, 2) == 1;
    let alt_huge = alt_big && bit(halved_s, 2) == 1;
    let largest = sign | ((1 << (to - 1)) - 1);
    let idc = fp_input_denormal(a, from) || fp_denormal_operand(x, from);
    fp_raise(
        if nan {
            zext(fp_is_snan(a, from) || alt_out == 1, 5)
        } else if infinite {
            zext(alt_out, 5)
        } else if alt_huge {
            zext(1, 5)
        } else if alt_big {
            zext(bit(halved_s, 4), 5) << 4
        } else {
            bits(rounded, to, 5)
        },
        idc,
    );
    if nan {
        if alt_out == 1 {
            sign
        } else if bit(fpcr, 25) == 1 {
            fp_default_nan(to)
        } else {
            fp_convert_nan(a, from, to)
        }
    } else if infinite && alt_out == 1 {
        largest
    } else if alt_huge {
        largest
    } else if alt_big {
        halved + (1 << fp_fraction(to))
    } else {
        bits(rounded, 0, to)
    }
}

// FCVT (scalar, between precisions): FPConvert, merged into d's register.
#[operation(FCVT_float)]
fn fcvt_float(d: Op, n: Op) {
    write_whole(d, fp_merge(fp_convert(n, width(n), width(d)), whole(d)));
}

// FPRoundInt of `w`-bit `a`: rounded to an integral value as `rounding`
// says (L0's), or ties away from zero if `away`; inexact only if `exact`
// (FRINTX). A NaN as FPProcessNaN. FPUnpack's input denormal exception
// only without AH.
fn fp_round_int(a: Op, w: Op, rounding: Op, away: Op, exact: Op) {
    let x = fp_unpack(a, w);
    let r = if away == 1 {
        fp_round_away(x, w)
    } else {
        fround(x, rounding)
    };
    let nan = fp_is_nan(a, w);
    fp_raise(
        if nan {
            zext(fp_is_snan(a, w), 5)
        } else {
            zext(exact == 1 && r != x, 5) << 4
        },
        fp_input_denormal(a, w),
    );
    if nan { fp_process_nan(a, w) } else { r }
}

// FRINTN: to nearest, ties to even; merged into d's register.
#[operation(FRINTN_float)]
fn frintn(d: Op, n: Op) {
    write_whole(d, fp_merge(fp_round_int(n, width(d), 0, 0, 0), whole(d)));
}

// FRINTP: toward +infinity.
#[operation(FRINTP_float)]
fn frintp(d: Op, n: Op) {
    write_whole(d, fp_merge(fp_round_int(n, width(d), 2, 0, 0), whole(d)));
}

// FRINTM: toward -infinity.
#[operation(FRINTM_float)]
fn frintm(d: Op, n: Op) {
    write_whole(d, fp_merge(fp_round_int(n, width(d), 1, 0, 0), whole(d)));
}

// FRINTZ: toward zero.
#[operation(FRINTZ_float)]
fn frintz(d: Op, n: Op) {
    write_whole(d, fp_merge(fp_round_int(n, width(d), 3, 0, 0), whole(d)));
}

// FRINTA: to nearest, ties away from zero.
#[operation(FRINTA_float)]
fn frinta(d: Op, n: Op) {
    write_whole(d, fp_merge(fp_round_int(n, width(d), 0, 1, 0), whole(d)));
}

// FRINTX: as FPCR says, inexact if the value changes.
#[operation(FRINTX_float)]
fn frintx(d: Op, n: Op) {
    write_whole(
        d,
        fp_merge(fp_round_int(n, width(d), fp_rounding(), 0, 1), whole(d)),
    );
}

// FRINTI: as FPCR says.
#[operation(FRINTI_float)]
fn frinti(d: Op, n: Op) {
    write_whole(
        d,
        fp_merge(fp_round_int(n, width(d), fp_rounding(), 0, 0), whole(d)),
    );
}

// FPToFixed of `w`-bit `a` times 2^fbits as an `iw`-bit integer, signed
// if `signed`, rounded as `rounding` says (L0's), or ties away from zero
// if `away`.
//
// - A NaN gives 0 and invalid.
// - A result out of range saturates (the most negative or positive
//   integer by the operand's sign; 0 for a negative one, unsigned) and is
//   invalid, not inexact; else inexact if the value was not integral.
// - FPUnpack's input denormal exception only without AH.
//
// The scaling is in double precision, exact (an overflow gives an
// infinity, out of range as the exact value is).
fn fp_to_fixed(a: Op, w: Op, fbits: Op, signed: Op, iw: Op, rounding: Op, away: Op) {
    let x = fp_unpack(a, w);
    let sw = if fbits == 0 { w } else { 64 };
    let double = if w == 64 { x } else { fcvt(x, 64, 0) };
    let scaled = if fbits == 0 {
        x
    } else {
        fmul(double, zext(fp_power_of_two(fbits, 64), 64), 0)
    };
    let t = if away == 1 {
        fp_round_away(scaled, sw)
    } else {
        scaled
    };
    let rm = if away == 1 { 3 } else { rounding };
    let r = if signed == 1 {
        ftoi(t, iw, rm)
    } else {
        ftou(t, iw, rm)
    };
    let s = if signed == 1 {
        status(ftoi(t, iw, rm))
    } else {
        status(ftou(t, iw, rm))
    };
    let invalid = bit(s, 0) == 1;
    let negative = bit(a, w - 1) == 1;
    let ones = !zext(0, iw);
    let saturated = if signed == 1 {
        if negative { !(ones >> 1) } else { ones >> 1 }
    } else if negative {
        zext(0, iw)
    } else {
        ones
    };
    let inexact = if away == 1 {
        t != scaled
    } else {
        bit(s, 4) == 1
    };
    fp_raise(
        if invalid {
            zext(1, 5)
        } else {
            zext(inexact, 5) << 4
        },
        fp_input_denormal(a, w),
    );
    if fp_is_nan(a, w) {
        zext(0, iw)
    } else if invalid {
        saturated
    } else {
        r
    }
}

// FCVTNS, FCVTNU (scalar): to nearest, ties to even.
#[operation(FCVTNS_float)]
fn fcvtns(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 1, width(d), 0, 0);
}

#[operation(FCVTNU_float)]
fn fcvtnu(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 0, width(d), 0, 0);
}

// FCVTPS, FCVTPU (scalar): toward +infinity.
#[operation(FCVTPS_float)]
fn fcvtps(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 1, width(d), 2, 0);
}

#[operation(FCVTPU_float)]
fn fcvtpu(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 0, width(d), 2, 0);
}

// FCVTMS, FCVTMU (scalar): toward -infinity.
#[operation(FCVTMS_float)]
fn fcvtms(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 1, width(d), 1, 0);
}

#[operation(FCVTMU_float)]
fn fcvtmu(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 0, width(d), 1, 0);
}

// FCVTAS, FCVTAU (scalar): to nearest, ties away from zero.
#[operation(FCVTAS_float)]
fn fcvtas(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 1, width(d), 0, 1);
}

#[operation(FCVTAU_float)]
fn fcvtau(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 0, width(d), 0, 1);
}

// FCVTZS, FCVTZU (scalar, integer): toward zero.
#[operation(FCVTZS_float_int)]
fn fcvtzs_int(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 1, width(d), 3, 0);
}

#[operation(FCVTZU_float_int)]
fn fcvtzu_int(d: Op, n: Op) {
    d = fp_to_fixed(n, width(n), 0, 0, width(d), 3, 0);
}

// FCVTZS, FCVTZU (scalar, fixed-point): toward zero, `fbits` fraction
// bits.
#[operation(FCVTZS_float_fix)]
fn fcvtzs_fix(d: Op, n: Op, fbits: Op) {
    d = fp_to_fixed(n, width(n), fbits, 1, width(d), 3, 0);
}

#[operation(FCVTZU_float_fix)]
fn fcvtzu_fix(d: Op, n: Op, fbits: Op) {
    d = fp_to_fixed(n, width(n), fbits, 0, width(d), 3, 0);
}

// FixedToFP of an integer (`fbits` 0) in any precision, or of a
// fixed-point number in single or double precision (`w`): the integer
// rounded, then scaled exactly (from 2^-64 to 2^64, never tiny or huge in
// those precisions; an integer is never tiny). The exceptions (5 bits)
// above the result.
fn fp_from_fixed_wide(i: Op, signed: Op, fbits: Op, w: Op) {
    let rm = fp_rounding();
    let r = if signed == 1 {
        itof(i, w, rm)
    } else {
        utof(i, w, rm)
    };
    let s = if signed == 1 {
        status(itof(i, w, rm))
    } else {
        status(utof(i, w, rm))
    };
    concat(
        bits(s, 0, 5),
        if fbits == 0 {
            r
        } else {
            fmul(r, zext(fp_power_of_two(0 - fbits, w), w), 0)
        },
    )
}

// FixedToFP of a fixed-point number in half precision, where the result
// may be tiny or huge, so the integer cannot be rounded before the
// scaling (2^40 with 40 fraction bits is 1.0; the integer alone is past
// half precision's range). The magnitude is rounded to odd at 24 bits
// (its 24 high bits, every bit below ORed into the lowest), which single
// precision holds exactly, also once scaled by 2^(shift - fbits) (from
// 2^-64 to 2^64); FPRound then rounds that to half precision. Rounding to
// odd at p' bits and then to p bits equals rounding once to p bits, in
// every direction and with the same exceptions, when p' >= p + 2: here 24
// >= 11 + 2. The value rounded to odd is never a tie at 11 bits unless
// the exact one is, and is inexact at 11 bits exactly when the exact one
// is. Do not replace it by a plain conversion to single precision, which
// rounds twice.
fn fp_from_fixed_half(i: Op, signed: Op, fbits: Op) {
    let iw = width(i);
    let rm = fp_rounding();
    let negative = signed == 1 && bit(i, iw - 1) == 1;
    let magnitude = zext(if negative { 0 - i } else { i }, 64);
    let zeros = clz(magnitude);
    let shift = if zeros < 40 { 40 - zeros } else { zext(0, 64) };
    let kept = (magnitude >> shift) | zext((magnitude & ((zext(1, 64) << shift) - 1)) != 0, 64);
    let single = fmul(
        utof(kept, 32, 0),
        trunc((shift + (127 - fbits)) << 23, 32),
        0,
    ) | (zext(negative, 32) << 31);
    fp_round(
        fcvt(single, 16, rm),
        status(fcvt(single, 16, rm)),
        fcvt(single, 16, 3),
        status(fcvt(single, 16, 3)),
        16,
        bit(fpcr, 19),
    )
}

// FixedToFP: the integer `i` (signed if `signed`) divided by 2^fbits, as
// a `w`-bit float rounded as FPCR says (FPRound; a zero is +0.0).
fn fp_from_fixed(i: Op, signed: Op, fbits: Op, w: Op) {
    let rounded = if fbits == 0 {
        fp_from_fixed_wide(i, signed, 0, w)
    } else if w == 16 {
        fp_from_fixed_half(i, signed, fbits)
    } else {
        fp_from_fixed_wide(i, signed, fbits, w)
    };
    fp_raise(bits(rounded, w, 5), zext(0, 1));
    bits(rounded, 0, w)
}

// SCVTF, UCVTF (scalar, integer): merged into d's register.
#[operation(SCVTF_float_int)]
fn scvtf_int(d: Op, n: Op) {
    write_whole(d, fp_merge(fp_from_fixed(n, 1, 0, width(d)), whole(d)));
}

#[operation(UCVTF_float_int)]
fn ucvtf_int(d: Op, n: Op) {
    write_whole(d, fp_merge(fp_from_fixed(n, 0, 0, width(d)), whole(d)));
}

// SCVTF, UCVTF (scalar, fixed-point): `fbits` fraction bits.
#[operation(SCVTF_float_fix)]
fn scvtf_fix(d: Op, n: Op, fbits: Op) {
    write_whole(d, fp_merge(fp_from_fixed(n, 1, fbits, width(d)), whole(d)));
}

#[operation(UCVTF_float_fix)]
fn ucvtf_fix(d: Op, n: Op, fbits: Op) {
    write_whole(d, fp_merge(fp_from_fixed(n, 0, fbits, width(d)), whole(d)));
}
