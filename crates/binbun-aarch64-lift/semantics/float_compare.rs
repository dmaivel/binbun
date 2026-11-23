// Scalar floating-point compares and the conditional select: Arm's
// FPCompare (helpers in float.rs) setting NZCV. `cond()` is
// `ConditionHolds` of the encoding's condition.

// FPCompare's exceptions for `w`-bit `a` and `b`, a signalling
// comparison if `signalling` (invalid for any NaN; else for a signalling
// NaN), set where `holds`: invalid, and input denormal (FPUnpack's, and
// FPProcessDenorms' unless an operand is a NaN).
fn fp_compare_raise(a: Op, b: Op, signalling: Op, w: Op, holds: Op) {
    let x = fp_unpack(a, w);
    let y = fp_unpack(b, w);
    let s = if signalling == 1 {
        status(fcmps(x, y))
    } else {
        status(fcmp(x, y))
    };
    let idc = fp_input_denormal(a, w)
        || fp_input_denormal(b, w)
        || ((fp_denormal_operand(x, w) || fp_denormal_operand(y, w))
            && !(fp_is_nan(a, w) || fp_is_nan(b, w)));
    fp_raise(zext(bit(s, 0) & holds, 5), idc & holds);
}

// FPCompare's outcome for `w`-bit `a` and `b` (as FPUnpack takes them):
// less (bit 0), equal (1), greater (2), unordered (3). Its NZCV is 1000
// less, 0110 equal, 0010 greater, 0011 unordered: N less, Z equal, C not
// less, V unordered.
fn fp_relation(a: Op, b: Op, w: Op) {
    fcmp(fp_unpack(a, w), fp_unpack(b, w))
}

// FCMP and FCMPE (`signalling`): NZCV from FPCompare of n and `m` (+0.0
// where bit 3 of the word is set, `fcmp s0, #0.0`).
fn fp_compare_flags(n: Op, m: Op, signalling: Op) {
    let w = width(n);
    let relation = fp_relation(n, m, w);
    fp_compare_raise(n, m, signalling, w, zext(1, 1));
    N = bit(relation, 0);
    Z = bit(relation, 1);
    C = !bit(relation, 0);
    V = bit(relation, 3);
}

// FCMP: a quiet comparison. The second operand is a register in some words
// and `#0.0` in others: the register's bits are read from its whole `v`
// register.
#[operation(FCMP_float)]
fn fcmp_float(n: Op, _m: Op) {
    let w = width(n);
    fp_compare_flags(
        n,
        if field(3, 1) == 1 {
            zext(0, w)
        } else {
            trunc(whole(_m), w)
        },
        0,
    );
}

// FCMPE: a signalling comparison.
#[operation(FCMPE_float)]
fn fcmpe_float(n: Op, _m: Op) {
    let w = width(n);
    fp_compare_flags(
        n,
        if field(3, 1) == 1 {
            zext(0, w)
        } else {
            trunc(whole(_m), w)
        },
        1,
    );
}

// FCCMP and FCCMPE (`signalling`): where the condition holds, NZCV from
// FPCompare of n and m (with its exceptions); else `nzcv` and none.
fn fp_conditional_compare(n: Op, m: Op, nzcv: Op, signalling: Op) {
    let w = width(n);
    let holds = cond();
    let relation = fp_relation(n, m, w);
    fp_compare_raise(n, m, signalling, w, holds);
    N = if holds {
        bit(relation, 0)
    } else {
        (nzcv >> 3) & 1
    };
    Z = if holds {
        bit(relation, 1)
    } else {
        (nzcv >> 2) & 1
    };
    C = if holds {
        !bit(relation, 0)
    } else {
        (nzcv >> 1) & 1
    };
    V = if holds { bit(relation, 3) } else { nzcv & 1 };
}

// FCCMP: a quiet comparison.
#[operation(FCCMP_float)]
fn fccmp(n: Op, m: Op, nzcv: Op) {
    fp_conditional_compare(n, m, nzcv, 0);
}

// FCCMPE: a signalling comparison.
#[operation(FCCMPE_float)]
fn fccmpe(n: Op, m: Op, nzcv: Op) {
    fp_conditional_compare(n, m, nzcv, 1);
}

// FCSEL: n where the condition holds, else m; the bits above cleared (no
// merging: FCSEL is not one of IsMerging's).
#[operation(FCSEL_float)]
fn fcsel(d: Op, n: Op, m: Op) {
    d = if cond() { n } else { m };
}
