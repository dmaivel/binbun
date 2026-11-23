// Moves to, from and between SIMD and floating-point registers that
// compute nothing: the bits as they are. A scalar written clears the bits
// of its `v` register above it; an element (`v0.d[1]`) leaves the others.

// FMOV (register): `h`, `s` or `d` to the same size.
#[operation(FMOV_float)]
fn fmov_register(d: Op, n: Op) {
    d = n;
}

// FMOV (general): between a general-purpose register and a SIMD and
// floating-point one, or the top half of a `v` register (`v0.d[1]`). A
// half-precision value to a `w` or `x` register is zero-extended; a `w` or
// `x` register to a `h` one gives its low 16 bits.
#[operation(FMOV_float_gen)]
fn fmov_general(d: Op, n: Op) {
    if width(d) > width(n) {
        d = zext(n, width(d));
    } else {
        d = trunc(n, width(d));
    }
}

// FMOV (scalar, immediate): the value Arm's `VFPExpandImm` gives `imm8`
// (bits 13 to 20) at the register's size: its sign, an exponent of NOT(b6),
// b6 repeated and bits 5 and 4, and a fraction of bits 3 to 0 then zeros.
#[operation(FMOV_float_imm)]
fn fmov_immediate(d: Op, _imm: Op) {
    let sign = field(20, 1);
    let b6 = field(19, 1);
    let high = field(17, 2);
    let low = field(13, 4);
    if width(d) == 64 {
        d = fit(
            (sign << 63) | ((1 - b6) << 62) | ((b6 * 255) << 54) | (high << 52) | (low << 48),
            64,
        );
    } else if width(d) == 32 {
        d = fit(
            (sign << 31) | ((1 - b6) << 30) | ((b6 * 31) << 25) | (high << 23) | (low << 19),
            32,
        );
    } else {
        d = fit(
            (sign << 15) | ((1 - b6) << 14) | ((b6 * 3) << 12) | (high << 10) | (low << 6),
            16,
        );
    }
}

// MOVI: `imm8` (bits 16 to 18, then 5 to 9) expanded by `cmode` (bits 12 to
// 15) and `op` (bit 29) into a 64-bit pattern (Arm's `AdvSIMDExpandImm`),
// in each 64 bits of the register: 32-bit elements of `imm8` shifted left
// by 0, 8, 16 or 24 (`cmode` 0xx0); 16-bit elements shifted by 0 or 8
// (10x0); 32-bit elements shifted by 8 or 16 with ones shifted in (110x,
// `msl`); bytes of `imm8` (1110, `op` 0); bytes of all ones or zeros, one
// per bit of `imm8` (1110, `op` 1: `movi d0` and the 2d form). A 128-bit
// register takes the pattern twice.
#[operation(MOVI_advsimd)]
fn movi(d: Op, _imm: Op) {
    let op = field(29, 1);
    let cmode = field(12, 4);
    let imm8 = (field(16, 3) << 5) | field(5, 5);
    if (cmode >> 3) == 0 {
        let e = imm8 << (8 * ((cmode >> 1) & 3));
        let p = fit(e | (e << 32), 64);
        if width(d) == 128 {
            d = concat(p, p);
        } else {
            d = p;
        }
    } else if (cmode >> 2) == 2 {
        let e = imm8 << (8 * ((cmode >> 1) & 1));
        let p = fit(e | (e << 16) | (e << 32) | (e << 48), 64);
        if width(d) == 128 {
            d = concat(p, p);
        } else {
            d = p;
        }
    } else if (cmode >> 1) == 6 {
        let e = (imm8 << (8 + 8 * (cmode & 1))) | ((1 << (8 + 8 * (cmode & 1))) - 1);
        let p = fit(e | (e << 32), 64);
        if width(d) == 128 {
            d = concat(p, p);
        } else {
            d = p;
        }
    } else if op == 0 {
        let p = fit(imm8 * 0x0101_0101_0101_0101, 64);
        if width(d) == 128 {
            d = concat(p, p);
        } else {
            d = p;
        }
    } else {
        let p = fit(
            (imm8 & 1) * 0xff
                | ((imm8 >> 1) & 1) * 0xff00
                | ((imm8 >> 2) & 1) * 0xff_0000
                | ((imm8 >> 3) & 1) * 0xff00_0000
                | ((imm8 >> 4) & 1) * 0xff_0000_0000
                | ((imm8 >> 5) & 1) * 0xff00_0000_0000
                | ((imm8 >> 6) & 1) * 0xff_0000_0000_0000
                | ((imm8 >> 7) & 1) * 0xff00_0000_0000_0000,
            64,
        );
        if width(d) == 128 {
            d = concat(p, p);
        } else {
            d = p;
        }
    }
}

// ORR (vector, register): the bitwise or of two vectors (`mov v1.16b,
// v0.16b` is its alias, `n` and `m` the same).
#[operation(ORR_advsimd_reg)]
fn orr_vector(d: Op, n: Op, m: Op) {
    d = n | m;
}
