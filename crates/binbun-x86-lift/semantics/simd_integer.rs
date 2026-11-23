// SSE and AVX integer arithmetic: saturation, multiplies, sums of
// differences, averages, minimum and maximum, absolute values and signs,
// comparisons, shifts, horizontal operations, the SSE4.2 string compares,
// CRC32 and AVX-VNNI. Lane-wise operations are written once for the
// legacy form (the destination is the first source) and once for the VEX
// form; the runtime applies each encoding's register write rule.

// `x` (lanes wider than `to` bits, signed) saturated to `to` signed bits.
fn si_ssat(x: Op, to: Op) {
    if sgt(x, (1 << (to - 1)) - 1) {
        (1 << (to - 1)) - 1
    } else if slt(x, 0 - (1 << (to - 1))) {
        1 << (to - 1)
    } else {
        trunc(x, to)
    }
}

// Saturating addition and subtraction of `w`-bit lanes, signed and
// unsigned.
fn si_adds(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, si_ssat(sext(a, 2 * w) + sext(b, 2 * w), w))
}

fn si_subs(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, si_ssat(sext(a, 2 * w) - sext(b, 2 * w), w))
}

fn si_addus(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, if a + b < a { (1 << w) - 1 } else { a + b })
}

fn si_subus(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, if a < b { 0 } else { a - b })
}

#[iclass(PADDSB)]
fn paddsb(dst: Op, src: Op) {
    dst = si_adds(dst, src, 8);
}

#[iclass(PADDSW)]
fn paddsw(dst: Op, src: Op) {
    dst = si_adds(dst, src, 16);
}

#[iclass(PADDUSB)]
fn paddusb(dst: Op, src: Op) {
    dst = si_addus(dst, src, 8);
}

#[iclass(PADDUSW)]
fn paddusw(dst: Op, src: Op) {
    dst = si_addus(dst, src, 16);
}

#[iclass(PSUBSB)]
fn psubsb(dst: Op, src: Op) {
    dst = si_subs(dst, src, 8);
}

#[iclass(PSUBSW)]
fn psubsw(dst: Op, src: Op) {
    dst = si_subs(dst, src, 16);
}

#[iclass(PSUBUSB)]
fn psubusb(dst: Op, src: Op) {
    dst = si_subus(dst, src, 8);
}

#[iclass(PSUBUSW)]
fn psubusw(dst: Op, src: Op) {
    dst = si_subus(dst, src, 16);
}

#[iclass(VPADDSB)]
fn vpaddsb(dst: Op, a: Op, b: Op) {
    dst = si_adds(a, b, 8);
}

#[iclass(VPADDSW)]
fn vpaddsw(dst: Op, a: Op, b: Op) {
    dst = si_adds(a, b, 16);
}

#[iclass(VPADDUSB)]
fn vpaddusb(dst: Op, a: Op, b: Op) {
    dst = si_addus(a, b, 8);
}

#[iclass(VPADDUSW)]
fn vpaddusw(dst: Op, a: Op, b: Op) {
    dst = si_addus(a, b, 16);
}

#[iclass(VPSUBSB)]
fn vpsubsb(dst: Op, a: Op, b: Op) {
    dst = si_subs(a, b, 8);
}

#[iclass(VPSUBSW)]
fn vpsubsw(dst: Op, a: Op, b: Op) {
    dst = si_subs(a, b, 16);
}

#[iclass(VPSUBUSB)]
fn vpsubusb(dst: Op, a: Op, b: Op) {
    dst = si_subus(a, b, 8);
}

#[iclass(VPSUBUSW)]
fn vpsubusw(dst: Op, a: Op, b: Op) {
    dst = si_subus(a, b, 16);
}

// Multiplies. The high halves are those of the full signed or unsigned
// products; PMULHRSW rounds the product's bits 30..15 (it adds 1 at bit
// 14); PMULUDQ and PMULDQ multiply the low halves of 64-bit lanes.
fn si_mulhw(a: Op, b: Op) {
    lanes(width(a) / 16, bits(sext(a, 32) * sext(b, 32), 16, 16))
}

fn si_mulhuw(a: Op, b: Op) {
    lanes(width(a) / 16, bits(zext(a, 32) * zext(b, 32), 16, 16))
}

fn si_mulhrsw(a: Op, b: Op) {
    lanes(
        width(a) / 16,
        bits(((sext(a, 32) * sext(b, 32)) >> 14) + 1, 1, 16),
    )
}

fn si_mull(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, a * b)
}

fn si_muludq(a: Op, b: Op) {
    lanes(
        width(a) / 64,
        zext(bits(a, 0, 32), 64) * zext(bits(b, 0, 32), 64),
    )
}

fn si_muldq(a: Op, b: Op) {
    lanes(
        width(a) / 64,
        sext(bits(a, 0, 32), 64) * sext(bits(b, 0, 32), 64),
    )
}

// PMADDWD: the sum of the two signed products of a 32-bit lane's words,
// wrapping (only -32768 × -32768 twice overflows, to 0x80000000).
fn si_maddwd(a: Op, b: Op) {
    lanes(
        width(a) / 32,
        sext(bits(a, 0, 16), 32) * sext(bits(b, 0, 16), 32)
            + sext(bits(a, 16, 16), 32) * sext(bits(b, 16, 16), 32),
    )
}

// PMADDUBSW: unsigned bytes of the first source times signed bytes of the
// second, adjacent products added with signed saturation.
fn si_maddubsw(a: Op, b: Op) {
    lanes(
        width(a) / 16,
        si_ssat(
            zext(bits(a, 0, 8), 32) * sext(bits(b, 0, 8), 32)
                + zext(bits(a, 8, 8), 32) * sext(bits(b, 8, 8), 32),
            16,
        ),
    )
}

#[iclass(PMULHW)]
fn pmulhw(dst: Op, src: Op) {
    dst = si_mulhw(dst, src);
}

#[iclass(PMULHUW)]
fn pmulhuw(dst: Op, src: Op) {
    dst = si_mulhuw(dst, src);
}

#[iclass(PMULHRSW)]
fn pmulhrsw(dst: Op, src: Op) {
    dst = si_mulhrsw(dst, src);
}

#[iclass(PMULLW)]
fn pmullw(dst: Op, src: Op) {
    dst = si_mull(dst, src, 16);
}

#[iclass(PMULLD)]
fn pmulld(dst: Op, src: Op) {
    dst = si_mull(dst, src, 32);
}

#[iclass(PMULUDQ)]
fn pmuludq(dst: Op, src: Op) {
    dst = si_muludq(dst, src);
}

#[iclass(PMULDQ)]
fn pmuldq(dst: Op, src: Op) {
    dst = si_muldq(dst, src);
}

#[iclass(PMADDWD)]
fn pmaddwd(dst: Op, src: Op) {
    dst = si_maddwd(dst, src);
}

#[iclass(PMADDUBSW)]
fn pmaddubsw(dst: Op, src: Op) {
    dst = si_maddubsw(dst, src);
}

#[iclass(VPMULHW)]
fn vpmulhw(dst: Op, a: Op, b: Op) {
    dst = si_mulhw(a, b);
}

#[iclass(VPMULHUW)]
fn vpmulhuw(dst: Op, a: Op, b: Op) {
    dst = si_mulhuw(a, b);
}

#[iclass(VPMULHRSW)]
fn vpmulhrsw(dst: Op, a: Op, b: Op) {
    dst = si_mulhrsw(a, b);
}

#[iclass(VPMULLW)]
fn vpmullw(dst: Op, a: Op, b: Op) {
    dst = si_mull(a, b, 16);
}

#[iclass(VPMULLD)]
fn vpmulld(dst: Op, a: Op, b: Op) {
    dst = si_mull(a, b, 32);
}

#[iclass(VPMULUDQ)]
fn vpmuludq(dst: Op, a: Op, b: Op) {
    dst = si_muludq(a, b);
}

#[iclass(VPMULDQ)]
fn vpmuldq(dst: Op, a: Op, b: Op) {
    dst = si_muldq(a, b);
}

#[iclass(VPMADDWD)]
fn vpmaddwd(dst: Op, a: Op, b: Op) {
    dst = si_maddwd(a, b);
}

#[iclass(VPMADDUBSW)]
fn vpmaddubsw(dst: Op, a: Op, b: Op) {
    dst = si_maddubsw(a, b);
}

// AVX-VNNI: each 32-bit lane of the destination accumulates the four
// products of unsigned bytes of the first source and signed bytes of the
// second (VPDPBUSD), or the two products of signed words (VPDPWSSD),
// wrapping; the S forms saturate the whole sum to 32 signed bits.
#[iclass(VPDPBUSD)]
fn vpdpbusd(dst: Op, a: Op, b: Op) {
    dst = lanes(
        width(dst) / 32,
        dst + zext(bits(a, 0, 8), 32) * sext(bits(b, 0, 8), 32)
            + zext(bits(a, 8, 8), 32) * sext(bits(b, 8, 8), 32)
            + zext(bits(a, 16, 8), 32) * sext(bits(b, 16, 8), 32)
            + zext(bits(a, 24, 8), 32) * sext(bits(b, 24, 8), 32),
    );
}

#[iclass(VPDPBUSDS)]
fn vpdpbusds(dst: Op, a: Op, b: Op) {
    dst = lanes(
        width(dst) / 32,
        si_ssat(
            sext(dst, 64)
                + zext(bits(a, 0, 8), 64) * sext(bits(b, 0, 8), 64)
                + zext(bits(a, 8, 8), 64) * sext(bits(b, 8, 8), 64)
                + zext(bits(a, 16, 8), 64) * sext(bits(b, 16, 8), 64)
                + zext(bits(a, 24, 8), 64) * sext(bits(b, 24, 8), 64),
            32,
        ),
    );
}

#[iclass(VPDPWSSD)]
fn vpdpwssd(dst: Op, a: Op, b: Op) {
    dst = lanes(
        width(dst) / 32,
        dst + sext(bits(a, 0, 16), 32) * sext(bits(b, 0, 16), 32)
            + sext(bits(a, 16, 16), 32) * sext(bits(b, 16, 16), 32),
    );
}

#[iclass(VPDPWSSDS)]
fn vpdpwssds(dst: Op, a: Op, b: Op) {
    dst = lanes(
        width(dst) / 32,
        si_ssat(
            sext(dst, 64)
                + sext(bits(a, 0, 16), 64) * sext(bits(b, 0, 16), 64)
                + sext(bits(a, 16, 16), 64) * sext(bits(b, 16, 16), 64),
            32,
        ),
    );
}

// PSADBW: in each 64-bit lane, the sum of the eight bytes' absolute
// differences (at most 2040), zero-extended.
fn si_psadbw(a: Op, b: Op) {
    let d = lanes(width(a) / 8, if a > b { a - b } else { b - a });
    let s = zext(0, width(a));
    for k in 0..8 {
        s = lanes(width(a) / 64, s + zext(bits(d, 8 * k, 8), 64));
    }
    s
}

// MPSADBW: in each 128-bit block, eight sums of absolute differences of
// four bytes: word i compares the first source's bytes i..i+4 from byte
// 4 × imm[2] with the second source's bytes from byte 4 × imm[1:0]. The
// upper block of the 256-bit form uses imm[5:3] on the upper halves.
fn si_mpsadbw(a: Op, b: Op, imm: Op) {
    let r = zext(0, width(a));
    for i in 0..width(a) / 128 {
        let x = bits(a, 128 * i, 128) >> (zext(bit(imm, 3 * i + 2), 128) << 5);
        let y = bits(b, 128 * i, 128) >> (zext(bits(imm, 3 * i, 2), 128) << 5);
        let s = zext(0, 128);
        for k in 0..4 {
            let xk = bits(x, 8 * k, 64);
            let yk = bits(y, 8 * k, 8);
            s = lanes(8, s + zext(if xk > yk { xk - yk } else { yk - xk }, 16));
        }
        r = r | (zext(s, width(a)) << (128 * i));
    }
    r
}

#[iclass(PSADBW)]
fn psadbw(dst: Op, src: Op) {
    dst = si_psadbw(dst, src);
}

#[iclass(VPSADBW)]
fn vpsadbw(dst: Op, a: Op, b: Op) {
    dst = si_psadbw(a, b);
}

#[iclass(MPSADBW)]
fn mpsadbw(dst: Op, src: Op, imm: Op) {
    dst = si_mpsadbw(dst, src, imm);
}

#[iclass(VMPSADBW)]
fn vmpsadbw(dst: Op, a: Op, b: Op, imm: Op) {
    dst = si_mpsadbw(a, b, imm);
}

// Averages, rounded up: (a + b + 1) / 2 without overflow.
fn si_avg(a: Op, b: Op, w: Op) {
    lanes(
        width(a) / w,
        trunc((zext(a, 2 * w) + zext(b, 2 * w) + 1) >> 1, w),
    )
}

#[iclass(PAVGB)]
fn pavgb(dst: Op, src: Op) {
    dst = si_avg(dst, src, 8);
}

#[iclass(PAVGW)]
fn pavgw(dst: Op, src: Op) {
    dst = si_avg(dst, src, 16);
}

#[iclass(VPAVGB)]
fn vpavgb(dst: Op, a: Op, b: Op) {
    dst = si_avg(a, b, 8);
}

#[iclass(VPAVGW)]
fn vpavgw(dst: Op, a: Op, b: Op) {
    dst = si_avg(a, b, 16);
}

// Minimum and maximum, signed and unsigned.
fn si_mins(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, if slt(a, b) { a } else { b })
}

fn si_maxs(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, if sgt(a, b) { a } else { b })
}

fn si_minu(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, if a < b { a } else { b })
}

fn si_maxu(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, if a > b { a } else { b })
}

#[iclass(PMINSB)]
fn pminsb(dst: Op, src: Op) {
    dst = si_mins(dst, src, 8);
}

#[iclass(PMINSW)]
fn pminsw(dst: Op, src: Op) {
    dst = si_mins(dst, src, 16);
}

#[iclass(PMINSD)]
fn pminsd(dst: Op, src: Op) {
    dst = si_mins(dst, src, 32);
}

#[iclass(PMINUB)]
fn pminub(dst: Op, src: Op) {
    dst = si_minu(dst, src, 8);
}

#[iclass(PMINUW)]
fn pminuw(dst: Op, src: Op) {
    dst = si_minu(dst, src, 16);
}

#[iclass(PMINUD)]
fn pminud(dst: Op, src: Op) {
    dst = si_minu(dst, src, 32);
}

#[iclass(PMAXSB)]
fn pmaxsb(dst: Op, src: Op) {
    dst = si_maxs(dst, src, 8);
}

#[iclass(PMAXSW)]
fn pmaxsw(dst: Op, src: Op) {
    dst = si_maxs(dst, src, 16);
}

#[iclass(PMAXSD)]
fn pmaxsd(dst: Op, src: Op) {
    dst = si_maxs(dst, src, 32);
}

#[iclass(PMAXUB)]
fn pmaxub(dst: Op, src: Op) {
    dst = si_maxu(dst, src, 8);
}

#[iclass(PMAXUW)]
fn pmaxuw(dst: Op, src: Op) {
    dst = si_maxu(dst, src, 16);
}

#[iclass(PMAXUD)]
fn pmaxud(dst: Op, src: Op) {
    dst = si_maxu(dst, src, 32);
}

#[iclass(VPMINSB)]
fn vpminsb(dst: Op, a: Op, b: Op) {
    dst = si_mins(a, b, 8);
}

#[iclass(VPMINSW)]
fn vpminsw(dst: Op, a: Op, b: Op) {
    dst = si_mins(a, b, 16);
}

#[iclass(VPMINSD)]
fn vpminsd(dst: Op, a: Op, b: Op) {
    dst = si_mins(a, b, 32);
}

#[iclass(VPMINUB)]
fn vpminub(dst: Op, a: Op, b: Op) {
    dst = si_minu(a, b, 8);
}

#[iclass(VPMINUW)]
fn vpminuw(dst: Op, a: Op, b: Op) {
    dst = si_minu(a, b, 16);
}

#[iclass(VPMINUD)]
fn vpminud(dst: Op, a: Op, b: Op) {
    dst = si_minu(a, b, 32);
}

#[iclass(VPMAXSB)]
fn vpmaxsb(dst: Op, a: Op, b: Op) {
    dst = si_maxs(a, b, 8);
}

#[iclass(VPMAXSW)]
fn vpmaxsw(dst: Op, a: Op, b: Op) {
    dst = si_maxs(a, b, 16);
}

#[iclass(VPMAXSD)]
fn vpmaxsd(dst: Op, a: Op, b: Op) {
    dst = si_maxs(a, b, 32);
}

#[iclass(VPMAXUB)]
fn vpmaxub(dst: Op, a: Op, b: Op) {
    dst = si_maxu(a, b, 8);
}

#[iclass(VPMAXUW)]
fn vpmaxuw(dst: Op, a: Op, b: Op) {
    dst = si_maxu(a, b, 16);
}

#[iclass(VPMAXUD)]
fn vpmaxud(dst: Op, a: Op, b: Op) {
    dst = si_maxu(a, b, 32);
}

// Absolute values (the most negative number stays itself) and PSIGN: the
// first source negated, zeroed or kept as the second's lane is negative,
// zero or positive.
fn si_abs(a: Op, w: Op) {
    lanes(width(a) / w, if slt(a, 0) { -a } else { a })
}

fn si_sign(a: Op, b: Op, w: Op) {
    lanes(
        width(a) / w,
        if slt(b, 0) {
            -a
        } else if b == 0 {
            0
        } else {
            a
        },
    )
}

#[iclass(PABSB)]
fn pabsb(dst: Op, src: Op) {
    dst = si_abs(src, 8);
}

#[iclass(PABSW)]
fn pabsw(dst: Op, src: Op) {
    dst = si_abs(src, 16);
}

#[iclass(PABSD)]
fn pabsd(dst: Op, src: Op) {
    dst = si_abs(src, 32);
}

#[iclass(VPABSB)]
fn vpabsb(dst: Op, src: Op) {
    dst = si_abs(src, 8);
}

#[iclass(VPABSW)]
fn vpabsw(dst: Op, src: Op) {
    dst = si_abs(src, 16);
}

#[iclass(VPABSD)]
fn vpabsd(dst: Op, src: Op) {
    dst = si_abs(src, 32);
}

#[iclass(PSIGNB)]
fn psignb(dst: Op, src: Op) {
    dst = si_sign(dst, src, 8);
}

#[iclass(PSIGNW)]
fn psignw(dst: Op, src: Op) {
    dst = si_sign(dst, src, 16);
}

#[iclass(PSIGND)]
fn psignd(dst: Op, src: Op) {
    dst = si_sign(dst, src, 32);
}

#[iclass(VPSIGNB)]
fn vpsignb(dst: Op, a: Op, b: Op) {
    dst = si_sign(a, b, 8);
}

#[iclass(VPSIGNW)]
fn vpsignw(dst: Op, a: Op, b: Op) {
    dst = si_sign(a, b, 16);
}

#[iclass(VPSIGND)]
fn vpsignd(dst: Op, a: Op, b: Op) {
    dst = si_sign(a, b, 32);
}

// Comparisons: all ones in a lane where it holds.
fn si_cmpeq(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, sext(a == b, w))
}

fn si_cmpgt(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, sext(sgt(a, b), w))
}

#[iclass(PCMPEQB)]
fn pcmpeqb(dst: Op, src: Op) {
    dst = si_cmpeq(dst, src, 8);
}

#[iclass(PCMPEQW)]
fn pcmpeqw(dst: Op, src: Op) {
    dst = si_cmpeq(dst, src, 16);
}

#[iclass(PCMPEQD)]
fn pcmpeqd(dst: Op, src: Op) {
    dst = si_cmpeq(dst, src, 32);
}

#[iclass(PCMPEQQ)]
fn pcmpeqq(dst: Op, src: Op) {
    dst = si_cmpeq(dst, src, 64);
}

#[iclass(PCMPGTB)]
fn pcmpgtb(dst: Op, src: Op) {
    dst = si_cmpgt(dst, src, 8);
}

#[iclass(PCMPGTW)]
fn pcmpgtw(dst: Op, src: Op) {
    dst = si_cmpgt(dst, src, 16);
}

#[iclass(PCMPGTD)]
fn pcmpgtd(dst: Op, src: Op) {
    dst = si_cmpgt(dst, src, 32);
}

#[iclass(PCMPGTQ)]
fn pcmpgtq(dst: Op, src: Op) {
    dst = si_cmpgt(dst, src, 64);
}

#[iclass(VPCMPEQB)]
fn vpcmpeqb(dst: Op, a: Op, b: Op) {
    dst = si_cmpeq(a, b, 8);
}

#[iclass(VPCMPEQW)]
fn vpcmpeqw(dst: Op, a: Op, b: Op) {
    dst = si_cmpeq(a, b, 16);
}

#[iclass(VPCMPEQD)]
fn vpcmpeqd(dst: Op, a: Op, b: Op) {
    dst = si_cmpeq(a, b, 32);
}

#[iclass(VPCMPEQQ)]
fn vpcmpeqq(dst: Op, a: Op, b: Op) {
    dst = si_cmpeq(a, b, 64);
}

#[iclass(VPCMPGTB)]
fn vpcmpgtb(dst: Op, a: Op, b: Op) {
    dst = si_cmpgt(a, b, 8);
}

#[iclass(VPCMPGTW)]
fn vpcmpgtw(dst: Op, a: Op, b: Op) {
    dst = si_cmpgt(a, b, 16);
}

#[iclass(VPCMPGTD)]
fn vpcmpgtd(dst: Op, a: Op, b: Op) {
    dst = si_cmpgt(a, b, 32);
}

#[iclass(VPCMPGTQ)]
fn vpcmpgtq(dst: Op, a: Op, b: Op) {
    dst = si_cmpgt(a, b, 64);
}

// Shifts of `w`-bit lanes by one count: an immediate, or the low 64 bits
// of a register or memory operand. A count of `w` or more gives 0 (the
// sign for arithmetic shifts): the count saturates to `w` before it is
// cut to a lane.
fn si_count(c: Op, w: Op) {
    let n = fit(c, 64);
    if n > w - 1 { w } else { n }
}

fn si_shl(a: Op, c: Op, w: Op) {
    let k = si_count(c, w);
    lanes(width(a) / w, a << k)
}

fn si_shr(a: Op, c: Op, w: Op) {
    let k = si_count(c, w);
    lanes(width(a) / w, a >> k)
}

fn si_sar(a: Op, c: Op, w: Op) {
    let k = si_count(c, w);
    lanes(width(a) / w, sar(a, k))
}

// PSLLDQ and PSRLDQ: each 128-bit block shifted by imm8 bytes; 16 or more
// clear it.
fn si_shldq(a: Op, imm: Op) {
    let r = zext(0, width(a));
    for i in 0..width(a) / 128 {
        let block = bits(a, 128 * i, 128) << (zext(imm, 128) << 3);
        r = r | (zext(block, width(a)) << (128 * i));
    }
    r
}

fn si_shrdq(a: Op, imm: Op) {
    let r = zext(0, width(a));
    for i in 0..width(a) / 128 {
        let block = bits(a, 128 * i, 128) >> (zext(imm, 128) << 3);
        r = r | (zext(block, width(a)) << (128 * i));
    }
    r
}

#[iclass(PSLLW)]
fn psllw(dst: Op, count: Op) {
    dst = si_shl(dst, count, 16);
}

#[iclass(PSLLD)]
fn pslld(dst: Op, count: Op) {
    dst = si_shl(dst, count, 32);
}

#[iclass(PSLLQ)]
fn psllq(dst: Op, count: Op) {
    dst = si_shl(dst, count, 64);
}

#[iclass(PSRLW)]
fn psrlw(dst: Op, count: Op) {
    dst = si_shr(dst, count, 16);
}

#[iclass(PSRLD)]
fn psrld(dst: Op, count: Op) {
    dst = si_shr(dst, count, 32);
}

#[iclass(PSRLQ)]
fn psrlq(dst: Op, count: Op) {
    dst = si_shr(dst, count, 64);
}

#[iclass(PSRAW)]
fn psraw(dst: Op, count: Op) {
    dst = si_sar(dst, count, 16);
}

#[iclass(PSRAD)]
fn psrad(dst: Op, count: Op) {
    dst = si_sar(dst, count, 32);
}

#[iclass(PSLLDQ)]
fn pslldq(dst: Op, imm: Op) {
    dst = si_shldq(dst, imm);
}

#[iclass(PSRLDQ)]
fn psrldq(dst: Op, imm: Op) {
    dst = si_shrdq(dst, imm);
}

#[iclass(VPSLLW)]
fn vpsllw(dst: Op, a: Op, count: Op) {
    dst = si_shl(a, count, 16);
}

#[iclass(VPSLLD)]
fn vpslld(dst: Op, a: Op, count: Op) {
    dst = si_shl(a, count, 32);
}

#[iclass(VPSLLQ)]
fn vpsllq(dst: Op, a: Op, count: Op) {
    dst = si_shl(a, count, 64);
}

#[iclass(VPSRLW)]
fn vpsrlw(dst: Op, a: Op, count: Op) {
    dst = si_shr(a, count, 16);
}

#[iclass(VPSRLD)]
fn vpsrld(dst: Op, a: Op, count: Op) {
    dst = si_shr(a, count, 32);
}

#[iclass(VPSRLQ)]
fn vpsrlq(dst: Op, a: Op, count: Op) {
    dst = si_shr(a, count, 64);
}

#[iclass(VPSRAW)]
fn vpsraw(dst: Op, a: Op, count: Op) {
    dst = si_sar(a, count, 16);
}

#[iclass(VPSRAD)]
fn vpsrad(dst: Op, a: Op, count: Op) {
    dst = si_sar(a, count, 32);
}

#[iclass(VPSLLDQ)]
fn vpslldq(dst: Op, a: Op, imm: Op) {
    dst = si_shldq(a, imm);
}

#[iclass(VPSRLDQ)]
fn vpsrldq(dst: Op, a: Op, imm: Op) {
    dst = si_shrdq(a, imm);
}

// AVX2 shifts by a count per lane (a count of the lane width or more gives
// 0, or the sign).
#[iclass(VPSLLVD)]
fn vpsllvd(dst: Op, a: Op, count: Op) {
    dst = lanes(width(a) / 32, a << count);
}

#[iclass(VPSLLVQ)]
fn vpsllvq(dst: Op, a: Op, count: Op) {
    dst = lanes(width(a) / 64, a << count);
}

#[iclass(VPSRLVD)]
fn vpsrlvd(dst: Op, a: Op, count: Op) {
    dst = lanes(width(a) / 32, a >> count);
}

#[iclass(VPSRLVQ)]
fn vpsrlvq(dst: Op, a: Op, count: Op) {
    dst = lanes(width(a) / 64, a >> count);
}

#[iclass(VPSRAVD)]
fn vpsravd(dst: Op, a: Op, count: Op) {
    dst = lanes(width(a) / 32, sar(a, count));
}

// Horizontal operations: in each 128-bit block, the results of adjacent
// pairs of the first source's block, then of the second's. `pa` and `pb`
// hold the pair results of the whole sources (half their width).
fn si_hblocks(pa: Op, pb: Op) {
    let r = zext(0, 2 * width(pa));
    for i in 0..width(pa) / 64 {
        let block = concat(bits(pb, 64 * i, 64), bits(pa, 64 * i, 64));
        r = r | (zext(block, 2 * width(pa)) << (128 * i));
    }
    r
}

// Pair sums and differences (the lower element minus the upper) of
// `w`-bit elements, wrapping; the SW forms saturate.
fn si_pairadd(x: Op, w: Op) {
    lanes(width(x) / (2 * w), bits(x, 0, w) + bits(x, w, w))
}

fn si_pairsub(x: Op, w: Op) {
    lanes(width(x) / (2 * w), bits(x, 0, w) - bits(x, w, w))
}

fn si_pairadds(x: Op) {
    lanes(
        width(x) / 32,
        si_ssat(sext(bits(x, 0, 16), 32) + sext(bits(x, 16, 16), 32), 16),
    )
}

fn si_pairsubs(x: Op) {
    lanes(
        width(x) / 32,
        si_ssat(sext(bits(x, 0, 16), 32) - sext(bits(x, 16, 16), 32), 16),
    )
}

#[iclass(PHADDW)]
fn phaddw(dst: Op, src: Op) {
    dst = si_hblocks(si_pairadd(dst, 16), si_pairadd(src, 16));
}

#[iclass(PHADDD)]
fn phaddd(dst: Op, src: Op) {
    dst = si_hblocks(si_pairadd(dst, 32), si_pairadd(src, 32));
}

#[iclass(PHADDSW)]
fn phaddsw(dst: Op, src: Op) {
    dst = si_hblocks(si_pairadds(dst), si_pairadds(src));
}

#[iclass(PHSUBW)]
fn phsubw(dst: Op, src: Op) {
    dst = si_hblocks(si_pairsub(dst, 16), si_pairsub(src, 16));
}

#[iclass(PHSUBD)]
fn phsubd(dst: Op, src: Op) {
    dst = si_hblocks(si_pairsub(dst, 32), si_pairsub(src, 32));
}

#[iclass(PHSUBSW)]
fn phsubsw(dst: Op, src: Op) {
    dst = si_hblocks(si_pairsubs(dst), si_pairsubs(src));
}

#[iclass(VPHADDW)]
fn vphaddw(dst: Op, a: Op, b: Op) {
    dst = si_hblocks(si_pairadd(a, 16), si_pairadd(b, 16));
}

#[iclass(VPHADDD)]
fn vphaddd(dst: Op, a: Op, b: Op) {
    dst = si_hblocks(si_pairadd(a, 32), si_pairadd(b, 32));
}

#[iclass(VPHADDSW)]
fn vphaddsw(dst: Op, a: Op, b: Op) {
    dst = si_hblocks(si_pairadds(a), si_pairadds(b));
}

#[iclass(VPHSUBW)]
fn vphsubw(dst: Op, a: Op, b: Op) {
    dst = si_hblocks(si_pairsub(a, 16), si_pairsub(b, 16));
}

#[iclass(VPHSUBD)]
fn vphsubd(dst: Op, a: Op, b: Op) {
    dst = si_hblocks(si_pairsub(a, 32), si_pairsub(b, 32));
}

#[iclass(VPHSUBSW)]
fn vphsubsw(dst: Op, a: Op, b: Op) {
    dst = si_hblocks(si_pairsubs(a), si_pairsubs(b));
}

// PHMINPOSUW: the smallest unsigned word in bits 0..16, the index of its
// first occurrence in bits 16..19, the rest 0.
fn si_phminposuw(x: Op) {
    let m = bits(x, 0, 16);
    let at = zext(0, 3);
    for i in 1..8 {
        let v = bits(x, 16 * i, 16);
        let less = v < m;
        at = if less { i } else { at };
        m = if less { v } else { m };
    }
    zext(concat(at, m), 128)
}

#[iclass(PHMINPOSUW)]
fn phminposuw(dst: Op, src: Op) {
    dst = si_phminposuw(src);
}

#[iclass(VPHMINPOSUW)]
fn vphminposuw(dst: Op, src: Op) {
    dst = si_phminposuw(src);
}

// The SSE4.2 string compares (SDM Vol. 2 §4.1). imm8[1:0] is the element
// format (unsigned/signed bytes/words), [3:2] the aggregation (equal any,
// ranges, equal each, equal ordered), [5:4] the polarity, [6] the output
// (least or most significant index; bit or element mask). The first
// operand is the set or pattern (`a`, length from eax/rax or its first
// null element), the second the string searched (`b`, edx/rdx).

// `len` (8 bits, at most `n`) as a mask of the first `len` of `n`
// elements.
fn si_valid(len: Op, n: Op) {
    bits((zext(1, 32) << zext(len, 32)) - 1, 0, n)
}

// An explicit length: the absolute value of the signed register `r`,
// saturated to `n` elements.
fn si_elen(r: Op, n: Op) {
    let x = if slt(r, 0) { -r } else { r };
    trunc(if x > n { n } else { x }, 8)
}

// An implicit length: the elements before the first null one.
fn si_ilen(x: Op, w: Op) {
    fit(ctz(lanes(128 / w, x == 0)), 8)
}

// IntRes2 for `w`-bit elements: a bit per element of `b`. Invalid
// elements override the comparisons as the SDM's table says: equal any
// and ranges never match them; equal each matches two invalid elements;
// equal ordered matches where the pattern has ended, and the pattern may
// run past the end of `b` (those elements do not exist and do not count).
fn si_str(a: Op, b: Op, la: Op, lb: Op, imm: Op, w: Op) {
    let n = 128 / w;
    let va = si_valid(la, n);
    let vb = si_valid(lb, n);
    let signed = bit(imm, 1) == 1;
    let any = zext(0, n);
    let ordered = !zext(0, n);
    for i in 0..n {
        let x = bits(a, i * w, w);
        let eq = lanes(n, b == x) & vb;
        let on = sext(bit(va, i), n);
        any = any | (eq & on);
        let past = !(!zext(0, n) >> i);
        ordered = ordered & (!on | (eq >> i) | past);
    }
    let ranges = zext(0, n);
    for i in 0..n / 2 {
        let low = bits(a, 2 * i * w, w);
        let high = bits(a, (2 * i + 1) * w, w);
        let ge = lanes(n, if signed { sge(b, low) } else { b >= low });
        let le = lanes(n, if signed { sle(b, high) } else { b <= high });
        ranges = ranges | (ge & le & vb & sext(bit(va, 2 * i + 1), n));
    }
    let each = (lanes(n, a == b) & va & vb) | (!va & !vb);
    let aggregation = bits(imm, 2, 2);
    let r = if aggregation == 0 {
        any
    } else if aggregation == 1 {
        ranges
    } else if aggregation == 2 {
        each
    } else {
        ordered
    };
    let polarity = bits(imm, 4, 2);
    if polarity == 1 {
        !r
    } else if polarity == 3 {
        r ^ vb
    } else {
        r
    }
}

// The compare in the format imm8[0] selects, as 16 bits (8 for words), and
// its flags: CF if any bit is set, ZF if `b` ends early, SF if `a` does,
// OF bit 0.
fn si_strcmp(a: Op, b: Op, imm: Op, la8: Op, lb8: Op, la16: Op, lb16: Op) {
    let word = bit(imm, 0) == 1;
    let r = if word {
        zext(si_str(a, b, la16, lb16, imm, 16), 16)
    } else {
        si_str(a, b, la8, lb8, imm, 8)
    };
    cf = r != 0;
    zf = if word { lb16 < 8 } else { lb8 < 16 };
    sf = if word { la16 < 8 } else { la8 < 16 };
    of = bit(r, 0);
    r
}

// The index output: the element count if no bit is set, else the least
// (imm8[6] = 0) or most significant set bit's index.
fn si_index(r: Op, imm: Op) {
    let n = 16 - (zext(bit(imm, 0), 16) << 3);
    if r == 0 {
        n
    } else if bit(imm, 6) == 1 {
        15 - clz(r)
    } else {
        ctz(r)
    }
}

// The mask output: the bits zero-extended (imm8[6] = 0), or each bit
// widened to its element.
fn si_mask(r: Op, imm: Op) {
    let words = bits(r, 0, 8);
    let expanded = if bit(imm, 0) == 1 {
        lanes(8, sext(words, 16))
    } else {
        lanes(16, sext(r, 8))
    };
    if bit(imm, 6) == 1 {
        expanded
    } else {
        zext(r, 128)
    }
}

fn si_estr(a: Op, b: Op, imm: Op, ra: Op, rb: Op) {
    si_strcmp(
        a,
        b,
        imm,
        si_elen(ra, 16),
        si_elen(rb, 16),
        si_elen(ra, 8),
        si_elen(rb, 8),
    )
}

fn si_istr(a: Op, b: Op, imm: Op) {
    si_strcmp(
        a,
        b,
        imm,
        si_ilen(a, 8),
        si_ilen(b, 8),
        si_ilen(a, 16),
        si_ilen(b, 16),
    )
}

#[iclass(PCMPESTRI, PCMPESTRI64, VPCMPESTRI, VPCMPESTRI64)]
fn pcmpestri(a: Op, b: Op, imm: Op, ra: Op, rb: Op, dst: Op) {
    dst = zext(si_index(si_estr(a, b, imm, ra, rb), imm), width(dst));
}

#[iclass(PCMPESTRM, PCMPESTRM64, VPCMPESTRM, VPCMPESTRM64)]
fn pcmpestrm(a: Op, b: Op, imm: Op, ra: Op, rb: Op, dst: Op) {
    dst = si_mask(si_estr(a, b, imm, ra, rb), imm);
}

#[iclass(PCMPISTRI, PCMPISTRI64, VPCMPISTRI, VPCMPISTRI64)]
fn pcmpistri(a: Op, b: Op, imm: Op, dst: Op) {
    dst = zext(si_index(si_istr(a, b, imm), imm), width(dst));
}

#[iclass(PCMPISTRM, VPCMPISTRM)]
fn pcmpistrm(a: Op, b: Op, imm: Op, dst: Op) {
    dst = si_mask(si_istr(a, b, imm), imm);
}

// CRC32 with the iSCSI polynomial 0x11EDC6F41, bit-reflected (SDM: the
// reflected source and destination, the remainder reflected back): the
// destination's low 32 bits are the running value, no inversion; the
// result is zero-extended to the destination.
#[iclass(CRC32)]
fn crc32(dst: Op, src: Op) {
    let crc = trunc(dst, 32);
    for i in 0..width(src) {
        crc = (crc >> 1) ^ (sext(bit(crc, 0) ^ bit(src, i), 32) & 0x82F63B78);
    }
    dst = zext(crc, width(dst));
}
