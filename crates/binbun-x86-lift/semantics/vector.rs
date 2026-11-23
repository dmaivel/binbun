// SSE and AVX data movement, logic and integer arithmetic. Register
// destinations follow the encoding's rule (the runtime's): a legacy SSE
// write keeps the rest of the register, a VEX write zeroes it.

// Moves of a whole operand, and loads into a wider register (the rest
// zero): MOVAPS to MOVDQU, scalar MOVSS/MOVSD loads, stores and register
// moves, MOVD and MOVQ in every direction, the non-temporal moves, and the
// low-quadword MOVLPS/MOVLPD (a legacy load keeps the high quadword).
#[iclass(
    MOVAPS, MOVUPS, MOVAPD, MOVUPD, MOVDQA, MOVDQU, LDDQU, MOVSS, MOVSD_XMM, MOVD, MOVQ, VMOVAPS,
    VMOVUPS, VMOVAPD, VMOVUPD, VMOVDQA, VMOVDQU, VLDDQU, VMOVD, VMOVQ, MOVNTDQ, MOVNTDQA, MOVNTI,
    MOVNTPD, MOVNTPS, VMOVNTDQ, VMOVNTDQA, VMOVNTPD, VMOVNTPS, MOVLPS, MOVLPD
)]
#[iform(
    VMOVSS_XMMdq_MEMd,
    VMOVSS_MEMd_XMMd,
    VMOVSD_XMMdq_MEMq,
    VMOVSD_MEMq_XMMq,
    VMOVLPS_MEMq_XMMq,
    VMOVLPD_MEMq_XMMq
)]
fn vmove(dst: Op, src: Op) {
    dst = zext(src, width(dst));
}

#[iclass(PXOR, XORPS, XORPD)]
fn pxor(dst: Op, src: Op) {
    dst = dst ^ src;
}

#[iclass(VPXOR, VXORPS, VXORPD)]
fn vpxor(dst: Op, a: Op, b: Op) {
    dst = a ^ b;
}

#[iclass(PAND, ANDPS, ANDPD)]
fn pand(dst: Op, src: Op) {
    dst = dst & src;
}

#[iclass(VPAND, VANDPS, VANDPD)]
fn vpand(dst: Op, a: Op, b: Op) {
    dst = a & b;
}

#[iclass(POR, ORPS, ORPD)]
fn por(dst: Op, src: Op) {
    dst = dst | src;
}

#[iclass(VPOR, VORPS, VORPD)]
fn vpor(dst: Op, a: Op, b: Op) {
    dst = a | b;
}

#[iclass(PANDN, ANDNPS, ANDNPD)]
fn pandn(dst: Op, src: Op) {
    dst = !dst & src;
}

#[iclass(VPANDN, VANDNPS, VANDNPD)]
fn vpandn(dst: Op, a: Op, b: Op) {
    dst = !a & b;
}

// Lane-wise addition and subtraction, wrapping, of `w`-bit lanes.
fn padd(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, a + b)
}

fn psub(a: Op, b: Op, w: Op) {
    lanes(width(a) / w, a - b)
}

#[iclass(PADDB)]
fn paddb(dst: Op, src: Op) {
    dst = padd(dst, src, 8);
}

#[iclass(PADDW)]
fn paddw(dst: Op, src: Op) {
    dst = padd(dst, src, 16);
}

#[iclass(PADDD)]
fn paddd(dst: Op, src: Op) {
    dst = padd(dst, src, 32);
}

#[iclass(PADDQ)]
fn paddq(dst: Op, src: Op) {
    dst = padd(dst, src, 64);
}

#[iclass(VPADDB)]
fn vpaddb(dst: Op, a: Op, b: Op) {
    dst = padd(a, b, 8);
}

#[iclass(VPADDW)]
fn vpaddw(dst: Op, a: Op, b: Op) {
    dst = padd(a, b, 16);
}

#[iclass(VPADDD)]
fn vpaddd(dst: Op, a: Op, b: Op) {
    dst = padd(a, b, 32);
}

#[iclass(VPADDQ)]
fn vpaddq(dst: Op, a: Op, b: Op) {
    dst = padd(a, b, 64);
}

#[iclass(PSUBB)]
fn psubb(dst: Op, src: Op) {
    dst = psub(dst, src, 8);
}

#[iclass(PSUBW)]
fn psubw(dst: Op, src: Op) {
    dst = psub(dst, src, 16);
}

#[iclass(PSUBD)]
fn psubd(dst: Op, src: Op) {
    dst = psub(dst, src, 32);
}

#[iclass(PSUBQ)]
fn psubq(dst: Op, src: Op) {
    dst = psub(dst, src, 64);
}

#[iclass(VPSUBB)]
fn vpsubb(dst: Op, a: Op, b: Op) {
    dst = psub(a, b, 8);
}

#[iclass(VPSUBW)]
fn vpsubw(dst: Op, a: Op, b: Op) {
    dst = psub(a, b, 16);
}

#[iclass(VPSUBD)]
fn vpsubd(dst: Op, a: Op, b: Op) {
    dst = psub(a, b, 32);
}

#[iclass(VPSUBQ)]
fn vpsubq(dst: Op, a: Op, b: Op) {
    dst = psub(a, b, 64);
}

// Elements. `vec_pick` and `vec_insert` take the element number `i` known
// at lift time or computed (an immediate's bits).

// Element `i` (`w` bits) of `x`.
fn vec_pick(x: Op, i: Op, w: Op) {
    trunc(x >> zext(zext(i, 16) * w, width(x)), w)
}

// `x` with element `i` (`w` bits) replaced by `v`.
fn vec_insert(x: Op, i: Op, w: Op, v: Op) {
    let at = zext(zext(i, 16) * w, width(x));
    let ones = zext(!zext(0, w), width(x));
    (x & !(ones << at)) | (zext(v, width(x)) << at)
}

// `x` `n` times side by side.
fn vec_repeat(x: Op, n: Op) {
    let r = x;
    for i in 1..n {
        r = concat(x, r);
    }
    r
}

// The sign bits of the `w`-bit elements of `x`, element 0 in bit 0.
fn vec_signs(x: Op, w: Op) {
    lanes(width(x) / w, msb(x))
}

// Whether a 64-bit address is not canonical (bits 63 to 47 not all equal).
fn vec_noncanonical(a: Op) {
    sext(trunc(a, 48), 64) != a
}

// Blends: element `i` from `b` if bit `i` (mod 8) of `imm` is set, else
// from `a`. The 256-bit PBLENDW uses the 8 bits for each 128-bit half.
fn vec_blend(a: Op, b: Op, imm: Op, w: Op) {
    let r = zext(0, width(a));
    for i in 0..width(a) / w {
        let e = if bit(imm, i & 7) {
            bits(b, i * w, w)
        } else {
            bits(a, i * w, w)
        };
        r = r | (zext(e, width(a)) << (i * w));
    }
    r
}

#[iclass(BLENDPS)]
fn blendps(dst: Op, src: Op, imm: Op) {
    dst = vec_blend(dst, src, imm, 32);
}

#[iclass(BLENDPD)]
fn blendpd(dst: Op, src: Op, imm: Op) {
    dst = vec_blend(dst, src, imm, 64);
}

#[iclass(PBLENDW)]
fn pblendw(dst: Op, src: Op, imm: Op) {
    dst = vec_blend(dst, src, imm, 16);
}

#[iclass(VBLENDPS, VPBLENDD)]
fn vblendps(dst: Op, a: Op, b: Op, imm: Op) {
    dst = vec_blend(a, b, imm, 32);
}

#[iclass(VBLENDPD)]
fn vblendpd(dst: Op, a: Op, b: Op, imm: Op) {
    dst = vec_blend(a, b, imm, 64);
}

#[iclass(VPBLENDW)]
fn vpblendw(dst: Op, a: Op, b: Op, imm: Op) {
    dst = vec_blend(a, b, imm, 16);
}

// Variable blends: element from the second source where the mask
// element's sign bit is set (the legacy forms' mask is xmm0).
#[iclass(BLENDVPS)]
fn blendvps(dst: Op, src: Op, mask: Op) {
    dst = lanes(width(dst) / 32, if msb(mask) { src } else { dst });
}

#[iclass(BLENDVPD)]
fn blendvpd(dst: Op, src: Op, mask: Op) {
    dst = lanes(width(dst) / 64, if msb(mask) { src } else { dst });
}

#[iclass(PBLENDVB)]
fn pblendvb(dst: Op, src: Op, mask: Op) {
    dst = lanes(width(dst) / 8, if msb(mask) { src } else { dst });
}

#[iclass(VBLENDVPS)]
fn vblendvps(dst: Op, a: Op, b: Op, mask: Op) {
    dst = lanes(width(dst) / 32, if msb(mask) { b } else { a });
}

#[iclass(VBLENDVPD)]
fn vblendvpd(dst: Op, a: Op, b: Op, mask: Op) {
    dst = lanes(width(dst) / 64, if msb(mask) { b } else { a });
}

#[iclass(VPBLENDVB)]
fn vpblendvb(dst: Op, a: Op, b: Op, mask: Op) {
    dst = lanes(width(dst) / 8, if msb(mask) { b } else { a });
}

// EXTRACTPS: the dword `imm[1:0]`, to a 32-bit register (64-bit ones are
// zero-extended) or memory.
#[iclass(EXTRACTPS, VEXTRACTPS)]
fn extractps(dst: Op, src: Op, imm: Op) {
    dst = zext(vec_pick(src, imm & 3, 32), width(dst));
}

// INSERTPS: the source dword `imm[7:6]` (a memory source is the dword
// itself) into dword `imm[5:4]`, then the dwords set in `imm[3:0]` zeroed.
fn vec_insertps(a: Op, e: Op, imm: Op) {
    let r = vec_insert(a, bits(imm, 4, 2), 32, e);
    for j in 0..4 {
        r = r & !(zext(sext(bit(imm, j), 32), 128) << (j * 32));
    }
    r
}

#[iclass(INSERTPS)]
fn insertps(dst: Op, src: Op, imm: Op) {
    dst = vec_insertps(dst, vec_pick(src, bits(imm, 6, 2), 32), imm);
}

#[iform(INSERTPS_XMMps_MEMd_IMMb)]
fn insertps_load(dst: Op, src: Op, imm: Op) {
    dst = vec_insertps(dst, src, imm);
}

#[iclass(VINSERTPS)]
fn vinsertps(dst: Op, a: Op, b: Op, imm: Op) {
    dst = vec_insertps(a, vec_pick(b, bits(imm, 6, 2), 32), imm);
}

#[iform(VINSERTPS_XMMdq_XMMdq_MEMd_IMMb)]
fn vinsertps_load(dst: Op, a: Op, b: Op, imm: Op) {
    dst = vec_insertps(a, b, imm);
}

// MASKMOVDQU: the bytes whose mask byte has its sign bit set, stored at
// [rdi] (ds, or the override). The processor checks the whole 16 bytes
// for writing even where the mask is zero (measured: a zero mask faults on
// a non-canonical, an unmapped and a read-only destination), so this is a
// read and write of all 16 bytes, the unselected ones written back
// unchanged.
#[iclass(MASKMOVDQU, VMASKMOVDQU)]
fn maskmovdqu(src: Op, mask: Op, m: Op) {
    let a = address(m);
    let old = load(m, a, 128);
    store(m, a, lanes(16, if msb(mask) { src } else { old }));
}

// MOVDDUP: the low quadword (of each 128-bit half) twice.
#[iclass(MOVDDUP, VMOVDDUP)]
fn movddup(dst: Op, src: Op) {
    let r = zext(0, width(dst));
    for i in 0..width(dst) / 64 {
        r = r | (zext(bits(src, (i >> 1) * 128, 64), width(dst)) << (i * 64));
    }
    dst = r;
}

// MOVSLDUP and MOVSHDUP: the even (odd) dwords, each twice.
fn vec_dup(s: Op, odd: Op) {
    let r = zext(0, width(s));
    for i in 0..width(s) / 32 {
        r = r | (zext(bits(s, ((i >> 1) * 2 + odd) * 32, 32), width(s)) << (i * 32));
    }
    r
}

#[iclass(MOVSLDUP, VMOVSLDUP)]
fn movsldup(dst: Op, src: Op) {
    dst = vec_dup(src, 0);
}

#[iclass(MOVSHDUP, VMOVSHDUP)]
fn movshdup(dst: Op, src: Op) {
    dst = vec_dup(src, 1);
}

// XED gives MOVHLPS's source, and the register sources of PUNPCKH*,
// UNPCKHPD and MOVHPD's store, as their low quadword; they use the high
// one (`wide`: 128 bits of the register).
#[iclass(MOVHLPS)]
fn movhlps(dst: Op, src: Op) {
    dst = bits(wide(src, 128), 64, 64);
}

#[iclass(VMOVHLPS)]
fn vmovhlps(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 64, 64), bits(b, 64, 64));
}

#[iclass(MOVLHPS)]
fn movlhps(dst: Op, src: Op) {
    dst = concat(src, dst);
}

#[iclass(VMOVLHPS)]
fn vmovlhps(dst: Op, a: Op, b: Op) {
    dst = concat(b, a);
}

// MOVHPS/MOVHPD: the high quadword from or to memory.
#[iclass(MOVHPS, MOVHPD)]
fn movhps(dst: Op, src: Op) {
    dst = concat(src, dst);
}

#[iform(MOVHPS_MEMq_XMMps, MOVHPD_MEMq_XMMsd)]
fn movhps_store(dst: Op, src: Op) {
    dst = bits(wide(src, 128), 64, 64);
}

#[iclass(VMOVHPS, VMOVHPD)]
fn vmovhps(dst: Op, a: Op, b: Op) {
    dst = concat(b, trunc(a, 64));
}

#[iform(VMOVHPS_MEMq_XMMdq, VMOVHPD_MEMq_XMMdq)]
fn vmovhps_store(dst: Op, src: Op) {
    dst = bits(src, 64, 64);
}

#[iclass(VMOVLPS, VMOVLPD)]
fn vmovlps(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, 64, 64), b);
}

// VMOVSS and VMOVSD between registers: the low element from the second
// source, the rest of 128 bits from the first.
#[iclass(VMOVSS, VMOVSD)]
fn vmovss(dst: Op, a: Op, b: Op) {
    dst = concat(bits(a, width(b), 128 - width(b)), b);
}

// MOVMSKPS/PD, PMOVMSKB: the elements' sign bits, zero-extended.
#[iclass(MOVMSKPS, VMOVMSKPS)]
fn movmskps(dst: Op, src: Op) {
    dst = zext(vec_signs(src, 32), width(dst));
}

#[iclass(MOVMSKPD, VMOVMSKPD)]
fn movmskpd(dst: Op, src: Op) {
    dst = zext(vec_signs(src, 64), width(dst));
}

#[iclass(PMOVMSKB, VPMOVMSKB)]
fn pmovmskb(dst: Op, src: Op) {
    dst = zext(vec_signs(src, 8), width(dst));
}

// Packs with saturation, per 128-bit half: the first source's elements,
// then the second's, each to half its width, signed (PACKSS) or unsigned
// from signed (PACKUS).
fn vec_ssat(x: Op) {
    let h = width(x) / 2;
    trunc(
        if sgt(x, (1 << (h - 1)) - 1) {
            (1 << (h - 1)) - 1
        } else if slt(x, (1 << width(x)) - (1 << (h - 1))) {
            (1 << width(x)) - (1 << (h - 1))
        } else {
            x
        },
        h,
    )
}

fn vec_usat(x: Op) {
    let h = width(x) / 2;
    trunc(
        if slt(x, 0) {
            0
        } else if sgt(x, (1 << h) - 1) {
            (1 << h) - 1
        } else {
            x
        },
        h,
    )
}

fn vec_pack(a: Op, b: Op, w: Op, signed: Op) {
    let k = 128 / w;
    let r = zext(0, width(a));
    for o in 0..width(a) / (w / 2) {
        let lane = o / (2 * k);
        let j = o - lane * 2 * k;
        let s = if j < k { a } else { b };
        let x = bits(s, (lane * k + (j & (k - 1))) * w, w);
        let e = if signed == 1 {
            vec_ssat(x)
        } else {
            vec_usat(x)
        };
        r = r | (zext(e, width(a)) << (o * (w / 2)));
    }
    r
}

#[iclass(PACKSSWB)]
fn packsswb(dst: Op, src: Op) {
    dst = vec_pack(dst, src, 16, 1);
}

#[iclass(PACKSSDW)]
fn packssdw(dst: Op, src: Op) {
    dst = vec_pack(dst, src, 32, 1);
}

#[iclass(PACKUSWB)]
fn packuswb(dst: Op, src: Op) {
    dst = vec_pack(dst, src, 16, 0);
}

#[iclass(PACKUSDW)]
fn packusdw(dst: Op, src: Op) {
    dst = vec_pack(dst, src, 32, 0);
}

#[iclass(VPACKSSWB)]
fn vpacksswb(dst: Op, a: Op, b: Op) {
    dst = vec_pack(a, b, 16, 1);
}

#[iclass(VPACKSSDW)]
fn vpackssdw(dst: Op, a: Op, b: Op) {
    dst = vec_pack(a, b, 32, 1);
}

#[iclass(VPACKUSWB)]
fn vpackuswb(dst: Op, a: Op, b: Op) {
    dst = vec_pack(a, b, 16, 0);
}

#[iclass(VPACKUSDW)]
fn vpackusdw(dst: Op, a: Op, b: Op) {
    dst = vec_pack(a, b, 32, 0);
}

// PALIGNR, per 128-bit half: the first source above the second, shifted
// right by `imm` bytes (all of it gone from 32 on), the low 128 bits.
fn vec_palignr(a: Op, b: Op, imm: Op) {
    let r = zext(0, width(a));
    for l in 0..width(a) / 128 {
        let c = concat(bits(a, l * 128, 128), bits(b, l * 128, 128));
        r = r | (zext(trunc(c >> zext(zext(imm, 16) * 8, 256), 128), width(a)) << (l * 128));
    }
    r
}

#[iclass(PALIGNR)]
fn palignr(dst: Op, src: Op, imm: Op) {
    dst = vec_palignr(dst, src, imm);
}

#[iclass(VPALIGNR)]
fn vpalignr(dst: Op, a: Op, b: Op, imm: Op) {
    dst = vec_palignr(a, b, imm);
}

// PEXTR*: the element the immediate's low bits select, zero-extended to a
// register, or stored.
#[iclass(PEXTRB, VPEXTRB)]
fn pextrb(dst: Op, src: Op, imm: Op) {
    dst = zext(vec_pick(src, imm & 15, 8), width(dst));
}

#[iclass(PEXTRW, PEXTRW_SSE4, VPEXTRW)]
fn pextrw(dst: Op, src: Op, imm: Op) {
    dst = zext(vec_pick(src, imm & 7, 16), width(dst));
}

#[iclass(PEXTRD, VPEXTRD)]
fn pextrd(dst: Op, src: Op, imm: Op) {
    dst = zext(vec_pick(src, imm & 3, 32), width(dst));
}

#[iclass(PEXTRQ, VPEXTRQ)]
fn pextrq(dst: Op, src: Op, imm: Op) {
    dst = zext(vec_pick(src, imm & 1, 64), width(dst));
}

// PINSR*: the low bits of the source into the element the immediate's low
// bits select.
#[iclass(PINSRB)]
fn pinsrb(dst: Op, src: Op, imm: Op) {
    dst = vec_insert(dst, imm & 15, 8, trunc(src, 8));
}

#[iclass(PINSRW)]
fn pinsrw(dst: Op, src: Op, imm: Op) {
    dst = vec_insert(dst, imm & 7, 16, trunc(src, 16));
}

#[iclass(PINSRD)]
fn pinsrd(dst: Op, src: Op, imm: Op) {
    dst = vec_insert(dst, imm & 3, 32, trunc(src, 32));
}

#[iclass(PINSRQ)]
fn pinsrq(dst: Op, src: Op, imm: Op) {
    dst = vec_insert(dst, imm & 1, 64, trunc(src, 64));
}

#[iclass(VPINSRB)]
fn vpinsrb(dst: Op, a: Op, src: Op, imm: Op) {
    dst = vec_insert(a, imm & 15, 8, trunc(src, 8));
}

#[iclass(VPINSRW)]
fn vpinsrw(dst: Op, a: Op, src: Op, imm: Op) {
    dst = vec_insert(a, imm & 7, 16, trunc(src, 16));
}

#[iclass(VPINSRD)]
fn vpinsrd(dst: Op, a: Op, src: Op, imm: Op) {
    dst = vec_insert(a, imm & 3, 32, trunc(src, 32));
}

#[iclass(VPINSRQ)]
fn vpinsrq(dst: Op, a: Op, src: Op, imm: Op) {
    dst = vec_insert(a, imm & 1, 64, trunc(src, 64));
}

// PMOVSX/PMOVZX: each source element (the source is as many elements as
// the destination holds) extended.
#[iclass(PMOVSXBW, VPMOVSXBW)]
fn pmovsx16(dst: Op, src: Op) {
    dst = lanes(width(dst) / 16, sext(src, 16));
}

#[iclass(PMOVSXBD, PMOVSXWD, VPMOVSXBD, VPMOVSXWD)]
fn pmovsx32(dst: Op, src: Op) {
    dst = lanes(width(dst) / 32, sext(src, 32));
}

#[iclass(PMOVSXBQ, PMOVSXWQ, PMOVSXDQ, VPMOVSXBQ, VPMOVSXWQ, VPMOVSXDQ)]
fn pmovsx64(dst: Op, src: Op) {
    dst = lanes(width(dst) / 64, sext(src, 64));
}

#[iclass(PMOVZXBW, VPMOVZXBW)]
fn pmovzx16(dst: Op, src: Op) {
    dst = lanes(width(dst) / 16, zext(src, 16));
}

#[iclass(PMOVZXBD, PMOVZXWD, VPMOVZXBD, VPMOVZXWD)]
fn pmovzx32(dst: Op, src: Op) {
    dst = lanes(width(dst) / 32, zext(src, 32));
}

#[iclass(PMOVZXBQ, PMOVZXWQ, PMOVZXDQ, VPMOVZXBQ, VPMOVZXWQ, VPMOVZXDQ)]
fn pmovzx64(dst: Op, src: Op) {
    dst = lanes(width(dst) / 64, zext(src, 64));
}

// PSHUFB, per 128-bit half: byte `i` is the byte of `a` the low 4 bits of
// `b`'s byte `i` select, or 0 if that byte's sign bit is set.
fn vec_pshufb(a: Op, b: Op) {
    let r = zext(0, width(a));
    for i in 0..width(a) / 8 {
        let s = bits(b, i * 8, 8);
        let e = if msb(s) {
            zext(0, 8)
        } else {
            vec_pick(bits(a, (i / 16) * 128, 128), s & 15, 8)
        };
        r = r | (zext(e, width(a)) << (i * 8));
    }
    r
}

#[iclass(PSHUFB)]
fn pshufb(dst: Op, src: Op) {
    dst = vec_pshufb(dst, src);
}

#[iclass(VPSHUFB)]
fn vpshufb(dst: Op, a: Op, b: Op) {
    dst = vec_pshufb(a, b);
}

// PSHUFD, per 128-bit half: dword `j` is the dword `imm` bits 2j..2j+2
// select.
#[iclass(PSHUFD, VPSHUFD)]
fn pshufd(dst: Op, src: Op, imm: Op) {
    let r = zext(0, width(src));
    for i in 0..width(src) / 32 {
        let e = vec_pick(bits(src, (i / 4) * 128, 128), bits(imm, (i & 3) * 2, 2), 32);
        r = r | (zext(e, width(src)) << (i * 32));
    }
    dst = r;
}

// PSHUFHW (`high` 1) and PSHUFLW (0), per 128-bit half: the words of the
// high (low) quadword shuffled as PSHUFD does dwords, the other kept.
fn vec_pshufw(s: Op, imm: Op, high: Op) {
    let r = zext(0, width(s));
    for i in 0..width(s) / 16 {
        let lane = bits(s, (i / 8) * 128, 128);
        let j = i & 7;
        let e = if (j >> 2) == high {
            vec_pick(bits(lane, high * 64, 64), bits(imm, (j & 3) * 2, 2), 16)
        } else {
            bits(lane, j * 16, 16)
        };
        r = r | (zext(e, width(s)) << (i * 16));
    }
    r
}

#[iclass(PSHUFHW, VPSHUFHW)]
fn pshufhw(dst: Op, src: Op, imm: Op) {
    dst = vec_pshufw(src, imm, 1);
}

#[iclass(PSHUFLW, VPSHUFLW)]
fn pshuflw(dst: Op, src: Op, imm: Op) {
    dst = vec_pshufw(src, imm, 0);
}

// PTEST: ZF if `a & b` is 0, CF if `!a & b` is 0; OF, AF, PF, SF cleared.
#[iclass(PTEST)]
fn ptest(a: Op, b: Op) {
    zf = (a & b) == 0;
    cf = (!a & b) == 0;
}

// XED's record for VPTEST, VTESTPS and VTESTPD lists only ZF and CF; the
// processor clears OF, AF, PF and SF as the SDM says (measured).
#[iclass(VPTEST)]
fn vptest(a: Op, b: Op) {
    zf = (a & b) == 0;
    cf = (!a & b) == 0;
    of = 0;
    af = 0;
    pf = 0;
    sf = 0;
}

// VTESTPS/VTESTPD: PTEST on the elements' sign bits only.
#[iclass(VTESTPS)]
fn vtestps(a: Op, b: Op) {
    zf = vec_signs(a & b, 32) == 0;
    cf = vec_signs(!a & b, 32) == 0;
    of = 0;
    af = 0;
    pf = 0;
    sf = 0;
}

#[iclass(VTESTPD)]
fn vtestpd(a: Op, b: Op) {
    zf = vec_signs(a & b, 64) == 0;
    cf = vec_signs(!a & b, 64) == 0;
    of = 0;
    af = 0;
    pf = 0;
    sf = 0;
}

// Unpacks, per 128-bit half: the elements of the low (`high` 0) or high
// half of `a` and `b`, interleaved, `a`'s first.
fn vec_unpack(a: Op, b: Op, w: Op, high: Op) {
    let k = 128 / w;
    let r = zext(0, width(a));
    for i in 0..width(a) / w {
        let lane = i / k;
        let j = i - lane * k;
        let from = lane * k + high * (k / 2) + (j >> 1);
        let e = if (j & 1) == 0 {
            bits(a, from * w, w)
        } else {
            bits(b, from * w, w)
        };
        r = r | (zext(e, width(a)) << (i * w));
    }
    r
}

#[iclass(PUNPCKLBW)]
fn punpcklbw(dst: Op, src: Op) {
    dst = vec_unpack(dst, wide(src, 128), 8, 0);
}

#[iclass(PUNPCKLWD)]
fn punpcklwd(dst: Op, src: Op) {
    dst = vec_unpack(dst, wide(src, 128), 16, 0);
}

#[iclass(PUNPCKLDQ, UNPCKLPS)]
fn punpckldq(dst: Op, src: Op) {
    dst = vec_unpack(dst, wide(src, 128), 32, 0);
}

#[iclass(PUNPCKLQDQ, UNPCKLPD)]
fn punpcklqdq(dst: Op, src: Op) {
    dst = vec_unpack(dst, wide(src, 128), 64, 0);
}

#[iclass(PUNPCKHBW)]
fn punpckhbw(dst: Op, src: Op) {
    dst = vec_unpack(dst, wide(src, 128), 8, 1);
}

#[iclass(PUNPCKHWD)]
fn punpckhwd(dst: Op, src: Op) {
    dst = vec_unpack(dst, wide(src, 128), 16, 1);
}

#[iclass(PUNPCKHDQ, UNPCKHPS)]
fn punpckhdq(dst: Op, src: Op) {
    dst = vec_unpack(dst, wide(src, 128), 32, 1);
}

#[iclass(PUNPCKHQDQ, UNPCKHPD)]
fn punpckhqdq(dst: Op, src: Op) {
    dst = vec_unpack(dst, wide(src, 128), 64, 1);
}

#[iclass(VPUNPCKLBW)]
fn vpunpcklbw(dst: Op, a: Op, b: Op) {
    dst = vec_unpack(a, b, 8, 0);
}

#[iclass(VPUNPCKLWD)]
fn vpunpcklwd(dst: Op, a: Op, b: Op) {
    dst = vec_unpack(a, b, 16, 0);
}

#[iclass(VPUNPCKLDQ, VUNPCKLPS)]
fn vpunpckldq(dst: Op, a: Op, b: Op) {
    dst = vec_unpack(a, b, 32, 0);
}

#[iclass(VPUNPCKLQDQ, VUNPCKLPD)]
fn vpunpcklqdq(dst: Op, a: Op, b: Op) {
    dst = vec_unpack(a, b, 64, 0);
}

#[iclass(VPUNPCKHBW)]
fn vpunpckhbw(dst: Op, a: Op, b: Op) {
    dst = vec_unpack(a, b, 8, 1);
}

#[iclass(VPUNPCKHWD)]
fn vpunpckhwd(dst: Op, a: Op, b: Op) {
    dst = vec_unpack(a, b, 16, 1);
}

#[iclass(VPUNPCKHDQ, VUNPCKHPS)]
fn vpunpckhdq(dst: Op, a: Op, b: Op) {
    dst = vec_unpack(a, b, 32, 1);
}

#[iclass(VPUNPCKHQDQ, VUNPCKHPD)]
fn vpunpckhqdq(dst: Op, a: Op, b: Op) {
    dst = vec_unpack(a, b, 64, 1);
}

// SHUFPS, per 128-bit half: dwords 0 and 1 from `a`, 2 and 3 from `b`,
// each selected by two bits of `imm`.
fn vec_shufps(a: Op, b: Op, imm: Op) {
    let r = zext(0, width(a));
    for i in 0..width(a) / 32 {
        let s = if (i & 3) < 2 { a } else { b };
        let e = vec_pick(bits(s, (i / 4) * 128, 128), bits(imm, (i & 3) * 2, 2), 32);
        r = r | (zext(e, width(a)) << (i * 32));
    }
    r
}

// SHUFPD: quadword `i` from `a` (even `i`) or `b` (odd), its 128-bit half's
// quadword that bit `i` of `imm` selects.
fn vec_shufpd(a: Op, b: Op, imm: Op) {
    let r = zext(0, width(a));
    for i in 0..width(a) / 64 {
        let s = if (i & 1) == 0 { a } else { b };
        let e = vec_pick(bits(s, (i / 2) * 128, 128), bit(imm, i), 64);
        r = r | (zext(e, width(a)) << (i * 64));
    }
    r
}

#[iclass(SHUFPS)]
fn shufps(dst: Op, src: Op, imm: Op) {
    dst = vec_shufps(dst, src, imm);
}

#[iclass(SHUFPD)]
fn shufpd(dst: Op, src: Op, imm: Op) {
    dst = vec_shufpd(dst, src, imm);
}

#[iclass(VSHUFPS)]
fn vshufps(dst: Op, a: Op, b: Op, imm: Op) {
    dst = vec_shufps(a, b, imm);
}

#[iclass(VSHUFPD)]
fn vshufpd(dst: Op, a: Op, b: Op, imm: Op) {
    dst = vec_shufpd(a, b, imm);
}

// Broadcasts: the source's low element in every element.
#[iclass(VPBROADCASTB)]
fn vpbroadcastb(dst: Op, src: Op) {
    dst = vec_repeat(trunc(src, 8), width(dst) / 8);
}

#[iclass(VPBROADCASTW)]
fn vpbroadcastw(dst: Op, src: Op) {
    dst = vec_repeat(trunc(src, 16), width(dst) / 16);
}

#[iclass(VBROADCASTSS, VPBROADCASTD)]
fn vbroadcastss(dst: Op, src: Op) {
    dst = vec_repeat(trunc(src, 32), width(dst) / 32);
}

#[iclass(VBROADCASTSD, VPBROADCASTQ)]
fn vbroadcastsd(dst: Op, src: Op) {
    dst = vec_repeat(trunc(src, 64), width(dst) / 64);
}

#[iclass(VBROADCASTF128, VBROADCASTI128)]
fn vbroadcastf128(dst: Op, src: Op) {
    dst = concat(src, src);
}

// VEXTRACTF128/I128 and VINSERTF128/I128: the 128-bit half `imm[0]`.
#[iclass(VEXTRACTF128, VEXTRACTI128)]
fn vextractf128(dst: Op, src: Op, imm: Op) {
    dst = if bit(imm, 0) {
        bits(src, 128, 128)
    } else {
        bits(src, 0, 128)
    };
}

#[iclass(VINSERTF128, VINSERTI128)]
fn vinsertf128(dst: Op, a: Op, b: Op, imm: Op) {
    dst = if bit(imm, 0) {
        concat(b, bits(a, 0, 128))
    } else {
        concat(bits(a, 128, 128), b)
    };
}

// VPERM2F128/I128: each 128-bit half of the result is the half of `a`
// (0, 1) or `b` (2, 3) that `imm` bits 0-1 (4-5) select, or 0 if bit 3
// (7) is set.
#[iclass(VPERM2F128, VPERM2I128)]
fn vperm2f128(dst: Op, a: Op, b: Op, imm: Op) {
    let all = concat(b, a);
    let low = if bit(imm, 3) {
        zext(0, 128)
    } else {
        vec_pick(all, bits(imm, 0, 2), 128)
    };
    let high = if bit(imm, 7) {
        zext(0, 128)
    } else {
        vec_pick(all, bits(imm, 4, 2), 128)
    };
    dst = concat(high, low);
}

// VPERMD/VPERMPS: dword `i` is the dword of `src` that the low 3 bits of
// `index`'s dword `i` select.
#[iclass(VPERMD, VPERMPS)]
fn vpermd(dst: Op, index: Op, src: Op) {
    let r = zext(0, 256);
    for i in 0..8 {
        r = r | (zext(vec_pick(src, bits(index, i * 32, 3), 32), 256) << (i * 32));
    }
    dst = r;
}

// VPERMQ/VPERMPD: quadword `i` is the quadword `imm` bits 2i..2i+2 select.
#[iclass(VPERMQ, VPERMPD)]
fn vpermq(dst: Op, src: Op, imm: Op) {
    let r = zext(0, 256);
    for i in 0..4 {
        r = r | (zext(vec_pick(src, bits(imm, i * 2, 2), 64), 256) << (i * 64));
    }
    dst = r;
}

// VPERMILPS, per 128-bit half: dword `i` is the dword the low 2 bits of
// the control's dword `i` select (the immediate form: `imm` bits
// 2(i mod 4)..).
#[iclass(VPERMILPS)]
fn vpermilps(dst: Op, a: Op, control: Op) {
    let r = zext(0, width(a));
    for i in 0..width(a) / 32 {
        let e = vec_pick(bits(a, (i / 4) * 128, 128), bits(control, i * 32, 2), 32);
        r = r | (zext(e, width(a)) << (i * 32));
    }
    dst = r;
}

#[iform(
    VPERMILPS_XMMdq_MEMdq_IMMb,
    VPERMILPS_XMMdq_XMMdq_IMMb,
    VPERMILPS_YMMqq_MEMqq_IMMb,
    VPERMILPS_YMMqq_YMMqq_IMMb
)]
fn vpermilps_imm(dst: Op, src: Op, imm: Op) {
    let r = zext(0, width(src));
    for i in 0..width(src) / 32 {
        let e = vec_pick(bits(src, (i / 4) * 128, 128), bits(imm, (i & 3) * 2, 2), 32);
        r = r | (zext(e, width(src)) << (i * 32));
    }
    dst = r;
}

// VPERMILPD, per 128-bit half: quadword `i` is the quadword bit 1 of the
// control's quadword `i` selects (the immediate form: `imm` bit `i`).
#[iclass(VPERMILPD)]
fn vpermilpd(dst: Op, a: Op, control: Op) {
    let r = zext(0, width(a));
    for i in 0..width(a) / 64 {
        let e = vec_pick(bits(a, (i / 2) * 128, 128), bit(control, i * 64 + 1), 64);
        r = r | (zext(e, width(a)) << (i * 64));
    }
    dst = r;
}

#[iform(
    VPERMILPD_XMMdq_MEMdq_IMMb,
    VPERMILPD_XMMdq_XMMdq_IMMb,
    VPERMILPD_YMMqq_MEMqq_IMMb,
    VPERMILPD_YMMqq_YMMqq_IMMb
)]
fn vpermilpd_imm(dst: Op, src: Op, imm: Op) {
    let r = zext(0, width(src));
    for i in 0..width(src) / 64 {
        let e = vec_pick(bits(src, (i / 2) * 128, 128), bit(imm, i), 64);
        r = r | (zext(e, width(src)) << (i * 64));
    }
    dst = r;
}

// VMASKMOVPS/PD, VPMASKMOVD/Q: only the elements whose mask element has
// its sign bit set are accessed (measured: an all-zero mask does not fault
// on a non-canonical, unmapped or read-only address); a load gives 0 in
// the others, a store leaves their memory alone.
#[iclass(VMASKMOVPS, VPMASKMOVD)]
fn vmaskmovps(dst: Op, mask: Op, m: Op) {
    let k = mask;
    let a = address(m);
    dst = zext(0, width(dst));
    for i in 0..width(dst) / 32 {
        if msb(bits(k, i * 32, 32)) {
            dst = dst | (zext(load(m, a + i * 4, 32), width(dst)) << (i * 32));
        }
    }
}

#[iclass(VMASKMOVPD, VPMASKMOVQ)]
fn vmaskmovpd(dst: Op, mask: Op, m: Op) {
    let k = mask;
    let a = address(m);
    dst = zext(0, width(dst));
    for i in 0..width(dst) / 64 {
        if msb(bits(k, i * 64, 64)) {
            dst = dst | (zext(load(m, a + i * 8, 64), width(dst)) << (i * 64));
        }
    }
}

#[iform(
    VMASKMOVPS_MEMdq_XMMdq_XMMdq,
    VMASKMOVPS_MEMqq_YMMqq_YMMqq,
    VPMASKMOVD_MEMdq_XMMdq_XMMdq,
    VPMASKMOVD_MEMqq_YMMqq_YMMqq
)]
fn vmaskmovps_store(m: Op, mask: Op, src: Op) {
    let k = mask;
    let v = src;
    let a = address(m);
    for i in 0..width(v) / 32 {
        if msb(bits(k, i * 32, 32)) {
            store(m, a + i * 4, bits(v, i * 32, 32));
        }
    }
}

#[iform(
    VMASKMOVPD_MEMdq_XMMdq_XMMdq,
    VMASKMOVPD_MEMqq_YMMqq_YMMqq,
    VPMASKMOVQ_MEMdq_XMMdq_XMMdq,
    VPMASKMOVQ_MEMqq_YMMqq_YMMqq
)]
fn vmaskmovpd_store(m: Op, mask: Op, src: Op) {
    let k = mask;
    let v = src;
    let a = address(m);
    for i in 0..width(v) / 64 {
        if msb(bits(k, i * 64, 64)) {
            store(m, a + i * 8, bits(v, i * 64, 64));
        }
    }
}

// Gathers (AVX2): element `i` (`w` bits, as many as the destination
// holds) is loaded from base + index element `i` × scale + displacement
// (the address size wraps it) if the sign bit of mask element `i` is set;
// elements are gathered in order, each written to the destination and its
// mask element cleared. When the instruction completes the mask is 0 and
// the destination is written at its operand's width (VEX: zero above it).
// #UD if any two of the destination, mask and index registers are the
// same.
//
// Measured (i9-14900F, E-cores), with non-canonical element addresses:
// - With an element gathered before the faulting one, the processor stops
//   there: the single-step trap arrives with rip on the gather (the
//   oracle's `ok`), the earlier elements gathered and their mask elements
//   cleared, and every other mask element over the vector length (VEX.L:
//   128 or 256 bits, also beyond the elements the instruction uses, as
//   VGATHERQPS's upper dwords) normalized to all ones or zeros by its sign
//   bit; the destination's bits up to the vector length are kept (zero
//   above). That is a `repeat()` here.
// - Faulting on its first element, it delivers the fault with the mask
//   already normalized (and the register zeroed above the vector length)
//   and the destination unchanged. L0's exceptions are
//   precise, so that takes two executions: the first normalizes the mask
//   and repeats; the second, with a normalized mask, faults.
// A page fault on a later element is precise in L0 (nothing done) where the
// processor keeps the elements before it, as above: the one gap (the test
// maps every page the interpreter touches, so it does not reach it).
fn vec_gather_norm(k: Op, w: Op) {
    lanes(width(k) / w, sext(msb(k), w))
}

#[iclass(VGATHERDPS, VGATHERDPD, VPGATHERDD, VPGATHERDQ)]
fn vgatherd(dst: Op, m: Op, mask: Op) {
    if same(dst, mask) == 1 || same(dst, m) == 1 || same(mask, m) == 1 {
        trap(UD);
    }
    let w = width(m);
    let vl = width(mask);
    let index = vsib_index(m);
    let k = vec_gather_norm(wide(mask, vl), w);
    let normalized = wide(mask, 512) == zext(k, 512);
    let done = zext(0, 1);
    let stop = zext(0, 1);
    for i in 0..width(dst) / w {
        let a = vsib_address(m, bits(index, i * 32, 32));
        let active = msb(bits(k, i * w, w));
        stop = stop | (active && vec_noncanonical(a) && (done || !normalized));
        let go = active && !stop;
        if go {
            dst = vec_insert(wide(dst, vl), i, w, load(m, a, w));
        }
        k = if go {
            vec_insert(k, i, w, zext(0, w))
        } else {
            k
        };
        done = done | go;
    }
    if stop {
        mask = k;
        repeat();
    } else {
        mask = zext(0, width(mask));
        dst = dst;
    }
}

#[iclass(VGATHERQPS, VGATHERQPD, VPGATHERQD, VPGATHERQQ)]
fn vgatherq(dst: Op, m: Op, mask: Op) {
    if same(dst, mask) == 1 || same(dst, m) == 1 || same(mask, m) == 1 {
        trap(UD);
    }
    let w = width(m);
    let vl = width(mask) * (64 / w);
    let index = vsib_index(m);
    let k = vec_gather_norm(wide(mask, vl), w);
    let normalized = wide(mask, 512) == zext(k, 512);
    let done = zext(0, 1);
    let stop = zext(0, 1);
    for i in 0..width(dst) / w {
        let a = vsib_address(m, bits(index, i * 64, 64));
        let active = msb(bits(k, i * w, w));
        stop = stop | (active && vec_noncanonical(a) && (done || !normalized));
        let go = active && !stop;
        if go {
            dst = vec_insert(wide(dst, vl), i, w, load(m, a, w));
        }
        k = if go {
            vec_insert(k, i, w, zext(0, w))
        } else {
            k
        };
        done = done | go;
    }
    if stop {
        mask = k;
        repeat();
    } else {
        mask = zext(0, width(mask));
        dst = dst;
    }
}

// VZEROUPPER: bits 128 and up of every vector register cleared; VZEROALL:
// the registers cleared.
#[iclass(VZEROUPPER)]
fn vzeroupper() {
    zmm0 = zext(trunc(zmm0, 128), 512);
    zmm1 = zext(trunc(zmm1, 128), 512);
    zmm2 = zext(trunc(zmm2, 128), 512);
    zmm3 = zext(trunc(zmm3, 128), 512);
    zmm4 = zext(trunc(zmm4, 128), 512);
    zmm5 = zext(trunc(zmm5, 128), 512);
    zmm6 = zext(trunc(zmm6, 128), 512);
    zmm7 = zext(trunc(zmm7, 128), 512);
    zmm8 = zext(trunc(zmm8, 128), 512);
    zmm9 = zext(trunc(zmm9, 128), 512);
    zmm10 = zext(trunc(zmm10, 128), 512);
    zmm11 = zext(trunc(zmm11, 128), 512);
    zmm12 = zext(trunc(zmm12, 128), 512);
    zmm13 = zext(trunc(zmm13, 128), 512);
    zmm14 = zext(trunc(zmm14, 128), 512);
    zmm15 = zext(trunc(zmm15, 128), 512);
}

#[iclass(VZEROALL)]
fn vzeroall() {
    zmm0 = 0;
    zmm1 = 0;
    zmm2 = 0;
    zmm3 = 0;
    zmm4 = 0;
    zmm5 = 0;
    zmm6 = 0;
    zmm7 = 0;
    zmm8 = 0;
    zmm9 = 0;
    zmm10 = 0;
    zmm11 = 0;
    zmm12 = 0;
    zmm13 = 0;
    zmm14 = 0;
    zmm15 = 0;
}
