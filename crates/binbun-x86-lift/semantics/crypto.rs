// AES (AES-NI and VAES), carry-less multiplication (PCLMULQDQ and
// VPCLMULQDQ), SHA-1 and SHA-256, and GFNI. A 128-bit AES state holds its
// bytes in column order: byte 4c + r is row r of column c. The 256-bit VEX
// forms of VAES, VPCLMULQDQ and GFNI work on each 128-bit lane (GFNI on
// each byte, with the matrix of its quadword) as the 128-bit form does.

// A 512-bit table from its quadwords, the highest first (byte 8j + k of the
// table is byte k of quadword j).
fn cr_quarter(q7: Op, q6: Op, q5: Op, q4: Op, q3: Op, q2: Op, q1: Op, q0: Op) {
    concat(
        concat(
            concat(zext(q7, 64), zext(q6, 64)),
            concat(zext(q5, 64), zext(q4, 64)),
        ),
        concat(
            concat(zext(q3, 64), zext(q2, 64)),
            concat(zext(q1, 64), zext(q0, 64)),
        ),
    )
}

// Entry `x` of the 256-byte table whose quarters (64 bytes each, the
// lowest first) are `t0` to `t3`.
fn cr_lookup(t0: Op, t1: Op, t2: Op, t3: Op, x: Op) {
    let low = if bit(x, 6) == 1 { t1 } else { t0 };
    let high = if bit(x, 6) == 1 { t3 } else { t2 };
    let quarter = if bit(x, 7) == 1 { high } else { low };
    trunc(quarter >> (zext(bits(x, 0, 6), 16) << 3), 8)
}

// The AES S-box (SubBytes) of the byte `x`.
fn cr_sbox(x: Op) {
    cr_lookup(
        cr_quarter(
            0x75b227ebe2801207,
            0x9a059618c323c704,
            0x1531d871f1e5a534,
            0xccf73f362693fdb7,
            0xc072a49cafa2d4ad,
            0xf04759fa7dc982ca,
            0x76abd7fe2b670130,
            0xc56f6bf27b777c63,
        ),
        cr_quarter(
            0xd2f3ff1021dab6bc,
            0xf5389d928f40a351,
            0xa89f3c507f02f945,
            0x85334d43fbaaefd0,
            0xcf584c4a39becb6a,
            0x5bb1fc20ed00d153,
            0x842fe329b3d63b52,
            0xa05a6e1b1a2c8309,
        ),
        cr_quarter(
            0x08ae7a65eaf4566c,
            0xa94ed58d6d37c8e7,
            0x79e4959162acd3c2,
            0x5c2406490a3a32e0,
            0xdb0b5ede14b8ee46,
            0x88902a22dc4f8160,
            0x73195d643d7ea7c4,
            0x1744975fec130ccd,
        ),
        cr_quarter(
            0x16bb54b00f2d9941,
            0x6842e6bf0d89a18c,
            0xdf2855cee9871e9b,
            0x948ed9691198f8e1,
            0x9e1dc186b9573561,
            0x0ef6034866b53e70,
            0x8a8bbd4b1f74dde8,
            0xc6b4a61c2e2578ba,
        ),
        x,
    )
}

// The inverse AES S-box (InvSubBytes) of the byte `x`.
fn cr_inv_sbox(x: Op) {
    cr_lookup(
        cr_quarter(
            0x25d18b6d49a25b76,
            0xb224d92866a12e08,
            0x4ec3fa420b954cee,
            0x3d23c2a632947b54,
            0xcbe9dec444438e34,
            0x87ff2f9b8239e37c,
            0xfbd7f3819ea340bf,
            0x38a53630d56a0952,
        ),
        cr_quarter(
            0x6b8a130103bdafc1,
            0x020f3fca8f1e2cd0,
            0x0645b3b80558e4f7,
            0x0ad3bc8c00abd890,
            0x849d8da75746155e,
            0xdab9edfd5048706c,
            0x92b6655dcc5ca4d4,
            0x1698688664f6f872,
        ),
        cr_quarter(
            0xf45acd78fec0db9a,
            0x2079d2c64b3e56fc,
            0x1bbe18aa0e62b76f,
            0x89c5291d711af147,
            0x6edf751ce837f9e2,
            0x8535ade72274ac96,
            0x73e6b4f0cecff297,
            0xeadc674f4111913a,
        ),
        cr_quarter(
            0x7d0c2155631469e1,
            0x26d677ba7e042b17,
            0x619953833cbbebc8,
            0xb0f52aae4d3be0a0,
            0xef9cc9939f7ae52d,
            0x0d4ab519a97f5160,
            0x5fec8027591012b1,
            0x31c7078833a8dd1f,
        ),
        x,
    )
}

// The multiplicative inverse of the byte `x` in GF(2^8) modulo
// x^8 + x^4 + x^3 + x + 1 (0x11B); the inverse of 0 is 0.
fn cr_gf_inverse(x: Op) {
    cr_lookup(
        cr_quarter(
            0x1959bb776f2035f2,
            0x426639f36c92452c,
            0xc2a2443015980ac1,
            0xc9a84d55f15a6e3a,
            0xb2ee40ffccfd3f58,
            0x5f602b994baab474,
            0xc7e5e1b0c0294fe8,
            0xd17b52cbf68d0100,
        ),
        cr_quarter(
            0x8281faa106d070b6,
            0x3cbab5108597b779,
            0x3b219333df9147f4,
            0x4336a649d3af5e16,
            0x1761ec51f0223e18,
            0xbf87244cca055ced,
            0x09e9255413ab64a7,
            0x69f5312d6737fe1d,
        ),
        cr_quarter(
            0x5786bcbd3d768ea5,
            0x71787511ef1fe00c,
            0x62d2e7ce4a12c826,
            0x4865b88fc32e7cfb,
            0x9a89dcf9889f142a,
            0x72848ad86d326ade,
            0xa4b902f7d9959e9b,
            0x56be7396807f7e83,
        ),
        cr_quarter(
            0x1c411acda07d9cdd,
            0x8c0346683438235b,
            0xb31e505de3d74e08,
            0xadcf0ec6ebd60db1,
            0x6b90f89dd5c48b94,
            0xeae2dbc563ae077a,
            0xe6acfc1b045327a9,
            0x0fe4d4daa32f280b,
        ),
        x,
    )
}

// `n` modulo 4, at lift time.
fn cr_mod4(n: Op) {
    n - n / 4 * 4
}

// ShiftRows then SubBytes, on each 128-bit lane of `s`: byte 4c + r of the
// result is the S-box of byte 4((c + r) mod 4) + r.
fn cr_shift_sub(s: Op) {
    let r = zext(0, width(s));
    for lane in 0..width(s) / 128 {
        for c in 0..4 {
            for row in 0..4 {
                let from = 128 * lane + 32 * cr_mod4(c + row) + 8 * row;
                let to = 128 * lane + 32 * c + 8 * row;
                r = r | (zext(cr_sbox(bits(s, from, 8)), width(s)) << to);
            }
        }
    }
    r
}

// InvShiftRows then InvSubBytes, on each 128-bit lane of `s`: byte 4c + r
// of the result is the inverse S-box of byte 4((c - r) mod 4) + r.
fn cr_inv_shift_sub(s: Op) {
    let r = zext(0, width(s));
    for lane in 0..width(s) / 128 {
        for c in 0..4 {
            for row in 0..4 {
                let from = 128 * lane + 32 * cr_mod4(c + 4 - row) + 8 * row;
                let to = 128 * lane + 32 * c + 8 * row;
                r = r | (zext(cr_inv_sbox(bits(s, from, 8)), width(s)) << to);
            }
        }
    }
    r
}

// Each byte of `v` times x (2) in GF(2^8) modulo 0x11B.
fn cr_xtime(v: Op) {
    lanes(width(v) / 8, (v << 1) ^ ((v >> 7) * 0x1b))
}

// Each 32-bit column of `v` rotated by `n` rows: row r of the result is
// row r + n mod 4 of `v`.
fn cr_rows(v: Op, n: Op) {
    lanes(width(v) / 32, ror(v, 8 * n))
}

// MixColumns on every column of `v`: row r becomes
// 2 a[r] + 3 a[r + 1] + a[r + 2] + a[r + 3].
fn cr_mix_columns(v: Op) {
    let next = cr_rows(v, 1);
    cr_xtime(v) ^ cr_xtime(next) ^ next ^ cr_rows(v, 2) ^ cr_rows(v, 3)
}

// InvMixColumns on every column of `v`: row r becomes
// 14 a[r] + 11 a[r + 1] + 13 a[r + 2] + 9 a[r + 3].
fn cr_inv_mix_columns(v: Op) {
    let m2 = cr_xtime(v);
    let m4 = cr_xtime(m2);
    let m8 = cr_xtime(m4);
    (m8 ^ m4 ^ m2) ^ cr_rows(m8 ^ m2 ^ v, 1) ^ cr_rows(m8 ^ m4 ^ v, 2) ^ cr_rows(m8 ^ v, 3)
}

#[iclass(AESENC)]
fn aesenc(dst: Op, key: Op) {
    dst = cr_mix_columns(cr_shift_sub(dst)) ^ key;
}

#[iclass(VAESENC)]
fn vaesenc(dst: Op, state: Op, key: Op) {
    dst = cr_mix_columns(cr_shift_sub(state)) ^ key;
}

#[iclass(AESENCLAST)]
fn aesenclast(dst: Op, key: Op) {
    dst = cr_shift_sub(dst) ^ key;
}

#[iclass(VAESENCLAST)]
fn vaesenclast(dst: Op, state: Op, key: Op) {
    dst = cr_shift_sub(state) ^ key;
}

#[iclass(AESDEC)]
fn aesdec(dst: Op, key: Op) {
    dst = cr_inv_mix_columns(cr_inv_shift_sub(dst)) ^ key;
}

#[iclass(VAESDEC)]
fn vaesdec(dst: Op, state: Op, key: Op) {
    dst = cr_inv_mix_columns(cr_inv_shift_sub(state)) ^ key;
}

#[iclass(AESDECLAST)]
fn aesdeclast(dst: Op, key: Op) {
    dst = cr_inv_shift_sub(dst) ^ key;
}

#[iclass(VAESDECLAST)]
fn vaesdeclast(dst: Op, state: Op, key: Op) {
    dst = cr_inv_shift_sub(state) ^ key;
}

#[iclass(AESIMC, VAESIMC)]
fn aesimc(dst: Op, src: Op) {
    dst = cr_inv_mix_columns(src);
}

// The S-box of each byte of the 32-bit `w` (SubWord).
fn cr_sub_word(w: Op) {
    concat(
        concat(cr_sbox(bits(w, 24, 8)), cr_sbox(bits(w, 16, 8))),
        concat(cr_sbox(bits(w, 8, 8)), cr_sbox(bits(w, 0, 8))),
    )
}

// AESKEYGENASSIST: SubWord of doublewords 1 and 3, and each also rotated
// right by a byte (RotWord) and xored with the round constant.
#[iclass(AESKEYGENASSIST, VAESKEYGENASSIST)]
fn aeskeygenassist(dst: Op, src: Op, rcon: Op) {
    let x1 = cr_sub_word(bits(src, 32, 32));
    let x3 = cr_sub_word(bits(src, 96, 32));
    let c = zext(rcon, 32);
    dst = concat(concat(ror(x3, 8) ^ c, x3), concat(ror(x1, 8) ^ c, x1));
}

// The 128-bit carry-less product of the 64-bit `a` and `b`.
fn cr_clmul(a: Op, b: Op) {
    let x = zext(a, 128);
    let r = zext(0, 128);
    for i in 0..64 {
        r = r ^ ((x << i) & sext(bit(b, i), 128));
    }
    r
}

// Quadword 1 of the 128-bit lane at `lane` of `v` if `high` is set, else
// quadword 0.
fn cr_quadword(v: Op, lane: Op, high: Op) {
    if high == 1 {
        bits(v, lane + 64, 64)
    } else {
        bits(v, lane, 64)
    }
}

// PCLMULQDQ: immediate bit 0 picks the first source's quadword, bit 4 the
// second's.
#[iclass(PCLMULQDQ)]
fn pclmulqdq(dst: Op, src: Op, imm: Op) {
    dst = cr_clmul(
        cr_quadword(dst, 0, bit(imm, 0)),
        cr_quadword(src, 0, bit(imm, 4)),
    );
}

#[iclass(VPCLMULQDQ)]
fn vpclmulqdq(dst: Op, a: Op, b: Op, imm: Op) {
    let x = a;
    let y = b;
    let first = bit(imm, 0);
    let second = bit(imm, 4);
    let r = zext(0, width(dst));
    for k in 0..width(dst) / 128 {
        let product = cr_clmul(
            cr_quadword(x, 128 * k, first),
            cr_quadword(y, 128 * k, second),
        );
        r = r | (zext(product, width(dst)) << (128 * k));
    }
    dst = r;
}

// SHA1RNDS4: four SHA-1 rounds on A, B, C, D (doublewords 3 to 0 of the
// destination) with the message words of the source (doubleword 3 first,
// the first already holding E), the round function and constant chosen by
// immediate bits 0 and 1. The first round adds no E.
#[iclass(SHA1RNDS4)]
fn sha1rnds4(dst: Op, src: Op, imm: Op) {
    let w = src;
    let func = bits(imm, 0, 2);
    let k = if func == 0 {
        zext(0x5a827999, 32)
    } else if func == 1 {
        zext(0x6ed9eba1, 32)
    } else if func == 2 {
        zext(0x8f1bbcdc, 32)
    } else {
        zext(0xca62c1d6, 32)
    };
    let a = bits(dst, 96, 32);
    let b = bits(dst, 64, 32);
    let c = bits(dst, 32, 32);
    let d = bits(dst, 0, 32);
    let e = zext(0, 32);
    for i in 0..4 {
        let choose = (b & c) ^ (!b & d);
        let parity = b ^ c ^ d;
        let majority = (b & c) ^ (b & d) ^ (c & d);
        let f = if func == 0 {
            choose
        } else if func == 2 {
            majority
        } else {
            parity
        };
        let t = f + rol(a, 5) + bits(w, 96 - 32 * i, 32) + e + k;
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    dst = concat(concat(a, b), concat(c, d));
}

// SHA1NEXTE: E (doubleword 3 of the destination) rotated left by 30, added
// to doubleword 3 of the source; the source's other doublewords kept.
#[iclass(SHA1NEXTE)]
fn sha1nexte(dst: Op, src: Op) {
    dst = concat(
        bits(src, 96, 32) + rol(bits(dst, 96, 32), 30),
        bits(src, 0, 96),
    );
}

// SHA1MSG1: W0 to W3 are doublewords 3 to 0 of the destination, W4 and W5
// doublewords 3 and 2 of the source; the result is W2 ^ W0, W3 ^ W1,
// W4 ^ W2, W5 ^ W3 (doubleword 3 first).
#[iclass(SHA1MSG1)]
fn sha1msg1(dst: Op, src: Op) {
    dst = dst ^ concat(bits(dst, 0, 64), bits(src, 64, 64));
}

// SHA1MSG2: W16 = (doubleword 3 of the destination ^ W13) rol 1, W17, W18
// likewise with W14, W15 (doublewords 2 to 0 of the source), and W19 =
// (doubleword 0 ^ W16) rol 1; the result is W16 to W19 (doubleword 3 first).
#[iclass(SHA1MSG2)]
fn sha1msg2(dst: Op, src: Op) {
    let w16 = rol(bits(dst, 96, 32) ^ bits(src, 64, 32), 1);
    let w17 = rol(bits(dst, 64, 32) ^ bits(src, 32, 32), 1);
    let w18 = rol(bits(dst, 32, 32) ^ bits(src, 0, 32), 1);
    let w19 = rol(bits(dst, 0, 32) ^ w16, 1);
    dst = concat(concat(w16, w17), concat(w18, w19));
}

// SHA256RNDS2: two SHA-256 rounds. A, B, E, F are doublewords 3 to 0 of
// the source, C, D, G, H those of the destination; the message words plus
// constants are doublewords 0 and 1 of xmm0. The result is A, B, E, F.
#[iclass(SHA256RNDS2)]
fn sha256rnds2(dst: Op, src: Op, wk: Op) {
    let words = wk;
    let a = bits(src, 96, 32);
    let b = bits(src, 64, 32);
    let c = bits(dst, 96, 32);
    let d = bits(dst, 64, 32);
    let e = bits(src, 32, 32);
    let f = bits(src, 0, 32);
    let g = bits(dst, 32, 32);
    let h = bits(dst, 0, 32);
    for i in 0..2 {
        let choose = (e & f) ^ (!e & g);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let sigma0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
        let sigma1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
        let t = choose + sigma1 + bits(words, 32 * i, 32) + h;
        h = g;
        g = f;
        f = e;
        e = t + d;
        d = c;
        c = b;
        b = a;
        a = t + majority + sigma0;
    }
    dst = concat(concat(a, b), concat(e, f));
}

// SHA-256's message schedule functions σ0 and σ1.
fn cr_small_sigma0(w: Op) {
    ror(w, 7) ^ ror(w, 18) ^ (w >> 3)
}

fn cr_small_sigma1(w: Op) {
    ror(w, 17) ^ ror(w, 19) ^ (w >> 10)
}

// SHA256MSG1: doubleword i of the destination plus σ0 of the next one
// (doubleword 0 of the source after doubleword 3).
#[iclass(SHA256MSG1)]
fn sha256msg1(dst: Op, src: Op) {
    let next = concat(bits(src, 0, 32), bits(dst, 32, 96));
    dst = lanes(4, dst + cr_small_sigma0(next));
}

// SHA256MSG2: W16 = doubleword 0 of the destination + σ1(W14), W17 =
// doubleword 1 + σ1(W15) (W14, W15: doublewords 2 and 3 of the source),
// W18 = doubleword 2 + σ1(W16), W19 = doubleword 3 + σ1(W17).
#[iclass(SHA256MSG2)]
fn sha256msg2(dst: Op, src: Op) {
    let w16 = bits(dst, 0, 32) + cr_small_sigma1(bits(src, 64, 32));
    let w17 = bits(dst, 32, 32) + cr_small_sigma1(bits(src, 96, 32));
    let w18 = bits(dst, 64, 32) + cr_small_sigma1(w16);
    let w19 = bits(dst, 96, 32) + cr_small_sigma1(w17);
    dst = concat(concat(w19, w18), concat(w17, w16));
}

// The product of each byte of `a` and `b` in GF(2^8) modulo 0x11B.
fn cr_gf_mul(a: Op, b: Op) {
    let t = a;
    let r = zext(0, width(a));
    for i in 0..8 {
        r = r ^ lanes(width(a) / 8, t * ((b >> i) & 1));
        t = cr_xtime(t);
    }
    r
}

#[iclass(GF2P8MULB)]
fn gf2p8mulb(dst: Op, src: Op) {
    dst = cr_gf_mul(dst, src);
}

#[iclass(VGF2P8MULB)]
fn vgf2p8mulb(dst: Op, a: Op, b: Op) {
    dst = cr_gf_mul(a, b);
}

// The affine transformation of each byte of `x` by the 8x8 bit matrix of
// its quadword of `m`, plus the byte `c`: bit i of a result byte is the
// parity of the byte and byte 7 - i of the matrix, xor bit i of `c`.
fn cr_affine(x: Op, m: Op, c: Op) {
    let n = width(x) / 8;
    let r = zext(0, width(x));
    for i in 0..8 {
        let row = lanes(
            width(m) / 64,
            ((m >> (56 - 8 * i)) & 0xff) * 0x0101010101010101,
        );
        let p = x & row;
        let p = lanes(n, p ^ (p >> 4));
        let p = lanes(n, p ^ (p >> 2));
        let p = lanes(n, p ^ (p >> 1));
        r = r | lanes(n, (p & 1) << i);
    }
    lanes(n, r ^ c)
}

// The GF(2^8) inverse of each byte of `x`.
fn cr_inverse_bytes(x: Op) {
    let r = zext(0, width(x));
    for i in 0..width(x) / 8 {
        r = r | (zext(cr_gf_inverse(bits(x, 8 * i, 8)), width(x)) << (8 * i));
    }
    r
}

#[iclass(GF2P8AFFINEQB)]
fn gf2p8affineqb(dst: Op, m: Op, c: Op) {
    dst = cr_affine(dst, m, c);
}

#[iclass(VGF2P8AFFINEQB)]
fn vgf2p8affineqb(dst: Op, x: Op, m: Op, c: Op) {
    dst = cr_affine(x, m, c);
}

#[iclass(GF2P8AFFINEINVQB)]
fn gf2p8affineinvqb(dst: Op, m: Op, c: Op) {
    dst = cr_affine(cr_inverse_bytes(dst), m, c);
}

#[iclass(VGF2P8AFFINEINVQB)]
fn vgf2p8affineinvqb(dst: Op, x: Op, m: Op, c: Op) {
    dst = cr_affine(cr_inverse_bytes(x), m, c);
}
