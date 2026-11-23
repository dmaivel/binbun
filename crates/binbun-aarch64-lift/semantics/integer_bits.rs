// Bitfield moves, extract, the one-source operations (bit and byte
// reversal, counts, ABS of FEAT_CSSC), variable shifts, and CRC32.

// `k` ones (all 64 from 64 on), at lift time.
fn int_ones(k: Op) {
    if k >= 64 {
        0xffff_ffff_ffff_ffff
    } else {
        (1 << k) - 1
    }
}

// DecodeBitMasks(N, imms, immr, FALSE, datasize) for the bitfield moves,
// at lift time (the element is the whole register: `N` is `sf`): `wmask`
// is S + 1 ones rotated right by R, `tmask` is (S - R) mod datasize + 1
// ones.
fn int_wmask(w: Op, r: Op, s: Op) {
    let ones = int_ones(s + 1);
    ((ones >> r) | (ones << (w - r))) & int_ones(w)
}

fn int_tmask(w: Op, r: Op, s: Op) {
    int_ones(((s - r) & (w - 1)) + 1)
}

// UBFM, and LSL, LSR, UBFIZ, UBFX, UXTB, UXTH (immediate): ROR(n, R)
// AND wmask AND tmask.
#[operation(UBFM)]
fn ubfm(d: Op, n: Op, immr: Op, imms: Op) {
    let w = width(d);
    d = ror(n, immr) & (int_wmask(w, immr, imms) & int_tmask(w, immr, imms));
}

// SBFM, and ASR, SBFIZ, SBFX, SXTB, SXTH, SXTW (immediate): the bits of
// UBFM, and copies of bit S of n where tmask is clear.
#[operation(SBFM)]
fn sbfm(d: Op, n: Op, immr: Op, imms: Op) {
    let w = width(d);
    let tmask = int_tmask(w, immr, imms);
    let bot = ror(n, immr) & int_wmask(w, immr, imms);
    let top = sext(bit(n, imms), w);
    d = (top & (tmask ^ int_ones(w))) | (bot & tmask);
}

// BFM, and BFC, BFI, BFXIL: ROR(n, R) where wmask is set, d elsewhere;
// then that where tmask is set, d elsewhere.
#[operation(BFM)]
fn bfm(d: Op, n: Op, immr: Op, imms: Op) {
    let w = width(d);
    let wmask = int_wmask(w, immr, imms);
    let tmask = int_tmask(w, immr, imms);
    let bot = (d & (wmask ^ int_ones(w))) | (ror(n, immr) & wmask);
    d = (d & (tmask ^ int_ones(w))) | (bot & tmask);
}

// EXTR, and ROR (immediate): bits lsb + datasize - 1..lsb of n:m.
#[operation(EXTR)]
fn extr(d: Op, n: Op, m: Op, lsb: Op) {
    d = bits(concat(n, m), lsb, width(d));
}

// RBIT: the bits in reverse order (the bytes reversed, then the bits of
// each byte).
#[operation(RBIT_int)]
fn rbit(d: Op, n: Op) {
    let r = bswap(n);
    r = ((r >> 1) & 0x5555_5555_5555_5555) | ((r & 0x5555_5555_5555_5555) << 1);
    r = ((r >> 2) & 0x3333_3333_3333_3333) | ((r & 0x3333_3333_3333_3333) << 2);
    d = ((r >> 4) & 0x0f0f_0f0f_0f0f_0f0f) | ((r & 0x0f0f_0f0f_0f0f_0f0f) << 4);
}

// REV16: the bytes of each halfword swapped.
#[operation(REV16_int)]
fn rev16(d: Op, n: Op) {
    d = ((n >> 8) & 0x00ff_00ff_00ff_00ff) | ((n & 0x00ff_00ff_00ff_00ff) << 8);
}

// REV32: the bytes of each word reversed.
#[operation(REV32_int)]
fn rev32(d: Op, n: Op) {
    d = ror(bswap(n), 32);
}

// REV, and REV64: the bytes of the register reversed.
#[operation(REV)]
fn rev(d: Op, n: Op) {
    d = bswap(n);
}

// CLZ: CountLeadingZeroBits (the width for 0).
#[operation(CLZ_int)]
fn clz_int(d: Op, n: Op) {
    d = clz(n);
}

// CLS: CountLeadingZeroBits(n<datasize-1:1> EOR n<datasize-2:0>), the
// sign bits after the first.
#[operation(CLS_int)]
fn cls_int(d: Op, n: Op) {
    let w = width(n);
    d = zext(clz(bits(n, 1, w - 1) ^ bits(n, 0, w - 1)), w);
}

// CTZ (FEAT_CSSC): CountTrailingZeroBits (the width for 0).
#[operation(CTZ)]
fn ctz_int(d: Op, n: Op) {
    d = ctz(n);
}

// CNT (FEAT_CSSC): the number of ones.
#[operation(CNT)]
fn cnt(d: Op, n: Op) {
    d = popcount(n);
}

// ABS (FEAT_CSSC): -n where n is negative (the most negative value stays).
#[operation(ABS)]
fn abs(d: Op, n: Op) {
    d = if slt(n, 0) { -n } else { n };
}

// LSLV, and LSL (register): the shift is m modulo datasize.
#[operation(LSLV)]
fn lslv(d: Op, n: Op, m: Op) {
    d = n << (m & (width(n) - 1));
}

// LSRV, and LSR (register).
#[operation(LSRV)]
fn lsrv(d: Op, n: Op, m: Op) {
    d = n >> (m & (width(n) - 1));
}

// ASRV, and ASR (register).
#[operation(ASRV)]
fn asrv(d: Op, n: Op, m: Op) {
    d = sar(n, m & (width(n) - 1));
}

// RORV, and ROR (register).
#[operation(RORV)]
fn rorv(d: Op, n: Op, m: Op) {
    d = ror(n, m & (width(n) - 1));
}

// The CRC of the low 8 << `sz` bits of `value` from `acc` with the
// bit-reflected polynomial `poly`, one bit at a time: Arm's
// BitReverse(Poly32Mod2(BitReverse(acc):Zeros(size) EOR
// BitReverse(value):Zeros(32), poly)), with no inversion.
fn int_crc(acc: Op, value: Op, poly: Op) {
    let crc = acc;
    for i in 0..(8 << field(10, 2)) {
        crc = (crc >> 1) ^ (sext(bit(crc, 0) ^ bit(value, i), 32) & poly);
    }
    crc
}

// CRC32B, CRC32H, CRC32W, CRC32X: the polynomial 0x04C11DB7.
#[operation(CRC32)]
fn crc32(d: Op, n: Op, m: Op) {
    d = int_crc(n, m, 0xedb8_8320);
}

// CRC32CB, CRC32CH, CRC32CW, CRC32CX: the polynomial 0x1EDC6F41.
#[operation(CRC32C)]
fn crc32c(d: Op, n: Op, m: Op) {
    d = int_crc(n, m, 0x82f6_3b78);
}
