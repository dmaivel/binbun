//! Helpers of the scalar floating-point and Advanced SIMD groups: the
//! expansion of 8-bit immediates.

/// `VFPExpandImm(imm8, N)`: the floating-point value of an 8-bit `FMOV`
/// immediate, `(-1)^a × (1 + efgh / 16) × 2^n` with `n` from `bcd`
/// (`0b111` is 0, `0b000` is 1, `0b100` is -3), the same in every width.
pub const fn vfp_expand_imm(imm8: u32) -> f64 {
    // (16 + efgh) / 16 × 2^n, with n + 3 = bcd XOR 0b100, in units of 1/128.
    let units = (16 + (imm8 & 0xf)) << (((imm8 >> 4) & 7) ^ 4);
    let magnitude = units as f64 / 128.0;
    if imm8 & 0x80 == 0 {
        magnitude
    } else {
        -magnitude
    }
}

/// `AdvSIMDExpandImm(op, cmode, imm8)`: the 64-bit value of an Advanced
/// SIMD modified immediate.
pub const fn adv_simd_expand_imm(op: u32, cmode: u32, imm8: u32) -> u64 {
    let imm8 = (imm8 & 0xff) as u64;
    match (cmode >> 1) & 7 {
        0 => words(imm8),
        1 => words(imm8 << 8),
        2 => words(imm8 << 16),
        3 => words(imm8 << 24),
        4 => halfwords(imm8),
        5 => halfwords(imm8 << 8),
        6 if cmode & 1 == 0 => words((imm8 << 8) | 0xff),
        6 => words((imm8 << 16) | 0xffff),
        _ => match (cmode & 1, op & 1) {
            (0, 0) => imm8 * 0x0101_0101_0101_0101,
            (0, _) => byte_mask(imm8),
            (_, 0) => {
                let b = (imm8 >> 6) & 1;
                words(
                    ((imm8 >> 7) << 31)
                        | ((b ^ 1) << 30)
                        | ((b * 0x1f) << 25)
                        | ((imm8 & 0x3f) << 19),
                )
            }
            _ => {
                let b = (imm8 >> 6) & 1;
                ((imm8 >> 7) << 63) | ((b ^ 1) << 62) | ((b * 0xff) << 54) | ((imm8 & 0x3f) << 48)
            }
        },
    }
}

/// `Replicate(word, 2)` of a 32-bit value.
const fn words(word: u64) -> u64 {
    let word = word & 0xffff_ffff;
    word | (word << 32)
}

/// `Replicate(half, 4)` of a 16-bit value.
const fn halfwords(half: u64) -> u64 {
    (half & 0xffff) * 0x0001_0001_0001_0001
}

/// Each bit of `imm8` selecting a byte of ones (`MOVI` 64-bit masks).
const fn byte_mask(imm8: u64) -> u64 {
    let mut value = 0;
    let mut bit = 0;
    while bit < 8 {
        if (imm8 >> bit) & 1 == 1 {
            value |= 0xff << (8 * bit);
        }
        bit += 1;
    }
    value
}
