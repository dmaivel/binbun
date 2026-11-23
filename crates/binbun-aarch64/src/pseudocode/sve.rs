//! Helpers of the SVE groups: the preference of `MOV` (bitmask immediate)
//! over `DUPM`.

use super::decode_bit_masks;

/// `SVEMoveMaskPreferred(imm13)`: whether `DUPM` with the bitmask
/// immediate `imm13` is better written as `MOV`; not when `DUP` (a signed
/// byte, optionally shifted left by 8, at some element size) can write the
/// value.
pub const fn sve_move_mask_preferred(imm13: u32) -> bool {
    let imm = decode_bit_masks(imm13 >> 12, imm13 & 0x3f, (imm13 >> 6) & 0x3f, 1);
    let words_equal = imm >> 32 == imm & 0xffff_ffff;
    let halves_equal = words_equal && (imm >> 16) & 0xffff == imm & 0xffff;
    if imm & 0xff != 0 {
        // 8-bit immediates: sign-extended from bit 7 at 64, 32 or 16 bits,
        // or a byte repeated.
        if sign_extended(imm, 7, 64)
            || (words_equal && sign_extended(imm, 7, 32))
            || (halves_equal && sign_extended(imm, 7, 16))
            || (halves_equal && (imm >> 8) & 0xff == imm & 0xff)
        {
            return false;
        }
    } else if sign_extended(imm, 15, 64)
        || (words_equal && sign_extended(imm, 15, 32))
        || halves_equal
    {
        // 16-bit immediates (a byte shifted left by 8): sign-extended from
        // bit 15 at 64 or 32 bits, or a halfword repeated.
        return false;
    }
    true
}

/// Whether bits `bit` to `width - 1` of `value` are all zeros or all ones.
const fn sign_extended(value: u64, bit: u32, width: u32) -> bool {
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let high = (value & mask) >> bit;
    high == 0 || high == mask >> bit
}

#[cfg(test)]
mod tests {
    use super::sve_move_mask_preferred;

    #[test]
    fn move_mask_preference() {
        // 0x000000ff000000ff (05c000e0): no DUP writes it, so LLVM writes
        // `mov z0.s, #0xff`.
        assert!(sve_move_mask_preferred(0x0007));
        // 0x100 (05c3c000) is `dup z0.d, #1, lsl #8`: LLVM keeps
        // `dupm z0.d, #0x100`.
        assert!(!sve_move_mask_preferred(0x1e00));
        // 0xffffffffffffff80 is a sign-extended byte.
        assert!(!sve_move_mask_preferred(0x1e78));
    }
}
