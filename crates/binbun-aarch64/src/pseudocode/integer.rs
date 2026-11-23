//! Helpers of the integer groups: bitmask immediates and the preferences of
//! `MOV` (bitmask) and `UBFX`/`SBFX`. `s` and `r` stand for `imms` and
//! `immr`.

/// `DecodeBitMasks(immN, imms, immr, TRUE, datasize)`: the bitmask
/// immediate of a logical-immediate instruction, `datasize` being 64 when
/// `sf` is 1, else 32. Reserved combinations are UNDEFINED and never reach
/// here; they give 0.
pub const fn decode_bit_masks(n: u32, s: u32, r: u32, sf: u32) -> u64 {
    let combined = (n << 6) | (!s & 0x3f);
    if combined < 2 {
        return 0;
    }
    let size = 1u32 << combined.ilog2();
    let levels = size - 1;
    let ones = s & levels;
    let rotation = r & levels;
    if ones == levels {
        return 0;
    }
    // ones + 1 set bits, rotated right by `rotation` within the element.
    let run = (1u64 << (ones + 1)) - 1;
    let element_mask = if size == 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    };
    let mut value = if rotation == 0 {
        run
    } else {
        ((run >> rotation) | (run << (size - rotation))) & element_mask
    };
    let mut width = size;
    while width < 64 {
        value |= value << width;
        width *= 2;
    }
    if sf == 1 { value } else { value & 0xffff_ffff }
}

/// `MoveWidePreferred(sf, immN, imms, immr)`: whether a bitmask immediate
/// is better written as `MOVZ` or `MOVN`, so `ORR` is not written as `MOV`.
/// That is the case when the value, or its inverse, is one halfword at a
/// halfword boundary of the register.
pub const fn move_wide_preferred(sf: u32, n: u32, s: u32, r: u32) -> bool {
    let value = decode_bit_masks(n, s, r, sf);
    let mask = if sf == 1 { u64::MAX } else { 0xffff_ffff };
    one_halfword(value, mask) || one_halfword(!value & mask, mask)
}

/// Whether `value` has bits set in at most one halfword of `mask`.
const fn one_halfword(value: u64, mask: u64) -> bool {
    let mut shift = 0;
    while shift < 64 {
        if value & !(0xffff << shift) & mask == 0 {
            return true;
        }
        shift += 16;
    }
    false
}

/// `BFXPreferred(sf, uns, imms, immr)`: whether `SBFM`/`UBFM` is better
/// written as `SBFX`/`UBFX` than as another alias.
pub const fn bfx_preferred(sf: u32, unsigned: u32, s: u32, r: u32) -> bool {
    // Not UBFIZ/SBFIZ.
    if s < r {
        return false;
    }
    // Not LSR/ASR.
    if s == (sf << 5) | 0b1_1111 {
        return false;
    }
    if r == 0 {
        // Not 32-bit UXT[BH] or SXT[BH].
        if sf == 0 && (s == 0b00_0111 || s == 0b00_1111) {
            return false;
        }
        // Not 64-bit SXT[BHW].
        if sf == 1 && unsigned == 0 && (s == 0b00_0111 || s == 0b00_1111 || s == 0b01_1111) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{bfx_preferred, decode_bit_masks, move_wide_preferred};

    #[test]
    fn bit_masks_repeat_rotated_runs() {
        // and x0, x0, #0xff: N=1, immr=0, imms=7.
        assert_eq!(decode_bit_masks(1, 7, 0, 1), 0xff);
        // #0x5555555555555555: 2-bit elements with one one.
        assert_eq!(decode_bit_masks(0, 0b11_1100, 0, 1), 0x5555_5555_5555_5555);
        // #0x80000001 (32 bits): two ones rotated right by one.
        assert_eq!(decode_bit_masks(0, 1, 1, 0), 0x8000_0001);
        // #0xfffc001f (32 bits): 19 ones rotated right by 14.
        assert_eq!(decode_bit_masks(0, 18, 14, 0), 0xfffc_001f);
    }

    #[test]
    fn move_wide_and_bitfield_preferences() {
        // orr w0, wzr, #0xf is not mov: MOVZ can write it.
        assert!(move_wide_preferred(0, 0, 3, 0));
        // #0x5555… cannot be written by MOVZ/MOVN.
        assert!(!move_wide_preferred(1, 0, 0b11_1100, 0));
        // #0xffffffffff80ffff is movn #0x7f, lsl #16.
        assert!(move_wide_preferred(1, 1, 56, 41));
        // ubfm x0, x1, #1, #3 is ubfx; with imms == 63 it is lsr.
        assert!(bfx_preferred(1, 1, 3, 1));
        assert!(!bfx_preferred(1, 1, 63, 1));
        // sbfm x0, x1, #0, #31 is sxtw.
        assert!(!bfx_preferred(1, 0, 31, 0));
    }
}
