//! Fixed-width bit vectors of 1 to [`MAX_WIDTH`] bits.

use core::cmp::Ordering;
use core::fmt;

use alloc::vec::Vec;

/// The widest value L0 handles (a ZMM register).
pub const MAX_WIDTH: u16 = 512;

const WORDS: usize = MAX_WIDTH as usize / 64;

/// A bit vector: a width and that many bits, little-endian in 64-bit
/// words. Bits above the width are always 0.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bits {
    width: u16,
    words: [u64; WORDS],
}

impl Bits {
    /// All zeros, `width` bits wide (clamped to 1..=[`MAX_WIDTH`]).
    pub const fn zero(width: u16) -> Self {
        Self {
            width: clamp(width),
            words: [0; WORDS],
        }
    }

    /// `value` truncated to `width` bits.
    pub fn from_u64(width: u16, value: u64) -> Self {
        let mut bits = Self::zero(width);
        bits.words[0] = value;
        bits.normalize()
    }

    /// `value` truncated to `width` bits.
    pub fn from_u128(width: u16, value: u128) -> Self {
        let mut bits = Self::zero(width);
        #[expect(clippy::cast_possible_truncation, reason = "splitting into words")]
        {
            bits.words[0] = value as u64;
            bits.words[1] = (value >> 64) as u64;
        }
        bits.normalize()
    }

    /// The first `width` bits of the little-endian `bytes` (missing bytes
    /// are 0).
    pub fn from_le_bytes(width: u16, bytes: &[u8]) -> Self {
        let mut bits = Self::zero(width);
        for (index, &byte) in bytes.iter().enumerate().take(WORDS * 8) {
            if let Some(word) = bits.words.get_mut(index / 8) {
                *word |= u64::from(byte) << ((index % 8) * 8);
            }
        }
        bits.normalize()
    }

    /// All ones, `width` bits wide.
    pub fn ones(width: u16) -> Self {
        Self::zero(width).invert()
    }

    /// The width in bits.
    pub const fn width(&self) -> u16 {
        self.width
    }

    /// The low 64 bits.
    pub const fn low_u64(&self) -> u64 {
        self.words[0]
    }

    /// The low 128 bits.
    pub fn low_u128(&self) -> u128 {
        u128::from(self.words[0]) | (u128::from(self.words[1]) << 64)
    }

    /// The value as little-endian bytes, `width` rounded up to whole bytes.
    pub fn to_le_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        let count = usize::from(self.width).div_ceil(8);
        (0..count).map(|index| {
            let word = self.words.get(index / 8).copied().unwrap_or(0);
            #[expect(clippy::cast_possible_truncation, reason = "one byte")]
            let byte = (word >> ((index % 8) * 8)) as u8;
            byte
        })
    }

    /// Whether every bit is 0.
    pub fn is_zero(&self) -> bool {
        self.words.iter().all(|&word| word == 0)
    }

    /// Bit `index` (0 is the least significant); false past the width.
    pub fn bit(&self, index: u16) -> bool {
        index < self.width
            && self
                .words
                .get(usize::from(index / 64))
                .is_some_and(|word| (word >> (index % 64)) & 1 == 1)
    }

    /// The most significant bit.
    pub fn msb(&self) -> bool {
        self.bit(self.width - 1)
    }

    /// A 1-bit value.
    pub fn from_bool(value: bool) -> Self {
        Self::from_u64(1, u64::from(value))
    }

    /// Clears the bits above the width.
    fn normalize(mut self) -> Self {
        let width = usize::from(self.width);
        for (index, word) in self.words.iter_mut().enumerate() {
            let low = index * 64;
            if low >= width {
                *word = 0;
            } else if width - low < 64 {
                *word &= (1u64 << (width - low)) - 1;
            }
        }
        self
    }

    fn map(self, other: &Self, f: impl Fn(u64, u64) -> u64) -> Self {
        let mut out = self;
        for (word, &other) in out.words.iter_mut().zip(&other.words) {
            *word = f(*word, other);
        }
        out.normalize()
    }

    /// Bitwise not.
    #[must_use]
    pub fn invert(self) -> Self {
        let mut out = self;
        for word in &mut out.words {
            *word = !*word;
        }
        out.normalize()
    }

    /// Bitwise and.
    #[must_use]
    pub fn and(self, other: &Self) -> Self {
        self.map(other, |a, b| a & b)
    }

    /// Bitwise or.
    #[must_use]
    pub fn or(self, other: &Self) -> Self {
        self.map(other, |a, b| a | b)
    }

    /// Bitwise exclusive or.
    #[must_use]
    pub fn xor(self, other: &Self) -> Self {
        self.map(other, |a, b| a ^ b)
    }

    /// Sum modulo 2^width, and the carry out of the top bit.
    pub fn add_carry(self, other: &Self, carry_in: bool) -> (Self, bool) {
        let mut out = self;
        let mut carry = u64::from(carry_in);
        for (word, &other) in out.words.iter_mut().zip(&other.words) {
            let (sum, first) = word.overflowing_add(other);
            let (sum, second) = sum.overflowing_add(carry);
            *word = sum;
            carry = u64::from(first || second);
        }
        // The carry out of the width: bit `width` of the full sum.
        let unmasked = out;
        let carry_out = if usize::from(self.width) == WORDS * 64 {
            carry == 1
        } else {
            let width = self.width;
            unmasked
                .words
                .get(usize::from(width / 64))
                .is_some_and(|word| (word >> (width % 64)) & 1 == 1)
        };
        (out.normalize(), carry_out)
    }

    /// Sum modulo 2^width.
    #[must_use]
    pub fn wrapping_add(self, other: &Self) -> Self {
        self.add_carry(other, false).0
    }

    /// Two's complement negation.
    #[must_use]
    pub fn wrapping_neg(self) -> Self {
        self.invert().wrapping_add(&Self::from_u64(self.width, 1))
    }

    /// Difference modulo 2^width.
    #[must_use]
    pub fn wrapping_sub(self, other: &Self) -> Self {
        self.wrapping_add(&other.wrapping_neg())
    }

    /// Unsigned comparison.
    pub fn ucmp(&self, other: &Self) -> Ordering {
        self.words.iter().rev().cmp(other.words.iter().rev())
    }

    /// Signed (two's complement) comparison.
    pub fn scmp(&self, other: &Self) -> Ordering {
        match (self.msb(), other.msb()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.ucmp(other),
        }
    }

    /// Shift left by `count` bits (0 when `count` is at least the width).
    #[must_use]
    pub fn shift_left(self, count: u32) -> Self {
        let mut out = Self::zero(self.width);
        if count >= u32::from(self.width) {
            return out;
        }
        let (words, bits) = ((count / 64) as usize, count % 64);
        for index in (words..WORDS).rev() {
            let low = self.words.get(index - words).copied().unwrap_or(0);
            let lower = if bits == 0 || index == words {
                0
            } else {
                self.words.get(index - words - 1).copied().unwrap_or(0) >> (64 - bits)
            };
            if let Some(word) = out.words.get_mut(index) {
                *word = (low << bits) | lower;
            }
        }
        out.normalize()
    }

    /// Logical shift right by `count` bits (0 when `count` is at least the
    /// width).
    #[must_use]
    pub fn shift_right(self, count: u32) -> Self {
        let mut out = Self::zero(self.width);
        if count >= u32::from(self.width) {
            return out;
        }
        let (words, bits) = ((count / 64) as usize, count % 64);
        for index in 0..WORDS - words {
            let high = self.words.get(index + words).copied().unwrap_or(0);
            let higher = if bits == 0 {
                0
            } else {
                self.words.get(index + words + 1).copied().unwrap_or(0) << (64 - bits)
            };
            if let Some(word) = out.words.get_mut(index) {
                *word = (high >> bits) | higher;
            }
        }
        out.normalize()
    }

    /// Arithmetic shift right by `count` bits (all sign bits when `count`
    /// is at least the width).
    #[must_use]
    pub fn shift_right_signed(self, count: u32) -> Self {
        let width = u32::from(self.width);
        if !self.msb() {
            return self.shift_right(count);
        }
        if count >= width {
            return Self::ones(self.width);
        }
        let fill = Self::ones(self.width).shift_left(width - count);
        self.shift_right(count).or(&fill)
    }

    /// The `width` bits starting at bit `offset` (bits past the value are 0).
    #[must_use]
    pub fn extract(self, offset: u16, width: u16) -> Self {
        let mut out = self.shift_right(u32::from(offset));
        out.width = clamp(width);
        out.normalize()
    }

    /// `self` as the high part and `low` as the low part; the width is the
    /// sum (clamped to [`MAX_WIDTH`]).
    #[must_use]
    pub fn concat(self, low: &Self) -> Self {
        let width = clamp(self.width + low.width);
        let mut high = self;
        high.width = width;
        let mut low_wide = *low;
        low_wide.width = width;
        high.shift_left(u32::from(low.width)).or(&low_wide)
    }

    /// Zero-extended (or truncated) to `width` bits.
    #[must_use]
    pub fn zext(self, width: u16) -> Self {
        let mut out = self;
        out.width = clamp(width);
        out.normalize()
    }

    /// Sign-extended (or truncated) to `width` bits.
    #[must_use]
    pub fn sext(self, width: u16) -> Self {
        let width = clamp(width);
        if width <= self.width || !self.msb() {
            return self.zext(width);
        }
        let fill = Self::ones(width).shift_left(u32::from(self.width));
        self.zext(width).or(&fill)
    }

    /// Number of 1 bits.
    pub fn popcount(&self) -> u32 {
        self.words.iter().map(|word| word.count_ones()).sum()
    }

    /// Number of 0 bits above the highest 1 bit (the width for 0).
    pub fn leading_zeros(&self) -> u32 {
        let width = u32::from(self.width);
        (0..self.width)
            .rev()
            .find(|&index| self.bit(index))
            .map_or(width, |index| width - 1 - u32::from(index))
    }

    /// Number of 0 bits below the lowest 1 bit (the width for 0).
    pub fn trailing_zeros(&self) -> u32 {
        (0..self.width)
            .find(|&index| self.bit(index))
            .map_or(u32::from(self.width), u32::from)
    }

    /// The bytes in reverse order (the width must be a multiple of 8).
    #[must_use]
    pub fn byte_swap(self) -> Self {
        let bytes: Vec<u8> = self.to_le_bytes().collect();
        let reversed: Vec<u8> = bytes.into_iter().rev().collect();
        Self::from_le_bytes(self.width, &reversed)
    }

    /// The value as an unsigned shift or rotate count: saturated to
    /// `u32::MAX`.
    pub fn as_count(&self) -> u32 {
        if self.words.iter().skip(1).any(|&word| word != 0) {
            return u32::MAX;
        }
        u32::try_from(self.words[0]).unwrap_or(u32::MAX)
    }
}

/// Width clamped to 1..=[`MAX_WIDTH`].
const fn clamp(width: u16) -> u16 {
    if width == 0 {
        1
    } else if width > MAX_WIDTH {
        MAX_WIDTH
    } else {
        width
    }
}

impl fmt::Debug for Bits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:#x}", self.width, HexValue(self))
    }
}

impl fmt::Display for Bits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", HexValue(self))
    }
}

/// Hexadecimal digits without leading zeros.
struct HexValue<'a>(&'a Bits);

impl fmt::LowerHex for HexValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let words = &self.0.words;
        let top = words.iter().rposition(|&word| word != 0).unwrap_or(0);
        if f.alternate() {
            f.write_str("0x")?;
        }
        let mut first = true;
        for index in (0..=top).rev() {
            let word = words.get(index).copied().unwrap_or(0);
            if first {
                write!(f, "{word:x}")?;
                first = false;
            } else {
                write!(f, "{word:016x}")?;
            }
        }
        Ok(())
    }
}
