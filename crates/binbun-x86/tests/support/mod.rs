//! Inputs for differential tests against XED (`tools/xed-oracle`).

pub mod notation;

use std::fmt::Write as _;

use binbun_x86::Mode;

/// splitmix64: small, fast, and deterministic across platforms.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    /// Uniform in `0..n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// True with probability `percent`/100.
    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[usize::try_from(self.below(items.len() as u64)).unwrap()]
    }
}

/// The modes random inputs are decoded in: mostly protected and 64-bit,
/// sometimes real mode.
pub const MODES: [Mode; 8] = [
    Mode::Bits16,
    Mode::Bits32,
    Mode::Bits32,
    Mode::Bits64,
    Mode::Bits64,
    Mode::Bits64,
    Mode::Real16,
    Mode::Real32,
];

/// A random runtime address for formatting: often 0, often near the ends
/// of the address space (so branch targets wrap), else anywhere.
pub fn address(rng: &mut Rng) -> u64 {
    match rng.below(4) {
        0 => 0,
        1 => rng.below(0x100),
        2 => {
            [0xffff, 0xffff_ffff, u64::MAX][usize::try_from(rng.below(3)).unwrap()]
                - rng.below(0x100)
        }
        _ => rng.next(),
    }
}

const LEGACY_PREFIXES: [u8; 11] = [
    0x66, 0x67, 0xf2, 0xf3, 0xf0, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65,
];

/// A random instruction-like byte string of up to 15 bytes, weighted so
/// every opcode map and prefix form is exercised often: legacy prefixes,
/// REX and REX2, the `0F`, `0F 38`, `0F 3A` and 3DNow! escapes, VEX, EVEX
/// and XOP. Bytes after the opcode are random, so ModRM, SIB, displacement
/// and immediate forms vary freely. One in twenty inputs is truncated.
pub fn instruction(rng: &mut Rng, mode: Mode) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(15);
    for _ in 0..[0, 0, 0, 1, 1, 2, 3][usize::try_from(rng.below(7)).unwrap()] {
        bytes.push(rng.pick(&LEGACY_PREFIXES));
    }
    let long = mode == Mode::Bits64;
    if long && rng.chance(25) {
        bytes.push(0x40 | (rng.byte() & 0x0f));
    }
    // In 16/32-bit mode VEX, EVEX need ModRM.mod = 3 in their first payload
    // byte, otherwise the bytes are LES, LDS or BOUND; force it usually.
    let payload = |rng: &mut Rng, byte: u8| {
        if !long && rng.chance(90) {
            byte | 0xc0
        } else {
            byte
        }
    };
    match rng.below(100) {
        94..97 if long => bytes.extend([0xd5, rng.byte()]),
        0..35 | 94..97 => {}
        35..60 => bytes.push(0x0f),
        60..66 => bytes.extend([0x0f, 0x38]),
        66..71 => bytes.extend([0x0f, 0x3a]),
        71..72 => bytes.extend([0x0f, 0x0f]),
        72..78 => {
            let raw = rng.byte();
            let p = payload(rng, raw);
            bytes.extend([0xc5, p]);
        }
        78..85 => {
            let any = rng.byte() & 0x1f;
            let map = rng.pick(&[1, 2, 3, 5, 7, any]);
            let raw = (rng.byte() & 0xe0) | map;
            let p = payload(rng, raw);
            bytes.extend([0xc4, p, rng.byte()]);
        }
        85..94 => {
            let any = rng.byte() & 0x07;
            let map = rng.pick(&[1, 2, 3, 4, 5, 6, 7, any]);
            let raw = (rng.byte() & 0xf8) | map;
            let p0 = payload(rng, raw);
            let p1 = if rng.chance(90) {
                rng.byte() | 0x04
            } else {
                rng.byte()
            };
            bytes.extend([0x62, p0, p1, rng.byte()]);
        }
        _ => {
            let any = rng.byte() & 0x1f;
            let map = rng.pick(&[8, 9, 10, any]);
            bytes.extend([0x8f, (rng.byte() & 0xe0) | map, rng.byte()]);
        }
    }
    while bytes.len() < 15 {
        bytes.push(rng.byte());
    }
    if rng.chance(5) {
        let keep = usize::try_from(rng.below(15)).unwrap();
        bytes.truncate(keep.max(1));
    }
    bytes
}

/// Lower-case hex of `bytes`, as the oracle reads it.
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            write!(out, "{byte:02x}").unwrap();
            out
        })
}
