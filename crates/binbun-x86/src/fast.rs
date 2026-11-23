//! The 64-bit fast path: in 64-bit mode, legacy encodings of the opcodes in
//! `generated/fast.rs` decode without the reference decoder's state in
//! memory.
//!
//! Here the prefixes (at most one of `66`/`F2`/`F3`, then at most one REX)
//! and the opcode are read; the opcode's generated function does the rest
//! with the decoder state in a local that never escapes, so its fields live
//! in registers. The generated code is the reference decoder's grammar,
//! compiled by the same generator specialised to what is known here. Any
//! other shape, opcode or error gives up: the reference decoder decodes the
//! bytes from scratch ([`Finish::fallback`]). Giving up inside the opcode's
//! function, which returns what the caller returns, lets the result be
//! written once, where the caller wants it.

use binbun_isa::FlowStep;

use crate::decode::{Instruction, checked, decode_in};
use crate::generated::fast::{FLOW, FULL, MAPS};
use crate::generated::state::State;
use crate::ild::{ESCAPE, FRONT, LEGACY, PLAIN, REX, entry};
use crate::{DecodeError, MAX_LENGTH, Mode};

/// The prefixes before a fast-path opcode.
#[derive(Debug, Clone, Copy)]
pub struct Head {
    /// 1 after `66` (XED's `OSZ`), else 0.
    pub osz: u8,
    /// 2 after `F2`, 3 after `F3` (XED's `REP`), else 0.
    pub rep: u8,
    /// The REX prefix, or 0 for none.
    pub rex: u8,
    /// Bytes up to the end of the opcode.
    pub end: u8,
}

/// What a fast path returns.
pub trait Finish {
    type Output;

    /// The answer for instruction `number` with decoder state `s`, decoded
    /// from `bytes` at `address`.
    fn finish(s: State, number: u16, address: u64, bytes: &[u8]) -> Self::Output;

    /// The reference decoder's answer for `bytes` at `address`.
    fn fallback(bytes: &[u8], address: u64) -> Self::Output;
}

/// An opcode's fast path: the instruction's first bytes (as `State::buf`),
/// the prefixes, the address, and all the bytes (for the fallback).
pub type Fast<F> = fn(&[u8; 32], Head, u64, &[u8]) -> <F as Finish>::Output;

/// Full decoding: the [`Instruction`].
#[derive(Debug)]
pub struct Full;

impl Finish for Full {
    type Output = Result<Instruction, DecodeError>;

    #[expect(
        clippy::inline_always,
        reason = "inlined into each arm, where the instruction is a constant"
    )]
    #[inline(always)]
    fn finish(s: State, number: u16, address: u64, bytes: &[u8]) -> Self::Output {
        match checked(number, s.fields) {
            Some(instruction) => Ok(instruction),
            None => Self::fallback(bytes, address),
        }
    }

    fn fallback(bytes: &[u8], _: u64) -> Self::Output {
        reference(bytes)
    }
}

/// Flow-only decoding: the [`FlowStep`]. With the instruction a constant,
/// what its flow does not read is dead code.
#[derive(Debug)]
pub struct FlowOnly;

impl Finish for FlowOnly {
    type Output = Result<FlowStep, DecodeError>;

    #[expect(
        clippy::inline_always,
        reason = "inlined into each arm, where the instruction is a constant"
    )]
    #[inline(always)]
    fn finish(s: State, number: u16, address: u64, bytes: &[u8]) -> Self::Output {
        match checked(number, s.fields) {
            Some(instruction) => Ok(instruction.flow_step(address)),
            None => Self::fallback(bytes, address),
        }
    }

    fn fallback(bytes: &[u8], address: u64) -> Self::Output {
        reference(bytes).map(|instruction| instruction.flow_step(address))
    }
}

/// An opcode without a fast path.
pub fn unhandled<F: Finish>(_: &[u8; 32], _: Head, address: u64, bytes: &[u8]) -> F::Output {
    F::fallback(bytes, address)
}

/// The reference decoder in 64-bit mode, out of line.
#[inline(never)]
fn reference(bytes: &[u8]) -> Result<Instruction, DecodeError> {
    decode_in::<true>(bytes, Mode::Bits64)
}

/// [`crate::decode`] in 64-bit mode.
#[inline]
pub fn decode(bytes: &[u8]) -> Result<Instruction, DecodeError> {
    run::<Full>(bytes, 0, &FULL)
}

/// [`crate::decode_flow`] in 64-bit mode.
#[inline]
pub fn decode_flow(bytes: &[u8], address: u64) -> Result<FlowStep, DecodeError> {
    run::<FlowOnly>(bytes, address, &FLOW)
}

/// Reads the prefixes and the opcode, then runs the opcode's entry of
/// `table`.
#[inline]
fn run<F: Finish>(bytes: &[u8], address: u64, table: &[[Fast<F>; 256]; MAPS]) -> F::Output {
    let padded;
    let window = if let Some(window) = bytes.first_chunk::<32>() {
        window
    } else {
        let Some(window) = pad(bytes) else {
            return F::fallback(bytes, address);
        };
        padded = window;
        &padded
    };
    let byte = |at: usize| window.get(at & 15).copied().unwrap_or(0);
    // At most one legacy prefix, then at most one REX. (Measured: branches,
    // even mispredicted, beat a chain of dependent loads; the next
    // instruction waits for this one's length.)
    let mut at = 0;
    let mut legacy = 0;
    let mut rex = 0;
    let mut class = entry(&FRONT, byte(0));
    if class == LEGACY {
        legacy = entry(&LEGACY_FIELDS, byte(0));
        at = 1;
        class = entry(&FRONT, byte(1));
    }
    if class == REX {
        rex = byte(at);
        at += 1;
        class = entry(&FRONT, byte(at));
    }
    let (map, opcode, end) = match class {
        PLAIN => (0, byte(at), at + 1),
        ESCAPE => match byte(at + 1) {
            0x38 => (2, byte(at + 2), at + 3),
            0x3a => (3, byte(at + 2), at + 3),
            // 3DNow!: the opcode is the last byte.
            0x0f => return F::fallback(bytes, address),
            second => (1, second, at + 2),
        },
        _ => return F::fallback(bytes, address),
    };
    let head = Head {
        osz: legacy >> 2,
        rep: legacy & 3,
        rex,
        #[expect(clippy::cast_possible_truncation, reason = "at most 5")]
        end: end as u8,
    };
    match table.get(map) {
        Some(opcodes) => entry(opcodes, opcode)(window, head, address, bytes),
        None => F::fallback(bytes, address),
    }
}

/// XED's `OSZ` (bit 2) and `REP` (bits 0-1) after each byte as the only
/// legacy prefix (66: `OSZ` 1; F2 and F3: `REP` 2 and 3).
const LEGACY_FIELDS: [u8; 256] = {
    let mut table = [0; 256];
    table[0x66] = 4;
    table[0xf2] = 2;
    table[0xf3] = 3;
    table
};

/// The first [`MAX_LENGTH`] bytes of `bytes`, zero-padded to 32; `None`
/// if there are fewer (the fast path always has 15 bytes available). Only
/// they count: past them the length decoder reads only bytes it then
/// masks away, as from the reference decoder's `State::buf`.
#[inline]
fn pad(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut window = [0; 32];
    *window.first_chunk_mut::<MAX_LENGTH>()? = *bytes.first_chunk::<MAX_LENGTH>()?;
    Some(window)
}

#[cfg(test)]
mod tests {
    use binbun_isa::FlowStep;

    use super::{Fast, Finish, decode, decode_flow, reference, run};
    use crate::decode::{Instruction, checked};
    use crate::generated::fast::{HANDLED, MAPS, table};
    use crate::generated::state::State;

    /// The fast path alone: `None` where it gives up.
    struct Probe;

    impl Finish for Probe {
        type Output = Option<Instruction>;

        fn finish(s: State, number: u16, _: u64, _: &[u8]) -> Self::Output {
            checked(number, s.fields)
        }

        fn fallback(_: &[u8], _: u64) -> Self::Output {
            None
        }
    }

    /// A small deterministic generator for the bytes after ModRM and SIB.
    struct Rng(u64);

    impl Rng {
        fn bytes(&mut self) -> [u8; 8] {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0.to_le_bytes()
        }
    }

    /// Checks `bytes`: full and flow-only decoding equal the reference
    /// decoder's, and so does the fast path alone where it answers.
    /// Returns whether it answered.
    fn check(bytes: &[u8], probes: &[[Fast<Probe>; 256]; MAPS]) -> bool {
        let expected = reference(bytes);
        assert_eq!(decode(bytes), expected, "{bytes:02x?}");
        let address = 0x7fff_0000_1000;
        assert_eq!(
            decode_flow(bytes, address),
            expected
                .as_ref()
                .map(|i| FlowStep::of(i, address))
                .map_err(|e| *e),
            "{bytes:02x?}"
        );
        let fast = run::<Probe>(bytes, address, probes);
        if let Some(fast) = &fast {
            assert_eq!(Ok(fast), expected.as_ref(), "{bytes:02x?}");
        }
        fast.is_some()
    }

    /// The structured sweep: for every opcode with a fast path, every
    /// prefix shape it reads (none, 66, F2 or F3, each with no REX or one
    /// of the 16) × every ModRM × every SIB, with random displacement and
    /// immediate bytes ([`check`]); every other encoding has only the 15
    /// bytes the fast path needs. Each opcode's fast path must answer for
    /// some of them.
    #[test]
    fn fast_path_equals_reference() {
        let probes = table::<Probe>();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let escape: [&[u8]; 4] = [&[], &[0x0f], &[0x0f, 0x38], &[0x0f, 0x3a]];
        let mut short = false;
        for &(map, opcode) in &HANDLED {
            let mut answered = 0;
            for prefix in [0, 0x66, 0xf2, 0xf3] {
                for rex in core::iter::once(0).chain(0x40..=0x4f) {
                    let mut head = [0u8; 6];
                    let mut length = 0;
                    let prefixes = [prefix, rex];
                    let opcode = [opcode];
                    let opcode_bytes = escape[usize::from(map)].iter().chain(&opcode);
                    for &byte in prefixes.iter().filter(|&&b| b != 0).chain(opcode_bytes) {
                        head[length] = byte;
                        length += 1;
                    }
                    for modrm in 0..=255u8 {
                        let has_sib = modrm >> 6 != 3 && modrm & 7 == 4;
                        for sib in 0..=if has_sib { 255 } else { 0 } {
                            let mut bytes = [0u8; 32];
                            bytes[..length].copy_from_slice(&head[..length]);
                            bytes[length] = modrm;
                            let mut end = length + 1;
                            if has_sib {
                                bytes[end] = sib;
                                end += 1;
                            }
                            bytes[end..end + 8].copy_from_slice(&rng.bytes());
                            bytes[end + 8..end + 16].copy_from_slice(&rng.bytes());
                            short = !short;
                            let available = if short { 15 } else { 32 };
                            answered += usize::from(check(&bytes[..available], &probes));
                        }
                    }
                }
            }
            assert!(
                answered > 0,
                "map {map} opcode {opcode:#04x}: never answered"
            );
        }
    }
}
