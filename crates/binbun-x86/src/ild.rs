//! Instruction-length decoding: prefixes, encoding (legacy, REX2, VEX, EVEX,
//! XOP), opcode map and opcode, ModRM, SIB, displacement and immediates.
//!
//! This follows XED's hand-written ILD (`xed-ild.c`) step for step, so that
//! lengths and errors match XED exactly; the per-opcode facts come from
//! `generated/ild.rs`, one packed table entry per opcode. It fills the
//! decoder [`State`], whose fields are XED's, for the later, generated
//! stages.

use crate::error::{DecodeError, Mode};
use crate::fast::Head;
use crate::generated::handlers::TAILS;
use crate::generated::ild::{
    DISP_WIDTHS, IMM_WIDTHS, LEGACY_ESCAPES, OPCODES, TABLE_INDEX, WIDTH_ENTER, WIDTH_MAP1_OP78,
    WIDTH_UNSET,
};
use crate::generated::state::State;

/// The longest x86 instruction.
pub const MAX_LENGTH: usize = 15;

/// A legacy map reached through `0F`.
#[derive(Debug, Clone, Copy)]
pub struct LegacyMap {
    /// The byte after `0F` that selects the map, or `None` for map 1.
    pub second: Option<u8>,
    pub map: u8,
    /// 3DNow!: the opcode is the instruction's last byte.
    pub trailing_opcode: bool,
}

/// ModRM codes of the packed opcode entries.
const MODRM_NONE: u16 = 0;
const MODRM_IGNORE_MOD: u16 = 2;

/// The index in `OPCODES` (and the handler tables) of map `map` in encoding
/// space `space`: 0, an empty table, if the map does not exist.
#[inline]
pub fn table_index(space: u8, map: u8) -> usize {
    // Map numbers above 31 (only `u8::MAX`, after a bad map) are masked to
    // 31, which no space has.
    let slot = usize::from(space & 3) << 5 | usize::from(map & 31);
    TABLE_INDEX.get(slot).map_or(0, |&index| usize::from(index))
}

/// Whether map `map` exists in encoding space `space`.
fn map_exists(space: u8, map: u8) -> bool {
    map < 32 && table_index(space, map) != 0
}

/// Decodes the length of the instruction at the start of `bytes`.
///
/// # Errors
///
/// As XED's `xed_ild_decode`: [`DecodeError::TooShort`] whenever the bytes
/// end before the instruction does (also when that is past 15 bytes), else
/// the first prefix or map error found.
pub fn decode_length(bytes: &[u8], mode: Mode) -> Result<usize, DecodeError> {
    let mut state = State::default();
    state.load(bytes, mode);
    let table = state.head();
    if state.out_of_bytes == 0 {
        let tail: fn(&mut State) = TAILS
            .get(table)
            .map_or(tail_of::<0>, |table| entry(table, state.nominal_opcode));
        tail(&mut state);
    }
    if state.out_of_bytes != 0 {
        return Err(DecodeError::TooShort);
    }
    DecodeError::from_code(state.error).map_or(Ok(state.pos), Err)
}

/// [`State::tail`] for the constant entry `ENTRY`: one shared out-of-line
/// copy per distinct entry, so that opcode handlers stay small.
#[inline(never)]
pub fn tail_of<const ENTRY: u16>(state: &mut State) {
    state.tail_in::<false, false>(ENTRY);
}

/// [`tail_of`] for a legacy encoding (no VEX, EVEX or XOP prefix, and not
/// 3DNow!) in 64-bit mode.
#[inline(never)]
pub fn tail64_of<const ENTRY: u16>(state: &mut State) {
    state.tail_in::<true, true>(ENTRY);
}

impl State {
    /// Index of the current `(MODE, 66, 67, REX.W)` in size tables.
    #[inline]
    pub fn size_point(&self) -> usize {
        self.size_point_in::<false>()
    }

    /// The fast path's start (`fast.rs`), on a fresh state: what
    /// [`State::load`] and [`State::head`] set for 64-bit mode, the
    /// prefixes of `head` and opcode `opcode` of legacy map `map`. The
    /// bytes stay out of the state (see [`State::fast_tail`]).
    #[expect(
        clippy::inline_always,
        reason = "each opcode's fast path keeps the state in registers"
    )]
    #[inline(always)]
    pub fn fast_start(&mut self, head: Head, map: u8, opcode: u8) {
        self.max = MAX_LENGTH;
        self.mode = 2;
        self.smode = 2;
        self.p4 = 1;
        self.tzcnt = 1;
        self.lzcnt = 1;
        self.cet = 1;
        // As `set_legacy` and `set_rex`, without branches.
        self.osz = head.osz;
        self.prefix66 = head.osz;
        self.rep = head.rep;
        self.ild_f2 = u8::from(head.rep == 2);
        self.ild_f3 = u8::from(head.rep == 3);
        self.first_f2f3 = head.rep;
        self.last_f2f3 = head.rep;
        let rex = u8::from(head.rex != 0);
        self.nrexes = rex;
        self.rex = rex;
        self.rexw = (head.rex >> 3) & 1;
        self.rexr = (head.rex >> 2) & 1;
        self.rexx = (head.rex >> 1) & 1;
        self.rexb = head.rex & 1;
        self.nprefixes = u8::from(head.osz | head.rep != 0) + rex;
        self.map = map;
        self.nominal_opcode = opcode;
        self.srm = opcode & 7;
        self.pos = usize::from(head.end);
    }

    /// [`State::tail`] for 64-bit mode and a legacy encoding, inline, with
    /// the bytes in `window` (as `State::buf`) instead of the state: an
    /// array indexed by a variable would keep the whole state in memory.
    #[expect(
        clippy::inline_always,
        reason = "each opcode's fast path keeps the state in registers"
    )]
    #[inline(always)]
    pub fn fast_tail(&mut self, window: &[u8; 32], entry: u16) {
        self.tail_from::<true, true>(window, entry);
    }

    /// [`State::size_point`], for 64-bit mode if `MODE64` (whatever the
    /// state says).
    #[inline]
    fn size_point_in<const MODE64: bool>(&self) -> usize {
        let mode = if MODE64 { 2 } else { usize::from(self.mode) };
        ((mode * 2 + usize::from(self.osz)) * 2 + usize::from(self.asz)) * 2
            + usize::from(self.rexw)
    }

    /// Starts length-decoding the instruction at the start of `bytes` (at
    /// most 15 are read) in `mode`; the state must be fresh (all zero).
    /// [`State::head`] reads up to the opcode; then, unless
    /// `out_of_bytes`, [`State::tail`] reads the rest.
    #[inline]
    pub fn load(&mut self, bytes: &[u8], mode: Mode) {
        self.max = bytes.len().min(MAX_LENGTH);
        self.mode = match mode.bits() {
            16 => 0,
            32 => 1,
            _ => 2,
        };
        self.realmode = u8::from(mode.is_real());
        // The stack address width is the mode's (XED's `SMODE`, which
        // `SrSP()` and stack operand sizes read).
        self.smode = self.mode;
        // XED's dual encodings, decoded as its `xed` command does and as
        // processors since 2013 run them: F3 90 is PAUSE, F3 0F BC TZCNT,
        // F3 0F BD LZCNT (not NOP, BSF, BSR); with CET (processors since
        // 2020), F3 0F 1E FA/FB are ENDBR64/ENDBR32, not reserved NOPs.
        self.p4 = 1;
        self.tzcnt = 1;
        self.lzcnt = 1;
        self.cet = 1;
        // A zero-padded copy: reads past the end are 0 and need no checks,
        // and eight bytes can be read from any position below 16.
        match (bytes.first_chunk::<16>(), self.buf.first_chunk_mut::<16>()) {
            (Some(head), Some(dest)) => *dest = *head,
            _ => copy_short(&mut self.buf, bytes),
        }
    }

    /// The packed entry (see `generated/ild.rs`) of the opcode read, or 0
    /// when there is no such map.
    #[inline]
    pub fn opcode_entry(&self) -> u16 {
        OPCODES
            .get(table_index(self.vexvalid, self.map))
            .map_or(0, |table| entry(table, self.nominal_opcode))
    }

    /// ModRM, SIB, displacement and immediates, as the packed opcode entry
    /// `entry` describes (inlined, so a constant `entry` folds away).
    #[expect(
        clippy::inline_always,
        reason = "callers pass constant entries to fold"
    )]
    #[inline(always)]
    pub fn tail(&mut self, entry: u16) {
        self.tail_in::<false, false>(entry);
    }

    /// [`State::tail`], specialised for 64-bit mode if `MODE64`, and for a
    /// legacy encoding that is not 3DNow! if `LEGACY` (no EVEX checks, no
    /// trailing opcode, no immediate width set before).
    #[expect(
        clippy::inline_always,
        reason = "callers pass constant entries to fold"
    )]
    #[inline(always)]
    fn tail_in<const MODE64: bool, const LEGACY: bool>(&mut self, entry: u16) {
        let buf = self.buf;
        self.tail_from::<MODE64, LEGACY>(&buf, entry);
    }

    /// [`State::tail_in`] reading the instruction's bytes from `buf` (as
    /// `State::buf`).
    #[expect(
        clippy::inline_always,
        reason = "callers pass constant entries to fold"
    )]
    #[inline(always)]
    fn tail_from<const MODE64: bool, const LEGACY: bool>(&mut self, buf: &[u8; 32], entry: u16) {
        self.modrm::<MODE64, LEGACY>(buf, entry & 3);
        self.sib(buf);
        self.displacement::<MODE64>(buf, entry >> 8);
        self.immediate::<MODE64, LEGACY>(buf, entry >> 2 & 63);
        if !LEGACY && self.vexvalid == 2 {
            self.late_evex();
        }
    }

    #[inline]
    fn mode64(&self) -> bool {
        self.mode == 2
    }

    #[inline]
    fn byte(&self, at: usize) -> u8 {
        byte_at(&self.buf, at)
    }

    // Inline, though cold: a call would put the fast path's state in
    // memory.
    #[cold]
    #[expect(
        clippy::inline_always,
        reason = "the fast path's state must not escape"
    )]
    #[inline(always)]
    fn too_short(&mut self) {
        self.out_of_bytes = 1;
        self.fail(if self.max >= MAX_LENGTH {
            DecodeError::TooLong
        } else {
            DecodeError::TooShort
        });
    }

    /// Too short, having consumed all bytes (XED sets the length to the
    /// limit in some scanners).
    #[cold]
    fn too_short_at_end(&mut self) {
        self.pos = self.max;
        self.too_short();
    }

    #[inline]
    fn fail(&mut self, error: DecodeError) {
        self.error = error as u8;
    }

    #[inline]
    fn failed(&self) -> bool {
        self.error != 0
    }

    #[cold]
    fn bad_map(&mut self) {
        // No map: nothing further (ModRM, immediates) is read.
        self.map = u8::MAX;
        self.fail(DecodeError::BadMap);
    }

    /// Prefixes, encoding prefixes and the opcode (with its map); returns
    /// the map's [`table_index`].
    #[expect(
        clippy::inline_always,
        reason = "measured: the fast paths need no call or saved registers"
    )]
    #[inline(always)]
    pub fn head(&mut self) -> usize {
        // Fast paths for the common shapes, with the effects the general
        // scanners would have: an opcode (or escape) after at most one of
        // 66/F2/F3, then at most one REX prefix. Each is decided before any
        // field is written, so that other shapes start the general path
        // fresh.
        let first = self.byte(0);
        match entry(&FRONT, first) {
            class @ (PLAIN | ESCAPE) if self.max >= 1 => return self.opcode_at(0, first, class),
            REX if self.mode64() && self.max >= 2 => {
                let second = self.byte(1);
                let class = entry(&FRONT, second);
                if class == PLAIN || class == ESCAPE {
                    self.set_rex(first);
                    self.nprefixes = 1;
                    return self.opcode_at(1, second, class);
                }
            }
            LEGACY if self.max >= 2 => {
                let second = self.byte(1);
                match entry(&FRONT, second) {
                    class @ (PLAIN | ESCAPE) => {
                        self.set_legacy(first);
                        self.nprefixes = 1;
                        return self.opcode_at(1, second, class);
                    }
                    REX if self.mode64() && self.max >= 3 => {
                        let third = self.byte(2);
                        let class = entry(&FRONT, third);
                        if class == PLAIN || class == ESCAPE {
                            self.set_legacy(first);
                            self.set_rex(second);
                            self.nprefixes = 2;
                            return self.opcode_at(2, third, class);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        self.head_general()
    }

    /// The fast paths' REX prefix `rex`.
    #[inline]
    fn set_rex(&mut self, rex: u8) {
        self.nrexes = 1;
        self.rex = 1;
        self.rexw = (rex >> 3) & 1;
        self.rexr = (rex >> 2) & 1;
        self.rexx = (rex >> 1) & 1;
        self.rexb = rex & 1;
    }

    /// The fast paths' only legacy prefix: 66, F2 or F3.
    #[inline]
    fn set_legacy(&mut self, prefix: u8) {
        match prefix {
            0x66 => {
                self.osz = 1;
                self.prefix66 = 1;
            }
            0xf2 => {
                self.ild_f2 = 1;
                self.last_f2f3 = 2;
                self.first_f2f3 = 2;
                self.rep = 2;
            }
            _ => {
                self.ild_f3 = 1;
                self.last_f2f3 = 3;
                self.first_f2f3 = 3;
                self.rep = 3;
            }
        }
    }

    /// The fast paths' opcode byte `byte` at `at`, of [`FRONT`] class
    /// `class` (a map-0 opcode or the escape): the map's table index.
    #[inline]
    fn opcode_at(&mut self, at: usize, byte: u8, class: u8) -> usize {
        if class == PLAIN {
            self.plain_opcode(at, byte);
            return table_index(0, 0);
        }
        self.pos = at;
        self.opcode();
        table_index(0, self.map)
    }

    /// [`State::head`] for any shape: the general prefix and encoding
    /// prefix scanners.
    #[inline(never)]
    fn head_general(&mut self) -> usize {
        self.prefixes();
        if self.out_of_bytes != 0 {
            return 0;
        }
        match self.byte(self.pos) {
            0xc4 | 0xc5 | 0x8f | 0x62 => {
                self.vector();
                if self.out_of_bytes != 0 {
                    return 0;
                }
            }
            0xd5 if self.mode64() => self.rex2(),
            _ => {}
        }
        if self.vexvalid == 0 && self.rex2 == 0 && !self.failed() {
            self.opcode();
        }
        table_index(self.vexvalid, self.map)
    }

    /// A one-byte (map 0) opcode at `pos`.
    #[inline]
    fn plain_opcode(&mut self, pos: usize, opcode: u8) {
        self.map = 0;
        self.nominal_opcode = opcode;
        self.srm = opcode & 7;
        self.pos = pos + 1;
    }

    /// The VEX, XOP and EVEX scanners (XED's `vex_scanner`, `evex_scanner`
    /// and the prefix checks after them).
    #[cold]
    fn vector(&mut self) {
        match self.byte(self.pos) {
            0xc5 => self.vex2(),
            0xc4 => self.vex3(),
            0x8f => self.xop(),
            _ => {}
        }
        if self.out_of_bytes != 0 || self.failed() {
            return;
        }
        if self.vexvalid == 0 {
            self.evex();
            if self.out_of_bytes != 0 {
                return;
            }
        }
        if self.vexvalid != 0 {
            if self.mode64() && self.rex != 0 {
                self.fail(DecodeError::BadRexPrefix);
            } else if self.prefix66 != 0 || self.ild_f2 != 0 || self.ild_f3 != 0 {
                self.fail(DecodeError::BadLegacyPrefix);
            }
        } else if self.mode64() && self.byte(self.pos) == 0xd5 {
            // 62 that was BOUND cannot be followed by REX2 here, but C4/C5/8F
            // that were not vector prefixes leave the byte as is.
            self.rex2();
        }
    }

    #[inline]
    fn prefixes(&mut self) {
        let mut pos = self.pos;
        let mut rex = 0u8;
        while pos < self.max {
            let b = self.byte(pos);
            if !is_prefix(b) {
                break;
            }
            match b {
                0x66 => {
                    self.osz = 1;
                    self.prefix66 = 1;
                    rex = 0;
                }
                0x67 => {
                    self.asz = 1;
                    rex = 0;
                }
                0x2e => {
                    if !self.mode64() {
                        self.hint = 1;
                        self.ild_seg = b;
                    } else if self.hint != 2 {
                        self.hint = 1;
                    }
                    self.nseg_prefixes += 1;
                    rex = 0;
                }
                0x3e => {
                    if !self.mode64() {
                        self.hint = 2;
                        self.ild_seg = b;
                    } else if !matches!(self.ild_seg, 0x64 | 0x65) {
                        self.hint = 2;
                    }
                    self.nseg_prefixes += 1;
                    rex = 0;
                }
                0x26 | 0x36 => {
                    if !self.mode64() {
                        self.ild_seg = b;
                        self.hint = 0;
                    }
                    self.nseg_prefixes += 1;
                    rex = 0;
                }
                0x64 | 0x65 => {
                    self.ild_seg = b;
                    self.hint = 0;
                    self.nseg_prefixes += 1;
                    rex = 0;
                }
                0xf0 => {
                    self.lock = 1;
                    rex = 0;
                }
                0xf2 | 0xf3 => {
                    let kind = if b == 0xf2 { 2 } else { 3 };
                    if b == 0xf2 {
                        self.ild_f2 = 1;
                    } else {
                        self.ild_f3 = 1;
                    }
                    self.last_f2f3 = kind;
                    if self.first_f2f3 == 0 {
                        self.first_f2f3 = kind;
                    }
                    rex = 0;
                }
                0x40..=0x4f if self.mode64() => {
                    self.nrexes += 1;
                    rex = b;
                }
                _ => break,
            }
            pos += 1;
            self.nprefixes += 1;
        }
        self.pos = pos;
        if rex != 0 {
            self.rex = 1;
            self.rexw = (rex >> 3) & 1;
            self.rexr = (rex >> 2) & 1;
            self.rexx = (rex >> 1) & 1;
            self.rexb = rex & 1;
        }
        // XED's MODE_FIRST_PREFIX (pre-Pentium chips) is not modelled: the
        // last of F2/F3 wins.
        self.rep = self.last_f2f3;
        if self.ild_seg != 0 {
            self.seg_ovd = match self.ild_seg {
                0x2e => 1,
                0x3e => 2,
                0x26 => 3,
                0x64 => 4,
                0x65 => 5,
                _ => 6,
            };
        }
        if pos >= self.max {
            self.too_short();
        }
    }

    fn set_vex_prefix(&mut self, pp: u8) {
        // pp: none, 66, F3, F2; XED's VEX_PREFIX: none, 66, F2, F3.
        self.vex_prefix = match pp & 3 {
            2 => 3,
            3 => 2,
            other => other,
        };
    }

    /// The register-extension and vector fields shared by VEX3 and XOP.
    fn vex3_payload(&mut self, p1: u8, p2: u8) {
        self.rexr = !p1 >> 7 & 1;
        self.rexx = !p1 >> 6 & 1;
        self.rexb = u8::from(self.mode64()) & (!p1 >> 5 & 1);
        self.rexw = p2 >> 7;
        self.vexdest3 = p2 >> 6 & 1;
        self.vexdest210 = (p2 >> 3) & 7;
        self.vl = (p2 >> 2) & 1;
        self.set_vex_prefix(p2);
    }

    fn vex2(&mut self) {
        let mut pos = self.pos;
        if pos + 1 >= self.max {
            return self.too_short_at_end();
        }
        pos += 1;
        let payload = self.byte(pos);
        // Outside 64-bit mode, C5 is LDS unless ModRM.mod would be 3.
        if !self.mode64() && payload >> 6 != 3 {
            return;
        }
        if pos + 1 >= self.max {
            return self.too_short_at_end();
        }
        self.rexr = !payload >> 7 & 1;
        self.vexdest3 = payload >> 6 & 1;
        self.vexdest210 = (payload >> 3) & 7;
        self.vl = (payload >> 2) & 1;
        self.set_vex_prefix(payload);
        self.map = 1;
        self.vexvalid = 1;
        self.pos = pos + 1;
        self.vector_opcode();
    }

    fn vex3(&mut self) {
        let mut pos = self.pos;
        if pos + 1 >= self.max {
            return self.too_short_at_end();
        }
        pos += 1;
        let p1 = self.byte(pos);
        // Outside 64-bit mode, C4 is LES unless ModRM.mod would be 3.
        if !self.mode64() && p1 >> 6 != 3 {
            return;
        }
        if pos + 2 >= self.max {
            return self.too_short_at_end();
        }
        let p2 = self.byte(pos + 1);
        self.pos = pos + 2;
        self.vex3_payload(p1, p2);
        let map = p1 & 0x1f;
        self.map = map;
        if !map_exists(1, map) {
            return self.bad_map();
        }
        self.vexvalid = 1;
        self.vector_opcode();
    }

    fn xop(&mut self) {
        let mut pos = self.pos;
        if pos + 1 >= self.max {
            return self.too_short();
        }
        // XOP unless ModRM.reg would be 0, which makes 8F a POP.
        if self.byte(pos + 1) & 0x38 == 0 {
            return;
        }
        pos += 1;
        if pos + 2 >= self.max {
            return self.too_short_at_end();
        }
        let p1 = self.byte(pos);
        let p2 = self.byte(pos + 1);
        self.pos = pos + 2;
        let map = p1 & 0x1f;
        self.map = map;
        if !matches!(map, 8..=10) {
            self.bad_map();
        }
        self.vex3_payload(p1, p2);
        self.vexvalid = 3;
        self.vector_opcode();
    }

    fn evex(&mut self) {
        let pos = self.pos;
        if self.byte(pos) != 0x62 {
            return;
        }
        if pos + 1 >= self.max {
            return self.too_short_at_end();
        }
        let p1 = self.byte(pos + 1);
        // Outside 64-bit mode, 62 is BOUND unless ModRM.mod would be 3.
        if !self.mode64() && p1 >> 6 != 3 {
            return;
        }
        self.vexvalid = 2;
        // APX (64-bit mode) narrows the map to 3 bits; bit 3 is B4.
        let map = if self.mode64() {
            self.rexb4 = p1 >> 3 & 1;
            p1 & 0x07
        } else {
            p1 & 0x0f
        };
        self.map = map;
        if map == 0 {
            self.pos = pos + 2;
            return self.bad_map();
        }
        if pos + 4 >= self.max {
            return self.too_short_at_end();
        }
        let p2 = self.byte(pos + 2);
        if self.mode64() {
            self.rexr = !p1 >> 7 & 1;
            self.rexx = !p1 >> 6 & 1;
            self.rexb = !p1 >> 5 & 1;
            self.rexr4 = !p1 >> 4 & 1;
        }
        if !map_exists(2, map) {
            self.pos = pos + 4;
            return self.bad_map();
        }
        self.rexw = p2 >> 7;
        self.vexdest3 = p2 >> 6 & 1;
        self.vexdest210 = (p2 >> 3) & 7;
        self.ubit = p2 >> 2 & 1;
        self.set_vex_prefix(p2);
        if p2 & 3 == 1 {
            self.osz = 1;
        }
        if !self.failed() {
            let p3 = self.byte(pos + 3);
            self.zeroing = p3 >> 7;
            self.llrc = (p3 >> 5) & 3;
            self.vl = self.llrc;
            self.bcrc = p3 >> 4 & 1;
            self.vexdest4 = !p3 >> 3 & 1;
            if !self.mode64() && p3 & 0x08 == 0 {
                self.fail(DecodeError::BadEvexVPrime);
            }
            self.mask = p3 & 7;
            if self.mask == 0 && self.zeroing != 0 {
                self.fail(DecodeError::BadEvexZeroingWithoutMask);
            }
            if self.mode64() {
                self.nf = p3 >> 2 & 1;
                self.nd = p3 >> 4 & 1;
                if map == 4 {
                    self.scc = p3 & 0x0f;
                }
            }
        }
        self.pos = pos + 4;
        self.vector_opcode();
    }

    /// APX: for EVEX memory forms, U is the inverted X4.
    #[inline]
    fn late_evex(&mut self) {
        if self.mod_ != 3 && self.mode64() {
            self.rexx4 = self.ubit ^ 1;
            self.ubit = 1;
        }
    }

    #[cold]
    fn rex2(&mut self) {
        let pos = self.pos;
        if self.byte(pos) != 0xd5 {
            return;
        }
        if self.rex != 0 {
            self.fail(DecodeError::BadRexPrefix);
        }
        if pos + 1 >= self.max {
            return self.too_short_at_end();
        }
        let payload = self.byte(pos + 1);
        self.rex2 = 1;
        self.map = payload >> 7;
        self.rexr4 = payload >> 6 & 1;
        self.rexx4 = payload >> 5 & 1;
        self.rexb4 = payload >> 4 & 1;
        self.rexw = payload >> 3 & 1;
        self.rexr = payload >> 2 & 1;
        self.rexx = payload >> 1 & 1;
        self.rexb = payload & 1;
        if pos + 2 >= self.max {
            return self.too_short_at_end();
        }
        let opcode = self.byte(pos + 2);
        self.nominal_opcode = opcode;
        self.srm = opcode & 7;
        self.pos = pos + 3;
    }

    /// The opcode after a VEX, EVEX or XOP prefix (presence checked by the
    /// caller).
    fn vector_opcode(&mut self) {
        self.nominal_opcode = self.byte(self.pos);
        self.pos += 1;
    }

    #[inline]
    fn opcode(&mut self) {
        let mut pos = self.pos;
        let b = self.byte(pos);
        if b != 0x0f {
            self.map = 0;
            self.nominal_opcode = b;
            self.srm = b & 7;
            self.pos = pos + 1;
            return;
        }
        pos += 1;
        if pos >= self.max {
            self.pos = pos - 1;
            return self.too_short();
        }
        let b = self.byte(pos);
        for legacy in &LEGACY_ESCAPES {
            match legacy.second {
                None => {
                    self.nominal_opcode = b;
                    self.map = legacy.map;
                    self.srm = b & 7;
                    self.pos = pos + 1;
                    return;
                }
                Some(second) if second == b => {
                    self.map = legacy.map;
                    self.pos = pos + 1;
                    if legacy.trailing_opcode {
                        self.amd3dnow = 1;
                    } else if pos + 1 < self.max {
                        let opcode = self.byte(pos + 1);
                        self.nominal_opcode = opcode;
                        self.srm = opcode & 7;
                        self.pos = pos + 2;
                    } else {
                        self.too_short();
                    }
                    return;
                }
                Some(_) => {}
            }
        }
        self.bad_map();
    }

    #[inline]
    fn modrm<const MODE64: bool, const LEGACY: bool>(&mut self, buf: &[u8; 32], kind: u16) {
        if kind == MODRM_NONE {
            return;
        }
        // XED's codes: 1 present, 2 present but MOD ignored. `UD0` (3) has
        // ModRM unless MODE_SHORT_UD0, which no chip sets here.
        let ignore_mod = kind == MODRM_IGNORE_MOD;
        let pos = self.pos;
        if pos >= self.max {
            return self.too_short();
        }
        let b = byte_at(buf, pos);
        self.pos = pos + 1;
        let mod_ = b >> 6;
        self.mod_ = mod_;
        self.reg = (b >> 3) & 7;
        self.rm = b & 7;
        if !LEGACY && self.llrc == 3 && (mod_ != 3 || self.bcrc == 0) && self.vexvalid == 2 {
            self.fail(DecodeError::BadEvexLength);
        }
        if ignore_mod {
            return;
        }
        // 16-bit addressing: in 16-bit mode without 67, in 32-bit mode with.
        let addr16 = !MODE64 && (self.mode == 0) != (self.asz != 0) && self.mode != 2;
        let layout = if addr16 {
            entry(&MODRM16, b)
        } else {
            entry(&MODRM32, b)
        };
        self.disp_width = layout & 0x7f;
        self.has_sib = layout >> 7;
    }

    #[inline]
    fn sib(&mut self, buf: &[u8; 32]) {
        if self.has_sib == 0 {
            return;
        }
        let pos = self.pos;
        if pos >= self.max {
            return self.too_short();
        }
        let b = byte_at(buf, pos);
        self.sibscale = b >> 6;
        self.sibindex = (b >> 3) & 7;
        self.sibbase = b & 7;
        self.pos = pos + 1;
        if b & 7 == 5 && self.mod_ == 0 {
            self.disp_width = 32;
        }
    }

    /// The width entry of `rule` in `table` for this state: bits, or a
    /// `WIDTH_*` marker.
    #[inline]
    fn width<const MODE64: bool, const POINTS: usize>(
        &self,
        table: &[[u8; POINTS]],
        rule: u16,
    ) -> u8 {
        let point = (self.size_point_in::<MODE64>() * 8 + usize::from(self.reg)) * 2
            + usize::from(self.rex2);
        table
            .get(usize::from(rule))
            .and_then(|widths| widths.get(point))
            .copied()
            .unwrap_or(WIDTH_UNSET)
    }

    #[inline]
    fn displacement<const MODE64: bool>(&mut self, buf: &[u8; 32], rule: u16) {
        if rule != 0 {
            let bits = self.width::<MODE64, _>(&DISP_WIDTHS, rule);
            if bits != WIDTH_UNSET {
                self.disp_width = bits;
            }
        }
        let bytes = usize::from(self.disp_width / 8);
        if bytes == 0 {
            return;
        }
        let pos = self.pos;
        if pos + bytes > self.max {
            return self.too_short();
        }
        self.disp = read_signed(read_at(buf, pos), bytes);
        self.pos = pos + bytes;
    }

    #[inline]
    fn immediate<const MODE64: bool, const LEGACY: bool>(&mut self, buf: &[u8; 32], rule: u16) {
        if (LEGACY || self.imm_width == 0) && rule != 0 {
            match self.width::<MODE64, _>(&IMM_WIDTHS, rule) {
                WIDTH_ENTER => {
                    self.imm_width = 16;
                    self.imm1_bytes = 1;
                }
                WIDTH_MAP1_OP78 => {
                    if self.vexvalid == 0 && (self.osz != 0 || self.ild_f2 != 0) {
                        self.imm_width = 8;
                        self.imm1_bytes = 1;
                    }
                }
                WIDTH_UNSET => {}
                bits => self.imm_width = bits,
            }
        }
        let mut pos = self.pos;
        if !LEGACY && self.amd3dnow != 0 {
            if pos >= self.max {
                return self.too_short();
            }
            self.nominal_opcode = byte_at(buf, pos);
            self.pos = pos + 1;
            return;
        }
        let bytes = usize::from(self.imm_width / 8);
        if bytes == 0 {
            return;
        }
        if pos + bytes > self.max {
            return self.too_short();
        }
        let value = read_at(buf, pos);
        self.uimm0 = if bytes >= 8 {
            value
        } else {
            value & ((1 << (8 * bytes)) - 1)
        };
        if bytes == 1 {
            self.esrc = byte_at(buf, pos) >> 4;
        }
        pos += bytes;
        self.pos = pos;
        if self.imm1_bytes != 0 {
            if pos + usize::from(self.imm1_bytes) > self.max {
                return self.too_short();
            }
            self.uimm1 = byte_at(buf, pos);
            self.pos = pos + 1;
        }
    }
}

/// The byte of `buf` (an instruction's bytes, zero-padded) at `at` (below
/// 16).
#[inline]
fn byte_at(buf: &[u8; 32], at: usize) -> u8 {
    buf.get(at & 15).copied().unwrap_or(0)
}

/// Eight little-endian bytes of `buf` from `at` (zero past the input).
#[inline]
fn read_at(buf: &[u8; 32], at: usize) -> u64 {
    let at = at & 15;
    buf.get(at..at + 8)
        .and_then(|b| b.first_chunk::<8>())
        .map_or(0, |b| u64::from_le_bytes(*b))
}

/// The low `bytes` bytes of `value`, sign-extended.
#[inline]
fn read_signed(value: u64, bytes: usize) -> i64 {
    let shift = 64 - 8 * u32::try_from(bytes.min(8)).unwrap_or(8);
    (value << shift).cast_signed() >> shift
}

/// The entry of a per-opcode table.
#[inline]
#[expect(
    clippy::indexing_slicing,
    reason = "a u8 always indexes a 256-entry table"
)]
pub fn entry<T: Copy>(table: &[T; 256], opcode: u8) -> T {
    table[usize::from(opcode)]
}

/// Bytes that may be prefixes: the legacy prefixes and, in 64-bit mode,
/// REX (40–4F). A quick filter before the full prefix `match`.
const PREFIXES: [bool; 256] = prefix_table();

#[expect(
    clippy::indexing_slicing,
    reason = "index below 256 by the loop condition"
)]
const fn prefix_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut byte = 0;
    while byte < 256 {
        table[byte] = matches!(byte, 0x26 | 0x2e | 0x36 | 0x3e | 0x40..=0x4f | 0x64..=0x67 | 0xf0 | 0xf2 | 0xf3);
        byte += 1;
    }
    table
}

#[inline]
fn is_prefix(byte: u8) -> bool {
    entry(&PREFIXES, byte)
}

/// Copies fewer than 16 `bytes` to `buf` (kept out of line, so that the
/// common 16-byte copy stays a single move).
#[cold]
#[inline(never)]
fn copy_short(buf: &mut [u8; 32], bytes: &[u8]) {
    for (dest, &byte) in buf.iter_mut().zip(bytes) {
        *dest = byte;
    }
}

/// [`FRONT`] classes.
const SLOW: u8 = 0;
/// A map-0 opcode in every mode: no prefix, escape, or byte that may start
/// an encoding prefix (`C4`, `C5`, `8F`, `62`, `D5`).
pub const PLAIN: u8 = 1;
/// A REX prefix in 64-bit mode (`INC`/`DEC` otherwise: also not plain).
pub const REX: u8 = 2;
/// The `0F` escape to the other legacy maps.
pub const ESCAPE: u8 = 3;
/// 66, F2 or F3.
pub const LEGACY: u8 = 4;

/// How [`State::head`] may take a first byte.
#[expect(
    clippy::indexing_slicing,
    reason = "the loop stays below the table's 256 entries"
)]
pub const FRONT: [u8; 256] = {
    let mut table = [PLAIN; 256];
    let mut byte = 0;
    while byte < 256 {
        table[byte] = match byte {
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x67 | 0xf0 | 0xc4 | 0xc5 | 0x8f | 0x62
            | 0xd5 => SLOW,
            0x66 | 0xf2 | 0xf3 => LEGACY,
            0x40..=0x4f => REX,
            0x0f => ESCAPE,
            _ => PLAIN,
        };
        byte += 1;
    }
    table
};

/// What a ModRM byte implies with 16-bit addressing: displacement bits.
const MODRM16: [u8; 256] = modrm_layout(false);
/// With 32/64-bit addressing: displacement bits, plus 0x80 for a SIB byte.
const MODRM32: [u8; 256] = modrm_layout(true);

#[expect(
    clippy::indexing_slicing,
    reason = "index below 256 by the loop condition"
)]
const fn modrm_layout(wide: bool) -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut byte = 0;
    while byte < 256 {
        let (mod_, rm) = (byte >> 6, byte & 7);
        table[byte] = match (wide, mod_, rm) {
            (_, 1, _) => 8,
            (false, 0, 6) | (false, 2, _) => 16,
            (true, 0, 5) | (true, 2, _) => 32,
            _ => 0,
        };
        if wide && mod_ != 3 && rm == 4 {
            table[byte] |= 0x80;
        }
        byte += 1;
    }
    table
}
