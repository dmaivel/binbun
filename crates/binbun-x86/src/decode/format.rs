//! Intel-syntax text, as XED's `xed_format_context` prints it with its
//! default options and no symbol callback (`xed-disas.c`).
//!
//! The text is: prefixes XED shows as keywords, the mnemonic, then the
//! operands that are not suppressed, in table order, separated by `, `.
//! Registers are lower case; memory operands get a size word (`dword ptr`);
//! numbers are lower-case hexadecimal without leading zeros; branch targets
//! are absolute, from the instruction's address.
//!
//! The printer collects the line in a stack buffer ([`Line`]), numbers
//! written by hand, and hands it to the formatter in one `write_str`:
//! writing token by token through `core::fmt` cost more than the rest of
//! the printer (as for the AArch64 printer).

use core::fmt::{self, Write};

use super::Instruction;
use super::flow::relative_target;
use super::operand::{OperandTemplate, Visibility};
use crate::generated::form::{Attribute, Category, IsaSet};
use crate::generated::operand::{Conversion, OperandName, OperandWidth, SEQUENCES, template};
use crate::generated::state::Fields;
use crate::{Mnemonic, Register};

use super::operand::ElementBase;

/// An instruction in Intel syntax, at an address (for branch targets).
#[derive(Debug, Clone, Copy)]
pub struct Intel<'a> {
    instruction: &'a Instruction,
    address: u64,
}

impl Instruction {
    /// The instruction in Intel syntax, as XED prints it; `address` is
    /// where the instruction is, for branch targets.
    pub const fn intel(&self, address: u64) -> Intel<'_> {
        Intel {
            instruction: self,
            address,
        }
    }

    /// The mnemonic as [`intel`](Self::intel) writes it after any prefix
    /// words, lower case (`movsb` for `REP_MOVSB`, `call far` for
    /// `CALL_FAR`).
    pub fn intel_mnemonic(&self) -> &'static str {
        self.info().intel
    }
}

impl fmt::Display for Intel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut line = Line::new();
        if self.print(&mut line).is_ok() {
            return f.write_str(line.as_str());
        }
        // Longer than any instruction's text should be: token by token.
        self.print(&mut Direct(f))
    }
}

impl Intel<'_> {
    fn print(&self, out: &mut impl Out) -> fmt::Result {
        Printer {
            instruction: self.instruction,
            s: &self.instruction.fields,
            out,
            emitted: false,
            address: self.address,
        }
        .instruction()
    }
}

/// Where the printer writes: text, and numbers it writes itself.
trait Out: Write {
    /// `value` in lower-case hexadecimal without leading zeros.
    fn hex(&mut self, value: u64) -> fmt::Result;

    /// `value` in decimal.
    fn decimal(&mut self, value: u64) -> fmt::Result;
}

/// Any text writer, with numbers through `core::fmt`.
struct Direct<'a, W: Write + ?Sized>(&'a mut W);

impl<W: Write + ?Sized> Write for Direct<'_, W> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0.write_str(text)
    }
}

impl<W: Write + ?Sized> Out for Direct<'_, W> {
    fn hex(&mut self, value: u64) -> fmt::Result {
        write!(self.0, "{value:x}")
    }

    fn decimal(&mut self, value: u64) -> fmt::Result {
        write!(self.0, "{value}")
    }
}

/// A line of ASCII text on the stack; writing past its end fails.
struct Line {
    bytes: [u8; LINE],
    len: usize,
}

/// Bytes of a [`Line`]: more than any instruction's text.
const LINE: usize = 128;

impl Line {
    const fn new() -> Self {
        Self {
            bytes: [0; LINE],
            len: 0,
        }
    }

    /// The next `n` bytes, appended, for the caller to fill with ASCII.
    fn reserve(&mut self, n: usize) -> Result<&mut [u8], fmt::Error> {
        let start = self.len;
        let bytes = self.bytes.get_mut(start..start + n).ok_or(fmt::Error)?;
        self.len = start + n;
        Ok(bytes)
    }

    fn as_str(&self) -> &str {
        // Validated in whole 16-byte blocks, which `from_utf8` checks for
        // ASCII a word at a time; the bytes after `len` are zeros.
        let validated = self.len.next_multiple_of(16).min(LINE);
        self.bytes
            .get(..validated)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .and_then(|text| text.get(..self.len))
            .unwrap_or_default()
    }
}

impl Write for Line {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        copy(self.reserve(text.len())?, text.as_bytes());
        Ok(())
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        let byte = u8::try_from(c).map_err(|_| fmt::Error)?;
        *self.reserve(1)?.first_mut().ok_or(fmt::Error)? = byte;
        Ok(())
    }
}

impl Out for Line {
    fn hex(&mut self, value: u64) -> fmt::Result {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let digits = (64 - value.leading_zeros()).div_ceil(4).max(1) as usize;
        let mut rest = value;
        for digit in self.reserve(digits)?.iter_mut().rev() {
            let nibble = usize::from(u8::try_from(rest & 15).unwrap_or_default());
            *digit = DIGITS.get(nibble).copied().unwrap_or_default();
            rest >>= 4;
        }
        Ok(())
    }

    fn decimal(&mut self, value: u64) -> fmt::Result {
        let digits = value.checked_ilog10().unwrap_or(0) as usize + 1;
        let mut rest = value;
        for digit in self.reserve(digits)?.iter_mut().rev() {
            *digit = b'0' + u8::try_from(rest % 10).unwrap_or_default();
            rest /= 10;
        }
        Ok(())
    }
}

/// Copies `source` to `target`, of the same length: pieces of text are
/// short, and two overlapping fixed-size copies cost less than a call of
/// `memcpy`.
fn copy(target: &mut [u8], source: &[u8]) {
    fn halves<const N: usize>(target: &mut [u8], source: &[u8]) {
        if let (Some(target), Some(source)) = (target.first_chunk_mut::<N>(), source.first_chunk())
        {
            *target = *source;
        }
        if let (Some(target), Some(source)) = (target.last_chunk_mut::<N>(), source.last_chunk()) {
            *target = *source;
        }
    }
    match source.len() {
        0 => {}
        1 => halves::<1>(target, source),
        2..4 => halves::<2>(target, source),
        4..8 => halves::<4>(target, source),
        8..=16 => halves::<8>(target, source),
        _ => target.copy_from_slice(source),
    }
}

/// The formatter's state while printing (XED's `xed_print_info_t`).
struct Printer<'a, 'f, W: Out> {
    instruction: &'a Instruction,
    s: &'a Fields,
    out: &'f mut W,
    /// Whether something was printed that a separator must follow.
    emitted: bool,
    address: u64,
}

impl<W: Out> Printer<'_, '_, W> {
    fn has(&self, attribute: Attribute) -> bool {
        self.instruction.attributes().contains(attribute)
    }

    /// The instruction's operand templates (static order).
    fn templates(&self) -> &'static [u16] {
        let info = self.instruction.info();
        let (first, count) = (usize::from(info.operands), usize::from(info.operand_count));
        SEQUENCES.get(first..first + count).unwrap_or_default()
    }

    fn instruction(&mut self) -> fmt::Result {
        self.prefixes()?;
        self.out.write_str(self.instruction.info().intel)?;
        if self.has(Attribute::DefaultFlags) {
            self.out.write_char(' ')?;
            self.out.write_str(Conversion::Dfvstr.text(self.s))?;
        }
        let templates = self.templates();
        if !templates.is_empty() {
            self.out.write_char(' ')?;
        }
        let mut extra_index = None;
        let mut skip = false;
        for (position, &index) in templates.iter().enumerate() {
            if skip {
                skip = false;
            } else {
                skip = self.operand(position, template(index), &mut extra_index)?;
            }
        }
        if let Some(index) = extra_index {
            self.spacer()?;
            self.register(Some(index), false)?;
        }
        Ok(())
    }

    /// XED's `xed_decoded_inst_dump_common_pre_mne`.
    fn prefixes(&mut self) -> fmt::Result {
        let s = self.s;
        let long_mode = s.mode == 2;
        let atomic = self.has(Attribute::Locked) || self.has(Attribute::Atomic);
        let mut words: [&str; 8] = [""; 8];
        let mut count = 0;
        let mut push = |word| {
            if let Some(slot) = words.get_mut(count) {
                *slot = word;
                count += 1;
            }
        };
        if self.has(Attribute::MpxPrefixAble) && s.rep == 2 {
            push("bnd");
        }
        if self.has(Attribute::HleAcqAble) && s.rep == 2 && atomic {
            push("xacquire");
        }
        if self.has(Attribute::HleRelAble)
            && s.rep == 3
            && (atomic || self.instruction.mnemonic() == Mnemonic::Mov)
        {
            push("xrelease");
        }
        if s.lock != 0 {
            push("lock");
        }
        if self.has(Attribute::Rep) && matches!(s.rep, 2 | 3) {
            push(if s.rep == 3 { "rep" } else { "repne" });
        } else {
            match s.hint {
                3 => push("hint-not-taken"),
                4 => push("hint-taken"),
                5 => push("notrack"),
                _ => {}
            }
        }
        if s.asz != 0 && !self.explicit_memory_operand() {
            push(if long_mode || s.mode == 0 {
                "addr32"
            } else {
                "addr16"
            });
        }
        if s.osz != 0 && !self.explicit_operand() {
            push(if long_mode || s.mode == 1 {
                "data16"
            } else {
                "data32"
            });
        }
        if self.has(Attribute::ApxNf) {
            push("{nf}");
        }
        for word in words.iter().take(count) {
            self.out.write_str(word)?;
            self.out.write_char(' ')?;
        }
        Ok(())
    }

    /// Whether a memory operand is printed (XED's
    /// `xed_decoded_inst_explicit_memop`).
    fn explicit_memory_operand(&self) -> bool {
        self.templates().iter().any(|&index| {
            let t = template(index);
            matches!(
                t.name,
                OperandName::Mem0 | OperandName::Mem1 | OperandName::Agen
            ) && (t.visibility != Visibility::Suppressed || self.string_memory(t))
        })
    }

    /// Whether an operand is printed (XED's `xed_decoded_inst_explicit_operand`).
    fn explicit_operand(&self) -> bool {
        self.templates().iter().any(|&index| {
            let t = template(index);
            t.visibility != Visibility::Suppressed || self.string_memory(t)
        })
    }

    /// A string instruction's memory operand, printed though suppressed.
    fn string_memory(&self, t: &OperandTemplate) -> bool {
        self.instruction.category() == Category::Stringop
            && matches!(t.name, OperandName::Mem0 | OperandName::Mem1)
    }

    fn spacer(&mut self) -> fmt::Result {
        if self.emitted {
            self.out.write_str(", ")?;
        }
        Ok(())
    }

    /// Operand `position` (template `t`); returns whether the next operand
    /// (a write mask printed here) is to be skipped. XED's
    /// `xed_print_operand`.
    fn operand(
        &mut self,
        position: usize,
        t: &OperandTemplate,
        extra_index: &mut Option<Register>,
    ) -> Result<bool, fmt::Error> {
        let s = self.s;
        if t.visibility == Visibility::Suppressed && !self.string_memory(t) {
            // A suppressed memory operand with a segment override shows
            // the segment.
            let segment = if t.name == OperandName::Mem0 && s.using_default_segment0 == 0 {
                Register::from_raw(s.seg0)
            } else if t.name == OperandName::Mem1 && s.using_default_segment1 == 0 {
                Register::from_raw(s.seg1)
            } else {
                None
            };
            if let Some(segment) = segment {
                self.spacer()?;
                self.out.write_str(segment.name())?;
                self.emitted = true;
            }
            return Ok(false);
        }
        let implicit = t.visibility == Visibility::Implicit;
        self.spacer()?;
        self.emitted = true;
        let mut skip = false;
        match t.name {
            OperandName::Agen | OperandName::Mem0 => {
                skip = self.memory0(position, t, extra_index)?;
            }
            OperandName::Mem1 => self.memory1(position)?,
            OperandName::Imm0 => self.immediate(position)?,
            OperandName::Imm1 => {
                self.out.write_str("0x")?;
                hex(self.out, u64::from(s.uimm1), 8)?;
            }
            OperandName::Ptr | OperandName::Absbr => {
                self.out.write_str("0x")?;
                hex(self.out, s.disp.cast_unsigned(), u32::from(s.brdisp_width))?;
            }
            OperandName::Relbr => self.relative_branch()?,
            OperandName::Reg0
            | OperandName::Reg1
            | OperandName::Reg2
            | OperandName::Reg3
            | OperandName::Reg4
            | OperandName::Reg5
            | OperandName::Reg6
            | OperandName::Reg7
            | OperandName::Reg8
            | OperandName::Reg9
            | OperandName::Base0
            | OperandName::Base1 => {
                self.register(self.register_of(t.name), implicit)?;
                skip = self.write_mask(position)?;
            }
        }
        self.decorations(t)?;
        Ok(skip)
    }

    fn register_of(&self, name: OperandName) -> Option<Register> {
        let s = self.s;
        Register::from_raw(match name {
            OperandName::Reg0 => s.reg0,
            OperandName::Reg1 => s.reg1,
            OperandName::Reg2 => s.reg2,
            OperandName::Reg3 => s.reg3,
            OperandName::Reg4 => s.reg4,
            OperandName::Reg5 => s.reg5,
            OperandName::Reg6 => s.reg6,
            OperandName::Reg7 => s.reg7,
            OperandName::Reg8 => s.reg8,
            OperandName::Reg9 => s.reg9,
            OperandName::Base0 => s.base0,
            OperandName::Base1 => s.base1,
            OperandName::Mem0
            | OperandName::Mem1
            | OperandName::Agen
            | OperandName::Imm0
            | OperandName::Imm1
            | OperandName::Relbr
            | OperandName::Absbr
            | OperandName::Ptr => 0,
        })
    }

    /// A register; an implicit `ST0` is `st` (XED's `print_reg`).
    fn register(&mut self, register: Option<Register>, implicit: bool) -> fmt::Result {
        match register {
            Some(Register::ST0) if implicit => self.out.write_str("st"),
            Some(register) => self.out.write_str(register.name()),
            None => self.out.write_str("invalid"),
        }
    }

    /// After the first operand: the AVX-512 write mask that is the next
    /// operand, `{k1}`, with its decorations (none for `k0`). Returns
    /// whether the next operand was such a mask, to be skipped.
    fn write_mask(&mut self, position: usize) -> Result<bool, fmt::Error> {
        if position != 0 {
            return Ok(false);
        }
        let Some(&next) = self.templates().get(1) else {
            return Ok(false);
        };
        let mask = template(next);
        if !mask.writemask {
            return Ok(false);
        }
        let register = self.register_of(mask.name);
        if register != Some(Register::K0) {
            self.out.write_char('{')?;
            self.register(register, false)?;
            self.out.write_char('}')?;
            self.decorations(mask)?;
        }
        Ok(true)
    }

    fn decorations(&mut self, t: &OperandTemplate) -> fmt::Result {
        for &conversion in t.conversions {
            if let Conversion::Multireg(count) = conversion {
                self.out.write_char('+')?;
                self.out.decimal(u64::from(count.saturating_sub(1)))?;
            } else {
                self.out.write_str(conversion.text(self.s))?;
            }
        }
        Ok(())
    }

    /// Bits of operand `position` (XED's `xed_decoded_inst_operand_length_bits`).
    fn length_bits(&self, position: usize) -> u32 {
        self.instruction.operand_bits(position)
    }

    /// Bits of one element of operand `position` (XED's
    /// `xed_decoded_inst_operand_element_size_bits`).
    fn element_bits(&self, position: usize) -> u32 {
        let Some(&index) = self.templates().get(position) else {
            return 0;
        };
        let t = template(index);
        let element = t.element_type;
        if element.bits() != 0 {
            return u32::from(element.bits());
        }
        match element.base() {
            ElementBase::Struct | ElementBase::Int | ElementBase::Uint => {
                self.length_bits(position)
            }
            ElementBase::Variable => u32::from(self.s.element_size),
            ElementBase::Int8
            | ElementBase::Uint8
            | ElementBase::Float16
            | ElementBase::Single
            | ElementBase::Double
            | ElementBase::Longdouble
            | ElementBase::Longbcd
            | ElementBase::Bfloat16
            | ElementBase::Bfloat8
            | ElementBase::Bfloat6
            | ElementBase::Bfloat4
            | ElementBase::Hfloat8
            | ElementBase::Hfloat6 => {
                if t.name.is_register() {
                    self.length_bits(position)
                } else {
                    0
                }
            }
        }
    }

    /// `MEM0` or `AGEN`; returns whether a write mask after it is to be
    /// skipped.
    fn memory0(
        &mut self,
        position: usize,
        t: &OperandTemplate,
        extra_index: &mut Option<Register>,
    ) -> Result<bool, fmt::Error> {
        let s = self.s;
        let agen = t.name == OperandName::Agen;
        let base = Register::from_raw(s.base0);
        let index = Register::from_raw(s.index);
        let bytes = self.length_bits(position) >> 3;
        if !agen && t.width != OperandWidth::Mprefetch {
            self.out.write_str(pointer_name(bytes))?;
        }
        if !self.amx() || bytes != 0 {
            self.out.write_str("ptr ")?;
        }
        if !agen
            && s.using_default_segment0 == 0
            && let Some(segment) = Register::from_raw(s.seg0)
        {
            self.out.write_str(segment.name())?;
            self.out.write_char(':')?;
        }
        self.out.write_char('[')?;
        let mut started = false;
        if let Some(base) = base {
            self.out.write_str(base.name())?;
            started = true;
        }
        if let Some(index) = index {
            if self.has(Attribute::IndexRegIsPointer) {
                *extra_index = Some(index);
            } else {
                if started {
                    self.out.write_char('+')?;
                }
                started = true;
                self.out.write_str(index.name())?;
                self.out.write_char('*')?;
                self.out.decimal(u64::from(s.scale))?;
            }
        }
        let no_base_index = base.is_none() && index.is_none();
        if s.brdisp_width == 0 && s.disp_width != 0 {
            let mut disp = memory_displacement(s);
            let mut bits = displacement_bits(s);
            if bits != 0 && (disp != 0 || no_base_index) {
                let negative = disp < 0;
                if started {
                    if negative {
                        self.out.write_char('-')?;
                        disp = disp.wrapping_neg();
                    } else {
                        self.out.write_char('+')?;
                    }
                }
                self.out.write_str("0x")?;
                if no_base_index && negative && s.easz == 3 {
                    bits = 64;
                }
                hex(self.out, disp.cast_unsigned(), bits)?;
            }
        }
        self.out.write_char(']')?;
        self.write_mask(position)
    }

    /// `MEM1`: segment and base only.
    fn memory1(&mut self, position: usize) -> fmt::Result {
        let s = self.s;
        let bytes = self.length_bits(position) >> 3;
        self.out.write_str(pointer_name(bytes))?;
        if !self.amx() || bytes != 0 {
            self.out.write_str("ptr ")?;
        }
        if s.using_default_segment1 == 0
            && let Some(segment) = Register::from_raw(s.seg1)
        {
            self.out.write_str(segment.name())?;
            self.out.write_char(':')?;
        }
        self.out.write_char('[')?;
        if let Some(base) = Register::from_raw(s.base1) {
            self.out.write_str(base.name())?;
        }
        self.out.write_char(']')
    }

    fn immediate(&mut self, position: usize) -> fmt::Result {
        let s = self.s;
        self.out.write_str("0x")?;
        if s.imm0signed != 0 {
            // Truncated to 32 bits, then sign-extended, as XED does.
            #[expect(clippy::cast_possible_truncation, reason = "XED's (xed_int32_t) cast")]
            let value = i64::from(signed_immediate(s) as i32);
            hex(
                self.out,
                value.cast_unsigned(),
                self.signed_immediate_bits(),
            )
        } else {
            hex(self.out, s.uimm0, self.element_bits(position))
        }
    }

    /// Width a signed immediate is shown at (XED's
    /// `xed_get_imm_sign_extend_display_bits`).
    fn signed_immediate_bits(&self) -> u32 {
        let s = self.s;
        if s.vexvalid == 2 {
            let element = self.element_bits(0);
            let immediate = u32::from(s.imm_width);
            if element > immediate {
                return element;
            }
            if immediate != 0 {
                return immediate;
            }
        }
        if self.has(Attribute::Byteop) {
            8
        } else {
            self.instruction.operand_width()
        }
    }

    /// XED's `print_rel_sym` for a branch, without symbols.
    fn relative_branch(&mut self) -> fmt::Result {
        let s = self.s;
        let displacement = if matches!(s.brdisp_width, 8 | 16 | 32 | 64) {
            s.disp
        } else {
            0
        };
        let target = relative_target(self.instruction, self.address, displacement);
        self.out.write_str("0x")?;
        hex(self.out, target, if s.mode == 2 { 64 } else { 32 })
    }

    /// XED's `xed_classify_amx`.
    fn amx(&self) -> bool {
        matches!(
            self.instruction.isa_set(),
            IsaSet::Ace1
                | IsaSet::AmxAvx512
                | IsaSet::AmxBf16
                | IsaSet::AmxComplex
                | IsaSet::AmxFp16
                | IsaSet::AmxFp8
                | IsaSet::AmxInt8
                | IsaSet::AmxMovrs
                | IsaSet::AmxTile
                | IsaSet::AmxTileBase
                | IsaSet::ApxFAmx
                | IsaSet::ApxFAmxBase
                | IsaSet::ApxFAmxMovrs
        )
    }
}

/// The first immediate sign-extended from its width.
fn signed_immediate(s: &Fields) -> i64 {
    let raw = s.uimm0;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "sign extension from the low bits"
    )]
    match s.imm_width {
        8 => i64::from(raw as i8),
        16 => i64::from(raw as i16),
        32 => i64::from(raw as i32),
        64 => raw.cast_signed(),
        _ => 0,
    }
}

/// The memory displacement, scaled for EVEX compressed displacements.
fn memory_displacement(s: &Fields) -> i64 {
    match s.disp_width {
        8 if s.nelem != 0 => s.disp * ((i64::from(s.nelem) * i64::from(s.element_size)) >> 3),
        8 | 16 | 32 | 64 => s.disp,
        _ => 0,
    }
}

/// The width a memory displacement is shown at (XED's
/// `xed_operand_values_get_memory_displacement_length_bits`).
fn displacement_bits(s: &Fields) -> u32 {
    if s.disp_width == 8 && s.nelem != 0 && u32::from(s.element_size) * u32::from(s.nelem) > 1 {
        16
    } else {
        u32::from(s.disp_width)
    }
}

/// XED's `xed_pointer_name`: the size word of a memory operand.
fn pointer_name(bytes: u32) -> &'static str {
    match bytes {
        1 => "byte ",
        2 => "word ",
        4 => "dword ",
        8 => "qword ",
        16 => "xmmword ",
        32 => "ymmword ",
        64 => "zmmword ",
        _ => "",
    }
}

/// `value` masked to `bits` (all of it at 64; x86 shift semantics above),
/// in lower-case hexadecimal without leading zeros (XED's
/// `xed_itoa_hex_ul`).
fn hex(out: &mut impl Out, value: u64, bits: u32) -> fmt::Result {
    let masked = if bits == 64 {
        value
    } else {
        value & ((1u64 << (bits & 63)) - 1)
    };
    out.hex(masked)
}
