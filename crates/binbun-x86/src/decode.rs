//! Full decoding: length, then which instruction it is.

pub mod flags;
pub mod flow;
pub mod format;
pub mod operand;

use flags::FlagsRule;
use flow::FlowKind;

use binbun_isa::FlowStep;

use crate::fast;
use crate::generated::form::{Attribute, Category, Extension, Form, INSTRUCTIONS, IsaSet};
use crate::generated::handlers::{HANDLERS, HANDLERS64, Handler, generic};
use crate::generated::state::{Fields, State};
use crate::{DecodeError, Mnemonic, Mode, Register, RegisterClass};

/// A set of [`Attribute`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Attributes(pub u128);

impl Attributes {
    /// Whether `attribute` is in the set.
    pub const fn contains(self, attribute: Attribute) -> bool {
        self.0 & (1 << attribute as u8) != 0
    }
}

/// What the decoder knows about one instruction of its table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionInfo {
    pub form: Form,
    pub attributes: Attributes,
    pub category: Category,
    pub extension: Extension,
    pub isa_set: IsaSet,
    /// The instruction's operand list: first index into
    /// `generated::operand::SEQUENCES`.
    pub operands: u16,
    /// Number of operands.
    pub operand_count: u8,
    /// The mnemonic in Intel syntax, lower case (`movsb` for `REP_MOVSB`,
    /// `call far` for `CALL_FAR`).
    pub intel: &'static str,
    /// Which flags record applies.
    pub flags: FlagsRule,
    /// How the instruction transfers control.
    pub flow: FlowKind,
}

/// A decoded instruction.
///
/// It keeps the decoder fields that operand values and text are read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// The instruction's number: its [`INSTRUCTIONS`] entry plus one.
    number: u16,
    fields: Fields,
}

impl Instruction {
    /// Length in bytes, 1 to 15.
    #[allow(clippy::len_without_is_empty, reason = "an instruction is never empty")]
    pub const fn len(&self) -> usize {
        self.fields.pos
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "`decode` only returns numbers of table entries"
    )]
    #[inline]
    fn info(&self) -> &'static InstructionInfo {
        &INSTRUCTIONS[usize::from(self.number) - 1]
    }

    /// The instruction's form (XED's iform).
    pub fn form(&self) -> Form {
        self.info().form
    }

    /// The instruction's mnemonic (XED's iclass).
    #[inline]
    pub fn mnemonic(&self) -> Mnemonic {
        self.info().form.mnemonic()
    }

    /// The instruction's attributes.
    pub fn attributes(&self) -> Attributes {
        self.info().attributes
    }

    /// The instruction's category.
    pub fn category(&self) -> Category {
        self.info().category
    }

    /// The ISA extension the instruction belongs to.
    pub fn extension(&self) -> Extension {
        self.info().extension
    }

    /// The feature set the instruction needs.
    pub fn isa_set(&self) -> IsaSet {
        self.info().isa_set
    }

    /// How the instruction is encoded (XED's `VEXVALID`).
    pub const fn encoding(&self) -> Encoding {
        match self.fields.vexvalid {
            1 => Encoding::Vex,
            2 => Encoding::Evex,
            3 => Encoding::Xop,
            _ => Encoding::Legacy,
        }
    }
}

/// An instruction's prefix family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// Legacy prefixes, with REX or REX2 or neither.
    Legacy,
    /// A VEX prefix.
    Vex,
    /// An EVEX prefix.
    Evex,
    /// AMD's XOP prefix.
    Xop,
}

/// Decodes the instruction at the start of `bytes`.
///
/// # Errors
///
/// As XED's `xed_decode`. Length-decoding errors come first; truncated
/// input is [`DecodeError::TooShort`], or [`DecodeError::TooLong`] when 15
/// bytes were available. Then [`DecodeError::Invalid`] when no instruction
/// has this encoding, errors of its operands, and finally the checks of
/// [`finalize`].
pub fn decode(bytes: &[u8], mode: Mode) -> Result<Instruction, DecodeError> {
    // In 64-bit mode the fast path, which falls back to a copy of the
    // reference decoder where every mode test folds.
    if mode == Mode::Bits64 {
        fast::decode(bytes)
    } else {
        decode_other(bytes, mode)
    }
}

/// What control-flow recovery needs of the instruction at the start of
/// `bytes`, which is at `address`: [`FlowStep::of`] the [`decode`]d
/// instruction, without decoding what flow does not depend on where the
/// 64-bit fast path applies.
///
/// # Errors
///
/// As [`decode`].
pub fn decode_flow(bytes: &[u8], mode: Mode, address: u64) -> Result<FlowStep, DecodeError> {
    if mode == Mode::Bits64 {
        fast::decode_flow(bytes, address)
    } else {
        decode_other(bytes, mode).map(|i| i.flow_step(address))
    }
}

/// The reference decoder outside 64-bit mode, out of line: the fast path
/// calls nothing else and needs no stack frame of its size.
#[inline(never)]
fn decode_other(bytes: &[u8], mode: Mode) -> Result<Instruction, DecodeError> {
    decode_in::<false>(bytes, mode)
}

/// [`decode`] by the reference decoder alone, without the 64-bit fast path
/// (with feature `internal-reference`, for differential fuzzing: the two must agree
/// on every input).
///
/// # Errors
///
/// As [`decode`].
#[cfg(feature = "internal-reference")]
#[doc(hidden)]
pub fn decode_reference(bytes: &[u8], mode: Mode) -> Result<Instruction, DecodeError> {
    if mode == Mode::Bits64 {
        decode_in::<true>(bytes, mode)
    } else {
        decode_other(bytes, mode)
    }
}

/// The reference decoder ([`decode`] without the fast path); `MODE64` when
/// `mode` is [`Mode::Bits64`].
#[expect(
    clippy::inline_always,
    reason = "each copy folds its mode into the inlined length decoder"
)]
#[inline(always)]
pub fn decode_in<const MODE64: bool>(bytes: &[u8], mode: Mode) -> Result<Instruction, DecodeError> {
    let mut state = State::default();
    state.load(bytes, mode);
    let table = state.head();
    let number = if state.out_of_bytes == 0 {
        handler::<MODE64>(table, state.nominal_opcode)(&mut state)
    } else {
        0
    };
    if let Some(error) = DecodeError::from_code(state.error) {
        return Err(error);
    }
    let info = usize::from(number)
        .checked_sub(1)
        .and_then(|index| INSTRUCTIONS.get(index))
        .ok_or(DecodeError::Invalid)?;
    if let Some(error) = finalize(&state, info) {
        return Err(error);
    }
    Ok(Instruction {
        number,
        fields: state.fields,
    })
}

/// The handler of `opcode` in the map with handler table `table`: a 64-bit
/// one for `MODE64` if the map has them.
#[inline]
fn handler<const MODE64: bool>(table: usize, opcode: u8) -> Handler {
    let handlers = match HANDLERS64.get(table) {
        Some(handlers) if MODE64 => Some(handlers),
        _ => HANDLERS.get(table),
    };
    handlers
        .and_then(|table| table.get(usize::from(opcode)))
        .copied()
        .unwrap_or(generic)
}

/// Instruction `number` (a number of a table entry) with `fields`, unless
/// [`finalize`] rejects it: the fast path's result.
#[expect(
    clippy::inline_always,
    reason = "with a constant `number` the checks fold away"
)]
#[inline(always)]
pub fn checked(number: u16, fields: Fields) -> Option<Instruction> {
    let info = usize::from(number)
        .checked_sub(1)
        .and_then(|index| INSTRUCTIONS.get(index))?;
    if needs_finalize(&fields, info) && finalize(&fields, info).is_some() {
        return None;
    }
    Some(Instruction { number, fields })
}

/// Whether [`finalize`] may reject an instruction.
#[inline]
fn needs_finalize(s: &Fields, info: &InstructionInfo) -> bool {
    s.lock != 0 || s.realmode != 0 || info.attributes.0 & FINALIZED != 0
}

/// The attributes that have checks in [`finalize`].
const FINALIZED: u128 = 1 << Attribute::NoSrcDestMatch as u32
    | 1 << Attribute::NoRegMatch as u32
    | 1 << Attribute::Gather as u32
    | 1 << Attribute::NoRipRel as u32;

/// XED's `xed_decode_finalize_operand_storage_fields`: encodings that decode
/// but are not allowed. A later check's error replaces an earlier one's.
fn finalize(s: &Fields, info: &InstructionInfo) -> Option<DecodeError> {
    if !needs_finalize(s, info) {
        return None;
    }
    let has = |attribute| info.attributes.contains(attribute);
    if s.lock != 0 && !has(Attribute::Locked) {
        return Some(DecodeError::BadLockPrefix);
    }
    let mut error = None;
    // AVX-512 forms with a mask register have it as the second register.
    let second = if has(Attribute::MaskopEvex) {
        s.reg3
    } else {
        s.reg1
    };
    if has(Attribute::NoSrcDestMatch) && (s.reg0 == second || s.reg0 == s.reg2) {
        error = Some(DecodeError::BadRegisterMatch);
    }
    if has(Attribute::NoRegMatch) && (s.reg0 == second || second == s.reg2 || s.reg0 == s.reg2) {
        error = Some(DecodeError::BadRegisterMatch);
    }
    if has(Attribute::Gather) {
        let id = vector_number;
        if info.extension == Extension::Avx2gather {
            // Index, destination and mask must all differ.
            let (index, dest, mask) = (id(s.index), id(s.reg0), id(s.reg1));
            if index == mask || index == dest || mask == dest {
                error = Some(DecodeError::GatherRegisters);
            }
        } else if has(Attribute::MaskopEvex) && id(s.index) == id(s.reg0) {
            error = Some(DecodeError::GatherRegisters);
        }
    }
    // BNDLDX/BNDSTX: no RIP-relative addressing in 64-bit mode.
    if has(Attribute::NoRipRel) && s.rm == 5 && s.mod_ == 0 && s.mode == 2 {
        error = Some(DecodeError::Invalid);
    }
    if s.realmode != 0
        && (s.vexvalid != 0 || has(Attribute::ProtectedMode))
        && !matches!(info.isa_set, IsaSet::Sep | IsaSet::Smx)
    {
        error = Some(DecodeError::InvalidMode);
    }
    error
}

/// A vector register's number within its class (`XMM3`, `YMM3` and `ZMM3`
/// are all 3), as XED compares gather registers; `raw` is a state register.
fn vector_number(raw: u16) -> u16 {
    let first = match Register::from_raw(raw).map(Register::class) {
        Some(RegisterClass::Zmm) => Register::ZMM0,
        Some(RegisterClass::Ymm) => Register::YMM0,
        _ => Register::XMM0,
    };
    raw.wrapping_sub(first as u16)
}
