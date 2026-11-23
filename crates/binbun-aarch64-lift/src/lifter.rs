//! What the generated code calls: everything mechanical about A64 operands,
//! written once, under one execution context (EL0 under Linux:
//! little-endian, `SCTLR_EL1.SA0` set, top-byte-ignore for data and branch
//! addresses).
//!
//! - Parameters are the operands of the encoding's own syntax
//!   ([`Instruction::encoding_operands`]), a shift written after an operand
//!   belonging to it (`x2, lsl #3` is one parameter, `#0x5, lsl #12` too):
//!   - registers: `w`*n* is the low half of `x`*n*, and a write to it zeroes
//!     the upper half; register 31 is the zero register (reads 0, writes
//!     are dropped) or, where the operand says so (`<Xn|SP>`), the stack
//!     pointer; an extension written after one (`w2, sxtw #3`) is Arm's
//!     `ExtendReg` to the width of the first parameter (`datasize`);
//!   - memory: the address is computed once, at the first access: the base
//!     (the stack pointer must be 16-byte aligned, else the SP alignment
//!     fault), plus the offset (an immediate, or a register extended or
//!     shifted as written: Arm's `ExtendReg`) unless post-indexed; the base
//!     is written back when the entry completes, unless the entry wrote a
//!     loaded value to it (CONSTRAINED UNPREDICTABLE `WBOVERLAPLD`:
//!     binbun suppresses the writeback). Accesses are at the virtual address
//!     as computed, tag included: top-byte-ignore for data is part of
//!     address translation, which the machine does (as it decides what
//!     faults), so L1 sees stack and constant addresses plainly;
//!   - immediates and labels are values known when lifting: the immediate
//!     (shifted as written) and the label's address, which a literal load
//!     reads; so are a system register operand (its encoding,
//!     `op0:op1:CRn:CRm:op2`), a `C` register of SYS (its number) and a
//!     named operand (`pldl1keep`, a barrier option, a `PSTATE` field, a
//!     BTI target: entries that do not use it as a value take their fields
//!     from the word, [`Lifter::field`]);
//!   - a condition (`csel`, `ccmp`) is no parameter: `cond()` tests it.
//! - Acquire/release, exclusive and atomic accesses fault when they cross an
//!   aligned 16-byte block (`FEAT_LSE2`, `SCTLR_EL1.nAA` clear: Arm's
//!   `AArch64.UnalignedAccessFaults`); other accesses never do.
//! - Control transfer targets have their top byte ignored as Linux's EL0
//!   does (`AArch64_BranchAddr`): cleared where bit 55 is clear (user
//!   addresses), kept where it is set (`TCR_EL1.TBI1` is clear). The
//!   program counter is architectural state, so this is L0's business.
//! - `PSTATE.BTYPE` is 0 after an instruction unless its entry sets it
//!   (indirect branches); the 0 is written first, since no lifted
//!   instruction reads it and L1 ends an instruction at its control
//!   transfer.
//!
//! Mistakes (operands the semantics cannot have, unsupported registers)
//! are collected and reported by [`Lifter::finish`].

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use binbun_aarch64::operand::{
    Extend, ExtendKind, Memory, Modifier, Offset, Register, RegisterClass, ShiftKind, Writeback,
};
use binbun_aarch64::{Condition, Instruction, Operand};
use binbun_semantics::Semantics;
use binbun_semantics::bits::Bits;
use binbun_semantics::build::Builder;
use binbun_semantics::interpret::{self, Value};
use binbun_semantics::ir::{Binary, ExprId, FloatOp, Format, RegisterId, Trap, Unary, View};

use crate::registers::{self, AARCH64, BTYPE, C, N, SP, V, Z};

/// A width or bit index as L0 takes it (out-of-range values saturate; the
/// builder reports them).
fn narrow(value: u64) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

/// The bits a branch target keeps with its top byte ignored.
const ADDRESS_BITS: u16 = 56;

/// Branch target `address` as Linux's EL0 uses it (Arm's
/// `AArch64_BranchAddr` and `AddrTop` with `TCR_EL1.TBI0` set, `TBID0` and
/// `TBI1` clear): the top byte cleared if bit 55 is clear (the lower, user
/// half); unchanged otherwise.
const fn branch_address(address: u64) -> u64 {
    if address & (1 << 55) == 0 {
        address & 0x00ff_ffff_ffff_ffff
    } else {
        address
    }
}

/// Why an instruction could not be lifted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiftError {
    /// No semantics for the instruction's encoding yet.
    Unsupported,
    /// The instruction needs something L0 does not model yet (a register
    /// class, an operand kind), or the semantics are inconsistent with it.
    Problem(String),
}

/// One parameter of an entry: an operand of the encoding's own syntax.
#[derive(Clone, Copy, Debug)]
enum Param {
    /// A register, with the shift or extension written after it.
    Register(Register, Modifier),
    Memory(Memory),
    /// An immediate, shifted as written.
    Immediate(u64),
    /// A label's address.
    Label(u64),
    /// Anything else (not lifted yet).
    Other(Operand),
}

/// The parameters of `instruction` at `address`, and problems found.
fn parameters(instruction: Instruction, address: u64) -> (Vec<Param>, Vec<String>) {
    let mut params: Vec<Param> = Vec::new();
    let mut problems = Vec::new();
    for &operand in instruction.encoding_operands().as_slice() {
        let modifier = match operand {
            Operand::Shift(shift) => Modifier::Shift(shift),
            Operand::Extend(extend) => Modifier::Extend(extend),
            Operand::Register(register) => {
                // SYS's `C` registers are fields of the encoding.
                params.push(if register.class == RegisterClass::C {
                    Param::Immediate(u64::from(register.number))
                } else {
                    Param::Register(register, Modifier::None)
                });
                continue;
            }
            Operand::Memory(memory) => {
                params.push(Param::Memory(memory));
                continue;
            }
            Operand::Immediate(immediate) => {
                params.push(Param::Immediate(immediate.value));
                continue;
            }
            Operand::Label(label) => {
                params.push(Param::Label(label.target(address)));
                continue;
            }
            // The condition is the instruction's (`cond()`), not a
            // parameter.
            Operand::Condition(_) => continue,
            Operand::SystemRegister(register) => {
                params.push(Param::Immediate(u64::from(register.encoding)));
                continue;
            }
            // A named operand (`pldl1keep`) is a parameter known when
            // lifting that no entry reads as a value: entries take its
            // field from the word.
            other @ (Operand::List(_)
            | Operand::Float(_)
            | Operand::Writeback(_)
            | Operand::Named(_)
            | Operand::Za(_)
            | Operand::ZaList(_)
            | Operand::TableSlice(_)
            | Operand::IndexedRegister(_)) => {
                params.push(Param::Other(other));
                continue;
            }
        };
        match (params.last_mut(), modifier) {
            (Some(Param::Register(_, slot @ Modifier::None)), _) => *slot = modifier,
            (Some(Param::Immediate(value)), Modifier::Shift(shift))
                if shift.kind == ShiftKind::Lsl =>
            {
                *value = value.checked_shl(u32::from(shift.amount)).unwrap_or(0);
            }
            // `msl #n`: shifted left by `n`, ones shifted in (`movi`).
            (Some(Param::Immediate(value)), Modifier::Shift(shift))
                if shift.kind == ShiftKind::Msl =>
            {
                let amount = u32::from(shift.amount);
                *value = value.checked_shl(amount).unwrap_or(0)
                    | 1u64.checked_shl(amount).map_or(u64::MAX, |bit| bit - 1);
            }
            _ => problems.push(format!("{modifier:?} after no register or immediate")),
        }
    }
    (params, problems)
}

/// Lifts one instruction: the generated code drives it.
#[derive(Debug)]
pub struct Lifter<'a> {
    /// The semantics being built.
    pub b: Builder,
    instruction: &'a Instruction,
    address: u64,
    params: Vec<Param>,
    /// The memory operand's address, once computed.
    memory_address: Option<ExprId>,
    /// The base register and its new value, written when the entry
    /// completes.
    writeback: Option<(View, ExprId)>,
    /// Constants the generated code made, by expression: control transfer
    /// targets known when lifting stay constants.
    constants: BTreeMap<ExprId, u64>,
    /// The entry leaves this word to later work ([`unlifted`](Self::unlifted)).
    unlifted: bool,
    problems: Vec<String>,
}

impl<'a> Lifter<'a> {
    /// A lifter for `instruction` at `address`.
    pub fn new(instruction: &'a Instruction, address: u64) -> Self {
        let (params, problems) = parameters(*instruction, address);
        // BTYPE's next value, 0 for every instruction lifted so far, is
        // written first: none of them reads it, and an instruction's effects
        // must come before its control transfer.
        let mut b = Builder::new();
        let zero = b.constant(2, 0);
        b.write(registers::whole(BTYPE), zero);
        Self {
            b,
            instruction,
            address,
            params,
            memory_address: None,
            writeback: None,
            constants: BTreeMap::new(),
            unlifted: false,
            problems,
        }
    }

    /// Records a problem; the lift fails at [`finish`](Self::finish).
    pub fn problem(&mut self, message: String) {
        self.problems.push(message);
    }

    /// The entry has no semantics for this word yet (state outside the
    /// modelled registers): the lift fails as [`LiftError::Unsupported`].
    pub fn unlifted(&mut self) {
        self.unlifted = true;
    }

    /// Bits `lsb..lsb + width` of the instruction word, known when lifting
    /// (the `field(lsb, width)` built-in).
    pub fn field(&self, lsb: u64, width: u64) -> u64 {
        let word = u64::from(self.instruction.word());
        let shifted = word.checked_shr(u32::try_from(lsb).unwrap_or(u32::MAX));
        let mask = 1u64.checked_shl(u32::try_from(width).unwrap_or(u32::MAX));
        shifted.unwrap_or(0) & mask.map_or(u64::MAX, |bit| bit - 1)
    }

    /// Where the syntax omits an optional register operand at its default
    /// (`ret` for `ret x30`): when the entry's `expected` parameters are one
    /// more than the operands, the register `x`*n* (*n* the 5-bit field at
    /// bit `lsb`, which holds the default) is parameter `position`.
    pub fn restore(&mut self, expected: usize, position: usize, lsb: u32) {
        if self.params.len() + 1 != expected || position > self.params.len() {
            return;
        }
        let number = u8::try_from((self.instruction.word() >> lsb) & 31).unwrap_or(31);
        let register = Register::new(RegisterClass::X, number);
        self.params
            .insert(position, Param::Register(register, Modifier::None));
    }

    fn param(&mut self, position: usize) -> Option<Param> {
        let param = self.params.get(position).copied();
        if param.is_none() {
            self.problem(format!("no operand {position}"));
        }
        param
    }

    /// The width in bits of parameter `position`: 32 for `w` registers, 64
    /// for `x` registers, immediates and labels, a SIMD and floating-point
    /// register's view's ([`registers::simd`]), the bytes accessed for
    /// memory (both registers of a pair).
    pub fn width(&self, position: usize) -> u64 {
        match self.params.get(position) {
            Some(Param::Register(register, _)) => match register.class {
                RegisterClass::W | RegisterClass::Wsp => 32,
                RegisterClass::B
                | RegisterClass::H
                | RegisterClass::S
                | RegisterClass::D
                | RegisterClass::Q
                | RegisterClass::V => {
                    registers::simd(*register).map_or(64, |view| u64::from(view.width))
                }
                RegisterClass::X
                | RegisterClass::Xsp
                | RegisterClass::Z
                | RegisterClass::P
                | RegisterClass::Pn
                | RegisterClass::Zt
                | RegisterClass::C
                | RegisterClass::Ffr => 64,
            },
            Some(Param::Memory(_)) => self
                .instruction
                .memory()
                .map_or(0, |access| u64::from(access.size) * 8),
            Some(Param::Immediate(_) | Param::Label(_) | Param::Other(_)) | None => 64,
        }
    }

    /// The value of immediate or label parameter `position`, known when
    /// lifting.
    pub fn immediate(&mut self, position: usize) -> u64 {
        match self.param(position) {
            Some(Param::Immediate(value) | Param::Label(value)) => value,
            Some(other) => {
                self.problem(format!("operand {position} ({other:?}) is not a value"));
                0
            }
            None => 0,
        }
    }

    /// Reads parameter `position`: a register (shifted as written) or
    /// memory (the access), or the value of an immediate or label.
    pub fn read(&mut self, position: usize) -> ExprId {
        match self.param(position) {
            Some(Param::Register(register, modifier)) => {
                let value = match registers::simd(register) {
                    Some(view) => self.b.read(view),
                    None => self.read_general(register),
                };
                self.modify(value, modifier)
            }
            Some(Param::Memory(memory)) => {
                let bytes = self.memory_bytes();
                let address = self.access_address(memory);
                self.b.load(address, bytes)
            }
            Some(Param::Immediate(value) | Param::Label(value)) => self.constant(64, value),
            Some(Param::Other(operand)) => {
                self.problem(format!("operand {operand:?} is not lifted yet"));
                self.b.undefined(64)
            }
            None => self.b.undefined(64),
        }
    }

    /// Writes `value` to parameter `position`: a register (a `w` register
    /// zero-extended into its `x` register; the zero register drops it; a
    /// SIMD and floating-point register as [`Self::write_simd`]) or memory
    /// (the access).
    pub fn write(&mut self, position: usize, value: ExprId) {
        match self.param(position) {
            Some(Param::Register(register, Modifier::None))
                if let Some(view) = registers::simd(register) =>
            {
                self.write_simd(register, view, value);
            }
            Some(Param::Register(register, Modifier::None)) => {
                // A loaded value written to the base suppresses its
                // writeback (`WBOVERLAPLD`, binbun's choice `WBSUPPRESS`).
                let base = registers::general(register).map(|view| registers::whole(view.register));
                if self.writeback.is_some_and(|(view, _)| Some(view) == base) {
                    self.writeback = None;
                }
                self.write_general(register, value);
            }
            Some(Param::Memory(memory)) => {
                let width = u64::from(self.b.width(value));
                if width != u64::from(self.memory_bytes()) * 8 {
                    self.problem(format!("a {width}-bit store to operand {position}"));
                }
                let address = self.access_address(memory);
                self.b.store(address, value);
            }
            Some(other) => self.problem(format!("operand {position} ({other:?}) is not written")),
            None => {}
        }
    }

    /// Reads a general-purpose register operand: 0 for the zero register.
    fn read_general(&mut self, register: Register) -> ExprId {
        let width = match register.class {
            RegisterClass::W | RegisterClass::Wsp => 32,
            RegisterClass::X | RegisterClass::Xsp => 64,
            RegisterClass::B
            | RegisterClass::H
            | RegisterClass::S
            | RegisterClass::D
            | RegisterClass::Q
            | RegisterClass::V
            | RegisterClass::Z
            | RegisterClass::P
            | RegisterClass::Pn
            | RegisterClass::Zt
            | RegisterClass::C
            | RegisterClass::Ffr => {
                self.problem(format!("{:?} registers are not lifted yet", register.class));
                return self.b.undefined(64);
            }
        };
        match registers::general(register) {
            Some(view) => self.b.read(view),
            None => self.b.constant(width, 0),
        }
    }

    /// Writes a SIMD and floating-point register operand, `view` of its
    /// `v` register: a scalar or a vector zero-extended into the whole
    /// register (Arm's `V[n, width] = value` clears the bits above it); an
    /// element (`v3.d[1]`) in place, the others kept (Arm's `Elem[...] =`).
    fn write_simd(&mut self, register: Register, view: View, value: ExprId) {
        let width = self.b.width(value);
        if width != view.width {
            self.problem(format!("a {width}-bit value written to {register:?}"));
            return;
        }
        if register.index.is_some() {
            self.b.write(view, value);
            return;
        }
        let whole = registers::whole(view.register);
        let value = self.b.zext(value, whole.width);
        self.b.write(whole, value);
    }

    /// Writes a general-purpose register operand.
    fn write_general(&mut self, register: Register, value: ExprId) {
        if register.is_zero() {
            return;
        }
        let Some(view) = registers::general(register) else {
            self.problem(format!("{:?} registers are not lifted yet", register.class));
            return;
        };
        let width = self.b.width(value);
        if width != view.width {
            self.problem(format!("a {width}-bit value written to {register:?}"));
            return;
        }
        let whole = registers::whole(view.register);
        let value = self.b.zext(value, whole.width);
        self.b.write(whole, value);
    }

    /// The `v` register holding SIMD and floating-point register parameter
    /// `position`, whole (128 bits).
    fn whole_view(&mut self, position: usize) -> Option<View> {
        let view = match self.param(position) {
            Some(Param::Register(register, _)) => registers::simd(register),
            Some(_) | None => None,
        };
        if view.is_none() {
            self.problem(format!(
                "operand {position} is no SIMD and floating-point register"
            ));
        }
        view.map(|view| registers::whole(view.register))
    }

    /// The whole `v` register (128 bits) of SIMD and floating-point register
    /// parameter `position`, read as state rather than as the operand (the
    /// `whole(op)` built-in): a scalar instruction merging its result into
    /// a register (FPCR.NEP) keeps the bits above it, also of a
    /// destination the instruction otherwise only writes.
    pub fn whole(&mut self, position: usize) -> ExprId {
        match self.whole_view(position) {
            Some(view) => self.b.read(view),
            None => self.b.undefined(128),
        }
    }

    /// Writes the whole `v` register (128 bits) of SIMD and floating-point
    /// register parameter `position` (the `write_whole(op, value)`
    /// built-in).
    pub fn write_whole(&mut self, position: usize, value: ExprId) {
        let Some(view) = self.whole_view(position) else {
            return;
        };
        let width = self.b.width(value);
        if width != view.width {
            self.problem(format!(
                "a {width}-bit value written to all of operand {position}"
            ));
            return;
        }
        self.b.write(view, value);
    }

    /// `value` shifted or extended as `modifier` says; an extension is to
    /// the width of the first parameter (Arm's `ExtendReg` to `datasize`,
    /// which the destination has).
    fn modify(&mut self, value: ExprId, modifier: Modifier) -> ExprId {
        let shift = match modifier {
            Modifier::None => return value,
            Modifier::Shift(shift) => shift,
            Modifier::Extend(extend) => {
                let width = self.width(0);
                return self.extend(value, extend, width);
            }
        };
        let op = match shift.kind {
            ShiftKind::Lsl => Binary::Shl,
            ShiftKind::Lsr => Binary::LShr,
            ShiftKind::Asr => Binary::AShr,
            ShiftKind::Ror => Binary::Ror,
            ShiftKind::Msl | ShiftKind::Mul => {
                self.problem(format!("{:?} of a general register", shift.kind));
                return value;
            }
        };
        let width = self.b.width(value);
        let amount = self.b.constant(width, u64::from(shift.amount));
        self.b.binary(op, value, amount)
    }

    /// Arm's `ExtendReg`: the low 8, 16, 32 or 64 bits of `value`, zero- or
    /// sign-extended to `width` bits, shifted left by the amount written.
    fn extend(&mut self, value: ExprId, extend: Extend, width: u64) -> ExprId {
        let (bits, signed) = match extend.kind {
            ExtendKind::Uxtb => (8, false),
            ExtendKind::Uxth => (16, false),
            ExtendKind::Uxtw => (32, false),
            ExtendKind::Uxtx => (64, false),
            ExtendKind::Sxtb => (8, true),
            ExtendKind::Sxth => (16, true),
            ExtendKind::Sxtw => (32, true),
            ExtendKind::Sxtx => (64, true),
        };
        let bits = bits.min(u64::from(self.b.width(value))).min(width);
        let low = self.bits(value, 0, bits);
        let extended = match (bits < width, signed) {
            (false, _) => low,
            (true, false) => self.zext(low, width),
            (true, true) => self.sext(low, width),
        };
        match extend.amount {
            Some(amount) if amount > 0 => {
                let amount = self.constant(width, u64::from(amount));
                self.b.binary(Binary::Shl, extended, amount)
            }
            _ => extended,
        }
    }

    /// The bytes the instruction's memory access moves.
    fn memory_bytes(&mut self) -> u16 {
        match self.instruction.memory() {
            Some(access) if access.size > 0 => narrow(u64::from(access.size)),
            _ => {
                self.problem("no fixed-size memory access".into());
                8
            }
        }
    }

    /// `bytes` bytes at byte `offset` of memory operand `position` (a
    /// register of a pair).
    pub fn load_at(&mut self, position: usize, offset: u64, bytes: u64) -> ExprId {
        let Some(address) = self.element_address(position, offset) else {
            return self.b.undefined(narrow(bytes.saturating_mul(8)));
        };
        self.b.load(address, narrow(bytes))
    }

    /// Stores `value` at byte `offset` of memory operand `position`.
    pub fn store_at(&mut self, position: usize, offset: u64, value: ExprId) {
        if let Some(address) = self.element_address(position, offset) {
            self.b.store(address, value);
        }
    }

    fn element_address(&mut self, position: usize, offset: u64) -> Option<ExprId> {
        let address = match self.param(position) {
            Some(Param::Memory(memory)) => self.access_address(memory),
            // A literal load reads at the label.
            Some(Param::Label(address)) => self.constant(64, address),
            _ => {
                self.problem(format!("operand {position} is not in memory"));
                return None;
            }
        };
        if offset == 0 {
            return Some(address);
        }
        let offset = self.b.constant(64, offset);
        Some(self.b.binary(Binary::Add, address, offset))
    }

    /// The address memory operand `position` accesses (computed as at its
    /// first access).
    pub fn address(&mut self, position: usize) -> ExprId {
        self.element_address(position, 0)
            .unwrap_or_else(|| self.b.undefined(64))
    }

    /// The alignment fault of an access that must be single-copy atomic
    /// (acquire/release, exclusive, atomic: Arm's
    /// `AArch64.UnalignedAccessFaults` with `FEAT_LSE2` and
    /// `SCTLR_EL1.nAA` clear) unless all its bytes lie in one aligned
    /// 16-byte block. Tested on the address's low 4 bits, as the SP
    /// alignment check is.
    pub fn check_alignment(&mut self, position: usize) {
        let bytes = u64::from(self.memory_bytes());
        let address = self.address(position);
        if bytes <= 1 {
            return;
        }
        let low = self.b.extract(address, 0, 4);
        let low = self.b.zext(low, 8);
        let room = self.b.constant(8, 16 - bytes.min(16));
        let crosses = self.b.binary(Binary::ULt, room, low);
        self.b.begin_if(crosses);
        self.b.trap(Trap::Alignment);
        self.b.end_if();
    }

    /// The address memory operand `memory` accesses; computed at the first
    /// access, with the SP alignment check and the writeback.
    fn access_address(&mut self, memory: Memory) -> ExprId {
        if let Some(address) = self.memory_address {
            address
        } else {
            let address = self.effective_address(memory);
            self.memory_address = Some(address);
            address
        }
    }

    /// Base plus offset (the base alone when post-indexed); records the
    /// writeback.
    fn effective_address(&mut self, memory: Memory) -> ExprId {
        let base = if memory.base.is_stack_pointer() {
            let sp = self.b.read(registers::whole(SP));
            self.check_stack_alignment(sp);
            sp
        } else {
            self.read_general(memory.base)
        };
        let offset = match memory.offset {
            Offset::None => None,
            Offset::Immediate(immediate) => Some(self.b.constant(64, immediate.value)),
            Offset::Register { index, modifier } => {
                let value = self.read_general(index);
                Some(match modifier {
                    Modifier::Extend(extend) => self.extend(value, extend, 64),
                    Modifier::None | Modifier::Shift(_) => {
                        let value = self.b.zext(value, 64);
                        self.modify(value, modifier)
                    }
                })
            }
            Offset::VectorLength(_) => {
                self.problem(format!("{:?} offsets are not lifted yet", memory.offset));
                None
            }
        };
        let sum = match offset {
            Some(offset) => self.b.binary(Binary::Add, base, offset),
            None => base,
        };
        match memory.writeback {
            Writeback::None => sum,
            Writeback::Pre => {
                self.set_writeback(memory.base, sum);
                sum
            }
            Writeback::Post => {
                self.set_writeback(memory.base, sum);
                base
            }
        }
    }

    fn set_writeback(&mut self, base: Register, value: ExprId) {
        match registers::general(base) {
            Some(view) => self.writeback = Some((registers::whole(view.register), value)),
            None => self.problem(format!("writeback to {base:?}")),
        }
    }

    /// The SP alignment fault (`SCTLR_EL1.SA0` is set) unless `sp` is a
    /// multiple of 16 (tested on its low 4 bits: no value as wide as an
    /// address is made of it, so L1 does not take the stack pointer as
    /// escaping).
    fn check_stack_alignment(&mut self, sp: ExprId) {
        let low = self.b.extract(sp, 0, 4);
        let zero = self.b.constant(4, 0);
        let misaligned = self.b.binary(Binary::Ne, low, zero);
        self.b.begin_if(misaligned);
        self.b.trap(Trap::Stack);
        self.b.end_if();
    }

    /// A control transfer's target: 64 bits, its top byte ignored
    /// ([`branch_address`]; computed when lifting for a constant).
    pub fn target(&mut self, value: ExprId) -> ExprId {
        let address = self.fit(value, 64);
        if let Some(&value) = self.constants.get(&address) {
            return self.constant(64, branch_address(value));
        }
        let upper = self.b.extract(address, ADDRESS_BITS - 1, 1);
        let low = self.b.extract(address, 0, ADDRESS_BITS);
        let cleared = self.b.zext(low, 64);
        self.b.select(upper, address, cleared)
    }

    /// The address of the next instruction (64 bits).
    pub fn next_address(&mut self) -> ExprId {
        self.constant(64, self.address.wrapping_add(4))
    }

    /// The width of register `id`.
    pub fn register_width(&self, id: RegisterId) -> u64 {
        u64::from(registers::whole(id).width)
    }

    /// Reads register `id` whole.
    pub fn read_register(&mut self, id: RegisterId) -> ExprId {
        self.b.read(registers::whole(id))
    }

    /// Writes register `id` whole.
    pub fn write_register(&mut self, id: RegisterId, value: ExprId) {
        self.b.write(registers::whole(id), value);
    }

    /// Whether the instruction's condition holds (`ConditionHolds`; 1 bit).
    pub fn condition(&mut self) -> ExprId {
        self.condition_of(&mut |l, id| l.read_register(id))
    }

    /// Whether the instruction's condition (of the flags, or of a
    /// compare-and-branch) holds for flag values `n`, `z`, `c`, `v`
    /// (`ConditionHolds` on them; 1 bit each).
    pub fn holds(&mut self, [n, z, c, v]: [ExprId; 4]) -> ExprId {
        self.condition_of(&mut |_, id| match id {
            N => n,
            Z => z,
            C => c,
            _ => v,
        })
    }

    /// `ConditionHolds` of the instruction's condition, taking the flags
    /// it needs from `flag`.
    fn condition_of(&mut self, flag: &mut dyn FnMut(&mut Self, RegisterId) -> ExprId) -> ExprId {
        let cond = match self.instruction.condition() {
            Some(Condition::Flags(cond) | Condition::Compare { cond, .. }) => cond as u8,
            Some(Condition::Zero { .. } | Condition::Bit { .. }) | None => {
                self.problem("the instruction tests no condition of the flags".into());
                return self.b.undefined(1);
            }
        };
        let base = match cond >> 1 {
            0 => flag(self, Z),
            1 => flag(self, C),
            2 => flag(self, N),
            3 => flag(self, V),
            4 => {
                let (c, z) = (flag(self, C), flag(self, Z));
                let not_z = self.b.unary(Unary::Not, z);
                self.b.binary(Binary::And, c, not_z)
            }
            5 => {
                let (n, v) = (flag(self, N), flag(self, V));
                self.b.binary(Binary::Eq, n, v)
            }
            6 => {
                let (n, v, z) = (flag(self, N), flag(self, V), flag(self, Z));
                let same = self.b.binary(Binary::Eq, n, v);
                let not_z = self.b.unary(Unary::Not, z);
                self.b.binary(Binary::And, same, not_z)
            }
            _ => self.b.constant(1, 1),
        };
        if cond & 1 == 1 && cond != 15 {
            self.b.unary(Unary::Not, base)
        } else {
            base
        }
    }

    /// The constant `value`, `width` bits wide.
    pub fn constant(&mut self, width: u64, value: u64) -> ExprId {
        let width = narrow(width);
        let id = self.b.constant(width, value);
        let truncated = if width >= 64 {
            value
        } else {
            value & ((1 << width) - 1)
        };
        self.constants.insert(id, truncated);
        id
    }

    /// The constant `value` as wide as `like`.
    pub fn literal(&mut self, like: ExprId, value: u64) -> ExprId {
        let width = self.b.width(like);
        self.constant(u64::from(width), value)
    }

    /// A value of the architecture's choice, `width` bits wide.
    pub fn undefined(&mut self, width: u64) -> ExprId {
        self.b.undefined(narrow(width))
    }

    /// A value of the architecture's choice, as wide as `like`.
    pub fn undefined_like(&mut self, like: ExprId) -> ExprId {
        let width = self.b.width(like);
        self.b.undefined(width)
    }

    /// `op` on `a`.
    pub fn unary(&mut self, op: Unary, a: ExprId) -> ExprId {
        if let Some(bits) = self.known(a)
            && let Some(folded) = self.folded(&interpret::unary(op, Value::defined(bits)))
        {
            return folded;
        }
        self.b.unary(op, a)
    }

    /// `op` on `a` and `b`: a constant if both are; `a` or `b` itself, or
    /// a constant, where the other is 0 or all ones in an and or an or.
    pub fn binary(&mut self, op: Binary, a: ExprId, b: ExprId) -> ExprId {
        match (self.known(a), self.known(b)) {
            (Some(x), Some(y)) => {
                let value = interpret::binary(op, Value::defined(x), Value::defined(y));
                if let Some(folded) = self.folded(&value) {
                    return folded;
                }
            }
            (Some(bits), None) | (None, Some(bits)) if matches!(op, Binary::And | Binary::Or) => {
                let other = if self.known(a).is_some() { b } else { a };
                let ones = bits == Bits::ones(bits.width());
                if ((op == Binary::And && bits.is_zero()) || (op == Binary::Or && ones))
                    && let Some(folded) = self.folded(&Value::defined(bits))
                {
                    return folded;
                }
                if (op == Binary::And && ones) || (op == Binary::Or && bits.is_zero()) {
                    return other;
                }
            }
            (Some(_) | None, Some(_) | None) => {}
        }
        self.b.binary(op, a, b)
    }

    /// `then` where `condition` holds, else `otherwise`: the one chosen if
    /// the condition is a constant.
    pub fn select(&mut self, condition: ExprId, then: ExprId, otherwise: ExprId) -> ExprId {
        if let Some(condition) = self.known(condition) {
            return if condition.is_zero() { otherwise } else { then };
        }
        self.b.select(condition, then, otherwise)
    }

    /// `value` zero-extended to `width` bits (a constant if it is one).
    pub fn zext(&mut self, value: ExprId, width: u64) -> ExprId {
        if let Some(bits) = self.known(value)
            && let Some(folded) = self.folded(&interpret::extend(
                false,
                Value::defined(bits),
                narrow(width),
            ))
        {
            return folded;
        }
        self.b.zext(value, narrow(width))
    }

    /// The bits of `value` if it is a constant the lift made (a value of
    /// at most 64 bits, known when lifting).
    fn known(&self, value: ExprId) -> Option<Bits> {
        let &bits = self.constants.get(&value)?;
        Some(Bits::from_u64(self.b.width(value), bits))
    }

    /// The constant an operation on constants gives, if it is one of at
    /// most 64 bits (else the operation is built).
    fn folded(&mut self, value: &Value) -> Option<ExprId> {
        let bits = value.known().filter(|bits| bits.width() <= 64)?;
        Some(self.constant(u64::from(bits.width()), bits.low_u64()))
    }

    /// `value` sign-extended to `width` bits.
    pub fn sext(&mut self, value: ExprId, width: u64) -> ExprId {
        self.b.sext(value, narrow(width))
    }

    /// The low `width` bits of `value`.
    pub fn trunc(&mut self, value: ExprId, width: u64) -> ExprId {
        self.bits(value, 0, width)
    }

    /// `value` resized to `width` bits: zero-extended or truncated.
    pub fn fit(&mut self, value: ExprId, width: u64) -> ExprId {
        if width > u64::from(self.b.width(value)) {
            self.zext(value, width)
        } else {
            self.bits(value, 0, width)
        }
    }

    /// `value` resized to `like`'s width.
    pub fn fit_like(&mut self, value: ExprId, like: ExprId) -> ExprId {
        let width = self.b.width(like);
        self.fit(value, u64::from(width))
    }

    /// The most significant bit of `value`.
    pub fn msb(&mut self, value: ExprId) -> ExprId {
        let top = self.b.width(value).saturating_sub(1);
        self.b.extract(value, top, 1)
    }

    /// Bit `index` of `value`, known at lift time.
    pub fn bit(&mut self, value: ExprId, index: u64) -> ExprId {
        self.bits(value, index, 1)
    }

    /// Bits `offset..offset + width` of `value`, known at lift time.
    pub fn bits(&mut self, value: ExprId, offset: u64, width: u64) -> ExprId {
        self.b.extract(value, narrow(offset), narrow(width))
    }

    /// Bit `index` of `value`, for an index computed at run time (bits past
    /// the width are 0).
    pub fn bit_at(&mut self, value: ExprId, index: ExprId) -> ExprId {
        let index = self.fit_like(index, value);
        let shifted = self.b.binary(Binary::LShr, value, index);
        self.b.extract(shifted, 0, 1)
    }

    /// The floating-point format `width` bits wide.
    pub fn format_of(&mut self, width: u64) -> Format {
        let width = narrow(width);
        Format::of_width(width).unwrap_or_else(|| {
            self.problem(format!("no floating-point format of {width} bits"));
            Format::Double
        })
    }

    /// The arithmetic operation numbered `code` (`farith`): add, subtract,
    /// multiply, divide.
    pub fn arith(&mut self, code: u64) -> FloatOp {
        match code {
            0 => FloatOp::Add,
            1 => FloatOp::Sub,
            2 => FloatOp::Mul,
            3 => FloatOp::Div,
            _ => {
                self.problem(format!("no arithmetic operation {code}"));
                FloatOp::Add
            }
        }
    }

    /// The floating-point operation `op` on scalar `operands`, rounded as
    /// `rounding` says: its result, or with `status` its exceptions. For
    /// [`FloatOp::FromInt`] the format is `target` bits wide; otherwise it
    /// is the operands'.
    pub fn float(
        &mut self,
        op: FloatOp,
        operands: &[ExprId],
        rounding: ExprId,
        target: Option<u16>,
        status: bool,
    ) -> ExprId {
        let first = operands.first().copied().unwrap_or(rounding);
        let width = match op {
            FloatOp::FromInt { .. } => target.unwrap_or(64),
            FloatOp::Add
            | FloatOp::Sub
            | FloatOp::Mul
            | FloatOp::Div
            | FloatOp::Sqrt
            | FloatOp::MulAdd
            | FloatOp::RoundToIntegral
            | FloatOp::Compare { .. }
            | FloatOp::Convert(_)
            | FloatOp::ToInt { .. } => self.b.width(first),
        };
        let format = self.format_of(u64::from(width));
        let rounding = self.fit(rounding, 2);
        if status {
            self.b.float_status(op, format, 1, rounding, operands)
        } else {
            self.b.float(op, format, 1, rounding, operands)
        }
    }

    /// The outputs of intrinsic `name` on `inputs`.
    pub fn intrinsic<const COUNT: usize>(
        &mut self,
        name: &str,
        inputs: &[ExprId],
    ) -> [ExprId; COUNT] {
        let declared = AARCH64
            .find_intrinsic(name)
            .and_then(|id| Some((id, AARCH64.intrinsic(id)?)));
        let outputs = match declared {
            Some((id, info)) if info.outputs.len() == COUNT => {
                self.b.intrinsic(id, inputs, info.outputs)
            }
            _ => {
                self.problem(format!("no intrinsic `{name}` with {COUNT} outputs"));
                Vec::new()
            }
        };
        core::array::from_fn(|i| match outputs.get(i) {
            Some(&output) => output,
            None => self.b.undefined(1),
        })
    }

    /// Enters the operating system.
    pub fn system_call(&mut self) {
        self.b.system_call();
    }

    /// What every completed instruction does after its entry: the base
    /// register's writeback.
    pub fn complete(&mut self) {
        if let Some((view, value)) = self.writeback.take() {
            self.b.write(view, value);
        }
    }

    /// The finished semantics.
    ///
    /// # Errors
    ///
    /// Problems recorded while lifting, or builder mistakes.
    pub fn finish(self) -> Result<Semantics, LiftError> {
        if self.unlifted {
            return Err(LiftError::Unsupported);
        }
        if !self.problems.is_empty() {
            return Err(LiftError::Problem(self.problems.join("; ")));
        }
        self.b.finish().map_err(|errors| {
            LiftError::Problem(
                errors
                    .iter()
                    .map(|e| e.0.as_str())
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        })
    }
}
