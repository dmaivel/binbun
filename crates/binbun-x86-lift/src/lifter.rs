//! What the generated code calls: everything mechanical about x86 operands
//! and flags, written once.
//!
//! - Operands by position (the decoder's [`Instruction::operands`] order):
//!   registers with x86's write rules (32-bit writes zero the upper half of
//!   a 64-bit register; 8- and 16-bit writes merge; a legacy SSE write to a
//!   vector register keeps the bits above it, a VEX or EVEX write zeroes
//!   them; `st(i)` is the physical x87 register `(top + i) mod 8`), memory
//!   through an
//!   effective address computed once per operand (base, index × scale,
//!   displacement, address size, `FS`/`GS` base), immediates extended as
//!   the instruction extends them, branch targets as addresses.
//! - Flags as 1-bit registers; at the end, the flags XED says the
//!   instruction sets, clears or leaves undefined and the semantics did not
//!   compute.
//! - Sites ([`crate::site`]): each undefined value the semantics or XED's
//!   flags make is its site's, with the site's inputs, found when the lift
//!   finishes (the operands as read, the values the entry defines).
//! - The stack (`push`, `pop`) and the condition of `Jcc`/`SETcc`/`CMOVcc`.
//!
//! Mistakes (operands the semantics cannot have, unsupported registers)
//! are collected and reported by [`Lifter::finish`].

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use binbun_semantics::Bits;
use binbun_semantics::Semantics;
use binbun_semantics::build::Builder;
use binbun_semantics::ir::{
    Binary, ExprId, FloatOp, Format, LaneOp, RegisterId, SiteId, Trap, Unary, View,
};
use binbun_x86::{
    Attribute, Condition, Encoding, Flag, FlagAction, FlagSet, Instruction, Memory, Mode, Operand,
    OperandName, Register, RegisterClass, Value, Visibility, relative_target,
};

use crate::registers::{self, FPR0, FS_BASE, FTOP, GS_BASE, MXCSR, RSP, X86};
use crate::site::{Input, Output};
use crate::sites::SITES;

/// Where a register operand lives.
#[derive(Clone, Copy, Debug)]
enum Place {
    /// A view of an L0 register.
    View(View),
    /// `st(i)`.
    Stack(u8),
}

/// A width or bit index as L0 takes it (out-of-range values saturate; the
/// builder reports them).
fn narrow(value: u64) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

/// Why an instruction could not be lifted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiftError {
    /// No semantics for the instruction's form yet.
    Unsupported,
    /// Only 64-bit mode is lifted so far.
    Mode(Mode),
    /// The instruction needs something L0 does not model yet (a register
    /// class, an operand kind), or the semantics are inconsistent with it.
    Problem(String),
}

/// Lifts one instruction: the generated code drives it.
#[derive(Debug)]
pub struct Lifter<'a> {
    /// The semantics being built.
    pub b: Builder,
    instruction: &'a Instruction,
    address: u64,
    /// Effective addresses of `MEM0` and `MEM1` once computed.
    addresses: [Option<ExprId>; 2],
    /// Inside `lanes(count, ...)`: the number of lanes.
    lanes: Option<u16>,
    problems: Vec<String>,
    /// Operands and flags read before the entry wrote them (the first
    /// read): their values as the instruction reads them.
    read: Vec<Seen>,
    /// Operands and flags written (the last write).
    written: Vec<Seen>,
    /// The undefined values of sites, some of whose inputs are found at the
    /// end.
    sites: Vec<Pending>,
}

/// An operand (by position) or a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Operand(usize),
    Flag(Flag),
}

/// A value read from or written to a [`Slot`], and the blocks open then
/// ([`Builder::scope`]).
#[derive(Debug)]
struct Seen {
    slot: Slot,
    value: ExprId,
    scope: Vec<u32>,
}

/// An undefined value of a site, with its inputs as far as they are known
/// when it is made.
#[derive(Debug)]
struct Pending {
    undefined: ExprId,
    site: SiteId,
    /// The blocks open where it is made.
    scope: Vec<u32>,
    /// Each input: its value, or the slot whose last write it is (one the
    /// entry writes after it made the value).
    inputs: Vec<Result<ExprId, Slot>>,
}

impl<'a> Lifter<'a> {
    /// A lifter for `instruction` at `address`.
    pub fn new(instruction: &'a Instruction, address: u64) -> Self {
        Self {
            b: Builder::new(),
            instruction,
            address,
            addresses: [None, None],
            lanes: None,
            problems: Vec::new(),
            read: Vec::new(),
            written: Vec::new(),
            sites: Vec::new(),
        }
    }

    /// Operations from here to [`end_lanes`](Self::end_lanes) apply lane
    /// by lane, on `count` lanes of each operand.
    pub fn begin_lanes(&mut self, count: u64) {
        if self.lanes.is_some() {
            self.problem("`lanes` inside `lanes`".into());
        }
        self.lanes = Some(narrow(count).max(1));
    }

    /// Ends [`begin_lanes`](Self::begin_lanes).
    pub fn end_lanes(&mut self) {
        self.lanes = None;
    }

    /// In lane mode, the number of lanes (`value` must split into them).
    fn lane_count(&mut self, value: ExprId) -> Option<u16> {
        let count = self.lanes?;
        let total = self.b.width(value);
        if !total.is_multiple_of(count) {
            self.problem(format!("{total} bits do not split into {count} lanes"));
        }
        Some(count)
    }

    /// `value` (one lane's worth) repeated `count` times.
    fn broadcast(&mut self, value: ExprId, count: u16) -> ExprId {
        let mut result = value;
        for _ in 1..count {
            result = self.b.concat(value, result);
        }
        result
    }

    /// In lane mode, `value` made as wide as `like`: repeated per lane if
    /// it is one lane wide.
    fn lane_like(&mut self, value: ExprId, like: ExprId, count: u16) -> ExprId {
        let (own, wanted) = (self.b.width(value), self.b.width(like));
        if own != wanted && u32::from(own) * u32::from(count) == u32::from(wanted) {
            self.broadcast(value, count)
        } else {
            value
        }
    }

    /// `op` on `a` (lane by lane in lane mode).
    pub fn unary(&mut self, op: Unary, a: ExprId) -> ExprId {
        match self.lane_count(a) {
            Some(count) => self.b.lanes(LaneOp::Unary(op), count, &[a]),
            None => self.b.unary(op, a),
        }
    }

    /// `op` on `a` and `b` (lane by lane in lane mode, where either may be
    /// one lane, repeated).
    pub fn binary(&mut self, op: Binary, a: ExprId, b: ExprId) -> ExprId {
        match self.lanes {
            Some(count) => {
                let b = self.lane_like(b, a, count);
                let a = self.lane_like(a, b, count);
                self.b.lanes(LaneOp::Binary(op), count, &[a, b])
            }
            None => self.b.binary(op, a, b),
        }
    }

    /// `then` where `condition` holds, else `otherwise` (lane by lane in
    /// lane mode, on a condition bit per lane, or one for all).
    pub fn select(&mut self, condition: ExprId, then: ExprId, otherwise: ExprId) -> ExprId {
        match self.lanes {
            Some(count) => {
                let otherwise = self.lane_like(otherwise, then, count);
                let then = self.lane_like(then, otherwise, count);
                let condition = if self.b.width(condition) == 1 {
                    self.broadcast(condition, count)
                } else {
                    condition
                };
                self.b
                    .lanes(LaneOp::Select, count, &[condition, then, otherwise])
            }
            None => self.b.select(condition, then, otherwise),
        }
    }

    /// The format of `width`-bit values.
    fn format(&mut self, width: u16) -> Format {
        Format::of_width(width).unwrap_or_else(|| {
            self.problem(format!("no floating-point format of {width} bits"));
            Format::Double
        })
    }

    /// The floating-point operation `op` on `operands` (lane by lane in
    /// lane mode), rounded as `rounding` says: its result, or with `status`
    /// its exceptions. For [`FloatOp::FromInt`], `format` is the result's;
    /// otherwise the operands' format comes from their (lanes') width.
    pub fn float(
        &mut self,
        op: FloatOp,
        operands: &[ExprId],
        rounding: ExprId,
        target: Option<u16>,
        status: bool,
    ) -> ExprId {
        let first = operands.first().copied().unwrap_or(rounding);
        let count = self.lane_count(first).unwrap_or(1);
        let lane = self.b.width(first) / count.max(1);
        let format = match op {
            FloatOp::FromInt { .. } => {
                let width = target.unwrap_or(64);
                self.format(width)
            }
            FloatOp::Add
            | FloatOp::Sub
            | FloatOp::Mul
            | FloatOp::Div
            | FloatOp::Sqrt
            | FloatOp::MulAdd
            | FloatOp::RoundToIntegral
            | FloatOp::Compare { .. }
            | FloatOp::Convert(_)
            | FloatOp::ToInt { .. } => self.format(lane),
        };
        // The rounding is one for all lanes.
        let saved = self.lanes.take();
        let rounding = self.fit(rounding, 2);
        self.lanes = saved;
        if status {
            self.b.float_status(op, format, count, rounding, operands)
        } else {
            self.b.float(op, format, count, rounding, operands)
        }
    }

    /// The format `width` bits wide, for conversions.
    pub fn format_of(&mut self, width: u64) -> Format {
        self.format(narrow(width))
    }

    /// The arithmetic operation numbered `code`: add, subtract, multiply,
    /// divide.
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

    /// x87 push: TOP decreases (the semantics write the new `st(0)` and its
    /// tag).
    pub fn fpush(&mut self) {
        let top = self.read_register(FTOP);
        let one = self.b.constant(3, 1);
        let new = self.b.binary(Binary::Sub, top, one);
        self.write_register(FTOP, new);
    }

    /// x87 pop: TOP increases (the semantics free the old `st(0)`'s tag).
    pub fn fpop(&mut self) {
        let top = self.read_register(FTOP);
        let one = self.b.constant(3, 1);
        let new = self.b.binary(Binary::Add, top, one);
        self.write_register(FTOP, new);
    }

    /// Records a problem; the lift fails at [`finish`](Self::finish).
    pub fn problem(&mut self, message: String) {
        self.problems.push(message);
    }

    /// The operand size in bits: 8 for byte instructions, else the
    /// effective operand size (XED's `xed_decoded_inst_get_operand_width`).
    pub fn osz(&self) -> u64 {
        if self.instruction.attributes().contains(Attribute::Byteop) {
            8
        } else {
            u64::from(self.instruction.operand_width())
        }
    }

    /// The effective address size in bits.
    pub fn asz(&self) -> u64 {
        u64::from(self.instruction.address_width())
    }

    /// The stack address size in bits.
    pub fn ssz(&self) -> u64 {
        u64::from(self.instruction.stack_address_width())
    }

    /// The address of the next instruction (64 bits).
    pub fn next_address(&mut self) -> ExprId {
        let next = self.address.wrapping_add(self.instruction.len() as u64);
        self.b.constant(64, next)
    }

    /// Runs the instruction again: a jump to its own address (an iteration
    /// of a `rep` string operation, which the processor also runs, and
    /// interrupts, one element at a time).
    pub fn repeat(&mut self) {
        let here = self.b.constant(64, self.address);
        self.b.jump(here);
    }

    /// `full` (rsi or rdi) at the address size: XED's `ArSI()`, `ArDI()`.
    pub fn address_register(&self, full: Register) -> Register {
        match (full, self.instruction.address_width()) {
            (Register::RSI, 32) => Register::ESI,
            (Register::RSI, 16) => Register::SI,
            (Register::RDI, 32) => Register::EDI,
            (Register::RDI, 16) => Register::DI,
            _ => full,
        }
    }

    /// The constant `value` as wide as `like` (in lane mode: in each of
    /// `like`'s lanes).
    pub fn literal(&mut self, like: ExprId, value: u64) -> ExprId {
        let width = self.b.width(like);
        match self.lane_count(like) {
            Some(count) => self.splat(width, count, value),
            None => self.b.constant(width, value),
        }
    }

    /// `value` in each of `count` lanes of a `width`-bit constant.
    fn splat(&mut self, width: u16, count: u16, value: u64) -> ExprId {
        let lane = width / count.max(1);
        let one = self.b.constant(lane, value);
        self.broadcast(one, count)
    }

    /// The constant `value`, `width` bits wide (in lane mode: in each
    /// lane).
    pub fn constant(&mut self, width: u64, value: u64) -> ExprId {
        match self.lanes {
            Some(count) => self.splat(narrow(width), count, value),
            None => self.b.constant(narrow(width), value),
        }
    }

    /// A constant of any width (not per lane).
    pub fn bits_constant(&mut self, value: Bits) -> ExprId {
        self.b.bits(value)
    }

    /// A value of the architecture's choice, `width` bits wide.
    pub fn undefined(&mut self, width: u64) -> ExprId {
        self.b.undefined(narrow(width))
    }

    /// `value` zero-extended to `width` bits (in lane mode: each lane).
    pub fn zext(&mut self, value: ExprId, width: u64) -> ExprId {
        self.extend(false, value, width)
    }

    /// `value` sign-extended to `width` bits (in lane mode: each lane).
    pub fn sext(&mut self, value: ExprId, width: u64) -> ExprId {
        self.extend(true, value, width)
    }

    fn extend(&mut self, signed: bool, value: ExprId, width: u64) -> ExprId {
        let width = narrow(width);
        match self.lane_count(value) {
            Some(count) => {
                let lane = self.b.width(value) / count.max(1);
                if width == lane {
                    value
                } else {
                    self.b
                        .lanes(LaneOp::Extend { signed, width }, count, &[value])
                }
            }
            None if signed => self.b.sext(value, width),
            None => self.b.zext(value, width),
        }
    }

    /// The low `width` bits of `value` (in lane mode: of each lane).
    pub fn trunc(&mut self, value: ExprId, width: u64) -> ExprId {
        self.bits(value, 0, width)
    }

    /// `value` resized to `width` bits: zero-extended or truncated (in lane
    /// mode: each lane).
    pub fn fit(&mut self, value: ExprId, width: u64) -> ExprId {
        let count = self.lane_count(value).unwrap_or(1);
        let own = u64::from(self.b.width(value) / count.max(1));
        if width > own {
            self.zext(value, width)
        } else {
            self.bits(value, 0, width)
        }
    }

    /// `value` resized to `like`'s width (shift counts and similar; in lane
    /// mode, a count one lane wide or narrower is resized to a lane and
    /// repeated, and a count as wide as `like` is one count per lane).
    pub fn fit_like(&mut self, value: ExprId, like: ExprId) -> ExprId {
        let width = self.b.width(like);
        if self.b.width(value) == width {
            return value;
        }
        if let Some(count) = self.lane_count(like) {
            let lane = width / count.max(1);
            let saved = self.lanes.take();
            let one = self.fit(value, u64::from(lane));
            self.lanes = saved;
            return self.broadcast(one, count);
        }
        self.fit(value, u64::from(width))
    }

    /// The most significant bit of `value` (in lane mode: of each lane).
    pub fn msb(&mut self, value: ExprId) -> ExprId {
        let count = self.lane_count(value).unwrap_or(1);
        let top = self.b.width(value) / count.max(1) - 1;
        self.bits(value, u64::from(top), 1)
    }

    /// Bit `index` of `value`, for an index known at lift time (in lane
    /// mode: of each lane).
    pub fn bit(&mut self, value: ExprId, index: u64) -> ExprId {
        self.bits(value, index, 1)
    }

    /// Bits `offset..offset + width` of `value`, known at lift time (in
    /// lane mode: of each lane).
    pub fn bits(&mut self, value: ExprId, offset: u64, width: u64) -> ExprId {
        let (offset, width) = (narrow(offset), narrow(width));
        match self.lane_count(value) {
            Some(count) => {
                if width == self.b.width(value) / count.max(1) && offset == 0 {
                    return value;
                }
                self.b
                    .lanes(LaneOp::Extract { offset, width }, count, &[value])
            }
            None => self.b.extract(value, offset, width),
        }
    }

    /// Bit `index` of `value`, for an index computed at run time (bits
    /// past the width are 0).
    pub fn bit_at(&mut self, value: ExprId, index: ExprId) -> ExprId {
        let index = self.fit_like(index, value);
        let shifted = self.b.binary(Binary::LShr, value, index);
        self.b.extract(shifted, 0, 1)
    }

    /// A value of the architecture's choice, as wide as `like`.
    pub fn undefined_like(&mut self, like: ExprId) -> ExprId {
        let width = self.b.width(like);
        self.b.undefined(width)
    }

    /// A value of the architecture's choice at `site`, `width` bits wide;
    /// `positions` are the operands of the entry's parameters.
    pub fn site(&mut self, site: SiteId, width: u64, positions: &[usize]) -> ExprId {
        let undefined = self.b.undefined(narrow(width));
        let Some(info) = SITES.get(usize::from(site.0)) else {
            self.problem(format!("no site {}", site.0));
            return undefined;
        };
        let mut inputs = Vec::with_capacity(info.inputs.len());
        for &input in info.inputs {
            let slot = |n: u8| positions.get(usize::from(n)).map(|&p| Slot::Operand(p));
            let value = match input {
                Input::Operand(n) => slot(n).and_then(|slot| self.as_read(slot)).map(Ok),
                Input::Flag(flag) => self.as_read(Slot::Flag(flag)).map(Ok),
                Input::Old => match info.output {
                    Output::Flag(flag) => Some(Ok(self.read_flag(flag))),
                    Output::Register(register) => Some(Ok(self.read_gpr(register))),
                    Output::Operand(_) | Output::Memory => None,
                },
                Input::Defined(n) => slot(n).map(|slot| self.defined(slot)),
                Input::DefinedFlag(flag) => Some(self.defined(Slot::Flag(flag))),
            };
            let Some(value) = value else {
                let name = X86.site(site).map_or("?", |info| info.name);
                self.problem(format!("site {name} cannot have input {input:?}"));
                return undefined;
            };
            inputs.push(value);
        }
        let scope = self.b.scope().to_vec();
        self.sites.push(Pending {
            undefined,
            site,
            scope,
            inputs,
        });
        undefined
    }

    /// [`site`](Self::site), as wide as `like`.
    pub fn site_like(&mut self, site: SiteId, like: ExprId, positions: &[usize]) -> ExprId {
        let width = self.b.width(like);
        self.site(site, u64::from(width), positions)
    }

    /// The value of `slot` as the instruction reads it, usable here: what
    /// the entry read before writing it, or read now if it has not written
    /// it yet. `None` if it wrote it without reading it here.
    fn as_read(&mut self, slot: Slot) -> Option<ExprId> {
        let scope = self.b.scope();
        let usable = |seen: &&Seen| seen.slot == slot && scope.starts_with(&seen.scope);
        if let Some(seen) = self.read.iter().find(usable) {
            return Some(seen.value);
        }
        if self.written.iter().any(|seen| seen.slot == slot) {
            return None;
        }
        Some(self.read_slot(slot))
    }

    /// What the entry defines for `slot`: what it wrote last, if usable
    /// here; else (written in a block closed now) its value now; else
    /// (not written yet) the slot, whose last write [`finish`](Self::finish)
    /// takes.
    fn defined(&mut self, slot: Slot) -> Result<ExprId, Slot> {
        let scope = self.b.scope();
        match self.written.iter().find(|seen| seen.slot == slot) {
            Some(seen) if scope.starts_with(&seen.scope) => Ok(seen.value),
            Some(_) => Ok(self.read_slot(slot)),
            None => Err(slot),
        }
    }

    /// Reads `slot` now for a site input: a register or flag; a memory
    /// operand would be a load the instruction does not make (an access,
    /// which may fault), so it is an unknown value instead.
    fn read_slot(&mut self, slot: Slot) -> ExprId {
        match slot {
            Slot::Operand(position)
                if self.operand(position).is_some_and(|operand| {
                    matches!(operand.value, Value::Memory(_)) && operand.name != OperandName::Agen
                }) =>
            {
                let width = u16::try_from(self.width(position)).unwrap_or(u16::MAX);
                self.b.undefined(width.max(1))
            }
            Slot::Operand(position) => self.read(position),
            Slot::Flag(flag) => self.read_flag(flag),
        }
    }

    /// Notes that `value` was read from `slot`: the instruction's input
    /// unless the entry wrote it first.
    fn note_read(&mut self, slot: Slot, value: ExprId) {
        let seen = |list: &[Seen]| list.iter().any(|seen| seen.slot == slot);
        if !seen(&self.read) && !seen(&self.written) {
            let scope = self.b.scope().to_vec();
            self.read.push(Seen { slot, value, scope });
        }
    }

    /// Notes that `value` was written to `slot`.
    fn note_write(&mut self, slot: Slot, value: ExprId) {
        let scope = self.b.scope().to_vec();
        self.written.retain(|seen| seen.slot != slot);
        self.written.push(Seen { slot, value, scope });
    }

    fn operand(&mut self, position: usize) -> Option<Operand> {
        let operand = self.instruction.operands().nth(position);
        if operand.is_none() {
            self.problem(format!("no operand {position}"));
        }
        operand
    }

    /// The width in bits of operand `position`.
    pub fn width(&self, position: usize) -> u64 {
        u64::from(self.instruction.operand_bits(position))
    }

    /// The `i` of operand `position` if it is the x87 register `st(i)`;
    /// 8 for any other operand.
    pub fn stack_index(&self, position: usize) -> u64 {
        self.instruction
            .operands()
            .nth(position)
            .and_then(|operand| {
                if let Value::Register(Some(register)) = operand.value
                    && register.class() == RegisterClass::X87
                {
                    (register as u16).checked_sub(Register::ST0 as u16)
                } else {
                    None
                }
            })
            .map_or(8, u64::from)
    }

    /// The low byte of immediate operand `position` (an interrupt's
    /// vector); 0 for any other operand.
    pub fn vector(&self, position: usize) -> u8 {
        self.instruction
            .operands()
            .nth(position)
            .and_then(|operand| {
                if let Value::Immediate { value, .. } = operand.value {
                    Some(value.to_le_bytes()[0])
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    /// Loads `bytes` bytes at byte `offset` of memory operand `position`
    /// (one wider than L0's values: an x87 environment, an FXSAVE image).
    pub fn load_part(&mut self, position: usize, offset: u64, bytes: u64) -> ExprId {
        let size = u16::try_from(bytes).unwrap_or(u16::MAX);
        match self.part_address(position, offset) {
            Some(address) => self.b.load(address, size),
            None => self.b.undefined(size.saturating_mul(8).max(1)),
        }
    }

    /// Stores `value` at byte `offset` of memory operand `position`.
    pub fn store_part(&mut self, position: usize, offset: u64, value: ExprId) {
        if let Some(address) = self.part_address(position, offset) {
            self.b.store(address, value);
        }
    }

    /// Accesses memory operand `position` (loads whose values are dropped):
    /// its address is checked and its pages must be there. One wider than
    /// L0's values (an FXSAVE image) is touched at both ends.
    pub fn probe(&mut self, position: usize) {
        let bytes = self.width(position) / 8;
        if bytes > 64 {
            self.load_part(position, 0, 16);
            self.load_part(position, bytes - 16, 16);
        } else {
            self.load_part(position, 0, bytes);
        }
    }

    /// The address of byte `offset` of memory operand `position`.
    fn part_address(&mut self, position: usize, offset: u64) -> Option<ExprId> {
        let operand = self.operand(position)?;
        let Value::Memory(memory) = operand.value else {
            self.problem(format!("operand {position} is not in memory"));
            return None;
        };
        let bytes = self.width(position) / 8;
        let base = self.address(operand, memory, bytes);
        let offset = self.b.constant(64, offset);
        Some(self.b.binary(Binary::Add, base, offset))
    }

    fn register_view(&mut self, register: Option<Register>) -> Option<View> {
        let view = register.and_then(registers::gpr);
        if view.is_none() {
            self.problem(format!("register {register:?} is not modelled"));
        }
        view
    }

    /// Where register operand `register` lives.
    fn place(&mut self, register: Option<Register>) -> Option<Place> {
        let place = register.and_then(|register| match register.class() {
            RegisterClass::Gpr => registers::gpr(register).map(Place::View),
            RegisterClass::Xmm | RegisterClass::Ymm | RegisterClass::Zmm => {
                registers::vector(register).map(Place::View)
            }
            RegisterClass::Mxcsr => Some(Place::View(registers::whole(MXCSR))),
            RegisterClass::X87 => (register as u16)
                .checked_sub(Register::ST0 as u16)
                .and_then(|index| u8::try_from(index).ok())
                .filter(|&index| index < 8)
                .map(Place::Stack),
            RegisterClass::Bndcfg
            | RegisterClass::Bndstat
            | RegisterClass::Bound
            | RegisterClass::Cr
            | RegisterClass::Dr
            | RegisterClass::Flags
            | RegisterClass::Ip
            | RegisterClass::Mask
            | RegisterClass::Mmx
            | RegisterClass::Msr
            | RegisterClass::Pseudo
            | RegisterClass::Pseudox87
            | RegisterClass::Sr
            | RegisterClass::Tmp
            | RegisterClass::Treg
            | RegisterClass::Uif
            | RegisterClass::Xcr => None,
        });
        if place.is_none() {
            self.problem(format!("register {register:?} is not modelled"));
        }
        place
    }

    /// Whether the instruction has a VEX or EVEX prefix (its vector writes
    /// zero the rest of the register).
    pub fn vex(&self) -> bool {
        matches!(
            self.instruction.encoding(),
            Encoding::Vex | Encoding::Evex | Encoding::Xop
        )
    }

    /// The width of L0 register `id`.
    pub fn register_width(&self, id: RegisterId) -> u64 {
        u64::from(registers::whole(id).width)
    }

    /// Reads an L0 register whole.
    pub fn read_register(&mut self, id: RegisterId) -> ExprId {
        self.b.read(registers::whole(id))
    }

    /// Writes an L0 register whole.
    pub fn write_register(&mut self, id: RegisterId, value: ExprId) {
        self.b.write(registers::whole(id), value);
    }

    /// The physical x87 register that is `st(index)`: `(top + index) mod
    /// 8`, 3 bits.
    fn physical(&mut self, index: u64) -> ExprId {
        let top = self.read_register(FTOP);
        let offset = self.b.constant(3, index);
        self.b.binary(Binary::Add, top, offset)
    }

    /// Reads `st(index)`: a selection among the eight physical registers.
    pub fn read_st(&mut self, index: u64) -> ExprId {
        let physical = self.physical(index);
        let mut value = self.read_register(RegisterId(FPR0.0 + 7));
        for k in (0..7u16).rev() {
            let register = self.read_register(RegisterId(FPR0.0 + k));
            let number = self.b.constant(3, u64::from(k));
            let here = self.b.binary(Binary::Eq, physical, number);
            value = self.b.select(here, register, value);
        }
        value
    }

    /// Writes `st(index)`: each physical register keeps its value unless it
    /// is the one.
    pub fn write_st(&mut self, index: u64, value: ExprId) {
        let physical = self.physical(index);
        for k in 0..8u16 {
            let id = RegisterId(FPR0.0 + k);
            let old = self.read_register(id);
            let number = self.b.constant(3, u64::from(k));
            let here = self.b.binary(Binary::Eq, physical, number);
            let new = self.b.select(here, value, old);
            self.write_register(id, new);
        }
    }

    /// The effective address of memory operand `operand` (`bytes` wide),
    /// 64 bits, computed and checked (canonical, and aligned where the
    /// instruction requires it) once.
    fn address(&mut self, operand: Operand, memory: Memory, bytes: u64) -> ExprId {
        let index = Self::memory_index(operand.name);
        if let Some(address) = self.addresses.get(index).copied().flatten() {
            return address;
        }
        // Stack-segment accesses (rsp or rbp as base) fault with #SS.
        let stack = memory
            .base
            .is_some_and(|base| matches!(base.full(), Register::RSP | Register::RBP));
        // An implied stack operand (LEAVE's saved frame pointer) is
        // addressed at the stack address size: a 67 prefix does not change
        // it (measured), though XED gives the address size's base.
        let address = if stack && operand.visibility == Visibility::Suppressed {
            let width = self.instruction.stack_address_width();
            let memory = Memory {
                base: memory.base.map(Register::full),
                ..memory
            };
            self.effective_address(memory, width)
        } else {
            self.effective_address(memory, self.instruction.address_width())
        };
        self.canonical(address, if stack { Trap::Stack } else { Trap::Protection });
        // XED's alignment attributes: the operand's size (16 bytes for
        // FXSAVE's 512-byte image), or 4 or 8 bytes.
        let attributes = self.instruction.attributes();
        let alignment = if attributes.contains(Attribute::RequiresAlignment) {
            if bytes > 64 { 16 } else { bytes }
        } else if attributes.contains(Attribute::RequiresAlignment4b) {
            4
        } else if attributes.contains(Attribute::RequiresAlignment8b) {
            8
        } else {
            1
        };
        if alignment > 1 {
            let mask = self.b.constant(64, alignment - 1);
            let offset = self.b.binary(Binary::And, address, mask);
            let zero = self.b.constant(64, 0);
            let misaligned = self.b.binary(Binary::Ne, offset, zero);
            self.b.begin_if(misaligned);
            self.b.trap(Trap::Protection);
            self.b.end_if();
        }
        if let Some(slot) = self.addresses.get_mut(index) {
            *slot = Some(address);
        }
        address
    }

    /// Traps with `trap` unless the 64-bit `address` is canonical (bits 63
    /// to 47 all equal).
    fn canonical(&mut self, address: ExprId, trap: Trap) {
        let low = self.b.extract(address, 0, 48);
        let extended = self.b.sext(low, 64);
        let bad = self.b.binary(Binary::Ne, extended, address);
        self.b.begin_if(bad);
        self.b.trap(trap);
        self.b.end_if();
    }

    /// A control transfer's target: 64 bits, and #GP unless canonical.
    pub fn target(&mut self, value: ExprId) -> ExprId {
        let saved = self.lanes.take();
        let target = self.fit(value, 64);
        self.canonical(target, Trap::Protection);
        self.lanes = saved;
        target
    }

    /// Base + index × scale + displacement at `width` bits, then the
    /// `FS`/`GS` base if the instruction overrides the segment.
    fn effective_address(&mut self, memory: Memory, width: u32) -> ExprId {
        let width = u16::try_from(width).unwrap_or(64);
        let mut sum = self.b.constant(width, memory.displacement.cast_unsigned());
        if let Some(base) = memory.base {
            let value = if matches!(base, Register::RIP | Register::EIP | Register::IP) {
                let next = self.next_address();
                self.fit(next, u64::from(width))
            } else if let Some(view) = self.register_view(Some(base)) {
                let value = self.b.read(view);
                self.fit(value, u64::from(width))
            } else {
                return sum;
            };
            sum = self.b.binary(Binary::Add, sum, value);
        }
        if let Some(index) = memory.index
            && let Some(view) = self.register_view(Some(index))
        {
            let value = self.b.read(view);
            let value = self.fit(value, u64::from(width));
            let scale = self.b.constant(width, u64::from(memory.scale.max(1)));
            let scaled = self.b.binary(Binary::Mul, value, scale);
            sum = self.b.binary(Binary::Add, sum, scaled);
        }
        let mut address = self.fit(sum, 64);
        let segment = if memory.segment == Some(Register::FS) {
            Some(FS_BASE)
        } else if memory.segment == Some(Register::GS) {
            Some(GS_BASE)
        } else {
            None
        };
        if let Some(segment) = segment {
            let base = self.b.read(registers::whole(segment));
            address = self.b.binary(Binary::Add, address, base);
        }
        address
    }

    fn memory_index(name: OperandName) -> usize {
        usize::from(name == OperandName::Mem1)
    }

    /// Memory operand `position`, or a problem if it is not one.
    fn memory_operand(&mut self, position: usize) -> Option<Memory> {
        if let Value::Memory(memory) = self.operand(position)?.value {
            return Some(memory);
        }
        self.problem(format!("operand {position} is not in memory"));
        None
    }

    /// The linear address of memory operand `position`, 64 bits, without
    /// the checks of a whole access: masked stores and loads check each
    /// element they access ([`load_at`](Self::load_at)).
    pub fn memory_address(&mut self, position: usize) -> ExprId {
        let saved = self.lanes.take();
        let address = if let Some(memory) = self.memory_operand(position) {
            self.effective_address(memory, self.instruction.address_width())
        } else {
            self.b.undefined(64)
        };
        self.lanes = saved;
        address
    }

    /// The index register of VSIB memory operand `position` (a gather's
    /// vector of indices), whole.
    pub fn vsib_index(&mut self, position: usize) -> ExprId {
        let saved = self.lanes.take();
        let view = self
            .memory_operand(position)
            .and_then(|memory| memory.index)
            .and_then(registers::vector);
        let value = if let Some(view) = view {
            self.b.read(view)
        } else {
            self.problem(format!("operand {position} has no vector index"));
            self.b.undefined(128)
        };
        self.lanes = saved;
        value
    }

    /// The linear address of the element of VSIB memory operand `position`
    /// whose index is `index` (an element of the index register): base +
    /// index (sign-extended, or cut to the address size) × scale +
    /// displacement at the address size, then the segment base.
    pub fn vsib_address(&mut self, position: usize, index: ExprId) -> ExprId {
        let Some(memory) = self.memory_operand(position) else {
            return self.b.undefined(64);
        };
        let saved = self.lanes.take();
        let width = self.instruction.address_width();
        let rest = Memory {
            index: None,
            segment: None,
            ..memory
        };
        let rest = self.effective_address(rest, width);
        let rest = self.fit(rest, u64::from(width));
        let index = if u32::from(self.b.width(index)) < width {
            self.b.sext(index, narrow(u64::from(width)))
        } else {
            self.fit(index, u64::from(width))
        };
        let scale = self
            .b
            .constant(narrow(u64::from(width)), u64::from(memory.scale.max(1)));
        let scaled = self.b.binary(Binary::Mul, index, scale);
        let sum = self.b.binary(Binary::Add, rest, scaled);
        let mut address = self.fit(sum, 64);
        let segment = if memory.segment == Some(Register::FS) {
            Some(FS_BASE)
        } else if memory.segment == Some(Register::GS) {
            Some(GS_BASE)
        } else {
            None
        };
        if let Some(segment) = segment {
            let base = self.b.read(registers::whole(segment));
            address = self.b.binary(Binary::Add, address, base);
        }
        self.lanes = saved;
        address
    }

    /// The trap a non-canonical address of memory operand `position`
    /// raises: #SS for stack-segment accesses (rsp or rbp as base).
    fn address_trap(&mut self, position: usize) -> Trap {
        let stack = self.memory_operand(position).is_some_and(|memory| {
            memory
                .base
                .is_some_and(|base| matches!(base.full(), Register::RSP | Register::RBP))
        });
        if stack { Trap::Stack } else { Trap::Protection }
    }

    /// Loads `bytes` bytes at `address`, an element of memory operand
    /// `position`: traps unless the address is canonical.
    pub fn load_at(&mut self, position: usize, address: ExprId, bytes: u64) -> ExprId {
        let saved = self.lanes.take();
        let trap = self.address_trap(position);
        self.canonical(address, trap);
        let value = self.b.load(address, narrow(bytes));
        self.lanes = saved;
        value
    }

    /// Stores `value` at `address`, an element of memory operand
    /// `position`: traps unless the address is canonical.
    pub fn store_at(&mut self, position: usize, address: ExprId, value: ExprId) {
        let saved = self.lanes.take();
        let trap = self.address_trap(position);
        self.canonical(address, trap);
        self.b.store(address, value);
        self.lanes = saved;
    }

    /// The vector register operand `position` names (for a VSIB memory
    /// operand, its index register).
    fn vector_register(&self, position: usize) -> Option<RegisterId> {
        let register = match self.instruction.operands().nth(position)?.value {
            Value::Register(register) => register,
            Value::Memory(memory) => memory.index,
            Value::Immediate { .. }
            | Value::SecondImmediate(_)
            | Value::Relative(_)
            | Value::Field(_) => None,
        };
        register
            .and_then(registers::vector)
            .map(|view| view.register)
    }

    /// 1 if operands `a` and `b` name the same vector register (a VSIB
    /// memory operand: its index register), else 0.
    pub fn same_register(&self, a: usize, b: usize) -> u64 {
        let (a, b) = (self.vector_register(a), self.vector_register(b));
        u64::from(a.is_some() && a == b)
    }

    /// Reads operand `position`; a vector register as `bits` bits of its
    /// register, also where XED's operand is narrower.
    pub fn read_wide(&mut self, position: usize, bits: u64) -> ExprId {
        let view = self
            .instruction
            .operands()
            .nth(position)
            .and_then(|operand| match operand.value {
                Value::Register(register) => register.and_then(registers::vector),
                Value::Memory(_)
                | Value::Immediate { .. }
                | Value::SecondImmediate(_)
                | Value::Relative(_)
                | Value::Field(_) => None,
            });
        let Some(view) = view else {
            return self.read(position);
        };
        let saved = self.lanes.take();
        let value = self.b.read(View {
            width: narrow(bits),
            ..view
        });
        self.lanes = saved;
        value
    }

    /// Reads operand `position` (operand access is never lane by lane).
    pub fn read(&mut self, position: usize) -> ExprId {
        let saved = self.lanes.take();
        let value = self.read_operand(position);
        self.lanes = saved;
        self.note_read(Slot::Operand(position), value);
        value
    }

    fn read_operand(&mut self, position: usize) -> ExprId {
        let width = u16::try_from(self.width(position)).unwrap_or(u16::MAX);
        let Some(operand) = self.operand(position) else {
            return self.b.undefined(width.max(1));
        };
        match operand.value {
            Value::Register(register) => match self.place(register) {
                // A vector register's operand may be its low part (`ss`).
                Some(Place::View(view)) if view.width > width && width > 0 => {
                    self.b.read(View { width, ..view })
                }
                Some(Place::View(view)) => self.b.read(view),
                Some(Place::Stack(index)) => self.read_st(u64::from(index)),
                None => self.b.undefined(width.max(1)),
            },
            Value::Memory(memory) if operand.name == OperandName::Agen => {
                // An address computation: the address at the address size,
                // without a segment base.
                let address = self.effective_address(
                    Memory {
                        segment: None,
                        ..memory
                    },
                    self.instruction.address_width(),
                );
                let address_width = u64::from(self.instruction.address_width());
                self.fit(address, address_width)
            }
            Value::Memory(memory) => {
                let address = self.address(operand, memory, u64::from(width / 8));
                self.b.load(address, width / 8)
            }
            Value::Immediate { value, signed } => {
                let constant = self.b.constant(width, value);
                let osz = u16::try_from(self.osz()).unwrap_or(64);
                if signed && osz > width {
                    self.b.sext(constant, osz)
                } else {
                    constant
                }
            }
            Value::SecondImmediate(value) => self.b.constant(width.max(8), u64::from(value)),
            Value::Relative(displacement) => {
                let target = relative_target(self.instruction, self.address, displacement);
                self.b.constant(64, target)
            }
            Value::Field(_) => {
                self.problem(format!(
                    "operand {position} ({:?}) is not modelled",
                    operand.name
                ));
                self.b.undefined(width.max(1))
            }
        }
    }

    /// Writes `value` to operand `position`.
    pub fn write(&mut self, position: usize, value: ExprId) {
        let saved = self.lanes.take();
        self.write_operand(position, value);
        self.lanes = saved;
        self.note_write(Slot::Operand(position), value);
    }

    fn write_operand(&mut self, position: usize, value: ExprId) {
        let Some(operand) = self.operand(position) else {
            return;
        };
        match operand.value {
            Value::Register(register)
                if register.is_some_and(|r| r.class() != RegisterClass::Gpr) =>
            {
                self.write_place(register, value);
            }
            Value::Register(register) => self.write_gpr(register, value),
            Value::Memory(memory) if operand.name != OperandName::Agen => {
                let bytes = self.width(position) / 8;
                let address = self.address(operand, memory, bytes);
                self.b.store(address, value);
            }
            Value::Memory(_)
            | Value::Immediate { .. }
            | Value::SecondImmediate(_)
            | Value::Relative(_)
            | Value::Field(_) => {
                self.problem(format!(
                    "operand {position} ({:?}) cannot be written",
                    operand.name
                ));
            }
        }
    }

    /// Writes a register other than a general-purpose one: a vector
    /// register by the encoding's rule, `st(i)`, or `mxcsr`.
    fn write_place(&mut self, register: Option<Register>, value: ExprId) {
        match self.place(register) {
            Some(Place::View(view)) if view.register.0 >= registers::ZMM0.0 && self.vex() => {
                let full = registers::whole(view.register);
                let wide = self.b.zext(value, full.width);
                self.b.write(full, wide);
            }
            Some(Place::View(view)) => {
                let width = self.b.width(value);
                self.b.write(View { width, ..view }, value);
            }
            Some(Place::Stack(index)) => self.write_st(u64::from(index), value),
            None => {}
        }
    }

    /// Reads a general-purpose register (any width).
    pub fn read_gpr(&mut self, register: impl Into<Option<Register>>) -> ExprId {
        match self.register_view(register.into()) {
            Some(view) => self.b.read(view),
            None => self.b.undefined(64),
        }
    }

    /// Writes a general-purpose register with x86's rules: a 32-bit write
    /// clears the upper half; 8- and 16-bit writes keep the other bits.
    pub fn write_gpr(&mut self, register: impl Into<Option<Register>>, value: ExprId) {
        let Some(view) = self.register_view(register.into()) else {
            return;
        };
        if view.width == 32 {
            let wide = self.b.zext(value, 64);
            self.b.write(registers::whole(view.register), wide);
        } else {
            self.b.write(view, value);
        }
    }

    /// Enters the operating system.
    pub fn system_call(&mut self) {
        self.b.system_call();
    }

    /// The `N` outputs of the intrinsic named `name` (see [`X86`]) on
    /// `inputs`.
    pub fn intrinsic<const N: usize>(&mut self, name: &str, inputs: &[ExprId]) -> [ExprId; N] {
        let declared = X86
            .find_intrinsic(name)
            .and_then(|id| Some((id, X86.intrinsic(id)?)));
        let outputs = match declared {
            Some((id, info)) if info.outputs.len() == N => {
                self.b.intrinsic(id, inputs, info.outputs)
            }
            _ => {
                self.problem(format!("no intrinsic `{name}` with {N} outputs"));
                Vec::new()
            }
        };
        core::array::from_fn(|i| match outputs.get(i) {
            Some(&output) => output,
            None => self.b.undefined(1),
        })
    }

    /// Reads a status flag.
    pub fn read_flag(&mut self, flag: Flag) -> ExprId {
        let value = if let Some(id) = registers::flag(flag) {
            self.b.read(registers::whole(id))
        } else {
            self.problem(format!("flag {flag:?} is not modelled"));
            return self.b.undefined(1);
        };
        self.note_read(Slot::Flag(flag), value);
        value
    }

    /// Writes a status flag.
    pub fn write_flag(&mut self, flag: Flag, value: ExprId) {
        match registers::flag(flag) {
            Some(id) => self.b.write(registers::whole(id), value),
            None => self.problem(format!("flag {flag:?} is not modelled")),
        }
        self.note_write(Slot::Flag(flag), value);
    }

    /// Whether the condition of a `Jcc`, `SETcc` or `CMOVcc` holds (1 bit).
    pub fn condition(&mut self) -> ExprId {
        let Some(condition) = self.instruction.condition() else {
            self.problem("the instruction tests no condition".into());
            return self.b.undefined(1);
        };
        let flag = |l: &mut Self, f| l.read_flag(f);
        let negate = |l: &mut Self, v| l.b.unary(Unary::Not, v);
        match condition {
            Condition::Overflow => flag(self, Flag::Of),
            Condition::NotOverflow => {
                let v = flag(self, Flag::Of);
                negate(self, v)
            }
            Condition::Below => flag(self, Flag::Cf),
            Condition::NotBelow => {
                let v = flag(self, Flag::Cf);
                negate(self, v)
            }
            Condition::Zero => flag(self, Flag::Zf),
            Condition::NotZero => {
                let v = flag(self, Flag::Zf);
                negate(self, v)
            }
            Condition::BelowOrEqual | Condition::Above => {
                let (cf, zf) = (flag(self, Flag::Cf), flag(self, Flag::Zf));
                let either = self.b.binary(Binary::Or, cf, zf);
                if condition == Condition::Above {
                    negate(self, either)
                } else {
                    either
                }
            }
            Condition::Sign => flag(self, Flag::Sf),
            Condition::NotSign => {
                let v = flag(self, Flag::Sf);
                negate(self, v)
            }
            Condition::Parity => flag(self, Flag::Pf),
            Condition::NotParity => {
                let v = flag(self, Flag::Pf);
                negate(self, v)
            }
            Condition::Less | Condition::NotLess => {
                let (sf, of) = (flag(self, Flag::Sf), flag(self, Flag::Of));
                let less = self.b.binary(Binary::Ne, sf, of);
                if condition == Condition::NotLess {
                    negate(self, less)
                } else {
                    less
                }
            }
            Condition::LessOrEqual | Condition::Greater => {
                let (sf, of, zf) = (
                    flag(self, Flag::Sf),
                    flag(self, Flag::Of),
                    flag(self, Flag::Zf),
                );
                let less = self.b.binary(Binary::Ne, sf, of);
                let less_or_equal = self.b.binary(Binary::Or, less, zf);
                if condition == Condition::Greater {
                    negate(self, less_or_equal)
                } else {
                    less_or_equal
                }
            }
            Condition::False => self.b.constant(1, 0),
            Condition::True => self.b.constant(1, 1),
            Condition::CountZero
            | Condition::Loop
            | Condition::LoopZero
            | Condition::LoopNotZero
            | Condition::TransactionAbort => {
                self.problem(format!("condition {condition:?} is not a flag condition"));
                self.b.undefined(1)
            }
        }
    }

    /// The stack address width's mask, as a view of `rsp`.
    fn stack_pointer(&self) -> View {
        let width = u16::try_from(self.instruction.stack_address_width()).unwrap_or(64);
        View {
            register: RSP,
            offset: 0,
            width,
        }
    }

    /// Pushes `value` (a whole number of bytes).
    pub fn push(&mut self, value: ExprId) {
        let view = self.stack_pointer();
        let sp = self.b.read(view);
        let bytes = self.b.width(value) / 8;
        let size = self.b.constant(view.width, u64::from(bytes));
        let new = self.b.binary(Binary::Sub, sp, size);
        let address = self.fit(new, 64);
        self.canonical(address, Trap::Stack);
        self.b.store(address, value);
        self.write_stack_pointer(view, new);
    }

    /// Pops a value as wide as the operand size.
    pub fn pop(&mut self) -> ExprId {
        let view = self.stack_pointer();
        let sp = self.b.read(view);
        let bytes = u16::try_from(self.osz() / 8).unwrap_or(8);
        let address = self.fit(sp, 64);
        self.canonical(address, Trap::Stack);
        let value = self.b.load(address, bytes);
        let size = self.b.constant(view.width, u64::from(bytes));
        let new = self.b.binary(Binary::Add, sp, size);
        self.write_stack_pointer(view, new);
        value
    }

    fn write_stack_pointer(&mut self, view: View, value: ExprId) {
        if view.width == 32 {
            let wide = self.b.zext(value, 64);
            self.b.write(registers::whole(RSP), wide);
        } else {
            self.b.write(view, value);
        }
    }

    /// Writes the flags XED says the instruction sets, clears or leaves
    /// undefined, other than those in `computed` (which the semantics
    /// wrote): one left undefined is its entry's site in `sites`. A flag
    /// XED says is modified but the semantics did not compute is a problem.
    /// `positions` are the operands of the entry's parameters.
    pub fn finish_flags(
        &mut self,
        computed: FlagSet,
        sites: &[(Flag, SiteId)],
        positions: &[usize],
    ) {
        let Some(flags) = self.instruction.flags() else {
            return;
        };
        for effect in flags.effects {
            if computed.contains(effect.flag) {
                continue;
            }
            match effect.action {
                FlagAction::Set | FlagAction::Clear => {
                    let value = self
                        .b
                        .constant(1, u64::from(effect.action == FlagAction::Set));
                    self.write_flag(effect.flag, value);
                }
                FlagAction::Undefined if flags.must_write => {
                    let Some(&(_, site)) = sites.iter().find(|(flag, _)| *flag == effect.flag)
                    else {
                        self.problem(format!("no site for undefined {:?}", effect.flag));
                        continue;
                    };
                    let value = self.site(site, 1, positions);
                    self.write_flag(effect.flag, value);
                }
                FlagAction::Modify
                | FlagAction::Undefined
                | FlagAction::FromAh
                | FlagAction::Pop => {
                    self.problem(format!(
                        "XED says {effect} but the semantics do not compute it"
                    ));
                }
                FlagAction::Test => {}
            }
        }
    }

    /// The finished semantics.
    ///
    /// # Errors
    ///
    /// Problems recorded while lifting, or builder mistakes.
    pub fn finish(mut self) -> Result<Semantics, LiftError> {
        for pending in core::mem::take(&mut self.sites) {
            // An output the entry wrote after making the value: its last
            // write, which must be usable where the value was made; one it
            // never wrote: its value as read.
            let inputs: Option<Vec<ExprId>> = pending
                .inputs
                .iter()
                .map(|&input| match input {
                    Ok(value) => Some(value),
                    Err(slot) => {
                        let seen = |list: &[Seen]| {
                            list.iter()
                                .find(|seen| seen.slot == slot)
                                .filter(|seen| pending.scope.starts_with(&seen.scope))
                                .map(|seen| seen.value)
                        };
                        let ever = self.written.iter().any(|seen| seen.slot == slot);
                        if ever {
                            seen(&self.written)
                        } else {
                            seen(&self.read)
                        }
                    }
                })
                .collect();
            match inputs {
                Some(inputs) => self.b.site(pending.undefined, pending.site, inputs),
                None => self.problem(format!(
                    "site {} lacks an input",
                    X86.site(pending.site).map_or("?", |info| info.name)
                )),
            }
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
