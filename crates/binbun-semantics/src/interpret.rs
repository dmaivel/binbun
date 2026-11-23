//! Running a [`Semantics`] on concrete state.
//!
//! Values carry a mask of undefined bits ([`Value::undefined`]):
//! [`Expr::Undefined`] is all undefined (unless the machine knows what the
//! processor does at its site, [`Machine::undefined`]), and every operation
//! passes undefinedness on — exactly through bitwise operations, extraction,
//! concatenation, extension, selection on a defined condition and shifts by
//! a defined count; any undefined input bit makes the whole result undefined
//! otherwise. A bitwise AND with a defined 0, or OR with a defined 1, is
//! defined whatever the other operand's bit (`x & 0 = 0`, `x | 1 = 1`),
//! lane-wise operations alike. Comparing with hardware then checks only the
//! defined bits. A condition or address with undefined bits stops
//! execution ([`Outcome::Undetermined`]).
//!
//! Exceptions are precise: when an instruction does not complete (a trap,
//! a memory fault, or any other outcome than [`Outcome::Next`] and
//! [`Outcome::Transfer`]), its register writes and stores are undone.

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::bits::Bits;
use crate::float;
use crate::ir::{
    Binary, EXCEPTIONS, Expr, ExprId, Flag, FloatOp, FloatOutput, Format, IntrinsicId, LaneOp,
    Local, RegisterId, Rounding, Semantics, SiteId, Stmt, Trap, Unary, View,
};

/// A value and which of its bits are undefined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Value {
    /// The bits (undefined bits are 0 here).
    pub bits: Bits,
    /// 1 for each undefined bit.
    pub undefined: Bits,
}

impl Value {
    /// A fully defined value.
    pub fn defined(bits: Bits) -> Self {
        Self {
            bits,
            undefined: Bits::zero(bits.width()),
        }
    }

    /// A fully undefined value of `width` bits.
    pub fn unknown(width: u16) -> Self {
        Self {
            bits: Bits::zero(width),
            undefined: Bits::ones(width),
        }
    }

    /// The width in bits.
    pub const fn width(&self) -> u16 {
        self.bits.width()
    }

    /// Whether every bit is defined.
    pub fn is_defined(&self) -> bool {
        self.undefined.is_zero()
    }

    /// The bits, or `None` if any is undefined.
    pub fn known(&self) -> Option<Bits> {
        self.is_defined().then_some(self.bits)
    }

    fn with_mask(bits: Bits, undefined: Bits) -> Self {
        Self {
            bits: bits.and(&undefined.invert()),
            undefined,
        }
    }

    /// Fully undefined if any input bit is, else `bits`.
    fn strict(bits: Bits, inputs: &[&Value]) -> Self {
        if inputs.iter().all(|value| value.is_defined()) {
            Self::defined(bits)
        } else {
            Self::unknown(bits.width())
        }
    }
}

/// A memory access the machine could not perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fault {
    /// The address accessed.
    pub address: u64,
    /// Whether it was a store.
    pub write: bool,
}

/// The state an instruction runs on.
pub trait Machine {
    /// The current value of a whole register.
    fn read(&mut self, register: RegisterId) -> Value;
    /// Replaces a whole register.
    fn write(&mut self, register: RegisterId, value: Value);
    /// Reads `bytes` bytes at `address`, little-endian.
    ///
    /// # Errors
    ///
    /// If the memory cannot be read.
    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault>;
    /// Writes `value` (a whole number of bytes) at `address`, little-endian.
    ///
    /// # Errors
    ///
    /// If the memory cannot be written.
    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault>;
    /// The outputs of `intrinsic` on `inputs`, `outputs` bits wide. By
    /// default unknown: what the processor or the system would supply.
    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[Value],
        outputs: &[u16],
    ) -> Vec<Value> {
        let _ = (intrinsic, inputs);
        outputs.iter().map(|&width| Value::unknown(width)).collect()
    }

    /// The value of an undefined value of `site`, `width` bits wide, whose
    /// inputs have the values `inputs`. By default unknown: what the
    /// architecture says; a machine for one processor may know better.
    fn undefined(&mut self, site: SiteId, inputs: &[Value], width: u16) -> Value {
        let _ = (site, inputs);
        Value::unknown(width)
    }

    /// [`undefined`](Self::undefined) of the instruction at `address`:
    /// what L1's and L2's interpreters ask, which know the instruction
    /// (L0's runs one instruction, and its machine knows which). A run
    /// whose L2 lacks a site's inputs takes, by the instruction and its
    /// occurrence, the value the processor chose in a run that has them.
    fn undefined_at(&mut self, address: u64, site: SiteId, inputs: &[Value], width: u16) -> Value {
        let _ = address;
        self.undefined(site, inputs, width)
    }
}

/// How an instruction ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// It completed; execution continues with the next instruction.
    Next,
    /// It completed and continues at an address (jump, call or return).
    Transfer(u64),
    /// It trapped.
    Trap(Trap),
    /// A memory access faulted.
    Fault(Fault),
    /// A condition or address depended on undefined bits.
    Undetermined,
    /// A loop ran longer than the fuel allows.
    OutOfFuel,
    /// The semantics are malformed (they do not pass the verifier).
    Malformed,
    /// It entered the operating system (its effects up to then happened);
    /// execution continues with the next instruction when the system
    /// returns.
    SystemCall,
}

/// Loop iterations allowed per instruction.
pub const FUEL: u64 = 1 << 24;

/// Runs `semantics` on `machine`, allowing [`FUEL`] loop iterations.
pub fn run(semantics: &Semantics, machine: &mut dyn Machine) -> Outcome {
    run_with_fuel(semantics, machine, FUEL)
}

/// Runs `semantics` on `machine`, allowing `fuel` loop iterations.
pub fn run_with_fuel(semantics: &Semantics, machine: &mut dyn Machine, fuel: u64) -> Outcome {
    let mut run = Run {
        semantics,
        machine,
        locals: vec![None; semantics.locals.len()],
        known: vec![(0, Value::unknown(1)); semantics.exprs.len()],
        generation: 1,
        fuel,
        transfer: None,
        journal: Vec::new(),
        system_call: false,
    };
    match run.block(&semantics.body) {
        Ok(Flow::Normal | Flow::Break) if run.system_call => Outcome::SystemCall,
        Ok(Flow::Normal | Flow::Break) => run.transfer.map_or(Outcome::Next, Outcome::Transfer),
        Err(outcome) => {
            run.undo();
            outcome
        }
    }
}

/// How a block ended.
enum Flow {
    Normal,
    Break,
}

/// An effect to undo: a register's or memory's previous value.
enum Undo {
    Register(RegisterId, Value),
    Memory(u64, Value),
}

struct Run<'a> {
    semantics: &'a Semantics,
    machine: &'a mut dyn Machine,
    locals: Vec<Option<Value>>,
    /// Values of expressions computed since locals last changed, by
    /// `ExprId`, with the generation they were computed in: expressions
    /// are a DAG (hash-consed), and a value used twice must not be computed
    /// twice (unrolled loops would take exponential time).
    known: Vec<(u32, Value)>,
    /// Bumped whenever a local is defined: older entries of `known` are
    /// stale.
    generation: u32,
    fuel: u64,
    /// Where execution continues, once a jump, call or return has run.
    transfer: Option<u64>,
    /// Previous values of what the instruction changed, in order.
    journal: Vec<Undo>,
    /// Whether a [`Stmt::SystemCall`] ran.
    system_call: bool,
}

impl Run<'_> {
    /// Restores everything the instruction changed, latest first.
    fn undo(&mut self) {
        while let Some(undo) = self.journal.pop() {
            match undo {
                Undo::Register(register, value) => self.machine.write(register, value),
                Undo::Memory(address, value) => {
                    // The bytes were just stored, so storing them again
                    // succeeds unless the machine changed under us.
                    let _ = self.machine.store(address, value);
                }
            }
        }
    }

    fn block(&mut self, statements: &[Stmt]) -> Result<Flow, Outcome> {
        for stmt in statements {
            if let Flow::Break = self.statement(stmt)? {
                return Ok(Flow::Break);
            }
        }
        Ok(Flow::Normal)
    }

    fn set(&mut self, local: Local, value: Value) -> Result<(), Outcome> {
        let slot = self
            .locals
            .get_mut(local.0 as usize)
            .ok_or(Outcome::Malformed)?;
        *slot = Some(value);
        self.generation = self.generation.wrapping_add(1).max(1);
        Ok(())
    }

    fn address(&mut self, id: ExprId) -> Result<u64, Outcome> {
        let value = self.eval(id)?;
        value
            .known()
            .map(|bits| bits.low_u64())
            .ok_or(Outcome::Undetermined)
    }

    fn statement(&mut self, stmt: &Stmt) -> Result<Flow, Outcome> {
        match stmt {
            Stmt::Read { local, view } => {
                let value = self.read_view(*view)?;
                self.set(*local, value)?;
            }
            Stmt::Write { view, value } => {
                let value = self.eval(*value)?;
                self.write_view(*view, value)?;
            }
            Stmt::Load {
                local,
                address,
                bytes,
            } => {
                let address = self.address(*address)?;
                let value = self.machine.load(address, *bytes).map_err(Outcome::Fault)?;
                self.set(*local, value)?;
            }
            Stmt::Store { address, value } => {
                let address = self.address(*address)?;
                let value = self.eval(*value)?;
                if let Ok(old) = self.machine.load(address, value.width() / 8) {
                    self.journal.push(Undo::Memory(address, old));
                }
                self.machine.store(address, value).map_err(Outcome::Fault)?;
            }
            Stmt::If {
                condition,
                then,
                otherwise,
            } => {
                let condition = self
                    .eval(*condition)?
                    .known()
                    .ok_or(Outcome::Undetermined)?;
                return self.block(if condition.is_zero() { otherwise } else { then });
            }
            Stmt::Loop(body) => loop {
                if self.fuel == 0 {
                    return Err(Outcome::OutOfFuel);
                }
                self.fuel -= 1;
                if let Flow::Break = self.block(body)? {
                    break;
                }
            },
            Stmt::Break => return Ok(Flow::Break),
            // One processor: the statements run in order, nothing between.
            Stmt::Atomic(body) => return self.block(body),
            Stmt::SystemCall => self.system_call = true,
            Stmt::Intrinsic {
                intrinsic,
                inputs,
                outputs,
            } => {
                let inputs = inputs
                    .iter()
                    .map(|&input| self.eval(input))
                    .collect::<Result<Vec<_>, _>>()?;
                let widths: Vec<u16> = outputs
                    .iter()
                    .map(|local| self.semantics.locals.get(local.0 as usize).copied())
                    .collect::<Option<_>>()
                    .ok_or(Outcome::Malformed)?;
                let values = self.machine.intrinsic(*intrinsic, &inputs, &widths);
                if values.len() != outputs.len() {
                    return Err(Outcome::Malformed);
                }
                for ((&local, value), &width) in outputs.iter().zip(values).zip(&widths) {
                    if value.width() != width {
                        return Err(Outcome::Malformed);
                    }
                    self.set(local, value)?;
                }
            }
            Stmt::Trap(trap) => return Err(Outcome::Trap(*trap)),
            Stmt::Jump { target } | Stmt::Call { target, .. } | Stmt::Return { target } => {
                self.transfer = Some(self.address(*target)?);
            }
        }
        Ok(Flow::Normal)
    }

    fn read_view(&mut self, view: View) -> Result<Value, Outcome> {
        let full = self.machine.read(view.register);
        if u32::from(view.offset) + u32::from(view.width) > u32::from(full.width()) {
            return Err(Outcome::Malformed);
        }
        Ok(Value::with_mask(
            full.bits.extract(view.offset, view.width),
            full.undefined.extract(view.offset, view.width),
        ))
    }

    fn write_view(&mut self, view: View, value: Value) -> Result<(), Outcome> {
        let full = self.machine.read(view.register);
        let width = full.width();
        if u32::from(view.offset) + u32::from(view.width) > u32::from(width)
            || value.width() != view.width
        {
            return Err(Outcome::Malformed);
        }
        let mask = Bits::ones(view.width)
            .zext(width)
            .shift_left(u32::from(view.offset));
        let place = |old: Bits, new: Bits| {
            old.and(&mask.invert())
                .or(&new.zext(width).shift_left(u32::from(view.offset)))
        };
        let merged = Value::with_mask(
            place(full.bits, value.bits),
            place(full.undefined, value.undefined),
        );
        self.journal.push(Undo::Register(view.register, full));
        self.machine.write(view.register, merged);
        Ok(())
    }

    fn eval(&mut self, id: ExprId) -> Result<Value, Outcome> {
        if let Some(&(generation, value)) = self.known.get(id.0 as usize)
            && generation == self.generation
        {
            return Ok(value);
        }
        let value = self.compute(id)?;
        if let Some(slot) = self.known.get_mut(id.0 as usize) {
            *slot = (self.generation, value);
        }
        Ok(value)
    }

    fn compute(&mut self, id: ExprId) -> Result<Value, Outcome> {
        let (expr, width) = self.semantics.expr(id).ok_or(Outcome::Malformed)?;
        let value = match expr {
            Expr::Const(bits) => Value::defined(bits),
            Expr::Local(local) => self
                .locals
                .get(local.0 as usize)
                .copied()
                .flatten()
                .ok_or(Outcome::Malformed)?,
            Expr::Undefined { serial, .. } => match self.semantics.site(serial) {
                Some(site) => {
                    let inputs = site
                        .inputs
                        .iter()
                        .map(|&input| self.eval(input))
                        .collect::<Result<Vec<_>, _>>()?;
                    let value = self.machine.undefined(site.site, &inputs, width);
                    if value.width() == width {
                        value
                    } else {
                        Value::unknown(width)
                    }
                }
                None => Value::unknown(width),
            },
            Expr::Unary(op, a) => unary(op, self.eval(a)?),
            Expr::Binary(op, a, b) => {
                let (a, b) = (self.eval(a)?, self.eval(b)?);
                binary(op, a, b)
            }
            Expr::Flag(op, a, b, c) => {
                let (a, b, c) = (self.eval(a)?, self.eval(b)?, self.eval(c)?);
                flag(op, a, b, c)
            }
            Expr::Extract {
                value,
                offset,
                width,
            } => extract(self.eval(value)?, offset, width),
            Expr::Concat { high, low } => {
                let (high, low) = (self.eval(high)?, self.eval(low)?);
                concat(high, low)
            }
            Expr::Extend {
                signed,
                value,
                width,
            } => extend(signed, self.eval(value)?, width),
            Expr::Select {
                condition,
                then,
                otherwise,
            } => {
                let condition = self.eval(condition)?;
                let (then, otherwise) = (self.eval(then)?, self.eval(otherwise)?);
                select(condition, then, otherwise)
            }
            Expr::Lanes {
                lanes: count,
                op,
                operands,
            } => {
                let mut values = Vec::with_capacity(op.arity());
                for &operand in operands.iter().take(op.arity()) {
                    values.push(self.eval(operand)?);
                }
                lanes(op, count, &values)
            }
            Expr::Float {
                op,
                format,
                lanes: count,
                output,
                rounding,
                operands,
            } => {
                let rounding = self.eval(rounding)?;
                let mut values = Vec::with_capacity(op.arity());
                for &operand in operands.iter().take(op.arity()) {
                    values.push(self.eval(operand)?);
                }
                float(op, format, count, output, rounding, &values)
            }
        };
        if value.width() == width {
            Ok(value)
        } else {
            Err(Outcome::Malformed)
        }
    }
}

/// `op` applied to `a`. Not and byte swap pass undefined bits on exactly;
/// the others give a fully undefined result if any input bit is.
pub fn unary(op: Unary, a: Value) -> Value {
    let width = a.width();
    match op {
        Unary::Not => Value::with_mask(a.bits.invert(), a.undefined),
        Unary::Neg => Value::strict(a.bits.wrapping_neg(), &[&a]),
        Unary::Popcount => {
            Value::strict(Bits::from_u64(width, u64::from(a.bits.popcount())), &[&a])
        }
        Unary::LeadingZeros => Value::strict(
            Bits::from_u64(width, u64::from(a.bits.leading_zeros())),
            &[&a],
        ),
        Unary::TrailingZeros => Value::strict(
            Bits::from_u64(width, u64::from(a.bits.trailing_zeros())),
            &[&a],
        ),
        Unary::ByteSwap => Value::with_mask(a.bits.byte_swap(), a.undefined.byte_swap()),
        Unary::EvenParity8 => {
            let low = Value::with_mask(
                a.bits.extract(0, 8.min(width)),
                a.undefined.extract(0, 8.min(width)),
            );
            Value::strict(
                Bits::from_bool(low.bits.popcount().is_multiple_of(2)),
                &[&low],
            )
        }
    }
}

/// `op` applied to `a` and `b` (of the same width). Bitwise operations, and
/// shifts and rotations by a defined count, pass undefined bits on exactly;
/// the others give a fully undefined result if any input bit is.
pub fn binary(op: Binary, a: Value, b: Value) -> Value {
    let (x, y) = (&a.bits, &b.bits);
    let width = x.width();
    let either = a.undefined.or(&b.undefined);
    // Bits each operand defines as 0 or as 1, which decide AND or OR
    // whatever the other operand's bit is.
    let zeros = |v: &Value| v.undefined.or(&v.bits).invert();
    let ones = |v: &Value| v.undefined.invert().and(&v.bits);
    match op {
        Binary::And => {
            let decided = zeros(&a).or(&zeros(&b));
            Value::with_mask(x.and(y), either.and(&decided.invert()))
        }
        Binary::Or => {
            let decided = ones(&a).or(&ones(&b));
            Value::with_mask(x.or(y), either.and(&decided.invert()))
        }
        Binary::Xor => Value::with_mask(x.xor(y), either),
        Binary::Shl | Binary::LShr | Binary::AShr | Binary::Rol | Binary::Ror => {
            let Some(count) = b.known() else {
                return Value::unknown(width);
            };
            // A rotation's count is taken modulo the width before it could
            // saturate.
            let count = if matches!(op, Binary::Rol | Binary::Ror) {
                modulo(&count, u32::from(width))
            } else {
                count.as_count()
            };
            let shift = |bits: Bits| shift(op, bits, count);
            let undefined = if op == Binary::AShr && a.undefined.msb() {
                // Bits shifted in copy the sign, so they are as undefined
                // as the sign.
                let shifted = shift(a.undefined);
                let fill = Bits::ones(width).shift_left(u32::from(width).saturating_sub(count));
                shifted.or(&fill)
            } else {
                shift(a.undefined)
            };
            Value::with_mask(shift(*x), undefined)
        }
        Binary::Add => Value::strict(x.wrapping_add(y), &[&a, &b]),
        Binary::Sub => Value::strict(x.wrapping_sub(y), &[&a, &b]),
        Binary::Mul => Value::strict(mul(x, y), &[&a, &b]),
        Binary::UDiv => Value::strict(udiv(x, y), &[&a, &b]),
        Binary::URem => Value::strict(urem(x, y), &[&a, &b]),
        Binary::SDiv => Value::strict(sdiv(x, y), &[&a, &b]),
        Binary::SRem => Value::strict(srem(x, y), &[&a, &b]),
        Binary::Eq => Value::strict(Bits::from_bool(x == y), &[&a, &b]),
        Binary::Ne => Value::strict(Bits::from_bool(x != y), &[&a, &b]),
        Binary::ULt => Value::strict(Bits::from_bool(x.ucmp(y) == Ordering::Less), &[&a, &b]),
        Binary::ULe => Value::strict(Bits::from_bool(x.ucmp(y) != Ordering::Greater), &[&a, &b]),
        Binary::SLt => Value::strict(Bits::from_bool(x.scmp(y) == Ordering::Less), &[&a, &b]),
        Binary::SLe => Value::strict(Bits::from_bool(x.scmp(y) != Ordering::Greater), &[&a, &b]),
    }
}

/// `bits` modulo `divisor` (not 0), exactly.
fn modulo(bits: &Bits, divisor: u32) -> u32 {
    let bytes: Vec<u8> = bits.to_le_bytes().collect();
    let remainder = bytes.iter().rev().fold(0u64, |remainder, &byte| {
        (remainder << 8 | u64::from(byte)) % u64::from(divisor.max(1))
    });
    u32::try_from(remainder).unwrap_or(0)
}

fn shift(op: Binary, bits: Bits, count: u32) -> Bits {
    let width = u32::from(bits.width());
    match op {
        Binary::Shl => bits.shift_left(count),
        Binary::LShr => bits.shift_right(count),
        Binary::AShr => bits.shift_right_signed(count),
        Binary::Rol => {
            let count = count % width;
            if count == 0 {
                bits
            } else {
                bits.shift_left(count).or(&bits.shift_right(width - count))
            }
        }
        Binary::Ror => {
            let count = count % width;
            if count == 0 {
                bits
            } else {
                bits.shift_right(count).or(&bits.shift_left(width - count))
            }
        }
        Binary::Add
        | Binary::Sub
        | Binary::Mul
        | Binary::UDiv
        | Binary::URem
        | Binary::SDiv
        | Binary::SRem
        | Binary::And
        | Binary::Or
        | Binary::Xor
        | Binary::Eq
        | Binary::Ne
        | Binary::ULt
        | Binary::ULe
        | Binary::SLt
        | Binary::SLe => bits,
    }
}

/// The 1-bit flag `op` computes from `a`, `b` and `c` (of the same width):
/// fully undefined if any input bit is.
pub fn flag(op: Flag, a: Value, b: Value, c: Value) -> Value {
    Value::strict(
        Bits::from_bool(flag_bits(op, &a.bits, &b.bits, &c.bits)),
        &[&a, &b, &c],
    )
}

/// `width` bits of `value` from bit `offset`, undefined where those bits are.
pub fn extract(value: Value, offset: u16, width: u16) -> Value {
    Value::with_mask(
        value.bits.extract(offset, width),
        value.undefined.extract(offset, width),
    )
}

/// `high` above `low`, each part's undefined bits kept.
pub fn concat(high: Value, low: Value) -> Value {
    Value::with_mask(
        high.bits.concat(&low.bits),
        high.undefined.concat(&low.undefined),
    )
}

/// `value` sign- (`signed`) or zero-extended to `width` bits: new bits are
/// as undefined as the sign, or defined zeros.
pub fn extend(signed: bool, value: Value, width: u16) -> Value {
    if signed {
        Value::with_mask(value.bits.sext(width), value.undefined.sext(width))
    } else {
        Value::with_mask(value.bits.zext(width), value.undefined.zext(width))
    }
}

/// `then` if the 1-bit `condition` is 1, else `otherwise`; fully undefined
/// (of `then`'s width) if the condition is.
pub fn select(condition: Value, then: Value, otherwise: Value) -> Value {
    match condition.known() {
        Some(bits) if bits.is_zero() => otherwise,
        Some(_) => then,
        None => Value::unknown(then.width()),
    }
}

/// `op` lane by lane on `count` lanes of `operands` (as many as `op`
/// takes), each lane as [`unary`], [`binary`], [`extract`], [`extend`] or
/// [`select`] would compute it.
pub fn lanes(op: LaneOp, count: u16, operands: &[Value]) -> Value {
    let count = count.max(1);
    let mut result: Option<Value> = None;
    for lane in 0..count {
        let part = |index: usize| {
            operands.get(index).map_or(Value::unknown(1), |value| {
                let width = value.width() / count;
                extract(*value, lane * width, width.max(1))
            })
        };
        let value = match op {
            LaneOp::Unary(op) => unary(op, part(0)),
            LaneOp::Binary(op) => binary(op, part(0), part(1)),
            LaneOp::Extract { offset, width } => extract(part(0), offset, width),
            LaneOp::Extend { signed, width } => extend(signed, part(0), width),
            LaneOp::Select => select(part(0), part(1), part(2)),
        };
        result = Some(match result {
            Some(low) => concat(value, low),
            None => value,
        });
    }
    result.unwrap_or(Value::unknown(1))
}

/// The IEEE operation `op` on `count` lanes of `format` (`operands` as many
/// as `op` takes), rounded as `rounding` says: its result or its
/// exceptions. A lane is fully undefined if any bit of its operands, or of
/// the rounding, is.
pub fn float(
    op: FloatOp,
    format: Format,
    count: u16,
    output: FloatOutput,
    rounding: Value,
    operands: &[Value],
) -> Value {
    let count = count.max(1);
    let result_lane = match output {
        FloatOutput::Status => EXCEPTIONS,
        FloatOutput::Value => match op {
            FloatOp::Compare { .. } => 4,
            FloatOp::Convert(target) => target.width(),
            FloatOp::ToInt { width, .. } => width,
            FloatOp::Add
            | FloatOp::Sub
            | FloatOp::Mul
            | FloatOp::Div
            | FloatOp::Sqrt
            | FloatOp::MulAdd
            | FloatOp::RoundToIntegral
            | FloatOp::FromInt { .. } => format.width(),
        },
    };
    let mut result: Option<Value> = None;
    for lane in 0..count {
        let parts: Vec<Value> = operands
            .iter()
            .map(|value| {
                let width = value.width() / count;
                extract(*value, lane * width, width.max(1))
            })
            .collect();
        let known: Option<Vec<Bits>> = parts.iter().map(Value::known).collect();
        let value = match (rounding.known(), known) {
            (Some(rounding), Some(parts)) => {
                let rounding = Rounding::of_bits(rounding.low_u64());
                let (value, status) = float::lane(op, format, rounding, &parts);
                Value::defined(match output {
                    FloatOutput::Value => value,
                    FloatOutput::Status => Bits::from_u64(EXCEPTIONS, u64::from(status)),
                })
            }
            (None | Some(_), None) | (None, Some(_)) => Value::unknown(result_lane),
        };
        result = Some(match result {
            Some(low) => concat(value, low),
            None => value,
        });
    }
    result.unwrap_or(Value::unknown(1))
}

/// Direct evaluation of a flag computation on defined bits.
fn flag_bits(op: Flag, a: &Bits, b: &Bits, c: &Bits) -> bool {
    match op {
        Flag::AddCarry => {
            let (sum, first) = a.add_carry(b, false);
            let (_, second) = sum.add_carry(c, false);
            first || second
        }
        Flag::AddOverflow => {
            let result = a.wrapping_add(b).wrapping_add(c);
            a.msb() == b.msb() && result.msb() != a.msb()
        }
        Flag::SubBorrow => {
            let width = a.width() + 1;
            let subtrahend = b.zext(width).wrapping_add(&c.zext(width));
            a.zext(width).ucmp(&subtrahend) == Ordering::Less
        }
        Flag::SubOverflow => {
            let result = a.wrapping_sub(b).wrapping_sub(c);
            a.msb() != b.msb() && result.msb() != a.msb()
        }
        Flag::NibbleCarry => a.xor(b).xor(c).bit(4),
    }
}

fn mul(x: &Bits, y: &Bits) -> Bits {
    Bits::from_u128(x.width(), x.low_u128().wrapping_mul(y.low_u128()))
}

fn udiv(x: &Bits, y: &Bits) -> Bits {
    match x.low_u128().checked_div(y.low_u128()) {
        Some(quotient) => Bits::from_u128(x.width(), quotient),
        None => Bits::ones(x.width()),
    }
}

fn urem(x: &Bits, y: &Bits) -> Bits {
    match x.low_u128().checked_rem(y.low_u128()) {
        Some(remainder) => Bits::from_u128(x.width(), remainder),
        None => *x,
    }
}

/// `x` as a signed 128-bit integer (sign-extended from its width).
fn signed(x: &Bits) -> i128 {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "two's complement reinterpretation"
    )]
    let value = x.sext(128).low_u128() as i128;
    value
}

#[expect(clippy::cast_sign_loss, reason = "two's complement reinterpretation")]
fn sdiv(x: &Bits, y: &Bits) -> Bits {
    let (a, b) = (signed(x), signed(y));
    if b == 0 {
        return Bits::ones(x.width());
    }
    if b == -1 && x.msb() && x.and(&Bits::ones(x.width()).shift_right(1)).is_zero() {
        // The most negative value divided by -1: the dividend.
        return *x;
    }
    Bits::from_u128(x.width(), a.wrapping_div(b) as u128)
}

#[expect(clippy::cast_sign_loss, reason = "two's complement reinterpretation")]
fn srem(x: &Bits, y: &Bits) -> Bits {
    let (a, b) = (signed(x), signed(y));
    if b == 0 {
        return *x;
    }
    if b == -1 {
        return Bits::zero(x.width());
    }
    Bits::from_u128(x.width(), a.wrapping_rem(b) as u128)
}
