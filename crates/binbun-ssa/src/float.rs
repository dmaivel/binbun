//! The reading view's floating-point assumptions.
//!
//! An architecture's floating-point instruction is an IEEE operation
//! ([`Op::Float`]) inside the architecture's own rules, which L0 states
//! in full: the rounding and the modes its control register holds, the
//! exceptions the register masks and the trap of one it does not, which
//! NaN an operation of a NaN gives, what a conversion out of range
//! gives. C's `a * b` says the operation and leaves the rest to the
//! floating-point environment (C11 7.6) and the implementation (F.2.1:
//! "this specification does not define the behavior of signaling NaNs",
//! nor which NaN an operation gives); a function compiled from it reads
//! the control register only because its instructions do. Two passes
//! take C's reading:
//!
//! - [`AssumeFloatControls`]: the control register's controls are, at
//!   entry, what a process starts with. Every read of them from a value
//!   that keeps them from entry is that constant, and the operations
//!   that follow from it fold ([`fold`]): the rounding is to nearest,
//!   the denormal modes are off, every exception is masked and its trap
//!   gone.
//! - [`AssumeFloatResults`]: a NaN is not told from another, so where an
//!   operation's result is chosen among NaNs by the operands' (x86: the
//!   first NaN operand quieted, else the indefinite; AArch64: the first
//!   signalling NaN, else the first NaN, else the default NaN), it is the
//!   operation's; and a float converted to an integer is in the
//!   integer's range (C11 6.3.1.4: undefined otherwise), so the
//!   conversion never raises invalid and its operand is no NaN.
//!
//! Unlike the reading view's other assumptions these settle values, not
//! only traps: a run under other controls, one that looks at a NaN's
//! payload, or one that converts out of range, computes something else.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::interpret::Value as Bitvalue;
use binbun_semantics::ir::{Binary, EXCEPTIONS, FloatOp, FloatOutput, Format, LaneOp, RegisterId};

use crate::condition::defining;
use crate::constant::evaluate;
use crate::ir::{BlockId, Definition, Function, Inst, InstId, Op, Type, Unknown, Value, ValueInfo};
use crate::pass::L1Env;

/// A floating-point control register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    /// The register.
    pub register: RegisterId,
    /// How many of its low bits are status flags; the bits above are its
    /// controls.
    pub status_bits: u16,
    /// Its value when a process starts.
    pub default: u64,
}

/// The pass `assume-default-float-controls`, the reading view's
/// assumption that a floating-point control register's controls are at
/// entry what a process starts with (x86-64's MXCSR: to nearest, every
/// exception masked, neither flush-to-zero nor denormals-are-zeros),
/// which the conventions make callee-saved (System V x86-64 3.2.1: "The
/// control bits of the MXCSR register are callee-saved", so a function C
/// was compiled to runs with those its caller had). Every extraction of
/// control bits from a value of the register that has them from entry is
/// that constant: the entry value, what a call left (callees keep the
/// controls), either with status flags raised, a block parameter of such
/// values. A value the function loaded into the register (`ldmxcsr`) is
/// not one. Then the pure operations those constants settle fold
/// ([`fold`]); the branch to an unmasked exception's trap is left on a
/// constant for [`FoldBranches`](crate::constant::FoldBranches).
///
/// Not part of decompilation's exact pipeline, as
/// [`AssumeDereferenced`](crate::stack::AssumeDereferenced). Preserves
/// nothing. Fuel: a unit per instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssumeFloatControls {
    controls: Vec<Control>,
    folded: Vec<u64>,
}

impl AssumeFloatControls {
    /// The pass, for a convention with these control registers.
    pub fn new(controls: Vec<Control>) -> Self {
        Self {
            controls,
            folded: Vec::new(),
        }
    }

    /// The machine instructions whose reads of the controls its runs
    /// assumed, one each, by address.
    pub fn folded(&self) -> &[u64] {
        &self.folded
    }
}

impl<'e> Pass<Function, L1Env<'e>> for AssumeFloatControls {
    fn name(&self) -> &'static str {
        "assume-default-float-controls"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(insts(function))?;
        let mut reads: Vec<(usize, Bits)> = Vec::new();
        for (index, inst) in function.insts.iter().enumerate() {
            let Op::Extract {
                value,
                offset,
                width,
            } = inst.op
            else {
                continue;
            };
            let control = self.controls.iter().find(|control| {
                offset >= control.status_bits && keeps(function, control, value, &mut Vec::new())
            });
            if let Some(control) = control {
                let bits = control.default.checked_shr(u32::from(offset)).unwrap_or(0);
                reads.push((index, Bits::from_u64(width, bits)));
            }
        }
        let mut made = BTreeSet::new();
        let mut sites = BTreeSet::new();
        for (index, bits) in reads {
            if let Some(inst) = function.insts.get_mut(index) {
                inst.op = Op::Const(bits);
                made.extend(inst.results.first().copied());
                sites.insert(inst.address);
            }
        }
        if made.is_empty() {
            return Ok(Changed::No);
        }
        fold(function, made);
        self.folded.extend(sites);
        Ok(Changed::Yes)
    }
}

/// Whether `value` is a value of `control`'s register with its controls
/// from entry: the entry value; what a call or a system call left (the
/// convention keeps the controls across them, and L1 knows nothing else
/// of the register after one); such a value with status flags raised
/// (or-ed with a zero extension of no more bits than the status flags,
/// or a constant within them); a block parameter of such values. `seen`
/// holds the block parameters being looked at (a loop's keeps them if
/// its other incoming values do).
fn keeps(function: &Function, control: &Control, value: Value, seen: &mut Vec<Value>) -> bool {
    let Some(info) = function.value(value) else {
        return false;
    };
    let (inst, index) = match info.definition {
        Definition::Parameter {
            block: BlockId(0),
            index,
        } => return index == u32::from(control.register.0),
        Definition::Parameter { block, index } => {
            if seen.contains(&value) {
                return true;
            }
            seen.push(value);
            let incoming: Vec<Option<Value>> = function
                .blocks
                .iter()
                .flat_map(|from| from.terminator.targets())
                .filter(|target| target.block == block)
                .map(|target| target.arguments.get(index as usize).copied())
                .collect();
            return incoming.into_iter().all(|argument| {
                argument.is_some_and(|argument| keeps(function, control, argument, seen))
            });
        }
        Definition::Result { inst, index } => (inst, index),
    };
    let flags = |x: Value| match defining(function, x) {
        Some(&Op::Extend {
            signed: false,
            value,
            ..
        }) => matches!(function.ty(value), Some(Type::Bits(width)) if width <= control.status_bits),
        Some(Op::Const(bits)) => {
            let leading = u16::try_from(bits.leading_zeros()).unwrap_or(u16::MAX);
            bits.width().saturating_sub(leading) <= control.status_bits
        }
        Some(_) | None => false,
    };
    match function.inst(inst).map(|i| &i.op) {
        Some(&Op::Binary(Binary::Or, a, b)) => {
            (flags(b) && keeps(function, control, a, seen))
                || (flags(a) && keeps(function, control, b, seen))
        }
        Some(Op::Call { changes, .. } | Op::SystemCall { changes, .. }) => {
            // The results: the memory, then the registers changed.
            index
                .checked_sub(1)
                .and_then(|at| changes.get(at as usize))
                .is_some_and(|&register| register == control.register)
        }
        Some(&Op::Undefined(Unknown::Call { register, .. }, _)) => register == control.register,
        Some(_) | None => false,
    }
}

/// The pass `assume-empty-x87-stack`, the reading view's assumption that
/// the x87 register stack is empty at a function's entry with TOP 0: no
/// convention passes an argument there (System V x86-64 §3.2.3: an
/// argument of the X87 classes is passed in memory; Microsoft x64: "The
/// x87 register stack is unused"), a process starts with the stack empty
/// and TOP 0, and code that keeps the stack balanced across calls leaves
/// it so. The entry values of `registers` (the abridged tag word, every
/// register free, and TOP) are 0 in every use, and the pure operations
/// that settles fold ([`fold`]): a stored environment's tag word is all
/// empty whatever the registers hold (`fnstenv`), so their entry values
/// are not read.
///
/// Not part of decompilation's exact pipeline. Preserves nothing. Fuel: a
/// unit per instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssumeEmptyX87 {
    registers: Vec<RegisterId>,
    folded: Vec<u64>,
}

impl AssumeEmptyX87 {
    /// The pass, for the x87 stack's tag word and TOP, `registers` (none
    /// on another architecture).
    pub fn new(registers: Vec<RegisterId>) -> Self {
        Self {
            registers,
            folded: Vec::new(),
        }
    }

    /// The machine instructions whose reads of the tag word or TOP at
    /// entry its runs assumed, one each, by address.
    pub fn folded(&self) -> &[u64] {
        &self.folded
    }
}

impl<'e> Pass<Function, L1Env<'e>> for AssumeEmptyX87 {
    fn name(&self) -> &'static str {
        "assume-empty-x87-stack"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(insts(function))?;
        // Each register's entry value (the entry block's parameters are
        // in register order) and the constant 0 that replaces it.
        let entry = function.blocks.first().map_or(&[][..], |b| &b.parameters);
        let mut entries: Vec<(Value, u16)> = self
            .registers
            .iter()
            .filter_map(|register| {
                let value = *entry.get(usize::from(register.0))?;
                match function.ty(value)? {
                    Type::Bits(width) => Some((value, width)),
                    Type::Memory => None,
                }
            })
            .collect();
        // Only an entry value an instruction computes with gets a constant:
        // a call (which passes every register on) and a terminator (an exit
        // state, a jump's arguments) neither assume nor change it.
        let mut read = BTreeSet::new();
        for inst in function.insts.iter().filter(|inst| computes(&inst.op)) {
            read.extend(inst.op.operands());
            read.extend(inst.op.inputs().iter().copied());
        }
        entries.retain(|(value, _)| read.contains(value));
        if entries.is_empty() {
            return Ok(Changed::No);
        }
        let mut replace = BTreeMap::new();
        for (value, width) in entries {
            let inst = InstId(u32::try_from(function.insts.len()).unwrap_or(u32::MAX));
            let zero = Value(u32::try_from(function.values.len()).unwrap_or(u32::MAX));
            function.values.push(ValueInfo {
                ty: Type::Bits(width),
                definition: Definition::Result { inst, index: 0 },
            });
            function.insts.push(Inst {
                op: Op::Const(Bits::from_u64(width, 0)),
                results: vec![zero],
                address: function.entry,
            });
            if let Some(block) = function.blocks.first_mut() {
                block.insts.insert(0, inst);
            }
            replace.insert(value, zero);
        }
        let mut sites = BTreeSet::new();
        let mut made = BTreeSet::new();
        for inst in function.insts.iter_mut().filter(|inst| computes(&inst.op)) {
            let mut used = false;
            inst.op.map_values(&mut |v| match replace.get(&v) {
                Some(&zero) => {
                    used = true;
                    zero
                }
                None => v,
            });
            if used {
                sites.insert(inst.address);
                made.extend(replace.values().copied());
            }
        }
        fold(function, made);
        self.folded.extend(sites);
        Ok(Changed::Yes)
    }
}

/// Whether `op` computes with what it reads ([`AssumeEmptyX87`]): not a
/// call or a system call, which pass every register on.
const fn computes(op: &Op) -> bool {
    !matches!(op, Op::Call { .. } | Op::SystemCall { .. })
}

/// The pass `assume-float-results`, the reading view's assumptions about
/// what floating-point operations give where C does not say:
///
/// - A NaN is not told from another. A choice, lane by lane, of a NaN
///   where a value `x` is a NaN (`x` itself, quieted or not; a constant
///   NaN; `x` in another format) and otherwise of a value that is a NaN
///   whenever `x` is (`x`; an arithmetic operation, a square root, a
///   rounding or a conversion of `x`) is that value: the operation's own
///   NaN. x86's rule for an operation's NaN (the first NaN operand
///   quieted, else the indefinite) is such a chain of choices. Where the
///   condition holds only if some of the operation's operands are NaNs
///   (a NaN test of each, or-ed; or and-ed with anything), the NaN chosen
///   may be any choice among its operands' NaNs, quieted or not, and
///   constant NaNs: AArch64's (`FPProcessNaNs`: the first signalling NaN,
///   else the first NaN; the default NaN where the result is a NaN;
///   FMA's default NaN for a quiet NaN addend and an infinity times a
///   zero).
/// - A float converted to an integer is in the integer's range: the
///   conversion's status never has invalid, so the choice of what the
///   architecture gives when it does (x86: the integer indefinite) is the
///   conversion's result; and its operand is no NaN, so a choice made
///   where that operand is one (AArch64: 0) is the conversion too.
///
/// Run after [`AssumeFloatControls`], whose folds leave the choices in
/// this form. Not part of decompilation's exact pipeline. Preserves
/// nothing. Fuel: a unit per instruction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssumeFloatResults {
    folded: Vec<u64>,
}

impl AssumeFloatResults {
    /// The machine instructions whose results its runs assumed, one
    /// each, by address.
    pub fn folded(&self) -> &[u64] {
        &self.folded
    }
}

impl<'e> Pass<Function, L1Env<'e>> for AssumeFloatResults {
    fn name(&self) -> &'static str {
        "assume-float-results"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(insts(function))?;
        let mut sites = BTreeSet::new();
        // Conversions to integers never raise invalid.
        let mut made = BTreeSet::new();
        for index in 0..function.insts.len() {
            if !in_range(function, index) {
                continue;
            }
            let width = function
                .insts
                .get(index)
                .and_then(|inst| inst.results.first())
                .and_then(|&result| function.ty(result));
            if let Some(inst) = function.insts.get_mut(index)
                && let Some(Type::Bits(width)) = width
            {
                inst.op = Op::Const(Bits::zero(width));
                made.extend(inst.results.first().copied());
                sites.insert(inst.address);
            }
        }
        if !made.is_empty() {
            fold(function, made);
        }
        // An operation's NaN is its own.
        let mut alias: BTreeMap<Value, Value> = BTreeMap::new();
        loop {
            let mut changed = false;
            for inst in &function.insts {
                let [result] = inst.results[..] else {
                    continue;
                };
                if alias.contains_key(&result) {
                    continue;
                }
                let look = Look {
                    function,
                    alias: &alias,
                };
                if let Some(value) = look.own_nan(&inst.op) {
                    alias.insert(result, value);
                    sites.insert(inst.address);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        replace(function, &alias);
        if sites.is_empty() {
            return Ok(Changed::No);
        }
        self.folded.extend(sites);
        Ok(Changed::Yes)
    }
}

/// Whether instruction `index` reads the invalid flag of a conversion to
/// an integer: bit 0 of a lane of the status of an
/// [`FloatOp::ToInt`].
fn in_range(function: &Function, index: usize) -> bool {
    let Some(inst) = function.insts.get(index) else {
        return false;
    };
    let status = if let Op::Extract {
        value,
        offset,
        width: 1,
    } = inst.op
        && offset % EXCEPTIONS == 0
    {
        value
    } else if let Op::Lanes {
        op: LaneOp::Extract {
            offset: 0,
            width: 1,
        },
        operands: [value, ..],
        ..
    } = inst.op
    {
        value
    } else {
        return false;
    };
    matches!(
        defining(function, status),
        Some(Op::Float {
            op: FloatOp::ToInt { .. },
            output: FloatOutput::Status,
            ..
        })
    )
}

/// A function with the values a pass has replaced so far.
struct Look<'a> {
    function: &'a Function,
    alias: &'a BTreeMap<Value, Value>,
}

impl Look<'_> {
    fn value(&self, value: Value) -> Value {
        resolve(self.alias, value)
    }

    fn op(&self, value: Value) -> Option<&Op> {
        defining(self.function, self.value(value))
    }

    fn constant(&self, value: Value) -> Option<Bits> {
        match self.op(value) {
            Some(Op::Const(bits)) => Some(*bits),
            Some(_) | None => None,
        }
    }

    /// What `op` gives if it is a choice, whole or lane by lane, whose
    /// condition holds only where some values are NaNs: the value chosen
    /// otherwise, where it is an operation of those values (a NaN
    /// whenever one is: its own NaN then) and the value chosen where the
    /// condition holds is a NaN of theirs or of its other operands, or a
    /// constant NaN, or a choice among such (x86: the first NaN operand
    /// quieted, else the indefinite, a chain of such choices; AArch64's
    /// `FPProcessNaNs`: the first signalling NaN, else the first NaN, where
    /// any operand is a NaN, and the default NaN where the result is);
    /// or a conversion of one of the values to an integer, which is of a
    /// number (in range).
    fn own_nan(&self, op: &Op) -> Option<Value> {
        let (lanes, condition, then, otherwise) = choice(op)?;
        let tested = self.implied(condition, lanes, DEPTH)?;
        let &(_, format) = tested.first()?;
        if tested.iter().any(|&(_, of)| of != format) {
            return None;
        }
        if self.converts(otherwise, &tested, lanes) {
            return Some(self.value(otherwise));
        }
        let mut result = None;
        for &(x, _) in &tested {
            let of = self.nan_of(otherwise, x, format, lanes)?;
            if result.is_some_and(|result| result != of) {
                return None;
            }
            result = Some(of);
        }
        let result = result?;
        let mut operands: Vec<Value> = tested.iter().map(|&(x, _)| x).collect();
        operands.extend(self.operation_operands(otherwise));
        self.chooses_nan(then, &operands, format, result, lanes, DEPTH)
            .then(|| self.value(otherwise))
    }

    /// `value`'s binary operation, whole (1 lane) or lane by lane: lanes,
    /// operation, operands.
    fn binary(&self, value: Value) -> Option<(u16, Binary, Value, Value)> {
        let op = self.op(value)?;
        if let Op::Binary(binary, a, b) = *op {
            Some((1, binary, a, b))
        } else if let Op::Lanes {
            lanes,
            op: LaneOp::Binary(binary),
            operands: [a, b, _],
        } = *op
        {
            Some((lanes, binary, a, b))
        } else {
            None
        }
    }

    /// `value`'s extraction of bits, whole (1 lane) or lane by lane:
    /// lanes, first bit, width, the value extracted from.
    fn extract(&self, value: Value) -> Option<(u16, u16, u16, Value)> {
        let op = self.op(value)?;
        if let Op::Extract {
            value,
            offset,
            width,
        } = *op
        {
            Some((1, offset, width, value))
        } else if let Op::Lanes {
            lanes,
            op: LaneOp::Extract { offset, width },
            operands: [value, ..],
        } = *op
        {
            Some((lanes, offset, width, value))
        } else {
            None
        }
    }

    /// The values (and their format) of which `condition` holding in each
    /// of its `lanes` lanes says one is a NaN: a NaN test's; either side's
    /// of an and; both sides' of an or (but a constant 0 side's), `depth`
    /// operations deep.
    fn implied(&self, condition: Value, lanes: u16, depth: u8) -> Option<Vec<(Value, Format)>> {
        if let Some(tested) = self.nan_test(condition, lanes) {
            return Some(vec![tested]);
        }
        let depth = depth.checked_sub(1)?;
        let (count, binary, a, b) = self.binary(condition)?;
        if count != lanes {
            return None;
        }
        let zero = |value: Value| self.constant(value).is_some_and(|bits| bits.is_zero());
        if binary == Binary::And {
            self.implied(a, lanes, depth)
                .or_else(|| self.implied(b, lanes, depth))
        } else if binary == Binary::Or {
            if zero(a) {
                return self.implied(b, lanes, depth);
            }
            if zero(b) {
                return self.implied(a, lanes, depth);
            }
            let mut tested = self.implied(a, lanes, depth)?;
            tested.extend(self.implied(b, lanes, depth)?);
            Some(tested)
        } else {
            None
        }
    }

    /// `value` without the bits above it it was concatenated under and
    /// then extracted from again (L0 entries give a result with its
    /// exceptions above it).
    fn peel(&self, value: Value) -> Value {
        let mut value = self.value(value);
        for _ in 0..DEPTH {
            let Some((1, 0, width, whole)) = self.extract(value) else {
                break;
            };
            let Some(&Op::Concat { low, .. }) = self.op(whole) else {
                break;
            };
            if self.function.ty(self.value(low)) != Some(Type::Bits(width)) {
                break;
            }
            value = self.value(low);
        }
        value
    }

    /// The operands of the floating-point operation `value` is (through
    /// [`Self::peel`]), if it is one.
    fn operation_operands(&self, value: Value) -> Vec<Value> {
        match self.op(self.peel(value)) {
            Some(&Op::Float { op, operands, .. }) => {
                operands.into_iter().take(op.arity()).collect()
            }
            Some(_) | None => Vec::new(),
        }
    }

    /// Whether `value` is a conversion to an integer, lane by lane, of one
    /// of the values `tested`.
    fn converts(&self, value: Value, tested: &[(Value, Format)], lanes: u16) -> bool {
        let Some(&Op::Float {
            op: FloatOp::ToInt { .. },
            format,
            lanes: n,
            output: FloatOutput::Value,
            operands: [operand, ..],
            ..
        }) = self.op(self.peel(value))
        else {
            return false;
        };
        n == lanes
            && tested
                .iter()
                .any(|&(x, of)| of == format && self.value(x) == self.value(operand))
    }

    /// Whether `value` (of `result`) is a NaN, lane by lane, of one of
    /// `operands` (of `format`), quieted or not, or a constant NaN, or an
    /// operand's constant (quieted), or a choice among such, quieted or
    /// not (or-ed with a constant), `depth` operations deep: the NaN an
    /// operation chooses among its operands'.
    fn chooses_nan(
        &self,
        value: Value,
        operands: &[Value],
        format: Format,
        result: Format,
        lanes: u16,
        depth: u8,
    ) -> bool {
        if operands
            .iter()
            .any(|&x| self.is_nan(value, x, format, result, lanes, DEPTH))
        {
            return true;
        }
        if let Some(bits) = self.constant(value) {
            let (fraction, _) = fields(format);
            let quiet = Bits::from_u64(bits.width(), 1).shift_left(u32::from(fraction) - 1);
            return format == result
                && operands.iter().any(|&x| {
                    self.constant(x)
                        .is_some_and(|operand| operand == bits || operand.or(&quiet) == bits)
                });
        }
        let Some(depth) = depth.checked_sub(1) else {
            return false;
        };
        if let Some((n, Binary::Or, a, b)) = self.binary(value)
            && n == lanes
        {
            return [(a, b), (b, a)].into_iter().any(|(chosen, quiet)| {
                self.constant(quiet).is_some()
                    && self.chooses_nan(chosen, operands, format, result, lanes, depth)
            });
        }
        let Some((n, _, then, otherwise)) = self.op(value).and_then(choice) else {
            return false;
        };
        n == lanes
            && self.chooses_nan(then, operands, format, result, lanes, depth)
            && self.chooses_nan(otherwise, operands, format, result, lanes, depth)
    }

    /// The value `condition` tests for a NaN in each of its `lanes`
    /// lanes (1: the whole value), and its format: the exponent all ones
    /// and the fraction not 0.
    fn nan_test(&self, condition: Value, lanes: u16) -> Option<(Value, Format)> {
        let (count, binary, first, second) = self.binary(condition)?;
        if count != lanes || binary != Binary::And {
            return None;
        }
        [(first, second), (second, first)]
            .into_iter()
            .find_map(|(exponent, fraction)| {
                let (tested, format) = self.field_test(exponent, lanes, true)?;
                let (other, same) = self.field_test(fraction, lanes, false)?;
                (self.value(tested) == self.value(other) && format == same)
                    .then_some((tested, format))
            })
    }

    /// The value and format `test` tests a field of in each lane: the
    /// exponent for all ones (`exponent`), or the fraction for not 0.
    fn field_test(&self, test: Value, lanes: u16, exponent: bool) -> Option<(Value, Format)> {
        let (n, relation, field, constant) = self.binary(test)?;
        let (m, offset, width, x) = self.extract(field)?;
        let bits = self.constant(constant)?;
        let holds = if exponent {
            relation == Binary::Eq && bits == Bits::ones(bits.width())
        } else {
            relation == Binary::Ne && bits.is_zero()
        };
        if !holds || n != lanes || m != lanes {
            return None;
        }
        let format = [Format::Half, Format::Single, Format::Double]
            .into_iter()
            .find(|&format| {
                let (fraction, exponent_bits) = fields(format);
                if exponent {
                    (offset, width) == (fraction, exponent_bits)
                } else {
                    (offset, width) == (0, fraction)
                }
            })?;
        let wide = format.width().checked_mul(lanes)?;
        (self.function.ty(self.value(x)) == Some(Type::Bits(wide))).then_some((x, format))
    }

    /// The format of `value`'s lanes if each is a NaN whenever `x`'s (of
    /// `format`) is: `x` itself, or an operation of `x` that gives a
    /// NaN for a NaN operand (through [`Self::peel`]).
    fn nan_of(&self, value: Value, x: Value, format: Format, lanes: u16) -> Option<Format> {
        let x = self.peel(x);
        let value = self.peel(value);
        if value == x {
            return Some(format);
        }
        let &Op::Float {
            op,
            format: of,
            lanes: n,
            output: FloatOutput::Value,
            operands,
            ..
        } = self.op(value)?
        else {
            return None;
        };
        let result = match op {
            FloatOp::Add
            | FloatOp::Sub
            | FloatOp::Mul
            | FloatOp::Div
            | FloatOp::Sqrt
            | FloatOp::MulAdd
            | FloatOp::RoundToIntegral => of,
            FloatOp::Convert(target) => target,
            FloatOp::Compare { .. } | FloatOp::FromInt { .. } | FloatOp::ToInt { .. } => {
                return None;
            }
        };
        let takes = operands
            .iter()
            .take(op.arity())
            .any(|&operand| self.peel(operand) == x);
        (of == format && n == lanes && takes).then_some(result)
    }

    /// Whether each lane of `value` (of `result`) is a NaN whenever
    /// `x`'s (of `format`) is: `x` itself in its own format, a constant
    /// of NaNs, or either or-ed with anything (the exponent stays all
    /// ones and the fraction not 0).
    fn is_nan(
        &self,
        value: Value,
        x: Value,
        format: Format,
        result: Format,
        lanes: u16,
        depth: u8,
    ) -> bool {
        if format == result && self.value(value) == self.value(x) {
            return true;
        }
        if let Some(bits) = self.constant(value) {
            return nans(&bits, result, lanes);
        }
        let Some(depth) = depth.checked_sub(1) else {
            return false;
        };
        match self.op(value) {
            Some(
                &(Op::Binary(Binary::Or, a, b)
                | Op::Lanes {
                    op: LaneOp::Binary(Binary::Or),
                    operands: [a, b, _],
                    ..
                }),
            ) => {
                self.is_nan(a, x, format, result, lanes, depth)
                    || self.is_nan(b, x, format, result, lanes, depth)
            }
            Some(_) | None => false,
        }
    }
}

/// How many operations deep [`Look::is_nan`] looks into an or.
const DEPTH: u8 = 6;

/// A choice's lanes (1 for a whole one), condition, and the values
/// chosen where it holds and where not.
fn choice(op: &Op) -> Option<(u16, Value, Value, Value)> {
    if let Op::Select {
        condition,
        then,
        otherwise,
    } = *op
    {
        Some((1, condition, then, otherwise))
    } else if let Op::Lanes {
        lanes,
        op: LaneOp::Select,
        operands: [condition, then, otherwise],
    } = *op
    {
        Some((lanes, condition, then, otherwise))
    } else {
        None
    }
}

/// The widths of `format`'s fraction and exponent.
const fn fields(format: Format) -> (u16, u16) {
    match format {
        Format::Half => (10, 5),
        Format::Single => (23, 8),
        Format::Double => (52, 11),
        Format::Extended => (63, 15),
    }
}

/// Whether `bits` is `lanes` NaNs of `format`.
fn nans(bits: &Bits, format: Format, lanes: u16) -> bool {
    let (fraction, exponent) = fields(format);
    let width = format.width();
    bits.width() == width.saturating_mul(lanes)
        && (0..lanes).all(|lane| {
            let lane = bits.extract(lane * width, width);
            lane.extract(fraction, exponent) == Bits::ones(exponent)
                && !lane.extract(0, fraction).is_zero()
        })
}

/// What a pure operation folds to.
enum Folded {
    Constant(Bits),
    Value(Value),
}

/// Folds the pure operations of `function` that the constants `made`
/// settle, to a fixed point: an operation of constants is its constant
/// (as [`Constants`](crate::constant::Constants) evaluates it), `x & 0`
/// and `x | ~0` are those, `x & ~0` and `x | 0` are `x`, a choice on a
/// constant is the value chosen; whole values and lanes alike. Only
/// operations that read a value this changed are looked at (and those
/// reading them), so the rest of the function stays as it was written.
/// An operation that becomes a constant is one in place; one that
/// becomes another value stays, unused, and its uses read that value.
fn fold(function: &mut Function, mut made: BTreeSet<Value>) {
    let mut alias: BTreeMap<Value, Value> = BTreeMap::new();
    loop {
        let mut changed = false;
        for index in 0..function.insts.len() {
            let Some(inst) = function.insts.get(index) else {
                continue;
            };
            let [result] = inst.results[..] else {
                continue;
            };
            let reads = inst
                .op
                .operands()
                .iter()
                .any(|operand| made.contains(operand) || alias.contains_key(operand));
            if !reads || alias.contains_key(&result) {
                continue;
            }
            let mut op = inst.op.clone();
            op.map_values(&mut |value| resolve(&alias, value));
            match folded(function, &op) {
                Some(Folded::Constant(bits))
                    if function.ty(result) == Some(Type::Bits(bits.width())) =>
                {
                    if let Some(inst) = function.insts.get_mut(index) {
                        inst.op = Op::Const(bits);
                    }
                    made.insert(result);
                }
                Some(Folded::Value(value)) if function.ty(result) == function.ty(value) => {
                    alias.insert(result, value);
                }
                Some(Folded::Constant(_) | Folded::Value(_)) | None => continue,
            }
            changed = true;
        }
        if !changed {
            break;
        }
    }
    replace(function, &alias);
}

/// What the pure operation `op` folds to, if anything ([`fold`]).
fn folded(function: &Function, op: &Op) -> Option<Folded> {
    let constant = |value: Value| match defining(function, value) {
        Some(Op::Const(bits)) => Some(*bits),
        Some(_) | None => None,
    };
    if let Op::Select {
        condition,
        then,
        otherwise,
    }
    | Op::Lanes {
        op: LaneOp::Select,
        operands: [condition, then, otherwise],
        ..
    } = *op
        && let Some(condition) = constant(condition)
    {
        if condition.is_zero() {
            return Some(Folded::Value(otherwise));
        }
        if condition == Bits::ones(condition.width()) {
            return Some(Folded::Value(then));
        }
    }
    if let Op::Binary(binary @ (Binary::And | Binary::Or), a, b)
    | Op::Lanes {
        op: LaneOp::Binary(binary @ (Binary::And | Binary::Or)),
        operands: [a, b, _],
        ..
    } = *op
    {
        for (side, other) in [(a, b), (b, a)] {
            let Some(bits) = constant(side) else {
                continue;
            };
            let zero = bits.is_zero();
            let ones = bits == Bits::ones(bits.width());
            let absorbs = if binary == Binary::And { zero } else { ones };
            if absorbs {
                return Some(Folded::Constant(bits));
            }
            if zero || ones {
                return Some(Folded::Value(other));
            }
        }
    }
    let operands: Vec<Bitvalue> = op
        .operands()
        .into_iter()
        .map(|operand| constant(operand).map(Bitvalue::defined))
        .collect::<Option<_>>()?;
    evaluate(op, &operands)?.known().map(Folded::Constant)
}

/// The value that replaces `value`, by `alias`.
fn resolve(alias: &BTreeMap<Value, Value>, mut value: Value) -> Value {
    while let Some(&next) = alias.get(&value) {
        value = next;
    }
    value
}

/// Every use of a value `alias` replaces, replaced.
fn replace(function: &mut Function, alias: &BTreeMap<Value, Value>) {
    if alias.is_empty() {
        return;
    }
    let mut replace = |value: Value| resolve(alias, value);
    for inst in &mut function.insts {
        inst.op.map_values(&mut replace);
    }
    for block in &mut function.blocks {
        block.terminator.map_values(&mut replace);
    }
}

/// `function`'s instructions, as units of fuel.
fn insts(function: &Function) -> u64 {
    u64::try_from(function.insts.len()).unwrap_or(u64::MAX)
}
