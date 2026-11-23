//! Running a [`Function`] on concrete state.
//!
//! Values carry a mask of undefined bits as in L0
//! ([`binbun_semantics::interpret`]), and pure operations are evaluated by
//! the same functions. Registers enter as the entry block's parameters;
//! memory is the [`Machine`]'s, and memory values are tokens for it. Calls
//! and system calls are not run: execution stops at them
//! ([`Outcome::Call`]). [`run_traced`] also records the run's path and
//! every value it defined ([`Trace`]).
//! [`run_calling`] goes on past calls and system calls with the results
//! a [`Calls`] gives (the callee's effect on memory is not modelled), as
//! behaviour checking compares two functions' calls in step.
//!
//! An exclusive or or a difference of a value with itself (one value, or
//! the same bits extracted from one: x86's `xor r9d, r9d`) is 0 whatever
//! its bits, undefined ones too.

use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{self, Fault, Machine, Value};
use binbun_semantics::ir::{Binary, SiteId, Trap};

use crate::ir::{
    self, BlockId, Definition, Function, Inst, Op, State, Target, Terminator, Type, Unknown,
};

/// How a run of a function ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A `Return` or `Leave` terminator: where control goes and every
    /// register's final value.
    Exit {
        /// Whether it was a return ([`Terminator::Return`]).
        returned: bool,
        /// Where control goes.
        address: u64,
        /// Every register's final value, in register order.
        registers: Vec<Value>,
    },
    /// An instruction trapped.
    Trap(Trap),
    /// A memory access faulted.
    Fault(Fault),
    /// A call that does not return (`Terminator::Stop`).
    Stop,
    /// An `Op::Call`, `Op::SystemCall` or `Op::Landing` (what the unwinder
    /// hands a landing pad), which the interpreter does not run: where it
    /// is (the instruction's address).
    Call(u64),
    /// An `IndirectJump` to an address none of its targets has (`address`
    /// of the jump target).
    Unresolved(u64),
    /// A branch condition, address or jump target depended on undefined bits.
    Undetermined,
    /// More blocks were entered than the fuel allows.
    OutOfFuel,
    /// The function is malformed: a value missing or of the wrong type, a
    /// bad index, or a width mismatch.
    Malformed,
}

/// Runs `function` from its entry block with `registers` (every register's
/// value, in register order) on `machine`'s memory, entering at most `fuel`
/// blocks.
pub fn run(
    function: &Function,
    declarations: &Declarations,
    registers: &[Value],
    machine: &mut dyn Machine,
    fuel: u64,
) -> Outcome {
    let mut run = Run {
        function,
        declarations,
        machine,
        slots: vec![None; function.values.len()],
        trace: None,
        calls: None,
    };
    run.execute(registers, fuel)
}

/// What a run did ([`run_traced`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trace {
    /// The blocks entered, in order.
    pub blocks: Vec<BlockId>,
    /// Every value defined (but the memory), in the order it was, with
    /// what it held: a value defined again (in a loop) is listed again.
    pub values: Vec<(ir::Value, Value)>,
}

/// [`run`], with the run's [`Trace`].
pub fn run_traced(
    function: &Function,
    declarations: &Declarations,
    registers: &[Value],
    machine: &mut dyn Machine,
    fuel: u64,
) -> (Outcome, Trace) {
    let mut run = Run {
        function,
        declarations,
        machine,
        slots: vec![None; function.values.len()],
        trace: Some(Trace::default()),
        calls: None,
    };
    let outcome = run.execute(registers, fuel);
    (outcome, run.trace.unwrap_or_default())
}

/// What a run that goes on past calls ([`run_calling`]) does at one.
pub trait Calls {
    /// The values of the registers `changes` after the call at `address`
    /// (the instruction's) to `target`, with every register's value at the
    /// call in `registers`; `None` stops the run there
    /// ([`Outcome::Call`]). A tail call (a [`Terminator::Leave`]) is not
    /// asked: the run ends there.
    fn call(
        &mut self,
        address: u64,
        target: Value,
        registers: &[Value],
        changes: &[binbun_semantics::ir::RegisterId],
    ) -> Option<Vec<Value>>;

    /// As [`Calls::call`], for a system call.
    fn system_call(
        &mut self,
        address: u64,
        registers: &[Value],
        changes: &[binbun_semantics::ir::RegisterId],
    ) -> Option<Vec<Value>>;
}

/// [`run_traced`], going on past calls and system calls with the results
/// `calls` gives (memory as it was: a callee's stores are not modelled).
pub fn run_calling(
    function: &Function,
    declarations: &Declarations,
    registers: &[Value],
    machine: &mut dyn Machine,
    fuel: u64,
    calls: &mut dyn Calls,
) -> (Outcome, Trace) {
    let mut run = Run {
        function,
        declarations,
        machine,
        slots: vec![None; function.values.len()],
        trace: Some(Trace::default()),
        calls: Some(calls),
    };
    let outcome = run.execute(registers, fuel);
    (outcome, run.trace.unwrap_or_default())
}

/// The contents of a value during a run.
#[derive(Clone, Copy)]
enum Slot {
    Bits(Value),
    /// The memory: the machine's.
    Memory,
}

struct Run<'a> {
    function: &'a Function,
    declarations: &'a Declarations,
    machine: &'a mut dyn Machine,
    /// Each value's contents, once defined.
    slots: Vec<Option<Slot>>,
    /// What the run did, if asked for.
    trace: Option<Trace>,
    /// What answers calls, if the run goes on past them.
    calls: Option<&'a mut dyn Calls>,
}

impl Run<'_> {
    /// Runs from the entry block with `registers`, entering at most `fuel`
    /// blocks.
    fn execute(&mut self, registers: &[Value], mut fuel: u64) -> Outcome {
        let mut block = match self.enter(registers) {
            Ok(block) => block,
            Err(outcome) => return outcome,
        };
        loop {
            if fuel == 0 {
                return Outcome::OutOfFuel;
            }
            fuel -= 1;
            if let Some(trace) = &mut self.trace {
                trace.blocks.push(block);
            }
            match self.block(block) {
                Ok(next) => block = next,
                Err(outcome) => return outcome,
            }
        }
    }

    /// Binds the entry block's parameters: `registers`, then the memory.
    fn enter(&mut self, registers: &[Value]) -> Result<BlockId, Outcome> {
        self.check_registers(registers)?;
        let function = self.function;
        let entry = function.blocks.first().ok_or(Outcome::Malformed)?;
        let (&memory, parameters) = entry.parameters.split_last().ok_or(Outcome::Malformed)?;
        if parameters.len() != registers.len() {
            return Err(Outcome::Malformed);
        }
        for (&parameter, &value) in parameters.iter().zip(registers) {
            self.bind(parameter, Slot::Bits(value))?;
        }
        self.bind(memory, Slot::Memory)?;
        Ok(BlockId(0))
    }

    /// Checks that `registers` are one value per declared register, of its
    /// width.
    fn check_registers(&self, registers: &[Value]) -> Result<(), Outcome> {
        let declared = self.declarations.registers;
        if registers.len() != declared.len()
            || registers
                .iter()
                .zip(declared)
                .any(|(value, info)| value.width() != info.width)
        {
            return Err(Outcome::Malformed);
        }
        Ok(())
    }

    /// Defines `id` as `slot`, which must fit its type.
    fn bind(&mut self, id: ir::Value, slot: Slot) -> Result<(), Outcome> {
        let fits = match (self.function.ty(id).ok_or(Outcome::Malformed)?, slot) {
            (Type::Bits(width), Slot::Bits(value)) => value.width() == width,
            (Type::Memory, Slot::Memory) => true,
            (Type::Bits(_), Slot::Memory) | (Type::Memory, Slot::Bits(_)) => false,
        };
        if !fits {
            return Err(Outcome::Malformed);
        }
        let place = self
            .slots
            .get_mut(id.0 as usize)
            .ok_or(Outcome::Malformed)?;
        *place = Some(slot);
        if let (Some(trace), Slot::Bits(value)) = (&mut self.trace, slot) {
            trace.values.push((id, value));
        }
        Ok(())
    }

    fn slot(&self, id: ir::Value) -> Result<Slot, Outcome> {
        self.slots
            .get(id.0 as usize)
            .copied()
            .flatten()
            .ok_or(Outcome::Malformed)
    }

    /// The bits `id` holds.
    fn get(&self, id: ir::Value) -> Result<Value, Outcome> {
        match self.slot(id)? {
            Slot::Bits(value) => Ok(value),
            Slot::Memory => Err(Outcome::Malformed),
        }
    }

    /// Checks that `id` holds the memory.
    fn memory(&self, id: ir::Value) -> Result<(), Outcome> {
        match self.slot(id)? {
            Slot::Memory => Ok(()),
            Slot::Bits(_) => Err(Outcome::Malformed),
        }
    }

    /// The address `id` holds, which must be defined.
    fn address(&self, id: ir::Value) -> Result<u64, Outcome> {
        self.get(id)?
            .known()
            .map(|bits| bits.low_u64())
            .ok_or(Outcome::Undetermined)
    }

    /// Runs block `id`: where control goes next.
    fn block(&mut self, id: BlockId) -> Result<BlockId, Outcome> {
        let function = self.function;
        let block = function.block(id).ok_or(Outcome::Malformed)?;
        for &inst in &block.insts {
            self.inst(function.inst(inst).ok_or(Outcome::Malformed)?)?;
        }
        self.terminator(&block.terminator)
    }

    fn inst(&mut self, inst: &Inst) -> Result<(), Outcome> {
        match &inst.op {
            Op::Call {
                target,
                memory,
                registers,
                changes,
                ..
            } => self.call(inst, Some(*target), *memory, registers, changes),
            Op::SystemCall {
                memory,
                registers,
                changes,
            } => self.call(inst, None, *memory, registers, changes),
            Op::Landing { .. } => Err(Outcome::Call(inst.address)),
            &Op::Load {
                memory,
                address,
                bytes,
                ..
            } => {
                self.memory(memory)?;
                let address = self.address(address)?;
                let value = self.machine.load(address, bytes).map_err(Outcome::Fault)?;
                self.single(inst, Slot::Bits(value))
            }
            &Op::Store {
                memory,
                address,
                value,
                ..
            } => {
                self.memory(memory)?;
                let address = self.address(address)?;
                let value = self.get(value)?;
                if !value.width().is_multiple_of(8) {
                    return Err(Outcome::Malformed);
                }
                self.machine.store(address, value).map_err(Outcome::Fault)?;
                self.single(inst, Slot::Memory)
            }
            Op::Intrinsic {
                intrinsic,
                memory,
                inputs,
            } => {
                self.memory(*memory)?;
                let inputs = inputs
                    .iter()
                    .map(|&input| self.get(input))
                    .collect::<Result<Vec<_>, _>>()?;
                let (&memory, outputs) = inst.results.split_last().ok_or(Outcome::Malformed)?;
                let widths = outputs
                    .iter()
                    .map(|&output| self.width(output))
                    .collect::<Result<Vec<_>, _>>()?;
                let values = self.machine.intrinsic(*intrinsic, &inputs, &widths);
                if values.len() != outputs.len() {
                    return Err(Outcome::Malformed);
                }
                for (&output, value) in outputs.iter().zip(values) {
                    self.bind(output, Slot::Bits(value))?;
                }
                self.bind(memory, Slot::Memory)
            }
            // A site's value: the machine's choice from its inputs.
            Op::Undefined(
                Unknown::Architecture {
                    site: Some(site), ..
                },
                inputs,
            ) => self.site(inst, *site, inputs),
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Extend { .. }
            | Op::Select { .. }
            | Op::Lanes { .. }
            | Op::Float { .. } => {
                let value = self.pure(inst)?;
                self.single(inst, Slot::Bits(value))
            }
        }
    }

    /// The value of `inst`, the undefined value of site `site`: the
    /// machine's choice from the site's `inputs` (unknown if it answers
    /// with another width).
    fn site(&mut self, inst: &Inst, site: SiteId, inputs: &[ir::Value]) -> Result<(), Outcome> {
        let inputs = inputs
            .iter()
            .map(|&input| self.get(input))
            .collect::<Result<Vec<_>, _>>()?;
        let &[result] = inst.results.as_slice() else {
            return Err(Outcome::Malformed);
        };
        let width = self.width(result)?;
        let value = self
            .machine
            .undefined_at(inst.address, site, &inputs, width);
        let value = if value.width() == width {
            value
        } else {
            Value::unknown(width)
        };
        self.bind(result, Slot::Bits(value))
    }

    /// The width of bit vector `id`.
    fn width(&self, id: ir::Value) -> Result<u16, Outcome> {
        match self.function.ty(id) {
            Some(Type::Bits(width)) => Ok(width),
            Some(Type::Memory) | None => Err(Outcome::Malformed),
        }
    }

    /// Goes through call `inst` (to `target`; a system call without one)
    /// with the results [`Calls`] gives, or stops at it.
    fn call(
        &mut self,
        inst: &Inst,
        target: Option<ir::Value>,
        memory: ir::Value,
        registers: &[ir::Value],
        changes: &[binbun_semantics::ir::RegisterId],
    ) -> Result<(), Outcome> {
        self.memory(memory)?;
        let target = target.map(|target| self.get(target)).transpose()?;
        let values = registers
            .iter()
            .map(|&register| self.get(register))
            .collect::<Result<Vec<_>, _>>()?;
        let results = match (&mut self.calls, target) {
            (Some(calls), Some(target)) => calls.call(inst.address, target, &values, changes),
            (Some(calls), None) => calls.system_call(inst.address, &values, changes),
            (None, _) => None,
        };
        self.returned(inst, results)
    }

    /// Binds the results of call `inst` (the new memory, then the
    /// registers it changes) to `results`; stops at it without them.
    fn returned(&mut self, inst: &Inst, results: Option<Vec<Value>>) -> Result<(), Outcome> {
        let results = results.ok_or(Outcome::Call(inst.address))?;
        let (&memory, registers) = inst.results.split_first().ok_or(Outcome::Malformed)?;
        if registers.len() != results.len() {
            return Err(Outcome::Malformed);
        }
        self.bind(memory, Slot::Memory)?;
        for (&register, value) in registers.iter().zip(results) {
            self.bind(register, Slot::Bits(value))?;
        }
        Ok(())
    }

    /// Defines the one result of `inst` as `slot`.
    fn single(&mut self, inst: &Inst, slot: Slot) -> Result<(), Outcome> {
        match inst.results.as_slice() {
            &[result] => self.bind(result, slot),
            _ => Err(Outcome::Malformed),
        }
    }

    /// Whether values `a` and `b` hold the same bits whatever those are:
    /// one value, or the same bits extracted from one.
    fn identical(&self, a: ir::Value, b: ir::Value) -> bool {
        a == b
            || self
                .extraction(a)
                .is_some_and(|x| self.extraction(b) == Some(x))
    }

    /// The value, offset and width `id` is extracted from, if it is an
    /// extraction.
    fn extraction(&self, id: ir::Value) -> Option<(ir::Value, u16, u16)> {
        let Definition::Result { inst, .. } = self.function.value(id)?.definition else {
            return None;
        };
        if let Op::Extract {
            value,
            offset,
            width,
        } = self.function.inst(inst)?.op
        {
            Some((value, offset, width))
        } else {
            None
        }
    }

    /// The value of the pure operation `inst`.
    fn pure(&self, inst: &Inst) -> Result<Value, Outcome> {
        Ok(match inst.op {
            Op::Const(bits) => Value::defined(bits),
            Op::Undefined(..) => {
                let &[result] = inst.results.as_slice() else {
                    return Err(Outcome::Malformed);
                };
                Value::unknown(self.width(result)?)
            }
            Op::Unary(op, a) => interpret::unary(op, self.get(a)?),
            Op::Binary(op, a, b) => {
                let (x, y) = (self.get(a)?, self.get(b)?);
                same(&[x, y])?;
                if matches!(op, Binary::Xor | Binary::Sub) && self.identical(a, b) {
                    Value::defined(Bits::zero(x.width()))
                } else {
                    interpret::binary(op, x, y)
                }
            }
            Op::Flag(op, a, b, c) => {
                let (a, b, c) = (self.get(a)?, self.get(b)?, self.get(c)?);
                same(&[a, b, c])?;
                interpret::flag(op, a, b, c)
            }
            Op::Extract {
                value,
                offset,
                width,
            } => {
                let value = self.get(value)?;
                if u32::from(offset) + u32::from(width) > u32::from(value.width()) {
                    return Err(Outcome::Malformed);
                }
                interpret::extract(value, offset, width)
            }
            Op::Concat { high, low } => interpret::concat(self.get(high)?, self.get(low)?),
            Op::Extend {
                signed,
                value,
                width,
            } => {
                let value = self.get(value)?;
                if width < value.width() {
                    return Err(Outcome::Malformed);
                }
                interpret::extend(signed, value, width)
            }
            Op::Select {
                condition,
                then,
                otherwise,
            } => {
                let condition = self.get(condition)?;
                let (then, otherwise) = (self.get(then)?, self.get(otherwise)?);
                if condition.width() != 1 {
                    return Err(Outcome::Malformed);
                }
                same(&[then, otherwise])?;
                interpret::select(condition, then, otherwise)
            }
            Op::Lanes {
                lanes,
                op,
                operands,
            } => {
                let values = operands
                    .iter()
                    .take(op.arity())
                    .map(|&operand| self.get(operand))
                    .collect::<Result<Vec<_>, _>>()?;
                interpret::lanes(op, lanes, &values)
            }
            Op::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands,
            } => {
                let rounding = self.get(rounding)?;
                let values = operands
                    .iter()
                    .take(op.arity())
                    .map(|&operand| self.get(operand))
                    .collect::<Result<Vec<_>, _>>()?;
                interpret::float(op, format, lanes, output, rounding, &values)
            }
            Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => return Err(Outcome::Malformed),
        })
    }

    /// Where control goes from a terminator; [`Err`] with the outcome if it
    /// leaves the function or stops.
    fn terminator(&mut self, terminator: &Terminator) -> Result<BlockId, Outcome> {
        match terminator {
            Terminator::Jump(target) => self.jump(target),
            Terminator::Branch {
                condition,
                then,
                otherwise,
            } => {
                let condition = self.get(*condition)?;
                if condition.width() != 1 {
                    return Err(Outcome::Malformed);
                }
                let bits = condition.known().ok_or(Outcome::Undetermined)?;
                self.jump(if bits.is_zero() { otherwise } else { then })
            }
            // Callees never throw here (the run stops at the call anyway).
            Terminator::Invoke { normal, .. } => self.jump(normal),
            Terminator::IndirectJump { address, targets } => {
                let address = self.address(*address)?;
                let function = self.function;
                for target in targets {
                    let block = function.block(target.block).ok_or(Outcome::Malformed)?;
                    if block.address == address {
                        return self.jump(target);
                    }
                }
                Err(Outcome::Unresolved(address))
            }
            Terminator::Return { address, state } => self.exit(true, *address, state).and_then(Err),
            Terminator::Leave { address, state, .. } => {
                self.exit(false, *address, state).and_then(Err)
            }
            Terminator::Trap(trap) => Err(Outcome::Trap(*trap)),
            Terminator::Stop => Err(Outcome::Stop),
            Terminator::Open => Err(Outcome::Malformed),
        }
    }

    /// Binds the parameters of `target`'s block to its arguments, all
    /// evaluated first (a parallel copy).
    fn jump(&mut self, target: &Target) -> Result<BlockId, Outcome> {
        let function = self.function;
        let block = function.block(target.block).ok_or(Outcome::Malformed)?;
        if block.parameters.len() != target.arguments.len() {
            return Err(Outcome::Malformed);
        }
        let values = target
            .arguments
            .iter()
            .map(|&argument| self.slot(argument))
            .collect::<Result<Vec<_>, _>>()?;
        for (&parameter, value) in block.parameters.iter().zip(values) {
            self.bind(parameter, value)?;
        }
        Ok(target.block)
    }

    /// The outcome of leaving the function to `address` in `state`.
    fn exit(&self, returned: bool, address: ir::Value, state: &State) -> Result<Outcome, Outcome> {
        let address = self.address(address)?;
        let registers = state
            .registers
            .iter()
            .map(|&register| self.get(register))
            .collect::<Result<Vec<_>, _>>()?;
        self.memory(state.memory)?;
        self.check_registers(&registers)?;
        Ok(Outcome::Exit {
            returned,
            address,
            registers,
        })
    }
}

/// Checks that `values` all have the same width.
fn same(values: &[Value]) -> Result<(), Outcome> {
    match values.split_first() {
        Some((first, rest)) if rest.iter().any(|value| value.width() != first.width()) => {
            Err(Outcome::Malformed)
        }
        Some(_) | None => Ok(()),
    }
}
