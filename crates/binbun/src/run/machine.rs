//! The run of a function's machine code, instruction by instruction
//! through each instruction's L0 (what its L1 is built from), recording
//! the registers and flags each one writes ([`Instructions`]).
//!
//! Calls are detected by the ABI: an instruction that transfers control
//! having pushed the address after it (x86-64) or put it in the link
//! register (AArch64) calls; reaching that address again returns.
//!
//! Values carry undefined bits, which lose that two reads of one register
//! are the same value: `xor eax, eax` of an undefined `eax` would be
//! undefined, where the processor gives 0 whatever `eax` holds. So an
//! exclusive or or a subtraction of one register's bits from themselves
//! (both read before the instruction writes anything) is 0
//! ([`zero_idioms`]).

// A run's stop holds values, once per run.
#![expect(clippy::result_large_err, reason = "stops hold values")]

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use binbun_decompile::validate::Link;
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{self, Fault, Machine, Outcome, Value};
use binbun_semantics::ir::{
    Binary, Expr, IntrinsicId, Local, RegisterId, Semantics, SiteId, Stmt, View,
};

use super::memory::Memory;
use super::state::Entry;
use super::{Callee, CalleeKind, Context, Need, Stop, Trace};
use crate::lift::decode_and_lift;
use crate::profile::Choices;

/// What each instruction of a run wrote, and how the run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instructions {
    /// Per instruction of the function (not of the callees stepped into),
    /// by address: each run's registers written, in register order.
    pub traces: BTreeMap<u64, Trace<Vec<(RegisterId, Value)>>>,
    /// How it ended.
    pub stop: Stop,
    /// The address of the instruction it ended at.
    pub at: u64,
    /// The instructions run (callees' included).
    pub steps: u64,
    /// Every register's value at the end.
    pub registers: Vec<Value>,
    /// The processor profile's values at the sites the run reached
    /// (none without a profile), by instruction, in order.
    pub choices: Choices,
}

/// The machine of one instruction: the run's registers and memory, and
/// the registers the instruction wrote; and the instruction's address,
/// for its sites' values.
struct Step<'m, 'a> {
    registers: &'m mut [Value],
    memory: &'m mut Memory<'a>,
    written: Vec<(RegisterId, Value)>,
    address: u64,
}

impl Machine for Step<'_, '_> {
    fn read(&mut self, register: RegisterId) -> Value {
        self.registers
            .get(usize::from(register.0))
            .copied()
            .unwrap_or_else(|| Value::unknown(1))
    }

    fn write(&mut self, register: RegisterId, value: Value) {
        if let Some(slot) = self.registers.get_mut(usize::from(register.0)) {
            *slot = value;
        }
        match self.written.iter_mut().find(|(id, _)| *id == register) {
            Some(entry) => entry.1 = value,
            None => self.written.push((register, value)),
        }
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        self.memory.load(address, bytes)
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        self.memory.store(address, value)
    }

    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[Value],
        outputs: &[u16],
    ) -> Vec<Value> {
        self.memory.intrinsic(intrinsic, inputs, outputs)
    }

    fn undefined(&mut self, site: SiteId, inputs: &[Value], width: u16) -> Value {
        self.memory.choose(self.address, site, inputs, width)
    }
}

/// One run of machine code.
struct Runner<'c, 'd, 'a> {
    context: &'c Context<'d, 'a>,
    registers: Vec<Value>,
    memory: Memory<'a>,
    /// The return addresses of the calls stepped into, innermost last.
    frames: Vec<u64>,
    traces: BTreeMap<u64, Trace<Vec<(RegisterId, Value)>>>,
    steps: u64,
}

/// Runs the function at `entry` from `state` under `context`.
pub(super) fn run(context: &Context<'_, '_>, entry: u64, state: &Entry<'_>) -> Instructions {
    let mut runner = Runner {
        context,
        registers: state.registers.clone(),
        memory: state.memory.clone(),
        frames: Vec::new(),
        traces: BTreeMap::new(),
        steps: 0,
    };
    let mut pc = entry;
    let stop = loop {
        match runner.step(pc, state.return_address) {
            Ok(next) => pc = next,
            Err(stop) => break stop,
        }
    };
    Instructions {
        traces: runner.traces,
        stop,
        at: pc,
        steps: runner.steps,
        registers: runner.registers,
        choices: runner.memory.take_choices(),
    }
}

impl Runner<'_, '_, '_> {
    /// The value of register `id`, if defined.
    fn known(&self, id: RegisterId) -> Option<u64> {
        self.registers
            .get(usize::from(id.0))
            .and_then(Value::known)
            .map(|bits| bits.low_u64())
    }

    /// Runs the instruction at `pc` (or the callee entered there): where
    /// control goes next, or how the run stops.
    fn step(&mut self, pc: u64, home: u64) -> Result<u64, Stop> {
        let context = self.context;
        if pc == home && self.frames.is_empty() {
            return Err(Stop::Returned(None));
        }
        if self.frames.last() == Some(&pc) {
            self.frames.pop();
        }
        if context.cancel.load(Ordering::Relaxed) {
            return Err(Stop::Cancelled);
        }
        if self.steps >= context.options.steps {
            return Err(Stop::OutOfSteps);
        }
        self.steps += 1;
        if self.memory.import_at(pc).is_some() {
            return self.enter(pc, false);
        }
        let lifted = decode_and_lift(context.database.image(), pc).map_err(|_| Stop::Malformed)?;
        let (mut semantics, _) = lifted.semantics.map_err(|_| Stop::Malformed)?;
        zero_idioms(&mut semantics);
        for &(id, value) in &context.setup.fixed {
            if value == context.entry
                && let Some(slot) = self.registers.get_mut(usize::from(id.0))
            {
                *slot = Value::defined(Bits::from_u64(slot.width(), pc));
            }
        }
        let stack = self.known(context.setup.stack_pointer);
        let mut machine = Step {
            registers: &mut self.registers,
            memory: &mut self.memory,
            written: Vec::new(),
            address: pc,
        };
        let outcome = interpret::run(&semantics, &mut machine);
        let mut written = machine.written;
        if self.frames.is_empty() {
            written.sort_unstable_by_key(|&(id, _)| id.0);
            self.traces
                .entry(pc)
                .or_default()
                .push(written, context.options.cap);
        }
        match outcome {
            Outcome::Next => Ok(lifted.next),
            Outcome::Transfer(target) if self.called(stack, lifted.next) => {
                self.enter(target, true)
            }
            Outcome::Transfer(target) => Ok(target),
            Outcome::Trap(trap) => Err(Stop::Trap(trap)),
            Outcome::Fault(fault) => Err(Stop::Fault {
                address: fault.address,
                write: fault.write,
                kind: self.memory.why(fault),
            }),
            Outcome::Undetermined => Err(Stop::Undetermined),
            Outcome::OutOfFuel => Err(Stop::OutOfSteps),
            Outcome::Malformed => Err(Stop::Malformed),
            Outcome::SystemCall => Err(Stop::NeedsStub {
                callee: Callee {
                    address: pc,
                    name: None,
                    kind: CalleeKind::SystemCall,
                },
                need: Need::SystemCall,
            }),
        }
    }

    /// Whether the instruction just run (the stack pointer `stack` before
    /// it) called: left the address after it, `next`, where the ABI's
    /// calls leave the return address.
    fn called(&mut self, stack: Option<u64>, next: u64) -> bool {
        let setup = &self.context.setup;
        match setup.link {
            Link::Stack { bytes } => {
                let Some((before, after)) = stack.zip(self.known(setup.stack_pointer)) else {
                    return false;
                };
                after == before.wrapping_sub(u64::from(bytes))
                    && self
                        .memory
                        .load(after, bytes)
                        .ok()
                        .and_then(|value| value.known())
                        .is_some_and(|bits| bits.low_u64() == next)
            }
            Link::Register(link) => self.known(link) == Some(next),
        }
    }

    /// Control enters `target` (`call`ed, or jumped to: an import's
    /// address): a stub, a callee stepped into, or a stop.
    fn enter(&mut self, target: u64, call: bool) -> Result<u64, Stop> {
        let context = self.context;
        let callee = context.resolve(target);
        if let Some(stub) = context.stub(&callee) {
            return self.stubbed(stub);
        }
        match callee.kind {
            CalleeKind::Function(_) if !call => Ok(target),
            CalleeKind::Function(_) if self.frames.len() < context.options.depth => {
                if let Some(home) = self.return_address() {
                    self.frames.push(home);
                }
                Ok(target)
            }
            CalleeKind::Function(_) => Err(Stop::NeedsStub {
                callee,
                need: Need::Depth,
            }),
            CalleeKind::Import | CalleeKind::SystemCall | CalleeKind::Unresolved => {
                let need = match callee.kind {
                    CalleeKind::Import => Need::Import,
                    CalleeKind::SystemCall => Need::SystemCall,
                    CalleeKind::Function(_) | CalleeKind::Unresolved => Need::Unresolved,
                };
                Err(Stop::NeedsStub { callee, need })
            }
        }
    }

    /// Where the callee just entered returns to.
    fn return_address(&mut self) -> Option<u64> {
        let setup = &self.context.setup;
        match setup.link {
            Link::Stack { bytes } => {
                let stack = self.known(setup.stack_pointer)?;
                let value = self.memory.load(stack, bytes).ok()?;
                value.known().map(|bits| bits.low_u64())
            }
            Link::Register(link) => self.known(link),
        }
    }

    /// Argument `k` of the callee just entered, as the convention passes
    /// it: an argument register, else the stack after the return address
    /// (and the home space).
    fn argument(&mut self, k: usize) -> Value {
        let context = self.context;
        let registers = &context.convention.arguments;
        if let Some(&register) = registers.get(k) {
            return self
                .registers
                .get(usize::from(register.0))
                .copied()
                .unwrap_or_else(|| Value::unknown(64));
        }
        let link = match context.setup.link {
            Link::Stack { bytes } => u64::from(bytes),
            Link::Register(_) => 0,
        };
        let index = u64::try_from(k - registers.len()).unwrap_or(u64::MAX);
        let offset = link + u64::from(context.convention.shadow) + index.saturating_mul(8);
        self.known(context.setup.stack_pointer)
            .and_then(|stack| self.memory.load(stack.wrapping_add(offset), 8).ok())
            .unwrap_or_else(|| Value::unknown(64))
    }

    /// Does what `stub` says for the callee just entered, then returns
    /// from it: the registers a call may change undefined, the result in
    /// the first result register.
    fn stubbed(&mut self, stub: &super::Stub) -> Result<u64, Stop> {
        let context = self.context;
        let needed = stub.arguments().map_or(0, |k| k + 1);
        let arguments: Vec<Value> = (0..needed).map(|k| self.argument(k)).collect();
        stub.copy(&mut self.memory, &arguments)
            .map_err(|fault| Stop::Fault {
                address: fault.address,
                write: fault.write,
                kind: self.memory.why(fault),
            })?;
        let home = self.return_address().ok_or(Stop::Undetermined)?;
        for register in &context.abi.call.changes {
            if let Some(slot) = self.registers.get_mut(usize::from(register.0)) {
                *slot = Value::unknown(slot.width());
            }
        }
        if let Some(&result) = context.convention.results.first()
            && let Some(slot) = self.registers.get_mut(usize::from(result.0))
        {
            *slot = stub.result(&arguments, slot.width());
        }
        let setup = &context.setup;
        if let Link::Stack { bytes } = setup.link
            && let Some(stack) = self.known(setup.stack_pointer)
            && let Some(slot) = self.registers.get_mut(usize::from(setup.stack_pointer.0))
        {
            let popped = stack.wrapping_add(u64::from(bytes));
            *slot = Value::defined(Bits::from_u64(slot.width(), popped));
        }
        Ok(home)
    }
}

/// Makes 0 every exclusive or and subtraction in `semantics` of the same
/// bits of one register from themselves, both read (by top-level reads)
/// before its first write: the processor's zero idioms, whatever the
/// register holds.
pub fn zero_idioms(semantics: &mut Semantics) {
    let mut reads: BTreeMap<Local, View> = BTreeMap::new();
    for stmt in &semantics.body {
        if let &Stmt::Read { local, view } = stmt {
            reads.insert(local, view);
        } else if matches!(stmt, Stmt::Write { .. }) {
            break;
        }
    }
    if reads.is_empty() {
        return;
    }
    // The bits of a register each expression is, where it is one's:
    // register, first bit, width.
    let mut bits: Vec<Option<(RegisterId, u16, u16)>> = Vec::with_capacity(semantics.exprs.len());
    for index in 0..semantics.exprs.len() {
        let Some(&(expr, width)) = semantics.exprs.get(index) else {
            break;
        };
        let of = |id: binbun_semantics::ir::ExprId| bits.get(id.0 as usize).copied().flatten();
        let these = if let Expr::Local(local) = expr {
            reads
                .get(&local)
                .map(|view| (view.register, view.offset, view.width))
        } else if let Expr::Extract {
            value,
            offset,
            width,
        } = expr
        {
            of(value).map(|(register, first, _)| (register, first + offset, width))
        } else {
            if let Expr::Binary(Binary::Xor | Binary::Sub, a, b) = expr
                && of(a).is_some()
                && of(a) == of(b)
                && let Some(slot) = semantics.exprs.get_mut(index)
            {
                *slot = (Expr::Const(Bits::zero(width)), width);
            }
            None
        };
        bits.push(these);
    }
}
