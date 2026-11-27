//! The function's own stack: which values are addresses at a known offset
//! from the stack pointer at entry, whether any of them escapes, and what a
//! load from a stack slot reads when a store in the function wrote it.
//!
//! - Offsets: the stack pointer's entry value is 0; adding or subtracting a
//!   constant keeps an offset; a block parameter whose arguments all have
//!   one offset has it. Anything else is not a stack address that is
//!   followed.
//! - Escape: a stack address escapes if it is stored, passed in an
//!   argument register or to an intrinsic whose inputs may escape
//!   ([`escapes`](binbun_semantics::ir::IntrinsicInfo::escapes): not a
//!   keyed hash), passed to a block parameter that is no stack address,
//!   or used by an operation (other than offset arithmetic) whose result
//!   is at least as wide as the stack pointer (`and rsp, -16`, a select, a
//!   vector holding it): narrower results
//!   (flags, comparisons) cannot carry it on.
//! - Forwarding: a load from a slot follows the memory backwards to the
//!   store that wrote it. Stack stores elsewhere are passed; other stores and
//!   calls only if the frame does not escape and the slot lies in the
//!   function's own frame (below the entry stack pointer), and calls only
//!   for slots at or above the stack pointer at the call. Anything else (an
//!   intrinsic, a merge of different values, the memory at entry) stops it.
//!   A landing pad's memory is that of the calls unwinding to it, passed
//!   as for each of those calls.
//! - Saves: a slot of the function's own frame every store of which (on
//!   the paths to a load of it) writes the entry value of a register
//!   callees keep, or a value read back from such a slot, is a save of
//!   that register: no other writer reaches it even when the frame escapes
//!   ([`Stack::holds`]).
//!
//! Under the pass manager, [`Stack`] is an [`Analysis`] (in an [`L1Env`],
//! from the [`Constants`]) and [`AssumeCanonical`] the pass that takes
//! the ABI's word that stack addresses (and those at constant offsets from
//! the thread pointer) are canonical, and the loader's that a fixed import
//! slot holds a mapped address; [`AssumeDereferenced`] is the reading
//! view's assumption that every address the function dereferences is,
//! [`AssumeAligned`] its assumption that the stack pointer is aligned at
//! entry as AAPCS64 says and [`AssumeAuthenticated`] its assumption that
//! a return address signed with pointer authentication authenticates;
//! [`TailJumps`] keeps a jump out of the function to a computed address
//! a tail call only where the ABI's conditions for one hold.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Analyses, Analysis, Changed, Cx, Pass, Refusal};
use binbun_semantics::ir::{Binary, Declarations, IntrinsicId, RegisterId, Trap};

use crate::condition::defining;
use crate::constant::{Constants, ReadOnly};
use crate::graph;
use crate::ir::{BlockId, Definition, Function, Inst, InstId, Op, Target, Terminator, Type, Value};
use crate::pass::{L1Env, blocks};

/// What is known about a value as a stack address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Offset {
    Unknown,
    Known(i64),
    Varies,
}

impl Offset {
    fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, x) | (x, Self::Unknown) => x,
            (Self::Known(a), Self::Known(b)) if a == b => Self::Known(a),
            (Self::Known(_) | Self::Varies, Self::Known(_) | Self::Varies) => Self::Varies,
        }
    }
}

/// The function's stack, as [the module](self) describes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stack {
    offsets: Vec<Offset>,
    escaped: bool,
    /// The offsets of the stack addresses that escape, sorted, each once.
    escaping: Vec<i64>,
    /// The stack pointer's register number.
    sp: usize,
    /// Each block's predecessors ([`graph::predecessors`]).
    predecessors: Vec<Vec<(BlockId, usize)>>,
    /// Whether each intrinsic may change memory, by number
    /// ([`IntrinsicInfo::stores`](binbun_semantics::ir::IntrinsicInfo::stores)):
    /// the search for a stored value passes those that do not.
    stores: Vec<bool>,
}

/// The most memories one search for a stored value looks at.
const STEPS: usize = 4096;

impl<'e> Analysis<Function, L1Env<'e>> for Stack {
    fn compute(
        function: &Function,
        env: &L1Env<'e>,
        analyses: &mut Analyses<Function, L1Env<'e>>,
    ) -> Self {
        let constants = analyses.get::<Constants>(function, env);
        Self::new(
            function,
            env.declarations,
            &constants,
            env.stack_pointer,
            env.arguments,
        )
    }
}

impl Stack {
    /// Finds stack addresses in `function` (of an architecture that
    /// declares `declarations`), whose stack pointer is `stack_pointer` and
    /// whose calls take arguments in `arguments`.
    pub fn new(
        function: &Function,
        declarations: &Declarations,
        constants: &Constants,
        stack_pointer: RegisterId,
        arguments: &[RegisterId],
    ) -> Self {
        let entry_sp = entry_value(function, stack_pointer);
        let predecessors = graph::predecessors(function);
        let offsets = offsets_from(function, constants, entry_sp, &predecessors);
        let mut stack = Self {
            offsets,
            escaped: false,
            escaping: Vec::new(),
            sp: stack_pointer.0 as usize,
            predecessors,
            stores: declarations.intrinsics.iter().map(|i| i.stores).collect(),
        };
        let argument_indices: Vec<usize> = arguments.iter().map(|r| r.0 as usize).collect();
        let width = entry_sp.and_then(|v| function.ty(v));
        stack.escaping = stack.escapes(function, declarations, width, &argument_indices);
        stack.escaped = !stack.escaping.is_empty();
        stack
    }

    /// `value`'s offset from the stack pointer at entry, if it is a stack
    /// address.
    pub fn offset(&self, value: Value) -> Option<i64> {
        match get(&self.offsets, value) {
            Offset::Known(offset) => Some(offset),
            Offset::Unknown | Offset::Varies => None,
        }
    }

    /// Whether a stack address escapes (then calls and other stores may
    /// write the frame).
    pub fn escaped(&self) -> bool {
        self.escaped
    }

    /// The offsets of the stack addresses that escape (from the stack
    /// pointer at entry), sorted: what [`Self::escaped`] says of each.
    pub fn escaping(&self) -> &[i64] {
        &self.escaping
    }

    /// The offsets of the stack addresses that escape, sorted, each once.
    fn escapes(
        &self,
        function: &Function,
        declarations: &Declarations,
        pointer: Option<Type>,
        arguments: &[usize],
    ) -> Vec<i64> {
        let mut escaping = Vec::new();
        for inst in &function.insts {
            let candidates: Vec<Value> = match &inst.op {
                Op::Load { .. }
                | Op::Const(_)
                | Op::Undefined(..)
                | Op::Landing { .. }
                | Op::Binary(Binary::Add | Binary::Sub, ..) => Vec::new(),
                Op::Store { value, .. } => alloc::vec![*value],
                Op::Call { registers, .. } | Op::SystemCall { registers, .. } => registers
                    .iter()
                    .enumerate()
                    .filter(|&(index, _)| index != self.sp && arguments.contains(&index))
                    .map(|(_, &v)| v)
                    .collect(),
                Op::Intrinsic {
                    intrinsic, inputs, ..
                } => {
                    if declarations
                        .intrinsic(*intrinsic)
                        .is_none_or(|info| info.escapes)
                    {
                        inputs.clone()
                    } else {
                        Vec::new()
                    }
                }
                op @ (Op::Unary(..)
                | Op::Binary(..)
                | Op::Flag(..)
                | Op::Extract { .. }
                | Op::Concat { .. }
                | Op::Extend { .. }
                | Op::Select { .. }
                | Op::Lanes { .. }
                | Op::Float { .. }) => {
                    // A result as wide as a pointer, or wider (a vector),
                    // can carry the address on.
                    let wide = match (inst.results.first().and_then(|&r| function.ty(r)), pointer) {
                        (Some(Type::Bits(width)), Some(Type::Bits(address))) => width >= address,
                        (Some(Type::Bits(_) | Type::Memory) | None, _) => false,
                    };
                    if wide { op.operands() } else { Vec::new() }
                }
            };
            escaping.extend(candidates.into_iter().filter_map(|v| self.offset(v)));
        }
        // Block arguments into parameters that are no stack address.
        for block in &function.blocks {
            for target in block.terminator.targets() {
                let parameters = function
                    .block(target.block)
                    .map_or(&[][..], |b| b.parameters.as_slice());
                for (&argument, &parameter) in target.arguments.iter().zip(parameters) {
                    if self.offset(parameter).is_none()
                        && let Some(offset) = self.offset(argument)
                    {
                        escaping.push(offset);
                    }
                }
            }
        }
        escaping.sort_unstable();
        escaping.dedup();
        escaping
    }

    /// The value the load `value` reads, if a store in the function wrote
    /// it (followed through loads of stored loads); else `value` itself.
    pub fn resolve(&self, function: &Function, value: Value) -> Value {
        let mut current = value;
        let mut seen = BTreeSet::new();
        while seen.insert(current) {
            match self.forward(function, current) {
                Some(stored) => current = stored,
                None => break,
            }
        }
        current
    }

    /// Whether `value` is `entry` (the entry value of a register callees
    /// keep) wherever it is computed: `entry` itself; a block parameter
    /// (not the entry block's) every argument of which is such a value;
    /// or a load of a stack slot every store reaching which wrote such a
    /// value. In the function's own frame (below the entry stack pointer)
    /// the slot is then a save of the register, which the ABI keeps from
    /// the callees and from stores through pointers to the frame's objects
    /// (no object of the program's lies there), so calls and stores to
    /// addresses not known are passed even when the frame escapes, as
    /// lowering takes such a slot for a save; elsewhere stores are passed
    /// as for forwarding. Values met again count as such: a reload stored
    /// back, or a loop passing the value round, by induction over a run
    /// takes only values that were `entry` already. A register the
    /// function saves and restores holds its entry value so even where
    /// paths that restore it in different blocks, or never change it,
    /// meet. `false` past [`STEPS`] values.
    pub fn holds(&self, function: &Function, value: Value, entry: Value) -> bool {
        let mut seen = BTreeSet::new();
        let mut work = vec![value];
        while let Some(value) = work.pop() {
            if value == entry || !seen.insert(value) {
                continue;
            }
            if seen.len() > STEPS {
                return false;
            }
            let (block, index) = match function.value(value).map(|v| v.definition) {
                Some(Definition::Parameter { block, index }) => (block, index),
                Some(Definition::Result { inst, .. }) => {
                    let Some(&Op::Load {
                        memory,
                        address,
                        bytes,
                        ..
                    }) = function.inst(inst).map(|inst| &inst.op)
                    else {
                        return false;
                    };
                    let Some(stored) = self.offset(address).and_then(|slot| {
                        self.reaching(function, memory, slot, i64::from(bytes), true)
                    }) else {
                        return false;
                    };
                    work.extend(stored);
                    continue;
                }
                None => return false,
            };
            if block == BlockId(0) {
                return false;
            }
            let Some(predecessors) = self.predecessors.get(block.0 as usize) else {
                return false;
            };
            for &(pred, edge) in predecessors {
                let Some(argument) = function
                    .block(pred)
                    .and_then(|b| b.terminator.targets().nth(edge))
                    .and_then(|t| t.arguments.get(index as usize).copied())
                else {
                    return false;
                };
                work.push(argument);
            }
        }
        true
    }

    /// The values the stores reaching the load `value` wrote, passing
    /// calls and stores to addresses not known as [`Self::holds`] does for
    /// a slot of the function's own frame (a save, which the ABI keeps
    /// from callees); `None` where `value` is no load of a stack slot or
    /// what reaches it cannot be told.
    pub fn saved(&self, function: &Function, value: Value) -> Option<Vec<Value>> {
        let Definition::Result { inst, .. } = function.value(value)?.definition else {
            return None;
        };
        let &Op::Load {
            memory,
            address,
            bytes,
            ..
        } = &function.inst(inst)?.op
        else {
            return None;
        };
        let slot = self.offset(address)?;
        self.reaching(function, memory, slot, i64::from(bytes), true)
    }

    /// The value the load `value` reads, if one store in the function wrote
    /// it.
    fn forward(&self, function: &Function, value: Value) -> Option<Value> {
        let inst = match function.value(value)?.definition {
            Definition::Result { inst, .. } => function.inst(inst)?,
            Definition::Parameter { .. } => return None,
        };
        let Op::Load {
            memory,
            address,
            bytes,
            ..
        } = inst.op
        else {
            return None;
        };
        let slot = self.offset(address)?;
        match self
            .reaching(function, memory, slot, i64::from(bytes), false)?
            .as_slice()
        {
            &[stored] => Some(stored),
            _ => None,
        }
    }

    /// The values stored in `slot` (`size` bytes) that memory `memory`
    /// may hold: those of the stores of the slot every path back finds,
    /// with no unknown writer on the way (a loop that writes nothing adds
    /// nothing); `None` past [`STEPS`] memories. A `save` slot (one
    /// [`holds`](Self::holds) asks of) in the function's own frame is safe
    /// from other writers even when the frame escapes.
    fn reaching(
        &self,
        function: &Function,
        memory: Value,
        slot: i64,
        size: i64,
        save: bool,
    ) -> Option<Vec<Value>> {
        // Only the function's own frame is safe from other writers.
        let own = slot.saturating_add(size) <= 0 && (save || !self.escaped);
        let mut found: Vec<Value> = Vec::new();
        let mut visited = BTreeSet::new();
        let mut work = vec![memory];
        while let Some(memory) = work.pop() {
            if !visited.insert(memory) {
                continue;
            }
            if visited.len() > STEPS {
                return None;
            }
            match function.value(memory)?.definition {
                Definition::Parameter { block, index } => {
                    // The memory at entry: not written by this function.
                    if block == BlockId(0) {
                        return None;
                    }
                    for &(pred, edge) in self.predecessors.get(block.0 as usize)? {
                        let argument = function
                            .block(pred)
                            .and_then(|b| b.terminator.targets().nth(edge))
                            .and_then(|t| t.arguments.get(index as usize).copied())?;
                        work.push(argument);
                    }
                }
                Definition::Result { inst, .. } => {
                    let inst = function.inst(inst)?;
                    let before = match &inst.op {
                        Op::Landing { memory: before, .. } => {
                            // The calls unwinding here ran, in part.
                            if !self.unwound_above(function, inst, own, slot)? {
                                return None;
                            }
                            *before
                        }
                        Op::Intrinsic {
                            intrinsic,
                            memory: before,
                            ..
                        } if !self.stores(*intrinsic) => *before,
                        Op::Store {
                            memory: before,
                            address,
                            value,
                            ..
                        } => {
                            let width = match function.ty(*value)? {
                                Type::Bits(width) => i64::from(width / 8),
                                Type::Memory => return None,
                            };
                            match self.offset(*address) {
                                Some(at) if at == slot && width == size => {
                                    if !found.contains(value) {
                                        found.push(*value);
                                    }
                                    continue;
                                }
                                Some(at)
                                    if at.saturating_add(width) <= slot
                                        || slot.saturating_add(size) <= at => {}
                                None if own => {}
                                Some(_) | None => return None,
                            }
                            *before
                        }
                        Op::Call {
                            memory: before,
                            registers,
                            ..
                        }
                        | Op::SystemCall {
                            memory: before,
                            registers,
                            ..
                        } => {
                            // At or above the stack pointer at the call:
                            // not the callee's frame.
                            if !own || !self.above(registers, slot) {
                                return None;
                            }
                            *before
                        }
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
                        | Op::Float { .. }
                        | Op::Load { .. }
                        | Op::Intrinsic { .. } => return None,
                    };
                    work.push(before);
                }
            }
        }
        Some(found)
    }

    /// Whether `slot` is at or above the stack pointer among a call's
    /// `registers`: not the callee's frame.
    fn above(&self, registers: &[Value], slot: i64) -> bool {
        registers
            .get(self.sp)
            .and_then(|&v| self.offset(v))
            .is_some_and(|sp| slot >= sp)
    }

    /// Whether intrinsic `intrinsic` may change memory (an unknown one may).
    fn stores(&self, intrinsic: IntrinsicId) -> bool {
        self.stores
            .get(usize::from(intrinsic.0))
            .copied()
            .unwrap_or(true)
    }

    /// Whether every call that unwinds to the landing pad `inst` leaves
    /// `slot` alone: `own` (the function's own frame) and the slot at or
    /// above its stack pointer. `None` if one is not such a call.
    fn unwound_above(
        &self,
        function: &Function,
        inst: &Inst,
        own: bool,
        slot: i64,
    ) -> Option<bool> {
        let calls = unwinding_calls(function, &self.predecessors, *inst.results.first()?)?;
        Some(
            calls
                .into_iter()
                .all(|registers| own && self.above(registers, slot)),
        )
    }
}

/// The registers at each call that unwinds to the landing pad whose
/// [`Op::Landing`] gives the memory `memory`: the calls ending the blocks
/// whose [`Terminator::Invoke`] unwinds to its block. `None` if one is not
/// such a call.
fn unwinding_calls<'f>(
    function: &'f Function,
    predecessors: &[Vec<(BlockId, usize)>],
    memory: Value,
) -> Option<Vec<&'f [Value]>> {
    let Definition::Result { inst, .. } = function.value(memory)?.definition else {
        return None;
    };
    let index = function
        .blocks
        .iter()
        .position(|block| block.insts.first() == Some(&inst))?;
    let mut calls = Vec::new();
    for &(pred, edge) in predecessors.get(index)? {
        let block = function.block(pred)?;
        if edge != 1 || !matches!(block.terminator, Terminator::Invoke { .. }) {
            return None;
        }
        let call = function.inst(*block.insts.last()?)?;
        let Op::Call { registers, .. } = &call.op else {
            return None;
        };
        calls.push(registers.as_slice());
    }
    Some(calls)
}

/// The pass `assume-canonical`: `function` under the assumption that its
/// stack and its caller's return address are canonical (the ABI's: the
/// stack pointer a caller passes is a canonical address, and so is the
/// return address its call leaves): every branch on L0's check that such
/// an address is canonical (`x == sext(x[0..k])`, or `!=`) becomes a jump
/// the way a canonical address goes, so the fault it guards against is not
/// decompiled. Such an address is a stack address ([`Stack::offset`]), or,
/// where calls leave the return address on the stack
/// ([`L1Env::return_slot`], x86), a load of that slot no store in the
/// function wrote, or, where the platform has a thread pointer
/// ([`L1Env::thread_pointer`]), its entry value plus a constant (by the
/// rules of [the module](self) for offsets): the system sets the thread
/// pointer to the thread's own control block (the TCB of the ELF TLS ABI,
/// Drepper's "ELF Handling For Thread-Local Storage"; Windows' TEB), a
/// canonical address, and what code reaches at a constant offset
/// from it is that block or the thread's static TLS beside it, which the
/// system maps. Or it is the loader's: a load, as wide as the address,
/// of a constant address whose bytes hold a fixed address
/// ([`ReadOnly::fixed_address`]: an import slot the loader fills before
/// the program runs and that never changes after), a mapped address.
///
/// Preserves nothing: the edges it removes (to the fault) were ones
/// constant propagation took (the check's operand varies), so the
/// [`Constants`] change (what is reachable, what reaches a join), and with
/// them the [`Stack`]; the graph changes, so the
/// [`Dominators`](graph::Dominators) do. Fuel: a unit per block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AssumeCanonical;

impl<'e> Pass<Function, L1Env<'e>> for AssumeCanonical {
    fn name(&self) -> &'static str {
        "assume-canonical"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(blocks(function))?;
        let stack = cx.analysis::<Stack>(function);
        let constants = cx.analysis::<Constants>(function);
        let covers = Covers {
            stack: &stack,
            constants: &constants,
            memory: cx.env.memory,
            return_slot: cx.env.return_slot,
            thread_pointer: cx.env.thread_pointer,
        };
        let folded = assume_canonical(function, &covers);
        Ok(Changed::from(folded > 0))
    }
}

/// What [`AssumeCanonical`] knows of a function to tell which addresses it
/// covers.
struct Covers<'a> {
    stack: &'a Stack,
    constants: &'a Constants,
    memory: &'a dyn ReadOnly,
    return_slot: Option<i64>,
    thread_pointer: Option<RegisterId>,
}

/// [`AssumeCanonical`] on `function` with what `covers` knows: how many
/// branches were folded.
fn assume_canonical(function: &mut Function, covers: &Covers<'_>) -> usize {
    // Offsets from the thread pointer, computed at the first check that
    // needs them.
    let mut thread: Option<Vec<Offset>> = None;
    let mut taken: Vec<(usize, Target)> = Vec::new();
    for (index, block) in function.blocks.iter().enumerate() {
        let Terminator::Branch {
            condition,
            then,
            otherwise,
        } = &block.terminator
        else {
            continue;
        };
        let Some((address, equal)) = canonical_check(function, *condition) else {
            continue;
        };
        let covered = covers.stack.offset(address).is_some()
            || covers
                .return_slot
                .is_some_and(|slot| caller_return(function, covers.stack, slot, address))
            || covers.thread_pointer.is_some_and(|register| {
                let offsets = thread.get_or_insert_with(|| {
                    let base = entry_value(function, register);
                    let predecessors = graph::predecessors(function);
                    offsets_from(function, covers.constants, base, &predecessors)
                });
                matches!(get(offsets, address), Offset::Known(_))
            })
            || fixed_load(function, covers.constants, covers.memory, address);
        if covered {
            taken.push((index, if equal { then } else { otherwise }.clone()));
        }
    }
    for &(index, ref target) in &taken {
        if let Some(block) = function.blocks.get_mut(index) {
            block.terminator = Terminator::Jump(target.clone());
        }
    }
    taken.len()
}

/// Whether `x` is a load, as wide as `x`, of a constant address whose
/// bytes hold a fixed address ([`ReadOnly::fixed_address`]).
fn fixed_load(function: &Function, constants: &Constants, memory: &dyn ReadOnly, x: Value) -> bool {
    let Some(&Op::Load { address, bytes, .. }) = defining(function, x) else {
        return false;
    };
    function.ty(x) == Some(Type::Bits(bytes.saturating_mul(8)))
        && constants
            .constant(address)
            .is_some_and(|at| at.width() <= 64 && memory.fixed_address(at.low_u64(), bytes))
}

/// The pass `tail-jumps`: a jump out of the function to a computed
/// address ([`Terminator::Leave`] whose address is no constant: through
/// a function pointer, or an import's slot) stays a tail call only where
/// the ABI's conditions for one hold: the stack pointer is back at its
/// entry value, the return address is untouched (x86: no store of the
/// function writes its slot, at [`L1Env::return_slot`]; a register link:
/// it holds its entry value), and the registers a callee keeps hold their
/// entry values (through the frame's saves, and the paths that meet:
/// [`Stack::holds`]). Then
/// the code it goes to finds the state its caller's call left, with that
/// caller to return to: under the convention's assumption that it is a
/// function (as for every computed call), it is called, and returns to
/// the caller what the caller expects of the function. Any
/// other becomes a computed jump to code not known
/// ([`Terminator::IndirectJump`] with no targets): a jump whose frame is
/// still up goes to code of this function, or to code no convention
/// describes.
///
/// Preserves nothing (the graph's exits change). Fuel: a unit per block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TailJumps {
    link: Option<RegisterId>,
    kept: Vec<RegisterId>,
    tails: usize,
    unresolved: usize,
}

impl TailJumps {
    /// The pass, for a convention whose calls leave the return address in
    /// register `link` (`None`: on the stack, at
    /// [`L1Env::return_slot`]) and whose callees keep the registers
    /// `kept` (the stack pointer among them or not).
    pub fn new(link: Option<RegisterId>, kept: Vec<RegisterId>) -> Self {
        Self {
            link,
            kept,
            tails: 0,
            unresolved: 0,
        }
    }

    /// How many computed jumps out of the function its last run kept as
    /// tail calls, and how many it made unresolved jumps.
    pub fn counts(&self) -> (usize, usize) {
        (self.tails, self.unresolved)
    }
}

impl<'e> Pass<Function, L1Env<'e>> for TailJumps {
    fn name(&self) -> &'static str {
        "tail-jumps"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(blocks(function))?;
        (self.tails, self.unresolved) = (0, 0);
        let leaving: Vec<usize> = function
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, block)| matches!(block.terminator, Terminator::Leave { .. }))
            .map(|(index, _)| index)
            .collect();
        if leaving.is_empty() {
            return Ok(Changed::No);
        }
        let stack = cx.analysis::<Stack>(function);
        let constants = cx.analysis::<Constants>(function);
        let sp = usize::from(cx.env.stack_pointer.0);
        let link_bytes = cx
            .env
            .declarations
            .info(cx.env.stack_pointer)
            .map_or(8, |info| i64::from(info.width / 8));
        let link_entry = self.link.and_then(|link| entry_value(function, link));
        let return_written = cx.env.return_slot.is_some_and(|slot| {
            function.insts.iter().any(|inst| {
                let Op::Store { address, value, .. } = inst.op else {
                    return false;
                };
                let bytes = match function.ty(value) {
                    Some(Type::Bits(width)) => i64::from(width.div_ceil(8)),
                    Some(Type::Memory) | None => i64::MAX,
                };
                stack.offset(address).is_some_and(|offset| {
                    offset < slot.saturating_add(link_bytes) && offset.saturating_add(bytes) > slot
                })
            })
        });
        let mut unresolved: Vec<(usize, Value)> = Vec::new();
        for index in leaving {
            let Some(Terminator::Leave { address, state, .. }) =
                function.blocks.get(index).map(|block| &block.terminator)
            else {
                continue;
            };
            let address = *address;
            if constants.constant(address).is_some() {
                continue;
            }
            let entry_height = state
                .registers
                .get(sp)
                .is_some_and(|&value| stack.offset(value) == Some(0));
            let link_kept = match (self.link, cx.env.return_slot) {
                (Some(link), _) => {
                    link_entry.is_some()
                        && state.registers.get(usize::from(link.0)).copied() == link_entry
                }
                (None, Some(_)) => !return_written,
                (None, None) => false,
            };
            let restored = self
                .kept
                .iter()
                .filter(|&&register| usize::from(register.0) != sp)
                .all(|&register| {
                    let Some(entry) = entry_value(function, register) else {
                        return true;
                    };
                    state
                        .registers
                        .get(usize::from(register.0))
                        .is_some_and(|&value| stack.holds(function, value, entry))
                });
            if entry_height && link_kept && restored {
                self.tails += 1;
            } else {
                unresolved.push((index, address));
            }
        }
        self.unresolved = unresolved.len();
        for &(index, address) in &unresolved {
            if let Some(block) = function.blocks.get_mut(index) {
                block.terminator = Terminator::IndirectJump {
                    address,
                    targets: Vec::new(),
                };
            }
        }
        Ok(Changed::from(!unresolved.is_empty()))
    }
}

/// The pass `assume-dereferenced-canonical`, the reading view's
/// assumption: `function` under the assumption that every address it
/// dereferences (loads from, stores to,
/// calls or jumps to) is canonical. Every branch on L0's check that an
/// address is canonical (as for [`AssumeCanonical`]) that guards an
/// access becomes a jump the way a canonical address goes. It guards an
/// access when its other way only traps as a non-canonical address does
/// (`#GP` or `#SS`: a block of no instructions ending in that trap) and
/// the way it keeps reaches, within the same machine instruction as the
/// check (the instruction address of the comparison), an access at that
/// address before anything with an effect but a load: a load or store at
/// it, a call of it, a jump to it, a return to it, passing only further
/// checks of that kind (another operand's, an alignment check) and jumps.
/// A comparison of the same form the program computes for itself (a
/// pointer-tagging test) traps nowhere and is left alone; so is a check
/// no access follows.
///
/// Not part of decompilation's exact pipeline: the reading view runs it on
/// a copy of the exact L1 and decompiles that. Preserves nothing, as
/// [`AssumeCanonical`]. Fuel: a unit per block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssumeDereferenced {
    folded: Vec<u64>,
}

impl AssumeDereferenced {
    /// The checks its runs have folded, one each, in order: the address
    /// of the machine instruction each guards (the access it checks).
    pub fn folded(&self) -> &[u64] {
        &self.folded
    }
}

impl<'e> Pass<Function, L1Env<'e>> for AssumeDereferenced {
    fn name(&self) -> &'static str {
        "assume-dereferenced-canonical"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(blocks(function))?;
        let mut taken: Vec<(usize, Target, u64)> = Vec::new();
        for (index, block) in function.blocks.iter().enumerate() {
            let Terminator::Branch {
                condition,
                then,
                otherwise,
            } = &block.terminator
            else {
                continue;
            };
            let Some((address, equal)) = canonical_check(function, *condition) else {
                continue;
            };
            let (good, bad) = if equal {
                (then, otherwise)
            } else {
                (otherwise, then)
            };
            let Some(at) = machine_address(function, *condition) else {
                continue;
            };
            if faults(function, bad.block) && accesses(function, good.block, at, address) {
                taken.push((index, good.clone(), at));
            }
        }
        for &(index, ref target, at) in &taken {
            if let Some(block) = function.blocks.get_mut(index) {
                block.terminator = Terminator::Jump(target.clone());
            }
            self.folded.push(at);
        }
        Ok(Changed::from(!taken.is_empty()))
    }
}

/// The pass `assume-aligned-stack`, the reading view's assumption that
/// the stack pointer at entry is 16-byte aligned, as AAPCS64 requires at
/// every public interface ("Universal stack constraints": `SP mod 16 =
/// 0`). Every branch on L0's check that the stack pointer an AArch64
/// access uses is aligned (`SCTLR_EL1.SA0`: `sp[0..k] != 0`, `k` at most
/// 4, or `==`) whose other way only traps as a misaligned stack pointer
/// does (a block of no instructions ending in [`Trap::Stack`]) becomes a
/// jump the aligned way where the checked value is a stack address at an
/// offset from the entry stack pointer that is a multiple of `2^k`.
/// x86's stack checks are canonical-address checks
/// ([`AssumeDereferenced`]), which this leaves alone.
///
/// Not part of decompilation's exact pipeline, as [`AssumeDereferenced`].
/// Preserves nothing, as [`AssumeCanonical`]. Fuel: a unit per block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssumeAligned {
    folded: Vec<u64>,
}

impl AssumeAligned {
    /// The checks its runs have folded, one each, in order: the address
    /// of the machine instruction each guards.
    pub fn folded(&self) -> &[u64] {
        &self.folded
    }
}

impl<'e> Pass<Function, L1Env<'e>> for AssumeAligned {
    fn name(&self) -> &'static str {
        "assume-aligned-stack"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(blocks(function))?;
        let stack = cx.analysis::<Stack>(function);
        let constants = cx.analysis::<Constants>(function);
        let mut taken: Vec<(usize, Target, u64)> = Vec::new();
        for (index, block) in function.blocks.iter().enumerate() {
            let Terminator::Branch {
                condition,
                then,
                otherwise,
            } = &block.terminator
            else {
                continue;
            };
            let Some((address, bits, misaligned)) =
                alignment_check(function, &constants, *condition)
            else {
                continue;
            };
            let (good, bad) = if misaligned {
                (otherwise, then)
            } else {
                (then, otherwise)
            };
            let aligned = stack
                .offset(address)
                .is_some_and(|offset| offset.rem_euclid(1 << bits) == 0);
            if aligned
                && only_traps(function, bad.block, Trap::Stack)
                && let Some(at) = machine_address(function, *condition)
            {
                taken.push((index, good.clone(), at));
            }
        }
        for &(index, ref target, at) in &taken {
            if let Some(block) = function.blocks.get_mut(index) {
                block.terminator = Terminator::Jump(target.clone());
            }
            self.folded.push(at);
        }
        Ok(Changed::from(!taken.is_empty()))
    }
}

/// The value `condition` checks the alignment of, the bits it checks and
/// whether it holds when they are not all 0, if it is L0's alignment
/// check: `x[0..k] != 0` (true) or `== 0` (false), `k` at most 4.
fn alignment_check(
    function: &Function,
    constants: &Constants,
    condition: Value,
) -> Option<(Value, u16, bool)> {
    let &Op::Binary(op @ (Binary::Ne | Binary::Eq), a, b) = defining(function, condition)? else {
        return None;
    };
    let misaligned = op == Binary::Ne;
    let low = [(a, b), (b, a)].into_iter().find_map(|(low, zero)| {
        constants
            .constant(zero)
            .is_some_and(|bits| bits.is_zero())
            .then_some(low)
    })?;
    let &Op::Extract {
        value,
        offset: 0,
        width,
    } = defining(function, low)?
    else {
        return None;
    };
    (width <= 4).then_some((value, width, misaligned))
}

/// Whether `block` only traps with `trap`: no instructions, then it.
fn only_traps(function: &Function, block: BlockId, trap: Trap) -> bool {
    function
        .block(block)
        .is_some_and(|block| block.insts.is_empty() && block.terminator == Terminator::Trap(trap))
}

/// The pass `assume-authenticated-returns`, the reading view's assumption
/// that a return address signed with pointer authentication
/// (`paciasp`, `pacibsp`: the link register's entry value, an
/// instruction key, the stack pointer as the modifier) authenticates
/// where the function takes it back (`autiasp`, `autibsp`, `retaa`,
/// `retab`): the return address is the one a call left, which a signature
/// round trip gives back. Every use of such a signature is the entry
/// value (what the frame record keeps is the return address, whether or
/// not the function returns). Where an authentication takes, with the
/// same key and a modifier at the same offset from the entry stack
/// pointer, a value that is a signature wherever it is computed
/// (directly, or restored from the frame slot it was saved to:
/// [`Stack::holds`]), its result is the entry value (exactly, as
/// [`authenticated_entry`] says) and the branch to its fault (a block of
/// no instructions ending in [`Trap::Authentication`], within the same
/// machine instruction) becomes a jump the other way. The memory after
/// each of their `compute_pac`s is the memory before it (a keyed hash
/// writes none), and, their codes unused, they no longer take the stack
/// pointer. Pointers signed otherwise (data keys, other registers,
/// function pointers branched to with `braa`) are left alone.
///
/// Not part of decompilation's exact pipeline, as [`AssumeDereferenced`].
/// Preserves nothing, as [`AssumeCanonical`]. Fuel: a unit per value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssumeAuthenticated {
    link: RegisterId,
    folded: Vec<u64>,
}

impl AssumeAuthenticated {
    /// The pass, for a convention whose calls leave the return address in
    /// register `link`.
    pub fn new(link: RegisterId) -> Self {
        Self {
            link,
            folded: Vec::new(),
        }
    }

    /// The authentication checks its runs have folded, one each, in
    /// order: the address of the machine instruction each is part of.
    pub fn folded(&self) -> &[u64] {
        &self.folded
    }
}

/// A pointer signed or authenticated by L0's `AddPAC` or `Auth`: the
/// pointer, the `compute_pac` instruction, its modifier and key, and the
/// masks the code is cut to before the exclusive or with the pointer
/// (the upper half's, the lower half's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pac {
    pointer: Value,
    hash: InstId,
    modifier: Value,
    key: u64,
    masks: (u64, u64),
}

impl<'e> Pass<Function, L1Env<'e>> for AssumeAuthenticated {
    fn name(&self) -> &'static str {
        "assume-authenticated-returns"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel
            .spend(u64::try_from(function.values.len()).unwrap_or(u64::MAX))?;
        let Some(entry) = entry_value(function, self.link) else {
            return Ok(Changed::No);
        };
        let Some(hash) = cx.env.declarations.find_intrinsic("compute_pac") else {
            return Ok(Changed::No);
        };
        let stack = cx.analysis::<Stack>(function);
        let constants = cx.analysis::<Constants>(function);
        let pacs = pacs(function, &constants, hash);
        let signed = signatures(&pacs, &stack, entry);
        // Each value to replace, by what replaces it.
        let mut replaced: BTreeMap<Value, Value> = BTreeMap::new();
        let mut hashes: BTreeSet<InstId> = BTreeSet::new();
        let mut authenticated: Vec<u64> = Vec::new();
        // A keyed hash no one needs: detached, its memory passed through.
        let mut unneeded = |hash: InstId, replaced: &mut BTreeMap<Value, Value>| {
            hashes.insert(hash);
            if let Some(inst) = function.inst(hash)
                && let Op::Intrinsic { memory, .. } = inst.op
                && let Some(&after) = inst.results.last()
            {
                replaced.insert(after, memory);
            }
        };
        // Every signature of the return address is the return address,
        // whether or not the function returns (`fail` signs it for the
        // frame record and calls `exit`).
        for &(signature, sign) in &signed {
            replaced.insert(signature, entry);
            unneeded(sign.hash, &mut replaced);
        }
        for (result, auth) in &pacs {
            if signing(function, &stack, &signed, *result, auth).is_none() {
                continue;
            }
            replaced.insert(*result, entry);
            unneeded(auth.hash, &mut replaced);
            if let Some(at) = machine_address(function, *result) {
                authenticated.push(at);
            }
        }
        if replaced.is_empty() {
            return Ok(Changed::No);
        }
        let mut replace = |mut value: Value| {
            while let Some(&next) = replaced.get(&value) {
                value = next;
            }
            value
        };
        for inst in &mut function.insts {
            inst.op.map_values(&mut replace);
        }
        for block in &mut function.blocks {
            block.terminator.map_values(&mut replace);
        }
        // The authentications' faults, now on the entry value.
        let mut taken: Vec<(usize, Target, u64)> = Vec::new();
        for (index, block) in function.blocks.iter().enumerate() {
            let Terminator::Branch {
                condition,
                then,
                otherwise,
            } = &block.terminator
            else {
                continue;
            };
            let Some(at) =
                machine_address(function, *condition).filter(|at| authenticated.contains(at))
            else {
                continue;
            };
            let good = if only_traps(function, then.block, Trap::Authentication) {
                otherwise
            } else if only_traps(function, otherwise.block, Trap::Authentication) {
                then
            } else {
                continue;
            };
            taken.push((index, good.clone(), at));
        }
        for (index, target, at) in taken {
            if let Some(block) = function.blocks.get_mut(index) {
                block.terminator = Terminator::Jump(target);
            }
            self.folded.push(at);
        }
        detach(function, &hashes);
        Ok(Changed::Yes)
    }
}

/// Detaches the keyed hashes `hashes` of `function`, whose codes nothing
/// uses any more, from their modifiers (the stack pointer): each hashes
/// its pointer with itself, so no stack address is taken for a code no
/// one reads (L1 has no instruction removal; lowering shows a keyed hash
/// only for a code it needs).
fn detach(function: &mut Function, hashes: &BTreeSet<InstId>) {
    for &hash in hashes {
        if let Some(inst) = function.insts.get_mut(hash.0 as usize)
            && let Op::Intrinsic { inputs, .. } = &mut inst.op
            && let [pointer, modifier, _] = inputs.as_mut_slice()
        {
            *modifier = *pointer;
        }
    }
}

/// Whether `value` is the link register's entry value `entry`
/// authenticated back: L0's `Auth` (`autiasp`, `retab`, …; `hash` is
/// `compute_pac`) of a value that is the entry value signed by L0's
/// `AddPAC` (`paciasp`, `pacibsp`) wherever it is computed (directly,
/// or restored from the frame slot it was saved to: [`Stack::holds`]),
/// both with one instruction key (IA, IB), the same masks and modifiers
/// at the same offset from the entry stack pointer. Its result is then
/// the entry value exactly, whether or not the authentication faults:
/// `Auth` recomputes the code on the signed pointer with its PAC field
/// made copies of bit 55, which is the pointer `AddPAC` hashed, with the
/// same modifier and key, and XORs it out of the field again.
pub fn authenticated_entry(
    function: &Function,
    constants: &Constants,
    stack: &Stack,
    hash: IntrinsicId,
    entry: Value,
    value: Value,
) -> bool {
    let Some(auth) = pac(function, constants, hash, value) else {
        return false;
    };
    let signed = signatures(&pacs(function, constants, hash), stack, entry);
    signing(function, stack, &signed, value, &auth).is_some()
}

/// Every value of `function` L0's `AddPAC` or `Auth` made ([`pac`]).
fn pacs(function: &Function, constants: &Constants, hash: IntrinsicId) -> Vec<(Value, Pac)> {
    (0..function.values.len())
        .filter_map(|index| {
            let value = Value(u32::try_from(index).ok()?);
            Some((value, pac(function, constants, hash, value)?))
        })
        .collect()
}

/// Those of `pacs` that sign the link register's entry value `entry` as
/// a return address: an instruction key (IA, IB), a modifier at a known
/// offset from the entry stack pointer.
fn signatures(pacs: &[(Value, Pac)], stack: &Stack, entry: Value) -> Vec<(Value, Pac)> {
    pacs.iter()
        .copied()
        .filter(|(_, p)| p.pointer == entry && p.key < 2 && stack.offset(p.modifier).is_some())
        .collect()
}

/// The signature among `signed` that `auth` (the making of `result`)
/// authenticates back ([`authenticated_entry`]), if one.
fn signing(
    function: &Function,
    stack: &Stack,
    signed: &[(Value, Pac)],
    result: Value,
    auth: &Pac,
) -> Option<(Value, Pac)> {
    signed.iter().copied().find(|&(signature, sign)| {
        signature != result
            && sign.key == auth.key
            && sign.masks == auth.masks
            && stack.offset(sign.modifier) == stack.offset(auth.modifier)
            && stack.holds(function, auth.pointer, signature)
    })
}

/// What L0's `AddPAC` or `Auth` made `value` of, if it is their result:
/// `select(_, p ^ (code & upper), p ^ (code & lower))`, `code` the first
/// output of intrinsic `hash` (`compute_pac`) with a constant key.
fn pac(function: &Function, constants: &Constants, hash: IntrinsicId, value: Value) -> Option<Pac> {
    let &Op::Select {
        then, otherwise, ..
    } = defining(function, value)?
    else {
        return None;
    };
    let (pointer, code, upper) = xor_masked(function, constants, then)?;
    let (other, again, lower) = xor_masked(function, constants, otherwise)?;
    if pointer != other || code != again {
        return None;
    }
    let Definition::Result { inst, index: 0 } = function.value(code)?.definition else {
        return None;
    };
    let Op::Intrinsic {
        intrinsic, inputs, ..
    } = &function.inst(inst)?.op
    else {
        return None;
    };
    let &[_, modifier, key] = inputs.as_slice() else {
        return None;
    };
    (*intrinsic == hash).then_some(())?;
    Some(Pac {
        pointer,
        hash: inst,
        modifier,
        key: constants.constant(key)?.low_u64(),
        masks: (upper, lower),
    })
}

/// `p`, `code` and `mask` where `value` is `p ^ (code & mask)`, `mask` a
/// constant.
fn xor_masked(
    function: &Function,
    constants: &Constants,
    value: Value,
) -> Option<(Value, Value, u64)> {
    let &Op::Binary(Binary::Xor, a, b) = defining(function, value)? else {
        return None;
    };
    [(a, b), (b, a)].into_iter().find_map(|(pointer, masked)| {
        let &Op::Binary(Binary::And, x, y) = defining(function, masked)? else {
            return None;
        };
        [(x, y), (y, x)].into_iter().find_map(|(code, mask)| {
            let mask = constants.constant(mask)?;
            (mask.width() == 64).then(|| (pointer, code, mask.low_u64()))
        })
    })
}

/// The machine instruction address `value` is computed at, if an
/// instruction computes it.
fn machine_address(function: &Function, value: Value) -> Option<u64> {
    match function.value(value)?.definition {
        Definition::Result { inst, .. } => function.inst(inst).map(|i| i.address),
        Definition::Parameter { .. } => None,
    }
}

/// Whether `block` only traps as an access at a non-canonical address
/// does: no instructions, then `#GP` or `#SS`.
fn faults(function: &Function, block: BlockId) -> bool {
    function.block(block).is_some_and(|block| {
        block.insts.is_empty()
            && matches!(
                block.terminator,
                Terminator::Trap(Trap::Protection | Trap::Stack)
            )
    })
}

/// The most blocks [`accesses`] walks through.
const GUARDS: usize = 16;

/// Whether control from the start of `block` reaches an access at
/// `address` within the machine instruction at `at`, by the rules of
/// [`AssumeDereferenced`].
fn accesses(function: &Function, mut block: BlockId, at: u64, address: Value) -> bool {
    for _ in 0..GUARDS {
        let Some(current) = function.block(block) else {
            return false;
        };
        for (index, &inst) in current.insts.iter().enumerate() {
            // A call's push of its return address is the call's own: the
            // target is checked before it (as the processor does) and
            // called after it.
            let rest = current.insts.get(index + 1..).unwrap_or_default();
            if pushes_return_of(function, inst, rest, address) {
                continue;
            }
            if let Some(found) = access(function, inst, at, address) {
                return found;
            }
        }
        block = match &current.terminator {
            Terminator::Jump(target) => target.block,
            Terminator::Branch {
                then, otherwise, ..
            } => {
                if faults(function, then.block) {
                    otherwise.block
                } else if faults(function, otherwise.block) {
                    then.block
                } else {
                    return false;
                }
            }
            Terminator::IndirectJump { address: to, .. }
            | Terminator::Return { address: to, .. }
            | Terminator::Leave { address: to, .. } => return *to == address,
            Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Invoke { .. }
            | Terminator::Open => {
                return false;
            }
        };
    }
    false
}

/// Whether `inst` stores the return address of a call of `address` that
/// follows it among `rest` (in the same machine instruction).
fn pushes_return_of(function: &Function, inst: InstId, rest: &[InstId], address: Value) -> bool {
    let Some(&Op::Store { value, .. }) = function.inst(inst).map(|i| &i.op) else {
        return false;
    };
    let at = function.inst(inst).map(|i| i.address);
    rest.iter()
        .filter_map(|&next| function.inst(next))
        .take_while(|next| Some(next.address) == at)
        .any(|next| {
            matches!(next.op, Op::Call { target, return_address, .. }
                if target == address && return_address == value)
        })
}

/// What instruction `inst` says about an access at `address` within the
/// machine instruction at `at`: `Some(true)`, it is one; `Some(false)`,
/// none can follow (another instruction's, or an effect other than a
/// load); `None`, look further.
fn access(function: &Function, inst: InstId, at: u64, address: Value) -> Option<bool> {
    let Some(inst) = function.inst(inst) else {
        return Some(false);
    };
    if inst.address != at {
        return Some(false);
    }
    match &inst.op {
        Op::Load { address: to, .. } => (*to == address).then_some(true),
        Op::Store { address: to, .. } | Op::Call { target: to, .. } => Some(*to == address),
        Op::Intrinsic { .. } | Op::SystemCall { .. } | Op::Landing { .. } => Some(false),
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
        | Op::Float { .. } => None,
    }
}

/// The address `condition` checks and what it is for a canonical one, if
/// it is L0's check that an address is canonical: `x == sext(x[0..k])`
/// (true) or `!=` (false).
fn canonical_check(function: &Function, condition: Value) -> Option<(Value, bool)> {
    let &Op::Binary(op, a, b) = defining(function, condition)? else {
        return None;
    };
    let equal = if op == Binary::Eq {
        true
    } else if op == Binary::Ne {
        false
    } else {
        return None;
    };
    let address = [(a, b), (b, a)]
        .into_iter()
        .find_map(|(extended, x)| sign_extends_low_bits(function, extended, x).then_some(x))?;
    Some((address, equal))
}

/// Whether `extended` is `x`'s low bits, fewer than its width, sign
/// extended back to its width.
fn sign_extends_low_bits(function: &Function, extended: Value, x: Value) -> bool {
    let Some(&Op::Extend {
        signed: true,
        value: low,
        width,
    }) = defining(function, extended)
    else {
        return false;
    };
    let Some(&Op::Extract {
        value,
        offset: 0,
        width: bits,
    }) = defining(function, low)
    else {
        return false;
    };
    value == x && bits < width && function.ty(x) == Some(Type::Bits(width))
}

/// Whether `x` is the caller's return address: a load, as wide as `x`, of
/// the stack slot at `slot` that no store in the function wrote.
fn caller_return(function: &Function, stack: &Stack, slot: i64, x: Value) -> bool {
    let Some(&Op::Load {
        address,
        bytes,
        atomic: None,
        ..
    }) = defining(function, x)
    else {
        return false;
    };
    function.ty(x) == Some(Type::Bits(bytes.saturating_mul(8)))
        && stack.offset(address) == Some(slot)
        && stack.resolve(function, x) == x
}

/// The value of register `register` at the function's entry.
pub fn entry_value(function: &Function, register: RegisterId) -> Option<Value> {
    function
        .blocks
        .first()
        .and_then(|entry| entry.parameters.get(register.0 as usize).copied())
}

/// The address `value` is AArch64's branch-target view of, if it is one:
/// `select(x[55], x, zext(x[0..56]))`, `x` with its top byte cleared
/// unless bit 55 is set (top-byte-ignore for instruction addresses in the
/// lower half), as `ret`, `br` and `blr` take their target. A return
/// address a call left is its own view: the call writes the address of
/// the instruction after it, a lower-half address whose top byte is 0.
pub fn top_byte_view(function: &Function, value: Value) -> Option<Value> {
    let &Op::Select {
        condition,
        then,
        otherwise,
    } = defining(function, value)?
    else {
        return None;
    };
    let &Op::Extract {
        value: tested,
        offset: 55,
        width: 1,
    } = defining(function, condition)?
    else {
        return None;
    };
    let &Op::Extend {
        signed: false,
        value: low,
        width: 64,
    } = defining(function, otherwise)?
    else {
        return None;
    };
    let &Op::Extract {
        value: cleared,
        offset: 0,
        width: 56,
    } = defining(function, low)?
    else {
        return None;
    };
    (tested == then && cleared == then && function.ty(then) == Some(Type::Bits(64))).then_some(then)
}

/// Each value's offset from `base` (an input of `function`, `None`: no
/// value has one), by the rules of [the module](self): `base` is at 0,
/// adding or subtracting a constant keeps an offset, a block parameter
/// whose arguments all have one offset has it; the other inputs vary.
/// The blocks are visited in order, again from the first once past the
/// last, until none changes, as sweeping them all would; only those an
/// offset they read changed since their last visit are ([`Readers`]): a
/// visit of another would change nothing. So a function's offsets take
/// time by the offsets that change, not by its blocks times the sweeps
/// (thousands, where a loop's offset reaches its back edge late).
fn offsets_from(
    function: &Function,
    constants: &Constants,
    base: Option<Value>,
    predecessors: &[Vec<(BlockId, usize)>],
) -> Vec<Offset> {
    let mut offsets = vec![Offset::Unknown; function.values.len()];
    for &parameter in function
        .blocks
        .first()
        .map_or(&[][..], |b| b.parameters.as_slice())
    {
        if let Some(slot) = offsets.get_mut(parameter.0 as usize) {
            *slot = if Some(parameter) == base {
                Offset::Known(0)
            } else {
                Offset::Varies
            };
        }
    }
    let readers = Readers::new(function);
    let blocks = u32::try_from(function.blocks.len()).unwrap_or(u32::MAX);
    let mut dirty: BTreeSet<u32> = (0..blocks).collect();
    let mut next = 0;
    while let Some(&index) = dirty.range(next..).next().or_else(|| dirty.first()) {
        dirty.remove(&index);
        next = index.saturating_add(1);
        let Some(block) = function.block(BlockId(index)) else {
            continue;
        };
        for (position, &parameter) in block.parameters.iter().enumerate() {
            if index == 0 {
                continue;
            }
            let mut offset = Offset::Unknown;
            for &(pred, edge) in predecessors
                .get(index as usize)
                .map_or(&[][..], Vec::as_slice)
            {
                let argument = function
                    .block(pred)
                    .and_then(|b| b.terminator.targets().nth(edge))
                    .and_then(|t| t.arguments.get(position).copied());
                let incoming = argument.map_or(Offset::Varies, |a| get(&offsets, a));
                offset = offset.meet(incoming);
            }
            if update(&mut offsets, parameter, offset) {
                dirty.extend(readers.of(parameter));
            }
        }
        for &inst in &block.insts {
            let Some(i) = function.inst(inst) else {
                continue;
            };
            let offset = instruction_offset(&offsets, constants, &i.op);
            for &result in &i.results {
                if update(&mut offsets, result, offset) {
                    dirty.extend(readers.of(result));
                }
            }
        }
    }
    offsets
}

/// The blocks whose offsets ([`offsets_from`]) read each value's: those
/// of the instructions whose offset it is an operand of
/// ([`offset_operands`]), and those its jumps pass it to as an argument.
/// Each value's run of `blocks` starts at its place in `starts`.
struct Readers {
    starts: Vec<u32>,
    blocks: Vec<u32>,
}

impl Readers {
    /// The readers of each of `function`'s values.
    fn new(function: &Function) -> Self {
        // Each value read and the block reading it, in block order.
        let each = |visit: &mut dyn FnMut(Value, u32)| {
            for (index, block) in function.blocks.iter().enumerate() {
                let index = u32::try_from(index).unwrap_or(u32::MAX);
                for &inst in &block.insts {
                    for value in function
                        .inst(inst)
                        .and_then(|i| offset_operands(&i.op))
                        .into_iter()
                        .flatten()
                    {
                        visit(value, index);
                    }
                }
                for target in block.terminator.targets() {
                    for &value in &target.arguments {
                        visit(value, target.block.0);
                    }
                }
            }
        };
        let mut starts = vec![0u32; function.values.len() + 1];
        each(&mut |value, _| {
            if let Some(count) = starts.get_mut(value.0 as usize + 1) {
                *count += 1;
            }
        });
        for i in 1..starts.len() {
            let before = starts.get(i - 1).copied().unwrap_or(0);
            if let Some(start) = starts.get_mut(i) {
                *start += before;
            }
        }
        let mut blocks = vec![0u32; starts.last().copied().unwrap_or(0) as usize];
        let mut filled = starts.clone();
        each(&mut |value, block| {
            if let Some(at) = filled.get_mut(value.0 as usize) {
                if let Some(slot) = blocks.get_mut(*at as usize) {
                    *slot = block;
                }
                *at += 1;
            }
        });
        Self { starts, blocks }
    }

    /// The blocks reading `value`'s offset.
    fn of(&self, value: Value) -> &[u32] {
        let at = value.0 as usize;
        match (self.starts.get(at), self.starts.get(at + 1)) {
            (Some(&from), Some(&to)) => self.blocks.get(from as usize..to as usize).unwrap_or(&[]),
            _ => &[],
        }
    }
}

/// The operands whose offsets [`instruction_offset`] reads for `op`: an
/// addition's or a subtraction's; the others' offsets vary whatever.
fn offset_operands(op: &Op) -> Option<[Value; 2]> {
    match *op {
        Op::Binary(Binary::Add | Binary::Sub, a, b) => Some([a, b]),
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
        | Op::Float { .. }
        | Op::Load { .. }
        | Op::Store { .. }
        | Op::Intrinsic { .. }
        | Op::Call { .. }
        | Op::SystemCall { .. }
        | Op::Landing { .. } => None,
    }
}

/// The offset of the result of `op`, from its operands' `offsets`.
fn instruction_offset(offsets: &[Offset], constants: &Constants, op: &Op) -> Offset {
    match *op {
        Op::Binary(Binary::Add, a, b) => match (get(offsets, a), get(offsets, b)) {
            (base @ Offset::Known(_), _) => combine(base, constants.constant(b).map(signed)),
            (_, base @ Offset::Known(_)) => combine(base, constants.constant(a).map(signed)),
            (Offset::Unknown, _) | (_, Offset::Unknown) => Offset::Unknown,
            (Offset::Varies, Offset::Varies) => Offset::Varies,
        },
        Op::Binary(Binary::Sub, a, b) => combine(
            get(offsets, a),
            constants
                .constant(b)
                .map(|bits| signed(bits).wrapping_neg()),
        ),
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
        | Op::Float { .. }
        | Op::Load { .. }
        | Op::Store { .. }
        | Op::Intrinsic { .. }
        | Op::Call { .. }
        | Op::SystemCall { .. }
        | Op::Landing { .. } => Offset::Varies,
    }
}

fn get(offsets: &[Offset], value: Value) -> Offset {
    offsets
        .get(value.0 as usize)
        .copied()
        .unwrap_or(Offset::Varies)
}

/// Lowers `value`'s offset by `offset`; whether it changed.
fn update(offsets: &mut [Offset], value: Value, offset: Offset) -> bool {
    let Some(slot) = offsets.get_mut(value.0 as usize) else {
        return false;
    };
    let lowered = slot.meet(offset);
    let changed = lowered != *slot;
    *slot = lowered;
    changed
}

/// `base` moved by the constant `delta`.
fn combine(base: Offset, delta: Option<i64>) -> Offset {
    match (base, delta) {
        (Offset::Known(base), Some(delta)) => Offset::Known(base.wrapping_add(delta)),
        (Offset::Unknown, _) => Offset::Unknown,
        (Offset::Known(_) | Offset::Varies, _) => Offset::Varies,
    }
}

fn signed(bits: Bits) -> i64 {
    bits.low_u64().cast_signed()
}
