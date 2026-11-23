//! What a function does to its caller's registers and stack, read off its
//! returns: the registers it gives back as they came (also those saved and
//! restored through the stack), those it changes, and how it moves the
//! stack pointer. Callers use it in place of the calling convention's
//! assumptions where it knows better.

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::ir::{Declarations, RegisterId};

use crate::build::CallEffect;
use crate::condition::defining;
use crate::constant::Constants;
use crate::graph;
use crate::ir::{BlockId, Definition, Function, Op, Terminator, Type, Value};
use crate::stack::{Stack, entry_value};

/// What a function does to one register, over all its returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kept {
    /// Every return gives it back with its value at entry.
    Yes,
    /// Some return gives back another value.
    No,
    /// Some return reloads it from a stack slot the analysis cannot follow
    /// (a frame whose address escaped, past a call): the calling
    /// convention decides.
    Unknown,
}

impl Kept {
    /// Over two returns.
    #[must_use]
    pub const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Yes, Self::Yes) => Self::Yes,
        }
    }
}

/// A function's effect on its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Per register, in register order.
    pub kept: Vec<Kept>,
    /// Per register, in register order: how many of its low bits every
    /// return gives back as they came (all of them where it is kept; the
    /// low half of a vector register saved and restored as a scalar).
    pub low: Vec<u16>,
    /// What every return adds to the stack pointer (x86-64: 8 for the
    /// popped return address, more for `ret n`).
    pub stack: i64,
}

impl Summary {
    /// The effect of calling the function: the registers it changes, those
    /// it may change by `convention` where the summary cannot tell, the
    /// values `convention` says it leaves known, and its stack pointer move.
    /// Of a register it changes, the low bits `convention` says a callee
    /// keeps are kept where every return gives them back, or where the
    /// summary cannot tell.
    pub fn effect(&self, stack_pointer: RegisterId, convention: &CallEffect) -> CallEffect {
        let changes: Vec<RegisterId> = self
            .kept
            .iter()
            .enumerate()
            .map(|(index, &kept)| (RegisterId(u16::try_from(index).unwrap_or(u16::MAX)), kept))
            .filter(|&(register, kept)| {
                register != stack_pointer
                    && (kept == Kept::No
                        || (kept == Kept::Unknown && convention.changes.contains(&register)))
            })
            .map(|(register, _)| register)
            .collect();
        let kept_low = convention
            .kept_low
            .iter()
            .filter(|&&(register, bits)| {
                let index = usize::from(register.0);
                changes.contains(&register)
                    && (self.kept.get(index) == Some(&Kept::Unknown)
                        || self.low.get(index).is_some_and(|&low| low >= bits))
            })
            .copied()
            .collect();
        CallEffect {
            changes,
            kept_low,
            known: convention.known.clone(),
            stack: Some((stack_pointer, self.stack)),
            returns: true,
        }
    }
}

/// The summary of `function` (registers of `declarations`, stack pointer
/// `stack_pointer`), if it returns and every way out of it is a return it
/// can see (no tail calls, no jumps it cannot follow; a tail call to code
/// that never returns is no way out, like a call that does not return),
/// each with the stack
/// pointer moved by the same known amount.
pub fn summarize(
    function: &Function,
    declarations: &Declarations,
    constants: &Constants,
    stack: &Stack,
    stack_pointer: RegisterId,
) -> Option<Summary> {
    let predecessors = graph::predecessors(function);
    let mut kept = vec![Kept::Yes; declarations.registers.len()];
    let mut low = vec![u16::MAX; declarations.registers.len()];
    let mut delta: Option<i64> = None;
    for (index, block) in function.blocks.iter().enumerate() {
        if !constants.reachable(BlockId(u32::try_from(index).unwrap_or(u32::MAX))) {
            continue;
        }
        let state = match &block.terminator {
            Terminator::Return { state, .. } => state,
            Terminator::Leave { returns: true, .. } => return None,
            Terminator::IndirectJump { targets, .. } if targets.is_empty() => return None,
            Terminator::Jump(_)
            | Terminator::Branch { .. }
            | Terminator::Invoke { .. }
            | Terminator::IndirectJump { .. }
            | Terminator::Leave { returns: false, .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => continue,
        };
        for (register, slot) in kept.iter_mut().enumerate() {
            let entry = entry_value(
                function,
                RegisterId(u16::try_from(register).unwrap_or(u16::MAX)),
            );
            let (here, bits) =
                if let (Some(entry), Some(&value)) = (entry, state.registers.get(register)) {
                    (
                        classify(function, stack, &predecessors, entry, value),
                        kept_bits(function, stack, &predecessors, entry, value),
                    )
                } else {
                    (Kept::No, 0)
                };
            if let Some(low) = low.get_mut(register) {
                *low = (*low).min(bits);
            }
            *slot = slot.and(here);
        }
        let sp = state
            .registers
            .get(stack_pointer.0 as usize)
            .and_then(|&value: &Value| stack.offset(value))?;
        match delta {
            Some(other) if other != sp => return None,
            Some(_) | None => delta = Some(sp),
        }
    }
    Some(Summary {
        kept,
        low,
        stack: delta?,
    })
}

/// How many low bits of `value` are `entry`'s, following stack slots (a
/// save in the function's own frame past calls, [`Stack::saved`]),
/// block parameters (the fewest of the incoming values'), zero
/// extensions, concatenations (their low part) and extractions of low
/// bits: a vector register saved as a scalar and reloaded into it
/// (AArch64's `str d8` and `ldr d8`, which clears the bits above) keeps
/// the scalar's bits. All of `entry`'s for `entry` itself.
fn kept_bits(
    function: &Function,
    stack: &Stack,
    predecessors: &[Vec<(BlockId, usize)>],
    entry: Value,
    value: Value,
) -> u16 {
    let width = |value: Value| match function.value(value).map(|info| info.ty) {
        Some(Type::Bits(width)) => width,
        Some(Type::Memory) | None => 0,
    };
    let mut kept = width(entry);
    let mut seen = BTreeSet::new();
    let mut work = vec![(value, kept)];
    while let Some((value, within)) = work.pop() {
        let value = stack.resolve(function, value);
        if value == entry {
            kept = kept.min(within);
            continue;
        }
        if !seen.insert((value, within)) {
            continue;
        }
        if seen.len() > STEPS {
            return 0;
        }
        let inner = match function.value(value).map(|info| info.definition) {
            Some(Definition::Parameter { block, index }) if block != BlockId(0) => {
                let incoming = predecessors
                    .get(block.0 as usize)
                    .map_or(&[][..], Vec::as_slice);
                for &(pred, edge) in incoming {
                    let argument = function
                        .block(pred)
                        .and_then(|b| b.terminator.targets().nth(edge))
                        .and_then(|t| t.arguments.get(index as usize).copied());
                    match argument {
                        Some(argument) => work.push((argument, within)),
                        None => return 0,
                    }
                }
                continue;
            }
            Some(Definition::Result { .. }) => match defining(function, value) {
                Some(Op::Load { .. }) => {
                    let Some(stored) = stack.saved(function, value) else {
                        return 0;
                    };
                    let within = within.min(width(value));
                    work.extend(stored.into_iter().map(|stored| (stored, within)));
                    continue;
                }
                Some(
                    &(Op::Extend {
                        signed: false,
                        value: inner,
                        ..
                    }
                    | Op::Concat { low: inner, .. }
                    | Op::Extract {
                        value: inner,
                        offset: 0,
                        ..
                    }),
                ) => inner,
                Some(_) | None => return 0,
            },
            Some(Definition::Parameter { .. }) | None => return 0,
        };
        work.push((inner, within.min(width(value)).min(width(inner))));
    }
    kept
}

/// Whether `value` is `entry`, following stack slots and block parameters
/// (every incoming value counts; a cycle adds nothing): a reload from a
/// stack slot that cannot be followed is [`Kept::Unknown`].
fn classify(
    function: &Function,
    stack: &Stack,
    predecessors: &[Vec<(BlockId, usize)>],
    entry: Value,
    value: Value,
) -> Kept {
    let mut kept = Kept::Yes;
    let mut seen = BTreeSet::new();
    let mut work = vec![value];
    while let Some(value) = work.pop() {
        let value = stack.resolve(function, value);
        if value == entry || !seen.insert(value) {
            continue;
        }
        if seen.len() > STEPS {
            return Kept::No;
        }
        match function.value(value).map(|info| info.definition) {
            Some(Definition::Parameter { block, index }) if block != BlockId(0) => {
                let incoming = predecessors
                    .get(block.0 as usize)
                    .map_or(&[][..], Vec::as_slice);
                for &(pred, edge) in incoming {
                    let argument = function
                        .block(pred)
                        .and_then(|b| b.terminator.targets().nth(edge))
                        .and_then(|t| t.arguments.get(index as usize).copied());
                    match argument {
                        Some(argument) => work.push(argument),
                        None => return Kept::No,
                    }
                }
            }
            Some(Definition::Result { .. }) => match defining(function, value) {
                Some(&Op::Load { address, .. }) if stack.offset(address).is_some() => {
                    kept = kept.and(Kept::Unknown);
                }
                Some(_) | None => return Kept::No,
            },
            Some(Definition::Parameter { .. }) | None => return Kept::No,
        }
    }
    kept
}

/// The most values one classification looks at.
const STEPS: usize = 4096;
