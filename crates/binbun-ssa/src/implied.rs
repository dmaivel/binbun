//! The pass `fold-implied-branches`: a branch on whether a value is zero,
//! in code entered only by an edge of an earlier branch that tested the
//! same value, goes the way that test decided.
//!
//! Instructions whose result is undefined for a zero operand are lifted so:
//! x86's `bsr`/`bsf` leave their destination as it was where the source is
//! 0, which is a branch on the source and a join that takes the register's
//! old value. Code tests the source first (`test %al,%al; je`), and the
//! instruction's own branch then tests it again, through the extensions
//! and extractions between the two. Unfolded, the old value is read on a
//! path no run takes, and a register whose entry value it is becomes a
//! parameter.
//!
//! The same value is the same bits once zero and sign extensions,
//! extractions from bit 0 and `a & a`, `a | a` are seen through: the low
//! `w` bits of one value ([`Key`]), whose being zero each of those
//! preserves. An edge's test holds in every block its target dominates
//! where the target is entered only by that edge.
//!
//! Exact: the folded edge is one no run takes. The graph changes, so
//! nothing built on it survives.

use alloc::vec::Vec;

use binbun_semantics::core::pass::{Changed, Cx, Pass, Preserved, Refusal};
use binbun_semantics::ir::{Binary, Unary};

use crate::graph::{Dominators, predecessors};
use crate::ir::{BlockId, Definition, Function, Op, Terminator, Type, Value};
use crate::pass::{L1Env, blocks};

/// The pass `fold-implied-branches` ([module](self)). Fuel: a unit per
/// block.
#[derive(Clone, Copy, Debug, Default)]
pub struct FoldImplied;

impl<'e> Pass<Function, L1Env<'e>> for FoldImplied {
    fn name(&self) -> &'static str {
        "fold-implied-branches"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(blocks(function))?;
        let dominators = cx.analysis::<Dominators>(function);
        Ok(Changed::from(fold(function, &dominators) > 0))
    }

    fn preserves(&self, _: &mut Preserved) {}
}

/// The low `width` bits of a value: what a test of a value against zero
/// tests, extensions and extractions seen through.
pub type Key = (Value, u16);

/// Folds the branches of `function` an earlier test decides (its
/// `dominators`): how many.
fn fold(function: &mut Function, dominators: &Dominators) -> usize {
    let preds = predecessors(function);
    // Each edge's test: the block it enters (entered by it alone), what it
    // tested, and whether that is zero there.
    let mut known: Vec<(BlockId, Key, bool)> = Vec::new();
    for (index, block) in function.blocks.iter().enumerate() {
        let Terminator::Branch {
            condition,
            then,
            otherwise,
        } = &block.terminator
        else {
            continue;
        };
        if then.block == otherwise.block {
            continue;
        }
        let Some((key, zero_if_true)) = zero_test(function, *condition) else {
            continue;
        };
        let from = BlockId(u32::try_from(index).unwrap_or(u32::MAX));
        for (target, zero) in [(then.block, zero_if_true), (otherwise.block, !zero_if_true)] {
            let only = preds
                .get(target.0 as usize)
                .is_some_and(|list| list.iter().all(|&(pred, _)| pred == from));
            if only {
                known.push((target, key, zero));
            }
        }
    }
    if known.is_empty() {
        return 0;
    }
    let mut decided = Vec::new();
    for (index, block) in function.blocks.iter().enumerate() {
        let Terminator::Branch { condition, .. } = &block.terminator else {
            continue;
        };
        let Some((key, zero_if_true)) = zero_test(function, *condition) else {
            continue;
        };
        let here = BlockId(u32::try_from(index).unwrap_or(u32::MAX));
        if let Some(&(_, _, zero)) = known
            .iter()
            .find(|&&(start, tested, _)| tested == key && dominators.dominates(start, here))
        {
            // The condition is true exactly when the value is zero, or
            // exactly when it is not.
            decided.push((index, zero == zero_if_true));
        }
    }
    for &(index, taken) in &decided {
        let Some(block) = function.blocks.get_mut(index) else {
            continue;
        };
        let Terminator::Branch {
            then, otherwise, ..
        } = &block.terminator
        else {
            continue;
        };
        let target = if taken { then } else { otherwise }.clone();
        block.terminator = Terminator::Jump(target);
    }
    decided.len()
}

/// What 1-bit `condition` tests: a value against zero (`v == 0`, `0 != v`
/// …, or the negation of such a test), as its [`Key`], with whether the
/// value is zero where the condition holds.
pub fn zero_test(function: &Function, mut condition: Value) -> Option<(Key, bool)> {
    let mut negated = false;
    let (binary, a, b) = loop {
        match *defining(function, condition)? {
            Op::Unary(Unary::Not, inner) if bits(function, inner) == Some(1) => {
                negated = !negated;
                condition = inner;
            }
            Op::Binary(binary @ (Binary::Eq | Binary::Ne), a, b) => break (binary, a, b),
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
            | Op::Landing { .. } => return None,
        }
    };
    let tested = if is_zero(function, b) {
        a
    } else if is_zero(function, a) {
        b
    } else {
        return None;
    };
    let width = bits(function, tested)?;
    Some((
        key(function, tested, width),
        (binary == Binary::Eq) != negated,
    ))
}

/// How many bits `value` has (none for the memory).
fn bits(function: &Function, value: Value) -> Option<u16> {
    match function.value(value)?.ty {
        Type::Bits(width) => Some(width),
        Type::Memory => None,
    }
}

/// Whether `value` is the constant 0.
fn is_zero(function: &Function, value: Value) -> bool {
    matches!(defining(function, value), Some(Op::Const(bits)) if bits.is_zero())
}

/// The operation that defines `value`, if an instruction does.
fn defining(function: &Function, value: Value) -> Option<&Op> {
    match function.value(value)?.definition {
        Definition::Result { inst, .. } => function.inst(inst).map(|inst| &inst.op),
        Definition::Parameter { .. } => None,
    }
}

/// The low `width` bits of `value`, with what keeps their being zero seen
/// through: extensions (of a value of `width` bits or fewer, all of it),
/// extractions from bit 0, and `a & a`, `a | a` of two values whose low
/// `width` bits are the same.
fn key(function: &Function, value: Value, width: u16) -> Key {
    let width_of = |v: Value| bits(function, v).unwrap_or(0);
    let Some(op) = defining(function, value) else {
        return (value, width);
    };
    match *op {
        Op::Extend { value: inner, .. } => key(function, inner, width.min(width_of(inner))),
        Op::Extract {
            value: inner,
            offset: 0,
            width: taken,
        } => key(function, inner, width.min(taken)),
        Op::Binary(Binary::And | Binary::Or, a, b) => {
            let (ka, kb) = (key(function, a, width), key(function, b, width));
            if ka == kb { ka } else { (value, width) }
        }
        Op::Const(_)
        | Op::Undefined(..)
        | Op::Unary(..)
        | Op::Binary(..)
        | Op::Flag(..)
        | Op::Extract { .. }
        | Op::Concat { .. }
        | Op::Select { .. }
        | Op::Lanes { .. }
        | Op::Float { .. }
        | Op::Load { .. }
        | Op::Store { .. }
        | Op::Intrinsic { .. }
        | Op::Call { .. }
        | Op::SystemCall { .. }
        | Op::Landing { .. } => (value, width),
    }
}
