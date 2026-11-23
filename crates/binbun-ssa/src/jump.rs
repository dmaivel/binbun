//! Where a computed jump can go, when it reads a table: the guard that
//! bounds the index, then the jump's address computed for every index in
//! the bound, reading the table from memory known before the program runs.
//!
//! 1. Guards: walking up the dominators from the jump, a branch whose one
//!    side leads to the jump (that side's block has no other way in) tells
//!    a condition that holds there; read as a comparison
//!    ([`condition::comparison`]) of a value `y` with a constant, it bounds
//!    `y` (`y <= N` unsigned: `0..=N`; `y == N`: `N`).
//! 2. The address is computed for each `y` in the bound, nearest guard
//!    first, with `y` put in wherever the same value occurs (the same
//!    operation on the same operands, through stack slots: a switch index
//!    spilled and reloaded, or loaded twice with nothing stored between,
//!    is the same value), constants from
//!    [`constant`](crate::constant), table entries from [`ReadOnly`]
//!    memory. If any address depends on something else, the guard does not
//!    bound this jump.
//! 3. No guard: if the address of a table read depends on a narrow value
//!    zero-extended (`movzx ecx, byte [..]`, `ldrb w0, [..]`: an enum's
//!    discriminant, whose range the compiler knew from its type), its
//!    width bounds it. The table is
//!    rarely that long: its entries are computed until one cannot be, and
//!    the caller must decide where the table ends ([`Bound::Width`]), from
//!    where each entry was read ([`Entry::reads`]).
//! 4. Neither: no targets.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{self, Value as Bitvalue};
use binbun_semantics::ir::Binary;

use crate::condition::{self, Relation, defining};
use crate::constant::{Constants, ReadOnly};
use crate::graph::{self, Dominators};
use crate::ir::{BlockId, Function, Op, Terminator, Type, Value};
use crate::stack::Stack;

/// What the analysis needs about the function.
#[derive(Clone, Copy, Debug)]
pub struct Facts<'a> {
    /// The function.
    pub function: &'a Function,
    /// Its constants.
    pub constants: &'a Constants,
    /// Its stack.
    pub stack: &'a Stack,
}

/// What bounds a table's index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    /// A branch the jump is only reached through: the entries are those
    /// the jump can take.
    Guard,
    /// Only the index's width: the entries run past the table's end into
    /// whatever follows it.
    Width,
}

/// Where a computed jump goes for one value of its index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The jump's address.
    pub target: u64,
    /// The addresses of the memory reads it was computed from, in the
    /// order evaluation made them (the same order for every entry).
    pub reads: Vec<u64>,
}

/// Where a computed jump goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    /// An entry for each value of the index, in order.
    pub entries: Vec<Entry>,
    /// What bounds the index.
    pub bound: Bound,
}

/// The table of the computed jump ending `block`, if a guard bounds its
/// index or its width does, to at most `limit` values; `None` if not
/// known.
pub fn targets(
    facts: Facts<'_>,
    memory: &dyn ReadOnly,
    block: BlockId,
    limit: u64,
) -> Option<Table> {
    let function = facts.function;
    let Terminator::IndirectJump { address, .. } = function.block(block)?.terminator else {
        return None;
    };
    let dominators = Dominators::new(function);
    let predecessors = graph::predecessors(function);
    let mut child = block;
    while let Some(parent) = dominators.parent(child) {
        let alone = predecessors
            .get(child.0 as usize)
            .is_some_and(|list| list.len() == 1);
        if let (
            true,
            Some(Terminator::Branch {
                condition,
                then,
                otherwise,
            }),
        ) = (alone, function.block(parent).map(|b| &b.terminator))
            && then.block != otherwise.block
            && let Some(comparison) = condition::comparison(function, facts.constants, *condition)
        {
            let holds = then.block == child;
            let comparison = if holds {
                comparison
            } else {
                comparison.negate()
            };
            if let Some((index, low, high)) = bound(facts.constants, comparison)
                && high.checked_sub(low).is_some_and(|span| span < limit)
                && let Some(entries) = evaluate_all(facts, memory, address, index, low, high)
            {
                return Some(Table {
                    entries,
                    bound: Bound::Guard,
                });
            }
        }
        child = parent;
    }
    let (index, high) = narrow(facts, address, limit)?;
    let entries = evaluate_prefix(facts, memory, address, index, high);
    (!entries.is_empty()).then_some(Table {
        entries,
        bound: Bound::Width,
    })
}

/// A value `address` depends on that is zero-extended from at most
/// `limit` values, and its largest value: the nearest in a walk of
/// `address`'s operands through the arithmetic of indexing (sums, a
/// difference's first operand, products, left shifts, extensions, parts,
/// the addresses of loads, and both choices of a select: AArch64 clears a
/// branch target's top byte unless bit 55 is set), so that entries are
/// read at addresses that grow with it. Only a value inside a load's
/// address is one: a narrow value the walk meets before any load is the
/// entry read (an offset table's byte, `ldrb w2, [x1, w0, uxtw]`), not
/// what chooses it.
fn narrow(facts: Facts<'_>, address: Value, limit: u64) -> Option<(Value, u64)> {
    let function = facts.function;
    // Each value with its depth and whether it is inside a load's address.
    let mut work = vec![(address, 0, false)];
    let mut seen = BTreeSet::new();
    while let Some((value, depth, read)) = work.pop() {
        let value = facts.stack.resolve(function, value);
        if depth > DEPTH || !seen.insert((value, read)) {
            continue;
        }
        let Some(op) = defining(function, value) else {
            continue;
        };
        if read
            && let &Op::Extend {
                signed: false,
                value: inner,
                ..
            } = op
            && let Some(Type::Bits(width)) = function.ty(inner)
            && let Some(high) = 1u64.checked_shl(u32::from(width)).map(|n| n - 1)
            && high < limit
            && facts.constants.constant(inner).is_none()
        {
            return Some((inner, high));
        }
        let next: &[Value] = match op {
            Op::Binary(Binary::Add | Binary::Mul | Binary::Shl, a, b) => &[*a, *b],
            Op::Select {
                then, otherwise, ..
            } => &[*then, *otherwise],
            Op::Binary(Binary::Sub, a, _)
            | Op::Extend { value: a, .. }
            | Op::Extract { value: a, .. } => &[*a],
            Op::Load { address: a, .. } => {
                work.push((*a, depth + 1, true));
                continue;
            }
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Concat { .. }
            | Op::Lanes { .. }
            | Op::Float { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => &[],
        };
        work.extend(next.iter().map(|&operand| (operand, depth + 1, read)));
    }
    None
}

/// The value a comparison with a constant bounds, and its bounds
/// (unsigned, inclusive).
fn bound(constants: &Constants, comparison: condition::Comparison) -> Option<(Value, u64, u64)> {
    let (relation, value, constant) = match (
        constants.constant(comparison.left),
        constants.constant(comparison.right),
    ) {
        (None, Some(n)) => (comparison.relation, comparison.left, n),
        (Some(n), None) => (comparison.relation.swap(), comparison.right, n),
        (Some(_), Some(_)) | (None, None) => return None,
    };
    let n = constant.low_u64();
    match relation {
        Relation::ULe => Some((value, 0, n)),
        Relation::ULt => Some((value, 0, n.checked_sub(1)?)),
        Relation::Eq => Some((value, n, n)),
        Relation::Ne
        | Relation::UGt
        | Relation::UGe
        | Relation::SLt
        | Relation::SLe
        | Relation::SGt
        | Relation::SGe => None,
    }
}

/// `address` for every `index` from `low` to `high`, in order; `None` if
/// one cannot be computed.
fn evaluate_all(
    facts: Facts<'_>,
    memory: &dyn ReadOnly,
    address: Value,
    index: Value,
    low: u64,
    high: u64,
) -> Option<Vec<Entry>> {
    let width = match facts.function.ty(index)? {
        Type::Bits(width) => width,
        Type::Memory => return None,
    };
    (low..=high)
        .map(|i| evaluate(facts, memory, address, index, Bits::from_u64(width, i)))
        .collect()
}

/// `address` for `index` from 0 up to `high`, until one cannot be
/// computed.
fn evaluate_prefix(
    facts: Facts<'_>,
    memory: &dyn ReadOnly,
    address: Value,
    index: Value,
    high: u64,
) -> Vec<Entry> {
    let Some(Type::Bits(width)) = facts.function.ty(index) else {
        return Vec::new();
    };
    (0..=high)
        .map_while(|i| evaluate(facts, memory, address, index, Bits::from_u64(width, i)))
        .collect()
}

/// `address` with `index` set to `value`.
fn evaluate(
    facts: Facts<'_>,
    memory: &dyn ReadOnly,
    address: Value,
    index: Value,
    value: Bits,
) -> Option<Entry> {
    let mut evaluator = Evaluator {
        facts,
        memory,
        index,
        value,
        known: BTreeMap::new(),
        reads: Vec::new(),
    };
    let target = evaluator.evaluate(address, 0)?.low_u64();
    Some(Entry {
        target,
        reads: evaluator.reads,
    })
}

/// Evaluates values with the index set.
struct Evaluator<'a> {
    facts: Facts<'a>,
    memory: &'a dyn ReadOnly,
    index: Value,
    value: Bits,
    known: BTreeMap<Value, Option<Bits>>,
    /// The addresses read so far.
    reads: Vec<u64>,
}

/// How deep evaluation and comparison go.
const DEPTH: u32 = 64;

impl Evaluator<'_> {
    fn evaluate(&mut self, value: Value, depth: u32) -> Option<Bits> {
        if depth > DEPTH {
            return None;
        }
        if let Some(&known) = self.known.get(&value) {
            return known;
        }
        let result = self.compute(value, depth);
        self.known.insert(value, result);
        result
    }

    fn compute(&mut self, value: Value, depth: u32) -> Option<Bits> {
        let facts = self.facts;
        if equivalent(facts, value, self.index, 0) {
            return Some(self.value);
        }
        if let Some(bits) = facts.constants.constant(value) {
            return Some(bits);
        }
        let resolved = facts.stack.resolve(facts.function, value);
        if resolved != value {
            return self.evaluate(resolved, depth + 1);
        }
        let op = defining(facts.function, value)?.clone();
        let mut operands = Vec::new();
        if let Op::Load { address, bytes, .. } = op {
            let address = self.evaluate(address, depth + 1)?.low_u64();
            self.reads.push(address);
            return self.memory.read(address, bytes);
        }
        if let Op::Select {
            condition,
            then,
            otherwise,
        } = op
        {
            let condition = self.evaluate(condition, depth + 1)?;
            let arm = if condition.is_zero() { otherwise } else { then };
            return self.evaluate(arm, depth + 1);
        }
        for operand in op.operands() {
            operands.push(Bitvalue::defined(self.evaluate(operand, depth + 1)?));
        }
        let result = match (op, operands.as_slice()) {
            (Op::Unary(unary, _), [a]) => interpret::unary(unary, *a),
            (Op::Binary(binary, ..), [a, b]) => interpret::binary(binary, *a, *b),
            (Op::Flag(flag, ..), [a, b, c]) => interpret::flag(flag, *a, *b, *c),
            (Op::Extract { offset, width, .. }, [a]) => interpret::extract(*a, offset, width),
            (Op::Concat { .. }, [high, low]) => interpret::concat(*high, *low),
            (Op::Extend { signed, width, .. }, [a]) => interpret::extend(signed, *a, width),
            (Op::Lanes { lanes, op, .. }, values) => interpret::lanes(op, lanes, values),
            (
                Op::Float {
                    op,
                    format,
                    lanes,
                    output,
                    ..
                },
                [rounding, values @ ..],
            ) => interpret::float(op, format, lanes, output, *rounding, values),
            (
                Op::Const(_)
                | Op::Undefined(..)
                | Op::Unary(..)
                | Op::Binary(..)
                | Op::Flag(..)
                | Op::Extract { .. }
                | Op::Concat { .. }
                | Op::Extend { .. }
                | Op::Select { .. }
                | Op::Float { .. }
                | Op::Load { .. }
                | Op::Store { .. }
                | Op::Intrinsic { .. }
                | Op::Call { .. }
                | Op::SystemCall { .. }
                | Op::Landing { .. },
                _,
            ) => return None,
        };
        result.known()
    }
}

/// Whether `a` and `b` are the same value: equal after following stack
/// slots, or the same pure operation on the same operands (a load being
/// pure for this: two loads of one memory, with nothing stored between,
/// from one address read the same).
fn equivalent(facts: Facts<'_>, a: Value, b: Value, depth: u32) -> bool {
    let function = facts.function;
    let a = plain(facts, a);
    let b = plain(facts, b);
    if a == b {
        return true;
    }
    if depth > DEPTH {
        return false;
    }
    let (Some(x), Some(y)) = (defining(function, a), defining(function, b)) else {
        return false;
    };
    let pure = |op: &Op| {
        matches!(
            op,
            Op::Const(_)
                | Op::Unary(..)
                | Op::Binary(..)
                | Op::Flag(..)
                | Op::Extract { .. }
                | Op::Concat { .. }
                | Op::Extend { .. }
                | Op::Select { .. }
                | Op::Load { .. }
        )
    };
    if !pure(x) || !pure(y) || shape(x) != shape(y) {
        return false;
    }
    x.operands()
        .into_iter()
        .zip(y.operands())
        .all(|(p, q)| equivalent(facts, p, q, depth + 1))
}

/// `value` with stack slots followed and views of a value at its own width
/// removed: the low bits of an extension back to the original width (x86:
/// `cmp eax` after a 32-bit write to `rax`) are the original value.
fn plain(facts: Facts<'_>, value: Value) -> Value {
    let function = facts.function;
    let mut value = facts.stack.resolve(function, value);
    for _ in 0..DEPTH {
        let Some(&Op::Extract {
            value: inner,
            offset: 0,
            width,
        }) = defining(function, value)
        else {
            break;
        };
        let Some(&Op::Extend {
            value: original, ..
        }) = defining(function, inner)
        else {
            break;
        };
        if function.ty(original) != Some(Type::Bits(width)) {
            break;
        }
        value = facts.stack.resolve(function, original);
    }
    value
}

/// `op` with its operands blanked: equal shapes differ only in operands.
fn shape(op: &Op) -> Op {
    let mut shape = op.clone();
    shape.map_values(&mut |_| Value(0));
    shape
}
