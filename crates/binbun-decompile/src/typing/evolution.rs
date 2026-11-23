//! Scalar evolutions (induction variables are an input to the solver, not
//! a loop-shape rule): the block parameters of L1 that step by a constant
//! per iteration of a loop, as LLVM's SCEV's `{start, +, step}<loop>`.
//!
//! A loop is a block (its header) with back edges: predecessors it
//! dominates. A parameter of the header is an evolution where every back
//! edge passes it plus one nonzero constant `step` (`p = phi(base, p +
//! d)`, `i = phi(k, i + d)`; through sums and differences of constants,
//! at most [`CHAIN`] deep, copies seen through) and every other edge one
//! value, its `start`. After `n` iterations it is `start + step·n`: a
//! pointer stepped by `d` from `base` is `base + d·i` for the loop's
//! iteration count `i`, so accesses through it are at `base + d·i (+
//! offset)`. Linear: each parameter's incoming edges once, each chain at
//! most [`CHAIN`] steps.
//!
//! Pointer families (`family`) take each pointer evolution's step as the
//! period it gives its family rather than rediscovering it from the cycle
//! its back edge closes: the evolution is the one place a loop's step is
//! found, and the families' union-find only closes the cycles no
//! evolution explains (back edges stepping by different constants, steps
//! by an index).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use binbun_semantics::ir::Binary;
use binbun_ssa::constant::Constants;
use binbun_ssa::graph::Dominators;
use binbun_ssa::ir::{BlockId, Definition, Function, Op, Value};

/// The most sums of a constant between a back edge's argument and the
/// parameter it steps.
pub(crate) const CHAIN: usize = 8;

/// A block parameter that steps by a constant per iteration of a loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Evolution {
    /// The loop's header (the parameter's block).
    pub(crate) header: BlockId,
    /// Its value on entering the loop (canonical).
    pub(crate) start: Value,
    /// What each iteration adds.
    pub(crate) step: i64,
}

/// The evolutions of one function's block parameters (canonical values).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Evolutions {
    /// Each evolving parameter's evolution.
    by_value: BTreeMap<Value, Evolution>,
}

impl Evolutions {
    /// The evolutions of `l1`'s block parameters, by `dominators`, with
    /// `canon` each value's canonical value (copies seen through),
    /// `constants` its constants and `incoming` the arguments each block
    /// parameter (block, index) gets from each predecessor lowered.
    pub(crate) fn new(
        l1: &Function,
        dominators: &Dominators,
        canon: &[Value],
        constants: &Constants,
        incoming: impl Fn(BlockId, usize) -> Vec<(BlockId, Value)>,
    ) -> Self {
        let canonical = |v: Value| canon.get(v.0 as usize).copied().unwrap_or(v);
        let mut by_value = BTreeMap::new();
        for (index, block) in l1.blocks.iter().enumerate() {
            let header = BlockId(u32::try_from(index).unwrap_or(u32::MAX));
            if !dominators.reachable(header) {
                continue;
            }
            for (position, &parameter) in block.parameters.iter().enumerate() {
                let parameter = canonical(parameter);
                let edges = incoming(header, position);
                if let Some(evolution) = evolve(
                    l1,
                    constants,
                    &canonical,
                    header,
                    parameter,
                    |pred| dominators.dominates(header, pred),
                    &edges,
                ) {
                    by_value.insert(parameter, evolution);
                }
            }
        }
        Self { by_value }
    }

    /// `v`'s evolution, if it is an evolving block parameter (canonical).
    pub(crate) fn of(&self, v: Value) -> Option<&Evolution> {
        self.by_value.get(&v)
    }
}

/// `parameter`'s evolution in the loop headed by `header`, from its
/// incoming `edges` (`back` says which predecessors close the loop).
fn evolve(
    l1: &Function,
    constants: &Constants,
    canonical: &impl Fn(Value) -> Value,
    header: BlockId,
    parameter: Value,
    back: impl Fn(BlockId) -> bool,
    edges: &[(BlockId, Value)],
) -> Option<Evolution> {
    let mut start = None;
    let mut step = None;
    for &(pred, argument) in edges {
        if back(pred) {
            let added = stepped(l1, constants, canonical, argument, parameter)?;
            if added == 0 || step.is_some_and(|known| known != added) {
                return None;
            }
            step = Some(added);
        } else {
            let argument = canonical(argument);
            if argument == parameter || start.is_some_and(|known| known != argument) {
                return None;
            }
            start = Some(argument);
        }
    }
    Some(Evolution {
        header,
        start: start?,
        step: step?,
    })
}

/// The constant `value` adds to `parameter` (`parameter + k`, through at
/// most [`CHAIN`] sums and differences of constants), if it is one.
fn stepped(
    l1: &Function,
    constants: &Constants,
    canonical: &impl Fn(Value) -> Value,
    value: Value,
    parameter: Value,
) -> Option<i64> {
    let constant = |v: Value| {
        constants
            .constant(v)
            .filter(|bits| bits.width() <= 64)
            .map(|bits| bits.sext(64).low_u64().cast_signed())
    };
    let mut at = canonical(value);
    let mut added = 0i64;
    for _ in 0..=CHAIN {
        if at == parameter {
            return Some(added);
        }
        let Definition::Result { inst, .. } = l1.value(at)?.definition else {
            return None;
        };
        let (next, k) = match l1.inst(inst)?.op {
            Op::Binary(Binary::Add, a, b) => match (constant(a), constant(b)) {
                (_, Some(k)) => (a, k),
                (Some(k), None) => (b, k),
                (None, None) => return None,
            },
            Op::Binary(Binary::Sub, a, b) => (a, constant(b)?.wrapping_neg()),
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Lanes { .. }
            | Op::Flag(..)
            | Op::Float { .. }
            | Op::Select { .. }
            | Op::Extend { .. }
            | Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => return None,
        };
        added = added.wrapping_add(k);
        at = canonical(next);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use binbun_semantics::bits::Bits;
    use binbun_ssa::constant::{NoMemory, propagate};
    use binbun_ssa::ir::{Block, Inst, InstId, Target, Terminator, Type, ValueInfo};

    /// `p = phi(base, p + 8)` in block 1, looping on itself while
    /// `p != end`, `base` and `end` the entry's parameters.
    fn pointer_loop() -> (Function, Value) {
        let mut f = Function::default();
        let mut value = |definition| {
            let v = Value(u32::try_from(f.values.len()).unwrap());
            f.values.push(ValueInfo {
                ty: Type::Bits(64),
                definition,
            });
            v
        };
        let base = value(Definition::Parameter {
            block: BlockId(0),
            index: 0,
        });
        let end = value(Definition::Parameter {
            block: BlockId(0),
            index: 1,
        });
        let p = value(Definition::Parameter {
            block: BlockId(1),
            index: 0,
        });
        let eight = value(Definition::Result {
            inst: InstId(0),
            index: 0,
        });
        let next = value(Definition::Result {
            inst: InstId(1),
            index: 0,
        });
        let more = value(Definition::Result {
            inst: InstId(2),
            index: 0,
        });
        if let Some(info) = f.values.get_mut(more.0 as usize) {
            info.ty = Type::Bits(1);
        }
        let inst = |op, result| Inst {
            op,
            results: alloc::vec![result],
            address: 4,
        };
        f.insts = alloc::vec![
            inst(Op::Const(Bits::from_u64(64, 8)), eight),
            inst(Op::Binary(Binary::Add, p, eight), next),
            inst(Op::Binary(Binary::Ne, next, end), more),
        ];
        let to = |block: u32, arguments: Vec<Value>| Target {
            block: BlockId(block),
            arguments,
        };
        f.blocks = alloc::vec![
            Block {
                address: 0,
                end: 0,
                parameters: alloc::vec![base, end],
                insts: Vec::new(),
                terminator: Terminator::Jump(to(1, alloc::vec![base])),
            },
            Block {
                address: 4,
                end: 4,
                parameters: alloc::vec![p],
                insts: alloc::vec![InstId(0), InstId(1), InstId(2)],
                terminator: Terminator::Branch {
                    condition: more,
                    then: to(1, alloc::vec![next]),
                    otherwise: to(2, Vec::new()),
                },
            },
            Block {
                address: 8,
                end: 8,
                parameters: Vec::new(),
                insts: Vec::new(),
                terminator: Terminator::Stop,
            },
        ];
        (f, p)
    }

    #[test]
    fn a_pointer_stepped_by_eight_evolves_from_its_base() {
        let (f, p) = pointer_loop();
        let dominators = Dominators::new(&f);
        let constants = propagate(&f, &NoMemory);
        let canon: Vec<Value> = (0..f.values.len())
            .map(|index| Value(u32::try_from(index).unwrap()))
            .collect();
        let predecessors = binbun_ssa::graph::predecessors(&f);
        let incoming = |block: BlockId, index: usize| {
            predecessors
                .get(block.0 as usize)
                .into_iter()
                .flatten()
                .filter_map(|&(pred, edge)| {
                    let target = f.block(pred)?.terminator.targets().nth(edge)?;
                    Some((pred, *target.arguments.get(index)?))
                })
                .collect()
        };
        let evolutions = Evolutions::new(&f, &dominators, &canon, &constants, incoming);
        assert_eq!(
            evolutions.of(p),
            Some(&Evolution {
                header: BlockId(1),
                start: Value(0),
                step: 8,
            })
        );
        // The entry's parameters do not evolve: no back edge reaches them.
        assert_eq!(evolutions.of(Value(0)), None);
        assert_eq!(evolutions.of(Value(1)), None);
    }
}
