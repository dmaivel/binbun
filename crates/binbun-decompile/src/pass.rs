//! L2 under the pass manager ([`binbun_semantics::core::pass`]): the environment its
//! passes run in ([`L2Env`]), a function's size (what fuel is measured
//! in) and the verifier the manager runs after each change (binbun-ast's).
//!
//! The passes: [`Structure`](crate::structure::Structure), the
//! simplifications of [`crate::simplify`],
//! [`ShortCircuit`](crate::structure::ShortCircuit) and
//! [`Loops`](crate::structure::Loops). The one L2 analysis,
//! [`Ranges`](crate::range::Ranges) (counted loops, values whose
//! signedness is free), is read by the loop rules and `signs`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use binbun_ast::ir::Function;
use binbun_ast::verify;
use binbun_semantics::Declarations;
use binbun_ssa::ir::{Definition, Function as L1, InstId, Op, Terminator, Type, Value};

use crate::itanium::Exceptions;

/// What L2 passes know beyond the function.
#[derive(Clone, Copy, Debug)]
pub struct L2Env<'a> {
    /// The architecture's registers and intrinsics.
    pub declarations: &'a Declarations,
    /// The program's exceptions: the landing pads' clauses and how
    /// unwinding resumes ([`crate::itanium::NONE`] where none are known).
    pub exceptions: &'a Exceptions,
    /// Which instructions of the L1 function read each of its values, for
    /// provenance alone (none: a function built without one).
    pub feeds: Option<&'a Feeds<'a>>,
}

/// Which machine instructions read each value of an L1 function: where
/// what an L2 node stood for went, when a pass removes the node
/// ([`Prune`](crate::simplify::Prune) gives a dead assignment's
/// instructions to the nodes standing for its readers). Provenance
/// alone reads it: no pass decides anything by it. A value is read by
/// the operations taking it as an operand, and by the branch on it or
/// the jump to it; not by the register states of calls, system calls,
/// returns and exits (every register's value, most of which they do not
/// read: a register the epilogue restores, what a call leaves behind).
#[derive(Clone, Debug)]
pub struct Feeds<'a> {
    l1: &'a L1,
    /// Per value, where its readers start in `readers` (one more: their
    /// end).
    starts: Vec<u32>,
    /// Each value's readers, in value order.
    readers: Vec<Reader>,
}

/// What reads a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reader {
    /// An instruction, as an operand.
    Inst(InstId),
    /// The terminator of a block (its condition, its computed address,
    /// the state it returns or leaves with), at this machine instruction.
    End(u64),
}

/// How many values [`Feeds::readers`] follows within one instruction.
const WITHIN: usize = 64;

impl<'a> Feeds<'a> {
    /// The readers of the values of `l1`.
    pub fn new(l1: &'a L1) -> Self {
        let bits = |v: &Value| matches!(l1.ty(*v), Some(Type::Bits(_)));
        let mut pairs: Vec<(Value, Reader)> = Vec::new();
        for (index, inst) in l1.insts.iter().enumerate() {
            let id = InstId(u32::try_from(index).unwrap_or(u32::MAX));
            let read = match &inst.op {
                Op::Call { target, .. } => Vec::from([*target]),
                Op::SystemCall { .. } | Op::Landing { .. } => Vec::new(),
                op @ (Op::Const(_)
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
                | Op::Intrinsic { .. }) => op.operands(),
            };
            pairs.extend(read.into_iter().filter(bits).map(|v| (v, Reader::Inst(id))));
        }
        for block in &l1.blocks {
            let read = match &block.terminator {
                Terminator::Branch { condition, .. } => Some(*condition),
                Terminator::IndirectJump { address, .. } => Some(*address),
                Terminator::Jump(_)
                | Terminator::Return { .. }
                | Terminator::Leave { .. }
                | Terminator::Trap(_)
                | Terminator::Stop
                | Terminator::Invoke { .. }
                | Terminator::Open => None,
            };
            pairs.extend(read.filter(bits).map(|v| (v, Reader::End(block.end))));
        }
        pairs.sort_by_key(|&(v, _)| v);
        let mut starts = Vec::with_capacity(l1.values.len() + 1);
        let mut at = 0;
        for index in 0..=l1.values.len() {
            while pairs.get(at).is_some_and(|&(v, _)| (v.0 as usize) < index) {
                at += 1;
            }
            starts.push(u32::try_from(at).unwrap_or(u32::MAX));
        }
        Self {
            l1,
            starts,
            readers: pairs.into_iter().map(|(_, reader)| reader).collect(),
        }
    }

    /// The machine instructions reading `v`, sorted, each once: those of
    /// its readers, but the instruction defining it (whose other results
    /// it feeds: their readers instead).
    pub fn readers(&self, v: Value) -> Vec<u64> {
        let l1 = self.l1;
        let mut out = Vec::new();
        let mut seen = Vec::from([v]);
        let mut work = Vec::from([v]);
        while let Some(u) = work.pop() {
            let defined = match l1.value(u).map(|info| info.definition) {
                Some(Definition::Result { inst, .. }) => l1.inst(inst).map(|i| i.address),
                Some(Definition::Parameter { .. }) | None => None,
            };
            let start = self.starts.get(u.0 as usize).copied().unwrap_or(0) as usize;
            let end = self.starts.get(u.0 as usize + 1).copied().unwrap_or(0) as usize;
            for &reader in self.readers.get(start..end).unwrap_or_default() {
                match reader {
                    Reader::End(address) => out.push(address),
                    Reader::Inst(id) => {
                        let Some(inst) = l1.inst(id) else {
                            continue;
                        };
                        if Some(inst.address) != defined {
                            out.push(inst.address);
                            continue;
                        }
                        for &result in &inst.results {
                            if seen.len() < WITHIN && !seen.contains(&result) {
                                seen.push(result);
                                work.push(result);
                            }
                        }
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// `function`'s size: its statements and expressions (each L2 pass spends
/// a unit of fuel per node).
pub fn size(function: &Function) -> u64 {
    let nodes = function.stmts.len().saturating_add(function.exprs.len());
    u64::try_from(nodes).unwrap_or(u64::MAX)
}

/// binbun-ast's verifier ([`verify::verify`]) as the manager runs it.
///
/// # Errors
///
/// The first broken rule, as text.
pub fn verify(function: &Function, env: &L2Env<'_>) -> Result<(), String> {
    verify::verify(function, env.declarations).map_err(|error| error.to_string())
}
