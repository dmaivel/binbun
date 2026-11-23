//! The control flow of an L2 function equals its L1's CFG.
//!
//! L2's graph ([`Graph`]) gives, by the `Origin::Block` of its
//! statements and decisions, where control enters each L1 block's code and
//! where it goes from there ([`Graph::flow`]: through the block's code and
//! at most one decision of its own, `&&` and `||` split into one decision
//! per block as C evaluates them). Over the blocks reached from the start:
//! the start is L1's entry, the blocks are L1's blocks reached from it,
//! and each entry into a block goes where L1's block goes (L1 blocks,
//! "exit" for a return, a leave, a trap, a stop, and the unknown targets
//! of a computed jump): to each of its successors, and nowhere else. A
//! block may be entered at more than one place (a loop's code entered at
//! its top and after its decision; an exit copied at each `goto` to it,
//! [`crate::structure::Exits`]): each entry is checked against all of the
//! block's successors, so L2's entries unfold L1's CFG, every path of one
//! a path of the other.
//!
//! One contraction, on L1's side only, per entry: a block that ends in a
//! jump and has no node in L2 where control goes from an entry (no
//! statement or decision stands for it there: its code all folded away or
//! none, and no copies on its edge) is replaced, as a successor, by its
//! jump's target (a loop of such blocks by "spin", as L2 has a loop of
//! joins alone): an entry may go to the block or, past it, to where it
//! jumps. This cannot hide a wrong edge: such a block does nothing but go
//! to its one target, so L1 going through it and L2 going straight to the
//! target are the same flow (what its code computes is the differential
//! check's); a block ending otherwise (a branch, a return…) must be in
//! L2; and an edge of L2 to anything but the block or the target is still
//! L1's or not. A block with a node in one copy of an exit may have none
//! in another, where simplification folded its code into its neighbours'.
//! Likewise a block that ends in a branch both of whose ways go, through
//! such blocks alone, to one same block, and has no node in L2 (the
//! `if` had nothing in either arm, and structuring dropped it:
//! [`crate::structure`]): it too does nothing but go to that one place,
//! whichever way its condition says.
//!
//! Exceptions: an invoke goes to its normal and its unwind targets; one
//! whose call resumes unwinding ([`Exceptions::resume`], which never
//! returns) only to its unwind target, as L2's graph has it. A block a
//! `Try`'s dispatch absorbed ([`Graph::absorbed`]: a landing pad's
//! selector test, which L2 says as the choice among the handlers) has no
//! node in L2 and is contracted through all its targets: this cannot hide
//! a wrong edge either, since the dispatch must then go to each of them.
//! An absorbed block whose call resumes unwinding (which the language
//! does implicitly) is contracted to where the exception goes: its unwind
//! target, else the exit.
//! So is a block L2 keeps (other code reaches it) that a dispatch's
//! decision leads to and that does nothing but resume unwinding: the
//! compiler shared the pad's resume with a cleanup's, and the dispatch
//! going there is the exception propagating.
//!
//! `va_start` ([`Stmt::VaStart`](binbun_ast::ir::Stmt::VaStart)) absorbs
//! the prologue's spill of the vector argument registers: the branch on
//! the caller's count of them and the blocks of the spill, contracted
//! through all their targets as a dispatch's are, but for the blocks
//! that trap on a misaligned save area (lowering proves the ABI's stack
//! alignment rules them out), which are contracted to nothing.
//!
//! Which way a decision goes (`then` or `else`) is not compared: a
//! condition may be negated by structuring; the differential check
//! catches a swapped branch.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::Function as Ast;
use binbun_ssa::ir::{BlockId, Definition, Function, Op, Terminator, Value};

use super::Mismatch;
use super::graph::{Graph, Successor};
use crate::itanium::Exceptions;

/// Checks that `l2`'s control flow is `l1`'s CFG, block by block, through
/// the blocks of its provenance; `exceptions` say which calls resume
/// unwinding.
///
/// # Errors
///
/// The first difference: L2's graph cannot be built, the start differs,
/// the blocks reached differ, or a block's successors differ.
pub fn structure(l1: &Function, l2: &Ast, exceptions: &Exceptions) -> Result<(), Mismatch> {
    let fail = |message| Mismatch {
        block: None,
        message,
    };
    let graph = Graph::of(l2, exceptions).map_err(fail)?;
    let flow = graph.flow().map_err(fail)?;
    let present = graph.blocks();
    let expected = L1 {
        function: l1,
        present: &present,
        absorbed: &graph.absorbed,
        exceptions,
    };
    let start = expected.contract(BlockId(0))?;
    let [start] = &start[..] else {
        return Err(fail("L1's start is not one block".to_string()));
    };
    if !start.contains(&flow.start) {
        return Err(fail(format!(
            "L2 starts at {} where L1 starts at {}",
            describe(flow.start),
            describe_any(start)
        )));
    }
    let expected = expected.successors(start)?;
    for region in &flow.regions {
        let Some(own) = expected.get(&region.block) else {
            return Err(Mismatch {
                block: Some(region.block),
                message: "reached in L2, not in L1".to_string(),
            });
        };
        if let Some(extra) = region
            .successors
            .iter()
            .find(|&successor| !own.iter().any(|ways| ways.contains(successor)))
        {
            return Err(Mismatch {
                block: Some(region.block),
                message: format!("L2 goes to {} where L1 does not", describe(*extra)),
            });
        }
        if let Some(missing) = own
            .iter()
            .find(|ways| ways.is_disjoint(&region.successors) && ways.is_disjoint(&region.optional))
        {
            return Err(Mismatch {
                block: Some(region.block),
                message: format!(
                    "L1 goes to {} where L2 does not from node {}",
                    describe_any(missing),
                    region.entry.0
                ),
            });
        }
    }
    let found = flow.blocks();
    if let Some(block) = expected.keys().find(|block| !found.contains_key(block)) {
        return Err(Mismatch {
            block: Some(*block),
            message: "reached in L1, not in L2".to_string(),
        });
    }
    Ok(())
}

fn describe(successor: Successor) -> String {
    match successor {
        Successor::Block(block) => format!("block {}", block.0),
        Successor::Exit => "the exit".to_string(),
        Successor::Spin => "a loop of no block".to_string(),
    }
}

/// One of `ways`, which an entry may go to for one L1 successor.
fn describe_any(ways: &BTreeSet<Successor>) -> String {
    let mut text = String::new();
    for (index, &way) in ways.iter().enumerate() {
        if index > 0 {
            text.push_str(" or ");
        }
        text.push_str(&describe(way));
    }
    text
}

/// How many blocks that only jump [`L1::meet`] follows each way.
const MEET: usize = 64;

/// How many branches with no node in L2 [`L1::meet`] goes through, one
/// inside the other.
const NESTED: usize = 4;

/// L1's CFG, the blocks L2 has no node of that only jump contracted.
struct L1<'a> {
    function: &'a Function,
    present: &'a BTreeSet<BlockId>,
    /// Blocks a `Try`'s dispatch stands for: contracted through all their
    /// targets.
    absorbed: &'a BTreeSet<BlockId>,
    exceptions: &'a Exceptions,
}

impl L1<'_> {
    fn terminator(&self, id: BlockId) -> Result<&Terminator, Mismatch> {
        self.function
            .block(id)
            .map(|block| &block.terminator)
            .ok_or_else(|| Mismatch {
                block: Some(id),
                message: "not in L1".to_string(),
            })
    }

    /// Where control going to `block` really goes: past the blocks that
    /// only jump and that L2 has no node of, and through every target of
    /// those a dispatch absorbed. One set per place it goes, of the ways
    /// an entry into L2 may go there: a block that only jumps and has a
    /// node, or past it (where that entry has none) its target.
    fn contract(&self, block: BlockId) -> Result<Vec<BTreeSet<Successor>>, Mismatch> {
        let mut found = Vec::new();
        // The absorbed branches gone through (each once).
        let mut branches = BTreeSet::new();
        // Each start, and whether a dispatch's decision leads there.
        let mut work = vec![(block, false)];
        while let Some((start, decided)) = work.pop() {
            // A chain of blocks that only jump; `ways` holds those of it
            // L2 has a node of, where an entry may go instead of past them.
            let mut at = start;
            let mut passed = BTreeSet::new();
            let mut ways = BTreeSet::new();
            loop {
                let terminator = self.terminator(at)?;
                if !ways.is_empty() && passed.contains(&at) {
                    ways.insert(Successor::Spin);
                    break;
                }
                if self.present.contains(&at) {
                    match terminator {
                        // A resume the dispatch shares with other code:
                        // going there propagates the exception.
                        Terminator::Stop if ways.is_empty() && decided && self.only_resumes(at) => {
                            ways.insert(Successor::Exit);
                        }
                        Terminator::Invoke { unwind, .. }
                            if ways.is_empty() && decided && self.only_resumes(at) =>
                        {
                            work.push((unwind.block, false));
                        }
                        Terminator::Jump(target) => {
                            ways.insert(Successor::Block(at));
                            passed.insert(at);
                            at = target.block;
                            continue;
                        }
                        Terminator::Branch { .. }
                        | Terminator::Invoke { .. }
                        | Terminator::IndirectJump { .. }
                        | Terminator::Return { .. }
                        | Terminator::Leave { .. }
                        | Terminator::Trap(_)
                        | Terminator::Stop
                        | Terminator::Open => {
                            ways.insert(Successor::Block(at));
                        }
                    }
                    break;
                }
                if let Some(next) = self.passes_on(at, terminator) {
                    if !passed.insert(at) {
                        ways.insert(Successor::Spin);
                        break;
                    }
                    at = next;
                    continue;
                }
                match terminator {
                    // Past a block L2 has a node of, only a plain chain:
                    // an entry going past it goes to one block.
                    Terminator::Branch { .. }
                    | Terminator::Invoke { .. }
                    | Terminator::Stop
                    | Terminator::Trap(_)
                        if !ways.is_empty() && self.absorbed.contains(&at) =>
                    {
                        break;
                    }
                    Terminator::Branch { .. } if self.absorbed.contains(&at) => {
                        if branches.insert(at) {
                            work.extend(terminator.targets().map(|target| (target.block, true)));
                        }
                        break;
                    }
                    Terminator::Invoke { unwind, .. }
                        if self.absorbed.contains(&at) && self.resumes(at) =>
                    {
                        if branches.insert(at) {
                            work.push((unwind.block, false));
                        }
                        break;
                    }
                    Terminator::Stop if self.absorbed.contains(&at) && self.resumes(at) => {
                        ways.insert(Successor::Exit);
                        break;
                    }
                    Terminator::Trap(_) if self.absorbed.contains(&at) => break,
                    Terminator::Jump(_)
                    | Terminator::Branch { .. }
                    | Terminator::Invoke { .. }
                    | Terminator::IndirectJump { .. }
                    | Terminator::Return { .. }
                    | Terminator::Leave { .. }
                    | Terminator::Trap(_)
                    | Terminator::Stop
                    | Terminator::Open => {
                        ways.insert(Successor::Block(at));
                        break;
                    }
                }
            }
            if !ways.is_empty() {
                found.push(ways);
            }
        }
        found.sort();
        found.dedup();
        Ok(found)
    }

    /// Where block `at`, which L2 has no node of and which ends in
    /// `terminator`, sends control if it does nothing but pass it on: its
    /// jump's target; of a branch no dispatch absorbed, the block both
    /// its ways come to ([`Self::meet`]: a decision L2 may have dropped).
    fn passes_on(&self, at: BlockId, terminator: &Terminator) -> Option<BlockId> {
        match terminator {
            Terminator::Jump(target) => Some(target.block),
            Terminator::Branch {
                then, otherwise, ..
            } if !self.absorbed.contains(&at) => self.meet(then.block, otherwise.block, NESTED),
            Terminator::Branch { .. }
            | Terminator::Invoke { .. }
            | Terminator::IndirectJump { .. }
            | Terminator::Return { .. }
            | Terminator::Leave { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => None,
        }
    }

    /// The first block control going to `a` and control going to `b`
    /// both come to through blocks that only jump (at most [`MEET`] each;
    /// one L2 has a node of elsewhere may have none on this way: an
    /// entry with code of one of them on one way only is no `if` with
    /// two empty arms) and branches with no node in L2 whose own ways
    /// meet (`if (a && b) {}` is two, `depth` deep at most), if they do.
    fn meet(&self, a: BlockId, b: BlockId, depth: usize) -> Option<BlockId> {
        let chain = |start: BlockId| {
            let mut blocks = vec![start];
            let mut at = start;
            for _ in 0..MEET {
                let next = match self.function.block(at).map(|block| &block.terminator) {
                    Some(Terminator::Jump(target)) => Some(target.block),
                    Some(Terminator::Branch {
                        then, otherwise, ..
                    }) if depth > 0 && !self.present.contains(&at) => {
                        self.meet(then.block, otherwise.block, depth - 1)
                    }
                    Some(_) | None => None,
                };
                match next {
                    Some(next) if !blocks.contains(&next) => {
                        at = next;
                        blocks.push(at);
                    }
                    Some(_) | None => break,
                }
            }
            blocks
        };
        let other = chain(b);
        chain(a).into_iter().find(|block| other.contains(block))
    }

    /// Whether block `id`'s last call (what follows it computes the
    /// state after it) calls a function that resumes unwinding (it never
    /// returns).
    fn resumes(&self, id: BlockId) -> bool {
        self.last_call(id)
            .is_some_and(|target| self.resume_target(target))
    }

    /// Whether block `id`'s last call calls a function that never throws
    /// (a constant address of [`Exceptions::nothrow`]).
    fn never_throws(&self, id: BlockId) -> bool {
        self.last_call(id)
            .and_then(|target| self.constant(target))
            .is_some_and(|address| self.exceptions.nothrow.contains(&address))
    }

    /// Whether block `id` does nothing but resume unwinding: computes
    /// values (no memory access, no other call) for one call, which
    /// resumes.
    fn only_resumes(&self, id: BlockId) -> bool {
        let l1 = self.function;
        let Some(block) = l1.block(id) else {
            return false;
        };
        let mut calls = 0;
        for inst in block.insts.iter().filter_map(|&inst| l1.inst(inst)) {
            match inst.op {
                Op::Call { target, .. } if self.resume_target(target) => calls += 1,
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
                | Op::Float { .. } => {}
                Op::Call { .. }
                | Op::Load { .. }
                | Op::Store { .. }
                | Op::Intrinsic { .. }
                | Op::SystemCall { .. }
                | Op::Landing { .. } => return false,
            }
        }
        calls == 1
    }

    /// The target of block `id`'s last call, if it has one.
    fn last_call(&self, id: BlockId) -> Option<Value> {
        let l1 = self.function;
        l1.block(id)
            .into_iter()
            .flat_map(|block| block.insts.iter().rev())
            .filter_map(|&inst| l1.inst(inst))
            .find_map(|inst| match inst.op {
                Op::Call { target, .. } => Some(target),
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
                | Op::SystemCall { .. }
                | Op::Landing { .. } => None,
            })
    }

    /// Whether a call to `target` resumes unwinding: a constant address
    /// of [`Exceptions::resume`].
    fn resume_target(&self, target: Value) -> bool {
        self.constant(target)
            .is_some_and(|address| self.exceptions.resume.contains(&address))
    }

    /// The address `target` is, if a constant.
    fn constant(&self, target: Value) -> Option<u64> {
        let l1 = self.function;
        let inst = match l1.value(target)?.definition {
            Definition::Result { inst, .. } => l1.inst(inst)?,
            Definition::Parameter { .. } => return None,
        };
        let Op::Const(bits) = inst.op else {
            return None;
        };
        Some(bits.low_u64())
    }

    /// The successors of each block reached from `start` (any of its
    /// ways), as [`L1::contract`] gives them.
    fn successors(
        &self,
        start: &BTreeSet<Successor>,
    ) -> Result<BTreeMap<BlockId, Vec<BTreeSet<Successor>>>, Mismatch> {
        let mut successors = BTreeMap::new();
        let mut work: Vec<BlockId> = start
            .iter()
            .filter_map(|successor| match successor {
                Successor::Block(block) => Some(*block),
                Successor::Exit | Successor::Spin => None,
            })
            .collect();
        while let Some(id) = work.pop() {
            if successors.contains_key(&id) {
                continue;
            }
            let terminator = self.terminator(id)?;
            let mut own = Vec::new();
            for (index, target) in terminator.targets().enumerate() {
                // A call that resumes unwinding never returns.
                if index == 0 && matches!(terminator, Terminator::Invoke { .. }) && self.resumes(id)
                {
                    continue;
                }
                // A call of a function that never throws never unwinds
                // (an exception table's range may still cover it), as L2
                // has it ([`itanium::unwinds`](crate::itanium::unwinds)).
                if index == 1
                    && matches!(terminator, Terminator::Invoke { .. })
                    && self.never_throws(id)
                {
                    continue;
                }
                own.extend(self.contract(target.block)?);
            }
            match terminator {
                Terminator::IndirectJump { .. }
                | Terminator::Return { .. }
                | Terminator::Leave { .. }
                | Terminator::Trap(_)
                | Terminator::Stop => {
                    own.push(BTreeSet::from([Successor::Exit]));
                }
                Terminator::Jump(_) | Terminator::Branch { .. } | Terminator::Invoke { .. } => {}
                Terminator::Open => {
                    return Err(Mismatch {
                        block: Some(id),
                        message: "L1 block is not terminated".to_string(),
                    });
                }
            }
            work.extend(
                own.iter()
                    .flatten()
                    .filter_map(|successor| match successor {
                        Successor::Block(block) => Some(*block),
                        Successor::Exit | Successor::Spin => None,
                    }),
            );
            successors.insert(id, own);
        }
        Ok(successors)
    }
}
