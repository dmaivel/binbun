//! The block graph of a [`Function`]: predecessors and dominators.

use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::core::pass::{Analyses, Analysis};

use crate::ir::{BlockId, Function};
use crate::pass::L1Env;

/// Each block's predecessors: the predecessor and the position of the edge
/// among its terminator's targets (a branch: 0 `then`, 1 `otherwise`).
pub fn predecessors(function: &Function) -> Vec<Vec<(BlockId, usize)>> {
    let mut predecessors = vec![Vec::new(); function.blocks.len()];
    for (index, block) in function.blocks.iter().enumerate() {
        let from = BlockId(u32::try_from(index).unwrap_or(u32::MAX));
        for (position, target) in block.terminator.targets().enumerate() {
            if let Some(list) = predecessors.get_mut(target.block.0 as usize) {
                list.push((from, position));
            }
        }
    }
    predecessors
}

/// The dominator tree of the blocks the entry (block 0) reaches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dominators {
    /// Each block's immediate dominator (the entry's is itself); `None`
    /// for blocks the entry does not reach.
    idom: Vec<Option<usize>>,
    /// Each reached block's place in a depth-first walk of the tree: when
    /// it is entered and when left. A block dominates another exactly
    /// when the other's walk lies within its own.
    walk: Vec<(u32, u32)>,
}

impl<'e> Analysis<Function, L1Env<'e>> for Dominators {
    fn compute(function: &Function, _: &L1Env<'e>, _: &mut Analyses<Function, L1Env<'e>>) -> Self {
        Self::new(function)
    }
}

impl Dominators {
    /// Cooper, Harvey and Kennedy's iteration ("A Simple, Fast Dominance
    /// Algorithm") over the blocks in reverse postorder.
    pub fn new(function: &Function) -> Self {
        let count = function.blocks.len();
        let successors: Vec<Vec<usize>> = function
            .blocks
            .iter()
            .map(|block| {
                block
                    .terminator
                    .targets()
                    .map(|target| target.block.0 as usize)
                    .filter(|&successor| successor < count)
                    .collect()
            })
            .collect();
        let order = reverse_postorder(&successors);
        let mut rank = vec![usize::MAX; count];
        for (position, &block) in order.iter().enumerate() {
            if let Some(slot) = rank.get_mut(block) {
                *slot = position;
            }
        }
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
        for (block, list) in successors.iter().enumerate() {
            for &successor in list {
                if let Some(slot) = predecessors.get_mut(successor) {
                    slot.push(block);
                }
            }
        }
        let mut idom: Vec<Option<usize>> = vec![None; count];
        if let Some(root) = idom.get_mut(0) {
            *root = Some(0);
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &block in order.iter().skip(1) {
                let mut new = None;
                for &predecessor in predecessors.get(block).map_or(&[][..], Vec::as_slice) {
                    if idom.get(predecessor).copied().flatten().is_none() {
                        continue;
                    }
                    new = match new {
                        None => Some(predecessor),
                        Some(other) => intersect(&idom, &rank, predecessor, other),
                    };
                }
                if let Some(slot) = idom.get_mut(block)
                    && *slot != new
                {
                    *slot = new;
                    changed = true;
                }
            }
        }
        let walk = walk(&idom);
        Self { idom, walk }
    }

    /// Whether the entry reaches `block`.
    pub fn reachable(&self, block: BlockId) -> bool {
        self.idom.get(block.0 as usize).copied().flatten().is_some()
    }

    /// `block`'s immediate dominator (none for the entry and for blocks it
    /// does not reach).
    pub fn parent(&self, block: BlockId) -> Option<BlockId> {
        let index = block.0 as usize;
        let parent = self.idom.get(index).copied().flatten()?;
        (parent != index).then(|| BlockId(u32::try_from(parent).unwrap_or(u32::MAX)))
    }

    /// Whether `a` dominates `b` (every block dominates itself).
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        if a == b {
            return true;
        }
        if !self.reachable(a) || !self.reachable(b) {
            return false;
        }
        match (self.walk.get(a.0 as usize), self.walk.get(b.0 as usize)) {
            (Some(&(a_in, a_out)), Some(&(b_in, b_out))) => a_in <= b_in && b_out <= a_out,
            _ => false,
        }
    }
}

/// Each block's entering and leaving times in a depth-first walk of the
/// dominator tree `idom` (each block's immediate dominator, the entry's
/// itself) from the entry; (0, 0) for blocks it does not reach.
fn walk(idom: &[Option<usize>]) -> Vec<(u32, u32)> {
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); idom.len()];
    for (block, parent) in idom.iter().enumerate() {
        if let Some(parent) = *parent
            && parent != block
            && let Some(list) = children.get_mut(parent)
        {
            list.push(block);
        }
    }
    let mut walk = vec![(0, 0); idom.len()];
    if idom.first().copied().flatten().is_none() {
        return walk;
    }
    let mut clock = 0u32;
    // The blocks being walked, each with how many of its children are.
    let mut stack = vec![(0usize, 0usize)];
    if let Some(slot) = walk.first_mut() {
        slot.0 = clock;
    }
    while let Some((block, next)) = stack.last_mut() {
        let block = *block;
        if let Some(&child) = children.get(block).and_then(|list| list.get(*next)) {
            *next += 1;
            clock += 1;
            if let Some(slot) = walk.get_mut(child) {
                slot.0 = clock;
            }
            stack.push((child, 0));
        } else {
            clock += 1;
            if let Some(slot) = walk.get_mut(block) {
                slot.1 = clock;
            }
            stack.pop();
        }
    }
    walk
}

/// The nearest common dominator of `a` and `b`, by the dominators found so
/// far.
fn intersect(idom: &[Option<usize>], rank: &[usize], mut a: usize, mut b: usize) -> Option<usize> {
    let rank_of = |block: usize| rank.get(block).copied().unwrap_or(usize::MAX);
    let up = |block: usize| idom.get(block).copied().flatten();
    while a != b {
        while rank_of(a) > rank_of(b) {
            a = up(a)?;
        }
        while rank_of(b) > rank_of(a) {
            b = up(b)?;
        }
    }
    Some(a)
}

/// The blocks reachable from block 0, in reverse postorder.
fn reverse_postorder(successors: &[Vec<usize>]) -> Vec<usize> {
    let mut visited = vec![false; successors.len()];
    let mut postorder = Vec::new();
    let mut stack: Vec<(usize, usize)> = Vec::new();
    if let Some(seen) = visited.get_mut(0) {
        *seen = true;
        stack.push((0, 0));
    }
    while let Some(top) = stack.last_mut() {
        let (block, next) = *top;
        top.1 += 1;
        if let Some(&successor) = successors.get(block).and_then(|list| list.get(next)) {
            if let Some(seen) = visited.get_mut(successor)
                && !*seen
            {
                *seen = true;
                stack.push((successor, 0));
            }
        } else {
            postorder.push(block);
            stack.pop();
        }
    }
    postorder.reverse();
    postorder
}
