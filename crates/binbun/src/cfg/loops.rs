//! Dominators and natural loops of a function's control flow.
//!
//! A block dominates another when every way from the function's entry to
//! the other goes through it. An edge to a block that dominates the edge's
//! source is a back edge; the natural loop of a back edge is its target
//! (the loop's header) and the blocks that reach its source without
//! going through the header. Loops of the same header are one loop.
//! Dominators are found by Cooper, Harvey and Kennedy's iteration over
//! the blocks in reverse postorder ("A Simple, Fast Dominance
//! Algorithm", 2001).

use std::collections::{BTreeMap, HashMap, HashSet};

use super::{BlockId, FunctionId, Program};

/// A natural loop of a function: its header and its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loop {
    /// The block every way into the loop goes through, where each
    /// iteration starts.
    pub header: BlockId,
    /// Its blocks, the header among them, by address.
    pub blocks: Vec<BlockId>,
}

/// A function's blocks reached from its entry, in reverse postorder (the
/// entry first), with the successors and predecessors of each among them
/// (by their places in that order).
struct Graph {
    order: Vec<BlockId>,
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
}

impl Program {
    /// The immediate dominator of each block of `function` reached from
    /// its entry, but the entry's: the nearest block every way to it from
    /// the entry goes through.
    pub fn dominators(&self, function: FunctionId) -> BTreeMap<BlockId, BlockId> {
        let Some(graph) = self.graph(function) else {
            return BTreeMap::new();
        };
        let idom = immediate_dominators(&graph);
        graph
            .order
            .iter()
            .zip(&idom)
            .skip(1)
            .filter_map(|(&block, &dominator)| Some((block, *graph.order.get(dominator)?)))
            .collect()
    }

    /// The natural loops of `function`, by their headers' addresses (an
    /// outer loop's header first where it comes first).
    pub fn loops(&self, function: FunctionId) -> Vec<Loop> {
        // A cycle goes back somewhere: without an edge to its own block or
        // one before it, a function has no loop.
        let goes_back = self.functions.get(function).is_some_and(|f| {
            f.blocks.iter().any(|&id| {
                self.blocks
                    .get(id)
                    .is_some_and(|block| self.successors(id).any(|(_, to)| to <= block.start))
            })
        });
        if !goes_back {
            return Vec::new();
        }
        let Some(graph) = self.graph(function) else {
            return Vec::new();
        };
        let idom = immediate_dominators(&graph);
        // Whether block `a` dominates block `b` (by their places).
        let dominates = |a: usize, mut b: usize| loop {
            if a == b {
                return true;
            }
            match idom.get(b) {
                Some(&up) if up != b => b = up,
                Some(_) | None => return false,
            }
        };
        let mut bodies: BTreeMap<usize, HashSet<usize>> = BTreeMap::new();
        for (source, targets) in graph.successors.iter().enumerate() {
            for &header in targets {
                if !dominates(header, source) {
                    continue;
                }
                // The blocks reaching the back edge's source without
                // going through the header.
                let body = bodies
                    .entry(header)
                    .or_insert_with(|| HashSet::from([header]));
                let mut work = vec![source];
                while let Some(block) = work.pop() {
                    if body.insert(block) {
                        work.extend(graph.predecessors.get(block).into_iter().flatten());
                    }
                }
            }
        }
        let start = |block: BlockId| self.blocks.get(block).map_or(u64::MAX, |b| b.start);
        let mut loops: Vec<Loop> = bodies
            .into_iter()
            .filter_map(|(header, body)| {
                let mut blocks: Vec<BlockId> = body
                    .into_iter()
                    .filter_map(|b| graph.order.get(b).copied())
                    .collect();
                blocks.sort_by_key(|&b| start(b));
                Some(Loop {
                    header: *graph.order.get(header)?,
                    blocks,
                })
            })
            .collect();
        loops.sort_by_key(|l| start(l.header));
        loops
    }

    /// `function`'s blocks reached from its entry, along the edges between
    /// them ([`Program::successors`]), as a [`Graph`]; `None` for no such
    /// function or no block at its entry.
    fn graph(&self, function: FunctionId) -> Option<Graph> {
        let function = self.functions.get(function)?;
        let entry = self.block_at(function.entry)?;
        let own: HashSet<BlockId> = function.blocks.iter().copied().collect();
        let next = |block: BlockId| -> Vec<BlockId> {
            self.successors(block)
                .filter_map(|(_, to)| self.block_at(to))
                .filter(|to| own.contains(to))
                .collect()
        };
        // Postorder, by a depth-first walk: each block with its successors
        // and how many of them were walked.
        let mut seen = HashSet::from([entry]);
        let mut order = Vec::new();
        let mut targets_of: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        let mut stack = vec![(entry, next(entry), 0usize)];
        while let Some((_, targets, walked)) = stack.last_mut() {
            if let Some(to) = targets.get(*walked).copied() {
                *walked += 1;
                if seen.insert(to) {
                    let further = next(to);
                    stack.push((to, further, 0));
                }
            } else if let Some((done, targets, _)) = stack.pop() {
                order.push(done);
                targets_of.insert(done, targets);
            }
        }
        order.reverse();
        let place: HashMap<BlockId, usize> =
            order.iter().enumerate().map(|(i, &b)| (b, i)).collect();
        let successors: Vec<Vec<usize>> = order
            .iter()
            .map(|b| {
                targets_of
                    .get(b)
                    .into_iter()
                    .flatten()
                    .filter_map(|to| place.get(to).copied())
                    .collect()
            })
            .collect();
        let mut predecessors = vec![Vec::new(); order.len()];
        for (from, targets) in successors.iter().enumerate() {
            for &to in targets {
                if let Some(into) = predecessors.get_mut(to) {
                    into.push(from);
                }
            }
        }
        Some(Graph {
            order,
            successors,
            predecessors,
        })
    }
}

/// The immediate dominator of each block of `graph` (by its place), the
/// entry its own.
fn immediate_dominators(graph: &Graph) -> Vec<usize> {
    const NONE: usize = usize::MAX;
    let mut idom = vec![NONE; graph.order.len()];
    let Some(entry) = idom.first_mut() else {
        return idom;
    };
    *entry = 0;
    // The nearest common dominator of `a` and `b`: up from the later in
    // reverse postorder until they meet.
    let meet = |idom: &[usize], mut a: usize, mut b: usize| {
        while a != b {
            while a > b {
                a = idom.get(a).copied().unwrap_or(0);
            }
            while b > a {
                b = idom.get(b).copied().unwrap_or(0);
            }
        }
        a
    };
    let mut changed = true;
    while changed {
        changed = false;
        for block in 1..graph.order.len() {
            let mut found = NONE;
            for &from in graph.predecessors.get(block).into_iter().flatten() {
                if idom.get(from).is_none_or(|&d| d == NONE) {
                    continue;
                }
                found = if found == NONE {
                    from
                } else {
                    meet(&idom, from, found)
                };
            }
            if found != NONE
                && let Some(slot) = idom.get_mut(block)
                && *slot != found
            {
                *slot = found;
                changed = true;
            }
        }
    }
    idom
}
