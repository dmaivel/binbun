//! Dominators, post-dominators, natural loops and irreducible edges of a
//! graph of numbered nodes (node 0 the entry), shared by [`regions`] and
//! the structuring passes.
//!
//! - Order: reverse post-order of a depth-first search from the entry,
//!   successors in order. An edge is *retreating* if it does not go to a
//!   later node in that order.
//! - Dominators and post-dominators: Cooper, Harvey and Kennedy's
//!   iteration. Post-dominators are over a virtual sink that every node
//!   leaving the function goes to; a node that cannot reach the sink (an
//!   endless loop) gets an edge to it too, the latest such node in the
//!   order first, so that every node has an immediate post-dominator.
//! - Loops: a retreating edge to a node that dominates its source is a
//!   back edge; its target heads a natural loop: the nodes the header
//!   dominates that reach a back edge's source without passing the header.
//!   Two loops are disjoint or nested. Any other retreating edge makes the
//!   graph irreducible: it is listed, and the loops are those of the back
//!   edges alone.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::Function;
use binbun_ssa::ir::BlockId;

use super::{Budget, Refusal};
use crate::itanium;
use crate::validate::graph::{Graph, Successor};

/// No node.
pub(super) const NONE: u32 = u32::MAX;

/// `index` as a `u32`.
pub(super) fn number(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(NONE)
}

/// `slice[index]`, or [`NONE`].
pub(super) fn at(slice: &[u32], index: u32) -> u32 {
    slice.get(index as usize).copied().unwrap_or(NONE)
}

/// Sets `slice[index]` if it exists.
pub(super) fn put(slice: &mut [u32], index: u32, value: u32) {
    if let Some(slot) = slice.get_mut(index as usize) {
        *slot = value;
    }
}

/// `lists[index]`, or nothing.
pub(super) fn list(lists: &[Vec<u32>], index: u32) -> &[u32] {
    lists.get(index as usize).map_or(&[], Vec::as_slice)
}

/// A dominator tree of the nodes reached from a root.
#[derive(Clone, Debug, Default)]
struct Tree {
    /// The nodes reached, in reverse post-order (the root first).
    order: Vec<u32>,
    /// Each node's position in `order` ([`NONE`]: not reached).
    position: Vec<u32>,
    /// Each node's immediate dominator (the root's is itself; [`NONE`]:
    /// not reached).
    idom: Vec<u32>,
    /// Each node's interval in a pre-order walk of the tree: `a`
    /// dominates `b` iff `b`'s interval is inside `a`'s.
    enter: Vec<u32>,
    exit: Vec<u32>,
}

impl Tree {
    /// The dominator tree of `successors` from `root`.
    fn new(successors: &[Vec<u32>], root: u32, budget: &mut Budget) -> Result<Self, Refusal> {
        let count = successors.len();
        let order = reverse_post_order(successors, root, budget)?;
        let mut position = vec![NONE; count];
        for (index, &node) in order.iter().enumerate() {
            put(&mut position, node, number(index));
        }
        let mut predecessors = vec![Vec::new(); count];
        for &node in &order {
            for &next in list(successors, node) {
                if let Some(slot) = predecessors.get_mut(next as usize) {
                    slot.push(node);
                }
            }
        }
        let mut idom = vec![NONE; count];
        put(&mut idom, root, root);
        let mut changed = true;
        while changed {
            changed = false;
            budget.charge(count as u64)?;
            for &node in order.iter().skip(1) {
                let mut new = NONE;
                for &before in list(&predecessors, node) {
                    if at(&idom, before) == NONE {
                        continue;
                    }
                    new = if new == NONE {
                        before
                    } else {
                        intersect(&idom, &position, before, new, budget)?
                    };
                }
                if at(&idom, node) != new {
                    put(&mut idom, node, new);
                    changed = true;
                }
            }
        }
        let (enter, exit) = intervals(&idom, &order, root);
        Ok(Self {
            order,
            position,
            idom,
            enter,
            exit,
        })
    }

    fn dominates(&self, a: u32, b: u32) -> bool {
        let (Some(&enter_a), Some(&enter_b)) =
            (self.enter.get(a as usize), self.enter.get(b as usize))
        else {
            return false;
        };
        enter_a != NONE
            && enter_b != NONE
            && enter_a <= enter_b
            && at(&self.exit, b) <= at(&self.exit, a)
    }
}

/// The nodes reached from `root`, in reverse post-order.
fn reverse_post_order(
    successors: &[Vec<u32>],
    root: u32,
    budget: &mut Budget,
) -> Result<Vec<u32>, Refusal> {
    let mut seen = vec![false; successors.len()];
    let mut order = Vec::new();
    let mut stack = vec![(root, 0usize)];
    if let Some(slot) = seen.get_mut(root as usize) {
        *slot = true;
    }
    while let Some((node, next)) = stack.last_mut() {
        budget.charge(1)?;
        let node = *node;
        if let Some(&target) = list(successors, node).get(*next) {
            *next += 1;
            if let Some(slot) = seen.get_mut(target as usize)
                && !*slot
            {
                *slot = true;
                stack.push((target, 0));
            }
        } else {
            order.push(node);
            stack.pop();
        }
    }
    order.reverse();
    Ok(order)
}

/// The nearest common dominator of `a` and `b`.
fn intersect(
    idom: &[u32],
    position: &[u32],
    mut a: u32,
    mut b: u32,
    budget: &mut Budget,
) -> Result<u32, Refusal> {
    while a != b {
        budget.charge(1)?;
        while at(position, a) > at(position, b) {
            a = at(idom, a);
        }
        while at(position, b) > at(position, a) {
            b = at(idom, b);
        }
    }
    Ok(a)
}

/// Pre-order intervals of the tree `idom` over `order` from `root`.
fn intervals(idom: &[u32], order: &[u32], root: u32) -> (Vec<u32>, Vec<u32>) {
    let count = idom.len();
    let mut children = vec![Vec::new(); count];
    for &node in order {
        let parent = at(idom, node);
        if node != root
            && let Some(slot) = children.get_mut(parent as usize)
        {
            slot.push(node);
        }
    }
    let mut enter = vec![NONE; count];
    let mut exit = vec![NONE; count];
    let mut clock = 0;
    let mut stack = vec![(root, 0usize)];
    put(&mut enter, root, clock);
    while let Some((node, next)) = stack.last_mut() {
        let node = *node;
        if let Some(&child) = list(&children, node).get(*next) {
            *next += 1;
            clock += 1;
            put(&mut enter, child, clock);
            stack.push((child, 0));
        } else {
            put(&mut exit, node, clock);
            stack.pop();
        }
    }
    (enter, exit)
}

/// A natural loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loop {
    /// Its header, which dominates its body.
    pub header: u32,
    /// The innermost loop around it.
    pub parent: Option<u32>,
    /// How many loops are around it (0: outermost).
    pub depth: u32,
    /// The nodes it is the innermost loop of (its header first), in order.
    pub nodes: Vec<u32>,
    /// The sources of its back edges.
    pub latches: Vec<u32>,
    /// Its exit edges: from a node of it (or of a loop inside it) to a
    /// node outside it.
    pub exits: Vec<(u32, u32)>,
}

/// The analysis of a graph: dominator trees, loops, irreducible edges.
#[derive(Clone, Debug, Default)]
pub(super) struct Analysis {
    dominators: Tree,
    post_dominators: Tree,
    /// The virtual sink of `post_dominators`.
    sink: u32,
    pub(super) loops: Vec<Loop>,
    /// Each node's innermost loop ([`NONE`]: none).
    pub(super) loop_of: Vec<u32>,
    /// Each loop's interval in a pre-order walk of the loop tree.
    loop_enter: Vec<u32>,
    loop_exit: Vec<u32>,
    pub(super) irreducible: Vec<(u32, u32)>,
}

impl Analysis {
    /// Analyses the graph `successors` (node 0 the entry), `exits` saying
    /// which nodes leave the function.
    pub(super) fn new(
        successors: &[Vec<u32>],
        exits: &[bool],
        budget: &mut Budget,
    ) -> Result<Self, Refusal> {
        let edges: usize = successors.iter().map(Vec::len).sum();
        budget.charge((successors.len() + edges) as u64)?;
        let dominators = Tree::new(successors, 0, budget)?;
        let (post_dominators, sink) = post_dominators(successors, exits, &dominators, budget)?;
        let mut analysis = Self {
            dominators,
            post_dominators,
            sink,
            loop_of: vec![NONE; successors.len()],
            ..Self::default()
        };
        analysis.find_loops(successors, budget)?;
        analysis.find_exits(successors, budget)?;
        Ok(analysis)
    }

    /// The nodes reached from the entry, in reverse post-order.
    pub(super) fn order(&self) -> &[u32] {
        &self.dominators.order
    }

    /// `node`'s position in [`Self::order`] ([`NONE`]: not reached).
    pub(super) fn position(&self, node: u32) -> u32 {
        at(&self.dominators.position, node)
    }

    /// `node`'s immediate dominator ([`NONE`]: the entry, or not reached).
    pub(super) fn idom(&self, node: u32) -> u32 {
        if node == 0 {
            NONE
        } else {
            at(&self.dominators.idom, node)
        }
    }

    /// Whether `a` dominates `b` (both reached).
    pub(super) fn dominates(&self, a: u32, b: u32) -> bool {
        self.dominators.dominates(a, b)
    }

    /// `node`'s interval in a pre-order walk of the dominator tree: the
    /// nodes it dominates are those whose first number is inside it.
    pub(super) fn interval(&self, node: u32) -> (u32, u32) {
        (
            at(&self.dominators.enter, node),
            at(&self.dominators.exit, node),
        )
    }

    /// `node`'s immediate post-dominator: `Some(NONE)` for the sink.
    pub(super) fn ipdom(&self, node: u32) -> Option<u32> {
        let parent = at(&self.post_dominators.idom, node);
        if parent == NONE || node == self.sink {
            None
        } else if parent == self.sink {
            Some(NONE)
        } else {
            Some(parent)
        }
    }

    /// Whether `node` is in `l` or a loop inside it.
    pub(super) fn in_loop(&self, node: u32, l: u32) -> bool {
        let inner = at(&self.loop_of, node);
        inner != NONE
            && at(&self.loop_enter, l) <= at(&self.loop_enter, inner)
            && at(&self.loop_exit, inner) <= at(&self.loop_exit, l)
    }

    /// The loop `l`.
    pub(super) fn loop_at(&self, l: u32) -> Option<&Loop> {
        self.loops.get(l as usize)
    }

    /// Finds the natural loops, inner headers (later in the order) first,
    /// and nests them.
    fn find_loops(&mut self, successors: &[Vec<u32>], budget: &mut Budget) -> Result<(), Refusal> {
        let order = self.dominators.order.clone();
        let mut predecessors = vec![Vec::new(); successors.len()];
        let mut latches = vec![Vec::new(); successors.len()];
        for &node in &order {
            for &next in list(successors, node) {
                if let Some(slot) = predecessors.get_mut(next as usize) {
                    slot.push(node);
                }
                if self.position(next) <= self.position(node) {
                    if self.dominates(next, node) {
                        if let Some(slot) = latches.get_mut(next as usize) {
                            slot.push(node);
                        }
                    } else {
                        self.irreducible.push((node, next));
                    }
                }
            }
        }
        // `root[l]`: the outermost loop found so far around loop `l`.
        let mut root: Vec<u32> = Vec::new();
        for &header in order.iter().rev() {
            let back = list(&latches, header);
            if back.is_empty() {
                continue;
            }
            let l = number(self.loops.len());
            root.push(l);
            put(&mut self.loop_of, header, l);
            self.loops.push(Loop {
                header,
                parent: None,
                depth: 0,
                nodes: Vec::new(),
                latches: back.to_vec(),
                exits: Vec::new(),
            });
            let mut work: Vec<u32> = back.iter().copied().filter(|&n| n != header).collect();
            while let Some(node) = work.pop() {
                budget.charge(1)?;
                let inner = at(&self.loop_of, node);
                let from = if inner == NONE {
                    put(&mut self.loop_of, node, l);
                    node
                } else {
                    let outer = find(&mut root, inner);
                    if outer == l {
                        continue;
                    }
                    put(&mut root, outer, l);
                    if let Some(found) = self.loops.get_mut(outer as usize) {
                        found.parent = Some(l);
                    }
                    self.loops
                        .get(outer as usize)
                        .map_or(node, |found| found.header)
                };
                work.extend(
                    list(&predecessors, from)
                        .iter()
                        .copied()
                        .filter(|&before| before != header && self.dominates(header, before)),
                );
            }
        }
        self.nest(&order);
        Ok(())
    }

    /// Depths, members and the loop tree's intervals.
    fn nest(&mut self, order: &[u32]) {
        let count = self.loops.len();
        let mut children = vec![Vec::new(); count];
        let mut roots = Vec::new();
        // Outer loops were found later.
        for l in (0..count).rev() {
            let parent = self.loops.get(l).and_then(|found| found.parent);
            match parent {
                Some(parent) => {
                    let depth = self.loop_at(parent).map_or(0, |found| found.depth + 1);
                    if let Some(found) = self.loops.get_mut(l) {
                        found.depth = depth;
                    }
                    if let Some(slot) = children.get_mut(parent as usize) {
                        slot.push(number(l));
                    }
                }
                None => roots.push(number(l)),
            }
        }
        for &node in order {
            let l = at(&self.loop_of, node);
            if let Some(found) = self.loops.get_mut(l as usize) {
                found.nodes.push(node);
            }
        }
        self.loop_enter = vec![NONE; count];
        self.loop_exit = vec![NONE; count];
        let mut clock = 0;
        for start in roots {
            let mut stack = vec![(start, 0usize)];
            put(&mut self.loop_enter, start, clock);
            while let Some((l, next)) = stack.last_mut() {
                let l = *l;
                if let Some(&child) = list(&children, l).get(*next) {
                    *next += 1;
                    clock += 1;
                    put(&mut self.loop_enter, child, clock);
                    stack.push((child, 0));
                } else {
                    put(&mut self.loop_exit, l, clock);
                    stack.pop();
                }
            }
            clock += 1;
        }
    }

    /// Each loop's exit edges.
    fn find_exits(&mut self, successors: &[Vec<u32>], budget: &mut Budget) -> Result<(), Refusal> {
        for index in 0..self.dominators.order.len() {
            let node = at(&self.dominators.order, number(index));
            for &next in list(successors, node) {
                let mut l = at(&self.loop_of, node);
                while l != NONE && !self.in_loop(next, l) {
                    budget.charge(1)?;
                    let Some(found) = self.loops.get_mut(l as usize) else {
                        break;
                    };
                    found.exits.push((node, next));
                    l = found.parent.unwrap_or(NONE);
                }
            }
        }
        Ok(())
    }
}

/// The root of `l` in the union-find `root`, compressing the path.
fn find(root: &mut [u32], l: u32) -> u32 {
    let mut top = l;
    while at(root, top) != top {
        top = at(root, top);
    }
    let mut node = l;
    while node != top {
        let next = at(root, node);
        put(root, node, top);
        node = next;
    }
    top
}

/// The post-dominator tree over a virtual sink (node `successors.len()`).
fn post_dominators(
    successors: &[Vec<u32>],
    exits: &[bool],
    dominators: &Tree,
    budget: &mut Budget,
) -> Result<(Tree, u32), Refusal> {
    let count = successors.len();
    let sink = number(count);
    // The reverse graph, the sink first reaching the exits.
    let mut reverse = vec![Vec::new(); count + 1];
    for (node, targets) in successors.iter().enumerate() {
        for &next in targets {
            if let Some(slot) = reverse.get_mut(next as usize) {
                slot.push(number(node));
            }
        }
    }
    let mut into_sink: Vec<u32> = (0..count)
        .filter(|&node| exits.get(node).copied().unwrap_or(false))
        .map(number)
        .collect();
    // Nodes that cannot reach the sink: the latest first gets an edge.
    let mut reaches = vec![false; count];
    let mut work = into_sink.clone();
    mark(&reverse, &mut reaches, &mut work, budget)?;
    for &node in dominators.order.iter().rev() {
        if !reaches.get(node as usize).copied().unwrap_or(true) {
            into_sink.push(node);
            work.push(node);
            mark(&reverse, &mut reaches, &mut work, budget)?;
        }
    }
    if let Some(slot) = reverse.get_mut(count) {
        *slot = into_sink;
    }
    Ok((Tree::new(&reverse, sink, budget)?, sink))
}

/// Marks in `reaches` the nodes `reverse` reaches from `work`.
fn mark(
    reverse: &[Vec<u32>],
    reaches: &mut [bool],
    work: &mut Vec<u32>,
    budget: &mut Budget,
) -> Result<(), Refusal> {
    while let Some(node) = work.pop() {
        budget.charge(1)?;
        match reaches.get_mut(node as usize) {
            Some(slot) if !*slot => *slot = true,
            Some(_) | None => continue,
        }
        work.extend(list(reverse, node).iter().copied());
    }
    Ok(())
}

/// Where a node's paths to the function's end all go first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostDominator {
    /// Another node.
    Node(u32),
    /// The virtual sink: no node is on every path.
    Sink,
}

/// The region graph of a function ([`regions`]) and its analysis.
///
/// Nodes are numbered from 0, the block the body starts with; each node
/// is an L1 block the function's code stands for (`Origin::Block`), and
/// an edge goes where control can go from the block's code, through its
/// decision, to another block's ([`Graph::flow`], over all the places it
/// is entered).
#[derive(Clone, Debug)]
pub struct Regions {
    /// The blocks, in the order found from the start.
    pub regions: Vec<BlockId>,
    /// Each region's successors, in order.
    pub successors: Vec<Vec<u32>>,
    /// Whether control can leave the function from each region.
    pub exits: Vec<bool>,
    /// The natural loops, inner ones before the loops around them.
    pub loops: Vec<Loop>,
    /// The retreating edges that are not back edges: one per edge that
    /// makes the graph irreducible (empty: reducible).
    pub irreducible: Vec<(u32, u32)>,
    analysis: Analysis,
}

impl Regions {
    /// The regions reached from the entry, in reverse post-order.
    pub fn order(&self) -> &[u32] {
        self.analysis.order()
    }

    /// Whether `node` is reached from the entry.
    pub fn reached(&self, node: u32) -> bool {
        self.analysis.position(node) != NONE
    }

    /// `node`'s immediate dominator (`None`: the entry, or not reached).
    pub fn idom(&self, node: u32) -> Option<u32> {
        Some(self.analysis.idom(node)).filter(|&parent| parent != NONE)
    }

    /// Whether `a` dominates `b` (every path from the entry to `b` goes
    /// through `a`; a node dominates itself).
    pub fn dominates(&self, a: u32, b: u32) -> bool {
        self.analysis.dominates(a, b)
    }

    /// `node`'s immediate post-dominator (`None`: `node` cannot reach the
    /// end, before the virtual edges).
    pub fn ipdom(&self, node: u32) -> Option<PostDominator> {
        self.analysis.ipdom(node).map(|parent| {
            if parent == NONE {
                PostDominator::Sink
            } else {
                PostDominator::Node(parent)
            }
        })
    }

    /// The innermost loop `node` is in.
    pub fn loop_of(&self, node: u32) -> Option<u32> {
        Some(at(&self.analysis.loop_of, node)).filter(|&l| l != NONE)
    }

    /// Whether `node` is in loop `l` (or a loop inside it).
    pub fn in_loop(&self, node: u32, l: u32) -> bool {
        self.analysis.in_loop(node, l)
    }
}

/// The region graph of `function`'s body: its blocks' graph
/// ([`Graph::flow`], one node per L1 block its code stands for) with its
/// dominators, post-dominators, loops and irreducible edges. Works on any
/// L2 function whose statements and decisions name their blocks:
/// goto-only or structured. Work is bounded by
/// [`Options::default`](super::Options)'s budget.
///
/// # Errors
///
/// [`Refusal::Malformed`] if the graph cannot be built (a statement is
/// missing, a label is defined twice, a jump has no target, statements
/// nest too deeply, a decision stands for no block) or the body does not
/// start with a block's code, [`Refusal::Budget`] if the analysis needs
/// more work than the budget allows.
pub fn regions(function: &Function) -> Result<Regions, Refusal> {
    let malformed = |_| Refusal::Malformed {
        stmt: None,
        reason: "its control flow graph cannot be built",
    };
    let flow = Graph::of(function, &itanium::NONE)
        .and_then(|graph| graph.flow())
        .map_err(malformed)?;
    let Successor::Block(start) = flow.start else {
        return Err(Refusal::Malformed {
            stmt: None,
            reason: "its body does not start with a block's code",
        });
    };
    let blocks = flow.blocks();
    let mut nodes = vec![start];
    nodes.extend(flow.regions.iter().map(|region| region.block));
    let mut seen = BTreeSet::new();
    nodes.retain(|&block| seen.insert(block));
    let index: BTreeMap<BlockId, u32> = nodes
        .iter()
        .enumerate()
        .map(|(i, &block)| (block, number(i)))
        .collect();
    let mut successors = Vec::with_capacity(nodes.len());
    let mut exits = Vec::with_capacity(nodes.len());
    let mut size = 0u64;
    for block in &nodes {
        let targets = blocks.get(block).map(BTreeSet::iter).into_iter().flatten();
        let mut own = Vec::new();
        let mut exit = false;
        for target in targets {
            match target {
                Successor::Block(target) => own.extend(index.get(target).copied()),
                Successor::Exit => exit = true,
                Successor::Spin => {}
            }
        }
        size += 1 + own.len() as u64;
        successors.push(own);
        exits.push(exit);
    }
    let mut budget = Budget::new(
        &super::Options::default(),
        size + function.stmts.len() as u64,
    );
    let analysis = Analysis::new(&successors, &exits, &mut budget)?;
    Ok(Regions {
        regions: nodes,
        successors,
        exits,
        loops: analysis.loops.clone(),
        irreducible: analysis.irreducible.clone(),
        analysis,
    })
}
