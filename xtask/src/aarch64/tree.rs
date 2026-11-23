//! The decode tree: switches on bit fields down to short candidate lists.
//!
//! Each switch reads the field that best splits the candidates left, a
//! candidate that leaves some of the field's bits free going into every arm
//! it allows. The cost of a field ([`Split::cost`]) is the number of
//! candidates a word is expected to meet after the switch, the words being
//! spread over the candidates as the encodings spread over the word space,
//! weighed against how many times candidates are copied. Equal subtrees are
//! built once. A field that leaves every candidate in the one arm it
//! allows is never switched on: the leaf's mask test checks those bits with
//! the others, in one compare.

use std::collections::{BTreeMap, HashMap};

use super::cube::Cube;
use super::model::Encoding;
use crate::Result;

/// Encodings that other, more specific encodings carve words out of. The
/// only overlap in A64 once field conditions are applied: the specific hints
/// (`NOP`, `YIELD`, `PACIASP`, `BTI`, …) inside the `HINT` catch-all.
const CATCH_ALL: &[&str] = &["HINT_HM_hints"];

/// Widest switch, in bits. With [`COPY_PENALTY`], chosen on the decode
/// benchmark (`bench --task decode`, main corpus): 10 bits and 1.5 decode
/// about 5% faster than 8 bits and 1.0, for 13% more generated code; 10
/// bits and 1.0 another 2% faster for 19% more.
const MAX_SWITCH: u32 = 10;

/// How much copying candidates into several arms counts against a field
/// (the exponent of the copy factor in [`Split::cost`]).
const COPY_PENALTY: f64 = 1.5;

#[derive(Debug)]
pub enum Node {
    /// `match (word >> shift) & ((1 << width) - 1)`; `None` children
    /// decode nothing.
    Switch {
        shift: u32,
        width: u32,
        children: Vec<Option<usize>>,
    },
    /// The candidates left, most specific first, and the bits the switches
    /// on the way here tested (only those some candidate fixes).
    Leaf { candidates: Vec<usize>, known: u32 },
}

#[derive(Debug, Default)]
pub struct Tree {
    /// Nodes; the root is node 0. Nodes are shared by every parent whose
    /// arm leads to the same candidates and known bits.
    pub nodes: Vec<Node>,
}

/// Statistics for the report.
#[derive(Debug, Default)]
pub struct Stats {
    /// Switches wider than one bit.
    pub switches: usize,
    /// One-bit switches.
    pub bits: usize,
    pub leaves: usize,
    /// Most switches on a path, leaf included.
    pub depth: usize,
    /// Leaves by number of candidates (index 0 unused).
    pub candidates: Vec<usize>,
}

/// Pairs (specific, general) of encodings that share words, the more
/// specific (more fixed bits) winning. Fails on any other overlap.
pub fn overlaps(encodings: &[Encoding<'_>]) -> Result<Vec<(usize, usize)>> {
    let mut pairs = Vec::new();
    for (i, a) in encodings.iter().enumerate() {
        for (j, b) in encodings.iter().enumerate().skip(i + 1) {
            if !a.fixed.intersects(b.fixed) {
                continue;
            }
            let shared = a.fixed.intersection(b.fixed);
            let holes: Vec<Cube> = a.excluded.iter().chain(&b.excluded).copied().collect();
            if !shared.exceeds(&holes) {
                continue;
            }
            let (specific, general) = if a.fixed.mask.count_ones() > b.fixed.mask.count_ones() {
                (i, j)
            } else {
                (j, i)
            };
            let resolved = CATCH_ALL.contains(&encodings[general].name())
                && encodings[specific].fixed.within(encodings[general].fixed)
                && encodings[specific].fixed.mask != encodings[general].fixed.mask;
            if !resolved {
                return Err(format!(
                    "{} and {} share words, e.g. {:#010x}",
                    a.name(),
                    b.name(),
                    shared.value
                )
                .into());
            }
            pairs.push((specific, general));
        }
    }
    Ok(pairs)
}

/// Builds the tree, sharing equal subtrees.
struct Builder<'a> {
    encodings: &'a [Encoding<'a>],
    nodes: Vec<Node>,
    built: HashMap<(Vec<usize>, u32), usize>,
}

impl Builder<'_> {
    /// The node for `candidates` (sorted) given the `known` bits; `None` if
    /// there are no candidates.
    fn node(&mut self, candidates: Vec<usize>, known: u32) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        let fixed = candidates
            .iter()
            .fold(0, |mask, &c| mask | self.encodings[c].fixed.mask);
        // Only the known bits some candidate fixes matter below.
        let known = known & fixed;
        let key = (candidates, known);
        if let Some(&id) = self.built.get(&key) {
            return Some(id);
        }
        let (candidates, known) = key;
        let id = self.nodes.len();
        self.nodes.push(Node::Leaf {
            candidates: Vec::new(),
            known,
        });
        let node = if let Some(split) = Split::best(self.encodings, &candidates, known) {
            self.switch(split, &candidates, known)
        } else {
            let mut sorted = candidates.clone();
            sorted.sort_by_key(|&c| {
                (
                    std::cmp::Reverse(self.encodings[c].fixed.mask.count_ones()),
                    c,
                )
            });
            Node::Leaf {
                candidates: sorted,
                known,
            }
        };
        self.nodes[id] = node;
        self.built.insert((candidates, known), id);
        Some(id)
    }

    /// A switch on `split`'s field, each candidate in every arm its fixed
    /// bits allow.
    fn switch(&mut self, split: Split, candidates: &[usize], known: u32) -> Node {
        let field = split.field();
        let mut arms = vec![Vec::new(); 1 << split.width];
        for &c in candidates {
            let fixed = self.encodings[c].fixed;
            for (value, arm) in (0u32..).zip(&mut arms) {
                if fixed.intersects(Cube::new(field, value << split.shift)) {
                    arm.push(c);
                }
            }
        }
        let children = arms
            .into_iter()
            .map(|arm| self.node(arm, known | field))
            .collect();
        Node::Switch {
            shift: split.shift,
            width: split.width,
            children,
        }
    }
}

impl Tree {
    pub fn build(encodings: &[Encoding<'_>]) -> Self {
        let mut builder = Builder {
            encodings,
            nodes: Vec::new(),
            built: HashMap::new(),
        };
        builder.node((0..encodings.len()).collect(), 0);
        Self {
            nodes: builder.nodes,
        }
    }

    pub fn stats(&self) -> Stats {
        let mut stats = Stats::default();
        for node in &self.nodes {
            match node {
                Node::Switch { width: 1, .. } => stats.bits += 1,
                Node::Switch { .. } => stats.switches += 1,
                Node::Leaf { candidates, .. } => {
                    stats.leaves += 1;
                    if stats.candidates.len() <= candidates.len() {
                        stats.candidates.resize(candidates.len() + 1, 0);
                    }
                    stats.candidates[candidates.len()] += 1;
                }
            }
        }
        let mut depths = vec![None; self.nodes.len()];
        stats.depth = self.depth(0, &mut depths);
        stats
    }

    /// Nodes on the longest path from `id` down, `id` included.
    fn depth(&self, id: usize, depths: &mut [Option<usize>]) -> usize {
        if let Some(depth) = depths[id] {
            return depth;
        }
        let depth = match &self.nodes[id] {
            Node::Switch { children, .. } => {
                1 + children
                    .iter()
                    .flatten()
                    .map(|&child| self.depth(child, depths))
                    .max()
                    .unwrap_or(0)
            }
            Node::Leaf { .. } => 1,
        };
        depths[id] = Some(depth);
        depth
    }
}

/// A field to switch on and what it costs.
#[derive(Debug, Clone, Copy)]
struct Split {
    shift: u32,
    width: u32,
    cost: f64,
}

impl Split {
    fn field(self) -> u32 {
        ((1 << self.width) - 1) << self.shift
    }

    /// The cheapest field of at most [`MAX_SWITCH`] unknown bits that tells
    /// some candidates apart (on ties the narrowest, then the highest);
    /// `None` if fixed bits cannot tell the candidates apart.
    fn best(encodings: &[Encoding<'_>], candidates: &[usize], known: u32) -> Option<Self> {
        if candidates.len() < 2 {
            return None;
        }
        let mut best: Option<Self> = None;
        for width in 1..=MAX_SWITCH {
            for shift in (0..=32 - width).rev() {
                let field = ((1u32 << width) - 1) << shift;
                if field & known != 0 {
                    continue;
                }
                let Some(cost) = Self::cost(encodings, candidates, shift, width) else {
                    continue;
                };
                if best.is_none_or(|best| cost < best.cost) {
                    best = Some(Self { shift, width, cost });
                }
            }
        }
        best
    }

    /// The cost of switching `candidates` on the field: `E * F^p`, `E` the
    /// expected number of candidates in the arm a word takes (a candidate's
    /// share of the words being `2^-(fixed bits)`, split evenly over the arms
    /// it is in), `F` the number of candidates in all arms over the number of
    /// candidates and `p` [`COPY_PENALTY`]. `None` if every arm that is not
    /// empty holds every candidate.
    fn cost(
        encodings: &[Encoding<'_>],
        candidates: &[usize],
        shift: u32,
        width: u32,
    ) -> Option<f64> {
        let field = ((1u32 << width) - 1) << shift;
        // Candidates by the field bits they fix and their values there:
        // (mask, value) → (count, share of the words). Ordered, so that the
        // sums and therefore the tree do not depend on hashing.
        let mut patterns: BTreeMap<(u32, u32), (u32, f64)> = BTreeMap::new();
        for &c in candidates {
            let fixed = encodings[c].fixed;
            let share = (-f64::from(fixed.mask.count_ones())).exp2();
            let entry = patterns
                .entry((
                    (fixed.mask & field) >> shift,
                    (fixed.value & field) >> shift,
                ))
                .or_default();
            entry.0 += 1;
            entry.1 += share;
        }
        let ones = (1u32 << width) - 1;
        let mut counts = vec![0u32; 1 << width];
        let mut shares = vec![0f64; 1 << width];
        for (&(mask, value), &(count, share)) in &patterns {
            let free = ones & !mask;
            let share = share / f64::from(1u32 << free.count_ones());
            // Every value of the free bits: the submasks of `free`.
            let mut bits = free;
            loop {
                let arm = (value | bits) as usize;
                counts[arm] += count;
                shares[arm] += share;
                if bits == 0 {
                    break;
                }
                bits = (bits - 1) & free;
            }
        }
        let n = u32::try_from(candidates.len()).ok()?;
        if counts.iter().all(|&count| count == 0 || count == n) {
            return None;
        }
        let total: f64 = shares.iter().sum();
        let expected = counts
            .iter()
            .zip(&shares)
            .map(|(&count, &share)| f64::from(count) * share)
            .sum::<f64>()
            / total;
        let copies = f64::from(counts.iter().sum::<u32>()) / f64::from(n);
        Some(expected * copies.powf(COPY_PENALTY))
    }
}
