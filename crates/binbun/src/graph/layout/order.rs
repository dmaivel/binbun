//! The order of each layer: a depth-first start, then barycentre sweeps
//! down and up, keeping the order with the fewest crossings.

#![expect(
    clippy::indexing_slicing,
    reason = "vertex and segment ids index the arenas of the layered graph that made them"
)]

use std::iter::repeat_n;

use binbun_semantics::core::Arena;

use super::{Layered, Vx, place};

/// Sweeps tried at most, and without improvement before stopping.
const SWEEPS: usize = 24;
const PATIENCE: usize = 6;

/// Orders `graph`'s layers to cross few edges.
pub(super) fn minimise(graph: &mut Layered, root: Vx) {
    start(graph, root);
    let mut best = graph.layers.clone();
    let mut fewest = crossings(graph);
    let mut stale = 0;
    for sweep in 0..SWEEPS {
        if fewest == 0 || stale >= PATIENCE {
            break;
        }
        let depth = graph.layers.len();
        if sweep % 2 == 0 {
            for layer in 1..depth {
                reorder(graph, layer, true);
            }
        } else {
            for layer in (0..depth.saturating_sub(1)).rev() {
                reorder(graph, layer, false);
            }
        }
        let now = crossings(graph);
        if now < fewest {
            fewest = now;
            best.clone_from(&graph.layers);
            stale = 0;
        } else {
            stale += 1;
        }
    }
    graph.layers = best;
    for layer in &graph.layers {
        for (i, &v) in layer.iter().enumerate() {
            graph.pos[v] = i;
        }
    }
}

/// The first order: each layer by a depth-first pre-order from `root`
/// along the edges down (then from the other nodes), a back edge's points
/// just after its source.
fn start(graph: &mut Layered, root: Vx) {
    let n = graph.vertices.len();
    let mut key: Arena<Vx, Option<f64>> = repeat_n(None, n).collect();
    let mut next = 0usize;
    let mut stack: Vec<Vx> = Vec::new();
    let nodes: Vec<Vx> = graph
        .vertices
        .iter()
        .filter(|(_, v)| v.real)
        .map(|(id, _)| id)
        .collect();
    for start in std::iter::once(root).chain(nodes) {
        if key[start].is_some() {
            continue;
        }
        stack.push(start);
        while let Some(v) = stack.pop() {
            if key[v].is_some() {
                continue;
            }
            key[v] = Some(place(next));
            next += 1;
            // Pushed in reverse so the first edge is visited first.
            for &s in graph.down[v].iter().rev() {
                let w = graph.segments[s].lower;
                if key[w].is_none() {
                    stack.push(w);
                }
            }
        }
    }
    for (_, chain) in graph.chains.iter() {
        if chain.valid && chain.back {
            let after = key[chain.from].map_or(f64::MAX, |k| k + 0.5);
            for &d in &chain.points {
                key[d] = Some(after);
            }
        }
    }
    for layer in 0..graph.layers.len() {
        let mut free: Vec<Vx> = graph
            .layers
            .get(layer)
            .into_iter()
            .flatten()
            .copied()
            .filter(|&v| graph.vertices[v].anchor.is_none())
            .collect();
        let at = |v: Vx| key[v].unwrap_or(f64::MAX);
        free.sort_by(|&a, &b| at(a).total_cmp(&at(b)).then(a.cmp(&b)));
        graph.settle(layer, free);
    }
}

/// Orders `layer` by the barycentres of its vertices' neighbours in the
/// layer above (`downward`) or below; a vertex with none keeps its place.
fn reorder(graph: &mut Layered, layer: usize, downward: bool) {
    let Some(vertices) = graph.layers.get(layer) else {
        return;
    };
    let mut keyed: Vec<(f64, usize, Vx)> = vertices
        .iter()
        .copied()
        .filter(|&v| graph.vertices[v].anchor.is_none())
        .map(|v| {
            let segments = if downward {
                &graph.up[v]
            } else {
                &graph.down[v]
            };
            let key = if segments.is_empty() {
                place(graph.pos[v])
            } else {
                let sum: f64 = segments
                    .iter()
                    .map(|&s| {
                        let s = &graph.segments[s];
                        if downward {
                            place(graph.pos[s.upper]) + s.bias
                        } else {
                            place(graph.pos[s.lower]) - s.bias
                        }
                    })
                    .sum();
                sum / place(segments.len())
            };
            (key, graph.pos[v], v)
        })
        .collect();
    keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
    graph.settle(layer, keyed.into_iter().map(|k| k.2).collect());
}

/// How many pairs of segments between adjacent layers cross.
pub(super) fn crossings(graph: &Layered) -> u64 {
    let mut between: Vec<Vec<(usize, usize)>> = repeat_n(Vec::new(), graph.layers.len()).collect();
    for (_, s) in graph.segments.iter() {
        let layer = graph.vertices[s.upper].layer;
        if let Some(list) = between.get_mut(layer) {
            list.push((graph.pos[s.upper], graph.pos[s.lower]));
        }
    }
    let mut total = 0;
    for (layer, mut pairs) in between.into_iter().enumerate() {
        let width = graph.layers.get(layer + 1).map_or(0, Vec::len);
        pairs.sort_unstable();
        // Inversions of the lower ends, counted with a Fenwick tree.
        let mut tree = vec![0u64; width + 1];
        for (seen, (_, lower)) in (0u64..).zip(pairs) {
            // Ends seen so far at places up to `lower`.
            let mut at_most = 0;
            let mut i = lower + 1;
            while i > 0 {
                at_most += tree.get(i).copied().unwrap_or(0);
                i &= i - 1;
            }
            total += seen - at_most;
            let mut i = lower + 1;
            while let Some(slot) = tree.get_mut(i) {
                *slot += 1;
                i += i.isolate_lowest_one();
            }
        }
    }
    total
}
