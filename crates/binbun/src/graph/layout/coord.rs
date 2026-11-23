//! Horizontal coordinates by Brandes and Köpf ("Fast and Simple Horizontal
//! Coordinate Assignment", 2001): four alignments of vertices into vertical
//! blocks with a median neighbour, each compacted, then balanced.
//!
//! Alignment follows ports: a vertex aligned below a node's port sits
//! where the port is, so an edge between two single ports is vertical.
//! Compaction is over the graph of blocks (each block as far left as its
//! left neighbours allow, then right as far as its right neighbours do),
//! which avoids the original's class shifts.

#![expect(
    clippy::indexing_slicing,
    reason = "vertex and segment ids index the arenas of the layered graph that made them"
)]

use std::iter::repeat_n;

use binbun_semantics::core::Arena;

use super::{Layered, Sg, Spacing, Vx};

/// Each vertex's centre.
pub(super) fn assign(graph: &Layered, spacing: &Spacing) -> Arena<Vx, f32> {
    let marked = conflicts(graph);
    let mut layouts = Vec::with_capacity(4);
    for downward in [true, false] {
        for rightward in [false, true] {
            layouts.push((
                rightward,
                place(graph, spacing, &marked, downward, rightward),
            ));
        }
    }
    let extent = |x: &Arena<Vx, f32>| {
        x.iter().fold((f32::MAX, f32::MIN), |(low, high), (v, &x)| {
            let half = graph.vertices[v].width / 2.0;
            (low.min(x - half), high.max(x + half))
        })
    };
    let extents: Vec<(f32, f32)> = layouts.iter().map(|(_, x)| extent(x)).collect();
    let (low, high) = extents
        .iter()
        .copied()
        .min_by(|a, b| (a.1 - a.0).total_cmp(&(b.1 - b.0)))
        .unwrap_or((0.0, 0.0));
    for ((rightward, x), &(l, h)) in layouts.iter_mut().zip(&extents) {
        let shift = if *rightward { high - h } else { low - l };
        for (_, x) in x.iter_mut() {
            *x += shift;
        }
    }
    let mut x: Arena<Vx, f32> = graph
        .vertices
        .ids()
        .map(|v| {
            let mut four = [0.0f32; 4];
            for (slot, (_, x)) in four.iter_mut().zip(&layouts) {
                *slot = x[v];
            }
            four.sort_by(f32::total_cmp);
            let [_, a, b, _] = four;
            f32::midpoint(a, b)
        })
        .collect();
    refine(graph, spacing, &mut x);
    x
}

/// Passes of [`refine`].
const PASSES: usize = 4;

/// Moves vertices, within the room their neighbours in the layer leave,
/// to where more of their edges are vertical, or else shorter: balancing
/// can leave a vertex between its alignments, far from both (a short edge
/// pulled towards long ones beside it).
fn refine(graph: &Layered, spacing: &Spacing, x: &mut Arena<Vx, f32>) {
    let port = |v: Vx, s: Sg| {
        let s = &graph.segments[s];
        if s.upper == v {
            s.upper_port
        } else {
            s.lower_port
        }
    };
    for pass in 0..PASSES {
        let layers: Vec<&Vec<Vx>> = if pass % 2 == 0 {
            graph.layers.iter().collect()
        } else {
            graph.layers.iter().rev().collect()
        };
        for layer in layers {
            for (i, &v) in layer.iter().enumerate() {
                // Where each edge of `v` would be vertical.
                let targets: Vec<f32> = graph.up[v]
                    .iter()
                    .chain(&graph.down[v])
                    .map(|&s| {
                        let seg = &graph.segments[s];
                        let other = if seg.upper == v { seg.lower } else { seg.upper };
                        x[other] + port(other, s) - port(v, s)
                    })
                    .collect();
                if targets.is_empty() {
                    continue;
                }
                let low = i
                    .checked_sub(1)
                    .and_then(|j| layer.get(j))
                    .map_or(f32::MIN, |&u| x[u] + separation(graph, spacing, u, v));
                let high = layer
                    .get(i + 1)
                    .map_or(f32::MAX, |&w| x[w] - separation(graph, spacing, v, w));
                if low > high {
                    continue;
                }
                let score = |at: f32| {
                    let straight = targets.iter().filter(|&&t| (t - at).abs() < 0.01).count();
                    let length: f32 = targets.iter().map(|&t| (t - at).abs()).sum();
                    (straight, length)
                };
                let mut sorted = targets.clone();
                sorted.sort_by(f32::total_cmp);
                let median = sorted.get(sorted.len() / 2).copied().unwrap_or(x[v]);
                let mut best = x[v];
                let mut best_score = score(best);
                for at in targets.iter().copied().chain([median.clamp(low, high)]) {
                    if at < low || at > high {
                        continue;
                    }
                    let s = score(at);
                    if s.0 > best_score.0 || (s.0 == best_score.0 && s.1 < best_score.1 - 0.5) {
                        best = at;
                        best_score = s;
                    }
                }
                x[v] = best;
            }
        }
    }
}

/// The segments to leave unaligned: those crossing a segment between two
/// edges' points (type 1 conflicts), so long edges stay straight.
fn conflicts(graph: &Layered) -> Arena<Sg, bool> {
    let mut marked: Arena<Sg, bool> = repeat_n(false, graph.segments.len()).collect();
    let inner = |s: Sg| {
        let s = &graph.segments[s];
        !graph.vertices[s.upper].real && !graph.vertices[s.lower].real
    };
    for pair in graph.layers.windows(2) {
        let [upper, lower] = pair else { continue };
        let last = lower.len().saturating_sub(1);
        let mut k0 = 0;
        let mut l = 0;
        for (l1, &v) in lower.iter().enumerate() {
            let inner_upper = graph.up[v]
                .iter()
                .find(|&&s| inner(s))
                .map(|&s| graph.pos[graph.segments[s].upper]);
            if l1 != last && inner_upper.is_none() {
                continue;
            }
            let k1 = inner_upper.unwrap_or(upper.len().saturating_sub(1));
            while l <= l1 {
                if let Some(&w) = lower.get(l) {
                    for &s in &graph.up[w] {
                        let k = graph.pos[graph.segments[s].upper];
                        if (k < k0 || k > k1) && !inner(s) {
                            marked[s] = true;
                        }
                    }
                }
                l += 1;
            }
            k0 = k1;
        }
    }
    marked
}

/// The separation between the centres of `a` and `b` side by side.
fn separation(graph: &Layered, spacing: &Spacing, a: Vx, b: Vx) -> f32 {
    let (va, vb) = (&graph.vertices[a], &graph.vertices[b]);
    let gap = match (va.real, vb.real) {
        (true, true) => spacing.node,
        (false, false) => spacing.track,
        (true, false) | (false, true) => spacing.track.max(spacing.node / 2.0),
    };
    f32::midpoint(va.width, vb.width) + gap
}

/// One of the four layouts: vertices aligned with their median neighbour
/// above (`downward`) or below, the layers read from the left or (mirrored)
/// from the right; coordinates as read (mirrored back by the caller's
/// balance only through `rightward`).
fn place(
    graph: &Layered,
    spacing: &Spacing,
    marked: &Arena<Sg, bool>,
    downward: bool,
    rightward: bool,
) -> Arena<Vx, f32> {
    let sign = if rightward { -1.0 } else { 1.0 };
    let ordered = |layer: &Vec<Vx>| {
        let mut l = layer.clone();
        if rightward {
            l.reverse();
        }
        l
    };
    let layers: Vec<Vec<Vx>> = if downward {
        graph.layers.iter().map(ordered).collect()
    } else {
        graph.layers.iter().rev().map(ordered).collect()
    };
    let (root, offset) = align(graph, marked, &layers, downward, rightward);
    let x = compact(graph, spacing, &layers, &root, &offset);
    graph
        .vertices
        .ids()
        .map(|v| sign * (x[root[v]] + offset[v]))
        .collect()
}

/// Each vertex's block (its root) and its offset from the root, aligning
/// each vertex of `layers` (in reading order) with a median neighbour in
/// the layer read before, unless that crosses an alignment made already.
fn align(
    graph: &Layered,
    marked: &Arena<Sg, bool>,
    layers: &[Vec<Vx>],
    downward: bool,
    rightward: bool,
) -> (Arena<Vx, Vx>, Arena<Vx, f32>) {
    let sign = if rightward { -1.0 } else { 1.0 };
    let at = |v: Vx| {
        let pos = graph.pos[v];
        if rightward {
            graph
                .layers
                .get(graph.vertices[v].layer)
                .map_or(0, |l| l.len() - 1 - pos)
        } else {
            pos
        }
    };
    let port = |v: Vx, s: Sg| {
        let s = &graph.segments[s];
        if s.upper == v {
            s.upper_port
        } else {
            s.lower_port
        }
    };
    let mut root: Arena<Vx, Vx> = graph.vertices.ids().collect();
    let mut align: Arena<Vx, Vx> = graph.vertices.ids().collect();
    let mut offset: Arena<Vx, f32> = repeat_n(0.0, graph.vertices.len()).collect();
    for layer in layers {
        let mut reach: Option<usize> = None;
        for &v in layer {
            let segments = if downward {
                &graph.up[v]
            } else {
                &graph.down[v]
            };
            let mut neighbours: Vec<(usize, Vx, Sg)> = segments
                .iter()
                .map(|&s| {
                    let seg = &graph.segments[s];
                    let u = if downward { seg.upper } else { seg.lower };
                    (at(u), u, s)
                })
                .collect();
            if neighbours.is_empty() {
                continue;
            }
            neighbours.sort_unstable();
            let degree = neighbours.len();
            let mut medians = vec![(degree - 1) / 2, degree / 2];
            medians.dedup();
            for m in medians {
                if align[v] != v {
                    break;
                }
                let Some(&(p, u, s)) = neighbours.get(m) else {
                    continue;
                };
                if !marked[s] && reach.is_none_or(|r| r < p) {
                    align[u] = v;
                    root[v] = root[u];
                    align[v] = root[v];
                    offset[v] = offset[u] + sign * (port(u, s) - port(v, s));
                    reach = Some(p);
                }
            }
        }
    }
    (root, offset)
}

/// Each block's place (by its root): as far left as the blocks left of it
/// in some layer allow, then right as far as those right of it do.
fn compact(
    graph: &Layered,
    spacing: &Spacing,
    layers: &[Vec<Vx>],
    root: &Arena<Vx, Vx>,
    offset: &Arena<Vx, f32>,
) -> Arena<Vx, f32> {
    let n = graph.vertices.len();
    // The graph of blocks: a block right of another in some layer is at
    // least their vertices' separation from it.
    let mut edges: Vec<(Vx, Vx, f32)> = Vec::new();
    for layer in layers {
        for pair in layer.windows(2) {
            let [a, b] = *pair else { continue };
            let w = separation(graph, spacing, a, b) + offset[a] - offset[b];
            edges.push((root[a], root[b], w));
        }
    }
    edges.sort_by(|x, y| x.0.cmp(&y.0).then(x.1.cmp(&y.1)).then(y.2.total_cmp(&x.2)));
    edges.dedup_by(|later, kept| later.0 == kept.0 && later.1 == kept.1);
    let mut preds: Arena<Vx, Vec<(Vx, f32)>> = repeat_n(Vec::new(), n).collect();
    let mut succs: Arena<Vx, Vec<(Vx, f32)>> = repeat_n(Vec::new(), n).collect();
    let mut indegree: Arena<Vx, usize> = repeat_n(0, n).collect();
    for &(a, b, w) in &edges {
        succs[a].push((b, w));
        preds[b].push((a, w));
        indegree[b] += 1;
    }
    let roots: Vec<Vx> = graph.vertices.ids().filter(|&v| root[v] == v).collect();
    let mut queue: Vec<Vx> = roots
        .iter()
        .copied()
        .filter(|&v| indegree[v] == 0)
        .rev()
        .collect();
    let mut topological = Vec::with_capacity(roots.len());
    while let Some(v) = queue.pop() {
        topological.push(v);
        for &(b, _) in &succs[v] {
            indegree[b] -= 1;
            if indegree[b] == 0 {
                queue.push(b);
            }
        }
    }
    // Alignment never crosses itself, so the graph of blocks has no cycle;
    // were one left, its blocks still get places.
    for &v in &roots {
        if indegree[v] > 0 {
            topological.push(v);
        }
    }
    let mut x: Arena<Vx, f32> = repeat_n(0.0, n).collect();
    for &v in &topological {
        if let Some(most) = preds[v]
            .iter()
            .map(|&(a, w)| x[a] + w)
            .max_by(f32::total_cmp)
        {
            x[v] = most;
        }
    }
    for &v in topological.iter().rev() {
        if let Some(least) = succs[v]
            .iter()
            .map(|&(b, w)| x[b] - w)
            .min_by(f32::total_cmp)
        {
            x[v] = x[v].max(least);
        }
    }
    x
}
