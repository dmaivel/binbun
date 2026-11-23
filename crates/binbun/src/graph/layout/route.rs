//! Orthogonal routes: each edge runs vertically through the layers (at its
//! ports and its points) and horizontally in the gaps between them, each
//! horizontal run on a track of its own among those it overlaps.

#![expect(
    clippy::indexing_slicing,
    reason = "vertex and edge ids index the arenas of the layered graph that made them"
)]

use std::iter::repeat_n;

use binbun_semantics::core::{Arena, Id};

use super::{Ed, Layered, Layout, Point, Rect, Route, Size, Spacing, Vx, count};

/// Which way a run's end leaves its track: up to the layer above, or down
/// to the layer below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Up,
    Down,
}

/// A horizontal run of an edge in a gap.
#[derive(Clone, Copy, Debug)]
struct Run {
    ends: [(f32, Side, Column); 2],
    track: usize,
}

/// What a vertical end of a run is: a point of an edge's (moving it moves
/// the edge through the point's layer), or a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Column {
    Point(Vx),
    Out(Ed),
    In(Ed),
}

/// Where the columns are.
struct Columns {
    x: Arena<Vx, f32>,
    ports: Arena<Ed, (f32, f32)>,
}

impl Columns {
    fn at(&self, graph: &Layered, column: Column) -> f32 {
        match column {
            Column::Point(v) => self.x[v],
            Column::Out(e) => self.x[graph.chains[e].from] + self.ports[e].0,
            Column::In(e) => self.x[graph.chains[e].to] + self.ports[e].1,
        }
    }

    fn shift(&mut self, column: Column, by: f32) {
        match column {
            Column::Point(v) => self.x[v] += by,
            Column::Out(e) => self.ports[e].0 += by,
            Column::In(e) => self.ports[e].1 += by,
        }
    }
}

/// Each gap's runs (gap `g` is above layer `g`, gap `depth` below the
/// last), and each edge's runs as (gap, index in the gap) in its order.
type Runs = (Vec<Vec<Run>>, Arena<Ed, Vec<(usize, usize)>>);

/// The runs of `graph`'s edges between its layers with columns at
/// `columns`.
fn runs(graph: &Layered, columns: &Columns) -> Runs {
    let mut gaps: Vec<Vec<Run>> = repeat_n(Vec::new(), graph.layers.len() + 1).collect();
    let mut steps: Arena<Ed, Vec<(usize, usize)>> =
        repeat_n(Vec::new(), graph.chains.len()).collect();
    for (e, chain) in graph.chains.iter() {
        if !chain.valid {
            continue;
        }
        let end = |column: Column, side: Side| (columns.at(graph, column), side, column);
        let from_layer = graph.vertices[chain.from].layer;
        let mut push =
            |gap: usize, a: (f32, Side, Column), b: (f32, Side, Column), always: bool| {
                if !always && (a.0 - b.0).abs() < 0.01 {
                    return;
                }
                if let Some(runs) = gaps.get_mut(gap) {
                    steps[e].push((gap, runs.len()));
                    runs.push(Run {
                        ends: [a, b],
                        track: 0,
                    });
                }
            };
        if chain.back {
            // Down out of the source, over to the riser, up the layers,
            // over to the target, down into it.
            let mut previous = end(Column::Out(e), Side::Up);
            let mut gap = from_layer + 1;
            for &d in &chain.points {
                let first = gap == from_layer + 1;
                push(gap, previous, end(Column::Point(d), Side::Up), first);
                previous = end(Column::Point(d), Side::Down);
                gap = graph.vertices[d].layer;
            }
            push(gap, previous, end(Column::In(e), Side::Down), true);
        } else {
            let mut previous = Column::Out(e);
            let mut gap = from_layer + 1;
            for &d in &chain.points {
                let next = Column::Point(d);
                push(gap, end(previous, Side::Up), end(next, Side::Down), false);
                previous = next;
                gap += 1;
            }
            push(
                gap,
                end(previous, Side::Up),
                end(Column::In(e), Side::Down),
                false,
            );
        }
    }
    (gaps, steps)
}

/// Runs that go up where the next goes down, round a cycle (edges trading
/// columns across a gap), would lie on each other whatever their order:
/// in the first such cycle, an end going down where another run goes up,
/// to be moved towards its own run's other end.
fn trade(gaps: &[Vec<Run>], near: f32) -> Option<(Column, f32)> {
    // `b`'s end going down where `a` goes up: `a` must be above `b`.
    let meets = |a: &Run, b: &Run| {
        b.ends.iter().find_map(|eb| {
            (eb.1 == Side::Down
                && a.ends
                    .iter()
                    .any(|ea| ea.1 == Side::Up && (ea.0 - eb.0).abs() < near))
            .then_some(*eb)
        })
    };
    for runs in gaps {
        let n = runs.len();
        // Depth-first search of the musts for a cycle.
        let mut state = vec![0u8; n];
        for start in 0..n {
            if state.get(start) != Some(&0) {
                continue;
            }
            let mut stack = vec![(start, 0usize)];
            if let Some(s) = state.get_mut(start) {
                *s = 1;
            }
            while let Some(&mut (a, ref mut next)) = stack.last_mut() {
                let Some(run_a) = runs.get(a) else { break };
                if let Some(b) = (*next..n)
                    .find(|&b| b != a && runs.get(b).is_some_and(|rb| meets(run_a, rb).is_some()))
                {
                    *next = b + 1;
                    match state.get(b) {
                        Some(0) => {
                            if let Some(s) = state.get_mut(b) {
                                *s = 1;
                            }
                            stack.push((b, 0));
                        }
                        Some(1) => {
                            let run_b = runs.get(b)?;
                            let down = meets(run_a, run_b)?;
                            let other = if run_b.ends[0].2 == down.2 {
                                run_b.ends[1]
                            } else {
                                run_b.ends[0]
                            };
                            return Some((down.2, (other.0 - down.0).signum()));
                        }
                        _ => {}
                    }
                } else {
                    if let Some(s) = state.get_mut(a) {
                        *s = 2;
                    }
                    stack.pop();
                }
            }
        }
    }
    None
}

impl Run {
    fn low(&self) -> f32 {
        self.ends[0].0.min(self.ends[1].0)
    }

    fn high(&self) -> f32 {
        self.ends[0].0.max(self.ends[1].0)
    }
}

/// Where the gaps and layers are, top to bottom.
struct Heights {
    gap_top: Vec<f32>,
    gap_height: Vec<f32>,
    layer_top: Vec<f32>,
    /// Everything's.
    total: f32,
}

/// The heights of `graph`'s layers (each its tallest node's) and gaps
/// (each as its `tracks` need, the top and bottom ones nothing without).
fn heights(graph: &Layered, sizes: &[Size], tracks: &[usize], spacing: &Spacing) -> Heights {
    let depth = graph.layers.len();
    let mut band: Vec<f32> = repeat_n(0.0f32, depth).collect();
    for (v, size) in sizes.iter().enumerate() {
        let layer = graph.vertices[Vx::from_index(v)].layer;
        if let Some(h) = band.get_mut(layer) {
            *h = h.max(size.height);
        }
    }
    let mut out = Heights {
        gap_top: Vec::with_capacity(depth + 1),
        gap_height: Vec::with_capacity(depth + 1),
        layer_top: Vec::with_capacity(depth),
        total: 0.0,
    };
    let mut y = 0.0;
    for (g, &n) in tracks.iter().enumerate() {
        let edge = g == 0 || g == depth;
        let height = if n == 0 {
            if edge { 0.0 } else { spacing.layer }
        } else {
            spacing.layer.max(count(n + 1) * spacing.track)
        };
        out.gap_top.push(y);
        out.gap_height.push(height);
        y += height;
        if let Some(&h) = band.get(g) {
            out.layer_top.push(y);
            y += h;
        }
    }
    out.total = y;
    out
}

/// The columns of `graph`'s edges, from centres `x` and the ports, with
/// the columns of edges trading places across a gap moved aside; the
/// runs between them.
fn settle_columns(graph: &Layered, x: &Arena<Vx, f32>, spacing: &Spacing) -> (Columns, Runs) {
    let near = spacing.track / 4.0;
    let mut columns = Columns {
        x: x.clone(),
        ports: graph
            .chains
            .values()
            .map(|c| (c.out_port, c.in_port))
            .collect(),
    };
    let (mut gaps, mut steps) = runs(graph, &columns);
    // Edges trading columns: one moved aside, until none (or a bound).
    for _ in 0..graph.chains.len() {
        let Some((column, towards)) = trade(&gaps, near) else {
            break;
        };
        columns.shift(column, towards * spacing.track / 2.0);
        (gaps, steps) = runs(graph, &columns);
    }
    (columns, (gaps, steps))
}

/// The layout of `graph` with centres `x`.
pub(super) fn route(
    graph: &Layered,
    x: &Arena<Vx, f32>,
    sizes: &[Size],
    spacing: &Spacing,
) -> Layout {
    let near = spacing.track / 4.0;
    let (columns, (mut gaps, steps)) = settle_columns(graph, x, spacing);
    let x = &columns.x;
    let tracks: Vec<usize> = gaps
        .iter_mut()
        .map(|runs| assign(runs, spacing.track, near))
        .collect();
    let Heights {
        gap_top,
        gap_height,
        layer_top,
        total: height,
    } = heights(graph, sizes, &tracks, spacing);
    let track_y = |gap: usize, track: usize| {
        let n = tracks.get(gap).copied().unwrap_or(1);
        let top = gap_top.get(gap).copied().unwrap_or(0.0);
        let h = gap_height.get(gap).copied().unwrap_or(0.0);
        top + (h - count(n.saturating_sub(1)) * spacing.track) / 2.0 + count(track) * spacing.track
    };
    let (mut left, mut right) = (f32::MAX, f32::MIN);
    for (v, vertex) in graph.vertices.iter() {
        left = left.min(x[v] - vertex.width / 2.0);
        right = right.max(x[v] + vertex.width / 2.0);
    }
    let nodes: Vec<Rect> = sizes
        .iter()
        .enumerate()
        .map(|(v, size)| {
            let v = Vx::from_index(v);
            Rect {
                x: x[v] - size.width / 2.0 - left,
                y: layer_top
                    .get(graph.vertices[v].layer)
                    .copied()
                    .unwrap_or(0.0),
                width: size.width,
                height: size.height,
            }
        })
        .collect();
    let edges = graph
        .chains
        .iter()
        .map(|(e, chain)| {
            if !chain.valid {
                return Route::default();
            }
            let (Some(from), Some(to)) =
                (nodes.get(chain.from.index()), nodes.get(chain.to.index()))
            else {
                return Route::default();
            };
            let mut points = vec![Point {
                x: columns.at(graph, Column::Out(e)) - left,
                y: from.bottom(),
            }];
            for &(gap, run) in &steps[e] {
                let Some(r) = gaps.get(gap).and_then(|runs| runs.get(run)) else {
                    continue;
                };
                let y = track_y(gap, r.track);
                points.push(Point {
                    x: r.ends[0].0 - left,
                    y,
                });
                points.push(Point {
                    x: r.ends[1].0 - left,
                    y,
                });
            }
            points.push(Point {
                x: columns.at(graph, Column::In(e)) - left,
                y: to.y,
            });
            Route {
                points: simplify(points),
                back: chain.back,
            }
        })
        .collect();
    Layout {
        nodes,
        edges,
        width: (right - left).max(0.0),
        height,
    }
}

/// `points` without repeats and without points in the middle of a
/// straight run.
fn simplify(points: Vec<Point>) -> Vec<Point> {
    let mut out: Vec<Point> = Vec::with_capacity(points.len());
    for p in points {
        if out
            .last()
            .is_some_and(|q| (q.x - p.x).abs() < 0.01 && (q.y - p.y).abs() < 0.01)
        {
            continue;
        }
        if let [.., a, b] = out.as_slice() {
            let vertical = (a.x - b.x).abs() < 0.01 && (b.x - p.x).abs() < 0.01;
            let horizontal = (a.y - b.y).abs() < 0.01 && (b.y - p.y).abs() < 0.01;
            if vertical || horizontal {
                out.pop();
            }
        }
        out.push(p);
    }
    out
}

/// What decides the tracks of a gap's runs.
struct Order {
    /// Each run's runs whose spans come near its own.
    conflicts: Vec<Vec<usize>>,
    /// Each run's runs to put below it, and whether that is a must.
    above: Vec<Vec<(usize, bool)>>,
    /// How many runs each must be below.
    indegree: Vec<usize>,
    /// How many of those are musts.
    musts: Vec<usize>,
}

/// The order of `runs`: runs whose spans come within `margin` of each
/// other conflict; a run whose end goes up at the place another's goes
/// down (within `near`) must be above it; otherwise the one whose being
/// above crosses fewer vertical ends goes above.
fn order(runs: &[Run], margin: f32, near: f32) -> Order {
    let n = runs.len();
    let overlaps = |a: &Run, b: &Run| a.low() < b.high() + margin && b.low() < a.high() + margin;
    // Crossings if `a` is above `b`: `a`'s ends going down through `b`'s
    // span, `b`'s going up through `a`'s.
    let cost = |a: &Run, b: &Run| {
        let through = |x: f32, r: &Run| x > r.low() + 0.5 && x < r.high() - 0.5;
        a.ends
            .iter()
            .filter(|e| e.1 == Side::Down && through(e.0, b))
            .count()
            + b.ends
                .iter()
                .filter(|e| e.1 == Side::Up && through(e.0, a))
                .count()
    };
    // A vertical end of `a` going up where one of `b` goes down: `a` must
    // be above, or the two would lie on each other.
    let must = |a: &Run, b: &Run| {
        a.ends.iter().any(|ea| {
            ea.1 == Side::Up
                && b.ends
                    .iter()
                    .any(|eb| eb.1 == Side::Down && (ea.0 - eb.0).abs() < near)
        })
    };
    let mut conflicts: Vec<Vec<usize>> = repeat_n(Vec::new(), n).collect();
    let mut above: Vec<Vec<(usize, bool)>> = repeat_n(Vec::new(), n).collect();
    let mut indegree: Vec<usize> = repeat_n(0, n).collect();
    let mut musts: Vec<usize> = repeat_n(0, n).collect();
    for i in 0..n {
        for j in i + 1..n {
            let (Some(a), Some(b)) = (runs.get(i), runs.get(j)) else {
                continue;
            };
            if !overlaps(a, b) {
                continue;
            }
            if let Some(c) = conflicts.get_mut(i) {
                c.push(j);
            }
            if let Some(c) = conflicts.get_mut(j) {
                c.push(i);
            }
            let (ij, ji) = (cost(a, b), cost(b, a));
            let order = if must(a, b) && !must(b, a) {
                Some((i, j, true))
            } else if must(b, a) && !must(a, b) {
                Some((j, i, true))
            } else if ij < ji {
                Some((i, j, false))
            } else if ji < ij {
                Some((j, i, false))
            } else {
                None
            };
            if let Some((upper, lower, hard)) = order {
                if let Some(list) = above.get_mut(upper) {
                    list.push((lower, hard));
                }
                if let Some(d) = indegree.get_mut(lower) {
                    *d += 1;
                }
                if hard && let Some(d) = musts.get_mut(lower) {
                    *d += 1;
                }
            }
        }
    }
    Order {
        conflicts,
        above,
        indegree,
        musts,
    }
}

/// Gives each run of a gap a track (0 the top) in their [`order`]:
/// conflicting runs on different tracks, each below those it must or
/// should be below (a cycle of preferences broken where no must is).
/// Returns the number of tracks.
fn assign(runs: &mut [Run], margin: f32, near: f32) -> usize {
    let n = runs.len();
    if n == 0 {
        return 0;
    }
    let Order {
        conflicts,
        above,
        mut indegree,
        mut musts,
    } = order(runs, margin, near);
    let mut floor: Vec<usize> = repeat_n(0, n).collect();
    let mut track: Vec<Option<usize>> = repeat_n(None, n).collect();
    let mut done = 0;
    let mut ready: Vec<usize> = (0..n)
        .rev()
        .filter(|&i| indegree.get(i) == Some(&0))
        .collect();
    while done < n {
        // A cycle of preferences: the first run left that no must keeps
        // waiting breaks it.
        let left = |i: &usize| track.get(*i).is_some_and(Option::is_none);
        let Some(i) = ready.pop().or_else(|| {
            (0..n)
                .filter(left)
                .find(|&i| musts.get(i) == Some(&0))
                .or_else(|| (0..n).find(left))
        }) else {
            break;
        };
        if track.get(i).is_some_and(Option::is_some) {
            continue;
        }
        let taken: Vec<usize> = conflicts
            .get(i)
            .into_iter()
            .flatten()
            .filter_map(|&j| track.get(j).copied().flatten())
            .collect();
        let mut t = floor.get(i).copied().unwrap_or(0);
        while taken.contains(&t) {
            t += 1;
        }
        if let Some(slot) = track.get_mut(i) {
            *slot = Some(t);
        }
        done += 1;
        for &(j, hard) in above.get(i).into_iter().flatten() {
            if let Some(f) = floor.get_mut(j) {
                *f = (*f).max(t + 1);
            }
            if hard && let Some(d) = musts.get_mut(j) {
                *d = d.saturating_sub(1);
            }
            if let Some(d) = indegree.get_mut(j) {
                *d = d.saturating_sub(1);
                if *d == 0 && track.get(j).is_some_and(Option::is_none) {
                    ready.push(j);
                }
            }
        }
    }
    let mut tracks = 0;
    for (run, t) in runs.iter_mut().zip(track) {
        run.track = t.unwrap_or(0);
        tracks = tracks.max(run.track + 1);
    }
    tracks
}
