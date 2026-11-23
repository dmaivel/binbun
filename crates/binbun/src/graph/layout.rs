//! A layered (Sugiyama) layout of a directed graph of sized nodes, drawn as
//! disassemblers usually draw control-flow graphs: the root on top, edges
//! going down, orthogonal edges with their bends between layers.
//!
//! 1. **Cycles.** A depth-first search from the root (then from every node
//!    not reached yet, in order) finds the back edges: those to a node on
//!    the search's stack. They are not reversed but routed as loops: down
//!    out of their source, up beside the layers between, down into their
//!    target.
//! 2. **Layers.** Each node's layer is its longest path from a source over
//!    the other edges, so every forward edge goes at least one layer down
//!    and the root is alone in layer 0 among the nodes it reaches.
//! 3. **Order.** An edge spanning layers gets a point in each layer it
//!    crosses (a back edge in each layer from its target's to its
//!    source's, the ends beside them); each layer is ordered by barycentre
//!    sweeps, down and up, keeping the order with the fewest crossings.
//! 4. **Ports.** Edges leave a node's bottom and enter its top at points
//!    spread across its width, in the order of their [`Edge::order`] (a
//!    conditional's not-taken edge left of its taken one), then of where
//!    they go.
//! 5. **Coordinates.** Brandes and Köpf's: the four alignments of each
//!    node with a median neighbour (ports included, so an edge between
//!    single ports is vertical), compacted against widths, and balanced.
//! 6. **Routes.** In each gap between layers an edge's horizontal run gets
//!    a track of its own among those it overlaps, ordered to cross as few
//!    of the other edges' vertical runs as possible; the gaps grow to hold
//!    their tracks.
//!
//! Nothing depends on hashing or on anything but the input, so the same
//! graph gets the same layout.

#![expect(
    clippy::indexing_slicing,
    reason = "vertex, segment and edge ids index the arenas of the layered graph that made them"
)]

mod coord;
mod order;
mod route;

use std::iter::repeat_n;
use std::ops::Range;

use binbun_semantics::core::{Arena, Id};

/// A node's size.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Size {
    /// Its width.
    pub width: f32,
    /// Its height.
    pub height: f32,
}

/// An edge to lay out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Edge {
    /// Its source node's index.
    pub from: usize,
    /// Its target node's index.
    pub to: usize,
    /// Where it leaves its source among the source's edges: lower to the
    /// left (ties by where they go).
    pub order: u8,
}

/// The distances between things, in the units of the sizes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Spacing {
    /// Between two nodes side by side.
    pub node: f32,
    /// The least gap between two layers.
    pub layer: f32,
    /// Between two parallel edge runs, and between an edge and a node it
    /// passes.
    pub track: f32,
}

impl Default for Spacing {
    fn default() -> Self {
        Self {
            node: 24.0,
            layer: 28.0,
            track: 8.0,
        }
    }
}

/// A point.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Point {
    /// Rightwards.
    pub x: f32,
    /// Downwards.
    pub y: f32,
}

/// A rectangle, by its top left corner.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rect {
    /// Its left.
    pub x: f32,
    /// Its top.
    pub y: f32,
    /// Its width.
    pub width: f32,
    /// Its height.
    pub height: f32,
}

impl Rect {
    /// Its right.
    pub fn right(&self) -> f32 {
        self.x + self.width
    }

    /// Its bottom.
    pub fn bottom(&self) -> f32 {
        self.y + self.height
    }

    /// Whether it and `other` share any area.
    pub fn intersects(&self, other: &Self) -> bool {
        self.x < other.right()
            && other.x < self.right()
            && self.y < other.bottom()
            && other.y < self.bottom()
    }
}

/// An edge's route.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Route {
    /// Its points, from its source's bottom to its target's top; each run
    /// between two is vertical or horizontal. Empty for an edge whose ends
    /// are not nodes.
    pub points: Vec<Point>,
    /// Whether it goes back up (a loop).
    pub back: bool,
}

/// A laid out graph.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Layout {
    /// The nodes' places, as the sizes were given.
    pub nodes: Vec<Rect>,
    /// The edges' routes, as the edges were given.
    pub edges: Vec<Route>,
    /// The width of everything.
    pub width: f32,
    /// The height of everything.
    pub height: f32,
}

/// A vertex of the layered graph: a node, or a point where an edge
/// crosses a layer (a node's id is its index).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Id)]
struct Vx(u32);

/// An edge, by its index in the input.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Id)]
struct Ed(u32);

/// A run of an edge between two adjacent layers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Id)]
struct Sg(u32);

/// A vertex beside a node (listed in [`Layered::anchored`]): the end of a
/// back edge's riser.
#[derive(Clone, Copy, Debug)]
struct Anchor {
    right: bool,
    /// Its place among the node's anchors on that side, nearest first.
    rank: usize,
}

#[derive(Clone, Copy, Debug)]
struct Vertex {
    layer: usize,
    width: f32,
    /// Whether it is a node.
    real: bool,
    anchor: Option<Anchor>,
}

#[derive(Clone, Copy, Debug)]
struct Segment {
    upper: Vx,
    lower: Vx,
    edge: Ed,
    /// Port offsets from the centres of the ends (nodes' ports; 0 for an
    /// edge's own points).
    upper_port: f32,
    lower_port: f32,
    /// How much its upper end counts as right of the vertex, in places, for
    /// the order: a conditional's edges pull their targets to their sides.
    bias: f64,
}

/// How an edge goes through the layers.
#[derive(Clone, Debug)]
struct Chain {
    valid: bool,
    from: Vx,
    to: Vx,
    back: bool,
    /// Its [`Edge::order`].
    order: u8,
    /// The points it crosses layers at: a forward edge's from its
    /// source's layer down, a back edge's from its source's layer up.
    points: Vec<Vx>,
    out_port: f32,
    in_port: f32,
}

impl Chain {
    /// The chain of an edge from `from` to `to`, not laid out yet.
    fn new(from: Vx, to: Vx, back: bool, order: u8) -> Self {
        Self {
            valid: true,
            from,
            to,
            back,
            order,
            points: Vec::new(),
            out_port: 0.0,
            in_port: 0.0,
        }
    }
}

/// The layered graph.
#[derive(Debug)]
struct Layered {
    vertices: Arena<Vx, Vertex>,
    segments: Arena<Sg, Segment>,
    /// Each vertex's segments to the layer above, and below.
    up: Arena<Vx, Vec<Sg>>,
    down: Arena<Vx, Vec<Sg>>,
    /// Each node's anchored vertices.
    anchored: Arena<Vx, Vec<Vx>>,
    layers: Vec<Vec<Vx>>,
    pos: Arena<Vx, usize>,
    chains: Arena<Ed, Chain>,
    /// Each node's edges out, in [`Edge::order`] then input order.
    out: Arena<Vx, Vec<Ed>>,
    /// Each node's edges in.
    into: Arena<Vx, Vec<Ed>>,
}

/// `n` as a coordinate.
fn count(n: usize) -> f32 {
    f32::from(u16::try_from(n).unwrap_or(u16::MAX))
}

/// `n` as a position to average.
fn place(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

/// Lays out the graph of nodes of `sizes` and `edges` with `root` on top
/// (node 0 if `root` is not a node). Edges whose ends are not nodes get
/// empty routes.
pub fn layout(sizes: &[Size], edges: &[Edge], root: usize, spacing: &Spacing) -> Layout {
    if sizes.is_empty() {
        return Layout {
            nodes: Vec::new(),
            edges: repeat_n(Route::default(), edges.len()).collect(),
            width: 0.0,
            height: 0.0,
        };
    }
    let root = Vx::from_index(if root < sizes.len() { root } else { 0 });
    let edges: Arena<Ed, Edge> = edges.iter().copied().collect();
    let mut graph = Layered::new(sizes, &edges, root);
    order::minimise(&mut graph, root);
    graph.ports(sizes);
    let x = coord::assign(&graph, spacing);
    route::route(&graph, &x, sizes, spacing)
}

impl Layered {
    /// The layered graph of `sizes` and `edges`: back edges found, layers,
    /// each edge's points.
    fn new(sizes: &[Size], edges: &Arena<Ed, Edge>, root: Vx) -> Self {
        let n = sizes.len();
        let valid = |e: &Edge| e.from < n && e.to < n;
        let mut out: Arena<Vx, Vec<Ed>> = repeat_n(Vec::new(), n).collect();
        let mut into: Arena<Vx, Vec<Ed>> = repeat_n(Vec::new(), n).collect();
        for (id, e) in edges.iter().filter(|(_, e)| valid(e)) {
            out[Vx::from_index(e.from)].push(id);
            into[Vx::from_index(e.to)].push(id);
        }
        for (_, list) in out.iter_mut() {
            list.sort_by_key(|&e| (edges[e].order, e));
        }
        let (back, post) = depth_first(&out, edges, root);
        let mut layer: Arena<Vx, usize> = repeat_n(0, n).collect();
        for &v in post.iter().rev() {
            for &e in &out[v] {
                if !back[e] {
                    let w = Vx::from_index(edges[e].to);
                    layer[w] = layer[w].max(layer[v] + 1);
                }
            }
        }
        let vertices: Arena<Vx, Vertex> = sizes
            .iter()
            .zip(layer.values())
            .map(|(size, &layer)| Vertex {
                layer,
                width: size.width,
                real: true,
                anchor: None,
            })
            .collect();
        let none = Chain {
            valid: false,
            ..Chain::new(root, root, false, 0)
        };
        let mut graph = Self {
            vertices,
            segments: Arena::new(),
            up: Arena::new(),
            down: Arena::new(),
            anchored: repeat_n(Vec::new(), n).collect(),
            layers: Vec::new(),
            pos: Arena::new(),
            chains: repeat_n(none, edges.len()).collect(),
            out,
            into,
        };
        // Chains in the order of each node's edges out, so the vertices'
        // ids follow it.
        for u in (0..n).map(Vx::from_index) {
            let list = graph.out[u].clone();
            let keys: Vec<u8> = list.iter().map(|&e| edges[e].order).collect();
            let (low, high) = (
                keys.iter().copied().min().unwrap_or(0),
                keys.iter().copied().max().unwrap_or(0),
            );
            let mut distinct = keys.clone();
            distinct.dedup();
            for e in list {
                let edge = edges[e];
                let v = Vx::from_index(edge.to);
                let mut chain = Chain::new(u, v, back[e], edge.order);
                if back[e] {
                    // On the right if it is the source's last edge of
                    // several, else on the left.
                    let right = edge.order == high && low < high;
                    graph.back_chain(&mut chain, e, (layer[v], layer[u]), right);
                } else {
                    let bias = if distinct.len() > 1 {
                        let rank = distinct.iter().position(|&k| k == edge.order).unwrap_or(0);
                        (place(rank) - place(distinct.len() - 1) / 2.0) * 0.4
                    } else {
                        0.0
                    };
                    graph.forward_chain(&mut chain, e, layer[u] + 1..layer[v], bias);
                }
                graph.chains[e] = chain;
            }
        }
        graph.index(layer.values().copied().max().unwrap_or(0) + 1);
        graph
    }

    /// A point of an edge's in `layer`.
    fn point(&mut self, layer: usize) -> Vx {
        self.anchored.push(Vec::new());
        self.vertices.push(Vertex {
            layer,
            width: 0.0,
            real: false,
            anchor: None,
        })
    }

    /// A segment of edge `edge` from `upper` down to `lower`.
    fn segment(&mut self, upper: Vx, lower: Vx, edge: Ed, bias: f64) {
        self.segments.push(Segment {
            upper,
            lower,
            edge,
            upper_port: 0.0,
            lower_port: 0.0,
            bias,
        });
    }

    /// Forward edge `e`'s points in `layers` (those between its ends), its
    /// first segment pulled by `bias`.
    fn forward_chain(&mut self, chain: &mut Chain, e: Ed, layers: Range<usize>, bias: f64) {
        let mut previous = chain.from;
        for l in layers {
            let d = self.point(l);
            let b = if previous == chain.from { bias } else { 0.0 };
            self.segment(previous, d, e, b);
            chain.points.push(d);
            previous = d;
        }
        let b = if previous == chain.from { bias } else { 0.0 };
        self.segment(previous, chain.to, e, b);
    }

    /// Back edge `e`'s points: up beside its source, the layers between,
    /// and beside its target (`layers`: the target's and the source's),
    /// on the `right` side or the left.
    fn back_chain(&mut self, chain: &mut Chain, e: Ed, layers: (usize, usize), right: bool) {
        for l in (layers.0..=layers.1).rev() {
            let d = self.point(l);
            if let Some(&below) = chain.points.last() {
                self.segment(d, below, e, 0.0);
            }
            chain.points.push(d);
        }
        let ends = [
            (chain.points.first().copied(), chain.from),
            (chain.points.last().copied(), chain.to),
        ];
        let single = chain.points.len() == 1;
        for (k, (d, node)) in ends.into_iter().enumerate() {
            let Some(d) = d else { continue };
            if single && k == 1 {
                break;
            }
            let rank = self.anchored[node]
                .iter()
                .filter(|&&a| self.vertices[a].anchor.is_some_and(|a| a.right == right))
                .count();
            self.vertices[d].anchor = Some(Anchor { right, rank });
            self.anchored[node].push(d);
        }
    }

    /// Indexes the segments by vertex and the vertices by layer (`depth`
    /// of them).
    fn index(&mut self, depth: usize) {
        let n = self.vertices.len();
        self.up = repeat_n(Vec::new(), n).collect();
        self.down = repeat_n(Vec::new(), n).collect();
        for (id, s) in self.segments.iter() {
            self.down[s.upper].push(id);
            self.up[s.lower].push(id);
        }
        self.layers = repeat_n(Vec::new(), depth).collect();
        for (id, v) in self.vertices.iter() {
            if let Some(list) = self.layers.get_mut(v.layer) {
                list.push(id);
            }
        }
        self.pos = repeat_n(0, n).collect();
    }

    /// Puts the anchored vertices of `layer` (whose others are in order)
    /// beside their nodes, and numbers the places.
    fn settle(&mut self, layer: usize, free: Vec<Vx>) {
        let mut placed = Vec::with_capacity(free.len());
        for v in free {
            let mut beside: Vec<(bool, usize, Vx)> = self.anchored[v]
                .iter()
                .filter(|&&a| self.vertices[a].layer == layer)
                .filter_map(|&a| self.vertices[a].anchor.map(|x| (x.right, x.rank, a)))
                .collect();
            beside.sort_unstable();
            let (right, left): (Vec<_>, Vec<_>) = beside.into_iter().partition(|b| b.0);
            placed.extend(left.iter().rev().map(|b| b.2));
            placed.push(v);
            placed.extend(right.iter().map(|b| b.2));
        }
        for (i, &v) in placed.iter().enumerate() {
            self.pos[v] = i;
        }
        if let Some(slot) = self.layers.get_mut(layer) {
            *slot = placed;
        }
    }

    /// Spreads each node's edges across its bottom (out) and top (in): by
    /// [`Edge::order`], then by where they go (or come from) in the order,
    /// a back edge on its riser's side.
    fn ports(&mut self, sizes: &[Size]) {
        for (index, size) in sizes.iter().enumerate() {
            let v = Vx::from_index(index);
            let side = |chain: &Chain, out: bool| -> f64 {
                let neighbour = if chain.back {
                    let end = if out {
                        chain.points.first()
                    } else {
                        chain.points.last()
                    };
                    return match end.and_then(|&d| self.vertices[d].anchor) {
                        Some(a) if a.right => f64::MAX,
                        _ => f64::MIN,
                    };
                } else if out {
                    chain.points.first().copied().unwrap_or(chain.to)
                } else {
                    chain.points.last().copied().unwrap_or(chain.from)
                };
                place(self.pos[neighbour])
            };
            let mut outs: Vec<(u8, f64, Ed)> = self.out[v]
                .iter()
                .map(|&e| (self.chains[e].order, side(&self.chains[e], true), e))
                .collect();
            outs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)).then(a.2.cmp(&b.2)));
            let mut ins: Vec<(f64, Ed)> = self.into[v]
                .iter()
                .map(|&e| (side(&self.chains[e], false), e))
                .collect();
            ins.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
            let spread = |k: usize, i: usize| {
                let step = size.width / count(k + 1);
                step * count(i + 1) - size.width / 2.0
            };
            for (i, &(_, _, e)) in outs.iter().enumerate() {
                self.chains[e].out_port = spread(outs.len(), i);
            }
            for (i, &(_, e)) in ins.iter().enumerate() {
                self.chains[e].in_port = spread(ins.len(), i);
            }
        }
        let ports: Vec<(f32, f32)> = self
            .segments
            .values()
            .map(|s| {
                let chain = &self.chains[s.edge];
                (
                    if self.vertices[s.upper].real {
                        chain.out_port
                    } else {
                        0.0
                    },
                    if self.vertices[s.lower].real {
                        chain.in_port
                    } else {
                        0.0
                    },
                )
            })
            .collect();
        for ((_, s), (upper, lower)) in self.segments.iter_mut().zip(ports) {
            s.upper_port = upper;
            s.lower_port = lower;
        }
    }
}

/// The back edges of a depth-first search from `root`, then from each
/// node not reached yet: edges to a node on the search's stack (a node's
/// edges in the order of `out`). Also the nodes in post-order.
fn depth_first(
    out: &Arena<Vx, Vec<Ed>>,
    edges: &Arena<Ed, Edge>,
    root: Vx,
) -> (Arena<Ed, bool>, Vec<Vx>) {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        New,
        Open,
        Done,
    }
    let n = out.len();
    let mut state: Arena<Vx, State> = repeat_n(State::New, n).collect();
    let mut back: Arena<Ed, bool> = repeat_n(false, edges.len()).collect();
    let mut post = Vec::with_capacity(n);
    let mut stack: Vec<(Vx, usize)> = Vec::new();
    for start in std::iter::once(root).chain((0..n).map(Vx::from_index)) {
        if state[start] != State::New {
            continue;
        }
        state[start] = State::Open;
        stack.push((start, 0));
        while let Some(top) = stack.last_mut() {
            let (v, i) = *top;
            if let Some(&e) = out[v].get(i) {
                top.1 += 1;
                let w = Vx::from_index(edges[e].to);
                match state[w] {
                    State::New => {
                        state[w] = State::Open;
                        stack.push((w, 0));
                    }
                    State::Open => back[e] = true,
                    State::Done => {}
                }
            } else {
                state[v] = State::Done;
                post.push(v);
                stack.pop();
            }
        }
    }
    (back, post)
}
