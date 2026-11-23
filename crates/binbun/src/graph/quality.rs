//! What makes a drawn graph hard to follow, counted: edges on top of each
//! other, edges through or along nodes, shared ports, crossings.

use crate::graph::layout::{Edge, Layout, Point, Rect};

/// How far apart two things must be to be told apart.
const APART: f32 = 0.5;

/// The faults of a layout, and its crossings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quality {
    /// Pairs of runs of two edges crossing at a right angle.
    pub crossings: usize,
    /// Pairs of runs of two edges lying on each other.
    pub overlapping: usize,
    /// Bends or ends of an edge lying on a run of another (a T, read as a
    /// join).
    pub touching: usize,
    /// Runs passing through a node.
    pub through_nodes: usize,
    /// Runs lying along a node's border.
    pub along_borders: usize,
    /// Pairs of edges leaving a node, or entering one, at the same point.
    pub shared_ports: usize,
    /// Pairs of nodes overlapping.
    pub overlapping_nodes: usize,
    /// Edges not running from their source's bottom to their target's top
    /// in vertical and horizontal runs.
    pub detached: usize,
}

impl Quality {
    /// Whether nothing is at fault (crossings are not faults).
    pub fn is_clean(&self) -> bool {
        Self {
            crossings: 0,
            ..*self
        } == Self::default()
    }
}

/// A vertical or horizontal run of edge `edge`.
#[derive(Clone, Copy, Debug)]
struct Run {
    edge: usize,
    a: Point,
    b: Point,
}

impl Run {
    fn vertical(&self) -> bool {
        (self.a.x - self.b.x).abs() < 0.01
    }

    fn x(&self) -> (f32, f32) {
        (self.a.x.min(self.b.x), self.a.x.max(self.b.x))
    }

    fn y(&self) -> (f32, f32) {
        (self.a.y.min(self.b.y), self.a.y.max(self.b.y))
    }

    /// Whether `p` lies on it.
    fn holds(&self, p: Point) -> bool {
        let ((x0, x1), (y0, y1)) = (self.x(), self.y());
        p.x > x0 - APART && p.x < x1 + APART && p.y > y0 - APART && p.y < y1 + APART
    }
}

/// How much `a` and `b` overlap.
fn overlap(a: (f32, f32), b: (f32, f32)) -> f32 {
    a.1.min(b.1) - a.0.max(b.0)
}

/// Measures `layout` of a graph with `edges`.
pub fn measure(layout: &Layout, edges: &[Edge]) -> Quality {
    let mut quality = Quality::default();
    let runs = routes(layout, edges, &mut quality);
    between_runs(&runs, &mut quality);
    for (i, route) in layout.edges.iter().enumerate() {
        for p in &route.points {
            quality.touching += runs.iter().filter(|r| r.edge != i && r.holds(*p)).count();
        }
    }
    against_nodes(&runs, layout, &mut quality);
    ports(layout, edges, &mut quality);
    for (i, a) in layout.nodes.iter().enumerate() {
        quality.overlapping_nodes += layout
            .nodes
            .iter()
            .skip(i + 1)
            .filter(|b| a.intersects(b))
            .count();
    }
    quality
}

/// The routes' runs; routes not from their source's bottom to their
/// target's top in vertical and horizontal runs counted as detached.
fn routes(layout: &Layout, edges: &[Edge], q: &mut Quality) -> Vec<Run> {
    let mut runs = Vec::new();
    for (i, route) in layout.edges.iter().enumerate() {
        let Some(edge) = edges.get(i) else { continue };
        let (Some(from), Some(to)) = (layout.nodes.get(edge.from), layout.nodes.get(edge.to))
        else {
            continue;
        };
        let (Some(first), Some(last)) = (route.points.first(), route.points.last()) else {
            q.detached += 1;
            continue;
        };
        let on_bottom =
            (first.y - from.bottom()).abs() < 0.01 && first.x > from.x && first.x < from.right();
        let on_top = (last.y - to.y).abs() < 0.01 && last.x > to.x && last.x < to.right();
        let straight = route
            .points
            .windows(2)
            .all(|w| matches!(w, [a, b] if (a.x - b.x).abs() < 0.01 || (a.y - b.y).abs() < 0.01));
        if !on_bottom || !on_top || !straight || route.points.len() < 2 {
            q.detached += 1;
        }
        for w in route.points.windows(2) {
            if let [a, b] = *w {
                runs.push(Run { edge: i, a, b });
            }
        }
    }
    runs
}

/// Runs of two edges on each other, and crossing.
fn between_runs(runs: &[Run], q: &mut Quality) {
    for (i, r) in runs.iter().enumerate() {
        for s in runs.iter().skip(i + 1) {
            if r.edge == s.edge {
                continue;
            }
            match (r.vertical(), s.vertical()) {
                (true, true) => {
                    if (r.a.x - s.a.x).abs() < APART && overlap(r.y(), s.y()) > APART {
                        q.overlapping += 1;
                    }
                }
                (false, false) => {
                    if (r.a.y - s.a.y).abs() < APART && overlap(r.x(), s.x()) > APART {
                        q.overlapping += 1;
                    }
                }
                (true, false) | (false, true) => {
                    let (up, across) = if r.vertical() { (r, s) } else { (s, r) };
                    let (left, right) = across.x();
                    let (top, bottom) = up.y();
                    let (x, y) = (up.a.x, across.a.y);
                    if x > left + APART
                        && x < right - APART
                        && y > top + APART
                        && y < bottom - APART
                    {
                        q.crossings += 1;
                    }
                }
            }
        }
    }
}

/// Runs through nodes or along their borders.
fn against_nodes(runs: &[Run], layout: &Layout, q: &mut Quality) {
    for r in runs {
        let ((x0, x1), (y0, y1)) = (r.x(), r.y());
        for node in &layout.nodes {
            let inside = Rect {
                x: node.x + APART,
                y: node.y + APART,
                width: node.width - 2.0 * APART,
                height: node.height - 2.0 * APART,
            };
            if x0 < inside.right() && x1 > inside.x && y0 < inside.bottom() && y1 > inside.y {
                q.through_nodes += 1;
            }
            if r.vertical() {
                let on_side =
                    (r.a.x - node.x).abs() < APART || (r.a.x - node.right()).abs() < APART;
                if on_side && overlap((y0, y1), (node.y, node.bottom())) > APART {
                    q.along_borders += 1;
                }
            } else {
                let on_side =
                    (r.a.y - node.y).abs() < APART || (r.a.y - node.bottom()).abs() < APART;
                if on_side && overlap((x0, x1), (node.x, node.right())) > APART {
                    q.along_borders += 1;
                }
            }
        }
    }
}

/// Pairs of edges leaving or entering a node at one point.
fn ports(layout: &Layout, edges: &[Edge], q: &mut Quality) {
    for (n, _) in layout.nodes.iter().enumerate() {
        let ends = |out: bool| -> Vec<f32> {
            edges
                .iter()
                .zip(&layout.edges)
                .filter(|(e, _)| if out { e.from == n } else { e.to == n })
                .filter_map(|(_, r)| {
                    if out {
                        r.points.first()
                    } else {
                        r.points.last()
                    }
                })
                .map(|p| p.x)
                .collect()
        };
        for xs in [ends(true), ends(false)] {
            for (i, a) in xs.iter().enumerate() {
                q.shared_ports += xs
                    .iter()
                    .skip(i + 1)
                    .filter(|b| (*a - **b).abs() < 1.0)
                    .count();
            }
        }
    }
}
