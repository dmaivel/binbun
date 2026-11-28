//! The graph view of a function, without the drawing: its blocks and
//! edges from `binbun::graph`, each block's lines as the listing renders
//! them (the user's names laid over), laid out once per function and
//! text size; the viewport (pan and zoom), hit testing, and the cursor's
//! moves along the blocks. The cursor is the listing's: a line inside a
//! block, so the listing, the C and the history see the same place.

use std::collections::HashMap;
use std::sync::Arc;

use binbun::Database;
use binbun::cfg::FunctionId;
pub use binbun::graph::layout::{Layout, Point, Rect, Size};
use binbun::graph::layout::{Spacing, layout};
pub use binbun::graph::svg::Metrics;
pub use binbun::graph::{BlockLine, EdgeKind, Exit, FunctionGraph, Target};
use binbun::graph::{Edge, block_line};

use crate::layout::TabId;
use crate::listing::{Listing, Overlay};

/// Zoom bounds.
pub const MIN_ZOOM: f32 = 0.03;
/// The largest zoom.
pub const MAX_ZOOM: f32 = 3.0;
/// Below this zoom blocks are drawn as plain rectangles.
pub const TEXT_ZOOM: f32 = 0.4;
/// The smallest code text, in pixels, a fit leaves: below it the boxes'
/// labels stop being readable.
pub const FIT_TEXT: f32 = 8.0;

/// The smallest zoom a fit goes to for code text of `code_size` pixels at
/// zoom 1: the text stays [`FIT_TEXT`] pixels, never past zoom 1 or below
/// [`TEXT_ZOOM`].
///
/// ```
/// use binbun_gui_view::graph::{TEXT_ZOOM, fit_floor};
/// assert!((fit_floor(13.0) * 13.0 - 8.0).abs() < 1e-4);
/// assert_eq!(fit_floor(4.0), 1.0);
/// assert_eq!(fit_floor(40.0), TEXT_ZOOM);
/// ```
pub fn fit_floor(code_size: f32) -> f32 {
    (FIT_TEXT / code_size.max(1.0)).clamp(TEXT_ZOOM, 1.0)
}

/// The rows a comment field adds to its block while it is edited, as the
/// listing's rows move down when it grows ([`Graph::grown`]).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Growth {
    /// The block.
    pub block: usize,
    /// Its first line moved: the first under the field.
    pub from: usize,
    /// How far it moves, at zoom 1 (less than zero: up, when the field
    /// has fewer lines than the comment it edits).
    pub by: f32,
}

/// One function's graph, laid out at zoom 1.
#[derive(Debug)]
pub struct Graph {
    /// The function.
    pub function: FunctionId,
    /// Its blocks and edges.
    pub model: FunctionGraph,
    /// Where they are.
    pub layout: Layout,
    /// Each block's lines as shown.
    pub lines: Vec<Vec<BlockLine>>,
    /// The text metrics it was laid out with.
    pub metrics: Metrics,
}

impl Graph {
    /// The graph of `function`, its lines from `listing` under `overlay`,
    /// laid out for `metrics`.
    pub fn build(
        db: &Database<'_>,
        listing: &Listing,
        overlay: &Overlay,
        function: FunctionId,
        metrics: Metrics,
    ) -> Option<Self> {
        let model = FunctionGraph::build(db, listing.lines(), function)?;
        let lines: Vec<Vec<BlockLine>> = model
            .blocks
            .iter()
            .map(|b| {
                b.lines
                    .iter()
                    .map(|&n| block_line(listing.render(db, n, overlay)))
                    .collect()
            })
            .collect();
        let sizes: Vec<Size> = lines
            .iter()
            .zip(&model.blocks)
            .map(|(lines, block)| {
                let chars = lines
                    .iter()
                    .map(|l| {
                        l.rendered
                            .tokens
                            .iter()
                            .map(|t| t.text.chars().count())
                            .sum()
                    })
                    .max()
                    .unwrap_or(0);
                metrics.size(chars, lines.len(), block.exit)
            })
            .collect();
        let spacing = Spacing {
            node: metrics.char_width * 3.0,
            layer: metrics.line_height * 1.6,
            track: (metrics.line_height * 0.45).round(),
        };
        let layout = layout(&sizes, &model.layout_edges(), 0, &spacing);
        Some(Self {
            function,
            model,
            layout,
            lines,
            metrics,
        })
    }

    /// Block `b`'s box (its terminal mark's room below it excluded).
    pub fn block_rect(&self, b: usize) -> Option<Rect> {
        self.block_rect_in(&self.layout, b)
    }

    /// Block `b`'s box in `layout` (this graph's, or one [`Self::grown`]).
    pub fn block_rect_in(&self, layout: &Layout, b: usize) -> Option<Rect> {
        let mut r = *layout.nodes.get(b)?;
        if self.model.blocks.get(b)?.exit != Exit::Edges {
            r.height -= self.metrics.mark;
        }
        Some(r)
    }

    /// The layout with `growth` laid in: its block taller, every block
    /// below the top of the block's rows from `growth.from` on moved down
    /// with them, and every edge point there but the ends on blocks that
    /// stay (an edge crossing the line stretches).
    pub fn grown(&self, growth: Growth) -> Layout {
        let mut layout = self.layout.clone();
        let Some(cut) = self.line_rect(growth.block, growth.from).map(|r| r.y) else {
            return layout;
        };
        let moves: Vec<bool> = (0..layout.nodes.len())
            .map(|b| b != growth.block && layout.nodes.get(b).is_some_and(|r| r.y >= cut))
            .collect();
        let stays = |b: usize| b != growth.block && !moves.get(b).copied().unwrap_or(false);
        for (b, r) in layout.nodes.iter_mut().enumerate() {
            if b == growth.block {
                r.height += growth.by;
            } else if moves.get(b).copied().unwrap_or(false) {
                r.y += growth.by;
            }
        }
        for (edge, route) in self.model.edges.iter().zip(&mut layout.edges) {
            let last = route.points.len().saturating_sub(1);
            for (k, p) in route.points.iter_mut().enumerate() {
                let held = (k == 0 && stays(edge.from)) || (k == last && stays(edge.to));
                if p.y >= cut && !held {
                    p.y += growth.by;
                }
            }
        }
        layout.height += growth.by;
        layout
    }

    /// Line `i` of block `b`'s box.
    pub fn line_rect(&self, b: usize, i: usize) -> Option<Rect> {
        let r = self.block_rect(b)?;
        let m = &self.metrics;
        Some(Rect {
            x: r.x,
            y: r.y + m.padding + m.line_height * count(i),
            width: r.width,
            height: m.line_height,
        })
    }

    /// The block, and the index of its line, showing listing line `n`; a
    /// line no block shows (a blank one dropped), the block's line before
    /// it.
    pub fn place(&self, n: u64) -> Option<(usize, usize)> {
        self.model.blocks.iter().enumerate().find_map(|(b, block)| {
            let first = *block.lines.first()?;
            let last = *block.lines.last()?;
            if n < first || n > last {
                return None;
            }
            let i = block.lines.partition_point(|&l| l <= n).saturating_sub(1);
            Some((b, i))
        })
    }

    /// The listing line at block `b`'s line `i`.
    pub fn line(&self, b: usize, i: usize) -> Option<u64> {
        self.model.blocks.get(b)?.lines.get(i).copied()
    }

    /// The block, line and column at `p` (graph coordinates).
    pub fn hit(&self, p: Point) -> Option<(usize, usize, usize)> {
        let m = &self.metrics;
        (0..self.model.blocks.len()).find_map(|b| {
            let r = self.block_rect(b)?;
            if p.x < r.x || p.x >= r.right() || p.y < r.y || p.y >= r.bottom() {
                return None;
            }
            let lines = self.model.blocks.get(b)?.lines.len();
            let i = index((p.y - r.y - m.padding) / m.line_height).min(lines.saturating_sub(1));
            let col = index((p.x - r.x - m.padding) / m.char_width);
            Some((b, i, col))
        })
    }

    /// Whether `p` is on a block (its mark included).
    pub fn on_block(&self, p: Point) -> bool {
        self.layout
            .nodes
            .iter()
            .any(|r| p.x >= r.x && p.x < r.right() && p.y >= r.y && p.y < r.bottom())
    }

    /// The listing token (its index among the listing line's tokens) at
    /// column `col` of block `b`'s line `i`.
    pub fn token(&self, b: usize, i: usize, col: usize) -> Option<usize> {
        let line = self.lines.get(b)?.get(i)?;
        let mut at = 0;
        for (k, t) in line.rendered.tokens.iter().enumerate() {
            let n = t.text.chars().count();
            if col >= at && col < at + n {
                return line.origin.get(k).copied();
            }
            at += n;
        }
        None
    }

    /// The edge within `tolerance` of `p`, nearest first.
    pub fn edge_at(&self, p: Point, tolerance: f32) -> Option<usize> {
        let mut best: Option<(f32, usize)> = None;
        for (e, route) in self.layout.edges.iter().enumerate() {
            for w in route.points.windows(2) {
                let [a, b] = w else { continue };
                let d = distance(p, *a, *b);
                if d <= tolerance && best.is_none_or(|(bd, _)| d < bd) {
                    best = Some((d, e));
                }
            }
        }
        best.map(|(_, e)| e)
    }

    /// The edges out of block `b`, and into it.
    fn edges(&self, b: usize, out: bool) -> impl Iterator<Item = &Edge> {
        self.model
            .edges
            .iter()
            .filter(move |e| if out { e.from == b } else { e.to == b })
    }

    /// Where the cursor on listing line `n` goes one line down (or up):
    /// the block's next line; past its end, along the only edge out, or
    /// the not-taken (falling) one; before its start, back along the only
    /// edge in, or the one falling into it.
    pub fn step(&self, n: u64, down: bool) -> Option<u64> {
        let (b, i) = self.place(n)?;
        let block = self.model.blocks.get(b)?;
        if down && i + 1 < block.lines.len() {
            return block.lines.get(i + 1).copied();
        }
        if !down && i > 0 {
            return block.lines.get(i - 1).copied();
        }
        let falls = |e: &&&Edge| matches!(e.kind, EdgeKind::NotTaken | EdgeKind::Next);
        let edges: Vec<&Edge> = self.edges(b, down).collect();
        let edge = if edges.len() == 1 {
            edges.first().copied()
        } else {
            edges.iter().find(falls).copied()
        }?;
        if down {
            self.model.blocks.get(edge.to)?.lines.first().copied()
        } else {
            self.model.blocks.get(edge.from)?.lines.last().copied()
        }
    }

    /// Edge `e`'s end away from block `from`: its target, or its source if
    /// `from` is the target.
    pub fn other_end(&self, e: usize, from: Option<usize>) -> Option<usize> {
        let edge = self.model.edges.get(e)?;
        Some(if from == Some(edge.to) {
            edge.from
        } else {
            edge.to
        })
    }
}

/// `x` as a count of cells (negative: 0).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a cell index on screen"
)]
fn index(x: f32) -> usize {
    x.floor().max(0.0) as usize
}

fn count(n: usize) -> f32 {
    f32::from(u16::try_from(n).unwrap_or(u16::MAX))
}

/// The distance from `p` to the run `a`–`b`.
fn distance(p: Point, a: Point, b: Point) -> f32 {
    let (x0, x1) = (a.x.min(b.x), a.x.max(b.x));
    let (y0, y1) = (a.y.min(b.y), a.y.max(b.y));
    let dx = (x0 - p.x).max(p.x - x1).max(0.0);
    let dy = (y0 - p.y).max(p.y - y1).max(0.0);
    dx.hypot(dy)
}

/// The graphs laid out so far, for one listing, overlay and text size.
#[derive(Debug, Default)]
pub struct Graphs {
    graphs: HashMap<FunctionId, Arc<Graph>>,
    made_for: Option<(usize, Overlay, Metrics)>,
}

impl Graphs {
    /// `function`'s graph, laid out now if it is not yet (or what it was
    /// made from changed).
    pub fn get(
        &mut self,
        db: &Database<'_>,
        listing: &Arc<Listing>,
        overlay: &Overlay,
        function: FunctionId,
        metrics: Metrics,
    ) -> Option<Arc<Graph>> {
        let key = (Arc::as_ptr(listing).addr(), overlay, metrics);
        if self
            .made_for
            .as_ref()
            .is_none_or(|(l, o, m)| (*l, o, *m) != key)
        {
            self.graphs.clear();
            self.made_for = Some((key.0, overlay.clone(), metrics));
        }
        if let Some(g) = self.graphs.get(&function) {
            return Some(Arc::clone(g));
        }
        let g = Arc::new(Graph::build(db, listing, overlay, function, metrics)?);
        self.graphs.insert(function, Arc::clone(&g));
        Some(g)
    }
}

/// A graph pane's view: zoom and the graph point at its top left.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Viewport {
    /// Screen pixels per graph unit.
    pub zoom: f32,
    /// The graph point at the pane's left.
    pub x: f32,
    /// The graph point at the pane's top.
    pub y: f32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            zoom: 1.0,
            x: 0.0,
            y: 0.0,
        }
    }
}

impl Viewport {
    /// The view as drawn, `scale` device pixels a pixel: its origin moved
    /// by under half a device pixel so that the graph's origin falls on a
    /// whole device pixel. Panned, everything then moves by whole device
    /// pixels, so what the renderer rounds to them on its own (a block's
    /// edges, its text's baseline) rounds alike from frame to frame: text
    /// never jumps a pixel against its block while the view glides.
    #[must_use]
    pub fn snapped(self, scale: f32) -> Self {
        let unit = self.zoom * scale;
        if unit <= 0.0 {
            return self;
        }
        Self {
            x: (self.x * unit).round() / unit,
            y: (self.y * unit).round() / unit,
            ..self
        }
    }

    /// `p` (graph) on screen, relative to the pane.
    pub fn to_screen(&self, p: Point) -> Point {
        Point {
            x: (p.x - self.x) * self.zoom,
            y: (p.y - self.y) * self.zoom,
        }
    }

    /// `p` (on screen, relative to the pane) in the graph.
    pub fn to_graph(&self, p: Point) -> Point {
        Point {
            x: p.x / self.zoom + self.x,
            y: p.y / self.zoom + self.y,
        }
    }

    /// Zooms by `factor` keeping the graph point under `pivot` (screen)
    /// there.
    pub fn zoom_at(&mut self, factor: f32, pivot: Point) {
        let at = self.to_graph(pivot);
        self.zoom = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        self.x = at.x - pivot.x / self.zoom;
        self.y = at.y - pivot.y / self.zoom;
    }

    /// The whole of a `width` × `height` graph in a `pane`, centred, no
    /// larger than zoom 1. A graph that would need a zoom below `floor`
    /// (see [`fit_floor`]) is shown at `floor` instead, centred on `focus`
    /// (the current node; else the graph's middle) as far as the graph's
    /// edges, `margin` screen pixels beyond them, allow.
    pub fn fit(
        &mut self,
        width: f32,
        height: f32,
        pane: Size,
        margin: f32,
        floor: f32,
        focus: Option<Rect>,
    ) {
        let zx = (pane.width - 2.0 * margin).max(1.0) / width.max(1.0);
        let zy = (pane.height - 2.0 * margin).max(1.0) / height.max(1.0);
        let whole = zx.min(zy).min(1.0);
        let floor = floor.clamp(MIN_ZOOM, 1.0);
        if whole >= floor {
            self.zoom = whole;
            self.x = width / 2.0 - pane.width / self.zoom / 2.0;
            self.y = height / 2.0 - pane.height / self.zoom / 2.0;
            return;
        }
        self.zoom = floor;
        let m = margin / floor;
        let centre = focus.map_or((width / 2.0, height / 2.0), |r| {
            (r.x + r.width / 2.0, r.y + r.height / 2.0)
        });
        // Per axis: centred on the focus where the graph is longer than the
        // view, without showing more than the margin past its edges.
        let axis = |at: f32, extent: f32, len: f32| {
            if extent + 2.0 * m <= len {
                extent / 2.0 - len / 2.0
            } else {
                (at - len / 2.0).clamp(-m, extent + m - len)
            }
        };
        self.x = axis(centre.0, width, pane.width / floor);
        self.y = axis(centre.1, height, pane.height / floor);
    }

    /// The graph rectangle on screen in a `pane`.
    pub fn visible(&self, pane: Size) -> Rect {
        Rect {
            x: self.x,
            y: self.y,
            width: pane.width / self.zoom,
            height: pane.height / self.zoom,
        }
    }

    /// Moves as little as shows `r` (graph) with `margin` screen pixels
    /// around it in a `pane`; a rectangle too large shows its top left.
    pub fn reveal(&mut self, r: Rect, pane: Size, margin: f32) {
        let m = margin / self.zoom;
        let v = self.visible(pane);
        let axis = |start: f32, len: f32, at: f32, size: f32| {
            if size + 2.0 * m > len || at - m < start {
                at - m
            } else if at + size + m > start + len {
                at + size + m - len
            } else {
                start
            }
        };
        self.x = axis(v.x, v.width, r.x, r.width);
        self.y = axis(v.y, v.height, r.y, r.height);
    }

    /// Centres `r` across and puts it a third of the way down a `pane`
    /// (as a jump lands).
    pub fn land(&mut self, r: Rect, pane: Size) {
        let v = self.visible(pane);
        self.x = r.x + r.width / 2.0 - v.width / 2.0;
        self.y = r.y - v.height / 3.0;
        if r.width > v.width {
            self.x = r.x - 8.0 / self.zoom;
        }
    }
}

/// A pane's graph mode.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GraphPane {
    /// The pane shows the graph (else the listing).
    pub on: bool,
    /// The function shown.
    pub function: Option<FunctionId>,
    /// The tab it was shown for: another (or none, as the graph is toggled
    /// on) is an arrival, which the tab's [`GraphMemory`] decides
    /// ([`GraphMemory::arrive`]).
    ///
    /// [`GraphMemory`]: crate::graph_memory::GraphMemory
    /// [`GraphMemory::arrive`]: crate::graph_memory::GraphMemory::arrive
    pub tab: Option<TabId>,
    /// The view.
    pub view: Viewport,
    /// Where a wheel's pan is heading (graph point at the top left).
    pub glide: Option<Point>,
    /// The cursor's listing line when the view last followed it.
    pub followed: Option<u64>,
    /// The cursor came by a jump: land on it rather than just reveal it.
    pub landing: bool,
    /// The pointer's last place while panning by drag (screen).
    pub drag: Option<Point>,
    /// The overview is being dragged.
    pub overview_drag: bool,
}

impl GraphPane {
    /// One frame of a wheel's glide: a third of the way there; whether it
    /// goes on.
    pub fn glide(&mut self) -> bool {
        let Some(to) = self.glide else {
            return false;
        };
        let (dx, dy) = (to.x - self.view.x, to.y - self.view.y);
        if (dx * self.view.zoom).abs() < 0.5 && (dy * self.view.zoom).abs() < 0.5 {
            self.view.x = to.x;
            self.view.y = to.y;
            self.glide = None;
            return false;
        }
        self.view.x += dx / 3.0;
        self.view.y += dy / 3.0;
        true
    }

    /// A wheel's pan by `(dx, dy)` screen pixels, glided if `smooth`.
    pub fn pan(&mut self, dx: f32, dy: f32, smooth: bool) {
        let from = self.glide.unwrap_or(Point {
            x: self.view.x,
            y: self.view.y,
        });
        let to = Point {
            x: from.x + dx / self.view.zoom,
            y: from.y + dy / self.view.zoom,
        };
        if smooth {
            self.glide = Some(to);
        } else {
            self.glide = None;
            self.view.x = to.x;
            self.view.y = to.y;
        }
    }
}

/// The overview's scale for a `width` × `height` graph in a square of
/// `side`.
pub fn overview_scale(width: f32, height: f32, side: f32) -> f32 {
    (side / width.max(1.0)).min(side / height.max(1.0))
}

#[cfg(test)]
mod tests {
    use binbun::analysis::Seeds;
    use binbun_loader::Image;

    use super::*;
    use crate::listing::Options;

    fn pane() -> Size {
        Size {
            width: 800.0,
            height: 600.0,
        }
    }

    /// Panned by any fraction of a pixel, a snapped view keeps every
    /// point's fraction of a device pixel on screen (what the renderer
    /// rounds moves by whole device pixels), and moves less than half a
    /// device pixel from the view it snaps.
    #[test]
    fn a_snapped_view_moves_by_whole_device_pixels() {
        let p = Point {
            x: 123.37,
            y: 45.81,
        };
        // How far apart two fractions are, round the pixel's ends.
        let apart = |a: f32, b: f32| {
            let d = (a - b).rem_euclid(1.0);
            d.min(1.0 - d)
        };
        for scale in [1.0, 1.5, 2.0] {
            for zoom in [1.0, 0.83, 1.7] {
                let at = |v: Viewport| {
                    let s = v.to_screen(p);
                    (s.x * scale, s.y * scale)
                };
                let first = at(Viewport {
                    zoom,
                    x: 10.0,
                    y: -4.0,
                }
                .snapped(scale));
                for k in 0..40_u8 {
                    let pan = f32::from(k) * 0.137;
                    let view = Viewport {
                        zoom,
                        x: 10.0 + pan,
                        y: -4.0 - pan / 2.0,
                    };
                    let snapped = view.snapped(scale);
                    let now = at(snapped);
                    assert!(apart(now.0, first.0) < 1e-3, "x {scale} {zoom} {k}");
                    assert!(apart(now.1, first.1) < 1e-3, "y {scale} {zoom} {k}");
                    let moved = (snapped.x - view.x).abs().max((snapped.y - view.y).abs());
                    assert!(
                        moved * zoom * scale <= 0.5 + 1e-3,
                        "moved {scale} {zoom} {k}"
                    );
                }
            }
        }
    }

    #[test]
    fn zooming_keeps_the_point_under_the_pointer() {
        let mut v = Viewport {
            zoom: 1.0,
            x: 100.0,
            y: 50.0,
        };
        let pivot = Point { x: 300.0, y: 200.0 };
        let before = v.to_graph(pivot);
        v.zoom_at(1.7, pivot);
        let after = v.to_graph(pivot);
        assert!((before.x - after.x).abs() < 1e-3 && (before.y - after.y).abs() < 1e-3);
        assert!((v.zoom - 1.7).abs() < 1e-6);
        v.zoom_at(1000.0, pivot);
        assert!((v.zoom - MAX_ZOOM).abs() < 1e-6);
    }

    #[test]
    fn fitting_shows_the_whole_graph_centred() {
        let mut v = Viewport::default();
        v.fit(4000.0, 1500.0, pane(), 10.0, 0.1, None);
        let r = v.visible(pane());
        assert!(r.x <= 0.0 && r.right() >= 4000.0 && r.y <= 0.0 && r.bottom() >= 1500.0);
        assert!((f32::midpoint(r.x, r.right()) - 2000.0).abs() < 1e-2);
        // A small graph is not blown up.
        v.fit(100.0, 100.0, pane(), 10.0, 0.1, None);
        assert!((v.zoom - 1.0).abs() < 1e-6);
    }

    #[test]
    fn fitting_stops_at_the_floor_on_the_current_node() {
        let floor = fit_floor(13.0);
        let node = Rect {
            x: 9000.0,
            y: 3000.0,
            width: 200.0,
            height: 40.0,
        };
        let mut v = Viewport::default();
        // Far too large for the pane: the floor, the node in the middle.
        v.fit(20000.0, 8000.0, pane(), 10.0, floor, Some(node));
        assert!((v.zoom - floor).abs() < 1e-6);
        let r = v.visible(pane());
        assert!((f32::midpoint(r.x, r.right()) - 9100.0).abs() < 1e-2);
        assert!((f32::midpoint(r.y, r.bottom()) - 3020.0).abs() < 1e-2);
        // A node at a corner: the view stays on the graph, the margin past it.
        let corner = Rect {
            x: 0.0,
            y: 0.0,
            ..node
        };
        v.fit(20000.0, 8000.0, pane(), 10.0, floor, Some(corner));
        assert!((v.x + 10.0 / floor).abs() < 1e-3 && (v.y + 10.0 / floor).abs() < 1e-3);
        // Tall and narrow: centred across, on the node down.
        let low = Rect {
            x: 50.0,
            y: 7000.0,
            ..node
        };
        v.fit(300.0, 8000.0, pane(), 10.0, floor, Some(low));
        let r = v.visible(pane());
        assert!((f32::midpoint(r.x, r.right()) - 150.0).abs() < 1e-2);
        assert!((f32::midpoint(r.y, r.bottom()) - 7020.0).abs() < 1e-2);
        // No node: the graph's middle.
        v.fit(20000.0, 8000.0, pane(), 10.0, floor, None);
        let r = v.visible(pane());
        assert!((f32::midpoint(r.x, r.right()) - 10000.0).abs() < 1e-2);
        // A graph that fits above the floor is fitted whole as before.
        v.fit(1200.0, 900.0, pane(), 10.0, floor, Some(node));
        let r = v.visible(pane());
        assert!(v.zoom >= floor && r.x <= 0.0 && r.right() >= 1200.0);
    }

    #[test]
    fn revealing_moves_only_as_needed() {
        let mut v = Viewport::default();
        let inside = Rect {
            x: 100.0,
            y: 100.0,
            width: 50.0,
            height: 20.0,
        };
        v.reveal(inside, pane(), 10.0);
        assert_eq!((v.x, v.y), (0.0, 0.0));
        let below = Rect { y: 900.0, ..inside };
        v.reveal(below, pane(), 10.0);
        assert!((v.y - (920.0 + 10.0 - 600.0)).abs() < 1e-3);
        assert!(v.x.abs() < 1e-6);
    }

    #[test]
    fn a_glide_arrives() {
        let mut g = GraphPane::default();
        g.pan(0.0, 120.0, true);
        let mut frames = 0;
        while g.glide() {
            frames += 1;
            assert!(frames < 100);
        }
        assert!((g.view.y - 120.0).abs() < 1e-3);
        assert!(frames > 1);
    }

    #[test]
    fn a_growing_field_moves_what_is_under_it_and_covers_nothing() {
        let path = format!(
            "{}/../../tests/fixtures/program-x86_64.elf",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = std::fs::read(path).unwrap();
        let image = Image::parse(&data).unwrap();
        let db = Database::new(&image, Seeds::ALL).unwrap();
        let listing = Listing::build(&db, &Options::default());
        let function = db.find_function("loop_sum").unwrap();
        let graph = Graph::build(
            &db,
            &listing,
            &Overlay::default(),
            function,
            Metrics::default(),
        )
        .unwrap();
        let overlaps = |layout: &Layout| {
            let n = layout.nodes.len();
            (0..n).any(|a| {
                (a + 1..n).any(|b| {
                    let (r, s) = (layout.nodes[a], layout.nodes[b]);
                    r.x < s.right() && s.x < r.right() && r.y < s.bottom() && s.y < r.bottom()
                })
            })
        };
        assert!(!overlaps(&graph.layout));
        // The field on the entry block's first line, three rows more.
        let by = 3.0 * graph.metrics.line_height;
        let growth = Growth {
            block: 0,
            from: 1,
            by,
        };
        let cut = graph.line_rect(0, 1).unwrap().y;
        let grown = graph.grown(growth);
        let (was, now) = (graph.layout.nodes[0], grown.nodes[0]);
        assert_eq!((now.x, now.y, now.width), (was.x, was.y, was.width));
        assert!((now.height - was.height - by).abs() < 1e-3);
        let mut moved = 0;
        for (b, (was, now)) in graph
            .layout
            .nodes
            .iter()
            .zip(&grown.nodes)
            .enumerate()
            .skip(1)
        {
            let expected = if was.y >= cut { was.y + by } else { was.y };
            assert!((now.y - expected).abs() < 1e-3, "block {b}");
            moved += usize::from(was.y >= cut);
        }
        assert!(moved > 0, "no block under the entry block");
        assert!(!overlaps(&grown), "{grown:?}");
        // Each edge still leaves its source's bottom and reaches its
        // target's top, in vertical and horizontal runs.
        for (edge, route) in graph.model.edges.iter().zip(&grown.edges) {
            let (Some(first), Some(last)) = (route.points.first(), route.points.last()) else {
                continue;
            };
            assert!(
                (first.y - grown.nodes[edge.from].bottom()).abs() < 1e-3,
                "{edge:?}"
            );
            assert!((last.y - grown.nodes[edge.to].y).abs() < 1e-3, "{edge:?}");
            for w in route.points.windows(2) {
                assert!(
                    (w[0].x - w[1].x).abs() < 1e-3 || (w[0].y - w[1].y).abs() < 1e-3,
                    "{edge:?}: {route:?}"
                );
            }
        }
        assert!((grown.height - graph.layout.height - by).abs() < 1e-3);
    }
}
