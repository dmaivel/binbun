//! A listing pane shown as the graph of the function at the cursor
//! (Space toggles): the blocks with their lines in the listing's font and
//! colours on a surface one step lighter than the editor, a hairline
//! border; edges green (taken), red (not taken), the muted foreground
//! (jumps, falls, cases), arrowheads at their targets, the cursor's
//! block's edges thicker and brighter; a quiet mark under each block no
//! edge leaves; text laid out at each zoom (GPUI has no zoom transform),
//! plain boxes when it would be too small to read; the overview in the
//! bottom right corner. Only what is on screen is drawn. A right click on
//! a block's token moves the cursor there and opens its context menu.

use std::rc::Rc;
use std::sync::Arc;

use binbun_gui_view::context::Surface;
use binbun_gui_view::graph::{
    EdgeKind, Exit, Graph, Growth, Metrics, Point as GPoint, Rect as GRect, Size as GSize,
    TEXT_ZOOM, Target, Viewport, fit_floor, overview_scale,
};
use binbun_gui_view::graph_memory::follow;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::{Role, Token};
use binbun_gui_view::scroll::Wheel;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Bounds, Context, MouseButton, MouseDownEvent, MouseMoveEvent, Pixels, Point,
    ScrollDelta, ScrollEvent, StyledText, Window, canvas, div, fill, point, px, size,
};

use crate::collab::{caret_bar, token_column};
use crate::highlight::Highlight;
use crate::listing_view::tones;
use crate::panes::measured;
use crate::scrolling::wheel;
use crate::tabs::name_click;
use crate::theme::{Theme, dim, hsla, solid, with_alpha};
use crate::workspace::{TabKind, Workspace};

/// The overview's longest side (logical pixels), and its margin.
const OVERVIEW: f32 = 200.0;
const OVERVIEW_MARGIN: f32 = 12.0;
/// How near (screen pixels) a click must be to an edge to take it.
const EDGE_HIT: f32 = 4.0;

/// A filled rectangle to paint, relative to the pane.
#[derive(Clone, Copy, Debug)]
struct Quad {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: u32,
}

impl Workspace {
    /// Whether pane `id` shows its listing as a graph.
    pub fn shows_graph(&self, id: PaneId) -> bool {
        matches!(self.layout.active(id), Some(TabKind::Listing))
            && self.panes.get(&id).is_some_and(|s| s.graph.on)
    }

    /// The text metrics graphs are laid out with (zoom 1).
    fn graph_metrics(&self) -> Metrics {
        let row = self.row(self.settings.listing_line_height);
        Metrics {
            char_width: self.char_width.unwrap_or(8.0),
            line_height: row,
            padding: (row * 0.4).round(),
            mark: row,
        }
    }

    /// The graph of the function holding pane `id`'s cursor.
    fn cursor_graph(&mut self, id: PaneId) -> Option<Arc<Graph>> {
        let metrics = self.graph_metrics();
        let listing = self.listing.clone()?;
        let session = self.session.as_ref()?;
        let db = session.database()?;
        let cursor = self.panes.get(&id)?.listing.cursor;
        let (function, _) = listing.function_of(listing.line(cursor)?.address)?;
        self.graphs
            .get(db, &listing, session.overlay(), function, metrics)
    }

    /// The size of pane `id` (a guess before it is first drawn).
    pub(crate) fn pane_size(&self, id: PaneId) -> (GSize, bool) {
        let b = self
            .panes
            .get(&id)
            .map(|s| s.bounds.get())
            .unwrap_or_default();
        let (w, h) = (f32::from(b.size.width), f32::from(b.size.height));
        if w > 0.0 && h > 0.0 {
            (
                GSize {
                    width: w,
                    height: h,
                },
                true,
            )
        } else {
            (
                GSize {
                    width: 1200.0,
                    height: 800.0,
                },
                false,
            )
        }
    }

    /// Space: pane `id`'s listing as the graph of the function at its
    /// cursor, or the listing again at the cursor.
    pub fn toggle_graph(&mut self, id: PaneId) {
        let on = self.shows_graph(id);
        if !on && self.cursor_graph(id).is_none() {
            return;
        }
        let rows = self.rows(id, self.settings.listing_line_height);
        let len = self.listing.as_ref().map_or(0, |l| l.len());
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        if on {
            state.graph.on = false;
            let cursor = state.listing.cursor;
            state
                .listing
                .scroll
                .anchor
                .reveal(cursor, len, rows, rows / 3);
        } else {
            state.graph.on = true;
            // Back as the tab's memory says (`render_graph`).
            state.graph.tab = None;
            state.graph.landing = false;
        }
        self.last_graph = !on;
    }

    /// Shows pane `id`'s listing as the graph (`graph`) or the text.
    pub fn set_graph(&mut self, id: PaneId, graph: bool) {
        if self.shows_graph(id) != graph {
            self.toggle_graph(id);
        }
    }

    /// Fits pane `id`'s graph to the pane.
    pub fn fit_graph(&mut self, id: PaneId) {
        let Some(graph) = self.cursor_graph(id) else {
            return;
        };
        let (pane, _) = self.pane_size(id);
        let floor = fit_floor(self.code_size());
        if let Some(state) = self.panes.get_mut(&id) {
            let focus = graph
                .place(state.listing.cursor)
                .and_then(|(b, _)| graph.block_rect(b));
            state.graph.glide = None;
            state.graph.view.fit(
                graph.layout.width,
                graph.layout.height,
                pane,
                24.0,
                floor,
                focus,
            );
        }
    }

    /// Zooms pane `id`'s graph by `factor` about its middle (`None`: back
    /// to 100%).
    pub fn zoom_graph(&mut self, id: PaneId, factor: Option<f32>) {
        let (pane, _) = self.pane_size(id);
        if let Some(state) = self.panes.get_mut(&id) {
            let view = &mut state.graph.view;
            let pivot = GPoint {
                x: pane.width / 2.0,
                y: pane.height / 2.0,
            };
            let factor = factor.unwrap_or(1.0 / view.zoom);
            state.graph.glide = None;
            view.zoom_at(factor, pivot);
        }
    }

    /// The cursor one line down (or up) in pane `id`'s graph: along the
    /// block, then along an edge.
    pub fn graph_step(&mut self, id: PaneId, down: bool) {
        let Some(graph) = self.cursor_graph(id) else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        if let Some(to) = graph.step(state.listing.cursor, down) {
            state.listing.cursor = to;
            state.listing.token = None;
            self.moved(id);
        }
    }

    /// Pane `id`'s graph.
    #[expect(clippy::too_many_lines, reason = "the layers of the view, in order")]
    pub fn render_graph(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        self.char_width(window);
        let Some(graph) = self.cursor_graph(id) else {
            // No function at the cursor: the text, the pane still a graph
            // (its view changes only when the user changes it) for when
            // its place is in one.
            return self.render_listing(id, window, cx);
        };
        let theme = self.theme;
        let focused = self.layout.focused() == id;
        let (pane, known) = self.pane_size(id);
        let tab = self.layout.active_tab(id);
        // The function's entry: what its view is remembered by.
        let entry = self.panes.get(&id).and_then(|s| {
            let listing = self.listing.as_ref()?;
            let address = listing.line(s.listing.cursor)?.address;
            listing.function_of(address).map(|(_, entry)| entry)
        });
        let Some(state) = self.panes.get_mut(&id) else {
            return div().into_any_element();
        };
        let g = &mut state.graph;
        let cursor = state.listing.cursor;
        let place = graph.place(cursor);
        let rects = place.and_then(|(b, i)| Some((graph.block_rect(b)?, graph.line_rect(b, i)?)));
        // Arriving (toggled on, another tab, another function): as the
        // tab's memory says; else following the cursor as little as shows
        // it (a jump in the graph lands on it).
        let arriving = g.function != Some(graph.function) || g.tab.is_none() || g.tab != tab;
        if known && arriving {
            let memory = tab.and_then(|t| self.places.graph_memory(t));
            match (rects, entry) {
                (Some((block, line)), Some(entry)) => {
                    g.view = memory
                        .cloned()
                        .unwrap_or_default()
                        .arrive(entry, cursor, block, line, pane, g.view);
                }
                (None, Some(entry)) => {
                    if let Some(pan) = memory.and_then(|m| m.pan(entry)) {
                        g.view.x = pan.x;
                        g.view.y = pan.y;
                    }
                }
                (_, None) => {}
            }
            g.glide = None;
            g.function = Some(graph.function);
            g.tab = tab;
            g.followed = Some(cursor);
            g.landing = false;
        } else if known && g.followed != Some(cursor) {
            if let Some((block, line)) = rects {
                g.glide = None;
                if g.landing {
                    g.view.land(block, pane);
                    if block.height * g.view.zoom > pane.height * 2.0 / 3.0 {
                        g.view = follow(g.view, block, line, pane);
                    }
                } else {
                    g.view = follow(g.view, block, line, pane);
                }
            }
            g.followed = Some(cursor);
            g.landing = false;
        }
        // Remembered as it is now, for the tab's next arrival.
        if known
            && !arriving
            && let (Some(tab), Some(entry)) = (tab, entry)
        {
            let shown = g.glide.map_or(g.view, |to| Viewport {
                x: to.x,
                y: to.y,
                ..g.view
            });
            self.places
                .graph_memory_mut(tab)
                .remember(entry, shown, g.followed);
        }
        if !known || g.glide() {
            window.request_animation_frame();
        }
        // Drawn on whole device pixels: the text keeps its place in its
        // block as the view glides.
        let view = g.view.snapped(window.scale_factor());
        let bounds = Rc::clone(&state.bounds);
        let focus = state.focus.clone();
        let token = state.listing.token;
        let highlight = state.listing.highlight.clone();
        let zoom = view.zoom;
        let row_h = graph.metrics.line_height * zoom;
        let pad = graph.metrics.padding * zoom;
        let visible = view.visible(pane);
        let current = place.map(|(b, _)| b);
        // The comment field: its item's first line, the lines its comment
        // takes, its column in the block (the listing's, less what the
        // block leaves out before it: the prefix, cross-references).
        let commenting = self
            .comment
            .as_ref()
            .filter(|c| c.pane == id)
            .and_then(|c| {
                let listing = self.listing.as_ref()?;
                let session = self.session.as_ref()?;
                let db = session.database()?;
                let n = listing.line_of(c.field.address);
                let (_, line, column) = listing.comment_place(db, n, session.overlay())?;
                let (b, i) = graph.place(line)?;
                let shown = &graph.lines.get(b)?.get(i)?.rendered.tokens;
                let full = listing.render(db, line, session.overlay()).tokens;
                let left_out = bare_width(&full).saturating_sub(bare_width(shown));
                let column = column.saturating_sub(left_out);
                Some((c, line, listing.comment_lines(line), column))
            });
        // The field's rows more than its comment's move the rows under it
        // down, its block taller and what is below it with them, as in the
        // listing.
        let growth = commenting.as_ref().and_then(|(c, line, lines, _)| {
            let (block, _) = graph.place(*line)?;
            let from = graph
                .model
                .blocks
                .get(block)?
                .lines
                .partition_point(|&l| l < lines.end);
            let comment = usize::try_from(lines.end - lines.start).unwrap_or(1);
            let shown = c.field.lines();
            (shown != comment).then(|| Growth {
                block,
                from,
                by: (f(shown) - f(comment)) * graph.metrics.line_height,
            })
        });
        let grown = growth.map(|g| graph.grown(g));
        let layout = grown.as_ref().unwrap_or(&graph.layout);
        // Block `b`'s row `i`'s top in it, the field's growth laid in.
        let row_top = |b: usize, i: usize| {
            let moved = growth.filter(|g| g.block == b && i >= g.from);
            pad + row_h * f(i) + moved.map_or(0.0, |g| g.by * zoom)
        };
        let mut field_box = None;
        let mut root = div()
            .id(("graph", id.0))
            .key_context(if commenting.is_some() {
                "CEdit"
            } else {
                "Code"
            })
            .track_focus(&focus)
            .size_full()
            .relative()
            .overflow_hidden()
            .bg(hsla(graph_surfaces(theme).0))
            .rounded_b(self.island_corner())
            .font_family(self.settings.code_font.clone())
            .font_features(self.font_features())
            .text_size(px(self.code_size() * zoom))
            .line_height(px(row_h))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.graph_down(id, e, window, cx);
                }),
            )
            .on_mouse_down(
                MouseButton::Middle,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.graph_down(id, e, window, cx);
                }),
            )
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.graph_right(id, e, window, cx);
                }),
            )
            .on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, window, cx| {
                this.graph_move(id, e, window, cx);
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    if let Some(s) = this.panes.get_mut(&id) {
                        s.graph.drag = None;
                        s.graph.overview_drag = false;
                    }
                    cx.notify();
                }),
            )
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                this.graph_wheel(id, e);
                cx.notify();
            }))
            .when(commenting.is_some(), |d| {
                // A click outside the pane drops the field (inside, the
                // click itself does).
                d.on_mouse_down_out(cx.listener(|this, _, window, cx| {
                    this.close_overlays(window, cx);
                    cx.notify();
                }))
            })
            .child(measured(bounds).absolute().size_full());
        // Edges and marks under the blocks' text, the cursor's block's
        // edges over the others.
        let mut quads: Vec<Quad> = Vec::new();
        let mut lit: Vec<Quad> = Vec::new();
        for (edge, route) in graph.model.edges.iter().zip(&layout.edges) {
            if !route_visible(&route.points, &visible) {
                continue;
            }
            let on = current.is_some_and(|c| edge.from == c || edge.to == c);
            let base = edge_colour(theme, edge.kind);
            let (color, width, out) = if on {
                (bright(theme, edge.kind), 2.0, &mut lit)
            } else {
                (base, 1.0, &mut quads)
            };
            let points: Vec<GPoint> = route.points.iter().map(|&p| view.to_screen(p)).collect();
            path(out, &points, width, color);
            if let Some(&tip) = points.last() {
                arrowhead(out, tip, (4.0 * zoom.sqrt()).clamp(2.0, 5.0), width, color);
            }
        }
        quads.append(&mut lit);
        let mut labels: Vec<(GPoint, String)> = Vec::new();
        for (b, block) in graph.model.blocks.iter().enumerate() {
            if block.exit == Exit::Edges {
                continue;
            }
            let Some(r) = graph.block_rect_in(layout, b) else {
                continue;
            };
            if !intersects(&r, &visible) {
                continue;
            }
            let at = view.to_screen(GPoint {
                x: r.x + r.width / 2.0,
                y: r.bottom(),
            });
            let name = |target: Target| {
                let (Target::Address(a) | Target::Import(a)) = target;
                self.listing
                    .as_ref()
                    .map_or_else(|| format!("{a:X}"), |l| l.describe(a))
            };
            if let Some(text) = terminal(&mut quads, theme, block.exit, at, zoom, &name) {
                labels.push((at, text));
            }
        }
        root = root.child(
            canvas(
                |_, _, _| {},
                move |bounds, (), window, _| {
                    for q in &quads {
                        window.paint_quad(fill(
                            Bounds::new(
                                point(bounds.origin.x + px(q.x), bounds.origin.y + px(q.y)),
                                size(px(q.w), px(q.h)),
                            ),
                            hsla(q.color),
                        ));
                    }
                },
            )
            .absolute()
            .size_full(),
        );
        // The blocks on screen.
        for (b, rect) in layout.nodes.iter().enumerate() {
            let Some(r) = graph.block_rect_in(layout, b) else {
                continue;
            };
            if !intersects(rect, &visible) {
                continue;
            }
            let at = view.to_screen(GPoint { x: r.x, y: r.y });
            let is_current = current == Some(b);
            let border = if is_current && focused {
                theme.border_focused
            } else {
                theme.border
            };
            let mut node = div()
                .absolute()
                .left(px(at.x))
                .top(px(at.y))
                .w(px(r.width * zoom))
                .h(px(r.height * zoom))
                .bg(hsla(solid(graph_surfaces(theme).1)))
                .border_1()
                .border_color(hsla(border))
                .overflow_hidden();
            if zoom < TEXT_ZOOM {
                if is_current {
                    node = node.bg(hsla(with_alpha(theme.accent, 0x66)));
                }
                root = root.child(node);
                continue;
            }
            for (i, line) in graph.lines.get(b).into_iter().flatten().enumerate() {
                let y = row_top(b, i);
                let here = place == Some((b, i));
                // On the field's lines: the first without its comment, then
                // `; ` where the field goes; the others empty.
                let edited = commenting.as_ref().and_then(|(c, first, lines, column)| {
                    let n = graph.line(b, i)?;
                    lines.contains(&n).then_some((*c, n == *first, *column))
                });
                let mut tokens = line.rendered.tokens.clone();
                if let Some((edit, first, column)) = edited {
                    if first {
                        if tokens.last().is_some_and(|t| t.role == Role::Comment) {
                            tokens.truncate(tokens.len().saturating_sub(2));
                        }
                        let width: usize = tokens.iter().map(|t| t.text.chars().count()).sum();
                        tokens.push(Token {
                            text: " ".repeat(column.saturating_sub(width).max(1)),
                            role: Role::Space,
                            target: None,
                            automatic: false,
                        });
                        tokens.push(Token {
                            text: "; ".to_owned(),
                            role: Role::Comment,
                            target: None,
                            automatic: false,
                        });
                        let char_w = self.char_width.unwrap_or(8.0) * zoom;
                        let x = at.x + pad + f(column + 2) * char_w;
                        field_box = Some(self.comment_box(edit, x, at.y + y, row_h));
                    } else {
                        tokens.clear();
                    }
                }
                let mut text = String::new();
                let mut runs = Vec::with_capacity(tokens.len());
                for (k, t) in tokens.iter().enumerate() {
                    if t.text.is_empty() {
                        continue;
                    }
                    text.push_str(&t.text);
                    let lit_token = t.role != Role::Space
                        && (highlight.as_deref() == Some(t.text.as_str())
                            || (here && token.is_some() && line.origin.get(k).copied() == token));
                    let back = lit_token.then_some(theme.search_match);
                    let color = theme.token(t);
                    for (len, tone) in tones(&t.text, t.role == Role::Number) {
                        let c = if tone { dim(color) } else { color };
                        runs.push(self.text_run(len, c, back));
                    }
                }
                let mut row = div()
                    .absolute()
                    .top(px(y - 1.0))
                    .left_0()
                    .right_0()
                    .h(px(row_h))
                    .pl(px(pad - 1.0))
                    .whitespace_nowrap()
                    .overflow_hidden();
                if here {
                    row = row.bg(hsla(if focused {
                        theme.active_line
                    } else {
                        theme.lit()
                    }));
                    // The caret at the cursor's token, as in the listing
                    // (not while the comment field takes the typing).
                    if commenting.is_none() {
                        let at_token = line.origin.iter().position(|&from| Some(from) == token);
                        let column = token_column(&line.rendered.tokens, at_token);
                        let char_w = self.char_width.unwrap_or(8.0) * zoom;
                        let x = pad - 1.0 + f(column as usize) * char_w;
                        row = row.child(caret_bar(self.own_caret(focused), (x, 0.0, row_h)));
                    }
                }
                node = node.child(row.child(StyledText::new(text).with_runs(runs)));
            }
            root = root.child(node);
        }
        root = root.children(field_box);
        // The terminal marks' words.
        if zoom >= TEXT_ZOOM {
            for (at, text) in labels {
                root = root.child(
                    div()
                        .absolute()
                        .left(px(at.x + 9.0 * zoom.sqrt()))
                        .top(px(at.y + 2.0))
                        .text_size(px(self.code_size() * zoom * 0.85))
                        .text_color(hsla(theme.text_placeholder))
                        .whitespace_nowrap()
                        .child(text),
                );
            }
        }
        if self.overview
            && (graph.layout.width * zoom > pane.width || graph.layout.height * zoom > pane.height)
        {
            root = root.child(self.overview_element(id, &graph, view, pane, current, cx));
        }
        root.into_any_element()
    }

    /// The overview: every block as a filled box, every edge a thin line
    /// in its colour, the view's rectangle outlined, the cursor's block in
    /// the accent, on a translucent surface in the bottom right corner.
    #[expect(clippy::too_many_lines, reason = "its layers and its three inputs")]
    fn overview_element(
        &self,
        id: PaneId,
        graph: &Graph,
        view: Viewport,
        pane: GSize,
        current: Option<usize>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let side = self.row(OVERVIEW);
        let scale = overview_scale(graph.layout.width, graph.layout.height, side);
        let (width, height) = (graph.layout.width * scale, graph.layout.height * scale);
        let mut quads: Vec<Quad> = Vec::new();
        for (e, route) in graph.model.edges.iter().zip(&graph.layout.edges) {
            let points: Vec<GPoint> = route
                .points
                .iter()
                .map(|p| GPoint {
                    x: p.x * scale,
                    y: p.y * scale,
                })
                .collect();
            path(
                &mut quads,
                &points,
                1.0,
                with_alpha(edge_colour(theme, e.kind), 0xb0),
            );
        }
        for (b, r) in graph.layout.nodes.iter().enumerate() {
            let color = if current == Some(b) {
                theme.accent
            } else {
                theme.border
            };
            quads.push(Quad {
                x: r.x * scale,
                y: r.y * scale,
                w: (r.width * scale).max(1.0),
                h: (r.height * scale).max(1.0),
                color,
            });
        }
        let v = view.visible(pane);
        let (vx, vy, vw, vh) = (v.x * scale, v.y * scale, v.width * scale, v.height * scale);
        let line = theme.text_muted;
        for q in [
            (vx, vy, vw, 1.0),
            (vx, vy + vh - 1.0, vw, 1.0),
            (vx, vy, 1.0, vh),
            (vx + vw - 1.0, vy, 1.0, vh),
        ] {
            quads.push(Quad {
                x: q.0,
                y: q.1,
                w: q.2,
                h: q.3,
                color: line,
            });
        }
        let margin = self.row(OVERVIEW_MARGIN);
        div()
            .id(("graph-overview", id.0))
            .absolute()
            .right(px(margin))
            .bottom(px(margin))
            .w(px(width + 2.0))
            .h(px(height + 2.0))
            .bg(hsla(with_alpha(theme.panel, 0xe0)))
            .border_1()
            .border_color(hsla(theme.border))
            .overflow_hidden()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, e: &MouseDownEvent, _, cx| {
                    cx.stop_propagation();
                    this.overview_to(id, e.position, scale);
                    if let Some(st) = this.panes.get_mut(&id) {
                        st.graph.overview_drag = true;
                    }
                    cx.notify();
                }),
            )
            .on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, _, cx| {
                if this.panes.get(&id).is_some_and(|st| st.graph.overview_drag) && e.dragging() {
                    cx.stop_propagation();
                    this.overview_to(id, e.position, scale);
                    cx.notify();
                }
            }))
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                cx.stop_propagation();
                let up = match wheel(e) {
                    Wheel::Lines(l) => l,
                    Wheel::Pixels(p) => p / 50.0,
                };
                this.zoom_graph(id, Some(1.1f32.powf(up)));
                cx.notify();
            }))
            .child(
                canvas(
                    |_, _, _| {},
                    move |bounds, (), window, _| {
                        for q in &quads {
                            window.paint_quad(fill(
                                Bounds::new(
                                    point(
                                        bounds.origin.x + px(q.x + 1.0),
                                        bounds.origin.y + px(q.y + 1.0),
                                    ),
                                    size(px(q.w), px(q.h)),
                                ),
                                hsla(q.color),
                            ));
                        }
                    },
                )
                .absolute()
                .size_full(),
            )
            .into_any_element()
    }

    /// Centres pane `id`'s view on the graph point under `position` in the
    /// overview (scaled by `scale`).
    fn overview_to(&mut self, id: PaneId, position: Point<Pixels>, scale: f32) {
        let (pane, _) = self.pane_size(id);
        let margin = self.row(OVERVIEW_MARGIN);
        let Some(graph) = self.cursor_graph(id) else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let b = state.bounds.get();
        let (width, height) = (graph.layout.width * scale, graph.layout.height * scale);
        let left = f32::from(b.origin.x) + pane.width - margin - width - 1.0;
        let top = f32::from(b.origin.y) + pane.height - margin - height - 1.0;
        let gx = (f32::from(position.x) - left) / scale;
        let gy = (f32::from(position.y) - top) / scale;
        let v = &mut state.graph.view;
        let visible = v.visible(pane);
        v.x = gx - visible.width / 2.0;
        v.y = gy - visible.height / 2.0;
        state.graph.glide = None;
    }

    /// Where `position` is in pane `id`'s graph.
    fn graph_point(&self, id: PaneId, position: Point<Pixels>) -> Option<(GPoint, GPoint)> {
        let state = self.panes.get(&id)?;
        let b = state.bounds.get();
        let screen = GPoint {
            x: f32::from(position.x - b.origin.x),
            y: f32::from(position.y - b.origin.y),
        };
        Some((screen, state.graph.view.to_graph(screen)))
    }

    fn graph_down(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.close_peek();
        // A click elsewhere in the pane drops the comment field (a click
        // in it moves its caret).
        if self.comment.as_ref().is_some_and(|c| c.pane == id) {
            self.comment = None;
        }
        if self.layout.focused() != id {
            self.focus_pane(id, window, cx);
        }
        let (Some(graph), Some((screen, at))) =
            (self.cursor_graph(id), self.graph_point(id, e.position))
        else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let zoom = state.graph.view.zoom;
        if let Some((b, i, col)) = graph.hit(at) {
            let Some(line) = graph.line(b, i) else {
                return;
            };
            let token = graph.token(b, i, col);
            let shown = graph.lines.get(b).and_then(|l| l.get(i));
            let picked = shown.and_then(|l| {
                let k = l.origin.iter().position(|&o| Some(o) == token)?;
                l.rendered.tokens.get(k)
            });
            // Ctrl+click or a middle click on a name: what it names in a
            // new tab.
            let named = picked.and_then(|t| t.target);
            if self.open_name(id, named, name_click(e, cx), window, cx) {
                return;
            }
            let Some(state) = self.panes.get_mut(&id) else {
                return;
            };
            state.listing.cursor = line;
            state.listing.token = token;
            state.graph.followed = Some(line);
            if let Some(t) = picked {
                if matches!(
                    t.role,
                    Role::Mnemonic
                        | Role::JumpMnemonic
                        | Role::CallMnemonic
                        | Role::ReturnMnemonic
                        | Role::PaddingMnemonic
                        | Role::Register
                        | Role::Number
                        | Role::CodeName
                        | Role::DataName
                        | Role::ImportName
                        | Role::LocalName
                ) {
                    state.listing.highlight = if state.listing.highlight.as_deref()
                        == Some(t.text.as_str())
                        && e.click_count == 1
                    {
                        None
                    } else {
                        Some(t.text.clone())
                    };
                }
                if e.click_count == 2
                    && let Some(target) = t.target
                {
                    self.jump(target, cx);
                    return;
                }
            }
            self.moved(id);
            cx.notify();
            return;
        }
        if e.button != MouseButton::Left {
            return;
        }
        if !graph.on_block(at)
            && let Some(edge) = graph.edge_at(at, EDGE_HIT / zoom)
        {
            let from = graph.place(state.listing.cursor).map(|(b, _)| b);
            if let Some(to) = graph.other_end(edge, from)
                && let Some(block) = graph.model.blocks.get(to)
            {
                let address = block.start;
                self.jump(address, cx);
                return;
            }
        }
        state.graph.drag = Some(screen);
        state.graph.glide = None;
        cx.notify();
    }

    /// A right click: on a block's line, the cursor to its token (as a
    /// single click, the highlight kept); elsewhere the cursor stays and
    /// no token is under it. Then the context menu.
    fn graph_right(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let on_line = self
            .cursor_graph(id)
            .zip(self.graph_point(id, e.position))
            .is_some_and(|(graph, (_, at))| graph.hit(at).is_some());
        let highlight = self
            .panes
            .get(&id)
            .and_then(|s| s.listing.highlight.clone());
        if on_line {
            let click = MouseDownEvent {
                click_count: 1,
                ..e.clone()
            };
            self.graph_down(id, &click, window, cx);
        } else if self.layout.focused() != id {
            self.focus_pane(id, window, cx);
        }
        if let Some(state) = self.panes.get_mut(&id) {
            if !on_line {
                state.listing.token = None;
            }
            if state.listing.highlight.is_none() {
                state.listing.highlight = highlight;
            }
        }
        self.open_context_menu(Surface::Graph, e.position, window, cx);
    }

    fn graph_move(
        &mut self,
        id: PaneId,
        e: &MouseMoveEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some((screen, at)) = self.graph_point(id, e.position) else {
            return;
        };
        if let Some(state) = self.panes.get_mut(&id)
            && let Some(from) = state.graph.drag
        {
            if e.dragging() {
                let v = &mut state.graph.view;
                v.x -= (screen.x - from.x) / v.zoom;
                v.y -= (screen.y - from.y) / v.zoom;
                state.graph.drag = Some(screen);
                cx.notify();
                return;
            }
            state.graph.drag = None;
        }
        let Some(graph) = self.cursor_graph(id) else {
            return;
        };
        let target = graph.hit(at).and_then(|(b, i, col)| {
            let k = graph.token(b, i, col)?;
            let line = graph.lines.get(b)?.get(i)?;
            let shown = line.origin.iter().position(|&o| o == k)?;
            let t = line.rendered.tokens.get(shown)?;
            matches!(t.role, Role::CodeName | Role::DataName | Role::ImportName)
                .then_some(t.target)
                .flatten()
        });
        self.hover_peek(target, None, e.position, window, cx);
    }

    /// The wheel over pane `id`'s graph: with Ctrl it zooms about the
    /// pointer, with Shift it pans across, else it pans down (eased).
    fn graph_wheel(&mut self, id: PaneId, e: &ScrollEvent) {
        let row = self.row(self.settings.listing_line_height);
        let smooth = self.settings.smooth_scroll;
        let Some((screen, _)) = self.graph_point(id, e.position) else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let (pixels, notch) = match wheel(e) {
            Wheel::Lines(l) => (l * row, true),
            Wheel::Pixels(p) => (p, false),
        };
        if e.modifiers.control {
            state.graph.glide = None;
            let notches = if notch {
                pixels / (3.0 * row)
            } else {
                pixels / 50.0
            };
            state.graph.view.zoom_at(1.15f32.powf(notches), screen);
        } else if e.modifiers.shift {
            state.graph.pan(-pixels, 0.0, smooth && notch);
        } else {
            let across = match e.delta {
                ScrollDelta::Pixels(p) => -f32::from(p.x),
                ScrollDelta::Lines(l) => -l.x * row,
            };
            state.graph.pan(across, -pixels, smooth && notch);
        }
    }
}

/// The width (characters) of a line's `tokens` before the user's comment
/// at their end (a space and the comment), if there is one.
fn bare_width(tokens: &[Token]) -> usize {
    let end = if tokens.last().is_some_and(|t| t.role == Role::Comment) {
        tokens.len().saturating_sub(2)
    } else {
        tokens.len()
    };
    tokens
        .get(..end)
        .unwrap_or_default()
        .iter()
        .map(|t| t.text.chars().count())
        .sum()
}

/// `n` as a coordinate.
fn f(n: usize) -> f32 {
    f32::from(u16::try_from(n).unwrap_or(u16::MAX))
}

/// Whether `a` and `b` overlap.
fn intersects(a: &GRect, b: &GRect) -> bool {
    a.x < b.right() && b.x < a.right() && a.y < b.bottom() && b.y < a.bottom()
}

/// Whether any of a route's box is in `visible`.
fn route_visible(points: &[GPoint], visible: &GRect) -> bool {
    let (mut x0, mut y0, mut x1, mut y1) = (f32::MAX, f32::MAX, f32::MIN, f32::MIN);
    for p in points {
        x0 = x0.min(p.x);
        y0 = y0.min(p.y);
        x1 = x1.max(p.x);
        y1 = y1.max(p.y);
    }
    intersects(
        &GRect {
            x: x0 - 1.0,
            y: y0 - 1.0,
            width: x1 - x0 + 2.0,
            height: y1 - y0 + 2.0,
        },
        visible,
    )
}

/// The graph's canvas and its blocks' fill: the canvas the darkest of the
/// editor's, the panels' and the window's colours, the blocks the
/// editor's (a block holds code, as a pane of code does), or, where the
/// editor's is the darkest, the lightest of the others. Blocks stand on a
/// darker canvas whatever the theme (Dark Modern's panels are darker than
/// its editor, One Dark's lighter); a theme of one surface colour (Gruvbox
/// Dark) has its canvas a shade darker than its blocks.
fn graph_surfaces(theme: &Theme) -> (u32, u32) {
    let others = [theme.panel, theme.background];
    let canvas = others
        .into_iter()
        .chain([theme.editor])
        .min_by_key(|&c| brightness(c))
        .unwrap_or(theme.editor);
    let block = if brightness(theme.editor) > brightness(canvas) {
        theme.editor
    } else {
        others
            .into_iter()
            .max_by_key(|&c| brightness(c))
            .unwrap_or(theme.panel)
    };
    let canvas = if brightness(canvas) < brightness(block) {
        canvas
    } else {
        darker(block, if theme.dark { 80 } else { 94 })
    };
    (canvas, block)
}

/// `colour` with its red, green and blue at `percent` of what they are.
fn darker(colour: u32, percent: u32) -> u32 {
    let [red, green, blue, alpha] = colour.to_be_bytes();
    let scale = |v: u8| u8::try_from(u32::from(v) * percent / 100).unwrap_or(v);
    u32::from_be_bytes([scale(red), scale(green), scale(blue), alpha])
}

/// `c`'s brightness (Rec. 709's weights over its red, green and blue).
fn brightness(c: u32) -> u32 {
    let [r, g, b, _] = c.to_be_bytes();
    2126 * u32::from(r) + 7152 * u32::from(g) + 722 * u32::from(b)
}

/// An edge's colour by kind: taken the theme's green, not taken its red
/// (`--branch-taken`, `--branch-not-taken`), unwinding the number token,
/// the rest the muted foreground.
fn edge_colour(theme: &Theme, kind: EdgeKind) -> u32 {
    match kind {
        EdgeKind::Taken => theme.branch_taken,
        EdgeKind::NotTaken => theme.branch_not_taken,
        EdgeKind::Unwind => theme.number,
        EdgeKind::Jump | EdgeKind::Next | EdgeKind::Case => theme.text_placeholder,
    }
}

/// An edge's colour touching the cursor's block: the plain ones in the
/// text colour.
fn bright(theme: &Theme, kind: EdgeKind) -> u32 {
    match kind {
        EdgeKind::Jump | EdgeKind::Next | EdgeKind::Case => theme.text,
        EdgeKind::Taken | EdgeKind::NotTaken | EdgeKind::Unwind => edge_colour(theme, kind),
    }
}

/// An orthogonal path `width` thick through `points` (screen).
fn path(out: &mut Vec<Quad>, points: &[GPoint], width: f32, color: u32) {
    let half = width / 2.0;
    for w in points.windows(2) {
        let [a, b] = w else { continue };
        let (x0, x1) = (a.x.min(b.x), a.x.max(b.x));
        let (y0, y1) = (a.y.min(b.y), a.y.max(b.y));
        out.push(Quad {
            x: x0 - half,
            y: y0 - half,
            w: x1 - x0 + width,
            h: y1 - y0 + width,
            color,
        });
    }
}

/// An arrowhead pointing down at `tip`, `reach` wide on each side.
fn arrowhead(out: &mut Vec<Quad>, tip: GPoint, reach: f32, width: f32, color: u32) {
    let steps = reach.ceil().max(1.0);
    let mut k = 0.0;
    while k < steps {
        let half = reach * (k + 1.0) / steps + width / 2.0 - 0.5;
        out.push(Quad {
            x: tip.x - half,
            y: tip.y - k - 1.0,
            w: 2.0 * half,
            h: 1.0,
            color,
        });
        k += 1.0;
    }
}

/// A block's terminal mark under `at` (its bottom's middle, screen): a
/// stub, capped for an end, dashed for an unknown target, an arrowhead
/// for a tail call; the word beside it, if any.
fn terminal(
    out: &mut Vec<Quad>,
    theme: &Theme,
    exit: Exit,
    at: GPoint,
    zoom: f32,
    name: &dyn Fn(Target) -> String,
) -> Option<String> {
    let muted = theme.text_placeholder;
    let stub = (8.0 * zoom).max(2.0);
    let width = 1.5f32.min(zoom * 1.5).max(1.0);
    if exit == Exit::Unknown {
        let mut y = 0.0;
        while y < stub {
            out.push(Quad {
                x: at.x - width / 2.0,
                y: at.y + y,
                w: width,
                h: (2.0f32).min(stub - y),
                color: muted,
            });
            y += 4.0;
        }
    } else {
        out.push(Quad {
            x: at.x - width / 2.0,
            y: at.y,
            w: width,
            h: stub,
            color: muted,
        });
    }
    let cap = |out: &mut Vec<Quad>| {
        out.push(Quad {
            x: at.x - 5.0 * zoom.sqrt(),
            y: at.y + stub - width / 2.0,
            w: 10.0 * zoom.sqrt(),
            h: width,
            color: muted,
        });
    };
    match exit {
        Exit::Edges => None,
        Exit::Return => {
            cap(out);
            None
        }
        Exit::NoReturn(_) => {
            cap(out);
            Some("noreturn".to_owned())
        }
        Exit::Stop => {
            cap(out);
            Some("stop".to_owned())
        }
        Exit::Unknown => Some("?".to_owned()),
        Exit::Tail(target) => {
            arrowhead(
                out,
                GPoint {
                    x: at.x,
                    y: at.y + stub + 3.0,
                },
                3.0,
                width,
                muted,
            );
            Some(name(target))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::Themes;

    #[test]
    fn blocks_stand_on_a_darker_canvas_in_every_bundled_theme() {
        let themes = Themes::new(None);
        for listed in themes.list() {
            let theme = themes.load(&listed.name, listed.dark).theme;
            let (canvas, block) = graph_surfaces(theme);
            assert!(
                brightness(canvas) < brightness(block),
                "{}: canvas {canvas:08x}, blocks {block:08x}",
                listed.name
            );
        }
        // Dark Modern: the blocks the editor's #1F1F1F on the panels' #181818.
        let modern = themes.load("Dark Modern", true).theme;
        assert_eq!(graph_surfaces(modern), (0x1818_18ff, 0x1f1f_1fff));
    }
}
