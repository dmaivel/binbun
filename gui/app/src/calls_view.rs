//! A listing pane shown as the call graph (the pane's toggle: Text /
//! Graph / Hex / Calls): the function at the cursor with its callers
//! above and callees below, so many levels each (settable), or a
//! Pathfinder search's subgraph with the chosen path brighter. Nodes are
//! compact boxes (a verification dot, the name, the address), edges
//! carry their call count when more than one call joins the pair, and a
//! function's calls nobody resolved hang under it as a dashed stub. A
//! click selects a node and moves the shared cursor there; a double
//! click opens the function; the overview sits in the corner as in the
//! control-flow graph.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use binbun::calls::Node;
use binbun::queries::verify::Verdict;
use binbun_gui_view::calls::{
    CallView, DEEPEST, Metrics, Point as GPoint, Rect as GRect, Shown, label,
};
use binbun_gui_view::commands::{Command, Facts};
use binbun_gui_view::context::Surface;
use binbun_gui_view::graph::{TEXT_ZOOM, fit_floor, overview_scale};
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::scroll::Wheel;
use binbun_gui_view::{FunctionId, View};
use gpui_kit::assets::IconName;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Bounds, Context, MouseButton, MouseDownEvent, MouseMoveEvent, Pixels, Point,
    ScrollDelta, ScrollEvent, Window, canvas, div, fill, point, px, size,
};

use crate::callers_view::CallersTab;
use crate::icons::icon;
use crate::panes::measured;
use crate::pathfinder_view::PathfinderUi;
use crate::right_dock::Panel;
use crate::scrolling::wheel;
use crate::theme::{hsla, solid, with_alpha};
use crate::workspace::{ICON, TabKind, Workspace};

/// The overview's longest side (logical pixels), and its margin.
const OVERVIEW: f32 = 160.0;
const OVERVIEW_MARGIN: f32 = 12.0;

/// A filled rectangle to paint, relative to the pane.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Quad {
    pub(crate) x: f32,
    pub(crate) y: f32,
    pub(crate) w: f32,
    pub(crate) h: f32,
    pub(crate) color: u32,
}

/// The call graph's, the Pathfinder's and the callers tables' state of
/// the window.
pub struct CallsUi {
    /// Caller levels a new neighbourhood shows.
    pub up: usize,
    /// Callee levels.
    pub down: usize,
    /// Each pane's call graph laid out.
    views: HashMap<PaneId, Arc<CallView>>,
    /// The Pathfinder panel.
    pub pathfinder: PathfinderUi,
    /// Each cross-references tab's callers table.
    pub callers: HashMap<PaneId, CallersTab>,
}

impl Default for CallsUi {
    fn default() -> Self {
        Self {
            up: 1,
            down: 1,
            views: HashMap::new(),
            pathfinder: PathfinderUi::default(),
            callers: HashMap::new(),
        }
    }
}

impl Workspace {
    /// Whether pane `id` shows its listing as the call graph.
    pub fn shows_calls(&self, id: PaneId) -> bool {
        matches!(self.layout.active(id), Some(TabKind::Listing))
            && self.panes.get(&id).is_some_and(|s| s.calls.on && !s.hex.on)
    }

    /// The text metrics call graphs are laid out with (zoom 1).
    fn call_metrics(&self) -> Metrics {
        let row = self.row(self.settings.listing_line_height);
        Metrics {
            char_width: self.char_width.unwrap_or(8.0),
            line_height: row,
            padding: (row * 0.3).round(),
        }
    }

    /// `node`'s name as shown and its address.
    pub fn node_name(&self, node: Node) -> (String, u64) {
        let Some(db) = self.session.as_ref().and_then(|s| s.database()) else {
            return (String::new(), 0);
        };
        match node {
            Node::Function(id) => {
                let entry = db.function(id).map_or(0, |f| f.entry);
                let name = self
                    .listing
                    .as_ref()
                    .zip(self.session.as_ref())
                    .and_then(|(l, s)| l.shown_name(entry, s.overlay()).map(str::to_owned))
                    .unwrap_or_else(|| format!("sub_{entry:X}"));
                (name, entry)
            }
            Node::Import(slot) => {
                let name = db
                    .calls()
                    .import_name(slot)
                    .map_or_else(|| format!("import_{slot:X}"), str::to_owned);
                (name, slot)
            }
        }
    }

    /// The node at `address`: the function starting there, else the
    /// import whose slot it is.
    pub fn node_at(&self, address: u64) -> Option<Node> {
        let db = self.session.as_ref()?.database()?;
        db.function_at(address).map(Node::Function).or_else(|| {
            db.calls()
                .import_name(address)
                .map(|_| Node::Import(address))
        })
    }

    /// The function holding `address`.
    fn function_holding(&self, address: u64) -> Option<FunctionId> {
        self.listing.as_ref()?.function_of(address).map(|(f, _)| f)
    }

    /// Pane `id`'s call graph, laid out now if what it shows, the text
    /// size or a name changed.
    fn call_view(&mut self, id: PaneId) -> Option<Arc<CallView>> {
        let shown = self.panes.get(&id)?.calls.shown.clone()?;
        let metrics = self.call_metrics();
        if let Some(view) = self.calls.views.get(&id)
            && view.shown == shown
            && view.metrics == metrics
            && view
                .nodes
                .iter()
                .all(|n| self.node_name(n.node).0 == n.name)
        {
            return Some(Arc::clone(view));
        }
        let session = self.session.as_ref()?;
        let graph = session.database()?.calls();
        let view = Arc::new(CallView::build(
            graph,
            shown,
            &|node| self.node_name(node),
            metrics,
        ));
        self.calls.views.insert(id, Arc::clone(&view));
        Some(view)
    }

    /// The address of pane `id`'s selected node.
    pub fn calls_address(&self, id: PaneId) -> Option<u64> {
        let state = self.panes.get(&id)?;
        let view = self.calls.views.get(&id)?;
        view.nodes.get(state.calls.selected?).map(|n| n.address)
    }

    /// Shows pane `id`'s listing as the call graph around the function at
    /// the cursor (opening a listing tab there if it shows something
    /// else).
    pub fn show_calls(&mut self, id: PaneId, window: &mut Window, cx: &mut Context<Self>) {
        let Some(centre) = self
            .current_address()
            .and_then(|a| self.function_holding(a))
        else {
            return;
        };
        let shown = Shown::Around {
            centre: Node::Function(centre),
            up: self.calls.up,
            down: self.calls.down,
        };
        self.show_in_calls(id, shown, window, cx);
    }

    /// Shows `shown` in pane `id`'s call graph.
    pub fn show_in_calls(
        &mut self,
        id: PaneId,
        shown: Shown,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !matches!(self.layout.active(id), Some(TabKind::Listing)) {
            self.open_tab(id, TabKind::Listing, window, cx);
        }
        self.leave_hex(id);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        if !state.calls.on {
            state.calls.on = true;
            state.calls.graph = state.graph.on;
            state.graph.on = false;
        }
        state.calls.shown = Some(shown);
        state.calls.selected = Some(0);
        state.calls.path = None;
        state.calls.target = None;
        state.calls.landing = true;
        self.calls.views.remove(&id);
    }

    /// Pane `id` back to its listing (or graph) from the call graph, the
    /// cursor on the selected function.
    pub fn leave_calls(&mut self, id: PaneId) {
        let address = self.calls_address(id);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        if !state.calls.on {
            return;
        }
        state.calls.on = false;
        state.graph.on = state.calls.graph;
        if let Some(address) = address {
            self.set_cursor(id, address, true);
        }
    }

    /// The commands' facts of the call graph, the Pathfinder and the
    /// callers tables over `base`.
    pub fn calls_facts(&self, base: Facts) -> Facts {
        let id = self.layout.focused();
        let callers = match self.layout.active(id) {
            Some(TabKind::Xrefs { of, .. }) => {
                matches!(self.node_at(*of), Some(Node::Function(_)))
            }
            _ => false,
        };
        let preview = self
            .layout
            .pane(id)
            .and_then(|p| p.tabs.get(p.active))
            .is_some_and(|t| t.preview);
        let whole = self
            .panes
            .get(&id)
            .and_then(|s| match &s.calls.shown {
                Some(Shown::Paths { whole, .. }) => Some(*whole),
                Some(Shown::Around { .. }) | None => None,
            })
            .filter(|_| self.shows_calls(id));
        Facts {
            calls: self.shows_calls(id),
            pathfinder: self.panel_shown(Panel::Pathfinder),
            paths: whole.is_some(),
            whole_subgraph: whole == Some(true),
            callers,
            caller_arguments: callers && self.calls.callers.get(&id).is_some_and(|t| t.on),
            preview,
            ..base
        }
    }

    /// Runs `command` where the call graph, the Pathfinder or a callers
    /// table takes it; whether it did.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "these views take a few of the registry's commands; `run` the rest"
    )]
    pub fn calls_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let id = self.layout.focused();
        match command {
            Command::ToggleCalls => {
                if self.shows_calls(id) {
                    self.leave_calls(id);
                } else {
                    self.show_calls(id, window, cx);
                }
                return true;
            }
            Command::MoreCallers
            | Command::FewerCallers
            | Command::MoreCallees
            | Command::FewerCallees => {
                self.calls_levels(id, command);
                return true;
            }
            Command::Pathfinder => {
                self.toggle_panel(Panel::Pathfinder);
                return true;
            }
            Command::PathFrom | Command::PathTo => {
                self.path_end(command == Command::PathFrom);
                return true;
            }
            Command::WholeSubgraph => {
                if let Some(state) = self.panes.get_mut(&id)
                    && let Some(Shown::Paths { whole, .. }) = &mut state.calls.shown
                {
                    *whole = !*whole;
                    state.calls.selected = Some(0);
                    state.calls.landing = true;
                }
                return true;
            }
            Command::CallerArguments => {
                self.toggle_caller_arguments(id);
                return true;
            }
            Command::KeepTab => {
                if let Some(active) = self.layout.pane(id).map(|p| p.active) {
                    self.layout.pin(id, active);
                }
                return true;
            }
            _ if !self.shows_calls(id) => return false,
            _ => {}
        }
        match command {
            Command::ToggleGraph => {
                self.leave_calls(id);
                self.set_graph(id, true);
            }
            Command::ToggleHex => {
                self.leave_calls(id);
                self.show_hex(id, window, cx);
            }
            Command::FitGraph => self.fit_calls(id),
            Command::Follow => {
                if let Some(address) = self.calls_address(id) {
                    self.leave_calls(id);
                    self.jump(address, cx);
                }
            }
            _ => return false,
        }
        true
    }

    /// One more or fewer level of callers or callees in pane `id`'s
    /// neighbourhood (and the next ones).
    fn calls_levels(&mut self, id: PaneId, command: Command) {
        let step = |n: usize, more: bool| {
            if more {
                (n + 1).min(DEEPEST)
            } else {
                n.saturating_sub(1)
            }
        };
        if matches!(command, Command::MoreCallers | Command::FewerCallers) {
            self.calls.up = step(self.calls.up, command == Command::MoreCallers);
        } else {
            self.calls.down = step(self.calls.down, command == Command::MoreCallees);
        }
        let (up, down) = (self.calls.up, self.calls.down);
        if let Some(state) = self.panes.get_mut(&id)
            && let Some(Shown::Around { centre, .. }) = state.calls.shown.clone()
        {
            state.calls.shown = Some(Shown::Around { centre, up, down });
            state.calls.landing = true;
        }
    }

    /// Fits pane `id`'s call graph to the pane.
    fn fit_calls(&mut self, id: PaneId) {
        let Some(view) = self.call_view(id) else {
            return;
        };
        let (pane, _) = self.pane_size(id);
        let floor = fit_floor(self.code_size());
        if let Some(state) = self.panes.get_mut(&id) {
            let focus = state.calls.selected.and_then(|i| view.rect(i));
            let nav = &mut state.calls.nav;
            nav.glide = None;
            nav.view.fit(
                view.layout.width,
                view.layout.height,
                pane,
                24.0,
                floor,
                focus,
            );
        }
    }

    /// Follows the shared cursor moved to `target`: its function's node
    /// selected if shown, else (a neighbourhood) the neighbourhood of it.
    fn follow_calls_target(&mut self, id: PaneId, view: &CallView) {
        let Some(target) = self.panes.get(&id).and_then(|s| s.calls.target) else {
            return;
        };
        let function = self.function_holding(target);
        let entry = function
            .and_then(|f| self.session.as_ref()?.database()?.function(f))
            .map(|f| f.entry);
        let found = entry.and_then(|e| view.at(e)).or_else(|| view.at(target));
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        state.calls.target = None;
        match (found, &state.calls.shown, function) {
            (Some(i), _, _) => {
                if state.calls.selected != Some(i) {
                    state.calls.selected = Some(i);
                    state.calls.landing = true;
                }
            }
            (None, Some(Shown::Around { up, down, .. }), Some(f)) => {
                state.calls.shown = Some(Shown::Around {
                    centre: Node::Function(f),
                    up: *up,
                    down: *down,
                });
                state.calls.selected = Some(0);
                state.calls.landing = true;
            }
            _ => state.calls.selected = None,
        }
    }

    /// Pane `id`'s call graph.
    #[expect(clippy::too_many_lines, reason = "the layers of the view, in order")]
    pub fn render_calls(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        self.char_width(window);
        let Some(mut view) = self.call_view(id) else {
            if let Some(state) = self.panes.get_mut(&id) {
                state.calls.on = false;
            }
            return self.render_listing(id, window, cx);
        };
        self.follow_calls_target(id, &view);
        if let Some(again) = self.call_view(id) {
            view = again;
        }
        let theme = self.theme;
        let focused = self.layout.focused() == id;
        let (pane, known) = self.pane_size(id);
        let verdicts: Vec<Option<bool>> = view.nodes.iter().map(|n| self.verdict(n.node)).collect();
        let Some(state) = self.panes.get_mut(&id) else {
            return div().into_any_element();
        };
        let calls = &mut state.calls;
        if known && calls.landing {
            if let Some(r) = calls.selected.and_then(|i| view.rect(i)) {
                calls.nav.glide = None;
                calls.nav.view.land(r, pane);
            }
            calls.landing = false;
        }
        if !known || calls.nav.glide() {
            window.request_animation_frame();
        }
        let nav = calls.nav.view;
        let selected = calls.selected;
        let lit: Vec<usize> = calls.path.map(|p| view.path_edges(p)).unwrap_or_default();
        let bounds = Rc::clone(&state.bounds);
        let focus = state.focus.clone();
        let zoom = nav.zoom;
        let m = view.metrics;
        let visible = nav.visible(pane);
        let mut root = div()
            .id(("calls", id.0))
            .key_context("Code")
            .track_focus(&focus)
            .size_full()
            .relative()
            .overflow_hidden()
            .bg(hsla(theme.editor))
            .rounded_b(self.island_corner())
            .font_family(self.settings.code_font.clone())
            .font_features(self.font_features())
            .text_size(px(self.code_size() * zoom))
            .line_height(px(m.line_height * zoom))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.calls_down(id, e, window, cx);
                }),
            )
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.calls_right(id, e, window, cx);
                }),
            )
            .on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, _, cx| {
                this.calls_move(id, e, cx);
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    if let Some(s) = this.panes.get_mut(&id) {
                        s.calls.nav.drag = None;
                        s.calls.nav.overview_drag = false;
                    }
                    cx.notify();
                }),
            )
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                this.calls_wheel(id, e);
                cx.notify();
            }))
            .child(measured(bounds).absolute().size_full());
        // Edges (the selected node's and the chosen path's brighter, over
        // the others), counts, and the unresolved stubs.
        let mut quads: Vec<Quad> = Vec::new();
        let mut bright: Vec<Quad> = Vec::new();
        let mut counts: Vec<(GPoint, usize)> = Vec::new();
        for (k, (edge, route)) in view.edges.iter().zip(&view.layout.edges).enumerate() {
            if !route_visible(&route.points, &visible) {
                continue;
            }
            let on = lit.contains(&k) || selected.is_some_and(|s| edge.from == s || edge.to == s);
            let (color, width, out) = if on {
                (theme.text, 2.0, &mut bright)
            } else {
                (theme.text_placeholder, 1.0, &mut quads)
            };
            let points: Vec<GPoint> = route.points.iter().map(|&p| nav.to_screen(p)).collect();
            path(out, &points, width, color);
            if let Some(&tip) = points.last() {
                arrowhead(out, tip, (4.0 * zoom.sqrt()).clamp(2.0, 5.0), width, color);
            }
            if edge.sites.len() > 1
                && let Some(&tip) = points.last()
            {
                counts.push((tip, edge.sites.len()));
            }
        }
        quads.append(&mut bright);
        let mut stubs: Vec<(GPoint, usize)> = Vec::new();
        for (i, node) in view.nodes.iter().enumerate() {
            let Some(r) = view.rect(i) else { continue };
            if node.unresolved == 0 || !intersects(&r, &visible) {
                continue;
            }
            let at = nav.to_screen(GPoint {
                x: r.right() - m.padding,
                y: r.bottom(),
            });
            dashed(
                &mut quads,
                at,
                (m.line_height * 0.8 * zoom).max(3.0),
                theme.text_placeholder,
            );
            stubs.push((at, node.unresolved));
        }
        root = root.child(
            canvas(
                |_, _, _| {},
                move |bounds, (), window, _| paint(window, bounds, &quads, 0.0),
            )
            .absolute()
            .size_full(),
        );
        // The nodes on screen.
        for (i, node) in view.nodes.iter().enumerate() {
            let Some(r) = view.rect(i) else { continue };
            if !intersects(&r, &visible) {
                continue;
            }
            let at = nav.to_screen(GPoint { x: r.x, y: r.y });
            let is_selected = selected == Some(i);
            let border = if is_selected && focused {
                theme.border_focused
            } else if is_selected {
                theme.text_muted
            } else {
                theme.border
            };
            let mut boxed = div()
                .absolute()
                .left(px(at.x))
                .top(px(at.y))
                .w(px(r.width * zoom))
                .h(px(r.height * zoom))
                .bg(hsla(if is_selected {
                    theme.element_selected
                } else {
                    solid(theme.panel)
                }))
                .border_1()
                .border_color(hsla(border))
                .overflow_hidden();
            if zoom >= TEXT_ZOOM {
                let dot = match verdicts.get(i).copied().flatten() {
                    Some(true) => theme.agreed,
                    Some(false) => theme.error,
                    None => with_alpha(theme.panel, 0),
                };
                let name_color = match node.node {
                    Node::Function(_) => theme.function,
                    Node::Import(_) => theme.type_,
                };
                let text = label(node);
                let split = node.name.len();
                let runs = vec![
                    self.text_run(split, name_color, None),
                    self.text_run(text.len() - split, theme.text_muted, None),
                ];
                boxed = boxed.child(
                    div()
                        .flex()
                        .items_center()
                        .h_full()
                        .px(px(m.padding * zoom))
                        .gap(px(m.char_width * 0.5 * zoom))
                        .whitespace_nowrap()
                        .child(
                            div()
                                .flex_none()
                                .size(px(m.char_width * 0.75 * zoom))
                                .rounded_full()
                                .bg(hsla(dot)),
                        )
                        .child(gpui_kit::StyledText::new(text).with_runs(runs)),
                );
            }
            root = root.child(boxed);
        }
        // Counts beside arrowheads, unresolved counts beside stubs.
        if zoom >= TEXT_ZOOM {
            let small = px(self.code_size() * zoom * 0.85);
            for (at, n) in counts {
                root = root.child(
                    div()
                        .absolute()
                        .left(px(at.x + 5.0 * zoom.sqrt()))
                        .top(px(at.y - m.line_height * zoom))
                        .text_size(small)
                        .text_color(hsla(theme.text_muted))
                        .child(format!("×{n}")),
                );
            }
            for (at, n) in stubs {
                root = root.child(
                    div()
                        .absolute()
                        .left(px(at.x + 4.0 * zoom.sqrt()))
                        .top(px(at.y + 1.0))
                        .text_size(small)
                        .text_color(hsla(theme.text_placeholder))
                        .child(format!("?{n}")),
                );
            }
        }
        if self.overview
            && (view.layout.width * zoom > pane.width || view.layout.height * zoom > pane.height)
        {
            root = root.child(self.calls_overview(id, &view, nav, pane, selected, cx));
        }
        root.into_any_element()
    }

    /// Whether `node` agreed with L1 (`Some(true)`), found to differ, or
    /// not checked, in either view.
    fn verdict(&self, node: Node) -> Option<bool> {
        let Node::Function(f) = node else {
            return None;
        };
        [View::Reading, View::Exact].iter().find_map(|&view| {
            let verification = self.facts.verified.get(&(f, view == View::Reading))?;
            match verification.verdict {
                Verdict::Agreed(_) => Some(true),
                Verdict::Differs(_) => Some(false),
                Verdict::NotCheckable(_) => None,
            }
        })
    }

    /// The overview: every node a box, every edge a line, the view's
    /// rectangle outlined, the selection in the accent.
    fn calls_overview(
        &self,
        id: PaneId,
        view: &CallView,
        nav: binbun_gui_view::graph::Viewport,
        pane: GSize,
        selected: Option<usize>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let side = self.row(OVERVIEW);
        let scale = overview_scale(view.layout.width, view.layout.height, side);
        let (width, height) = (view.layout.width * scale, view.layout.height * scale);
        let mut quads: Vec<Quad> = Vec::new();
        for route in &view.layout.edges {
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
                with_alpha(theme.text_placeholder, 0xb0),
            );
        }
        for (i, r) in view.layout.nodes.iter().enumerate() {
            quads.push(Quad {
                x: r.x * scale,
                y: r.y * scale,
                w: (r.width * scale).max(1.0),
                h: (r.height * scale).max(1.0),
                color: if selected == Some(i) {
                    theme.accent
                } else {
                    theme.border
                },
            });
        }
        let v = nav.visible(pane);
        let (vx, vy, vw, vh) = (v.x * scale, v.y * scale, v.width * scale, v.height * scale);
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
                color: theme.text_muted,
            });
        }
        let margin = self.row(OVERVIEW_MARGIN);
        div()
            .id(("calls-overview", id.0))
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
                    this.calls_overview_to(id, e.position, scale);
                    if let Some(st) = this.panes.get_mut(&id) {
                        st.calls.nav.overview_drag = true;
                    }
                    cx.notify();
                }),
            )
            .on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, _, cx| {
                if this
                    .panes
                    .get(&id)
                    .is_some_and(|st| st.calls.nav.overview_drag)
                    && e.dragging()
                {
                    cx.stop_propagation();
                    this.calls_overview_to(id, e.position, scale);
                    cx.notify();
                }
            }))
            .child(
                canvas(
                    |_, _, _| {},
                    move |bounds, (), window, _| paint(window, bounds, &quads, 1.0),
                )
                .absolute()
                .size_full(),
            )
            .into_any_element()
    }

    /// Centres pane `id`'s view on the point under `position` in the
    /// overview (scaled by `scale`).
    fn calls_overview_to(&mut self, id: PaneId, position: Point<Pixels>, scale: f32) {
        let (pane, _) = self.pane_size(id);
        let margin = self.row(OVERVIEW_MARGIN);
        let Some(view) = self.calls.views.get(&id).cloned() else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let b = state.bounds.get();
        let (width, height) = (view.layout.width * scale, view.layout.height * scale);
        let left = f32::from(b.origin.x) + pane.width - margin - width - 1.0;
        let top = f32::from(b.origin.y) + pane.height - margin - height - 1.0;
        let gx = (f32::from(position.x) - left) / scale;
        let gy = (f32::from(position.y) - top) / scale;
        let v = &mut state.calls.nav.view;
        let shown = v.visible(pane);
        v.x = gx - shown.width / 2.0;
        v.y = gy - shown.height / 2.0;
        state.calls.nav.glide = None;
    }

    /// Where `position` is in pane `id`'s call graph: on screen and in the
    /// graph.
    fn calls_point(&self, id: PaneId, position: Point<Pixels>) -> Option<(GPoint, GPoint)> {
        let state = self.panes.get(&id)?;
        let b = state.bounds.get();
        let screen = GPoint {
            x: f32::from(position.x - b.origin.x),
            y: f32::from(position.y - b.origin.y),
        };
        Some((screen, state.calls.nav.view.to_graph(screen)))
    }

    /// A click: on a node, it is selected and the shared cursor goes to
    /// it (a double click opens it); elsewhere the view is dragged.
    fn calls_down(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.close_peek();
        if self.layout.focused() != id {
            self.focus_pane(id, window, cx);
        }
        let Some((screen, at)) = self.calls_point(id, e.position) else {
            return;
        };
        let Some(view) = self.calls.views.get(&id).cloned() else {
            return;
        };
        if let Some(i) = view.hit(at) {
            let Some(address) = view.nodes.get(i).map(|n| n.address) else {
                return;
            };
            if e.click_count == 2 {
                self.leave_calls(id);
                self.jump(address, cx);
                return;
            }
            self.select_node(id, i, address);
            cx.notify();
            return;
        }
        if let Some(state) = self.panes.get_mut(&id) {
            state.calls.nav.drag = Some(screen);
            state.calls.nav.glide = None;
        }
        cx.notify();
    }

    /// Selects node `i` (at `address`) of pane `id`: the pane's listing
    /// cursor goes there, and the sync group follows.
    fn select_node(&mut self, id: PaneId, i: usize, address: u64) {
        let line = self.listing.as_ref().map(|l| l.line_of(address));
        if let Some(state) = self.panes.get_mut(&id) {
            state.calls.selected = Some(i);
            if let Some(line) = line {
                state.listing.cursor = line;
                state.listing.token = None;
            }
        }
        self.moved(id);
    }

    /// A right click: the node under the pointer selected, then the
    /// context menu about it.
    fn calls_right(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let hit = self
            .calls_point(id, e.position)
            .zip(self.calls.views.get(&id).cloned())
            .and_then(|((_, at), view)| {
                let i = view.hit(at)?;
                Some((i, view.nodes.get(i)?.address))
            });
        if self.layout.focused() != id {
            self.focus_pane(id, window, cx);
        }
        if let Some((i, address)) = hit {
            self.select_node(id, i, address);
            self.menu_subject = Some(address);
            self.open_context_menu(Surface::Row, e.position, window, cx);
        }
    }

    fn calls_move(&mut self, id: PaneId, e: &MouseMoveEvent, cx: &mut Context<Self>) {
        let Some((screen, _)) = self.calls_point(id, e.position) else {
            return;
        };
        if let Some(state) = self.panes.get_mut(&id)
            && let Some(from) = state.calls.nav.drag
        {
            if e.dragging() {
                let v = &mut state.calls.nav.view;
                v.x -= (screen.x - from.x) / v.zoom;
                v.y -= (screen.y - from.y) / v.zoom;
                state.calls.nav.drag = Some(screen);
                cx.notify();
                return;
            }
            state.calls.nav.drag = None;
        }
    }

    /// The wheel over pane `id`'s call graph: with Ctrl it zooms about
    /// the pointer, with Shift it pans across, else it pans down.
    fn calls_wheel(&mut self, id: PaneId, e: &ScrollEvent) {
        let row = self.row(self.settings.listing_line_height);
        let smooth = self.settings.smooth_scroll;
        let Some((screen, _)) = self.calls_point(id, e.position) else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let nav = &mut state.calls.nav;
        let (pixels, notch) = match wheel(e) {
            Wheel::Lines(l) => (l * row, true),
            Wheel::Pixels(p) => (p, false),
        };
        if e.modifiers.control {
            nav.glide = None;
            let notches = if notch {
                pixels / (3.0 * row)
            } else {
                pixels / 50.0
            };
            nav.view.zoom_at(1.15f32.powf(notches), screen);
        } else if e.modifiers.shift {
            nav.pan(-pixels, 0.0, smooth && notch);
        } else {
            let across = match e.delta {
                ScrollDelta::Pixels(p) => -f32::from(p.x),
                ScrollDelta::Lines(l) => -l.x * row,
            };
            nav.pan(across, -pixels, smooth && notch);
        }
    }

    /// The call graph's tools in pane `id`'s toolbar: the caller and
    /// callee levels of a neighbourhood, each with its steppers; a path
    /// search's whole-subgraph toggle.
    pub fn calls_tools(&self, id: PaneId, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.shows_calls(id) {
            return None;
        }
        let shown = self.panes.get(&id)?.calls.shown.clone()?;
        let (up, down) = match shown {
            Shown::Around { up, down, .. } => (up, down),
            Shown::Paths { whole, .. } => {
                let toggle = self
                    .icon_button(
                        "calls-whole",
                        IconName::Network,
                        Command::WholeSubgraph,
                        true,
                        whole,
                        cx,
                    )
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _: &MouseDownEvent, _, _| {
                            this.layout.focus(id);
                        }),
                    );
                return Some(toggle.into_any_element());
            }
        };
        let theme = self.theme;
        let stepper =
            |name: IconName, n: usize, less: Command, more: Command, cx: &mut Context<Self>| {
                let focus = move |this: &mut Self,
                                  _: &MouseDownEvent,
                                  _: &mut Window,
                                  _: &mut Context<Self>| {
                    this.layout.focus(id);
                };
                div()
                    .flex()
                    .items_center()
                    .gap(px(1.0))
                    .child(icon(name, self.z(ICON), hsla(theme.text_muted)))
                    .child(
                        self.icon_button(
                            ("calls-less", less as usize),
                            IconName::Minus,
                            less,
                            n > 0,
                            false,
                            cx,
                        )
                        .on_mouse_down(MouseButton::Left, cx.listener(focus)),
                    )
                    .child(
                        div()
                            .min_w(self.z(10.0))
                            .text_color(hsla(theme.text))
                            .child(n.to_string()),
                    )
                    .child(
                        self.icon_button(
                            ("calls-more", more as usize),
                            IconName::Plus,
                            more,
                            n < DEEPEST,
                            false,
                            cx,
                        )
                        .on_mouse_down(MouseButton::Left, cx.listener(focus)),
                    )
            };
        Some(
            div()
                .flex()
                .items_center()
                .gap(self.z(8.0))
                .child(stepper(
                    IconName::ArrowUp,
                    up,
                    Command::FewerCallers,
                    Command::MoreCallers,
                    cx,
                ))
                .child(stepper(
                    IconName::ArrowDown,
                    down,
                    Command::FewerCallees,
                    Command::MoreCallees,
                    cx,
                ))
                .into_any_element(),
        )
    }
}

/// Paints `quads` (relative to `bounds`, moved by `inset`).
fn paint(window: &mut Window, bounds: Bounds<Pixels>, quads: &[Quad], inset: f32) {
    for q in quads {
        window.paint_quad(fill(
            Bounds::new(
                point(
                    bounds.origin.x + px(q.x + inset),
                    bounds.origin.y + px(q.y + inset),
                ),
                size(px(q.w), px(q.h)),
            ),
            hsla(q.color),
        ));
    }
}

/// The graph's size, for the overview and fitting.
type GSize = binbun_gui_view::graph::Size;

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

/// A dashed stub `length` long down from `at`.
fn dashed(out: &mut Vec<Quad>, at: GPoint, length: f32, color: u32) {
    let mut y = 0.0;
    while y < length {
        out.push(Quad {
            x: at.x - 0.5,
            y: at.y + y,
            w: 1.0,
            h: 2.0f32.min(length - y),
            color,
        });
        y += 4.0;
    }
}
