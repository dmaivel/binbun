//! The window's layout: the title bar, the map on the left, the
//! panes (flat with hairlines, or islands), and the status bar.
//!
//! A pane has a tab bar (back and forward on the left, split and
//! maximise on the right; the active tab filled with the editor's colour
//! and open to the content below, the others on the darker bar; a close
//! button on the active and the hovered tab; a preview tab in italic) and
//! a toolbar (the breadcrumb `file › section › function`; small
//! tools on the right: the C view, a list's filter). Every bar is a line
//! of the interface font plus padding.

use std::cell::Cell;
use std::f32::consts::TAU;
use std::rc::Rc;
use std::time::Instant;

use binbun_gui_view::commands::{self, Command};
use binbun_gui_view::layout::{Axis, Node, PaneId, Tab, TabDrop};
use binbun_gui_view::map;
use binbun_gui_view::map::{Group, Kind};
use binbun_gui_view::session::{Session, analysis_label};
use binbun_gui_view::{Stage, View};
use gpui_kit::assets::IconName;
use gpui_kit::base::actions::{SelectLeft, SelectRight};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, AnyView, App, Bounds, Canvas, ClickEvent, Context, Div, DragMoveEvent, ElementId,
    ExternalPaths, IntoElement, KeyDownEvent, ModifiersChangedEvent, MouseButton, MouseDownEvent,
    MouseMoveEvent, Pixels, Render, SharedString, Stateful, Transformation, Window, canvas,
    deferred, div, px, radians,
};

use crate::actions;
use crate::context_menu::OwnItem;
use crate::icons::icon;
use crate::sidebar::{MAX_WIDTH as SIDEBAR_MAX, MIN_WIDTH as SIDEBAR_MIN, kind_icon, tabular};
use crate::tab_drag::{DraggedTab, TabPreview};
use crate::theme::hsla;
use crate::workspace::{
    EdgeDrag, ICON, ICON_BUTTON, STATUS_PAD, TAB_PAD, TOOLBAR_PAD, TabKind, Workspace,
};
use crate::{FRAME_TRACE, STARTED};

/// A pane's least width or height while a divider is dragged (logical).
const PANE_MIN: f32 = 120.0;

/// An island's frame: half the islands' gap (logical).
pub const FRAME: f32 = 2.0;

/// The radius of an island's surface's corners, inside its frame
/// (logical).
const ISLAND_RADIUS: f32 = 5.0;

/// An island's hairline, around its surface inside its frame (device
/// independent, as the flat panes' hairlines).
const HAIRLINE: f32 = 1.0;

/// A choice of a pane's view selector (its toolbar's, as text).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ViewChoice {
    Listing,
    Unified,
    Graph,
    Hex,
    Calls,
    C,
    Reading,
    Exact,
    Ir,
}

impl ViewChoice {
    /// What it says.
    const fn label(self) -> &'static str {
        match self {
            Self::Listing => "Listing",
            Self::Unified => "Unified",
            Self::Graph => "Graph",
            Self::Hex => "Hex",
            Self::Calls => "Calls",
            Self::C => "C",
            Self::Reading => "Reading",
            Self::Exact => "Exact",
            Self::Ir => "IR",
        }
    }

    /// What the view button and its menu call it: the reading view is the
    /// C, the exact view the exact C.
    const fn menu_label(self) -> &'static str {
        match self {
            Self::Exact => "Exact C",
            Self::Reading | Self::C => "C",
            Self::Listing | Self::Unified | Self::Graph | Self::Hex | Self::Calls | Self::Ir => {
                self.label()
            }
        }
    }

    /// The command whose keys choose it (its tooltip names them).
    const fn command(self) -> Command {
        match self {
            Self::Listing | Self::C => Command::SwitchView,
            Self::Unified => Command::ToggleUnified,
            Self::Graph => Command::ToggleGraph,
            Self::Hex => Command::ToggleHex,
            Self::Calls => Command::ToggleCalls,
            Self::Reading | Self::Exact => Command::ToggleReadingView,
            Self::Ir => Command::ShowInIr,
        }
    }
}

impl Workspace {
    /// The pane tree under `node`, the split at `path` (child indices from
    /// the root): its children by their sizes, a divider between each two
    /// (a hairline, or the islands' frames, with a 4 px hit area over it)
    /// that drags them and evens them on a double-click.
    fn render_node(
        &mut self,
        node: &Node,
        path: &[usize],
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        match node {
            Node::Pane(id) => self.render_pane(*id, window, cx),
            Node::Split {
                axis,
                children,
                sizes,
            } => {
                let bounds = Rc::clone(
                    self.layout_ui
                        .split_bounds
                        .entry(path.to_vec())
                        .or_default(),
                );
                let mut split = div()
                    .relative()
                    .flex()
                    .size_full()
                    .min_w_0()
                    .min_h_0()
                    .child(measured(bounds).absolute().size_full());
                split = match axis {
                    Axis::Row => split.flex_row(),
                    Axis::Column => split.flex_col(),
                };
                // The hit area centred on the hairline (a cell's first
                // pixel), or on the gap between islands (their frames').
                let offset = if self.settings.islands { -2.0 } else { -1.5 };
                for (i, (child, &size)) in children.iter().zip(sizes).enumerate() {
                    let child_path = [path, &[i]].concat();
                    let element = self.render_node(child, &child_path, window, cx);
                    let cell = div()
                        .relative()
                        .flex_1()
                        .flex_grow(size)
                        .min_w_0()
                        .min_h_0()
                        .flex();
                    let cell = if self.settings.islands || i == 0 {
                        cell
                    } else {
                        match axis {
                            Axis::Row => cell.border_l_1(),
                            Axis::Column => cell.border_t_1(),
                        }
                        .border_color(hsla(self.theme.border))
                    };
                    let divider = (i > 0).then(|| Self::divider(*axis, path, i, offset, cx));
                    split = split.child(cell.child(element).children(divider));
                }
                split.into_any_element()
            }
        }
    }

    /// The hit area of the divider before child `index` of the split at
    /// `path`, `offset` pixels from the child's start.
    fn divider(
        axis: Axis,
        path: &[usize],
        index: usize,
        offset: f32,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let id = ElementId::Name(format!("divider{path:?}.{index}").into());
        let handle = div().id(id).absolute();
        let handle = match axis {
            Axis::Row => handle
                .top_0()
                .bottom_0()
                .left(px(offset))
                .w(px(4.0))
                .cursor_col_resize(),
            Axis::Column => handle
                .left_0()
                .right_0()
                .top(px(offset))
                .h(px(4.0))
                .cursor_row_resize(),
        };
        let down = path.to_vec();
        let click = path.to_vec();
        handle
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    this.layout_ui.drag = Some(EdgeDrag::Split {
                        path: down.clone(),
                        index,
                    });
                    cx.stop_propagation();
                    cx.notify();
                }),
            )
            .on_click(cx.listener(move |this, e: &ClickEvent, _, cx| {
                if e.click_count() == 2 {
                    this.layout.even(&click);
                    cx.notify();
                }
            }))
    }

    /// Follows the pointer during `drag`: the map's or the dock's width
    /// (logical, within the map's limits), a split's divider (each pane
    /// kept [`PANE_MIN`] long), a hex pane's side area under its bytes.
    fn drag_edge(&mut self, drag: &EdgeDrag, e: &MouseMoveEvent, window: &Window) {
        let scale = self.settings.ui_scale;
        match drag {
            EdgeDrag::Map => {
                let x = f32::from(e.position.x) / scale;
                self.sidebar_width = x.clamp(SIDEBAR_MIN, SIDEBAR_MAX);
            }
            EdgeDrag::Dock => {
                let x = f32::from(window.viewport_size().width - e.position.x) / scale;
                self.layout_ui.dock_width = Some(x.clamp(SIDEBAR_MIN, SIDEBAR_MAX));
            }
            EdgeDrag::DockSplit => self.drag_dock_split(e.position.y),
            EdgeDrag::Split { path, index } => {
                let bounds = self.layout_ui.split_bounds.get(path).map(|b| b.get());
                if let (Some(bounds), Some((axis, _))) = (bounds, self.layout.split_at(path)) {
                    let (at, length) = match axis {
                        Axis::Row => (e.position.x - bounds.origin.x, bounds.size.width),
                        Axis::Column => (e.position.y - bounds.origin.y, bounds.size.height),
                    };
                    self.layout.drag_divider(
                        path,
                        *index,
                        f32::from(at),
                        f32::from(length),
                        PANE_MIN * scale,
                    );
                }
            }
            EdgeDrag::HexSide(id) => self.drag_hex_side(*id, e.position.y),
        }
    }

    /// An island: the panel's surface in its half of the gap around it,
    /// its frame, in the gap's colour; its last children are
    /// [`Self::island_edge`], which rounds the surface's corners and
    /// draws its hairline, in the 1 px padding around its other children.
    /// The surfaces at its corners round theirs by [`Self::island_corner`],
    /// so that while translucent the edge lies beside them, never on them.
    pub fn island(&self) -> Div {
        let island = div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .overflow_hidden();
        if self.settings.islands {
            self.gap_frame(island).p(px(HAIRLINE))
        } else {
            island
        }
    }

    /// The radius of a surface's corners at an island's corners, inside
    /// its hairline; none without islands.
    pub fn island_corner(&self) -> Pixels {
        if self.settings.islands {
            self.z(ISLAND_RADIUS) - px(HAIRLINE)
        } else {
            px(0.0)
        }
    }

    /// How far an island's children are inside its edge: its hairline
    /// (none without islands).
    pub fn island_inset(&self) -> Pixels {
        px(if self.settings.islands { HAIRLINE } else { 0.0 })
    }

    /// An island of the panel's colour for children that paint none
    /// (a dock's). Translucent, the panel is a backdrop beside the frame
    /// rather than under it.
    pub fn panel_island(&self) -> Div {
        let theme = self.theme;
        self.island()
            .bg(hsla(theme.under(theme.panel)))
            .when(theme.translucent, |d| {
                d.child(
                    div()
                        .absolute()
                        .inset(self.island_inset())
                        .rounded(self.island_corner())
                        .bg(hsla(theme.panel)),
                )
            })
    }

    /// An island's edge, painted over its other children (GPUI clips
    /// children to rectangles, so whatever they paint): its corners
    /// outside its rounded surface in the gap's colour, then its hairline
    /// in the border's, along the rounded outline. Each corner is a ring
    /// around the corner's circle (the corner's square clips it), as wide
    /// as the radius so that it reaches the corner. The rings reach in to
    /// the hairline's inner edge, where the surfaces' corners are, so that
    /// the hairline's antialiased curve lies on them rather than on a seam
    /// between two antialiased edges. None without islands.
    pub fn island_edge(&self) -> Vec<Div> {
        if !self.settings.islands {
            return Vec::new();
        }
        let r = self.z(ISLAND_RADIUS);
        // The ring's inner and outer radii about the circle's centre, `r`
        // in from the corner.
        let inner = r - px(HAIRLINE);
        let outer = inner + r;
        let cap = |top: bool, left: bool| {
            let offset = r - outer;
            let ring = div()
                .absolute()
                .size(outer * 2.0)
                .rounded_full()
                .border(r)
                .border_color(hsla(self.theme.gap));
            let ring = if top {
                ring.top(offset)
            } else {
                ring.bottom(offset)
            };
            let ring = if left {
                ring.left(offset)
            } else {
                ring.right(offset)
            };
            let square = div().absolute().size(r).overflow_hidden();
            let square = if top {
                square.top_0()
            } else {
                square.bottom_0()
            };
            let square = if left {
                square.left_0()
            } else {
                square.right_0()
            };
            square.child(ring)
        };
        let hairline = div()
            .absolute()
            .inset_0()
            .rounded(r)
            .border(px(HAIRLINE))
            .border_color(hsla(self.theme.border));
        vec![
            cap(true, true),
            cap(true, false),
            cap(false, true),
            cap(false, false),
            hairline,
        ]
    }

    /// `element` framed by half the islands' gap, in the gap's colour.
    pub fn gap_frame(&self, mut element: Div) -> Div {
        let half: gpui_kit::AbsoluteLength = self.z(FRAME).into();
        let widths = &mut element.style().border_widths;
        widths.top = Some(half);
        widths.right = Some(half);
        widths.bottom = Some(half);
        widths.left = Some(half);
        element.border_color(hsla(self.theme.gap))
    }

    fn render_pane(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let kind = self.layout.active(id).cloned();
        let content = match &kind {
            Some(TabKind::Listing) if self.shows_unified(id) => self.render_unified(id, window, cx),
            Some(TabKind::Listing) if self.shows_hex(id) => self.render_hex(id, window, cx),
            Some(TabKind::Listing) if self.shows_calls(id) => self.render_calls(id, window, cx),
            Some(TabKind::Listing) if self.shows_graph(id) => self.render_graph(id, window, cx),
            Some(TabKind::Listing) => self.render_listing(id, window, cx),
            Some(TabKind::C { .. }) if self.shows_ir(id) => self.render_ir(id, window, cx),
            Some(TabKind::C { .. }) => self.render_c(id, window, cx),
            Some(TabKind::Settings) => self.render_settings(id, window, cx),
            Some(TabKind::Xrefs { .. }) if self.shows_callers(id) => self.render_callers(id, cx),
            Some(TabKind::Strings | TabKind::Xrefs { .. }) => self.render_list(id, cx),
            Some(TabKind::Struct(_)) => self.render_struct(id, cx),
            Some(TabKind::Found(n)) => self.render_results(id, *n, window, cx),
            Some(TabKind::Folder(key)) => self.render_folder(id, key, cx),
            Some(TabKind::Console) => self.render_console(window, cx),
            Some(TabKind::Terminal(terminal)) => self.render_terminal(id, *terminal, window, cx),
            None => {
                let focus = self.panes.get(&id).map(|s| s.focus.clone());
                div()
                    .size_full()
                    .bg(hsla(self.theme.editor))
                    .rounded_b(self.island_corner())
                    .when_some(focus, |d, f| d.track_focus(&f))
                    .into_any_element()
            }
        };
        // Only the bottom dock and a pane of lists or shells have a tab
        // bar: one showing code has its toolbar as its top, the settings
        // and a struct their own (the window's tabs are the places, the
        // settings and structs). The console's header is its toolbar.
        let bar = self.layout.is_dock(id)
            || self.layout.pane(id).is_some_and(|p| {
                p.tabs
                    .iter()
                    .any(|t| crate::tabs::is_below_code(&t.content))
            });
        self.island()
            .id(("pane", id.0))
            .bg(hsla(self.theme.under(self.theme.editor)))
            .when(bar, |d| d.child(self.tab_bar(id, cx)))
            .when(
                kind.is_some()
                    && !matches!(
                        kind,
                        Some(
                            TabKind::Settings
                                | TabKind::Struct(_)
                                | TabKind::Console
                                | TabKind::Terminal(_)
                        )
                    ),
                |d| d.child(self.toolbar(id, !bar, cx)),
            )
            .child(
                div()
                    .relative()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .child(self.find_area(id, content, cx))
                    .on_drag_move::<DraggedTab>(cx.listener(
                        move |this, e: &DragMoveEvent<DraggedTab>, _, cx| {
                            this.tab_drag_over(id, e, cx);
                        },
                    ))
                    .on_drop(cx.listener(move |this, d: &DraggedTab, window, cx| {
                        this.drop_on_body(id, d.tab, window, cx);
                    }))
                    .children(self.drop_zone(id, cx)),
            )
            .children(self.island_edge())
            .into_any_element()
    }

    /// Pane `id`'s `content` under its find bar, if one is open: both in
    /// the find bar's key context (`F3` and `Shift+F3` there).
    fn find_area(&mut self, id: PaneId, content: AnyElement, cx: &mut Context<Self>) -> AnyElement {
        let bar = self.render_find_bar(id, cx);
        let open = bar.is_some();
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .when(open, |d| d.key_context("Find"))
            .children(bar)
            .child(div().flex_1().min_h_0().child(content))
            .into_any_element()
    }

    /// An icon button: `name` in a square, muted at
    /// rest, the text colour when `on`, a field on hover; its tooltip
    /// names `command` and its keys. Disabled when not `enabled`.
    pub fn icon_button(
        &self,
        id: impl Into<ElementId>,
        name: IconName,
        command: Command,
        enabled: bool,
        on: bool,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        self.icon_button_look(id, name, command, enabled, on)
            .when(enabled, |d| {
                d.on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                    this.run(command, window, cx);
                }))
            })
    }

    /// [`Self::icon_button`] without its click: for a button whose click
    /// does something else (opens a menu), its tooltip `command`'s.
    pub fn icon_button_look(
        &self,
        id: impl Into<ElementId>,
        name: IconName,
        command: Command,
        enabled: bool,
        on: bool,
    ) -> Stateful<Div> {
        let theme = self.theme;
        let color = if !enabled {
            theme.text_placeholder
        } else if on {
            theme.text
        } else {
            theme.text_muted
        };
        let title = commands::lookup(command).map_or("", |i| i.title);
        div()
            .id(id)
            .flex()
            .flex_none()
            .items_center()
            .justify_center()
            .size(self.z(ICON_BUTTON))
            .rounded(self.z(4.0))
            .when(on, |d| d.bg(hsla(theme.element_selected)))
            .when(enabled, |d| d.hover(|s| s.bg(hsla(theme.element_hover))))
            .tooltip(self.key_tooltip(title, command))
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
            .child(icon(name, self.z(ICON), hsla(color)))
    }

    /// A tooltip saying `title` and `command`'s keys as the registry
    /// writes them, a sequence whole (`Ctrl-K S`; GPUI Kit's key hint
    /// shows only the first keystroke).
    pub fn key_tooltip(
        &self,
        title: impl Into<SharedString>,
        command: Command,
    ) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
        self.keyed_tooltip(title, commands::key_label(&self.keymap, command))
    }

    /// A tooltip saying `title` and, muted at its right, `key`.
    pub fn keyed_tooltip(
        &self,
        title: impl Into<SharedString>,
        key: Option<String>,
    ) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
        let title = title.into();
        let muted = hsla(self.theme.text_muted);
        move |window, cx| {
            let (title, key) = (title.clone(), key.clone());
            Tooltip::element(move |_, _| {
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(title.clone())
                    .children(
                        key.clone()
                            .map(|key| div().flex_none().text_xs().text_color(muted).child(key)),
                    )
            })
            .build(window, cx)
        }
    }

    /// A tab's label: a pane's tab of code is named after its view (where
    /// it is, the breadcrumb says).
    fn tab_label(&self, tab: &Tab<TabKind>) -> String {
        let named = |address: u64| {
            let session = self.session.as_ref()?;
            self.listing
                .as_ref()?
                .shown_name(address, session.overlay())
                .map(str::to_owned)
        };
        match &tab.content {
            TabKind::Listing => {
                let view = match self.layout.find_tab(tab.id()) {
                    Some((pane, _)) if self.layout.active_tab(pane) == Some(tab.id()) => {
                        self.pane_view(pane)
                    }
                    Some(_) | None => self.places.view(tab.id()).unwrap_or_default(),
                };
                if view.calls {
                    "Calls"
                } else if view.hex {
                    "Hex"
                } else if view.graph {
                    "Graph"
                } else {
                    "Listing"
                }
                .to_owned()
            }
            TabKind::Settings => "Settings".to_owned(),
            TabKind::Strings => "Strings".to_owned(),
            TabKind::Xrefs { of, .. } => format!(
                "Xrefs to {}",
                named(*of).unwrap_or_else(|| format!("{of:X}"))
            ),
            TabKind::C { view, .. } => match view {
                View::Reading => "C",
                View::Exact => "Exact C",
            }
            .to_owned(),
            TabKind::Struct(target) => self.struct_tab_label(target),
            TabKind::Found(n) => self.results_label(*n),
            TabKind::Folder(key) => self
                .folder_path(key)
                .pop()
                .unwrap_or_else(|| "Folder".to_owned()),
            TabKind::Console => "Console".to_owned(),
            TabKind::Terminal(id) => self.terminal_title(*id),
        }
    }

    /// A tab's icon.
    pub(crate) fn tab_icon(kind: &TabKind, graph: bool) -> IconName {
        match kind {
            TabKind::Listing if graph => IconName::Workflow,
            TabKind::Listing => IconName::Binary,
            TabKind::C { .. } => IconName::FileCode,
            TabKind::Settings => IconName::Settings,
            TabKind::Strings => IconName::Quote,
            TabKind::Xrefs { .. } => IconName::ArrowRightLeft,
            TabKind::Struct(_) => IconName::Braces,
            TabKind::Found(_) => IconName::Search,
            TabKind::Console => IconName::SquareTerminal,
            TabKind::Terminal(_) => IconName::Terminal,
            // The icon of the folder's items.
            TabKind::Folder(key) => {
                let items = match Group::of_key(key) {
                    Some(Group::Bookmarks) => Kind::Bookmark,
                    Some(Group::Sections) => Kind::Section,
                    Some(Group::Functions) | None => Kind::Function,
                    Some(Group::Imports) => Kind::Import,
                    Some(Group::Exports) => Kind::Export,
                    Some(Group::Data) => Kind::Data,
                    Some(Group::Types) => Kind::Type,
                };
                kind_icon(items, false)
            }
        }
    }

    #[expect(clippy::too_many_lines, reason = "nav, tabs, tools")]
    fn tab_bar(&self, id: PaneId, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let Some(pane) = self.layout.pane(id) else {
            return div().into_any_element();
        };
        let count = pane.tabs.len();
        let focused = self.layout.focused() == id;
        // Each part paints the bar's colour itself, so the active tab's
        // never lies on it; a pixel on top centres what is in it on the
        // bar as drawn, as the tabs are.
        let edge = |d: Div| {
            d.h_full()
                .pt(px(1.0))
                .bg(hsla(theme.tab_bar))
                .border_b_1()
                .border_color(hsla(theme.border))
        };
        // Tabs past the bar's width scroll sideways: the
        // wheel's vertical turns move them too, with no scrollbar; the
        // active tab is scrolled into view whenever it changes (opened,
        // switched to, dragged along).
        let mut tabs = div()
            .id(("tabs", id.0))
            .flex()
            .flex_initial()
            .h_full()
            .min_w_0()
            .overflow_x_scroll();
        if let Some(state) = self.panes.get(&id) {
            tabs = tabs.track_scroll(&state.tab_scroll);
            let active = pane
                .tabs
                .get(pane.active)
                .map(|tab| (tab.id(), pane.active));
            if active.is_some() && state.tab_revealed.replace(active) != active {
                state.tab_scroll.scroll_to_item(pane.active);
            }
        }
        for (index, tab) in pane.tabs.iter().enumerate() {
            let active = index == pane.active;
            let label = self.tab_label(tab);
            // Each tab's own view (the active one's as its pane shows it).
            let view = if active {
                self.pane_view(id)
            } else {
                self.places.view(tab.id()).unwrap_or_default()
            };
            let (tab_icon, icon_color) = if let TabKind::Terminal(terminal) = tab.content {
                self.terminal_icon(terminal)
            } else if tab.content == TabKind::Listing && view.hex {
                (IconName::Grid3x3, theme.text_muted)
            } else if tab.content == TabKind::Listing && view.calls {
                (IconName::Network, theme.text_muted)
            } else {
                (Self::tab_icon(&tab.content, view.graph), theme.text_muted)
            };
            let dragged = DraggedTab {
                tab: tab.id(),
                label: label.clone(),
                icon: tab_icon,
            };
            let (scale, text) = (self.settings.ui_scale, self.settings.ui_font_size);
            let label_color = if active && focused {
                theme.text
            } else if active {
                theme.editor_foreground
            } else {
                theme.text_muted
            };
            let group: ElementId = ("tab-group", index).into();
            let group_name = format!("tab-{}-{index}", id.0);
            tabs = tabs.child(
                div()
                    .id(group)
                    .group(group_name.clone())
                    .flex()
                    .flex_none()
                    .items_center()
                    .gap(self.z(6.0))
                    .h_full()
                    .pl(self.z(10.0))
                    .pr(self.z(4.0))
                    .relative()
                    .border_r_1()
                    .border_color(hsla(theme.border))
                    // Every tab has the same box (borders, padding, close
                    // slot), so nothing in it moves when it is activated:
                    // the bar's line under the inactive ones is drawn
                    // over their box (a border would change its inner
                    // height), and the active one, without it, opens
                    // into the content.
                    .when(active, |d| d.bg(hsla(theme.editor)))
                    .when(!active, |d| {
                        d.bg(hsla(theme.tab_bar)).child(
                            div()
                                .absolute()
                                .left_0()
                                .right_0()
                                .bottom_0()
                                .h(px(1.0))
                                .bg(hsla(theme.border)),
                        )
                    })
                    .on_click(cx.listener(move |this, e: &ClickEvent, window, cx| {
                        this.layout.activate(id, index);
                        if e.click_count() == 2 {
                            this.layout.pin(id, index);
                        }
                        this.ensure_documents();
                        this.focus_pane(id, window, cx);
                    }))
                    // Dragged: along the bar, to another, to a pane's
                    // edge (`tab_drag`); a tab dropped on it goes before it.
                    .on_drag(dragged, move |dragged, _, _, cx| {
                        cx.new(|_| TabPreview {
                            tab: dragged.clone(),
                            theme,
                            scale,
                            text,
                        })
                    })
                    .drag_over::<DraggedTab>(move |style, _, _, _| {
                        style.bg(hsla(theme.element_selected))
                    })
                    .on_drop(cx.listener(move |this, d: &DraggedTab, window, cx| {
                        this.drop_tab(
                            d.tab,
                            TabDrop::Into {
                                pane: id,
                                at: index,
                            },
                            window,
                            cx,
                        );
                    }))
                    .child(icon(tab_icon, self.z(ICON), hsla(icon_color)))
                    .child(
                        div()
                            .text_color(hsla(label_color))
                            .when(tab.preview, Styled::italic)
                            .whitespace_nowrap()
                            .child(label),
                    )
                    .child(
                        div()
                            .id(("close", index))
                            .flex()
                            .items_center()
                            .justify_center()
                            .size(self.z(16.0))
                            .rounded(self.z(3.0))
                            .when(!active, |d| {
                                d.invisible().group_hover(group_name, Styled::visible)
                            })
                            .hover(|s| s.bg(hsla(theme.element_hover)))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                cx.stop_propagation();
                                this.layout.close_tab(id, index);
                                this.forget_closed_panes();
                                let to = this.layout.focused();
                                this.focus_pane(to, window, cx);
                                this.ensure_documents();
                            }))
                            .child(icon(IconName::X, self.z(12.0), hsla(theme.text_muted))),
                    ),
            );
        }
        let tools = edge(div())
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(2.0))
            .px(self.z(4.0))
            .rounded_tr(self.island_corner())
            .children(self.pane_tools(id, cx));
        div()
            .flex()
            .flex_none()
            .h(self.bar(TAB_PAD))
            .bg(hsla(theme.under(theme.tab_bar)))
            .rounded_t(self.island_corner())
            .child(tabs)
            // The bar past the tabs: a tab dropped there goes last.
            .child(
                edge(div())
                    .flex_1()
                    .min_w_0()
                    .drag_over::<DraggedTab>(move |style, _, _, _| {
                        style.bg(hsla(theme.element_selected))
                    })
                    .on_drop(cx.listener(move |this, d: &DraggedTab, window, cx| {
                        this.drop_tab(
                            d.tab,
                            TabDrop::Into {
                                pane: id,
                                at: count,
                            },
                            window,
                            cx,
                        );
                    })),
            )
            .child(tools)
            .into_any_element()
    }

    /// The breadcrumb of pane `id`: the file, then where its cursor is
    /// (section and function), or what its list is.
    fn crumbs(&self, id: PaneId) -> Vec<(String, u32)> {
        let theme = self.theme;
        let mut crumbs: Vec<(String, u32)> = Vec::new();
        let Some(session) = &self.session else {
            return crumbs;
        };
        crumbs.push((session.file_name(), theme.text_muted));
        if let Some(arch) = session.slice() {
            crumbs.push((arch.to_owned(), theme.text_muted));
        }
        match self.layout.active(id) {
            Some(TabKind::Strings) => crumbs.push(("Strings".to_owned(), theme.text)),
            Some(TabKind::Xrefs { of, .. }) => {
                crumbs.push(("Xrefs".to_owned(), theme.text_muted));
                let name = self
                    .listing
                    .as_ref()
                    .and_then(|l| l.shown_name(*of, session.overlay()).map(str::to_owned))
                    .unwrap_or_else(|| format!("{of:X}"));
                crumbs.push((name, theme.function));
            }
            Some(TabKind::Listing | TabKind::C { .. }) => {
                if let (Some(listing), Some(address), Some(db)) =
                    (&self.listing, self.cursor_address(id), session.database())
                {
                    if let Some(section) = listing.section(db, address) {
                        crumbs.push((section, theme.text_muted));
                    }
                    let (named, color) = match listing.function_of(address) {
                        Some((_, entry)) => (entry, theme.function),
                        None => (address, theme.constant),
                    };
                    if let Some(name) = listing.shown_name(named, session.overlay()) {
                        let name = self
                            .demangled
                            .get(name)
                            .and_then(Clone::clone)
                            .unwrap_or_else(|| name.to_owned());
                        crumbs.push((name, color));
                    }
                }
            }
            Some(TabKind::Found(n)) => crumbs.push((self.results_label(*n), theme.text)),
            Some(TabKind::Folder(key)) => {
                let path = self.folder_path(key);
                let last = path.len().saturating_sub(1);
                for (i, name) in path.into_iter().enumerate() {
                    let color = if i == last {
                        theme.text
                    } else {
                        theme.text_muted
                    };
                    crumbs.push((name, color));
                }
            }
            Some(
                TabKind::Settings | TabKind::Struct(_) | TabKind::Console | TabKind::Terminal(_),
            )
            | None => {}
        }
        crumbs
    }

    /// Pane `id`'s Split Right and Maximize buttons, and Close Pane where
    /// its tab has another pane; the bottom dock's Hide and Maximize. Each
    /// acts on this pane (focused first).
    fn pane_tools(&self, id: PaneId, cx: &mut Context<Self>) -> Vec<Stateful<Div>> {
        let maximized = self.maximized == Some(id);
        let dock = self.layout.is_dock(id);
        let several = self.layout.panes().nth(1).is_some() && !dock;
        let mut tools = vec![
            if dock {
                self.icon_button(
                    ("hide-dock", id.0),
                    IconName::ChevronDown,
                    Command::ToggleBottomDock,
                    true,
                    false,
                    cx,
                )
            } else {
                self.icon_button(
                    ("split", id.0),
                    IconName::Columns2,
                    Command::SplitRight,
                    true,
                    false,
                    cx,
                )
            },
            self.icon_button(
                ("maximize", id.0),
                if maximized {
                    IconName::Minimize2
                } else {
                    IconName::Maximize2
                },
                Command::ToggleMaximize,
                self.facts().panes,
                maximized,
                cx,
            ),
        ];
        if several {
            tools.push(self.icon_button(
                ("close-pane", id.0),
                IconName::X,
                Command::ClosePane,
                true,
                false,
                cx,
            ));
        }
        tools
            .into_iter()
            .map(|tool| {
                tool.on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, _| {
                        this.layout.focus(id);
                    }),
                )
            })
            .collect()
    }

    /// The pane's toolbar: the breadcrumb on the left, small tools on
    /// the right (the C view; a list's filter; a mark when the pane does
    /// not follow the shared cursor). At the pane's `top` (no tab bar
    /// over it), its corners rounded and the pane's tools at its end.
    fn toolbar(&self, id: PaneId, top: bool, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let mut row = div()
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(6.0))
            .h(self.bar(TOOLBAR_PAD))
            .pl(self.z(12.0))
            .pr(self.z(6.0))
            // Its items centred on the bar as drawn, its bottom line in it
            // (the line takes a pixel from below the content).
            .pt(px(1.0))
            .bg(hsla(theme.editor))
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .whitespace_nowrap()
            .overflow_hidden()
            .when(top, |d| d.rounded_t(self.island_corner()));
        for (i, (crumb, color)) in self.crumbs(id).into_iter().enumerate() {
            if i > 0 {
                row = row.child(div().text_color(hsla(theme.text_placeholder)).child("›"));
            }
            row = row.child(
                div()
                    .min_w_0()
                    .overflow_hidden()
                    .text_ellipsis()
                    .text_color(hsla(color))
                    .child(crumb),
            );
        }
        row = row.child(div().flex_1());
        let query = self
            .panes
            .get(&id)
            .filter(|_| {
                matches!(
                    self.layout.active(id),
                    Some(TabKind::Strings | TabKind::Xrefs { .. } | TabKind::Folder(_))
                )
            })
            .map(|s| s.list.query.clone())
            .filter(|q| !q.is_empty());
        if let Some(query) = query {
            row = row.child(
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(6.0))
                    .px(self.z(6.0))
                    .h(self.z(ICON_BUTTON))
                    .rounded(self.z(4.0))
                    .bg(hsla(theme.element_hover))
                    .child(icon(IconName::Search, self.z(ICON), hsla(theme.text_muted)))
                    .child(query),
            );
        }
        let synced = self.layout.pane(id).is_some_and(|p| p.synced);
        if !synced {
            row = row.child(
                self.icon_button(
                    ("unsynced", id.0),
                    IconName::Link2Off,
                    Command::ToggleSync,
                    true,
                    false,
                    cx,
                )
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, _| {
                        this.layout.focus(id);
                    }),
                ),
            );
        }
        if self.c_view_of(id).is_some() {
            if self.shows_ir(id) {
                row = row.children(self.ir_toolbar(id, cx));
            } else {
                row = row.children(self.verify_chip(id, cx));
                row = row.children(self.compare_chip(id, cx));
                row = row.children(self.state_selector(id, cx));
            }
        }
        if matches!(self.layout.active(id), Some(TabKind::Listing)) {
            row = row.children(self.unified_tools(id, cx));
            row = row.children(self.hex_tools(id, cx));
            row = row.children(self.calls_tools(id, cx));
        }
        if crate::tabs::is_code(self.layout.active(id)) {
            row = row.children(self.view_selector(id, cx));
        }
        row = row.children(self.xrefs_tools(id, cx));
        if top {
            row = row.children(self.pane_tools(id, cx));
        }
        row.into_any_element()
    }

    /// Pane `id`'s view selector: one button naming what it shows
    /// (`Listing`, `Graph`, `Hex`, `Calls`, `C`, `Exact C`, `IR`),
    /// opening a menu of every view with its keys, the one shown checked.
    /// What a pane shows changes only here (or by these commands' keys),
    /// never by a navigation.
    fn view_selector(&self, id: PaneId, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let listing = matches!(self.layout.active(id), Some(TabKind::Listing));
        let c = self.c_view_of(id);
        let unified = listing && self.shows_unified(id);
        let hex = listing && !unified && self.shows_hex(id);
        let calls = listing && self.shows_calls(id);
        let graph = listing && !hex && !calls && self.shows_graph(id);
        let ir = c.is_some() && self.shows_ir(id);
        let in_function = self
            .cursor_address(id)
            .and_then(|a| self.listing.as_ref()?.function_of(a))
            .is_some();
        let shown = match c {
            Some(_) if ir => ViewChoice::Ir,
            Some(View::Reading) => ViewChoice::Reading,
            Some(View::Exact) => ViewChoice::Exact,
            None if unified => ViewChoice::Unified,
            None if hex => ViewChoice::Hex,
            None if calls => ViewChoice::Calls,
            None if graph => ViewChoice::Graph,
            None => ViewChoice::Listing,
        };
        // Each view, whether it can be shown here, its keys.
        let choices = [
            (ViewChoice::Listing, true),
            (ViewChoice::Unified, true),
            (ViewChoice::Graph, in_function || graph),
            (ViewChoice::Hex, self.hex_image().is_some() || hex),
            (ViewChoice::Calls, in_function || calls),
            (ViewChoice::Reading, true),
            (ViewChoice::Exact, true),
            (ViewChoice::Ir, true),
        ]
        .map(|(choice, enabled)| {
            (
                choice,
                enabled,
                commands::key_label(&self.keymap, choice.command()),
            )
        });
        let button = div()
            .id(("view", id.0))
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(4.0))
            .pl(self.z(8.0))
            .pr(self.z(4.0))
            .h(self.z(ICON_BUTTON))
            .rounded(self.z(4.0))
            .border_1()
            .border_color(hsla(theme.border_variant))
            .text_color(hsla(theme.text))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    window.prevent_default();
                    cx.stop_propagation();
                    this.layout.focus(id);
                    let items = choices
                        .iter()
                        .map(|(choice, enabled, key)| {
                            let choice = *choice;
                            let mut item =
                                OwnItem::new(choice.menu_label(), move |this, window, cx| {
                                    this.show_view_choice(id, choice, window, cx);
                                });
                            item.enabled = *enabled;
                            item.checked = choice == shown;
                            item.key.clone_from(key);
                            item
                        })
                        .collect();
                    this.toggle_own_menu(format!("view {}", id.0), e.position, items, window, cx);
                }),
            )
            .child(shown.menu_label())
            .child(icon(
                IconName::ChevronDown,
                self.z(ICON),
                hsla(theme.text_muted),
            ));
        vec![button.into_any_element()]
    }

    /// Pane `id` shows `choice` from the view menu: a view of the C from a
    /// listing goes to the C first.
    fn show_view_choice(
        &mut self,
        id: PaneId,
        choice: ViewChoice,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let of_c = matches!(
            choice,
            ViewChoice::Reading | ViewChoice::Exact | ViewChoice::Ir
        );
        if of_c && self.c_view_of(id).is_none() {
            self.choose_view(id, ViewChoice::C, window, cx);
        }
        // The IR is a toggle: only on when it is not shown.
        if choice != ViewChoice::Ir || !self.shows_ir(id) {
            self.choose_view(id, choice, window, cx);
        }
        cx.notify();
    }

    /// Pane `id` shows `choice` (the view selector's).
    fn choose_view(
        &mut self,
        id: PaneId,
        choice: ViewChoice,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if choice != ViewChoice::Unified {
            self.leave_unified(id);
        }
        match choice {
            ViewChoice::Listing | ViewChoice::Graph => {
                self.set_code_view(id, &TabKind::Listing);
                self.leave_hex(id);
                self.leave_calls(id);
                self.set_graph(id, choice == ViewChoice::Graph);
            }
            ViewChoice::Unified => {
                self.enter_unified(id);
            }
            ViewChoice::Hex => {
                self.set_code_view(id, &TabKind::Listing);
                self.show_hex(id, window, cx);
            }
            ViewChoice::Calls => {
                self.set_code_view(id, &TabKind::Listing);
                self.focus_pane(id, window, cx);
                self.show_calls(id, window, cx);
            }
            ViewChoice::C => {
                let view = self.default_view();
                self.set_code_view(
                    id,
                    &TabKind::C {
                        function: None,
                        view,
                    },
                );
            }
            ViewChoice::Reading | ViewChoice::Exact => {
                if let Some(state) = self.panes.get_mut(&id) {
                    state.ir.on = false;
                    state.ir.dropdown = false;
                }
                let view = if choice == ViewChoice::Reading {
                    View::Reading
                } else {
                    View::Exact
                };
                self.set_view(id, view);
                self.ensure_documents();
            }
            ViewChoice::Ir => {
                self.layout.focus(id);
                self.run(Command::ShowInIr, window, cx);
                return;
            }
        }
        self.focus_pane(id, window, cx);
    }

    /// The status bar: on the left the docks' toggles (the map, the
    /// console), the session and
    /// the threads' button beside it, and what failed (else, quietly, what
    /// was done to the project);
    /// on the right a quiet spinner while the analysis runs, the cursor's
    /// function and address, the format and architecture (which C view a
    /// pane shows, its view selector says).
    #[expect(clippy::too_many_lines, reason = "the bar's items, in order")]
    fn status(&self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let item = |id: &'static str| {
            div()
                .id(id)
                .flex()
                .flex_none()
                .items_center()
                .h(self.z(ICON_BUTTON))
                .px(self.z(6.0))
                .rounded(self.z(4.0))
                .hover(|s| s.bg(hsla(theme.element_hover)))
        };
        // The settings file's problems are a banner (`banners`).
        let error = self.error.as_ref().map(|error| {
            div()
                .min_w_0()
                .pl(self.z(6.0))
                .text_color(hsla(theme.error))
                .overflow_hidden()
                .whitespace_nowrap()
                .text_ellipsis()
                .child(error.clone())
        });
        let notice = self
            .projects
            .notice
            .as_ref()
            .filter(|_| error.is_none())
            .map(|notice| {
                div()
                    .min_w_0()
                    .pl(self.z(6.0))
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .child(notice.clone())
            });
        let left = div()
            .flex()
            .items_center()
            .gap(self.z(2.0))
            .min_w_0()
            .child(self.icon_button(
                "map-toggle",
                IconName::PanelLeft,
                Command::ToggleLeftSidebar,
                true,
                self.left_sidebar,
                cx,
            ))
            .child(
                // Its menu, by either button: the console and each
                // terminal, a new one, the bottom dock shown or hidden.
                self.icon_button_look(
                    "console-toggle",
                    IconName::SquareTerminal,
                    Command::ToggleConsole,
                    self.session.is_some(),
                    self.console_shown(),
                )
                .when(self.session.is_some(), |d| {
                    d.on_click(cx.listener(|this, e: &ClickEvent, window, cx| {
                        this.shell_menu(e.position(), window, cx);
                    }))
                })
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(|this, e: &MouseDownEvent, window, cx| {
                        if this.session.is_some() {
                            this.shell_menu(e.position, window, cx);
                        }
                        cx.stop_propagation();
                    }),
                ),
            )
            .child(
                // The robot: a click shows the agent used last (or starts
                // one); its menu each agent, a new one, and changes which.
                self.icon_button(
                    "agent-launch",
                    IconName::Bot,
                    Command::ToggleAgents,
                    self.session.is_some(),
                    self.agent_shown(),
                    cx,
                )
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(|this, e: &MouseDownEvent, window, cx| {
                        if this.session.is_some() {
                            this.agent_menu(e.position, window, cx);
                        }
                        cx.stop_propagation();
                    }),
                ),
            )
            .children(self.render_collab_status(self.threads_status(cx), cx))
            .children(error)
            .children(notice);
        // A correction analyses the binary again beside the one shown.
        let again = self.session.as_ref().is_some_and(Session::reanalysing);
        let spinner =
            ((self.session.is_some() && self.stage < Stage::Warmed) || again).then(|| {
                window.request_animation_frame();
                let progress = self.session.as_ref().and_then(Session::progress);
                let label = analysis_label(self.stage, again, progress);
                let turn = STARTED.elapsed().as_secs_f32().fract();
                div()
                    .id("spinner")
                    .flex()
                    .items_center()
                    .h(self.z(ICON_BUTTON))
                    .px(self.z(6.0))
                    .gap(self.z(6.0))
                    .whitespace_nowrap()
                    .font_features(tabular())
                    .child(
                        icon(IconName::LoaderCircle, self.z(ICON), hsla(theme.text_muted))
                            .with_transformation(Transformation::rotate(radians(turn * TAU))),
                    )
                    .child(label)
            });
        let cursor = match (&self.listing, &self.session, self.current_address()) {
            (Some(listing), Some(session), Some(address)) => {
                let function = listing
                    .function_of(address)
                    .and_then(|(_, entry)| listing.shown_name(entry, session.overlay()));
                Some(match function {
                    Some(f) => {
                        let f = self
                            .demangled
                            .get(f)
                            .and_then(Clone::clone)
                            .unwrap_or_else(|| f.to_owned());
                        format!("{f}  {address:X}")
                    }
                    None => format!("{address:X}"),
                })
            }
            _ => None,
        };
        let cursor = cursor.map(|text| {
            item("status-cursor")
                .max_w(self.z(420.0))
                .overflow_hidden()
                .whitespace_nowrap()
                .text_ellipsis()
                .font_features(tabular())
                .tooltip(self.key_tooltip("Go Anywhere…", Command::GoAnywhere))
                .on_click(
                    cx.listener(|this, _, window, cx| this.run(Command::GoAnywhere, window, cx)),
                )
                .child(text)
        });
        let format = self
            .session
            .as_ref()
            .and_then(|s| s.database())
            .map(|db| map::format_label(db.image()))
            .map(|label| div().flex_none().px(self.z(6.0)).child(label));
        div()
            .flex()
            .flex_none()
            .items_center()
            .justify_between()
            .gap(self.z(12.0))
            .h(self.bar(STATUS_PAD))
            .px(self.z(4.0))
            // Its items centred on the bar as drawn, its top line in it.
            .pb(px(1.0))
            .bg(hsla(theme.background))
            .border_t_1()
            .border_color(hsla(theme.border))
            .text_color(hsla(theme.text_muted))
            .child(left)
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .gap(self.z(2.0))
                    .children(spinner)
                    .children(cursor)
                    .children(format),
            )
            .into_any_element()
    }
}

impl Render for Workspace {
    #[expect(
        clippy::too_many_lines,
        reason = "the window's parts and its edge drag"
    )]
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let frame_start = (*FRAME_TRACE).then(Instant::now);
        let frame_cpu = frame_start.and_then(|_| thread_cpu());
        // This frame's places showing the others' cursors, noted anew.
        self.collab.drawn.clear();
        // A tab dragged and let go anywhere else: no drop zone left shown.
        if !cx.has_active_drag() {
            self.layout_ui.tab_drop = None;
        }
        self.step_smooth(window);
        self.publish_cursor();
        // A token clicked on the same line moves the caret the others see.
        self.collab_publish();
        self.char_width(window);
        self.facts_tick(window, cx);
        // The overlay's focus never outlives it (a card closed by the
        // pointer, or by following an xref): the focused pane takes it back.
        if !self.about
            && !self.files_and_folders.is_open()
            && self.peek.is_none()
            && self.picker.is_none()
            && self.overlay_focus.is_focused(window)
        {
            let id = self.layout.focused();
            self.focus_pane(id, window, cx);
        }
        if std::mem::take(&mut self.layout_ui.refocus) {
            let id = self.layout.focused();
            self.focus_pane(id, window, cx);
        }
        let theme = self.theme;
        let titlebar = self.render_titlebar(cx);
        let banners = self.render_banners(window, cx);
        let tree = match self.maximized {
            Some(id) => Node::Pane(id),
            None => self.layout.tree().clone(),
        };
        let panes = self.render_node(&tree, &[], window, cx);
        let left = self.left_sidebar.then(|| {
            let content = self.render_sidebar(window, cx);
            let island = self
                .island()
                .relative()
                .w(self.z(self.sidebar_width))
                .flex_none()
                .bg(hsla(theme.under(theme.panel)));
            let island = if self.settings.islands {
                island
            } else {
                island.border_r_1().border_color(hsla(theme.border))
            };
            // Its edge drags its width.
            let edge = div()
                .id("map-edge")
                .absolute()
                .top_0()
                .bottom_0()
                .right_0()
                .w(px(4.0))
                .cursor_col_resize()
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| {
                        this.layout_ui.drag = Some(EdgeDrag::Map);
                        cx.stop_propagation();
                        cx.notify();
                    }),
                );
            island
                .child(content)
                .child(edge)
                .children(self.island_edge())
        });
        let right = self.render_right_dock(window, cx);
        // With no binary open the editor area is the start page, or the
        // settings when they are open.
        let editor = if self.shows_start() {
            self.island()
                .bg(hsla(theme.under(theme.editor)))
                .child(self.render_start(window, cx))
                .children(self.island_edge())
                .into_any_element()
        } else if self.session.is_none() && !self.shows_tool() {
            let id = self.layout.focused();
            self.render_pane(id, window, cx)
        } else {
            // The window's tabs over the panes of the one shown.
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .child(self.render_window_tabs(cx))
                .child(div().flex_1().min_h_0().flex().child(panes))
                .into_any_element()
        };
        // The feature map: right of the panes, or above them.
        let (map_right, map_top) = match self.render_feature_map(cx) {
            Some((true, strip)) => (Some(strip), None),
            Some((false, band)) => (None, Some(band)),
            None => (None, None),
        };
        // Islands keep the gap in their frames, and the window's edge in
        // the body's.
        let body = div().relative().flex().flex_1().min_h_0();
        let body = if self.settings.islands {
            self.gap_frame(body)
        } else {
            body
        };
        let editor = div()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .children(map_top)
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .child(editor)
                    .children(map_right),
            );
        let body = body
            .children(left.filter(|_| self.session.is_some()))
            .child(editor)
            .children(right)
            .child(self.drop_target());
        let modal = self.render_modal(cx);
        let popover = self
            .render_avatar_popover(cx)
            .or_else(|| self.render_session_popover(cx));
        let peek = self.render_peek(window, cx);
        let why = self.render_why_card(window, cx);
        let state_menu = self.render_state_menu(cx);
        let state_form = self.render_state_form(cx);
        let stub_menu = self.render_stub_menu(cx);
        let context_menu = self.render_context_menu();
        let feature_tip = self.render_feature_tip();
        let type_field = self.render_type_field();
        let c_type = self.render_c_type();
        let status = self.status(window, cx);
        let root = div()
            .id("workspace")
            // A context everywhere: `!Find` (Functions' Shift+F3) needs
            // one to hold, the focus on nothing too.
            .key_context("Workspace")
            .size_full()
            .flex()
            .flex_col()
            .when_some(self.layout_ui.drag.clone(), |d, drag| {
                let rows = match &drag {
                    EdgeDrag::Split { path, .. } => {
                        matches!(self.layout.split_at(path), Some((Axis::Column, _)))
                    }
                    EdgeDrag::HexSide(_) | EdgeDrag::DockSplit => true,
                    EdgeDrag::Map | EdgeDrag::Dock => false,
                };
                let d = if rows {
                    d.cursor_row_resize()
                } else {
                    d.cursor_col_resize()
                };
                d.on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, window, cx| {
                    this.drag_edge(&drag, e, window);
                    cx.notify();
                }))
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| {
                        this.layout_ui.drag = None;
                        cx.notify();
                    }),
                )
            })
            .bg(hsla(theme.under(if self.settings.islands {
                theme.gap
            } else {
                theme.editor
            })))
            .text_color(hsla(theme.text))
            .font_family(self.settings.ui_font.clone())
            .text_size(self.z(self.settings.ui_font_size))
            .line_height(self.z(self.ui_line()))
            .capture_key_down(cx.listener(|this, e: &KeyDownEvent, window, cx| {
                if this.menu_keys(e, window, cx) || this.overlay_keys(e, cx) {
                    cx.stop_propagation();
                }
            }))
            .on_modifiers_changed(cx.listener(|this, e: &ModifiersChangedEvent, window, cx| {
                this.alt_changed(e, window, cx);
            }))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, window, cx| {
                this.open_dropped(paths, window, cx);
            }))
            // An arrow a menu leaves (no submenu to open or close) moves
            // to the menu beside it.
            .on_action(cx.listener(|this, _: &SelectLeft, window, cx| {
                this.neighbour_menu(false, window, cx);
            }))
            .on_action(cx.listener(|this, _: &SelectRight, window, cx| {
                this.neighbour_menu(true, window, cx);
            }));
        // The trace's phases: the render ends here; the mark, the root's
        // first child, is laid out with the rest and prepainted and painted
        // first.
        let phases = frame_start.map(|start| FramePhases {
            start,
            cpu: frame_cpu,
            render: start.elapsed(),
            prepaint: Rc::default(),
            paint: Rc::default(),
        });
        actions::listen(root, cx)
            .children(phases.as_ref().map(frame_mark))
            .child(titlebar)
            .children(banners)
            .child(body)
            .child(status)
            .children(modal)
            .children(popover)
            .children(peek)
            .children(why)
            .children(state_menu)
            .children(state_form)
            .children(stub_menu)
            .children(context_menu)
            .children(feature_tip)
            .children(type_field)
            .children(c_type)
            .children(phases.map(frame_probe))
    }
}

/// An empty element measuring what it fills (`absolute().size_full()`)
/// into `bounds`, which a view reads to lay out its next frame (the rows
/// in sight). Its size changed (a dock opened or closed, a divider
/// dragged, the window resized), the view draws again at once: else it
/// would show the rows of its old size until something else redrew it.
pub fn measured(bounds: Rc<Cell<Bounds<Pixels>>>) -> Canvas<()> {
    canvas(
        move |now, window, _| {
            if bounds.replace(now).size != now.size {
                window.request_animation_frame();
            }
        },
        |_, (), _, _| {},
    )
}

/// `BINBUN_FRAME_TRACE`'s times within a frame: its start (the window's
/// render), the render's length, and when the prepaint and the paint
/// began (the mark's).
struct FramePhases {
    start: Instant,
    /// The thread's CPU time at the start.
    cpu: Option<std::time::Duration>,
    render: std::time::Duration,
    prepaint: Rc<Cell<Option<Instant>>>,
    paint: Rc<Cell<Option<Instant>>>,
}

/// The calling thread's CPU time so far, where the system has a clock
/// for it (`BINBUN_FRAME_TRACE`: a frame's time on the CPU, apart from
/// the time other processes took the core).
fn thread_cpu() -> Option<std::time::Duration> {
    #[cfg(unix)]
    {
        let t = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
        Some(std::time::Duration::new(
            u64::try_from(t.tv_sec).ok()?,
            u32::try_from(t.tv_nsec).ok()?,
        ))
    }
    #[cfg(not(unix))]
    None
}

/// `BINBUN_FRAME_TRACE`'s mark: an empty element, the root's first child,
/// noting when the prepaint and the paint begin.
fn frame_mark(phases: &FramePhases) -> impl IntoElement {
    let prepaint = Rc::clone(&phases.prepaint);
    let paint = Rc::clone(&phases.paint);
    canvas(
        move |_, _, _| prepaint.set(Some(Instant::now())),
        move |_, (), _, _| paint.set(Some(Instant::now())),
    )
}

/// `BINBUN_FRAME_TRACE`'s probe: an empty element painted after every
/// other (deferred, at the highest priority), tracing the CPU time from
/// the window's render to the end of its paint (`frame 3.71 ms`, wall
/// time), the thread's CPU time over it (`cpu`, where known), its phases
/// (render, layout to the first prepaint, prepaint, paint) and when it
/// ended (milliseconds since the start).
fn frame_probe(phases: FramePhases) -> impl IntoElement {
    deferred(canvas(
        |_, _, _| {},
        move |_, (), _, _| {
            let ms = |from: Instant, to: Instant| (to - from).as_secs_f64() * 1e3;
            let end = Instant::now();
            let rendered = phases.start + phases.render;
            let prepaint = phases.prepaint.get().unwrap_or(end);
            let paint = phases.paint.get().unwrap_or(end);
            let cpu = phases
                .cpu
                .zip(thread_cpu())
                .map_or(f64::NAN, |(from, to)| {
                    to.saturating_sub(from).as_secs_f64() * 1e3
                });
            eprintln!(
                "frame {:.2} ms cpu {cpu:.2} render {:.2} layout {:.2} prepaint {:.2} paint {:.2} at {:.1}",
                ms(phases.start, end),
                ms(phases.start, rendered),
                ms(rendered, prepaint),
                ms(prepaint, paint),
                ms(paint, end),
                ms(*STARTED, end),
            );
        },
    ))
    .with_priority(usize::MAX)
}
