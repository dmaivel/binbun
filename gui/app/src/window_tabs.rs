//! The window's tabs: each a place, shown by its own split of panes. The
//! panes of a tab all show its place and share its Back/Forward trail; a
//! navigation moves the tab it is in, and nothing moves a tab but what is
//! done in it. Ctrl+click or a middle click on a name opens it in a new tab
//! beside the current one, its split and views copied
//! ([`Workspace::open_window_tab`]).
//!
//! The settings and a struct being edited are tabs of the strip too, of a
//! pane of their own (and the console or a terminal, left alone in one):
//! not places,
//! nothing navigates in them (a navigation from one goes to a tab of a
//! place first), and one is always a place.
//!
//! The tab shown is the workspace's own layout, panes, places and trails;
//! the others wait parked, swapped in when switched to. The bottom dock is
//! the window's: it moves to the tab shown, its pane's state with it.

use std::collections::HashMap;

use binbun_gui_view::commands::Command;
use binbun_gui_view::history::Trails;
use binbun_gui_view::layout::{Layout, PaneId};
use binbun_gui_view::map::Kind;
use binbun_gui_view::tabs::Places;
use gpui_kit::assets::IconName;
use gpui_kit::prelude::*;
use gpui_kit::{AnyElement, ClickEvent, Context, Div, MouseButton, Window, div, px};

use crate::icons::icon;
use crate::sidebar::kind_icon;
use crate::tabs::is_code;
use crate::theme::hsla;
use crate::workspace::{ICON, PaneState, TAB_PAD, TabKind, Workspace};

/// A tab not shown: what the workspace holds of the one shown.
pub struct Parked {
    layout: Layout<TabKind>,
    panes: HashMap<PaneId, PaneState>,
    places: Places,
    trails: Trails,
    shared: Option<u64>,
    maximized: Option<PaneId>,
}

/// The window's tabs, in order: the shown one's slot empty (its state is
/// the workspace's own).
pub struct WindowTabs {
    slots: Vec<Option<Parked>>,
    active: usize,
}

impl Default for WindowTabs {
    fn default() -> Self {
        Self {
            slots: vec![None],
            active: 0,
        }
    }
}

/// What a window tab of `layout` shows instead of a place (the settings,
/// a struct, the console, a terminal): a lone pane holding only it.
fn tool_of(layout: &Layout<TabKind>) -> Option<&TabKind> {
    let mut panes = layout.code_panes();
    let pane = panes.next()?;
    if panes.next().is_some() || pane.tabs.len() != 1 {
        return None;
    }
    let tab = pane.tabs.first()?;
    matches!(
        tab.content,
        TabKind::Settings | TabKind::Struct(_) | TabKind::Console | TabKind::Terminal(_)
    )
    .then_some(&tab.content)
}

impl Workspace {
    /// Shows `incoming`; what was shown, parked. The bottom dock moves to
    /// `incoming`, its pane's state (and its being maximized) with it.
    fn swap_in(&mut self, incoming: Parked) -> Parked {
        let dock = self.layout.take_dock();
        let dock_id = dock.as_ref().map(|parts| parts.pane.id);
        let state = dock_id.and_then(|id| self.panes.remove(&id));
        let maximized = dock_id.is_some() && self.maximized == dock_id;
        let mut outgoing = Parked {
            layout: std::mem::replace(&mut self.layout, incoming.layout),
            panes: std::mem::replace(&mut self.panes, incoming.panes),
            places: std::mem::replace(&mut self.places, incoming.places),
            trails: std::mem::replace(&mut self.trails, incoming.trails),
            shared: std::mem::replace(&mut self.shared, incoming.shared),
            maximized: std::mem::replace(&mut self.maximized, incoming.maximized),
        };
        if maximized {
            outgoing.maximized = None;
        }
        if let Some(dock) = dock
            && let Some(id) = self.layout.put_dock(dock)
        {
            if let Some(state) = state {
                self.panes.insert(id, state);
            }
            if maximized {
                self.maximized = Some(id);
            }
        }
        outgoing
    }

    /// The first pane id no tab of the window has given.
    fn next_pane_id(&self) -> u32 {
        self.window_tabs
            .slots
            .iter()
            .flatten()
            .map(|parked| parked.layout.next_pane())
            .fold(self.layout.next_pane(), u32::max)
    }

    /// Window tab `index`'s layout.
    fn layout_of(&self, index: usize) -> Option<&Layout<TabKind>> {
        if index == self.window_tabs.active {
            Some(&self.layout)
        } else {
            Some(&self.window_tabs.slots.get(index)?.as_ref()?.layout)
        }
    }

    /// Whether the tab shown is the settings or a struct, not a place.
    pub fn shows_tool(&self) -> bool {
        tool_of(&self.layout).is_some()
    }

    /// Takes the tabs of `kind` (the console, which one window tab shows)
    /// out of the window tabs not shown: a pane left without tabs closes,
    /// a window tab left without any goes.
    pub fn take_parked(&mut self, kind: &TabKind) {
        let mut emptied = Vec::new();
        for (index, slot) in self.window_tabs.slots.iter_mut().enumerate() {
            let Some(parked) = slot else {
                continue;
            };
            loop {
                let found = parked
                    .layout
                    .panes()
                    .find_map(|p| Some((p.id, p.tabs.iter().position(|t| &t.content == kind)?)));
                let Some((pane, at)) = found else {
                    break;
                };
                parked.layout.close_tab(pane, at);
            }
            let live: Vec<PaneId> = parked.layout.panes().map(|p| p.id).collect();
            parked.panes.retain(|id, _| live.contains(id));
            if parked.maximized.is_some_and(|m| !live.contains(&m)) {
                parked.maximized = None;
            }
            if parked.layout.panes().all(|p| p.tabs.is_empty()) {
                emptied.push(index);
            }
        }
        for index in emptied.into_iter().rev() {
            self.window_tabs.slots.remove(index);
            if index < self.window_tabs.active {
                self.window_tabs.active -= 1;
            }
        }
    }

    /// The shown window tab's index.
    pub fn window_tabs_active(&self) -> usize {
        self.window_tabs.active
    }

    /// Whether a window tab, shown or not, has a tab of `kind` (the bottom
    /// dock's, hidden or not, among them).
    pub fn has_tab(&self, kind: &TabKind) -> bool {
        let has = |layout: &Layout<TabKind>| {
            layout
                .every_pane()
                .any(|p| p.tabs.iter().any(|t| &t.content == kind))
        };
        has(&self.layout)
            || self
                .window_tabs
                .slots
                .iter()
                .flatten()
                .any(|p| has(&p.layout))
    }

    /// Window tab `to` becomes the shown one (its state the workspace's;
    /// the focus and documents are the caller's).
    fn show_window_tab(&mut self, to: usize) {
        let from = self.window_tabs.active;
        if to == from {
            return;
        }
        let Some(incoming) = self.window_tabs.slots.get_mut(to).and_then(Option::take) else {
            return;
        };
        let outgoing = self.swap_in(incoming);
        if let Some(slot) = self.window_tabs.slots.get_mut(from) {
            *slot = Some(outgoing);
        }
        self.window_tabs.active = to;
        let next = self.next_pane_id();
        self.layout.reserve_panes(next);
    }

    /// Shows window tab `to`.
    pub fn switch_window_tab(&mut self, to: usize, window: &mut Window, cx: &mut Context<Self>) {
        if to == self.window_tabs.active {
            return;
        }
        self.show_window_tab(to);
        self.after_layout(window, cx);
        cx.notify();
    }

    /// The tab of a place nearest the shown one (before it first).
    fn nearest_place_tab(&self) -> Option<usize> {
        let active = self.window_tabs.active;
        let count = self.window_tabs.slots.len();
        (0..active)
            .rev()
            .chain(active + 1..count)
            .find(|&i| self.layout_of(i).is_some_and(|l| tool_of(l).is_none()))
    }

    /// A navigation from the settings or a struct goes to the nearest tab
    /// of a place first.
    pub fn leave_tool_tab(&mut self) {
        if self.shows_tool()
            && let Some(to) = self.nearest_place_tab()
        {
            self.show_window_tab(to);
            self.ensure_documents();
        }
    }

    /// Shows `kind` (the settings, a struct) in a tab of the strip of its
    /// own: the open one brought back, else a new one after the shown tab.
    /// The pane showing it.
    pub fn open_tool_tab(&mut self, kind: TabKind, cx: &mut Context<Self>) -> PaneId {
        let open = (0..self.window_tabs.slots.len())
            .find(|&i| self.layout_of(i).and_then(tool_of) == Some(&kind));
        if let Some(index) = open {
            self.show_window_tab(index);
            self.ensure_documents();
            return self.layout.focused();
        }
        let first = self.next_pane_id();
        let Some((layout, _)) = Layout::new(kind.clone()).copied(first, |_| true) else {
            let id = self.layout.focused();
            self.layout.open(id, kind, false);
            return id;
        };
        let from = self.window_tabs.active;
        let outgoing = self.swap_in(Parked {
            layout,
            panes: HashMap::new(),
            places: Places::default(),
            trails: Trails::default(),
            shared: None,
            maximized: None,
        });
        if let Some(slot) = self.window_tabs.slots.get_mut(from) {
            *slot = Some(outgoing);
        }
        self.window_tabs.slots.insert(from + 1, None);
        self.window_tabs.active = from + 1;
        let id = self.layout.focused();
        self.ensure_pane(id, cx);
        self.ensure_documents();
        id
    }

    /// `f` of each tab of a place, in the strip's order (each parked one
    /// swapped in for `f` only; the settings and structs are not places),
    /// and where among them the shown one is (the nearest place's, if the
    /// settings or a struct are shown).
    pub fn each_place_tab<R>(&mut self, mut f: impl FnMut(&Self) -> R) -> (Vec<R>, usize) {
        let active = self.window_tabs.active;
        let shown = if self.shows_tool() {
            self.nearest_place_tab()
        } else {
            Some(active)
        };
        let mut out = Vec::new();
        let mut position = 0;
        for index in 0..self.window_tabs.slots.len() {
            if self.layout_of(index).is_none_or(|l| tool_of(l).is_some()) {
                continue;
            }
            if Some(index) == shown {
                position = out.len();
            }
            if index == active {
                out.push(f(self));
                continue;
            }
            let Some(parked) = self.window_tabs.slots.get_mut(index).and_then(Option::take) else {
                continue;
            };
            let shown_tab = self.swap_in(parked);
            out.push(f(self));
            let parked = self.swap_in(shown_tab);
            if let Some(slot) = self.window_tabs.slots.get_mut(index) {
                *slot = Some(parked);
            }
        }
        (out, position)
    }

    /// A tab built by `fill` (given the workspace showing a new, empty
    /// tab), parked at `position` in the strip if `fill` says it holds
    /// something; the shown tab stays shown.
    pub fn add_place_tab_at(
        &mut self,
        position: usize,
        cx: &mut Context<Self>,
        fill: impl FnOnce(&mut Self, &mut Context<Self>) -> bool,
    ) {
        let first = self.next_pane_id();
        let mut empty = Layout::new(TabKind::Listing);
        empty.reserve_panes(first);
        let shown = self.swap_in(Parked {
            layout: empty,
            panes: HashMap::new(),
            places: Places::default(),
            trails: Trails::default(),
            shared: None,
            maximized: None,
        });
        let filled = fill(self, cx);
        let built = self.swap_in(shown);
        if filled {
            let position = position.min(self.window_tabs.slots.len());
            self.window_tabs.slots.insert(position, Some(built));
            if position <= self.window_tabs.active {
                self.window_tabs.active += 1;
            }
        }
        let next = self.next_pane_id();
        self.layout.reserve_panes(next);
    }

    /// Shows the next window tab (else the previous), round the strip.
    pub fn cycle_window_tab(&mut self, next: bool, window: &mut Window, cx: &mut Context<Self>) {
        let count = self.window_tabs.slots.len();
        if count < 2 {
            return;
        }
        let active = self.window_tabs.active;
        let to = if next {
            (active + 1) % count
        } else {
            (active + count - 1) % count
        };
        self.switch_window_tab(to, window, cx);
    }

    /// Whether window tab `index` may close: not the last tab of a place.
    pub fn can_close_window_tab(&self, index: usize) -> bool {
        let count = self.window_tabs.slots.len();
        let places = (0..count)
            .filter(|&i| self.layout_of(i).is_some_and(|l| tool_of(l).is_none()))
            .count();
        let place = self.layout_of(index).is_some_and(|l| tool_of(l).is_none());
        count >= 2 && index < count && !(place && places < 2)
    }

    /// Opens `address` in a new window tab after the shown one: its split
    /// and each pane's view copied (lists left behind), a trail of its
    /// own. Shown if `focus`, else the shown one stays.
    pub fn open_window_tab(
        &mut self,
        address: u64,
        focus: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.leave_tool_tab();
        let first = self.next_pane_id();
        let Some((layout, ids)) = self.layout.copied(first, |kind| is_code(Some(kind))) else {
            return;
        };
        let views: Vec<_> = ids
            .iter()
            .map(|&(old, new)| (new, self.pane_view(old), self.layout.active(old).cloned()))
            .collect();
        let from = self.window_tabs.active;
        let outgoing = self.swap_in(Parked {
            layout,
            panes: HashMap::new(),
            places: Places::default(),
            trails: Trails::default(),
            shared: None,
            maximized: None,
        });
        if let Some(slot) = self.window_tabs.slots.get_mut(from) {
            *slot = Some(outgoing);
        }
        self.window_tabs.slots.insert(from + 1, None);
        self.window_tabs.active = from + 1;
        for (id, view, kind) in views {
            if self.layout.pane(id).is_none() {
                continue;
            }
            self.ensure_pane(id, cx);
            let content = self.code_at(kind.as_ref(), Some(address));
            self.set_code_view(id, &content);
            if let Some(tab) = self.layout.active_tab(id) {
                self.places.set_view(tab, view);
                self.show_view(id, tab, view);
            }
        }
        self.go(address, None);
        self.after_layout(window, cx);
        if !focus {
            self.switch_window_tab(from, window, cx);
        }
        cx.notify();
    }

    /// Closes window tab `index` (not the last tab of a place); a shown one
    /// gives way to the next, else the one before.
    pub fn close_window_tab(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        if !self.can_close_window_tab(index) {
            return;
        }
        let count = self.window_tabs.slots.len();
        if index == self.window_tabs.active {
            let to = if index + 1 < count {
                index + 1
            } else {
                index - 1
            };
            self.switch_window_tab(to, window, cx);
        }
        self.window_tabs.slots.remove(index);
        if index < self.window_tabs.active {
            self.window_tabs.active -= 1;
        }
        cx.notify();
    }

    /// Forgets every window tab but the shown one, a place (another binary
    /// opens).
    pub fn forget_window_tabs(&mut self) {
        self.leave_tool_tab();
        self.window_tabs = WindowTabs::default();
    }

    /// Window tab `index`'s title: the settings' or the struct's name; the
    /// function its place is in, else the address; with no binary, Start.
    fn window_tab_title(&self, index: usize) -> String {
        if let Some(tool) = self.layout_of(index).and_then(tool_of) {
            return match tool {
                TabKind::Struct(target) => self.struct_tab_label(target),
                TabKind::Console => "Console".to_owned(),
                TabKind::Terminal(id) => self.terminal_title(*id),
                TabKind::Settings
                | TabKind::Listing
                | TabKind::C { .. }
                | TabKind::Strings
                | TabKind::Xrefs { .. }
                | TabKind::Found(_)
                | TabKind::Folder(_) => "Settings".to_owned(),
            };
        }
        if self.session.is_none() {
            return "Start".to_owned();
        }
        let address = if index == self.window_tabs.active {
            self.shared.or_else(|| self.current_address())
        } else {
            self.window_tabs
                .slots
                .get(index)
                .and_then(Option::as_ref)
                .and_then(|parked| parked.shared)
        };
        let Some(address) = address else {
            return "\u{2014}".to_owned();
        };
        self.listing
            .as_ref()
            .and_then(|listing| listing.function_of(address))
            .map_or_else(
                || format!("{address:X}"),
                |(_, entry)| self.shown_function(entry),
            )
    }

    /// The window's tab strip, drawn as a tab bar: Back and Forward, a tab
    /// per place (the shown one in the editor's colour, open to the panes
    /// under it; the others on the bar, a hairline under them), then a
    /// button opening a tab at the shown one's place.
    pub fn render_window_tabs(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let facts = self.facts();
        // Each part paints the bar's colour and its line itself, so the
        // shown tab, without the line, opens into the panes; a pixel on top
        // centres what is in it on the bar as drawn, as the tabs are.
        let edge = |d: Div| {
            d.h_full()
                .pt(px(1.0))
                .bg(hsla(theme.tab_bar))
                .border_b_1()
                .border_color(hsla(theme.border))
        };
        let nav = edge(div())
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(2.0))
            .px(self.z(4.0))
            .border_r_1()
            .child(self.icon_button(
                "window-back",
                IconName::ArrowLeft,
                Command::Back,
                facts.back,
                false,
                cx,
            ))
            .child(self.icon_button(
                "window-forward",
                IconName::ArrowRight,
                Command::Forward,
                facts.forward,
                false,
                cx,
            ));
        let new = div()
            .id("window-tab-new")
            .flex()
            .flex_none()
            .items_center()
            .justify_center()
            .size(self.z(22.0))
            .rounded(self.z(4.0))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .tooltip(self.keyed_tooltip("New Tab", None))
            .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                let at = this.shared.or_else(|| this.current_address());
                if let Some(at) = at {
                    this.open_window_tab(at, true, window, cx);
                }
            }))
            .child(icon(IconName::Plus, self.z(14.0), hsla(theme.text_muted)));
        div()
            .flex()
            .flex_none()
            .h(self.bar(TAB_PAD))
            .bg(hsla(theme.tab_bar))
            .child(nav)
            .children((0..self.window_tabs.slots.len()).map(|index| self.window_tab(index, cx)))
            .child(
                edge(div())
                    .flex()
                    .flex_1()
                    .min_w_0()
                    .items_center()
                    .px(self.z(4.0))
                    .child(new),
            )
            .into_any_element()
    }

    /// Window tab `index` in the strip: the function's icon and name, its
    /// close button (shown on the shown tab, else on hover).
    fn window_tab(&self, index: usize, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let active = index == self.window_tabs.active;
        let several = self.window_tabs.slots.len() > 1;
        let group_name = format!("window-tab-{index}");
        let close = div()
            .id(("window-tab-close", index))
            .flex()
            .items_center()
            .justify_center()
            .size(self.z(16.0))
            .rounded(self.z(3.0))
            .when(!active || !several, |d| {
                d.invisible().when(several, |d| {
                    d.group_hover(group_name.clone(), Styled::visible)
                })
            })
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_click(cx.listener(move |this, _, window, cx| {
                cx.stop_propagation();
                this.close_window_tab(index, window, cx);
            }))
            .child(icon(IconName::X, self.z(12.0), hsla(theme.text_muted)));
        div()
            .id(("window-tab", index))
            .group(group_name)
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
            .on_mouse_down(
                MouseButton::Middle,
                cx.listener(move |this, _, window, cx| {
                    this.close_window_tab(index, window, cx);
                }),
            )
            .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                this.switch_window_tab(index, window, cx);
            }))
            .child(icon(
                self.layout_of(index)
                    .and_then(tool_of)
                    .map_or(kind_icon(Kind::Function, false), |tool| {
                        Self::tab_icon(tool, false)
                    }),
                self.z(ICON),
                hsla(theme.text_muted),
            ))
            .child(
                div()
                    .whitespace_nowrap()
                    .text_color(hsla(if active { theme.text } else { theme.text_muted }))
                    .child(self.window_tab_title(index)),
            )
            .child(close)
            .into_any_element()
    }
}
