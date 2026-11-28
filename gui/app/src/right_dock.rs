//! The right dock: the panels beside the code as tabs (Threads, History,
//! the session's Chat, Conflicts, Refused changes and Your edits, the
//! Origin panel, the Pathfinder). One shows at a time, or two stacked: a
//! tab dragged onto the dock's lower part (or Move Below in its menu)
//! makes a half of its own under the first, the divider between them
//! dragged. A panel reopens in the half it was last in. The dock's width
//! drags at its left edge; its › hides it with its panels kept, as View ›
//! Right Dock does. Its tabs stay in it (they are panels, not panes).
//! The panels that restore from the project alone (Threads, History, the
//! Pathfinder) are saved with the layout, as they were placed; the
//! binary's panels close with it.

use std::cell::Cell;
use std::collections::HashSet;
use std::rc::Rc;

use binbun_gui_view::commands::Command;
use binbun_gui_view::layout::TabId;
use binbun_gui_view::layout_file::{SavedHalf, SavedPanel, SavedRight};
use gpui_kit::assets::IconName;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Bounds, ClickEvent, Context, Div, MouseButton, MouseDownEvent, Pixels, Point,
    Window, div, px, relative,
};

use crate::collab::Tab;
use crate::context_menu::OwnItem;
use crate::facts_view::ORIGIN_WIDTH;
use crate::icons::icon;
use crate::panes::measured;
use crate::pathfinder_view::PATHFINDER_WIDTH;
use crate::tab_drag::{DraggedTab, TabPreview};
use crate::theme::{hsla, with_alpha};
use crate::threads_view::DOCK_WIDTH;
use crate::workspace::{EdgeDrag, ICON, TAB_PAD, Workspace};

/// The session panels' width, the chat's.
const SESSION_WIDTH: f32 = 320.0;

/// A panel of the right dock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Panel {
    /// The threads and suggestions.
    Threads,
    /// Every change, newest first.
    History,
    /// The session's chat, or a list of the status bar's counters.
    Session(Tab),
    /// Where a value comes from (or goes).
    Origin,
    /// The paths between two places.
    Pathfinder,
}

impl Panel {
    /// Its tab's title.
    fn title(self) -> &'static str {
        match self {
            Self::Threads => "Threads",
            Self::History => "History",
            Self::Session(Tab::Chat) => "Chat",
            Self::Session(Tab::Conflicts) => "Conflicts",
            Self::Session(Tab::Refused) => "Refused",
            Self::Session(Tab::Local) => "Your edits",
            Self::Origin => "Origin",
            Self::Pathfinder => "Pathfinder",
        }
    }

    /// Its tab's icon.
    fn icon(self) -> IconName {
        match self {
            Self::Threads => IconName::MessageSquareText,
            Self::History => IconName::FileClock,
            Self::Session(Tab::Chat) => IconName::MessageSquare,
            Self::Session(Tab::Conflicts) => IconName::GitMergeConflict,
            Self::Session(Tab::Refused) => IconName::Ban,
            Self::Session(Tab::Local) => IconName::Upload,
            Self::Origin => IconName::Waypoints,
            Self::Pathfinder => IconName::Route,
        }
    }

    /// The width it asks of the dock (logical) while the dock's edge was
    /// not dragged.
    fn width(self) -> f32 {
        match self {
            Self::Threads | Self::History => DOCK_WIDTH,
            Self::Session(_) => SESSION_WIDTH,
            Self::Origin => ORIGIN_WIDTH,
            Self::Pathfinder => PATHFINDER_WIDTH,
        }
    }

    /// As saved, if it is: one that restores from the project alone.
    fn saved(self) -> Option<SavedPanel> {
        match self {
            Self::Threads => Some(SavedPanel::Threads),
            Self::History => Some(SavedPanel::History),
            Self::Pathfinder => Some(SavedPanel::Pathfinder),
            Self::Session(_) | Self::Origin => None,
        }
    }

    /// The panel saved as `saved`.
    fn restored(saved: SavedPanel) -> Self {
        match saved {
            SavedPanel::Threads => Self::Threads,
            SavedPanel::History => Self::History,
            SavedPanel::Pathfinder => Self::Pathfinder,
        }
    }
}

/// One half of the dock: its panels in order and the one shown.
#[derive(Debug, Default)]
struct Half {
    panels: Vec<Panel>,
    active: usize,
}

/// The dock's panels: a top half and, stacked under it, a bottom half
/// (none while empty; a bottom half left alone rises), the top's share of
/// the height while stacked, and the panels last put in the bottom half.
#[derive(Debug)]
pub struct RightDock {
    halves: [Half; 2],
    split: f32,
    below: HashSet<Panel>,
    /// The dock's bounds as drawn (its divider dragged against them).
    bounds: Rc<Cell<Bounds<Pixels>>>,
}

impl Default for RightDock {
    fn default() -> Self {
        Self {
            halves: [Half::default(), Half::default()],
            split: 0.5,
            below: HashSet::new(),
            bounds: Rc::default(),
        }
    }
}

impl RightDock {
    /// Whether no panel is open.
    pub fn is_empty(&self) -> bool {
        self.halves.iter().all(|half| half.panels.is_empty())
    }

    /// Where panel `panel` is: its half and its index there.
    fn place(&self, panel: Panel) -> Option<(usize, usize)> {
        self.halves
            .iter()
            .enumerate()
            .find_map(|(h, half)| Some((h, half.panels.iter().position(|&p| p == panel)?)))
    }

    /// Whether panel `panel` is open (shown or not).
    pub fn is_open(&self, panel: Panel) -> bool {
        self.place(panel).is_some()
    }

    /// Whether panel `panel` is the one its half shows.
    pub fn shows(&self, panel: Panel) -> bool {
        self.place(panel)
            .is_some_and(|(h, i)| self.halves.get(h).is_some_and(|half| half.active == i))
    }

    /// Whether panel `panel` is in the lowest half (its bottom the dock's).
    pub fn lowest(&self, panel: Panel) -> bool {
        self.place(panel)
            .is_some_and(|(h, _)| h == 1 || !self.stacked())
    }

    /// Whether two halves are shown, stacked.
    pub fn stacked(&self) -> bool {
        self.halves.iter().all(|half| !half.panels.is_empty())
    }

    /// Opens panel `panel`, or brings its tab forward: a new one at the
    /// end of the half it was last in (the bottom one only beside a top).
    pub fn open(&mut self, panel: Panel) {
        if let Some((h, i)) = self.place(panel) {
            self.activate(h, i);
            return;
        }
        let top_empty = self
            .halves
            .first()
            .is_none_or(|half| half.panels.is_empty());
        let h = usize::from(self.below.contains(&panel) && !top_empty);
        if let Some(half) = self.halves.get_mut(h) {
            half.panels.push(panel);
            half.active = half.panels.len() - 1;
        }
    }

    /// Closes panel `panel` (the tab on its left shown, if it was);
    /// whether it was open.
    pub fn close(&mut self, panel: Panel) -> bool {
        let Some((h, i)) = self.place(panel) else {
            return false;
        };
        self.take(h, i);
        self.settle();
        true
    }

    /// Moves panel `panel` into half `to` before its tab `at` (at the end
    /// past them), shown there; it reopens there.
    pub fn move_to(&mut self, panel: Panel, to: usize, at: usize) {
        let Some((h, i)) = self.place(panel) else {
            return;
        };
        let to = to.min(1);
        let at = if h == to && at > i { at - 1 } else { at };
        self.take(h, i);
        if let Some(half) = self.halves.get_mut(to) {
            let at = at.min(half.panels.len());
            half.panels.insert(at, panel);
            half.active = at;
        }
        if to == 1 {
            self.below.insert(panel);
        } else {
            self.below.remove(&panel);
        }
        self.settle();
    }

    /// Half `half` shows its tab `index`.
    pub fn activate(&mut self, half: usize, index: usize) {
        if let Some(half) = self.halves.get_mut(half)
            && index < half.panels.len()
        {
            half.active = index;
        }
    }

    /// Each half shown: its index, its panels, its active one.
    fn shown_halves(&self) -> impl Iterator<Item = (usize, &[Panel], usize)> {
        self.halves
            .iter()
            .enumerate()
            .filter(|(_, half)| !half.panels.is_empty())
            .map(|(h, half)| (h, half.panels.as_slice(), half.active))
    }

    /// The widest of the open panels' widths (logical), so that switching
    /// tabs does not move the dock's edge.
    fn width(&self) -> Option<f32> {
        self.halves
            .iter()
            .flat_map(|half| half.panels.iter().map(|p| p.width()))
            .reduce(f32::max)
    }

    /// Takes tab `index` out of half `half`, the one on its left shown if
    /// it was.
    fn take(&mut self, half: usize, index: usize) {
        let Some(half) = self.halves.get_mut(half) else {
            return;
        };
        if index >= half.panels.len() {
            return;
        }
        half.panels.remove(index);
        if index <= half.active {
            half.active = half.active.saturating_sub(1);
        }
        half.active = half.active.min(half.panels.len().saturating_sub(1));
    }

    /// A bottom half left alone rises to the top (its panels no longer
    /// below).
    fn settle(&mut self) {
        let [top, bottom] = &mut self.halves;
        if top.panels.is_empty() && !bottom.panels.is_empty() {
            std::mem::swap(top, bottom);
            for panel in &top.panels {
                self.below.remove(panel);
            }
        }
    }

    /// The dock as saved, `shown` or not: its panels that are saved, each
    /// half's front one (the nearest saved one on its left, if it is not
    /// saved); `None` without any.
    pub fn saved(&self, shown: bool) -> Option<SavedRight> {
        let halves = self.halves.each_ref().map(|half| {
            let panels: Vec<SavedPanel> = half.panels.iter().filter_map(|p| p.saved()).collect();
            let before = half
                .panels
                .iter()
                .take(half.active + 1)
                .filter(|p| p.saved().is_some())
                .count();
            SavedHalf {
                panels,
                active: before.saturating_sub(1),
            }
        });
        if halves.iter().all(|half| half.panels.is_empty()) {
            return None;
        }
        Some(SavedRight {
            halves,
            split: self.split,
            shown,
        })
    }

    /// The panels of `saved` put back in their halves after those open
    /// (a session's), its front ones in front, its share taken.
    fn restore(&mut self, saved: &SavedRight) {
        self.split = saved.split.clamp(0.2, 0.8);
        for (h, half) in saved.halves.iter().enumerate() {
            for panel in half.panels.iter().copied().map(Panel::restored) {
                if self.is_open(panel) {
                    continue;
                }
                if h == 1 {
                    self.below.insert(panel);
                }
                if let Some(to) = self.halves.get_mut(h) {
                    to.panels.push(panel);
                }
            }
            let front = half.panels.get(half.active).copied().map(Panel::restored);
            if let Some((h, i)) = front.and_then(|panel| self.place(panel)) {
                self.activate(h, i);
            }
        }
        self.settle();
    }
}

/// A panel's tab being dragged.
#[derive(Clone, Debug)]
pub struct DraggedPanel {
    panel: Panel,
}

impl Workspace {
    /// Whether panel `panel` is on screen: the dock shown, its tab the one
    /// its half shows.
    pub fn panel_shown(&self, panel: Panel) -> bool {
        self.right_sidebar && self.right_dock.shows(panel)
    }

    /// Opens panel `panel` in the right dock (its tab brought forward if
    /// it is open), the dock shown.
    pub fn open_panel(&mut self, panel: Panel) {
        self.right_dock.open(panel);
        self.right_sidebar = true;
        self.panel_opened(panel);
    }

    /// What panel `panel` shows, taken when it opens: the threads and the
    /// history from the session, the Pathfinder's question from the
    /// project.
    fn panel_opened(&mut self, panel: Panel) {
        match panel {
            Panel::Threads | Panel::History => self.refresh_talk(),
            Panel::Pathfinder => self.pathfinder_opened(),
            Panel::Session(_) | Panel::Origin => {}
        }
    }

    /// The saved panels opened again with the binary's layout, each where
    /// it was; the dock shown if it was, or if it already shows a panel.
    pub fn restore_right_dock(&mut self, saved: &SavedRight) {
        let showing = self.right_sidebar && !self.right_dock.is_empty();
        self.right_dock.restore(saved);
        for half in &saved.halves {
            for &panel in &half.panels {
                self.panel_opened(Panel::restored(panel));
            }
        }
        self.right_sidebar = !self.right_dock.is_empty() && (saved.shown || showing);
    }

    /// The binary's panels closed with it (or with its analysis made
    /// again): what they showed is gone. The session's stay.
    pub fn close_binary_panels(&mut self) {
        for panel in [
            Panel::Threads,
            Panel::History,
            Panel::Origin,
            Panel::Pathfinder,
        ] {
            self.close_panel(panel);
        }
    }

    /// Closes panel `panel`; the dock hidden with its last.
    pub fn close_panel(&mut self, panel: Panel) {
        if !self.right_dock.close(panel) {
            return;
        }
        match panel {
            Panel::Origin => self.facts.origin = None,
            Panel::Pathfinder => self.pathfinder_closed(),
            Panel::Threads | Panel::History | Panel::Session(_) => {}
        }
        if self.right_dock.is_empty() {
            self.right_sidebar = false;
        }
    }

    /// Panel `panel` closed if it is shown, else opened (its command).
    pub fn toggle_panel(&mut self, panel: Panel) {
        if self.panel_shown(panel) {
            self.close_panel(panel);
        } else {
            self.open_panel(panel);
        }
    }

    /// View › Right Dock: the dock shown or hidden, its panels kept; with
    /// none, the threads opened (a binary open).
    pub fn toggle_right_dock(&mut self) {
        if !self.right_dock.is_empty() {
            self.right_sidebar = !self.right_sidebar;
        } else if self.session.is_some() {
            self.open_panel(Panel::Threads);
        }
    }

    /// The right dock, if shown: each half's tabs over its panel, the
    /// halves stacked with a divider between them, its width dragged at
    /// its left edge.
    pub fn render_right_dock(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        if !self.right_sidebar || self.right_dock.is_empty() {
            return None;
        }
        let theme = self.theme;
        let width = self
            .layout_ui
            .dock_width
            .or_else(|| self.right_dock.width())
            .unwrap_or(DOCK_WIDTH);
        let stacked = self.right_dock.stacked();
        let split = self.right_dock.split;
        let shown: Vec<(usize, Panel)> = self
            .right_dock
            .shown_halves()
            .filter_map(|(h, panels, active)| Some((h, *panels.get(active)?)))
            .collect();
        let mut column = div()
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .child(
                measured(Rc::clone(&self.right_dock.bounds))
                    .absolute()
                    .size_full(),
            );
        for (h, panel) in shown {
            let share = match (stacked, h) {
                (false, _) => 1.0,
                (true, 0) => split,
                (true, _) => 1.0 - split,
            };
            let body = self.panel_body(panel, window, cx);
            let half = div()
                .relative()
                .flex()
                .flex_col()
                .flex_1()
                .flex_grow(share)
                .min_h_0()
                .when(h > 0, |d| d.border_t_1().border_color(hsla(theme.border)))
                .child(self.dock_strip(h, cx))
                .child(div().flex_1().min_h_0().flex().flex_col().child(body))
                .when(h > 0, |d| d.child(Self::dock_divider(cx)));
            column = column.child(half);
        }
        // A panel's tab dragged onto the lower part stacks it below.
        if !stacked && cx.has_active_drag() {
            column = column.child(
                div()
                    .id("dock-stack")
                    .absolute()
                    .left_0()
                    .right_0()
                    .bottom_0()
                    .h(relative(0.45))
                    .drag_over::<DraggedPanel>(move |style, _, _, _| {
                        style
                            .bg(hsla(with_alpha(theme.accent, 0x33)))
                            .border_2()
                            .border_color(hsla(theme.accent))
                    })
                    .on_drop(cx.listener(|this, d: &DraggedPanel, _, cx| {
                        this.right_dock.move_to(d.panel, 1, 0);
                        cx.notify();
                    })),
            );
        }
        // Its left edge drags its width, as the map's.
        let edge = div()
            .id("dock-edge")
            .absolute()
            .top_0()
            .bottom_0()
            .left_0()
            .w(px(4.0))
            .cursor_col_resize()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.layout_ui.drag = Some(EdgeDrag::Dock);
                    cx.stop_propagation();
                    cx.notify();
                }),
            );
        let island = self
            .panel_island()
            .relative()
            .w(self.z(width))
            .flex_none()
            .when(!self.settings.islands, |d| {
                d.border_l_1().border_color(hsla(theme.border))
            })
            .child(column)
            .child(edge)
            .children(self.island_edge());
        Some(island.into_any_element())
    }

    /// The divider over a stacked bottom half: it drags the halves'
    /// share; a double click evens them.
    fn dock_divider(cx: &mut Context<Self>) -> AnyElement {
        div()
            .id("dock-divider")
            .absolute()
            .left_0()
            .right_0()
            .top(px(-2.0))
            .h(px(4.0))
            .cursor_row_resize()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.layout_ui.drag = Some(EdgeDrag::DockSplit);
                    cx.stop_propagation();
                    cx.notify();
                }),
            )
            .on_click(cx.listener(|this, e: &ClickEvent, _, cx| {
                if e.click_count() == 2 {
                    this.right_dock.split = 0.5;
                    cx.notify();
                }
            }))
            .into_any_element()
    }

    /// The divider between the halves dragged to `y` (window pixels): the
    /// top half's share, each half kept a fifth of the height.
    pub fn drag_dock_split(&mut self, y: Pixels) {
        let bounds = self.right_dock.bounds.get();
        let height = f32::from(bounds.size.height);
        if height <= 0.0 {
            return;
        }
        self.right_dock.split = (f32::from(y - bounds.origin.y) / height).clamp(0.2, 0.8);
    }

    /// Half `half`'s tabs: each its panel's icon (the chat's and the
    /// threads' unread dot on it while another tab shows), title and close
    /// button, dragged along the bar, to the other half or below; a
    /// right-click's menu moves it between the halves. The top's ends with
    /// the dock's hide button.
    #[expect(clippy::too_many_lines, reason = "each tab's parts, then the bar's")]
    fn dock_strip(&self, half: usize, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let Some((_, panels, active)) = self.right_dock.shown_halves().find(|(h, ..)| *h == half)
        else {
            return div().into_any_element();
        };
        let count = panels.len();
        let (scale, text) = (self.settings.ui_scale, self.settings.ui_font_size);
        // As a pane's bar: each part paints the bar's colour itself, a
        // pixel on top centring what is in it.
        let edge = |d: Div| {
            d.h_full()
                .pt(px(1.0))
                .bg(hsla(theme.tab_bar))
                .border_b_1()
                .border_color(hsla(theme.border))
        };
        let mut tabs = div()
            .id(("dock-tabs", half))
            .flex()
            .flex_initial()
            .h_full()
            .min_w_0()
            .overflow_x_scroll();
        for (index, &panel) in panels.iter().enumerate() {
            let on = index == active;
            let group = format!("dock-tab-{half}-{index}");
            let dot = match panel {
                Panel::Session(Tab::Chat) => self.collab.unread.dot(),
                Panel::Threads => self.threads.unread.dot(),
                Panel::History | Panel::Session(_) | Panel::Origin | Panel::Pathfinder => None,
            }
            .filter(|_| !on)
            .map(|dot| {
                self.notification_dot(dot)
                    .top(self.z(-3.0))
                    .right(self.z(-4.0))
            });
            tabs = tabs.child(
                div()
                    .id(("dock-tab", half * 100 + index))
                    .group(group.clone())
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
                    .when(on, |d| d.bg(hsla(theme.panel)))
                    .when(!on, |d| {
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
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.open_panel(panel);
                        cx.notify();
                    }))
                    .on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                            this.panel_menu(panel, half, e.position, window, cx);
                            cx.stop_propagation();
                        }),
                    )
                    .on_drag(DraggedPanel { panel }, move |dragged, _, _, cx| {
                        let panel = dragged.panel;
                        cx.new(|_| TabPreview {
                            tab: DraggedTab {
                                tab: TabId(u64::MAX),
                                label: panel.title().to_owned(),
                                icon: panel.icon(),
                            },
                            theme,
                            scale,
                            text,
                        })
                    })
                    .drag_over::<DraggedPanel>(move |style, _, _, _| {
                        style.bg(hsla(theme.element_selected))
                    })
                    .on_drop(cx.listener(move |this, d: &DraggedPanel, _, cx| {
                        this.right_dock.move_to(d.panel, half, index);
                        cx.notify();
                    }))
                    .child(
                        div()
                            .relative()
                            .flex()
                            .child(icon(panel.icon(), self.z(ICON), hsla(theme.text_muted)))
                            .children(dot),
                    )
                    .child(
                        div()
                            .whitespace_nowrap()
                            .text_color(hsla(if on { theme.text } else { theme.text_muted }))
                            .child(panel.title()),
                    )
                    .child(
                        div()
                            .id(("dock-close", half * 100 + index))
                            .flex()
                            .items_center()
                            .justify_center()
                            .size(self.z(16.0))
                            .rounded(self.z(3.0))
                            .when(!on, |d| d.invisible().group_hover(group, Styled::visible))
                            .hover(|s| s.bg(hsla(theme.element_hover)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.stop_propagation();
                                this.close_panel(panel);
                                cx.notify();
                            }))
                            .child(icon(IconName::X, self.z(12.0), hsla(theme.text_muted))),
                    ),
            );
        }
        // The bar past the tabs: a tab dropped there goes last.
        let rest = edge(div())
            .flex_1()
            .min_w_0()
            .drag_over::<DraggedPanel>(move |style, _, _, _| style.bg(hsla(theme.element_selected)))
            .on_drop(cx.listener(move |this, d: &DraggedPanel, _, cx| {
                this.right_dock.move_to(d.panel, half, count);
                cx.notify();
            }));
        let hide = (half == 0).then(|| {
            edge(div())
                .flex()
                .flex_none()
                .items_center()
                .px(self.z(4.0))
                .rounded_tr(self.island_corner())
                .child(self.icon_button(
                    "dock-hide",
                    IconName::ChevronRight,
                    Command::ToggleRightSidebar,
                    true,
                    false,
                    cx,
                ))
        });
        div()
            .flex()
            .flex_none()
            .h(self.bar(TAB_PAD))
            .bg(hsla(theme.under(theme.tab_bar)))
            .when(half == 0, |d| d.rounded_t(self.island_corner()))
            .child(tabs)
            .child(rest)
            .children(hide)
            .into_any_element()
    }

    /// A panel tab's menu: Move Below (or Move Above, in the bottom half),
    /// and Close.
    fn panel_menu(
        &mut self,
        panel: Panel,
        half: usize,
        at: Point<Pixels>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let mut items = Vec::new();
        if half == 0 {
            // A lone panel has nothing to stack under.
            let alone = !self.right_dock.stacked()
                && self
                    .right_dock
                    .shown_halves()
                    .all(|(_, panels, _)| panels.len() < 2);
            items.push(OwnItem {
                enabled: !alone,
                ..OwnItem::new("Move Below", move |this, _, cx| {
                    this.right_dock.move_to(panel, 1, usize::MAX);
                    cx.notify();
                })
            });
        } else {
            items.push(OwnItem::new("Move Above", move |this, _, cx| {
                this.right_dock.move_to(panel, 0, usize::MAX);
                cx.notify();
            }));
        }
        items.push(OwnItem::new("Close", move |this, _, cx| {
            this.close_panel(panel);
            cx.notify();
        }));
        self.toggle_own_menu("dock-panel", at, items, window, cx);
    }

    /// Panel `panel`'s content, filling its half.
    fn panel_body(
        &mut self,
        panel: Panel,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        match panel {
            Panel::Threads => {
                let reply = self.reply_box(window, cx);
                self.render_threads(&reply, cx)
            }
            Panel::History => self.render_history(),
            Panel::Session(tab) => self.render_session_body(tab, window, cx),
            Panel::Origin => self
                .render_origin(cx)
                .unwrap_or_else(|| div().into_any_element()),
            Panel::Pathfinder => self.render_pathfinder(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use binbun_gui_view::layout_file::SavedPanel;

    use super::{Panel, RightDock};
    use crate::collab::Tab;

    fn halves(dock: &RightDock) -> Vec<(Vec<Panel>, usize)> {
        dock.halves
            .iter()
            .map(|half| (half.panels.clone(), half.active))
            .collect()
    }

    const CHAT: Panel = Panel::Session(Tab::Chat);

    /// Panels open as tabs of the top half, the one opened or brought
    /// forward shown; a closed one's left neighbour is shown after it.
    #[test]
    fn panels_open_as_tabs_and_close_to_their_left() {
        let mut dock = RightDock::default();
        assert!(dock.is_empty());
        dock.open(Panel::Threads);
        dock.open(CHAT);
        dock.open(Panel::Pathfinder);
        assert!(dock.shows(Panel::Pathfinder) && !dock.shows(Panel::Threads));
        dock.open(Panel::Threads);
        assert!(dock.shows(Panel::Threads));
        dock.open(CHAT);
        assert!(dock.close(CHAT));
        assert!(dock.shows(Panel::Threads));
        assert!(!dock.close(Panel::Origin));
        assert_eq!(
            halves(&dock)[0],
            (vec![Panel::Threads, Panel::Pathfinder], 0)
        );
        assert!(!dock.stacked());
    }

    /// The saved panels come back in their halves with the front ones in
    /// front; one not saved in front leaves its saved neighbour on the
    /// left in front, and panels already open stay before them.
    #[test]
    fn saved_panels_come_back_where_they_were() {
        let mut dock = RightDock::default();
        assert_eq!(dock.saved(true), None);
        dock.open(Panel::Threads);
        dock.open(CHAT);
        dock.open(Panel::Pathfinder);
        dock.open(Panel::Origin);
        dock.open(Panel::History);
        dock.move_to(Panel::History, 1, 0);
        dock.open(CHAT);
        dock.split = 0.3;
        let saved = dock.saved(false).unwrap();
        assert!(!saved.shown);
        let names = |h: usize| (saved.halves[h].panels.clone(), saved.halves[h].active);
        assert_eq!(
            names(0),
            (vec![SavedPanel::Threads, SavedPanel::Pathfinder], 0)
        );
        assert_eq!(names(1), (vec![SavedPanel::History], 0));

        let mut after = RightDock::default();
        after.open(CHAT);
        after.restore(&saved);
        assert_eq!(
            halves(&after),
            vec![
                (vec![CHAT, Panel::Threads, Panel::Pathfinder], 1),
                (vec![Panel::History], 0),
            ]
        );
        assert!((after.split - 0.3).abs() < 1e-6);
        // History reopens below.
        after.close(Panel::History);
        after.open(Panel::History);
        assert!(after.stacked());
    }

    /// A panel moved below stacks a half of its own, reopens there while
    /// a top half is beside it, and a bottom half left alone rises.
    #[test]
    fn a_panel_moved_below_stacks_and_reopens_there() {
        let mut dock = RightDock::default();
        dock.open(Panel::Threads);
        dock.open(CHAT);
        dock.move_to(CHAT, 1, 0);
        assert!(dock.stacked());
        assert!(dock.shows(Panel::Threads) && dock.shows(CHAT));
        assert!(dock.lowest(CHAT) && !dock.lowest(Panel::Threads));
        dock.close(CHAT);
        assert!(!dock.stacked());
        dock.open(CHAT);
        assert_eq!(halves(&dock)[1], (vec![CHAT], 0));
        // The top half closed: the bottom one rises, no longer below.
        dock.close(Panel::Threads);
        assert_eq!(halves(&dock)[0], (vec![CHAT], 0));
        assert!(!dock.stacked());
        dock.open(Panel::Threads);
        dock.close(CHAT);
        dock.open(CHAT);
        assert_eq!(halves(&dock)[0], (vec![Panel::Threads, CHAT], 1));
        // Moved along its own bar.
        dock.move_to(CHAT, 0, 0);
        assert_eq!(halves(&dock)[0], (vec![CHAT, Panel::Threads], 0));
        // A lone panel moved below stays on top.
        dock.close(Panel::Threads);
        dock.move_to(CHAT, 1, 0);
        assert_eq!(halves(&dock)[0], (vec![CHAT], 0));
        assert!(!dock.stacked());
    }
}
