//! Tabs dragged: along
//! their bar to reorder, onto another pane's bar to move there (at the
//! drop position), onto a pane's body to move into it, or near one of its
//! edges to open in a new pane on that side, the half it would take shown
//! while dragging. A dragged preview tab is kept (pinned); the pane a tab
//! leaves closes if emptied, unless it is the only one. A tab keeps its
//! identity wherever it goes, so its place, its view and a graph following
//! it go along (`binbun_gui_view::layout::Layout::move_tab`). The keys:
//! Move Tab Left and Right, Move Tab to Next Pane.

use binbun_gui_view::layout::{Direction, PaneId, TabDrop, TabId, drop_side};
use gpui_kit::assets::IconName;
use gpui_kit::prelude::*;
use gpui_kit::{AnyElement, Context, DragMoveEvent, Window, div, px, relative};

use crate::icons::icon;
use crate::theme::{Theme, hsla, with_alpha};
use crate::workspace::{ICON, Workspace};

/// A tab being dragged: which, and what its preview shows.
#[derive(Clone, Debug)]
pub struct DraggedTab {
    /// The tab.
    pub tab: TabId,
    /// Its label.
    pub label: String,
    /// Its icon.
    pub icon: IconName,
}

/// The preview under the pointer while a tab is dragged: the tab as its
/// bar shows it.
pub struct TabPreview {
    /// What it shows.
    pub tab: DraggedTab,
    /// The colours.
    pub theme: &'static Theme,
    /// The window's zoom.
    pub scale: f32,
    /// The interface's text size (logical).
    pub text: f32,
}

impl Render for TabPreview {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        let theme = self.theme;
        let z = |v: f32| px(v * self.scale);
        div()
            .flex()
            .items_center()
            .gap(z(6.0))
            .px(z(10.0))
            .py(z(5.0))
            .text_size(z(self.text))
            .bg(hsla(theme.editor))
            .border_1()
            .border_color(hsla(theme.border_focused))
            .rounded(z(4.0))
            .shadow_md()
            .text_color(hsla(theme.text))
            .child(icon(self.tab.icon, z(ICON), hsla(theme.text_muted)))
            .child(self.tab.label.clone())
    }
}

impl Workspace {
    /// Moves tab `tab` where `to` says, the pane it lands in focused. A
    /// pane's view of code dropped into another pane that has one stays
    /// where it was (a pane shows one view of code; on an edge, it makes a
    /// pane of its own). The bottom dock takes only what opens below the
    /// code (lists, the console, terminals).
    pub fn drop_tab(
        &mut self,
        tab: TabId,
        to: TabDrop,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.layout_ui.tab_drop = None;
        let content = self
            .layout
            .find_tab(tab)
            .and_then(|(pane, index)| self.layout.pane(pane)?.tabs.get(index))
            .map(|t| t.content.clone());
        let code = crate::tabs::is_code(content.as_ref());
        let target = match to {
            TabDrop::Into { pane, .. } | TabDrop::Edge { pane, .. } => pane,
        };
        if self.layout.is_dock(target) && !content.as_ref().is_some_and(crate::tabs::is_below_code)
        {
            cx.notify();
            return;
        }
        if let TabDrop::Into { pane, .. } = to
            && code
            && self.layout.find_tab(tab).map(|(from, _)| from) != Some(pane)
            && self.code_tab_of(pane).is_some()
        {
            cx.notify();
            return;
        }
        // A tab shown where it is dragged from goes in the view it shows.
        if let Some((from, _)) = self.layout.find_tab(tab)
            && self.layout.active_tab(from) == Some(tab)
        {
            self.keep_view(from, tab);
        }
        let Some(landed) = self.layout.move_tab(tab, to) else {
            cx.notify();
            return;
        };
        self.forget_closed_panes();
        let made = !self.panes.contains_key(&landed);
        self.ensure_pane(landed, cx);
        // A pane made for it shows it at its place, in its view (a pane
        // that showed another tab does so as tabs brought back do).
        if made {
            self.show_tab(landed, tab);
            if let Some(view) = self.places.view(tab) {
                self.show_view(landed, tab, view);
            }
            if let Some(at) = self.places.at(tab) {
                self.set_cursor(landed, at, false);
            }
        }
        self.focus_pane(landed, window, cx);
        self.ensure_documents();
        cx.notify();
    }

    /// A tab dragged over pane `id`'s body: where it would go there (an
    /// edge's new pane, or into it), shown until it moves off.
    pub fn tab_drag_over(
        &mut self,
        id: PaneId,
        e: &DragMoveEvent<DraggedTab>,
        cx: &mut Context<Self>,
    ) {
        let b = e.bounds;
        let at = e.event.position;
        let over = if b.contains(&at) {
            let x = f32::from(at.x - b.origin.x) / f32::from(b.size.width).max(1.0);
            let y = f32::from(at.y - b.origin.y) / f32::from(b.size.height).max(1.0);
            // The bottom dock takes a tab into itself, edges or not.
            let side = drop_side(x, y).filter(|_| !self.layout.is_dock(id));
            Some((id, side))
        } else {
            None
        };
        let mine = self.layout_ui.tab_drop.is_some_and(|(pane, _)| pane == id);
        if over.is_some() && over != self.layout_ui.tab_drop {
            self.layout_ui.tab_drop = over;
            cx.notify();
        } else if over.is_none() && mine {
            self.layout_ui.tab_drop = None;
            cx.notify();
        }
    }

    /// A tab dropped on pane `id`'s body: on the side shown, else into
    /// it after its active tab.
    pub fn drop_on_body(
        &mut self,
        id: PaneId,
        tab: TabId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let side = self
            .layout_ui
            .tab_drop
            .filter(|(pane, _)| *pane == id)
            .and_then(|(_, side)| side);
        let to = match side {
            Some(side) => TabDrop::Edge { pane: id, side },
            None => TabDrop::Into {
                pane: id,
                at: self.layout.pane(id).map_or(0, |p| p.active + 1),
            },
        };
        self.drop_tab(tab, to, window, cx);
    }

    /// What pane `id`'s body shows while a tab is dragged over it: the
    /// half a new pane on that side would take, else the whole pane.
    pub fn drop_zone(&self, id: PaneId, cx: &Context<Self>) -> Option<AnyElement> {
        let (_, side) = self
            .layout_ui
            .tab_drop
            .filter(|(pane, _)| *pane == id && cx.has_active_drag())?;
        let theme = self.theme;
        let zone = div()
            .absolute()
            .bg(hsla(with_alpha(theme.accent, 0x33)))
            .border_2()
            .border_color(hsla(theme.accent));
        let zone = match side {
            None => zone.inset_0(),
            Some(Direction::Left) => zone.left_0().top_0().bottom_0().w(relative(0.5)),
            Some(Direction::Right) => zone.right_0().top_0().bottom_0().w(relative(0.5)),
            Some(Direction::Up) => zone.left_0().right_0().top_0().h(relative(0.5)),
            Some(Direction::Down) => zone.left_0().right_0().bottom_0().h(relative(0.5)),
        };
        Some(zone.into_any_element())
    }

    /// Move Tab Left or Right: pane `id`'s active tab one place along its
    /// bar.
    pub fn step_tab(
        &mut self,
        id: PaneId,
        right: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(pane) = self.layout.pane(id) else {
            return;
        };
        let (index, len) = (pane.active, pane.tabs.len());
        let Some(tab) = self.layout.active_tab(id) else {
            return;
        };
        let at = if right {
            if index + 1 >= len {
                return;
            }
            index + 2
        } else {
            let Some(at) = index.checked_sub(1) else {
                return;
            };
            at
        };
        self.drop_tab(tab, TabDrop::Into { pane: id, at }, window, cx);
    }

    /// Move Tab to Next Pane: pane `id`'s active tab after the next pane's
    /// active tab (in tree order, wrapping).
    pub fn tab_to_next_pane(&mut self, id: PaneId, window: &mut Window, cx: &mut Context<Self>) {
        let ids: Vec<PaneId> = self.layout.panes().map(|p| p.id).collect();
        let next = ids
            .iter()
            .position(|&p| p == id)
            .and_then(|i| ids.get((i + 1) % ids.len()))
            .copied()
            .filter(|&p| p != id);
        let (Some(next), Some(tab)) = (next, self.layout.active_tab(id)) else {
            return;
        };
        let at = self.layout.pane(next).map_or(0, |p| p.active + 1);
        self.drop_tab(tab, TabDrop::Into { pane: next, at }, window, cx);
    }
}
