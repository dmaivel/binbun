//! Panes as views (`binbun_gui_view::tabs`): a pane holds at most one tab
//! of code, its view (the listing, the C), which changes only when the
//! user changes it ([`Workspace::set_code_view`]). Linked panes show one
//! place: a navigation from the map, a list or a name moves them all and
//! never opens a tab; Ctrl+click or a middle click opens its target in a
//! new window tab (`window_tabs`; with Shift, the current one kept
//! shown). Lists whose rows go places (the strings,
//! cross-references, results, a map folder) open in the bottom dock, below
//! the code, so a row clicked leaves its list in view
//! ([`Workspace::open_below`]), as do the console and terminals. A pane's other tabs keep their views when
//! brought back; its tab of code brought back shows where the pane is: the
//! linked place, or its own.

use binbun_gui_view::layout::{Axis, PaneId, TabId};
use binbun_gui_view::tabs::{Click, Opening, Shown, View};
use gpui_kit::{App, ClickEvent, Context, MouseButton, MouseDownEvent, Window};

use crate::workspace::{TabKind, Workspace};

/// A click on a row or a map entry, as `binbun_gui_view::tabs` reads it.
pub fn row_click(e: &ClickEvent, cx: &App) -> Click {
    Click {
        secondary: e.modifiers().secondary(cx),
        shift: e.modifiers().shift,
        middle: e.is_middle_click(),
        count: e.click_count(),
    }
}

/// A mouse down on a name in the listing, the graph or the C (a right
/// button's, Ctrl or not, opens nothing).
pub fn name_click(e: &MouseDownEvent, cx: &App) -> Click {
    Click {
        secondary: e.button == MouseButton::Left && e.modifiers.secondary(cx),
        shift: e.modifiers.shift,
        middle: e.button == MouseButton::Middle,
        count: e.click_count,
    }
}

/// Whether `kind` is a view of code (the listing or a C).
pub fn is_code(kind: Option<&TabKind>) -> bool {
    matches!(kind, Some(TabKind::Listing | TabKind::C { .. }))
}

/// Whether `kind` opens below the code, in the bottom dock: a list whose
/// rows go places, the console, a terminal. A pane of them has a tab bar,
/// and its tabs close and cycle there.
pub fn is_below_code(kind: &TabKind) -> bool {
    matches!(
        kind,
        TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Found(_)
            | TabKind::Folder(_)
            | TabKind::Console
            | TabKind::Terminal(_)
    )
}

impl Workspace {
    /// Opens `kind`, a list or a shell ([`is_below_code`]; `preview` as
    /// [`Layout::open`] takes it), in the bottom dock: made along the
    /// bottom if there is none, shown if hidden, a tab equal to it brought
    /// back. The dock's pane.
    ///
    /// [`Layout::open`]: binbun_gui_view::layout::Layout::open
    pub fn open_below(&mut self, kind: TabKind, preview: bool, cx: &mut Context<Self>) -> PaneId {
        let id = if let Some(id) = self.layout.open_in_dock(kind.clone(), preview) {
            id
        } else {
            let id = self.layout.focused();
            self.layout.open(id, kind, preview);
            id
        };
        self.ensure_pane(id, cx);
        id
    }

    /// Pane `id`'s active tab is at `address` now.
    pub fn placed(&mut self, id: PaneId, address: u64) {
        if let Some(tab) = self.layout.active_tab(id) {
            self.places.set(tab, address);
        }
    }

    /// Each pane whose active tab changed since last asked shows that
    /// tab's view again (its own: the graph or the text, the hex view, the
    /// call graph, the IR); the tabs closed are forgotten. A tab of code
    /// shows where its pane is: a linked pane the linked place, one on its
    /// own its own place. Nothing else moves. A tab first seen (opened from
    /// no tab of code) starts as the setting says.
    pub fn show_tabs(&mut self) {
        let layout = &self.layout;
        self.places.retain(|tab| layout.find_tab(tab).is_some());
        self.trails
            .retain(|pane| layout.pane(pane).is_some_and(|p| !p.synced));
        let fresh = View {
            graph: self.new_listing_graph(),
            ..View::default()
        };
        for pane in self.layout.panes() {
            for tab in &pane.tabs {
                self.places.adopt(tab.id(), fresh);
            }
        }
        let shown: Vec<(PaneId, TabId)> = self
            .layout
            .panes()
            .filter_map(|p| Some((p.id, p.tabs.get(p.active)?.id())))
            .collect();
        for (pane, tab) in shown {
            let Some(shown) = self.show_tab(pane, tab) else {
                continue;
            };
            self.show_view(pane, tab, shown.view.unwrap_or(fresh));
            if !is_code(self.layout.active(pane)) {
                continue;
            }
            let linked = self.layout.pane(pane).is_some_and(|p| p.synced);
            let at = if linked {
                self.shared.or(shown.at)
            } else {
                shown.at
            };
            if let Some(at) = at {
                self.set_cursor(pane, at, false);
            }
        }
    }

    /// Pane `id` shows tab `tab` now: the tab it showed keeps the view it
    /// is left in (and its call graph, if it shows one); what `tab` is to
    /// show again, if it is another.
    pub fn show_tab(&mut self, id: PaneId, tab: TabId) -> Option<Shown> {
        let view = self.pane_view(id);
        if let Some(before) = self.places.shown(id).filter(|&before| before != tab) {
            self.keep_view(id, before);
        }
        self.places.show(id, tab, view)
    }

    /// Tab `tab` keeps pane `id`'s view as its own (and its call graph, if
    /// it shows one).
    pub fn keep_view(&mut self, id: PaneId, tab: TabId) {
        let view = self.pane_view(id);
        if view.calls
            && let Some(state) = self.panes.get(&id)
        {
            self.places.keep_calls(tab, state.calls.clone());
        }
        if let Some(unified) = self.unified_view_of(id) {
            self.places.keep_unified(tab, unified);
        }
        self.places.set_view(tab, view);
    }

    /// The view of pane `id`'s active tab, as its pane shows it.
    pub fn pane_view(&self, id: PaneId) -> View {
        self.panes.get(&id).map_or_else(View::default, |s| View {
            graph: if s.calls.on {
                s.calls.graph
            } else if s.hex.on {
                s.hex.graph
            } else {
                s.graph.on
            },
            hex: s.hex.on,
            calls: s.calls.on,
            ir: s.ir.on,
            unified: s.unified.on,
        })
    }

    /// Pane `id` shows tab `tab`'s view `view` (its call graph as it was
    /// left, laid out again as what it shows says; one not kept is not
    /// shown).
    pub fn show_view(&mut self, id: PaneId, tab: TabId, view: View) {
        let calls = view
            .calls
            .then(|| self.places.calls(tab).cloned())
            .flatten();
        // Its unified listing's layers and folds (a tab first shown: as
        // they start), at its place.
        let unified = self.places.unified(tab).cloned().unwrap_or_default();
        let at = self.places.at(tab);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let calls_on = calls.is_some();
        match calls {
            Some(calls) => state.calls = calls,
            None => state.calls.on = false,
        }
        state.calls.graph = view.graph;
        state.hex.on = view.hex;
        state.hex.graph = view.graph;
        state.unified.set_view(&unified);
        let unified_on = view.unified && !view.hex && !calls_on;
        if unified_on && !state.unified.on && state.unified.target.is_none() {
            state.unified.target = at.map(|a| (a, true));
        }
        state.unified.on = unified_on;
        let graph = view.graph && !view.hex && !calls_on && !unified_on;
        if graph && !state.graph.on {
            // An arrival: as the tab's memory says.
            state.graph.tab = None;
            state.graph.landing = false;
        }
        state.graph.on = graph;
        if state.ir.on != view.ir {
            state.ir.on = view.ir;
            state.ir.dropdown = false;
        }
        if !view.hex && self.hex.field.as_ref().is_some_and(|f| f.pane == id) {
            self.hex.field = None;
        }
    }

    /// The view of code `kind` (the listing, or a C in `kind`'s C view)
    /// at `address`: a C shows the function holding it.
    pub(crate) fn code_at(&self, kind: Option<&TabKind>, address: Option<u64>) -> TabKind {
        let function = address
            .and_then(|a| self.listing.as_ref()?.function_of(a))
            .map(|(f, _)| f);
        match kind {
            Some(&TabKind::C { view, .. }) => TabKind::C { function, view },
            Some(
                TabKind::Listing
                | TabKind::Settings
                | TabKind::Console
                | TabKind::Terminal(_)
                | TabKind::Strings
                | TabKind::Xrefs { .. }
                | TabKind::Struct(_)
                | TabKind::Found(_)
                | TabKind::Folder(_),
            )
            | None => TabKind::Listing,
        }
    }

    /// The tab of pane `id` that is its view of code, by its index.
    pub fn code_tab_of(&self, id: PaneId) -> Option<usize> {
        self.layout
            .pane(id)?
            .tabs
            .iter()
            .position(|t| is_code(Some(&t.content)))
    }

    /// Pane `id` shows `kind` (the listing or a C view) as its view of
    /// code, where the pane is: its tab of code changed in place (it has
    /// at most one), else one added and shown. The only way a pane's view
    /// of code changes.
    pub fn set_code_view(&mut self, id: PaneId, kind: &TabKind) {
        let address = self.code_address(id);
        let content = self.code_at(Some(kind), address);
        match self.code_tab_of(id) {
            Some(index) => {
                if let Some(tab) = self.layout.pane_mut(id).and_then(|p| p.tabs.get_mut(index)) {
                    tab.content = content;
                }
                self.layout.activate(id, index);
            }
            None => {
                self.layout.open(id, content, false);
            }
        }
        if let Some(address) = address {
            self.set_cursor(id, address, false);
        }
        self.ensure_documents();
    }

    /// Where pane `id`'s view of code is (shown or not): a linked pane the
    /// linked place, one on its own its tab of code's place.
    pub fn code_address(&self, id: PaneId) -> Option<u64> {
        let linked = self.layout.pane(id).is_some_and(|p| p.synced);
        let own = self
            .code_tab_of(id)
            .and_then(|index| Some(self.layout.pane(id)?.tabs.get(index)?.id()))
            .and_then(|tab| self.places.at(tab));
        if linked {
            self.shared.or(own)
        } else {
            own.or(self.shared)
        }
    }

    /// The linked pane a navigation from pane `from` (a list's, the
    /// map's: the focused one) shows its target in: `from` itself if it is
    /// linked and shows code, else a linked pane showing code (the listing
    /// first), else a linked pane holding a tab of code (brought back),
    /// else `from` given a listing.
    pub fn linked_code_pane(&mut self, from: PaneId) -> PaneId {
        let linked = |p: &binbun_gui_view::layout::Pane<TabKind>| p.synced;
        let shows = |kind: Option<&TabKind>, listing: bool| {
            if listing {
                matches!(kind, Some(TabKind::Listing))
            } else {
                is_code(kind)
            }
        };
        if self
            .layout
            .pane(from)
            .is_some_and(|p| linked(p) && shows(p.tabs.get(p.active).map(|t| &t.content), false))
        {
            return from;
        }
        for listing in [true, false] {
            if let Some(id) = self
                .layout
                .panes()
                .find(|p| linked(p) && shows(p.tabs.get(p.active).map(|t| &t.content), listing))
                .map(|p| p.id)
            {
                return id;
            }
        }
        let holding = self
            .layout
            .panes()
            .filter(|p| linked(p))
            .find_map(|p| Some((p.id, p.tabs.iter().position(|t| is_code(Some(&t.content)))?)));
        if let Some((id, index)) = holding {
            self.layout.activate(id, index);
            self.ensure_documents();
            return id;
        }
        self.set_code_view(from, &TabKind::Listing);
        from
    }

    /// Opens `address` as `opening` says, from pane `from` (the pane the
    /// navigation came from: a list's, the map's, a name's): in the linked
    /// panes (their place moved there, a step on their trail), or in a new
    /// window tab.
    pub fn open_at(
        &mut self,
        from: PaneId,
        address: u64,
        opening: Opening,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match opening {
            Opening::Linked { focus } => {
                self.leave_tool_tab();
                let id = self.linked_code_pane(from);
                let focused = self.layout.focused();
                self.layout.focus(id);
                let here = self.location();
                self.trails.of(id, true).push(here);
                self.go(address, None);
                if focus {
                    self.focus_pane(id, window, cx);
                } else {
                    self.layout.focus(focused);
                }
            }
            Opening::Tab { focus } => self.open_window_tab(address, focus, window, cx),
        }
        self.ensure_documents();
        cx.notify();
    }

    /// Ctrl+click or a middle click on a name in pane `id` naming
    /// `target`: opened in a new window tab as `click` says; whether it was
    /// such a click.
    pub fn open_name(
        &mut self,
        id: PaneId,
        target: Option<u64>,
        click: Click,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(opening) = click.on_name() else {
            return false;
        };
        if let Some(target) = target {
            self.open_at(id, target, opening, window, cx);
        }
        true
    }

    /// Open Graph in Split: a new linked pane beside the focused one,
    /// showing the function at its cursor as a graph (linked, it moves with
    /// the other linked panes). The focus stays.
    pub fn open_graph_in_split(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        let Some(address) = self.cursor_address(id) else {
            return;
        };
        if self
            .listing
            .as_ref()
            .and_then(|l| l.function_of(address))
            .is_none()
        {
            return;
        }
        let Some(new) = self.layout.split(id, Axis::Row, TabKind::Listing) else {
            return;
        };
        self.ensure_pane(new, cx);
        let linked = self.layout.pane(id).is_some_and(|p| p.synced);
        if let Some(pane) = self.layout.pane_mut(new) {
            pane.synced = linked;
        }
        if let Some(tab) = self.layout.active_tab(new) {
            self.show_tab(new, tab);
        }
        self.leave_hex(new);
        self.leave_calls(new);
        if let Some(state) = self.panes.get_mut(&new) {
            state.graph.on = true;
            state.graph.tab = None;
        }
        self.set_cursor(new, address, true);
        self.focus_pane(id, window, cx);
        self.ensure_documents();
    }
}
