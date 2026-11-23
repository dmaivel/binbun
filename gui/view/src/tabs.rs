//! Panes as views: where each pane's view of code is, how a click opens
//! what it names, and what a C view shows once its place is in no
//! function.
//!
//! A pane holds at most one tab of code, its view (the listing, its graph,
//! hex or call graph; the C, its IR): the view changes only when the user
//! changes it. Linked panes show one place and share one back/forward
//! trail ([`crate::history::Trails`]); a pane on its own keeps its own
//! place and trail. A Ctrl+click or a middle click opens its target in a
//! new window tab ([`Opening::Tab`]). The other tabs are things that do
//! not move (cross-references, search results, strings, a struct, the
//! settings): each keeps the view it was left in ([`View`]).

use std::collections::HashMap;

use binbun::cfg::FunctionId;

use crate::calls::CallsPane;
use crate::graph_memory::GraphMemory;
use crate::layout::{PaneId, TabId};
use crate::listing::Listing;

/// How a navigation opens its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opening {
    /// In the linked panes, their place moved there (a click in the map
    /// or a list; a double click or Enter gives the code the focus:
    /// `focus`).
    Linked {
        /// The code pane takes the focus.
        focus: bool,
    },
    /// In a new window tab beside the current one, with a place and trail
    /// of its own (Ctrl+click, a middle click; with Shift, the current tab
    /// stays shown: `focus` false).
    Tab {
        /// The new tab is shown.
        focus: bool,
    },
}

/// A click on a name or a row: its button and modifiers, and how many
/// clicks it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Click {
    /// Ctrl held (Cmd on macOS).
    pub secondary: bool,
    /// Shift held.
    pub shift: bool,
    /// The middle button.
    pub middle: bool,
    /// The click count (2: a double click).
    pub count: usize,
}

impl Click {
    /// Whether it opens a new tab (Ctrl or the middle button), the current
    /// one kept shown with Shift.
    fn new_tab(self) -> Option<Opening> {
        (self.secondary || self.middle).then_some(Opening::Tab { focus: !self.shift })
    }

    /// How a click on a row of the map or of a list opens its target: a
    /// new tab with Ctrl or the middle button, else in the linked panes
    /// (a double click gives them the focus).
    pub fn on_row(self) -> Opening {
        self.new_tab().unwrap_or(Opening::Linked {
            focus: self.count >= 2,
        })
    }

    /// How a click on a name in the listing or the C opens what it names:
    /// a new tab with Ctrl or the middle button; `None` for a plain
    /// click, which moves the cursor as it always has.
    pub fn on_name(self) -> Option<Opening> {
        self.new_tab()
    }
}

/// What a tab brought back shows again: its place and its view (each
/// `None` if it has not had one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shown {
    /// Its cursor's address.
    pub at: Option<u64>,
    /// Its view when it was left.
    pub view: Option<View>,
}

/// A tab's view: its listing as the graph, the hex view or the call
/// graph, its C as the IR. A tab of the listing toggles them in place,
/// each tab its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(clippy::struct_excessive_bools, reason = "independent toggles")]
pub struct View {
    /// Its listing shown as the graph (under the hex view or the call
    /// graph: what leaving them shows).
    pub graph: bool,
    /// Its listing shown as the hex view.
    pub hex: bool,
    /// Its listing shown as the call graph (under the hex view if both).
    pub calls: bool,
    /// Its C shown as the IR.
    pub ir: bool,
}

/// Each tab's place and view, and which tab each pane showed last (a
/// pane's tab of code is where the pane is).
#[derive(Clone, Debug, Default)]
pub struct Places {
    /// Each tab's cursor address, as last set.
    at: HashMap<TabId, u64>,
    /// Each tab's view as it was last left (or given it).
    views: HashMap<TabId, View>,
    /// The call graph of each tab left showing one (what it showed, its
    /// view): not made again from the tab's place.
    calls: HashMap<TabId, CallsPane>,
    /// The tab each pane showed when last asked.
    shown: HashMap<PaneId, TabId>,
    /// Where each tab's graph was left ([`GraphMemory`]).
    graphs: HashMap<TabId, GraphMemory>,
}

impl Places {
    /// Tab `tab`'s place, if it has one.
    pub fn at(&self, tab: TabId) -> Option<u64> {
        self.at.get(&tab).copied()
    }

    /// Where tab `tab`'s graph was left, if it was shown.
    pub fn graph_memory(&self, tab: TabId) -> Option<&GraphMemory> {
        self.graphs.get(&tab)
    }

    /// Where tab `tab`'s graph was left, to be told where it is now.
    pub fn graph_memory_mut(&mut self, tab: TabId) -> &mut GraphMemory {
        self.graphs.entry(tab).or_default()
    }

    /// Tab `tab`'s view as it was last left (or given it), if it has one.
    pub fn view(&self, tab: TabId) -> Option<View> {
        self.views.get(&tab).copied()
    }

    /// Tab `tab` shows `view` (a tab opened from another takes its view).
    pub fn set_view(&mut self, tab: TabId, view: View) {
        self.views.insert(tab, view);
    }

    /// Tab `tab` shows `view` unless it has a view already (a tab first
    /// seen).
    pub fn adopt(&mut self, tab: TabId, view: View) {
        self.views.entry(tab).or_insert(view);
    }

    /// Tab `tab` was left showing the call graph `calls`.
    pub fn keep_calls(&mut self, tab: TabId, calls: CallsPane) {
        self.calls.insert(tab, calls);
    }

    /// The call graph tab `tab` was left showing, if it was.
    pub fn calls(&self, tab: TabId) -> Option<&CallsPane> {
        self.calls.get(&tab)
    }

    /// Tab `tab` is at `address` now.
    pub fn set(&mut self, tab: TabId, address: u64) {
        self.at.insert(tab, address);
    }

    /// Forgets the tabs `live` says are gone: their places and views. (A
    /// pane's shown tab is kept, gone or not: the tab shown after it is
    /// shown again.)
    pub fn retain(&mut self, live: impl Fn(TabId) -> bool) {
        self.at.retain(|&tab, _| live(tab));
        self.views.retain(|&tab, _| live(tab));
        self.calls.retain(|&tab, _| live(tab));
        self.graphs.retain(|&tab, _| live(tab));
    }

    /// Pane `pane` shows tab `tab` now, the tab it showed before left in
    /// `view`. If that was another tab, what `tab` is to show again;
    /// `None` if it is the same, or the pane's first (as it was laid out:
    /// nothing to show again).
    pub fn show(&mut self, pane: PaneId, tab: TabId, view: View) -> Option<Shown> {
        let before = self.shown.insert(pane, tab)?;
        if before == tab {
            return None;
        }
        self.views.insert(before, view);
        Some(Shown {
            at: self.at(tab),
            view: self.view(tab),
        })
    }

    /// The tab pane `pane` showed when last asked.
    pub fn shown(&self, pane: PaneId) -> Option<TabId> {
        self.shown.get(&pane).copied()
    }

    /// Forgets everything (the layout was replaced: its tab ids start
    /// again).
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Tab `tab` as it was saved (`layout.toml`): its place, its view (the
    /// graph or the text).
    pub fn restore(&mut self, tab: TabId, at: Option<u64>, graph: bool) {
        if let Some(at) = at {
            self.at.insert(tab, at);
        }
        self.views.insert(
            tab,
            View {
                graph,
                ..View::default()
            },
        );
    }
}

/// What a C tab shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CSubject {
    /// A function's C.
    Function(FunctionId),
    /// Its place is in no function (its function was deleted under it,
    /// or it went where no function is before showing one): the tab says
    /// so, at that address.
    Outside(u64),
    /// Nothing yet (no place).
    Nothing,
}

/// What a C tab showing `function` (`None`: none, or its function gone)
/// at `place` shows.
pub fn c_subject(function: Option<FunctionId>, place: Option<u64>) -> CSubject {
    match (function, place) {
        (Some(function), _) => CSubject::Function(function),
        (None, Some(address)) => CSubject::Outside(address),
        (None, None) => CSubject::Nothing,
    }
}

/// The function a C tab showing `function` at `place` shows once
/// `listing` is built again (after a correction, an undo): the one it
/// showed (by its id now, which the session's reopening gave it); if
/// none, the function holding its place now (made again there), else
/// none.
pub fn retarget(
    function: Option<FunctionId>,
    place: Option<u64>,
    listing: &Listing,
) -> Option<FunctionId> {
    function.or_else(|| listing.function_of(place?).map(|(f, _)| f))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests fail loudly"
    )]

    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use binbun::corrections::{Bounds, Corrections};

    use super::*;
    use crate::layout::Layout;
    use crate::listing::Options as ListingOptions;
    use crate::session::{Event, Session};
    use crate::settings::SymbolDownload;

    #[test]
    fn clicks_open_as_the_decision_says() {
        let click = |secondary, shift, middle, count| Click {
            secondary,
            shift,
            middle,
            count,
        };
        let linked = |focus| Opening::Linked { focus };
        let tab = |focus| Opening::Tab { focus };
        // A row: a single click moves the linked panes (the focus kept), a
        // double click gives them the focus.
        assert_eq!(click(false, false, false, 1).on_row(), linked(false));
        assert_eq!(click(false, false, false, 2).on_row(), linked(true));
        // Shift alone changes nothing.
        assert_eq!(click(false, true, false, 1).on_row(), linked(false));
        // Ctrl or the middle button: a new tab, Shift keeping the current
        // one shown.
        for count in [1, 2] {
            assert_eq!(click(true, false, false, count).on_row(), tab(true));
            assert_eq!(click(false, false, true, count).on_row(), tab(true));
            assert_eq!(click(true, true, false, count).on_row(), tab(false));
            assert_eq!(click(false, true, true, count).on_row(), tab(false));
        }
        // A name: a plain click (even double, which follows) opens nothing.
        assert_eq!(click(false, false, false, 1).on_name(), None);
        assert_eq!(click(false, false, false, 2).on_name(), None);
        assert_eq!(click(false, true, false, 1).on_name(), None);
        assert_eq!(click(true, false, false, 1).on_name(), Some(tab(true)));
        assert_eq!(click(false, false, true, 1).on_name(), Some(tab(true)));
        assert_eq!(click(true, true, false, 1).on_name(), Some(tab(false)));
    }

    #[test]
    fn tabs_keep_their_places_and_views_and_show_them_when_brought_back() {
        let pane = PaneId(0);
        let mut layout = Layout::new("listing");
        let mut places = Places::default();
        let first = layout.active_tab(pane).unwrap();
        let text = View::default();
        let graph = View {
            graph: true,
            ..View::default()
        };
        // The pane's first tab as laid out: nothing to show again.
        assert_eq!(places.show(pane, first, text), None);
        places.set(first, 0x1000);
        assert_eq!(places.show(pane, first, text), None, "the same tab");

        // Ctrl+click on a call, the first as text: a new tab of the
        // listing at its target (no view yet: the app gives it its
        // opener's).
        let called = layout.open_new(pane, "listing", true).unwrap();
        assert_ne!(called, first);
        assert_eq!(
            places.show(pane, called, text),
            Some(Shown {
                at: None,
                view: None
            })
        );
        places.set_view(called, text);
        places.set(called, 0x2000);
        // Navigating in it moves it, not the first.
        places.set(called, 0x2040);
        assert_eq!(places.at(first), Some(0x1000));

        // Space in it (the graph), then the first brought back: its own
        // place, as text.
        layout.activate(pane, 0);
        let shown = layout.active_tab(pane).unwrap();
        assert_eq!(shown, first);
        assert_eq!(
            places.show(pane, shown, graph),
            Some(Shown {
                at: Some(0x1000),
                view: Some(text)
            })
        );
        // And the second again: a graph, where it was left.
        assert_eq!(
            places.show(pane, called, text),
            Some(Shown {
                at: Some(0x2040),
                view: Some(graph)
            })
        );

        // Closed, its place is forgotten.
        layout.close_tab(pane, 1);
        places.retain(|t| layout.find_tab(t).is_some());
        assert_eq!(places.at(called), None);
        assert_eq!(places.view(called), None);
        assert_eq!(places.at(first), Some(0x1000));
        assert_eq!(
            places.show(pane, first, text),
            Some(Shown {
                at: Some(0x1000),
                view: Some(text)
            }),
            "the pane's shown tab closed: the first is shown anew"
        );
    }

    #[test]
    fn each_tab_keeps_its_own_view_when_switched() {
        // The owner's report: the graph on tab 1, tab 2 a listing when
        // left; tab 2 brought back is a listing, tab 1 a graph again.
        let pane = PaneId(0);
        let mut layout = Layout::new("listing");
        let mut places = Places::default();
        let one = layout.active_tab(pane).unwrap();
        let text = View::default();
        let graph = View {
            graph: true,
            ..View::default()
        };
        places.show(pane, one, text);
        // Tab 2 opened behind tab 1 (a listing then), never shown yet.
        let two = layout.open_new(pane, "listing", false).unwrap();
        places.set_view(two, text);
        // Space on tab 1, then tab 2.
        layout.activate(pane, 1);
        let shown = places.show(pane, two, graph).unwrap();
        assert_eq!(shown.view, Some(text), "tab 2 stays a listing");
        // Tab 1 again: its graph.
        layout.activate(pane, 0);
        let shown = places.show(pane, one, text).unwrap();
        assert_eq!(shown.view, Some(graph), "tab 1 is a graph again");
        // A tab first seen takes the view given; one with a view keeps it.
        let three = layout.open_new(pane, "listing", false).unwrap();
        places.adopt(three, graph);
        places.adopt(one, text);
        assert_eq!(places.view(three), Some(graph));
        assert_eq!(places.view(one), Some(graph));
        // The hex view is the tab's too, the graph under it kept.
        let hex = View {
            graph: true,
            hex: true,
            ..View::default()
        };
        places.show(pane, two, hex);
        assert_eq!(places.view(one), Some(hex));
        assert_eq!(places.view(two), Some(text));
    }

    /// Polls `session` until an event is the listing `wanted` takes; the
    /// session's reopening (the ids now by the ids before) if one came.
    fn listing_after(
        session: &mut Session,
        wanted: impl Fn(&Listing) -> bool,
    ) -> (Arc<Listing>, Option<Arc<HashMap<FunctionId, FunctionId>>>) {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut reopened = None;
        loop {
            for event in session.poll() {
                if let Event::Reopened(functions) = &event {
                    reopened = Some(Arc::clone(functions));
                }
                if let Event::Listing(listing) = event
                    && wanted(&listing)
                {
                    return (listing, reopened);
                }
            }
            assert!(Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_function_deleted_under_a_c_tab_leaves_it_at_its_address() {
        let dir =
            std::env::temp_dir().join(format!("binbun-gui-tabs-delete-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("program");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf"),
            &binary,
        )
        .unwrap();
        let mut session = Session::open_in(
            binary,
            Some(&dir),
            ListingOptions::default(),
            SymbolDownload::Never,
            Arc::new(|| {}),
        )
        .unwrap();
        let (listing, _) = listing_after(&mut session, |_| true);
        // A C tab in the function at 0x1190, its cursor on 0x1193.
        let place = Some(0x1193);
        let (shown, entry) = listing.function_of(0x1193).unwrap();
        assert_eq!(entry, 0x1190);
        assert_eq!(c_subject(Some(shown), place), CSubject::Function(shown));

        // Edit > Delete Function: analysed again, the function gone.
        let mut deleted = Corrections::default();
        deleted.set_bounds(0x1190, Some(Bounds::Deleted));
        session.correct(deleted).unwrap();
        let (listing, reopened) = listing_after(&mut session, |l| l.function_of(0x1193).is_none());
        let reopened = reopened.unwrap();
        let function = reopened.get(&shown).copied();
        assert_eq!(function, None);
        let function = retarget(function, place, &listing);
        // The tab stays at its address, which is code in no function now
        // (the listing still has its line), and says so.
        assert_eq!(c_subject(function, place), CSubject::Outside(0x1193));
        let line = listing.line(listing.line_of(0x1193)).unwrap();
        assert!(line.address <= 0x1193 && line.address >= 0x1190);

        // Undone: the function is back where the tab is, and it shows it.
        session.undo().unwrap();
        let (listing, _) = listing_after(&mut session, |l| l.function_of(0x1193).is_some());
        let (back, _) = listing.function_of(0x1193).unwrap();
        let function = retarget(function, place, &listing);
        assert_eq!(c_subject(function, place), CSubject::Function(back));
        // A tab showing a function keeps it, wherever its place is.
        assert_eq!(retarget(Some(back), Some(0x2004), &listing), Some(back));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
