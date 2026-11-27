//! The window's layout saved per project (its `layout.toml`,
//! [`binbun_gui_view::layout_file`]) and restored when the binary opens
//! again: the panes and their sizes, the tabs that can be restored, the
//! active and focused ones, the map's and the dock's widths, the console
//! open or not and its height, the hex side areas' shares under their
//! bytes. Saved when it changes (looked at every
//! half second), when the binary closes and when the app quits.
//! Each tab of code is restored at its place, in its view, a graph
//! following the tab it followed.

use std::collections::HashMap;

use binbun_gui_view::FunctionId;
use binbun_gui_view::graph_memory::{GraphMemory, Pan};
use binbun_gui_view::hex::SideSplit;
use binbun_gui_view::layout::{PaneId, Tab, TabId};
use binbun_gui_view::layout_file::{SavedLayout, SavedPlace, SavedSplit, SavedTab};
use binbun_gui_view::session::{Project, Session};
use binbun_gui_view::tabs::View;
use gpui_kit::Context;

use crate::sidebar::{MAX_WIDTH, MIN_WIDTH};
use crate::workspace::{TabKind, Workspace};

impl Workspace {
    /// The shown window tab's split as it is saved (its lists of results
    /// dropped).
    fn saved_split(&self) -> SavedSplit {
        let entry = |f: FunctionId| {
            self.functions
                .iter()
                .find(|(_, id)| *id == f)
                .map(|&(entry, _)| entry)
        };
        let layout = self.layout.map_tabs(|kind| match kind {
            TabKind::Listing => Some(SavedTab::Listing),
            TabKind::C { function, view } => Some(SavedTab::C {
                entry: match function {
                    Some(f) => Some(entry(*f)?),
                    None => None,
                },
                view: *view,
            }),
            TabKind::Strings => Some(SavedTab::Strings),
            TabKind::Xrefs { of, len } => Some(SavedTab::Xrefs { of: *of, len: *len }),
            TabKind::Folder(key) => Some(SavedTab::Folder(key.clone())),
            TabKind::Settings | TabKind::Struct(_) | TabKind::Found(_) => None,
        });
        let hex_sides = layout
            .panes()
            .filter_map(|p| {
                let split = self.panes.get(&p.id)?.hex.side_split;
                (split != SideSplit::default()).then_some((p.id, split.share()))
            })
            .collect();
        // Each tab's place (a linked pane's tab of code: the linked place,
        // shown or not), its view (the active tab's as its pane shows it).
        let mut places = HashMap::new();
        for pane in layout.panes() {
            let shown = self.pane_view(pane.id);
            for (index, tab) in pane.tabs.iter().enumerate() {
                let id = tab.id();
                let memory = self.places.graph_memory(id);
                let view = if index == pane.active {
                    Some(shown)
                } else {
                    self.places.view(id)
                };
                let code = matches!(tab.content, SavedTab::Listing | SavedTab::C { .. });
                let listing = matches!(tab.content, SavedTab::Listing);
                let at = if pane.synced && code {
                    self.shared.or_else(|| self.places.at(id))
                } else {
                    self.places.at(id)
                };
                // The unified listing's layers and folds: the pane's for
                // its shown tab, as kept for the others.
                let unified_view = if index == pane.active {
                    self.unified_view_of(pane.id)
                } else {
                    self.places.unified(id).cloned()
                };
                let place = SavedPlace {
                    at,
                    graph: listing && view.is_some_and(|v| v.graph),
                    zoom: memory.and_then(GraphMemory::zoom),
                    pan: memory.and_then(GraphMemory::latest).map(|pan| Pan {
                        followed: None,
                        ..*pan
                    }),
                    unified: listing && view.is_some_and(|v| v.unified),
                    unified_view: unified_view.filter(|_| listing).unwrap_or_default(),
                };
                if place != SavedPlace::default() {
                    places.insert(id, place);
                }
            }
        }
        SavedSplit {
            layout,
            hex_sides,
            places,
        }
    }

    /// The layout as it is saved: every window tab of a place (the
    /// settings and structs are not saved), the shown one at the top.
    fn saved_layout(&mut self) -> SavedLayout {
        let (mut splits, shown) = self.each_place_tab(Self::saved_split);
        let main = if shown < splits.len() {
            splits.remove(shown)
        } else {
            self.saved_split()
        };
        SavedLayout {
            layout: main.layout,
            sidebar_width: self.sidebar_width,
            dock_width: self.layout_ui.dock_width,
            console: self.console.open,
            console_height: self.console.height,
            hex_sides: main.hex_sides,
            places: main.places,
            shown: shown.min(splits.len()),
            others: splits,
        }
    }

    /// Saves the layout beside the project if it changed since it was
    /// last saved or restored. Nothing before the binary's layout was
    /// restored (the default would overwrite it); a failure is said once
    /// per binary.
    pub fn save_layout(&mut self) {
        let file = self
            .session
            .as_ref()
            .and_then(Session::project)
            .map(Project::layout);
        let Some(file) = file.filter(|_| self.layout_ui.saved.is_some()) else {
            return;
        };
        let saved = self.saved_layout();
        let text = saved.to_toml();
        if self.layout_ui.saved.as_ref() == Some(&text) {
            return;
        }
        if let Err(error) = saved.save(&file) {
            if !self.layout_ui.save_failed {
                self.error = Some(error);
            }
            self.layout_ui.save_failed = true;
        }
        self.layout_ui.saved = Some(text);
    }

    /// Restores the layout saved for the binary just opened, once its
    /// functions are known: a C tab whose function is gone is skipped (its
    /// pane closed if it is left empty); with nothing left, the layout
    /// stays as it is. The other window tabs of places come back around
    /// the shown one, each at its place (one with nothing left is not).
    /// From then on the layout is saved as it changes.
    pub fn restore_layout(&mut self, cx: &mut Context<Self>) {
        let Some(file) = self
            .session
            .as_ref()
            .and_then(Session::project)
            .map(Project::layout)
        else {
            return;
        };
        let saved = SavedLayout::load(&file).unwrap_or_else(|error| {
            self.error = Some(error);
            None
        });
        if let Some(saved) = saved {
            let main = SavedSplit {
                layout: saved.layout,
                hex_sides: saved.hex_sides,
                places: saved.places,
            };
            if self.apply_split(main, cx) {
                self.layout_ui.refocus = true;
            }
            for (k, other) in saved.others.into_iter().enumerate() {
                let position = if k < saved.shown { k } else { k + 1 };
                self.add_place_tab_at(position, cx, |this, cx| {
                    let filled = this.apply_split(other, cx);
                    if filled {
                        this.settle_restored();
                    }
                    filled
                });
            }
            self.sidebar_width = saved.sidebar_width.clamp(MIN_WIDTH, MAX_WIDTH);
            self.layout_ui.dock_width = saved.dock_width.map(|w| w.clamp(MIN_WIDTH, MAX_WIDTH));
            self.console.open = saved.console;
            self.console.height = saved.console_height;
        }
        self.layout_ui.saved = Some(self.saved_layout().to_toml());
        self.layout_ui.save_failed = false;
    }

    /// Shows `split` as the shown window tab's panes, its tabs that can no
    /// longer be restored (a function gone) dropped; whether any is left
    /// (else the tab stays as it was).
    fn apply_split(&mut self, split: SavedSplit, cx: &mut Context<Self>) -> bool {
        let functions = &self.functions;
        let function = |entry: u64| {
            let i = functions.binary_search_by_key(&entry, |&(e, _)| e).ok()?;
            functions.get(i).map(|&(_, id)| id)
        };
        let layout = split.layout.map_tabs(|tab| match tab {
            SavedTab::Listing => Some(TabKind::Listing),
            SavedTab::C { entry, view } => Some(TabKind::C {
                function: match entry {
                    Some(entry) => Some(function(*entry)?),
                    None => None,
                },
                view: *view,
            }),
            SavedTab::Strings => Some(TabKind::Strings),
            SavedTab::Xrefs { of, len } => Some(TabKind::Xrefs { of: *of, len: *len }),
            SavedTab::Folder(key) => Some(TabKind::Folder(key.clone())),
        });
        if !layout.panes().any(|p| !p.tabs.is_empty()) {
            return false;
        }
        self.layout = layout;
        // Its tabs are numbered afresh (as saved: their places are by
        // those numbers); a tab without a place saved (a file written
        // before) is a listing.
        self.places.clear();
        let tabs: Vec<TabId> = self
            .layout
            .panes()
            .flat_map(|p| p.tabs.iter().map(Tab::id))
            .collect();
        for tab in tabs {
            let place = split.places.get(&tab).cloned().unwrap_or_default();
            let view = View {
                graph: place.graph,
                unified: place.unified,
                ..View::default()
            };
            self.places.restore(tab, place.at, view);
            self.places.keep_unified(tab, place.unified_view);
            if place.zoom.is_some() || place.pan.is_some() {
                *self.places.graph_memory_mut(tab) = GraphMemory::saved(place.zoom, place.pan);
            }
        }
        self.maximized = None;
        let live: Vec<PaneId> = self.layout.panes().map(|p| p.id).collect();
        self.panes.retain(|id, _| live.contains(id));
        for id in live {
            self.ensure_pane(id, cx);
            // The active tab in the view it was left in.
            if let Some(tab) = self.layout.active_tab(id)
                && let Some(view) = self.places.view(tab)
            {
                self.show_view(id, tab, view);
            }
        }
        for (id, share) in split.hex_sides {
            if let Some(state) = self.panes.get_mut(&id) {
                state.hex.side_split = SideSplit::new(share);
            }
        }
        true
    }
}
