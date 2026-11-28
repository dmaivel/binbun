//! Editor-style panes: a tree of splits whose leaves are panes, each pane a
//! row of tabs with at most one preview tab.
//!
//! A pane splits right (`Axis::Row`) or down (`Axis::Column`); splits share
//! their space by their children's sizes (fractions summing to one: a new
//! pane takes half of the one split, a closed pane's space goes to its
//! neighbours, a divider dragged moves the two children beside it, each
//! kept at least a minimum long) and never directly hold a split of their
//! own axis, so splitting a pane next to same-axis siblings adds one more
//! sibling.
//! The focus moves between panes by direction over their rectangles in the
//! unit square, or in tree order. Pane ids are never reused, and a pane may
//! leave the sync group (`Pane::synced`).
//!
//! Tabs are things: each has an identity
//! ([`TabId`], never reused) the GUI keeps its place by. Besides
//! [`Layout::open`] (a tab holding equal content is brought back), a
//! navigation opens its target in the pane's preview tab
//! ([`Layout::open_preview`]) or in a new tab ([`Layout::open_new`]),
//! equal content or not: two tabs of the listing are two places.
//!
//! The dock is a pane along the layout's bottom, spanning it (the root
//! column's last child): what opens below the code opens there. It hides
//! without closing (its pane kept aside, its tabs with it), cannot be
//! split, takes a tab dropped on its edges into itself, and goes when its
//! last tab does. The panes of the code area always keep one. A window's
//! dock moves between its tabs' layouts ([`Layout::take_dock`],
//! [`Layout::put_dock`]).

/// The dock's share of the layout's height when it first shows.
pub const DOCK_SIZE: f32 = 0.35;

/// A pane's identity, unique for the layout's lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PaneId(pub u32);

/// A tab's identity, unique for the layout's lifetime (a layout from
/// its parts numbers its tabs afresh).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TabId(pub u64);

/// Where a moved tab goes ([`Layout::move_tab`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabDrop {
    /// Into pane `pane`'s bar before its tab `at` (at the end past them).
    Into {
        /// The pane.
        pane: PaneId,
        /// The position, among the tabs there as they were.
        at: usize,
    },
    /// Into a new pane on `side` of pane `pane`, taking half of it.
    Edge {
        /// The pane split.
        pane: PaneId,
        /// The side the new pane is on.
        side: Direction,
    },
}

/// Where a tab dropped on a pane's body at `(x, y)` (fractions of its
/// width and height) goes: a new pane on the side whose outer quarter it
/// is in (the nearest edge's), else (`None`) into the pane.
pub fn drop_side(x: f32, y: f32) -> Option<Direction> {
    [
        (x, Direction::Left),
        (1.0 - x, Direction::Right),
        (y, Direction::Up),
        (1.0 - y, Direction::Down),
    ]
    .into_iter()
    .min_by(|a, b| a.0.total_cmp(&b.0))
    .filter(|&(distance, _)| distance < 0.25)
    .map(|(_, side)| side)
}

/// How a split lays out its children.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Axis {
    /// Side by side, left to right.
    Row,
    /// Stacked, top to bottom.
    Column,
}

/// A direction to move the focus in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Towards smaller `x`.
    Left,
    /// Towards larger `x`.
    Right,
    /// Towards smaller `y`.
    Up,
    /// Towards larger `y`.
    Down,
}

/// One tab of a pane.
#[derive(Clone, Debug, PartialEq)]
pub struct Tab<T> {
    /// What the tab shows.
    pub content: T,
    /// Whether this is the pane's preview tab, replaced by the next preview
    /// open instead of kept.
    pub preview: bool,
    /// Its identity, given by the layout it is in.
    id: TabId,
}

impl<T> Tab<T> {
    /// A tab of `content` to give a layout ([`Layout::from_parts`]), which
    /// gives it its identity.
    pub fn new(content: T, preview: bool) -> Self {
        Self {
            content,
            preview,
            id: TabId(0),
        }
    }

    /// Its identity.
    pub fn id(&self) -> TabId {
        self.id
    }
}

/// A leaf of the layout: tabs, the active one, and sync membership.
///
/// A pane is empty only if it is the layout's last pane.
#[derive(Clone, Debug)]
pub struct Pane<T> {
    /// The pane's id.
    pub id: PaneId,
    /// The tabs, left to right.
    pub tabs: Vec<Tab<T>>,
    /// The index of the active tab in `tabs`.
    pub active: usize,
    /// Whether the pane follows the sync group's navigation.
    pub synced: bool,
}

/// A node of the layout tree.
///
/// A split has at least two children, none of them a split of the same
/// axis, and a size for each: its share of the split's length, all of them
/// positive and summing to one.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    /// A pane.
    Pane(PaneId),
    /// Children laid out along `axis`.
    Split {
        /// How the children are laid out.
        axis: Axis,
        /// The children, left to right or top to bottom.
        children: Vec<Node>,
        /// Each child's share of the split's length, in order.
        sizes: Vec<f32>,
    },
}

impl Node {
    /// A split of `children` along `axis` in equal shares.
    pub fn even(axis: Axis, children: Vec<Node>) -> Self {
        let sizes = even_sizes(children.len());
        Self::Split {
            axis,
            children,
            sizes,
        }
    }
}

/// A rectangle in the unit square, `y` growing downwards.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rect {
    /// The left edge.
    pub x: f32,
    /// The top edge.
    pub y: f32,
    /// The width.
    pub w: f32,
    /// The height.
    pub h: f32,
}

/// Panes in a tree of splits, with one focused pane.
#[derive(Clone, Debug)]
pub struct Layout<T> {
    /// The split tree; its leaves are exactly the ids in `panes` (the
    /// dock's among them while it is shown, the root column's last).
    tree: Node,
    /// The panes, in tree order.
    panes: Vec<Pane<T>>,
    /// The focused pane, always one of `panes`.
    focused: PaneId,
    /// The id the next new pane gets.
    next_id: u32,
    /// The id the next new tab gets.
    next_tab: u64,
    /// The dock, if there is one.
    dock: Option<Dock<T>>,
}

/// A layout's dock: its pane's id, the pane itself while hidden, its
/// share of the height.
#[derive(Clone, Debug)]
struct Dock<T> {
    /// Its pane's id.
    id: PaneId,
    /// Its pane while hidden (out of the tree, its tabs kept); `None`
    /// while it is shown.
    hidden: Option<Pane<T>>,
    /// Its share of the layout's height, as last shown.
    size: f32,
}

/// A dock taken out of a layout ([`Layout::take_dock`]): to put into
/// another of the window's ([`Layout::put_dock`]), or saved.
#[derive(Clone, Debug)]
pub struct DockParts<T> {
    /// Its pane: its id, tabs and active one.
    pub pane: Pane<T>,
    /// Whether it is shown.
    pub shown: bool,
    /// Its share of the layout's height.
    pub size: f32,
}

impl<T: Clone + PartialEq + std::fmt::Debug> Layout<T> {
    /// One pane, `PaneId(0)`, holding `content` as a pinned tab, synced and
    /// focused.
    pub fn new(content: T) -> Self {
        Self {
            tree: Node::Pane(PaneId(0)),
            panes: vec![Pane {
                id: PaneId(0),
                tabs: vec![Tab {
                    content,
                    preview: false,
                    id: TabId(0),
                }],
                active: 0,
                synced: true,
            }],
            focused: PaneId(0),
            next_id: 1,
            next_tab: 1,
            dock: None,
        }
    }

    /// A new tab's identity.
    fn fresh_tab(&mut self) -> TabId {
        let id = TabId(self.next_tab);
        self.next_tab += 1;
        id
    }

    /// The split tree.
    pub fn tree(&self) -> &Node {
        &self.tree
    }

    /// The focused pane.
    pub fn focused(&self) -> PaneId {
        self.focused
    }

    /// Focuses pane `id`; false if there is no such pane.
    pub fn focus(&mut self, id: PaneId) -> bool {
        let exists = self.shows(id);
        if exists {
            self.focused = id;
        }
        exists
    }

    /// Whether pane `id` is on screen (in the tree; not a hidden dock).
    pub fn shows(&self, id: PaneId) -> bool {
        self.panes.iter().any(|pane| pane.id == id)
    }

    /// Pane `id`, if it exists (the dock's while hidden too).
    pub fn pane(&self, id: PaneId) -> Option<&Pane<T>> {
        self.every_pane().find(|pane| pane.id == id)
    }

    /// Pane `id`, mutably, if it exists.
    pub fn pane_mut(&mut self, id: PaneId) -> Option<&mut Pane<T>> {
        let hidden = self.dock.as_mut().and_then(|dock| dock.hidden.as_mut());
        self.panes
            .iter_mut()
            .chain(hidden)
            .find(|pane| pane.id == id)
    }

    /// The panes on screen in tree order: left to right, top to bottom
    /// (the dock, while shown, last).
    pub fn panes(&self) -> impl Iterator<Item = &Pane<T>> {
        self.panes.iter()
    }

    /// The panes on screen, then the dock's while hidden: every pane whose
    /// tabs the layout holds.
    pub fn every_pane(&self) -> impl Iterator<Item = &Pane<T>> {
        let hidden = self.dock.as_ref().and_then(|dock| dock.hidden.as_ref());
        self.panes.iter().chain(hidden)
    }

    /// The panes of the code area: those on screen but the dock.
    pub fn code_panes(&self) -> impl Iterator<Item = &Pane<T>> {
        let dock = self.dock();
        self.panes.iter().filter(move |pane| Some(pane.id) != dock)
    }

    /// The dock's pane, shown or hidden.
    pub fn dock(&self) -> Option<PaneId> {
        self.dock.as_ref().map(|dock| dock.id)
    }

    /// Whether pane `id` is the dock's.
    pub fn is_dock(&self, id: PaneId) -> bool {
        self.dock() == Some(id)
    }

    /// Whether the dock is shown.
    pub fn dock_shown(&self) -> bool {
        self.dock.as_ref().is_some_and(|dock| dock.hidden.is_none())
    }

    /// The number of panes, at least one.
    pub fn len(&self) -> usize {
        self.panes.len()
    }

    /// Never true: a layout always has a pane.
    pub fn is_empty(&self) -> bool {
        self.panes.is_empty()
    }

    /// The content of pane `id`'s active tab.
    pub fn active(&self, id: PaneId) -> Option<&T> {
        let pane = self.pane(id)?;
        pane.tabs.get(pane.active).map(|tab| &tab.content)
    }

    /// The content of pane `id`'s active tab, mutably.
    pub fn active_mut(&mut self, id: PaneId) -> Option<&mut T> {
        let pane = self.pane_mut(id)?;
        pane.tabs.get_mut(pane.active).map(|tab| &mut tab.content)
    }

    /// The identity of pane `id`'s active tab.
    pub fn active_tab(&self, id: PaneId) -> Option<TabId> {
        let pane = self.pane(id)?;
        pane.tabs.get(pane.active).map(Tab::id)
    }

    /// Where tab `tab` is: its pane and index.
    pub fn find_tab(&self, tab: TabId) -> Option<(PaneId, usize)> {
        self.every_pane().find_map(|pane| {
            let index = pane.tabs.iter().position(|t| t.id == tab)?;
            Some((pane.id, index))
        })
    }

    /// Whether tab `tab` is the active tab of its pane.
    pub fn is_active(&self, tab: TabId) -> bool {
        self.find_tab(tab)
            .is_some_and(|(id, index)| self.pane(id).is_some_and(|p| p.active == index))
    }

    /// Splits `id`: a new pane after it on `axis` (`Row` = right, `Column` =
    /// down) holding `content` as a pinned tab, synced as `id` is; focuses
    /// it; returns its id (ids never reused). Splitting a pane whose parent
    /// split has the same axis adds a sibling right after it. `None` if
    /// there is no pane `id` or the ids are exhausted.
    pub fn split(&mut self, id: PaneId, axis: Axis, content: T) -> Option<PaneId> {
        let tab = Tab {
            content,
            preview: false,
            id: self.fresh_tab(),
        };
        self.split_beside(id, axis, false, tab)
    }

    /// A new pane beside `id` on `axis` (before it if `before`) holding
    /// `tab`, synced as `id` is, focused; its id. The dock does not split.
    fn split_beside(
        &mut self,
        id: PaneId,
        axis: Axis,
        before: bool,
        tab: Tab<T>,
    ) -> Option<PaneId> {
        if self.is_dock(id) {
            return None;
        }
        let index = self.panes.iter().position(|pane| pane.id == id)?;
        let synced = self.panes.get(index)?.synced;
        let new = PaneId(self.next_id);
        self.next_id = self.next_id.checked_add(1)?;
        insert_beside(&mut self.tree, id, axis, new, before);
        // The new leaf directly follows (or precedes) `id`'s in tree order.
        self.panes.insert(
            if before { index } else { index + 1 },
            Pane {
                id: new,
                tabs: vec![tab],
                active: 0,
                synced,
            },
        );
        self.focused = new;
        Some(new)
    }

    /// Moves tab `tab` (dragged, or by a key) where `to` says: into a pane
    /// at a position (along its own bar: reordered), or into a new pane on
    /// a side of one. It keeps its identity (its place, what follows it),
    /// is pinned (a preview dragged is kept), and is active and focused
    /// where it lands; the pane it left, if emptied, closes. `None` (and
    /// nothing done) if there is no such tab or pane, or it is the only
    /// tab of a pane dropped on that pane's own edge, or the only tab of
    /// the code area's last pane leaving it. A tab dropped on the dock's
    /// edge goes into the dock.
    pub fn move_tab(&mut self, tab: TabId, to: TabDrop) -> Option<PaneId> {
        let to = match to {
            TabDrop::Edge { pane, .. } if self.is_dock(pane) => TabDrop::Into {
                pane,
                at: usize::MAX,
            },
            other @ (TabDrop::Into { .. } | TabDrop::Edge { .. }) => other,
        };
        let (from, index) = self.find_tab(tab)?;
        let target = match to {
            TabDrop::Into { pane, .. } | TabDrop::Edge { pane, .. } => pane,
        };
        let alone = self.pane(from)?.tabs.len() == 1;
        let last_code =
            alone && target != from && !self.is_dock(from) && self.code_panes().count() <= 1;
        if !self.shows(target)
            || !self.shows(from)
            || (alone && target == from && matches!(to, TabDrop::Edge { .. }))
            || last_code
        {
            return None;
        }
        let pane = self.pane_mut(from)?;
        let mut moved = pane.tabs.remove(index);
        moved.preview = false;
        // As a tab closed: the one on its left active, if it was.
        if index <= pane.active {
            pane.active = pane.active.saturating_sub(1);
        }
        pane.active = pane.active.min(pane.tabs.len().saturating_sub(1));
        let emptied = pane.tabs.is_empty();
        let landed = match to {
            TabDrop::Into { pane: id, at } => {
                // A position along its own bar counts the tab still there.
                let at = if id == from && at > index { at - 1 } else { at };
                let pane = self.pane_mut(id)?;
                let at = at.min(pane.tabs.len());
                pane.tabs.insert(at, moved);
                pane.active = at;
                self.focused = id;
                id
            }
            TabDrop::Edge { pane: id, side } => {
                let (axis, before) = match side {
                    Direction::Left => (Axis::Row, true),
                    Direction::Right => (Axis::Row, false),
                    Direction::Up => (Axis::Column, true),
                    Direction::Down => (Axis::Column, false),
                };
                self.split_beside(id, axis, before, moved)?
            }
        };
        if emptied && from != landed {
            self.close_pane(from);
            self.focused = landed;
        }
        Some(landed)
    }

    /// Closes pane `id` unless it is the code area's last; a split left
    /// with one child is replaced by it (and flattened into its parent if
    /// same axis); the focus, if it was there, moves to the pane that took
    /// its place: the last pane of the previous sibling, else the first
    /// pane of the next. The dock keeps its height; the dock closed goes
    /// with its tabs. Returns whether it closed.
    pub fn close_pane(&mut self, id: PaneId) -> bool {
        if self.is_dock(id) {
            self.detach_dock();
            self.dock = None;
            return true;
        }
        if self.code_panes().count() <= 1 {
            return false;
        }
        self.without_dock(|layout| layout.close_code_pane(id))
    }

    /// Closes pane `id` of the code area (the dock out of the tree).
    fn close_code_pane(&mut self, id: PaneId) -> bool {
        let Some(index) = self.panes.iter().position(|pane| pane.id == id) else {
            return false;
        };
        let successor = remove_leaf(&mut self.tree, id);
        normalize(&mut self.tree);
        self.panes.remove(index);
        if self.focused == id
            && let Some(next) = successor.or_else(|| self.panes.first().map(|pane| pane.id))
        {
            self.focused = next;
        }
        true
    }

    /// Opens `content` in pane `id` (an editor's preview tabs): a tab
    /// already holding equal content is activated (and pinned if
    /// `!preview`); else with `preview` the pane's preview tab (if any) is
    /// replaced in place, or a new preview tab is added after the active
    /// tab; else a pinned tab is added after the active tab. The opened tab
    /// becomes active. At most one preview tab per pane.
    pub fn open(&mut self, id: PaneId, content: T, preview: bool) {
        let Some(pane) = self.pane_mut(id) else {
            return;
        };
        if let Some(index) = pane.tabs.iter().position(|tab| tab.content == content) {
            if !preview && let Some(tab) = pane.tabs.get_mut(index) {
                tab.preview = false;
            }
            pane.active = index;
            return;
        }
        if preview && let Some(index) = pane.tabs.iter().position(|tab| tab.preview) {
            if let Some(tab) = pane.tabs.get_mut(index) {
                tab.content = content;
            }
            pane.active = index;
            return;
        }
        let index = (pane.active + 1).min(pane.tabs.len());
        let tab = self.fresh_tab();
        let Some(pane) = self.pane_mut(id) else {
            return;
        };
        pane.tabs.insert(
            index,
            Tab {
                content,
                preview,
                id: tab,
            },
        );
        pane.active = index;
    }

    /// A navigation's target in pane `id`'s preview tab (a single click):
    /// the preview tab, if there is one, takes `content` in place
    /// (keeping its identity: its place moves), else a new preview tab is
    /// added after the active tab; either way it becomes active. Unlike
    /// [`Self::open`], a tab of equal content is not brought back.
    pub fn open_preview(&mut self, id: PaneId, content: T) -> Option<TabId> {
        let pane = self.pane_mut(id)?;
        if let Some(index) = pane.tabs.iter().position(|tab| tab.preview) {
            let tab = pane.tabs.get_mut(index)?;
            tab.content = content;
            let tab = tab.id;
            pane.active = index;
            return Some(tab);
        }
        let index = (pane.active + 1).min(pane.tabs.len());
        let tab = self.fresh_tab();
        let pane = self.pane_mut(id)?;
        pane.tabs.insert(
            index,
            Tab {
                content,
                preview: true,
                id: tab,
            },
        );
        pane.active = index;
        Some(tab)
    }

    /// A navigation's target in a new pinned tab of pane `id` (Ctrl+click,
    /// a middle click), after the active tab: activated if `activate`, else
    /// opened in the background (the active tab stays).
    pub fn open_new(&mut self, id: PaneId, content: T, activate: bool) -> Option<TabId> {
        let index = {
            let pane = self.pane(id)?;
            (pane.active + 1).min(pane.tabs.len())
        };
        let tab = self.fresh_tab();
        let pane = self.pane_mut(id)?;
        pane.tabs.insert(
            index,
            Tab {
                content,
                preview: false,
                id: tab,
            },
        );
        if activate {
            pane.active = index;
        }
        Some(tab)
    }

    /// Pins tab `index` of `id` (a double-click, an edit).
    pub fn pin(&mut self, id: PaneId, index: usize) {
        if let Some(tab) = self.pane_mut(id).and_then(|pane| pane.tabs.get_mut(index)) {
            tab.preview = false;
        }
    }

    /// Activates tab `index` of `id`, if it exists.
    pub fn activate(&mut self, id: PaneId, index: usize) {
        if let Some(pane) = self.pane_mut(id)
            && index < pane.tabs.len()
        {
            pane.active = index;
        }
    }

    /// Next/previous tab of `id`, wrapping.
    pub fn cycle(&mut self, id: PaneId, forward: bool) {
        let Some(pane) = self.pane_mut(id) else {
            return;
        };
        let len = pane.tabs.len();
        if len == 0 {
            return;
        }
        let active = pane.active % len;
        pane.active = if forward {
            (active + 1) % len
        } else {
            (active + len - 1) % len
        };
    }

    /// Closes tab `index` of `id`. If it was active, the tab to its left
    /// becomes active (else the new first); otherwise the active tab stays
    /// active. A pane left empty is closed unless it is the code area's
    /// last (the dock's, shown or hidden, goes). Returns whether a tab
    /// closed.
    pub fn close_tab(&mut self, id: PaneId, index: usize) -> bool {
        let Some(pane) = self.pane_mut(id) else {
            return false;
        };
        if index >= pane.tabs.len() {
            return false;
        }
        pane.tabs.remove(index);
        if index <= pane.active {
            pane.active = pane.active.saturating_sub(1);
        }
        pane.active = pane.active.min(pane.tabs.len().saturating_sub(1));
        if pane.tabs.is_empty() {
            self.close_pane(id);
        }
        true
    }

    /// Each pane's rectangle in the unit square (each split's children by
    /// their sizes), in tree order.
    pub fn rects(&self) -> Vec<(PaneId, Rect)> {
        let mut out = Vec::with_capacity(self.panes.len());
        place(
            &self.tree,
            Rect {
                x: 0.0,
                y: 0.0,
                w: 1.0,
                h: 1.0,
            },
            &mut out,
        );
        out
    }

    /// Moves the focus to the nearest pane in `direction` from the focused
    /// one: among panes entirely beyond its edge on that side and
    /// overlapping it on the other axis, the closest edge; ties by most
    /// overlap, then by smallest distance between centres, then the first
    /// in tree order. Returns whether it moved.
    pub fn move_focus(&mut self, direction: Direction) -> bool {
        let rects = self.rects();
        let Some(from) = rects
            .iter()
            .find(|(id, _)| *id == self.focused)
            .map(|(_, rect)| *rect)
        else {
            return false;
        };
        let mut best: Option<(PaneId, Candidate)> = None;
        for (id, rect) in &rects {
            if *id == self.focused {
                continue;
            }
            let Some(candidate) = Candidate::measure(from, *rect, direction) else {
                continue;
            };
            if best
                .as_ref()
                .is_none_or(|(_, current)| candidate.beats(current))
            {
                best = Some((*id, candidate));
            }
        }
        match best {
            Some((id, _)) => {
                self.focused = id;
                true
            }
            None => false,
        }
    }

    /// The next pane in tree order after the focused one, wrapping;
    /// focuses it.
    pub fn focus_next(&mut self) -> PaneId {
        let next = self
            .panes
            .iter()
            .position(|pane| pane.id == self.focused)
            .map_or(0, |index| index + 1);
        if let Some(pane) = self.panes.get(next).or_else(|| self.panes.first()) {
            self.focused = pane.id;
        }
        self.focused
    }

    /// The axis and sizes of the split at `path` (child indices from the
    /// root), if there is one there.
    pub fn split_at(&self, path: &[usize]) -> Option<(Axis, &[f32])> {
        let mut node = &self.tree;
        for &index in path {
            match node {
                Node::Split { children, .. } => node = children.get(index)?,
                Node::Pane(_) => return None,
            }
        }
        match node {
            Node::Split { axis, sizes, .. } => Some((*axis, sizes)),
            Node::Pane(_) => None,
        }
    }

    /// Drags the divider before child `index` of the split at `path` to
    /// `at`, measured from the split's start in a split `length` long (in
    /// the unit of `min`, logical pixels): only the two children beside it
    /// change, each kept at least `min` long; nothing changes if they
    /// cannot both be. Returns whether the sizes changed.
    pub fn drag_divider(
        &mut self,
        path: &[usize],
        index: usize,
        at: f32,
        length: f32,
        min: f32,
    ) -> bool {
        let Some(Node::Split { sizes, .. }) = node_at_mut(&mut self.tree, path) else {
            return false;
        };
        let Some(before) = index.checked_sub(1) else {
            return false;
        };
        if length <= 0.0 || !at.is_finite() {
            return false;
        }
        let start: f32 = sizes.iter().take(before).sum();
        let (Some(&first), Some(&second)) = (sizes.get(before), sizes.get(index)) else {
            return false;
        };
        let pair = first + second;
        let min = min.max(0.0) / length;
        if pair < 2.0 * min {
            return false;
        }
        let moved = (at / length - start).clamp(min, pair - min);
        if (moved - first).abs() <= f32::EPSILON {
            return false;
        }
        if let Some(size) = sizes.get_mut(before) {
            *size = moved;
        }
        if let Some(size) = sizes.get_mut(index) {
            *size = pair - moved;
        }
        true
    }

    /// Gives the children of the split at `path` equal sizes (a divider's
    /// double-click). Returns whether there is a split there.
    pub fn even(&mut self, path: &[usize]) -> bool {
        match node_at_mut(&mut self.tree, path) {
            Some(Node::Split { sizes, .. }) => {
                *sizes = even_sizes(sizes.len());
                true
            }
            Some(Node::Pane(_)) | None => false,
        }
    }

    /// The same layout with each tab's content mapped by `f` (what can be
    /// saved; what can be restored): a tab mapped to `None` is dropped, an
    /// active one dropped leaves the tab on its left active (else the
    /// first), and a pane left without tabs closes unless it is the code
    /// area's last (the dock, shown or hidden, goes).
    pub fn map_tabs<U: Clone + PartialEq + std::fmt::Debug>(
        &self,
        mut f: impl FnMut(&T) -> Option<U>,
    ) -> Layout<U> {
        let panes = self
            .panes
            .iter()
            .map(|pane| mapped_pane(pane, &mut f))
            .collect();
        let dock = self.dock.as_ref().map(|dock| Dock {
            id: dock.id,
            hidden: dock.hidden.as_ref().map(|pane| mapped_pane(pane, &mut f)),
            size: dock.size,
        });
        let mut mapped = Layout {
            tree: self.tree.clone(),
            panes,
            focused: self.focused,
            next_id: self.next_id,
            next_tab: self.next_tab,
            dock,
        };
        mapped.close_empty();
        mapped
    }

    /// A layout from its parts, as saved: `tree`'s leaves must be exactly
    /// `panes`' ids, each once. Splits are normalized (sizes that are not
    /// positive or not one per child are made equal, the rest scaled to sum
    /// to one), active tabs clamped, a focus that is not a pane moved to the
    /// first, panes without tabs closed unless one is left; its tabs get
    /// their identities. `None` if the leaves do not match.
    pub fn from_parts(mut tree: Node, mut panes: Vec<Pane<T>>, focused: PaneId) -> Option<Self> {
        let mut leaves = Vec::with_capacity(panes.len());
        collect_leaves(&tree, &mut leaves);
        let mut sorted = leaves.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if leaves.is_empty() || sorted.len() != leaves.len() || panes.len() != leaves.len() {
            return None;
        }
        let mut ordered = Vec::with_capacity(panes.len());
        let mut next_tab = 0;
        for id in &leaves {
            let index = panes.iter().position(|pane| pane.id == *id)?;
            let mut pane = panes.swap_remove(index);
            pane.active = pane.active.min(pane.tabs.len().saturating_sub(1));
            for tab in &mut pane.tabs {
                tab.id = TabId(next_tab);
                next_tab += 1;
            }
            ordered.push(pane);
        }
        normalize(&mut tree);
        let next_id = leaves.iter().map(|id| id.0).max()?.checked_add(1)?;
        let focused = if leaves.contains(&focused) {
            focused
        } else {
            *leaves.first()?
        };
        let mut layout = Self {
            tree,
            panes: ordered,
            focused,
            next_id,
            next_tab,
            dock: None,
        };
        layout.close_empty();
        Some(layout)
    }

    /// A copy keeping only the tabs `keep` takes (a pane left without one
    /// closed, unless it is the last), every pane synced and numbered
    /// afresh from `first`, its sizes kept; each pane's id beside its
    /// copy's; the dock left out (a window has one). `None` if the ids run
    /// out.
    pub fn copied(
        &self,
        first: u32,
        keep: impl Fn(&T) -> bool,
    ) -> Option<(Self, Vec<(PaneId, PaneId)>)> {
        if self.dock.is_some() {
            let mut code = self.clone();
            code.take_dock();
            return code.copied(first, keep);
        }
        let mut ids = Vec::with_capacity(self.panes.len());
        let mut next = first;
        for pane in &self.panes {
            ids.push((pane.id, PaneId(next)));
            next = next.checked_add(1)?;
        }
        let new_of = |id: PaneId| {
            ids.iter()
                .find(|(old, _)| *old == id)
                .map_or(id, |&(_, new)| new)
        };
        let panes = self
            .panes
            .iter()
            .map(|pane| {
                let shown = pane.tabs.get(pane.active).map(Tab::id);
                let tabs: Vec<Tab<T>> = pane
                    .tabs
                    .iter()
                    .filter(|tab| keep(&tab.content))
                    .cloned()
                    .collect();
                Pane {
                    id: new_of(pane.id),
                    active: tabs.iter().position(|t| Some(t.id) == shown).unwrap_or(0),
                    tabs,
                    synced: true,
                }
            })
            .collect();
        let tree = renumbered(&self.tree, &new_of);
        let copy = Self::from_parts(tree, panes, new_of(self.focused))?;
        Some((copy, ids))
    }

    /// The id the next new pane gets.
    pub fn next_pane(&self) -> u32 {
        self.next_id
    }

    /// Opens `content` in the dock as [`Self::open`] does: the dock made
    /// along the bottom if there is none, shown if hidden. The dock's
    /// pane; `None` if the ids run out.
    pub fn open_in_dock(&mut self, content: T, preview: bool) -> Option<PaneId> {
        let id = if let Some(id) = self.dock() {
            id
        } else {
            let id = PaneId(self.next_id);
            self.next_id = self.next_id.checked_add(1)?;
            self.dock = Some(Dock {
                id,
                hidden: Some(Pane {
                    id,
                    tabs: Vec::new(),
                    active: 0,
                    synced: false,
                }),
                size: DOCK_SIZE,
            });
            id
        };
        self.show_dock();
        self.open(id, content, preview);
        Some(id)
    }

    /// Shows the dock, if hidden, along the bottom at its share (the code
    /// area's panes scaled to the rest). Returns whether a dock is shown.
    pub fn show_dock(&mut self) -> bool {
        let Some(dock) = self.dock.as_mut() else {
            return false;
        };
        let Some(pane) = dock.hidden.take() else {
            return true;
        };
        let size = dock.size.clamp(0.05, 0.95);
        let id = pane.id;
        self.panes.push(pane);
        let code = std::mem::replace(&mut self.tree, Node::Pane(id));
        self.tree = Node::Split {
            axis: Axis::Column,
            children: vec![code, Node::Pane(id)],
            sizes: vec![1.0 - size, size],
        };
        normalize(&mut self.tree);
        true
    }

    /// Hides the dock: its pane leaves the tree, kept with its tabs, its
    /// share remembered; the focus, if on it, goes to the pane above.
    /// Returns whether it was shown.
    pub fn hide_dock(&mut self) -> bool {
        let Some((pane, size)) = self.detach_dock() else {
            return false;
        };
        if let Some(dock) = &mut self.dock {
            dock.hidden = Some(pane);
            dock.size = size;
        }
        true
    }

    /// The dock taken out, shown or hidden, for another of the window's
    /// layouts ([`Self::put_dock`]) or to save; `None` without one.
    pub fn take_dock(&mut self) -> Option<DockParts<T>> {
        let shown = self.dock_shown();
        let (pane, size) = if let Some(parts) = self.detach_dock() {
            parts
        } else {
            let dock = self.dock.as_mut()?;
            (dock.hidden.take()?, dock.size)
        };
        self.dock = None;
        Some(DockParts { pane, shown, size })
    }

    /// Puts `parts` in as the dock (another of the window's layouts', or
    /// as saved): its pane keeps its id unless a pane here has it (new
    /// panes are numbered past it), its tabs get identities of this
    /// layout's; into a dock already here its tabs are opened instead. A
    /// dock without tabs is none. The dock's pane.
    pub fn put_dock(&mut self, parts: DockParts<T>) -> Option<PaneId> {
        let DockParts {
            mut pane,
            shown,
            size,
        } = parts;
        if pane.tabs.is_empty() {
            return self.dock();
        }
        if let Some(id) = self.dock() {
            let active = pane.tabs.get(pane.active).map(|tab| tab.content.clone());
            for tab in pane.tabs {
                self.open(id, tab.content, tab.preview);
            }
            if let Some(content) = active
                && let Some(dock) = self.pane_mut(id)
                && let Some(index) = dock.tabs.iter().position(|tab| tab.content == content)
            {
                dock.active = index;
            }
            if shown {
                self.show_dock();
            }
            return Some(id);
        }
        if self.every_pane().any(|other| other.id == pane.id) {
            pane.id = PaneId(self.next_id);
        }
        self.next_id = self.next_id.max(pane.id.0.checked_add(1)?);
        for tab in &mut pane.tabs {
            tab.id = self.fresh_tab();
        }
        pane.active = pane.active.min(pane.tabs.len().saturating_sub(1));
        let id = pane.id;
        self.dock = Some(Dock {
            id,
            hidden: Some(pane),
            size,
        });
        if shown {
            self.show_dock();
        }
        Some(id)
    }

    /// The dock's pane out of the tree, if shown (the code area's panes
    /// scaled to fill the height; the focus, if on it, to the pane above),
    /// with its share; the dock itself is the caller's to keep or drop.
    fn detach_dock(&mut self) -> Option<(Pane<T>, f32)> {
        let id = self.dock().filter(|_| self.dock_shown())?;
        let Node::Split {
            axis: Axis::Column,
            children,
            sizes,
        } = &mut self.tree
        else {
            return None;
        };
        if children.last() != Some(&Node::Pane(id)) {
            return None;
        }
        children.pop();
        let size = sizes.pop().unwrap_or(DOCK_SIZE);
        let count = children.len();
        fix_sizes(sizes, count);
        normalize(&mut self.tree);
        let index = self.panes.iter().position(|pane| pane.id == id)?;
        let pane = self.panes.remove(index);
        if self.focused == id
            && let Some(above) = leaf(&self.tree, true)
        {
            self.focused = above;
        }
        Some((pane, size))
    }

    /// `f` done to the code area alone: the dock, if shown, out of the
    /// tree meanwhile and back at its share after (the focus kept on it).
    fn without_dock<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let on_dock = self.is_dock(self.focused);
        let hidden = self.hide_dock();
        let out = f(self);
        if hidden {
            self.show_dock();
            if on_dock && let Some(dock) = self.dock() {
                self.focused = dock;
            }
        }
        out
    }

    /// New panes are numbered from `from` at least (ids another layout of
    /// the window holds are not given again).
    pub fn reserve_panes(&mut self, from: u32) {
        self.next_id = self.next_id.max(from);
    }

    /// Closes every pane without tabs unless it is the code area's last
    /// (a dock without tabs, shown or hidden, goes).
    fn close_empty(&mut self) {
        if self
            .dock
            .as_ref()
            .and_then(|dock| dock.hidden.as_ref())
            .is_some_and(|pane| pane.tabs.is_empty())
        {
            self.dock = None;
        }
        let empty: Vec<PaneId> = self
            .panes
            .iter()
            .filter(|pane| pane.tabs.is_empty())
            .map(|pane| pane.id)
            .collect();
        for id in empty {
            self.close_pane(id);
        }
    }
}

/// Tolerance for comparing rectangle edges and measures.
const EPSILON: f32 = 1e-4;

/// `pane` with each tab's content mapped by `f` ([`Layout::map_tabs`]): a
/// tab mapped to `None` dropped, an active one dropped leaving the tab on
/// its left active (else the first).
fn mapped_pane<T, U>(pane: &Pane<T>, f: &mut impl FnMut(&T) -> Option<U>) -> Pane<U> {
    let mut tabs = Vec::with_capacity(pane.tabs.len());
    let mut active = 0;
    for (index, tab) in pane.tabs.iter().enumerate() {
        let Some(content) = f(&tab.content) else {
            continue;
        };
        if index <= pane.active {
            active = tabs.len();
        }
        tabs.push(Tab {
            content,
            preview: tab.preview,
            id: tab.id,
        });
    }
    Pane {
        id: pane.id,
        tabs,
        active,
        synced: pane.synced,
    }
}

/// How far a pane is from the focused one in a direction.
#[derive(Debug)]
struct Candidate {
    /// The gap between the facing edges.
    distance: f32,
    /// The length both share on the other axis.
    overlap: f32,
    /// The distance between the centres.
    centre: f32,
}

impl Candidate {
    /// `to` measured from `from` in `direction`; `None` unless `to` lies
    /// entirely beyond `from`'s edge on that side and overlaps it on the
    /// other axis.
    fn measure(from: Rect, to: Rect, direction: Direction) -> Option<Self> {
        let vertical = overlap(from.y, from.h, to.y, to.h);
        let horizontal = overlap(from.x, from.w, to.x, to.w);
        let (distance, shared) = match direction {
            Direction::Left => (from.x - (to.x + to.w), vertical),
            Direction::Right => (to.x - (from.x + from.w), vertical),
            Direction::Up => (from.y - (to.y + to.h), horizontal),
            Direction::Down => (to.y - (from.y + from.h), horizontal),
        };
        if distance < -EPSILON || shared <= EPSILON {
            return None;
        }
        let dx = (to.x + to.w / 2.0) - (from.x + from.w / 2.0);
        let dy = (to.y + to.h / 2.0) - (from.y + from.h / 2.0);
        Some(Self {
            distance: distance.max(0.0),
            overlap: shared,
            centre: dx.hypot(dy),
        })
    }

    /// Whether `self` is strictly preferred to `other`.
    fn beats(&self, other: &Self) -> bool {
        if (self.distance - other.distance).abs() > EPSILON {
            return self.distance < other.distance;
        }
        if (self.overlap - other.overlap).abs() > EPSILON {
            return self.overlap > other.overlap;
        }
        self.centre < other.centre - EPSILON
    }
}

/// The length shared by `[start, start + len]` and
/// `[other, other + other_len]`, zero if they are disjoint.
fn overlap(start: f32, len: f32, other: f32, other_len: f32) -> f32 {
    ((start + len).min(other + other_len) - start.max(other)).max(0.0)
}

/// Inserts pane `new` after leaf `target` on `axis` (`before` it if
/// `before`): as a sibling if `target`'s parent split has that axis, else
/// by replacing `target` with a split of the two; either way the new pane
/// takes half of `target`'s share. Returns whether `target` was found.
fn insert_beside(node: &mut Node, target: PaneId, axis: Axis, new: PaneId, before: bool) -> bool {
    match node {
        Node::Pane(id) => {
            let hit = *id == target;
            if hit {
                let pair = if before {
                    vec![Node::Pane(new), Node::Pane(target)]
                } else {
                    vec![Node::Pane(target), Node::Pane(new)]
                };
                *node = Node::even(axis, pair);
            }
            hit
        }
        Node::Split {
            axis: own,
            children,
            sizes,
        } => {
            if *own == axis
                && let Some(index) = children
                    .iter()
                    .position(|child| *child == Node::Pane(target))
                && let Some(size) = sizes.get_mut(index)
            {
                let half = *size / 2.0;
                *size = half;
                let at = if before { index } else { index + 1 };
                sizes.insert(at, half);
                children.insert(at, Node::Pane(new));
                return true;
            }
            children
                .iter_mut()
                .any(|child| insert_beside(child, target, axis, new, before))
        }
    }
}

/// Removes leaf `target` from the splits under `node`, leaving the tree to
/// be normalized; its share goes to its neighbours, halved if it has two.
/// Returns the pane that takes its place (the last pane of the previous
/// sibling, else the first pane of the next), `None` if `target` is not
/// under `node` or is `node` itself.
fn remove_leaf(node: &mut Node, target: PaneId) -> Option<PaneId> {
    match node {
        Node::Pane(_) => None,
        Node::Split {
            children, sizes, ..
        } => {
            let Some(index) = children
                .iter()
                .position(|child| *child == Node::Pane(target))
            else {
                return children
                    .iter_mut()
                    .find_map(|child| remove_leaf(child, target));
            };
            children.remove(index);
            let freed = if index < sizes.len() {
                sizes.remove(index)
            } else {
                0.0
            };
            let neighbours = [
                index.checked_sub(1),
                Some(index).filter(|&i| i < sizes.len()),
            ];
            let count = neighbours.iter().flatten().count();
            for neighbour in neighbours.into_iter().flatten() {
                if let Some(size) = sizes.get_mut(neighbour) {
                    *size += freed / if count == 2 { 2.0 } else { 1.0 };
                }
            }
            match index.checked_sub(1) {
                Some(previous) => children.get(previous).and_then(|child| leaf(child, true)),
                None => children.first().and_then(|child| leaf(child, false)),
            }
        }
    }
}

/// Restores the tree's invariants bottom-up: same-axis child splits are
/// flattened into their parent (their children's sizes scaled by their
/// own), a split with one child is replaced by it, and sizes that are not
/// one positive share per child are made equal, the rest scaled to sum to
/// one.
fn normalize(node: &mut Node) {
    let replacement = match node {
        Node::Pane(_) => None,
        Node::Split {
            axis,
            children,
            sizes,
        } => {
            for child in children.iter_mut() {
                normalize(child);
            }
            fix_sizes(sizes, children.len());
            let mut flat = Vec::with_capacity(children.len());
            let mut flat_sizes = Vec::with_capacity(children.len());
            for (child, size) in std::mem::take(children).into_iter().zip(sizes.iter()) {
                match child {
                    Node::Split {
                        axis: inner,
                        children: grandchildren,
                        sizes: inner_sizes,
                    } if inner == *axis => {
                        flat_sizes.extend(inner_sizes.iter().map(|inner| inner * size));
                        flat.extend(grandchildren);
                    }
                    other @ (Node::Split { .. } | Node::Pane(_)) => {
                        flat_sizes.push(*size);
                        flat.push(other);
                    }
                }
            }
            *children = flat;
            *sizes = flat_sizes;
            fix_sizes(sizes, children.len());
            if children.len() == 1 {
                children.pop()
            } else {
                None
            }
        }
    };
    if let Some(only) = replacement {
        *node = only;
    }
}

/// Makes `sizes` one positive share for each of `count` children summing
/// to one: equal shares if they are not that, else scaled.
fn fix_sizes(sizes: &mut Vec<f32>, count: usize) {
    let total: f32 = sizes.iter().sum();
    let valid = sizes.len() == count
        && total.is_finite()
        && total > 0.0
        && sizes.iter().all(|size| size.is_finite() && *size > 0.0);
    if valid {
        for size in sizes.iter_mut() {
            *size /= total;
        }
    } else {
        *sizes = even_sizes(count);
    }
}

/// `count` equal shares of one.
#[expect(
    clippy::cast_precision_loss,
    reason = "share counts are small pane counts"
)]
fn even_sizes(count: usize) -> Vec<f32> {
    vec![1.0 / count.max(1) as f32; count]
}

/// The node at `path` (child indices from `node`), mutably.
fn node_at_mut<'a>(node: &'a mut Node, path: &[usize]) -> Option<&'a mut Node> {
    let mut node = node;
    for &index in path {
        match node {
            Node::Split { children, .. } => node = children.get_mut(index)?,
            Node::Pane(_) => return None,
        }
    }
    Some(node)
}

/// Appends the panes under `node`, in tree order.
fn collect_leaves(node: &Node, out: &mut Vec<PaneId>) {
    match node {
        Node::Pane(id) => out.push(*id),
        Node::Split { children, .. } => {
            for child in children {
                collect_leaves(child, out);
            }
        }
    }
}

/// `node` with each pane's id as `new_of` gives it.
fn renumbered(node: &Node, new_of: &impl Fn(PaneId) -> PaneId) -> Node {
    match node {
        Node::Pane(id) => Node::Pane(new_of(*id)),
        Node::Split {
            axis,
            children,
            sizes,
        } => Node::Split {
            axis: *axis,
            children: children.iter().map(|c| renumbered(c, new_of)).collect(),
            sizes: sizes.clone(),
        },
    }
}

/// The first (or with `last`, the last) pane under `node` in tree order.
fn leaf(node: &Node, last: bool) -> Option<PaneId> {
    let mut node = node;
    loop {
        match node {
            Node::Pane(id) => return Some(*id),
            Node::Split { children, .. } => {
                node = if last {
                    children.last()?
                } else {
                    children.first()?
                };
            }
        }
    }
}

/// Appends each pane under `node` with its share of `rect`, in tree order.
fn place(node: &Node, rect: Rect, out: &mut Vec<(PaneId, Rect)>) {
    match node {
        Node::Pane(id) => out.push((*id, rect)),
        Node::Split {
            axis,
            children,
            sizes,
        } => {
            // Every boundary from the running sum, so neighbours share
            // their common edge exactly and the last ends at the end.
            let mut before = 0.0;
            let count = children.len();
            for (index, (child, size)) in children.iter().zip(sizes).enumerate() {
                let after = if index + 1 == count {
                    1.0
                } else {
                    before + size
                };
                let part = match axis {
                    Axis::Row => {
                        let start = rect.x + rect.w * before;
                        let end = rect.x + rect.w * after;
                        Rect {
                            x: start,
                            w: end - start,
                            ..rect
                        }
                    }
                    Axis::Column => {
                        let start = rect.y + rect.h * before;
                        let end = rect.y + rect.h * after;
                        Rect {
                            y: start,
                            h: end - start,
                            ..rect
                        }
                    }
                };
                place(child, part, out);
                before = after;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(id: u32) -> Node {
        Node::Pane(PaneId(id))
    }

    fn row(children: Vec<Node>) -> Node {
        Node::even(Axis::Row, children)
    }

    fn col(children: Vec<Node>) -> Node {
        Node::even(Axis::Column, children)
    }

    /// `node` with every split's sizes made equal: its shape alone.
    fn shape(node: &Node) -> Node {
        match node {
            Node::Pane(id) => Node::Pane(*id),
            Node::Split { axis, children, .. } => {
                Node::even(*axis, children.iter().map(shape).collect())
            }
        }
    }

    /// The sizes of the split at `path`.
    fn sizes(layout: &Layout<&'static str>, path: &[usize]) -> Vec<f32> {
        layout.split_at(path).unwrap().1.to_vec()
    }

    fn all_close(a: &[f32], b: &[f32]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| close(*x, *y))
    }

    fn close(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-5
    }

    fn rect_of(layout: &Layout<&'static str>, id: PaneId) -> Rect {
        layout
            .rects()
            .into_iter()
            .find(|(pane, _)| *pane == id)
            .unwrap()
            .1
    }

    /// A | (B / C): ids 0, 1, 2.
    fn three() -> Layout<&'static str> {
        let mut layout = Layout::new("a");
        let b = layout.split(PaneId(0), Axis::Row, "b").unwrap();
        layout.split(b, Axis::Column, "c").unwrap();
        layout
    }

    fn ids(layout: &Layout<&'static str>) -> Vec<u32> {
        layout.panes().map(|pane| pane.id.0).collect()
    }

    /// The dock opens along the bottom under the whole code area, hides
    /// without closing (its tabs kept and closable, the code's shares as
    /// they were, the focus on the pane above) and shows again as high.
    #[test]
    fn the_dock_spans_the_bottom_and_hides_without_closing() {
        let mut layout = three();
        let dock = layout.open_in_dock("console", false).unwrap();
        assert_eq!(dock, PaneId(3));
        assert!(layout.dock_shown());
        let r = rect_of(&layout, dock);
        assert!(close(r.x, 0.0) && close(r.w, 1.0), "{r:?}");
        assert!(close(r.h, DOCK_SIZE) && close(r.y + r.h, 1.0), "{r:?}");
        assert!(close(rect_of(&layout, PaneId(0)).h, 1.0 - DOCK_SIZE));
        layout.open_in_dock("terminal", false);
        assert_eq!(
            contents(&layout, dock),
            vec![("console", false), ("terminal", false)]
        );
        assert_eq!(layout.code_panes().count(), 3);

        assert!(layout.focus(dock));
        assert!(layout.hide_dock());
        assert!(!layout.dock_shown());
        assert_eq!(layout.focused(), PaneId(2));
        assert_eq!(ids(&layout), vec![0, 1, 2]);
        assert_eq!(shape(layout.tree()), row(vec![p(0), col(vec![p(1), p(2)])]));
        assert!(all_close(&sizes(&layout, &[]), &[0.5, 0.5]));
        assert!(!layout.focus(dock));
        assert_eq!(layout.every_pane().count(), 4);
        assert!(layout.close_tab(dock, 1));
        assert_eq!(contents(&layout, dock), vec![("console", false)]);

        assert!(layout.show_dock());
        assert!(close(rect_of(&layout, dock).h, DOCK_SIZE));
        assert!(close(rect_of(&layout, PaneId(1)).w, 0.5));
    }

    /// The dock does not split, takes a tab dropped on its edge, keeps its
    /// height as code panes close, and goes with its last tab; the code
    /// area keeps its last pane and that pane's only tab.
    #[test]
    fn the_dock_keeps_to_itself_and_the_code_area_keeps_a_pane() {
        let mut layout = Layout::new("code");
        let dock = layout.open_in_dock("xrefs", false).unwrap();
        assert_eq!(layout.split(dock, Axis::Row, "x"), None);
        let code = layout.active_tab(PaneId(0)).unwrap();
        assert_eq!(
            layout.move_tab(code, TabDrop::Into { pane: dock, at: 0 }),
            None
        );
        assert!(!layout.close_pane(PaneId(0)));

        let below = layout.split(PaneId(0), Axis::Column, "c").unwrap();
        assert_eq!(shape(layout.tree()), col(vec![p(0), p(below.0), p(dock.0)]));
        let c = layout.active_tab(below).unwrap();
        let edge = TabDrop::Edge {
            pane: dock,
            side: Direction::Right,
        };
        assert_eq!(layout.move_tab(c, edge), Some(dock));
        assert_eq!(
            contents(&layout, dock),
            vec![("xrefs", false), ("c", false)]
        );
        assert_eq!(ids(&layout), vec![0, dock.0]);

        let height = rect_of(&layout, dock).h;
        let d = layout.split(PaneId(0), Axis::Column, "d").unwrap();
        assert!(close(rect_of(&layout, dock).h, height));
        assert!(layout.focus(dock));
        assert!(layout.close_pane(d));
        assert!(close(rect_of(&layout, dock).h, height));
        assert_eq!(layout.focused(), dock);

        assert!(layout.close_tab(dock, 0));
        assert!(layout.close_tab(dock, 0));
        assert_eq!(layout.dock(), None);
        assert_eq!(ids(&layout), vec![0]);
        assert_eq!(layout.focused(), PaneId(0));
    }

    /// A window's dock moves between its tabs' layouts with its pane's id
    /// (taking another where a pane has it), its tabs numbered afresh;
    /// copies leave it out; mapping carries it, hidden or not, and drops
    /// it emptied.
    #[test]
    fn the_dock_moves_between_layouts_and_copies_leave_it_out() {
        let mut first = three();
        let dock = first.open_in_dock("console", false).unwrap();
        first.open_in_dock("xrefs", true);
        first.hide_dock();
        let (copy, _) = first.copied(10, |_| true).unwrap();
        assert_eq!(copy.dock(), None);
        assert_eq!(copy.every_pane().count(), 3);

        let parts = first.take_dock().unwrap();
        assert!(!parts.shown);
        assert_eq!(first.dock(), None);
        let mut second = Layout::new("code");
        second.reserve_panes(first.next_pane());
        assert_eq!(second.put_dock(parts), Some(dock));
        assert!(!second.dock_shown());
        assert!(second.next_pane() > dock.0);
        assert_eq!(
            contents(&second, dock),
            vec![("console", false), ("xrefs", true)]
        );
        let mapped = second.map_tabs(|t| (*t != "xrefs").then_some(*t));
        assert_eq!(contents(&mapped, dock), vec![("console", false)]);
        assert_eq!(
            second.map_tabs(|t| (*t == "code").then_some(*t)).dock(),
            None
        );

        let mut third = Layout::new("code");
        let parts = DockParts {
            pane: Pane {
                id: PaneId(0),
                tabs: vec![Tab::new("console", false)],
                active: 0,
                synced: false,
            },
            shown: true,
            size: 0.25,
        };
        let id = third.put_dock(parts).unwrap();
        assert_ne!(id, PaneId(0));
        assert!(close(rect_of(&third, id).h, 0.25));
    }

    fn contents(layout: &Layout<&'static str>, id: PaneId) -> Vec<(&'static str, bool)> {
        layout
            .pane(id)
            .unwrap()
            .tabs
            .iter()
            .map(|tab| (tab.content, tab.preview))
            .collect()
    }

    #[test]
    fn a_copy_keeps_what_is_kept_under_fresh_ids() {
        // code | (code / list), the list closed in the copy.
        let mut layout = three();
        layout.open(PaneId(2), "list", false);
        layout.close_tab(PaneId(2), 0);
        layout.open(PaneId(1), "list", false);
        layout.activate(PaneId(1), 0);
        layout.pane_mut(PaneId(1)).unwrap().synced = false;
        let (copy, renumbering) = layout.copied(7, |t| *t != "list").unwrap();
        assert_eq!(
            renumbering,
            vec![
                (PaneId(0), PaneId(7)),
                (PaneId(1), PaneId(8)),
                (PaneId(2), PaneId(9))
            ]
        );
        assert_eq!(ids(&copy), vec![7, 8]);
        assert_eq!(shape(copy.tree()), row(vec![p(7), p(8)]));
        assert_eq!(copy.pane(PaneId(8)).unwrap().tabs[0].content, "b");
        assert!(copy.panes().all(|pane| pane.synced));
        assert!(copy.next_pane() >= 10);
        // The original is as it was.
        assert_eq!(ids(&layout), vec![0, 1, 2]);
    }

    #[test]
    fn reserved_ids_are_not_given_again() {
        let mut layout = Layout::new("a");
        layout.reserve_panes(5);
        assert_eq!(layout.split(PaneId(0), Axis::Row, "b"), Some(PaneId(5)));
    }

    #[test]
    fn splits_build_a_flattened_tree() {
        let mut layout = Layout::new("a");
        let b = layout.split(PaneId(0), Axis::Row, "b").unwrap();
        assert_eq!(&shape(layout.tree()), &row(vec![p(0), p(1)]));
        assert_eq!(layout.focused(), b);
        let c = layout.split(b, Axis::Column, "c").unwrap();
        assert_eq!(
            &shape(layout.tree()),
            &row(vec![p(0), col(vec![p(1), p(2)])])
        );
        let d = layout.split(c, Axis::Row, "d").unwrap();
        assert_eq!(
            &shape(layout.tree()),
            &row(vec![p(0), col(vec![p(1), row(vec![p(2), p(3)])])])
        );
        assert_eq!(layout.focused(), d);
        assert_eq!(layout.active(d), Some(&"d"));
        assert_eq!(contents(&layout, d), vec![("d", false)]);

        // Same-axis parent: a sibling, not a nested split.
        layout.split(PaneId(0), Axis::Row, "e").unwrap();
        layout.pane_mut(b).unwrap().synced = false;
        let f = layout.split(b, Axis::Column, "f").unwrap();
        assert_eq!(
            &shape(layout.tree()),
            &row(vec![
                p(0),
                p(4),
                col(vec![p(1), p(5), row(vec![p(2), p(3)])])
            ])
        );
        // Each new pane took half of the one split.
        assert!(all_close(&sizes(&layout, &[]), &[0.25, 0.25, 0.5]));
        assert!(all_close(&sizes(&layout, &[2]), &[0.25, 0.25, 0.5]));
        assert!(all_close(&sizes(&layout, &[2, 2]), &[0.5, 0.5]));
        assert_eq!(ids(&layout), vec![0, 4, 1, 5, 2, 3]);
        assert!(!layout.pane(f).unwrap().synced);
        assert!(layout.pane(PaneId(4)).unwrap().synced);
        assert_eq!(layout.len(), 6);
        assert!(layout.split(PaneId(99), Axis::Row, "x").is_none());
    }

    #[test]
    fn rects_tile_the_unit_square() {
        let mut layout = three();
        layout.split(PaneId(2), Axis::Row, "d").unwrap();
        layout.split(PaneId(0), Axis::Column, "e").unwrap();
        layout.split(PaneId(1), Axis::Row, "f").unwrap();
        layout.split(PaneId(1), Axis::Row, "g").unwrap();
        let rects = layout.rects();
        assert_eq!(
            rects.iter().map(|(id, _)| id.0).collect::<Vec<_>>(),
            ids(&layout)
        );
        let area: f32 = rects.iter().map(|(_, rect)| rect.w * rect.h).sum();
        assert!(close(area, 1.0));
        for (index, (_, one)) in rects.iter().enumerate() {
            assert!(one.x >= 0.0 && one.y >= 0.0 && one.w > 0.0 && one.h > 0.0);
            assert!(one.x + one.w <= 1.0 + 1e-6 && one.y + one.h <= 1.0 + 1e-6);
            for (_, two) in rects.iter().skip(index + 1) {
                let shared =
                    overlap(one.x, one.w, two.x, two.w) * overlap(one.y, one.h, two.y, two.h);
                assert!(shared < 1e-6, "{one:?} overlaps {two:?}");
            }
        }

        let layout = three();
        let left = rect_of(&layout, PaneId(0));
        let bottom = rect_of(&layout, PaneId(2));
        assert!(close(left.x, 0.0) && close(left.w, 0.5) && close(left.h, 1.0));
        assert!(
            close(bottom.x, 0.5)
                && close(bottom.y, 0.5)
                && close(bottom.w, 0.5)
                && close(bottom.h, 0.5)
        );
    }

    #[test]
    fn focus_moves_by_direction() {
        let (a, b, c) = (PaneId(0), PaneId(1), PaneId(2));
        let mut layout = three();
        assert!(layout.focus(b));
        assert!(layout.move_focus(Direction::Left));
        assert_eq!(layout.focused(), a);
        // B and C tie on edge, overlap and centre distance: tree order.
        assert!(layout.move_focus(Direction::Right));
        assert_eq!(layout.focused(), b);
        assert!(layout.move_focus(Direction::Down));
        assert_eq!(layout.focused(), c);
        assert!(layout.move_focus(Direction::Up));
        assert_eq!(layout.focused(), b);

        // Edges.
        assert!(!layout.move_focus(Direction::Up));
        assert!(!layout.move_focus(Direction::Right));
        assert_eq!(layout.focused(), b);
        layout.focus(c);
        assert!(!layout.move_focus(Direction::Down));
        layout.focus(a);
        assert!(!layout.move_focus(Direction::Left));
        assert!(!layout.move_focus(Direction::Up));
        assert!(!layout.move_focus(Direction::Down));
        assert_eq!(layout.focused(), a);
        assert!(!layout.focus(PaneId(7)));
        assert_eq!(layout.focused(), a);
    }

    #[test]
    fn focus_prefers_most_overlap() {
        // (A | B) / (C | D | E)
        let mut layout = Layout::new("a");
        let c = layout.split(PaneId(0), Axis::Column, "c").unwrap();
        let b = layout.split(PaneId(0), Axis::Row, "b").unwrap();
        let d = layout.split(c, Axis::Row, "d").unwrap();
        let e = layout.split(d, Axis::Row, "e").unwrap();
        assert_eq!(
            &shape(layout.tree()),
            &col(vec![row(vec![p(0), p(2)]), row(vec![p(1), p(3), p(4)])])
        );
        // C, D and E in thirds.
        assert!(layout.even(&[1]));
        layout.focus(b);
        assert!(layout.move_focus(Direction::Down));
        assert_eq!(layout.focused(), e);
        layout.focus(PaneId(0));
        assert!(layout.move_focus(Direction::Down));
        assert_eq!(layout.focused(), c);
        layout.focus(d);
        // A and B overlap D by a sixth each and their centres are equally
        // far: the first in tree order.
        assert!(layout.move_focus(Direction::Up));
        assert_eq!(layout.focused(), PaneId(0));
    }

    #[test]
    fn focus_next_wraps_in_tree_order() {
        let mut layout = three();
        layout.focus(PaneId(0));
        assert_eq!(layout.focus_next(), PaneId(1));
        assert_eq!(layout.focus_next(), PaneId(2));
        assert_eq!(layout.focus_next(), PaneId(0));
        assert_eq!(layout.focused(), PaneId(0));
    }

    #[test]
    fn closing_panes_collapses_splits_and_moves_focus() {
        // A | (B / (C | D))
        let mut layout = three();
        let d = layout.split(PaneId(2), Axis::Row, "d").unwrap();
        assert_eq!(
            &shape(layout.tree()),
            &row(vec![p(0), col(vec![p(1), row(vec![p(2), p(3)])])])
        );
        layout.focus(PaneId(1));
        assert!(layout.close_pane(PaneId(1)));
        // The column collapses to C | D, flattened into the root row; the
        // focus goes to the next sibling's first pane.
        assert_eq!(&shape(layout.tree()), &row(vec![p(0), p(2), p(3)]));
        assert_eq!(layout.focused(), PaneId(2));
        assert!(layout.pane(PaneId(1)).is_none());

        assert!(layout.close_pane(d));
        assert_eq!(&shape(layout.tree()), &row(vec![p(0), p(2)]));
        assert_eq!(layout.focused(), PaneId(2));

        assert!(layout.close_pane(PaneId(2)));
        assert_eq!(layout.tree(), &p(0));
        assert_eq!(layout.focused(), PaneId(0));
        assert!(!layout.close_pane(PaneId(0)));
        assert!(!layout.close_pane(PaneId(9)));
        assert_eq!(layout.len(), 1);
        assert!(!layout.is_empty());
    }

    #[test]
    fn closing_moves_focus_to_previous_sibling() {
        let mut layout = three();
        layout.focus(PaneId(2));
        assert!(layout.close_pane(PaneId(2)));
        assert_eq!(&shape(layout.tree()), &row(vec![p(0), p(1)]));
        assert_eq!(layout.focused(), PaneId(1));
        assert_eq!(ids(&layout), vec![0, 1]);
    }

    #[test]
    fn ids_are_never_reused() {
        let mut layout = Layout::new("a");
        let first = layout.split(PaneId(0), Axis::Row, "b").unwrap();
        assert!(layout.close_pane(first));
        let second = layout.split(PaneId(0), Axis::Row, "c").unwrap();
        assert_ne!(first, second);
        assert_eq!(second, PaneId(2));
    }

    #[test]
    fn preview_tabs() {
        let id = PaneId(0);
        let mut layout = Layout::new("a");
        let previews = |layout: &Layout<&'static str>| {
            layout
                .pane(id)
                .unwrap()
                .tabs
                .iter()
                .filter(|tab| tab.preview)
                .count()
        };

        layout.open(id, "b", true);
        assert_eq!(contents(&layout, id), vec![("a", false), ("b", true)]);
        assert_eq!(layout.active(id), Some(&"b"));

        // Replaced in place.
        layout.open(id, "c", true);
        assert_eq!(contents(&layout, id), vec![("a", false), ("c", true)]);
        assert_eq!(layout.pane(id).unwrap().active, 1);

        // Pinned, it stays; the next preview gets a new tab.
        layout.pin(id, 1);
        layout.open(id, "d", true);
        assert_eq!(
            contents(&layout, id),
            vec![("a", false), ("c", false), ("d", true)]
        );

        // Replaced in place even when another tab is active.
        layout.activate(id, 0);
        layout.open(id, "e", true);
        assert_eq!(
            contents(&layout, id),
            vec![("a", false), ("c", false), ("e", true)]
        );
        assert_eq!(layout.pane(id).unwrap().active, 2);

        // Existing content is activated; a preview open keeps it as it is.
        layout.open(id, "a", true);
        assert_eq!(layout.pane(id).unwrap().active, 0);
        layout.open(id, "e", true);
        assert_eq!(layout.pane(id).unwrap().active, 2);
        assert_eq!(previews(&layout), 1);
        // A pinned open of existing preview content pins it.
        layout.activate(id, 0);
        layout.open(id, "e", false);
        assert_eq!(layout.pane(id).unwrap().active, 2);
        assert_eq!(previews(&layout), 0);

        // A pinned open goes after the active tab.
        layout.activate(id, 0);
        layout.open(id, "f", false);
        assert_eq!(
            contents(&layout, id),
            vec![("a", false), ("f", false), ("c", false), ("e", false)]
        );
        assert_eq!(layout.active(id), Some(&"f"));
        layout.open(id, "g", true);
        layout.open(id, "h", false);
        assert_eq!(previews(&layout), 1);
        assert_eq!(layout.active(id), Some(&"h"));
    }

    #[test]
    fn navigations_reuse_one_preview_tab_and_new_tabs_pile_up() {
        let id = PaneId(0);
        let mut layout = Layout::new("listing");
        let first = layout.active_tab(id).unwrap();

        // A single click: a preview tab after the active one, even of
        // content equal to a tab's (another place in the listing).
        let preview = layout.open_preview(id, "listing").unwrap();
        assert_ne!(preview, first);
        assert_eq!(
            contents(&layout, id),
            vec![("listing", false), ("listing", true)]
        );
        assert_eq!(layout.active_tab(id), Some(preview));

        // The next one replaces it in place (the same tab moves), from
        // wherever the active tab is.
        layout.activate(id, 0);
        assert_eq!(layout.open_preview(id, "c"), Some(preview));
        assert_eq!(contents(&layout, id), vec![("listing", false), ("c", true)]);
        assert_eq!(layout.active_tab(id), Some(preview));

        // Pinned (an edit, a double click), it stays; the next navigation
        // gets a new preview tab.
        layout.pin(id, 1);
        let next = layout.open_preview(id, "listing").unwrap();
        assert_ne!(next, preview);
        assert_eq!(
            contents(&layout, id),
            vec![("listing", false), ("c", false), ("listing", true)]
        );

        // Ctrl+click: a pinned tab after the active one each time, the
        // preview tab left as it is.
        layout.activate(id, 0);
        let new = layout.open_new(id, "listing", true).unwrap();
        let again = layout.open_new(id, "listing", true).unwrap();
        assert_ne!(new, again);
        assert_eq!(
            contents(&layout, id),
            vec![
                ("listing", false),
                ("listing", false),
                ("listing", false),
                ("c", false),
                ("listing", true)
            ]
        );
        assert_eq!(layout.active_tab(id), Some(again));
        assert_eq!(layout.find_tab(again), Some((id, 2)));
        // In the background: after the active one, which stays active.
        let behind = layout.open_new(id, "c", false).unwrap();
        assert_eq!(layout.active_tab(id), Some(again));
        assert_eq!(layout.find_tab(behind), Some((id, 3)));
        assert!(!layout.is_active(behind));
        // Still one preview tab.
        let previews = layout
            .pane(id)
            .unwrap()
            .tabs
            .iter()
            .filter(|t| t.preview)
            .count();
        assert_eq!(previews, 1);
        // Identities are never reused, across panes too.
        let other = layout.split(id, Axis::Row, "c").unwrap();
        let split = layout.active_tab(other).unwrap();
        let mut seen: Vec<TabId> = layout
            .panes()
            .flat_map(|p| p.tabs.iter().map(Tab::id))
            .collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 7);
        assert!(seen.contains(&split));
    }

    #[test]
    fn dragged_tabs_reorder_along_their_bar_and_move_between_panes() {
        let mut layout = Layout::new("a");
        let left = PaneId(0);
        layout.open(left, "b", false);
        layout.open(left, "c", false);
        let third = layout.active_tab(left).unwrap();
        let first = layout.pane(left).unwrap().tabs[0].id();

        // Along its bar: before the first; to the end (positions count the
        // tab still there).
        assert_eq!(
            layout.move_tab(third, TabDrop::Into { pane: left, at: 0 }),
            Some(left)
        );
        assert_eq!(
            contents(&layout, left),
            vec![("c", false), ("a", false), ("b", false)]
        );
        assert_eq!(layout.active_tab(left), Some(third));
        layout.move_tab(third, TabDrop::Into { pane: left, at: 3 });
        assert_eq!(
            contents(&layout, left),
            vec![("a", false), ("b", false), ("c", false)]
        );
        // One step right of `a`: past `b`.
        layout.move_tab(first, TabDrop::Into { pane: left, at: 2 });
        assert_eq!(
            contents(&layout, left),
            vec![("b", false), ("a", false), ("c", false)]
        );

        // A preview dragged into another pane: pinned, active and focused
        // there, its identity kept; the pane left keeps the rest.
        let right = layout.split(left, Axis::Row, "r").unwrap();
        layout.focus(left);
        let preview = layout.open_preview(left, "p").unwrap();
        assert_eq!(
            layout.move_tab(preview, TabDrop::Into { pane: right, at: 0 }),
            Some(right)
        );
        assert_eq!(contents(&layout, right), vec![("p", false), ("r", false)]);
        assert_eq!(layout.find_tab(preview), Some((right, 0)));
        assert_eq!(layout.focused(), right);
        assert_eq!(layout.pane(left).unwrap().tabs.len(), 3);
    }

    #[test]
    fn dragged_tabs_split_by_edge_and_an_emptied_pane_closes() {
        let mut layout = Layout::new("a");
        let left = PaneId(0);
        layout.open(left, "b", false);
        let right = layout.split(left, Axis::Row, "p").unwrap();
        layout.open(right, "r", false);
        let id_of = |layout: &Layout<&'static str>, pane: PaneId, index: usize| {
            layout.pane(pane).unwrap().tabs[index].id()
        };
        // On a pane's edges: a new pane on that side, half of it.
        let moved = id_of(&layout, left, 0);
        let above = layout
            .move_tab(
                moved,
                TabDrop::Edge {
                    pane: left,
                    side: Direction::Up,
                },
            )
            .unwrap();
        assert_eq!(
            &shape(layout.tree()),
            &row(vec![col(vec![p(above.0), p(0)]), p(right.0)])
        );
        assert_eq!(layout.active(above), Some(&"a"));
        assert_eq!(layout.focused(), above);
        let from_right = id_of(&layout, right, 1);
        let leftmost = layout
            .move_tab(
                from_right,
                TabDrop::Edge {
                    pane: left,
                    side: Direction::Left,
                },
            )
            .unwrap();
        assert_eq!(
            &shape(layout.tree()),
            &row(vec![
                col(vec![p(above.0), row(vec![p(leftmost.0), p(0)])]),
                p(right.0)
            ])
        );

        // The last tab dragged out of a pane closes it; the only tab of a
        // pane on that pane's own edge does nothing.
        assert_eq!(
            layout.move_tab(from_right, TabDrop::Into { pane: right, at: 9 }),
            Some(right)
        );
        assert!(layout.pane(leftmost).is_none());
        assert_eq!(layout.focused(), right);
        let alone = id_of(&layout, above, 0);
        assert_eq!(
            layout.move_tab(
                alone,
                TabDrop::Edge {
                    pane: above,
                    side: Direction::Down
                }
            ),
            None
        );
        assert_eq!(layout.find_tab(alone), Some((above, 0)));
        // Moved under its own pane's neighbour, that one survives as is.
        assert_eq!(
            layout.move_tab(
                alone,
                TabDrop::Edge {
                    pane: left,
                    side: Direction::Down
                }
            ),
            Some(PaneId(right.0 + 3))
        );
        assert!(layout.pane(above).is_none());
        // The only pane left keeps its last tab.
        let mut one = Layout::new("x");
        let only = one.active_tab(PaneId(0)).unwrap();
        assert_eq!(
            one.move_tab(
                only,
                TabDrop::Into {
                    pane: PaneId(0),
                    at: 0
                }
            ),
            Some(PaneId(0))
        );
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn a_tab_dropped_on_a_body_goes_to_the_nearest_edge_quarter_else_into_it() {
        assert_eq!(drop_side(0.5, 0.5), None);
        assert_eq!(drop_side(0.3, 0.7), None);
        assert_eq!(drop_side(0.1, 0.5), Some(Direction::Left));
        assert_eq!(drop_side(0.9, 0.4), Some(Direction::Right));
        assert_eq!(drop_side(0.5, 0.05), Some(Direction::Up));
        assert_eq!(drop_side(0.6, 0.8), Some(Direction::Down));
        // In a corner, the nearer edge.
        assert_eq!(drop_side(0.1, 0.05), Some(Direction::Up));
        assert_eq!(drop_side(0.95, 0.9), Some(Direction::Right));
        // A quarter in: still into the pane.
        assert_eq!(drop_side(0.25, 0.5), None);
    }

    #[test]
    fn close_tab_activates_left_neighbour_and_closes_emptied_panes() {
        let mut layout = Layout::new("a");
        let id = PaneId(0);
        layout.open(id, "b", false);
        layout.open(id, "c", false);
        layout.open(id, "d", false);
        assert_eq!(layout.active(id), Some(&"d"));

        assert!(layout.close_tab(id, 3));
        assert_eq!(layout.active(id), Some(&"c"));
        // A tab left of the active one: the active tab stays active.
        assert!(layout.close_tab(id, 0));
        assert_eq!(layout.active(id), Some(&"c"));
        layout.activate(id, 0);
        assert!(layout.close_tab(id, 0));
        assert_eq!(layout.active(id), Some(&"c"));
        assert!(!layout.close_tab(id, 5));

        // An emptied pane closes, unless it is the last.
        let other = layout.split(id, Axis::Row, "x").unwrap();
        assert!(layout.close_tab(other, 0));
        assert!(layout.pane(other).is_none());
        assert_eq!(layout.focused(), id);
        assert!(layout.close_tab(id, 0));
        assert_eq!(layout.len(), 1);
        assert_eq!(layout.pane(id).unwrap().tabs, Vec::new());
        assert_eq!(layout.active(id), None);
        layout.open(id, "y", true);
        assert_eq!(contents(&layout, id), vec![("y", true)]);
        assert_eq!(layout.active(id), Some(&"y"));
    }

    #[test]
    fn cycle_wraps() {
        let mut layout = Layout::new("a");
        let id = PaneId(0);
        layout.open(id, "b", false);
        layout.open(id, "c", false);
        layout.cycle(id, true);
        assert_eq!(layout.active(id), Some(&"a"));
        layout.cycle(id, false);
        assert_eq!(layout.active(id), Some(&"c"));
        layout.cycle(id, false);
        assert_eq!(layout.active(id), Some(&"b"));
        *layout.active_mut(id).unwrap() = "z";
        assert_eq!(contents(&layout, id)[1], ("z", false));
    }

    #[test]
    fn dividers_drag_within_their_minimum() {
        // A | (B / C), the root 1000 wide and 800 high, panes 100 at least.
        let mut layout = three();
        assert!(layout.drag_divider(&[], 1, 300.0, 1000.0, 100.0));
        assert!(all_close(&sizes(&layout, &[]), &[0.3, 0.7]));
        let a = rect_of(&layout, PaneId(0));
        let b = rect_of(&layout, PaneId(1));
        assert!(close(a.w, 0.3) && close(b.x, 0.3) && close(b.w, 0.7));
        // Clamped to the minimum on either side.
        assert!(layout.drag_divider(&[], 1, 50.0, 1000.0, 100.0));
        assert!(all_close(&sizes(&layout, &[]), &[0.1, 0.9]));
        assert!(layout.drag_divider(&[], 1, 990.0, 1000.0, 100.0));
        assert!(all_close(&sizes(&layout, &[]), &[0.9, 0.1]));
        // Unchanged: no move, no divider there, no split there.
        assert!(!layout.drag_divider(&[], 1, 995.0, 1000.0, 100.0));
        assert!(!layout.drag_divider(&[], 0, 500.0, 1000.0, 100.0));
        assert!(!layout.drag_divider(&[], 2, 500.0, 1000.0, 100.0));
        assert!(!layout.drag_divider(&[5], 1, 500.0, 1000.0, 100.0));
        assert!(!layout.drag_divider(&[0], 1, 500.0, 1000.0, 100.0));
        // Too short for both minimums: left as it is.
        assert!(!layout.drag_divider(&[], 1, 500.0, 1000.0, 600.0));
        assert!(all_close(&sizes(&layout, &[]), &[0.9, 0.1]));

        // The column inside: its own length.
        assert!(layout.drag_divider(&[1], 1, 200.0, 800.0, 100.0));
        assert!(all_close(&sizes(&layout, &[1]), &[0.25, 0.75]));
        let c = rect_of(&layout, PaneId(2));
        assert!(close(c.x, 0.9) && close(c.y, 0.25) && close(c.h, 0.75));

        // Evened by a double-click.
        assert!(layout.even(&[]));
        assert!(all_close(&sizes(&layout, &[]), &[0.5, 0.5]));
        assert!(!layout.even(&[0]));

        // Of three, only the two beside the divider move.
        let mut layout = Layout::new("a");
        let b = layout.split(PaneId(0), Axis::Row, "b").unwrap();
        layout.split(b, Axis::Row, "c").unwrap();
        assert!(layout.even(&[]));
        assert!(layout.drag_divider(&[], 2, 600.0, 1200.0, 100.0));
        assert!(all_close(
            &sizes(&layout, &[]),
            &[1.0 / 3.0, 1.0 / 6.0, 1.0 / 2.0]
        ));
    }

    #[test]
    fn splitting_and_closing_keep_sizes() {
        let mut layout = Layout::new("a");
        let b = layout.split(PaneId(0), Axis::Row, "b").unwrap();
        layout.drag_divider(&[], 1, 30.0, 100.0, 0.0);
        // The new pane takes half of the one split.
        let c = layout.split(b, Axis::Row, "c").unwrap();
        assert!(all_close(&sizes(&layout, &[]), &[0.3, 0.35, 0.35]));
        // A closed pane's space goes to both neighbours.
        assert!(layout.close_pane(b));
        assert!(all_close(&sizes(&layout, &[]), &[0.475, 0.525]));
        // At the end, to its one neighbour.
        let d = layout.split(c, Axis::Row, "d").unwrap();
        assert!(all_close(&sizes(&layout, &[]), &[0.475, 0.2625, 0.2625]));
        assert!(layout.close_pane(d));
        assert!(all_close(&sizes(&layout, &[]), &[0.475, 0.525]));
        assert!(layout.close_pane(PaneId(0)));
        assert_eq!(layout.tree(), &p(c.0));

        // A | (B / (C | D)); closing B flattens C | D into the root, their
        // shares scaled by the column's.
        let mut layout = three();
        layout.split(PaneId(2), Axis::Row, "d").unwrap();
        layout.drag_divider(&[], 1, 40.0, 100.0, 0.0);
        layout.drag_divider(&[1, 1], 1, 25.0, 100.0, 0.0);
        assert!(layout.close_pane(PaneId(1)));
        assert_eq!(&shape(layout.tree()), &row(vec![p(0), p(2), p(3)]));
        assert!(all_close(&sizes(&layout, &[]), &[0.4, 0.15, 0.45]));
        // The rectangles follow the sizes and still tile the square.
        let rects = layout.rects();
        let xs: Vec<(f32, f32)> = rects.iter().map(|(_, r)| (r.x, r.w)).collect();
        assert!(all_close(
            &xs.iter().flat_map(|&(x, w)| [x, w]).collect::<Vec<_>>(),
            &[0.0, 0.4, 0.4, 0.15, 0.55, 0.45]
        ));
        assert!(
            rects
                .iter()
                .all(|(_, r)| close(r.y, 0.0) && close(r.h, 1.0))
        );
    }

    #[test]
    fn mapping_tabs_drops_tabs_and_emptied_panes() {
        let mut layout = Layout::new("a");
        let a = PaneId(0);
        layout.open(a, "x", false);
        layout.open(a, "c", true);
        layout.activate(a, 1);
        let b = layout.split(a, Axis::Row, "x").unwrap();
        layout.pane_mut(b).unwrap().synced = false;
        layout.focus(b);
        let mapped = layout.map_tabs(|t| (*t != "x").then(|| t.to_uppercase()));
        // The active tab dropped: its left neighbour is active; the
        // preview stays a preview; B, emptied, closed and the focus moved.
        let pane = mapped.pane(a).unwrap();
        let tabs: Vec<(&str, bool)> = pane
            .tabs
            .iter()
            .map(|t| (t.content.as_str(), t.preview))
            .collect();
        assert_eq!(tabs, vec![("A", false), ("C", true)]);
        assert_eq!(pane.active, 0);
        assert_eq!(mapped.tree(), &p(0));
        assert_eq!(mapped.focused(), a);
        assert!(mapped.pane(b).is_none());

        // Nothing dropped: the same layout.
        let same = layout.map_tabs(|t| Some(*t));
        assert_eq!(same.tree(), layout.tree());
        assert_eq!(same.focused(), b);
        assert!(!same.pane(b).unwrap().synced);
        assert_eq!(same.pane(a).unwrap().active, 1);
        // Ids stay unique after mapping.
        let mut same = same;
        assert_eq!(same.split(a, Axis::Column, "n"), Some(PaneId(2)));
    }

    #[test]
    fn layouts_from_parts_are_checked_and_normalized() {
        let pane = |id: u32, tabs: &[&'static str], active: usize| Pane {
            id: PaneId(id),
            tabs: tabs
                .iter()
                .map(|&content| Tab::new(content, false))
                .collect(),
            active,
            synced: true,
        };
        let tree = Node::Split {
            axis: Axis::Row,
            children: vec![
                p(7),
                Node::Split {
                    axis: Axis::Row,
                    children: vec![p(3), p(5)],
                    sizes: vec![1.0, 3.0],
                },
            ],
            sizes: vec![2.0, 2.0],
        };
        let layout = Layout::from_parts(
            tree.clone(),
            vec![
                pane(5, &["c"], 0),
                pane(7, &["a", "b"], 9),
                pane(3, &["d"], 0),
            ],
            PaneId(42),
        )
        .unwrap();
        // Same-axis splits flattened, sizes scaled to one; tree order; the
        // focus on the first pane; the active tab clamped.
        assert_eq!(&shape(layout.tree()), &row(vec![p(7), p(3), p(5)]));
        assert!(all_close(&sizes(&layout, &[]), &[0.5, 0.125, 0.375]));
        assert_eq!(ids(&layout), vec![7, 3, 5]);
        assert_eq!(layout.focused(), PaneId(7));
        assert_eq!(layout.active(PaneId(7)), Some(&"b"));
        // New ids after the largest.
        let mut grown = layout.clone();
        assert_eq!(grown.split(PaneId(3), Axis::Column, "e"), Some(PaneId(8)));

        // Leaves and panes must match, each once.
        assert!(Layout::from_parts(tree, vec![pane(7, &["a"], 0)], PaneId(7)).is_none());
        let twice = Node::even(Axis::Row, vec![p(1), p(1)]);
        assert!(
            Layout::from_parts(
                twice,
                vec![pane(1, &["a"], 0), pane(1, &["b"], 0)],
                PaneId(1)
            )
            .is_none()
        );

        // Bad sizes made equal; a pane without tabs closed, its share to
        // its neighbour.
        let bad = Node::Split {
            axis: Axis::Column,
            children: vec![p(0), p(1), p(2)],
            sizes: vec![-1.0, f32::NAN],
        };
        let layout = Layout::from_parts(
            bad,
            vec![pane(0, &["a"], 0), pane(1, &[], 0), pane(2, &["c"], 0)],
            PaneId(1),
        )
        .unwrap();
        assert_eq!(&shape(layout.tree()), &col(vec![p(0), p(2)]));
        assert!(all_close(&sizes(&layout, &[]), &[0.5, 0.5]));
        // The focus was on the closed pane: the previous one takes it.
        assert_eq!(layout.focused(), PaneId(0));
    }
}
