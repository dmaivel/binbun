//! Where a tab's graph was left (lead's rule, 2026-11-14): its zoom, and
//! each function's pan (the last [`REMEMBERED`]), so the graph comes back
//! as it was.
//!
//! - Back to the graph with the cursor where it was: exactly as left.
//! - The cursor moved meanwhile (in the text, by a jump, by the tab a graph
//!   in a split follows): the zoom kept, the graph scrolled as little as
//!   brings the cursor's block (its line, if the block is larger than the
//!   view) into view; not at all if it is in view.
//! - Another function: the tab's last zoom, centred on the cursor's block;
//!   one shown before in the tab comes back where it was left (then the
//!   rule above).

use crate::graph::{Rect, Size, Viewport};

/// How many functions' pans a tab remembers.
pub const REMEMBERED: usize = 32;

/// The screen pixels kept around what is scrolled into view.
pub const MARGIN: f32 = 48.0;

/// One function's graph as it was left in a tab.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pan {
    /// The function's entry.
    pub entry: u64,
    /// The graph point at the pane's left.
    pub x: f32,
    /// The graph point at the pane's top.
    pub y: f32,
    /// The cursor's listing line the view had followed (none: unknown, as
    /// restored from a file).
    pub followed: Option<u64>,
}

/// A tab's graph as it was left: its zoom, each function's pan, the most
/// recent first.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GraphMemory {
    zoom: Option<f32>,
    pans: Vec<Pan>,
}

impl GraphMemory {
    /// The tab's graph shows `view` of the function at `entry`, having
    /// followed the cursor to line `followed`: remembered, that function
    /// the most recent (the least recent forgotten past [`REMEMBERED`]).
    pub fn remember(&mut self, entry: u64, view: Viewport, followed: Option<u64>) {
        self.zoom = Some(view.zoom);
        self.pans.retain(|pan| pan.entry != entry);
        self.pans.insert(
            0,
            Pan {
                entry,
                x: view.x,
                y: view.y,
                followed,
            },
        );
        self.pans.truncate(REMEMBERED);
    }

    /// The tab's last zoom, if its graph was ever shown.
    pub fn zoom(&self) -> Option<f32> {
        self.zoom
    }

    /// The function at `entry`'s pan as it was left, if remembered.
    pub fn pan(&self, entry: u64) -> Option<&Pan> {
        self.pans.iter().find(|pan| pan.entry == entry)
    }

    /// The pan of the function shown last.
    pub fn latest(&self) -> Option<&Pan> {
        self.pans.first()
    }

    /// A memory as saved: the zoom and the last function's pan.
    pub fn saved(zoom: Option<f32>, latest: Option<Pan>) -> Self {
        Self {
            zoom,
            pans: latest.into_iter().collect(),
        }
    }

    /// The view a tab's graph arrives at (shown again, or another
    /// function): the function at `entry`, the cursor on listing line
    /// `cursor`, in `block` at `line` (graph rectangles), in a `pane`;
    /// `current` is the view before (its zoom is kept for a tab never
    /// shown as a graph).
    pub fn arrive(
        &self,
        entry: u64,
        cursor: u64,
        block: Rect,
        line: Rect,
        pane: Size,
        current: Viewport,
    ) -> Viewport {
        let zoom = self.zoom.unwrap_or(current.zoom);
        if let Some(pan) = self.pan(entry) {
            let left = Viewport {
                zoom,
                x: pan.x,
                y: pan.y,
            };
            if pan.followed == Some(cursor) {
                return left;
            }
            return follow(left, block, line, pane);
        }
        let mut view = Viewport { zoom, ..current };
        view.land(block, pane);
        // A block taller than the view: its line in it.
        if block.height * zoom > pane.height {
            view = follow(view, block, line, pane);
        }
        view
    }
}

/// `view` scrolled as little as brings the cursor's `block` into view in a
/// `pane` ([`MARGIN`] around it), or on an axis the block is larger than
/// the view, its `line`; unmoved where they are in view.
pub fn follow(view: Viewport, block: Rect, line: Rect, pane: Size) -> Viewport {
    let m = MARGIN / view.zoom;
    let v = view.visible(pane);
    let least = |start: f32, len: f32, at: f32, size: f32| {
        if at - m < start {
            at - m
        } else if at + size + m > start + len {
            at + size + m - len
        } else {
            start
        }
    };
    let axis = |start: f32, len: f32, (b, bs): (f32, f32), (l, ls): (f32, f32)| {
        if bs + 2.0 * m <= len {
            least(start, len, b, bs)
        } else if ls + 2.0 * m <= len {
            least(start, len, l, ls)
        } else if l + ls < start || l > start + len {
            // A line wider than the view, off it: its start.
            l - m
        } else {
            start
        }
    };
    Viewport {
        zoom: view.zoom,
        x: axis(v.x, v.width, (block.x, block.width), (line.x, line.width)),
        y: axis(
            v.y,
            v.height,
            (block.y, block.height),
            (line.y, line.height),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PANE: Size = Size {
        width: 800.0,
        height: 600.0,
    };

    fn rect(x: f32, y: f32, width: f32, height: f32) -> Rect {
        Rect {
            x,
            y,
            width,
            height,
        }
    }

    fn view(zoom: f32, x: f32, y: f32) -> Viewport {
        Viewport { zoom, x, y }
    }

    #[test]
    fn back_to_the_graph_with_the_cursor_unmoved_shows_it_exactly_as_left() {
        let mut memory = GraphMemory::default();
        // Panned and zoomed so the cursor's block is far off screen: still
        // exactly as left, nothing scrolled.
        let left = view(0.5, -300.0, 2000.0);
        memory.remember(0x1000, left, Some(40));
        let block = rect(0.0, 0.0, 200.0, 100.0);
        let line = rect(0.0, 20.0, 200.0, 17.0);
        assert_eq!(
            memory.arrive(0x1000, 40, block, line, PANE, Viewport::default()),
            left
        );
    }

    #[test]
    fn a_cursor_moved_meanwhile_scrolls_as_little_as_shows_its_block() {
        let mut memory = GraphMemory::default();
        let left = view(2.0, 100.0, 100.0);
        memory.remember(0x1000, left, Some(40));
        // Visible: 100..500 × 100..400 (graph units at zoom 2), margin 24.
        // The cursor's block in view: nothing moves.
        let shown = rect(200.0, 200.0, 100.0, 50.0);
        let line = rect(200.0, 210.0, 100.0, 8.5);
        assert_eq!(
            memory.arrive(0x1000, 41, shown, line, PANE, Viewport::default()),
            left
        );
        // Below the view: scrolled down just far enough (its bottom and the
        // margin at the view's bottom), the zoom and x kept.
        let below = rect(200.0, 700.0, 100.0, 50.0);
        let moved = memory.arrive(0x1000, 90, below, line, PANE, Viewport::default());
        assert_eq!(moved, view(2.0, 100.0, 700.0 + 50.0 + 24.0 - 300.0));
        // Left of it: scrolled left to its left edge and the margin.
        let aside = rect(-500.0, 200.0, 100.0, 50.0);
        let moved = memory.arrive(0x1000, 90, aside, line, PANE, Viewport::default());
        assert_eq!(moved, view(2.0, -500.0 - 24.0, 100.0));
    }

    #[test]
    fn a_block_larger_than_the_view_brings_its_line_into_view() {
        let start = view(1.0, 0.0, 0.0);
        // Taller than the 600 px view: the line counts, not the block.
        let block = rect(100.0, 0.0, 300.0, 2000.0);
        let seen = rect(100.0, 300.0, 300.0, 17.0);
        assert_eq!(follow(start, block, seen, PANE), start);
        let unseen = rect(100.0, 1500.0, 300.0, 17.0);
        assert_eq!(
            follow(start, block, unseen, PANE),
            view(1.0, 0.0, 1500.0 + 17.0 + 48.0 - 600.0)
        );
    }

    #[test]
    fn another_function_opens_at_the_last_zoom_centred_and_each_comes_back() {
        let mut memory = GraphMemory::default();
        memory.remember(0x1000, view(0.5, 10.0, 20.0), Some(4));
        // Never shown: the tab's zoom, the block centred across and a
        // third of the way down.
        let block = rect(1000.0, 1000.0, 200.0, 100.0);
        let line = rect(1000.0, 1010.0, 200.0, 17.0);
        let other = memory.arrive(0x2000, 9, block, line, PANE, Viewport::default());
        assert_eq!(other, view(0.5, 1100.0 - 800.0, 1000.0 - 400.0));
        memory.remember(0x2000, view(1.5, 7.0, 8.0), Some(9));
        // The first again: where it was left, at the tab's zoom now.
        let first_block = rect(0.0, 0.0, 10.0, 10.0);
        assert_eq!(
            memory.arrive(
                0x1000,
                4,
                first_block,
                first_block,
                PANE,
                Viewport::default()
            ),
            view(1.5, 10.0, 20.0)
        );
        assert_eq!(memory.latest().map(|p| p.entry), Some(0x2000));
    }

    #[test]
    fn a_tab_remembers_its_last_functions_only() {
        let mut memory = GraphMemory::default();
        for entry in 0..40_u64 {
            #[expect(clippy::cast_precision_loss, reason = "a test's small numbers")]
            memory.remember(entry, view(1.0, entry as f32, 0.0), None);
        }
        // Shown again, one goes to the front and stays.
        memory.remember(9, view(1.0, 99.0, 0.0), None);
        memory.remember(40, view(1.0, 40.0, 0.0), None);
        assert!(memory.pan(9).is_some());
        assert_eq!(memory.pan(9).map(|p| p.x), Some(99.0));
        assert!(memory.pan(40).is_some() && memory.pan(39).is_some());
        // The least recent past the bound are forgotten (0 to 7 first,
        // then 8 when 40 came).
        let kept = (0..=40).filter(|&e| memory.pan(e).is_some()).count();
        assert_eq!(kept, REMEMBERED);
        assert!(memory.pan(7).is_none() && memory.pan(8).is_none());
        assert!(memory.pan(10).is_some());
    }
}
