//! Range selections in the listing (whole lines) and the C (characters):
//! the model is `binbun_gui_view::selection`'s; here the keys no command
//! takes (Shift with the arrows, Page Up and Down, Home and End; with Ctrl,
//! Home and End to the top and the bottom), Escape, Copy, the bytes the
//! corrections and the hex view take from the listing's selection, the
//! selection shared with the sync group's listings (their hex views
//! following it), and the instructions behind the C's selected lines.

use std::ops::RangeInclusive;

use binbun_gui_view::cdoc::CDocument;
use binbun_gui_view::collab::Selection as Shared;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::Listing;
use binbun_gui_view::selection::{
    TextPos, byte_at, c_text, item_lines, line_addresses, listing_bytes, listing_text,
};
use gpui_kit::{ClipboardItem, Context, KeyDownEvent};

use crate::workspace::{ListingState, TabKind, Workspace};

/// [`Workspace::move_cursor`]'s lines to the first line.
pub const TOP: i64 = i64::MIN / 2;

/// [`Workspace::move_cursor`]'s lines to the last line.
pub const BOTTOM: i64 = i64::MAX / 2;

/// Where line `line` of `document`'s code starts: the characters of its
/// indentation.
pub fn indentation(document: &CDocument, line: usize) -> usize {
    document
        .line_text(line)
        .chars()
        .take_while(|c| c.is_whitespace())
        .count()
}

/// Selects in `state` the lines of `listing` holding `bytes` (first, past
/// the last, whether the cursor is at the first), the cursor at the same
/// end; none drops the selection.
pub fn select_lines(state: &mut ListingState, listing: &Listing, bytes: Option<(u64, u64, bool)>) {
    let Some((start, end, at_start)) = bytes else {
        state.selection.clear();
        return;
    };
    let lines = item_lines(listing, start, end.saturating_sub(1).max(start));
    let (cursor, anchor) = if at_start {
        (*lines.start(), *lines.end())
    } else {
        (*lines.end(), *lines.start())
    };
    state.cursor = cursor;
    state.selection.anchor = Some(anchor);
}

impl Workspace {
    /// Whether pane `id` shows the listing as text (not as a graph, the
    /// hex view or the call graph).
    pub fn shows_listing_text(&self, id: PaneId) -> bool {
        matches!(self.layout.active(id), Some(TabKind::Listing))
            && self
                .panes
                .get(&id)
                .is_some_and(|s| !s.hex.on && !s.graph.on && !s.calls.on)
    }

    /// Whether pane `id` shows C (not as the IR).
    pub fn shows_c(&self, id: PaneId) -> bool {
        matches!(self.layout.active(id), Some(TabKind::C { .. })) && !self.shows_ir(id)
    }

    /// Pane `id`'s listing selection: its lines, in order.
    pub fn listing_selection(&self, id: PaneId) -> Option<RangeInclusive<u64>> {
        let state = &self.panes.get(&id)?.listing;
        state.selection.range(state.cursor)
    }

    /// Pane `id`'s C selection: where it starts and ends (excluded).
    pub fn c_selection(&self, id: PaneId) -> Option<(TextPos, TextPos)> {
        let c = &self.panes.get(&id)?.c;
        c.selection.range(TextPos::new(c.line, c.column))
    }

    /// The bytes pane `id` selects, as addresses: its hex view's, else its
    /// listing's lines' items; the first, past the last, and whether the
    /// cursor is at the first.
    pub fn pane_bytes(&self, id: PaneId) -> Option<(u64, u64, bool)> {
        if self.shows_hex(id) {
            return self.hex_bytes(id);
        }
        if !self.shows_listing_text(id) {
            return None;
        }
        let state = &self.panes.get(&id)?.listing;
        let lines = self.listing_selection(id)?;
        let (start, end) = listing_bytes(self.listing.as_ref()?, lines.clone())?;
        Some((
            start,
            end,
            state.cursor == *lines.start() && lines.start() != lines.end(),
        ))
    }

    /// The bytes the focused pane selects (see [`Self::pane_bytes`]): the
    /// first and past the last.
    pub fn selected_bytes(&self) -> Option<(u64, u64)> {
        self.pane_bytes(self.layout.focused())
            .map(|(start, end, _)| (start, end))
    }

    /// Whether the focused pane's listing or C selects anything (Copy
    /// takes it).
    pub fn selects(&self) -> bool {
        let id = self.layout.focused();
        (self.shows_listing_text(id) && self.listing_selection(id).is_some())
            || (self.shows_c(id) && self.c_selection(id).is_some())
    }

    /// Pane `id`'s selection as presence says it: addresses in the listing
    /// and the hex view, the text's lines and columns in the C.
    pub fn presence_selection(&self, id: PaneId) -> Option<Shared> {
        if self.shows_c(id) {
            let (from, to) = self.c_selection(id)?;
            let pos = |p: TextPos| {
                (
                    u32::try_from(p.line).unwrap_or(u32::MAX),
                    u32::try_from(p.column).unwrap_or(u32::MAX),
                )
            };
            return Some(Shared::Text {
                from: pos(from),
                to: pos(to),
            });
        }
        let (first, last) = if self.shows_hex(id) {
            let (start, end, _) = self.hex_bytes(id)?;
            (start, end.saturating_sub(1))
        } else if self.shows_listing_text(id) {
            let lines = self.listing_selection(id)?;
            let listing = self.listing.as_ref()?;
            let address = |n: u64| listing.line(n).map(|l| l.address);
            (address(*lines.start())?, address(*lines.end())?)
        } else {
            return None;
        };
        Some(Shared::Addresses { first, last })
    }

    /// Pane `id`'s selected bytes on the listings and hex views of the
    /// panes synced with it; none drops theirs.
    pub fn share_selection(&mut self, id: PaneId) {
        let Some(listing) = self.listing.clone() else {
            return;
        };
        let bytes = self.pane_bytes(id);
        let others: Vec<PaneId> = self
            .layout
            .panes()
            .filter(|p| p.synced && p.id != id)
            .map(|p| p.id)
            .filter(|&p| matches!(self.layout.active(p), Some(TabKind::Listing)))
            .collect();
        for other in others {
            if let Some(state) = self.panes.get_mut(&other) {
                select_lines(&mut state.listing, &listing, bytes);
                state.hex.followed = Some(state.listing.cursor);
            }
            if self.shows_hex(other) {
                self.hex_take(other, bytes);
            }
        }
    }

    /// The instructions behind the C cursor's line of the sync group's C,
    /// or behind every line of its selection: the provenance the listing
    /// washes.
    pub fn behind_c(&self) -> Vec<u64> {
        let Some((id, document)) = self
            .layout
            .panes()
            .filter(|p| p.synced && !self.shows_ir(p.id))
            .find_map(|p| {
                Some((
                    p.id,
                    self.document(p.tabs.get(p.active).map(|t| &t.content)?)?,
                ))
            })
        else {
            return Vec::new();
        };
        let Some(state) = self.panes.get(&id) else {
            return Vec::new();
        };
        let cursor = TextPos::new(state.c.line, state.c.column);
        let lines = state.c.selection.lines(cursor).unwrap_or_else(|| {
            let line = document.comment_owner(state.c.line);
            line..=line
        });
        line_addresses(document, lines)
    }

    /// Escape: drops the focused pane's listing or C selection; whether it
    /// had one.
    pub fn clear_selection(&mut self) -> bool {
        let id = self.layout.focused();
        let (listing, c) = (self.shows_listing_text(id), self.shows_c(id));
        let Some(state) = self.panes.get_mut(&id) else {
            return false;
        };
        let cursor = TextPos::new(state.c.line, state.c.column);
        let cleared = if listing {
            state.listing.selection.clear()
        } else if c {
            state.c.selection.clear(cursor)
        } else {
            false
        };
        if cleared {
            self.moved(id);
        }
        cleared
    }

    /// Copy: the focused pane's listing lines or C text selected, as
    /// shown; whether there were any.
    pub fn copy_selection(&self, cx: &mut Context<Self>) -> bool {
        let Some(text) = self.selection_text() else {
            return false;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        true
    }

    /// The text Copy takes from the focused pane's selection.
    fn selection_text(&self) -> Option<String> {
        let id = self.layout.focused();
        if self.shows_listing_text(id) {
            let lines = self.listing_selection(id)?;
            let session = self.session.as_ref()?;
            let db = session.database()?;
            return Some(listing_text(
                self.listing.as_ref()?,
                db,
                session.overlay(),
                lines,
            ));
        }
        if self.shows_c(id) {
            let (from, to) = self.c_selection(id)?;
            let document = self.document(self.layout.active(id)?)?;
            return Some(c_text(document, from, to));
        }
        None
    }

    /// The keys selections take in pane `id`'s listing or C that no
    /// command does: Shift with Up, Down, Page Up, Page Down (lines), Home
    /// and End (the line's start and end; with Ctrl, Cmd on macOS, as
    /// Cursor to the Top and to the Bottom, the top and the bottom), and in
    /// the C Left and Right (a character); whether it took `e`.
    pub fn selection_key(&mut self, id: PaneId, e: &KeyDownEvent) -> bool {
        let k = &e.keystroke;
        let (secondary, other) = if cfg!(target_os = "macos") {
            (k.modifiers.platform, k.modifiers.control)
        } else {
            (k.modifiers.control, k.modifiers.platform)
        };
        if !k.modifiers.shift || k.modifiers.alt || other {
            return false;
        }
        let c = self.shows_c(id);
        if self.layout.focused() != id || !(c || self.shows_listing_text(id)) {
            return false;
        }
        match (k.key.as_str(), secondary) {
            ("up", false) => self.move_cursor(-1, true),
            ("down", false) => self.move_cursor(1, true),
            ("pageup", false) => self.move_cursor(-self.page(id), true),
            ("pagedown", false) => self.move_cursor(self.page(id), true),
            ("home", true) => {
                self.move_cursor(TOP, true);
                self.c_to_edge(id, false);
            }
            ("end", true) => {
                self.move_cursor(BOTTOM, true);
                self.c_to_edge(id, true);
            }
            ("home" | "end", false) => self.select_to_edge(id, k.key == "end"),
            ("left" | "right", false) if c => self.c_step(id, k.key == "right"),
            _ => return false,
        }
        true
    }

    /// Shift+Home or Shift+End in pane `id`: in the listing the cursor's
    /// line selected; in the C to the line's end, or to where its code
    /// starts (from there, to its first column).
    fn select_to_edge(&mut self, id: PaneId, end: bool) {
        let document = self
            .layout
            .active(id)
            .and_then(|k| self.document(k))
            .cloned();
        let c = self.shows_c(id);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        if !c {
            state.listing.selection.leave(state.listing.cursor, true);
            self.moved(id);
            return;
        }
        let Some(document) = document else {
            return;
        };
        let at = TextPos::new(state.c.line, state.c.column);
        state.c.selection.leave(at, true);
        let len = document.line_text(state.c.line).chars().count();
        let code = indentation(&document, state.c.line);
        state.c.column = if end {
            len
        } else if state.c.column.min(len) == code {
            0
        } else {
            code
        };
        self.c_moved(id, &document);
    }

    /// Ctrl+Shift+Home or End in pane `id`'s C: the cursor to the first
    /// line's start or the last line's end.
    fn c_to_edge(&mut self, id: PaneId, end: bool) {
        if !self.shows_c(id) {
            return;
        }
        let Some(document) = self
            .layout
            .active(id)
            .and_then(|k| self.document(k))
            .cloned()
        else {
            return;
        };
        if let Some(state) = self.panes.get_mut(&id) {
            state.c.column = if end {
                document.line_text(state.c.line).chars().count()
            } else {
                0
            };
        }
        self.c_moved(id, &document);
    }

    /// Shift+Left or Shift+Right in pane `id`'s C: the selection extended
    /// by a character, across line breaks.
    fn c_step(&mut self, id: PaneId, right: bool) {
        let Some(document) = self
            .layout
            .active(id)
            .and_then(|k| self.document(k))
            .cloned()
        else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let len = |n: usize| document.line_text(n).chars().count();
        let (line, column) = (state.c.line, state.c.column.min(len(state.c.line)));
        state
            .c
            .selection
            .leave(TextPos::new(state.c.line, state.c.column), true);
        let (line, column) = if right {
            if column < len(line) {
                (line, column + 1)
            } else if line + 1 < document.lines.len() {
                (line + 1, 0)
            } else {
                (line, column)
            }
        } else if column > 0 {
            (line, column - 1)
        } else if let Some(before) = line.checked_sub(1) {
            (before, len(before))
        } else {
            (line, column)
        };
        state.c.line = line;
        state.c.column = column;
        self.c_moved(id, &document);
    }

    /// Pane `id`'s C cursor moved within `document` by a selection's key:
    /// its token under it, its line shown, the sync group told.
    fn c_moved(&mut self, id: PaneId, document: &CDocument) {
        let rows = self.rows(id, self.settings.c_line_height);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let text = document.line_text(state.c.line);
        state.c.span = document.span_at(state.c.line, byte_at(text, state.c.column));
        let total = document.lines.len() as u64;
        state.c.scroll.reveal(state.c.line as u64, total, rows, 2);
        self.moved(id);
    }

    /// Whether the focused pane shows text Select All takes: C, or the
    /// listing as text with its cursor in a function.
    pub fn selects_all(&self) -> bool {
        let id = self.layout.focused();
        if self.shows_c(id) {
            return self
                .layout
                .active(id)
                .and_then(|k| self.document(k))
                .is_some_and(|d| !d.lines.is_empty());
        }
        self.shows_listing_text(id) && self.listing_function(id).is_some()
    }

    /// The entry of the function holding pane `id`'s listing cursor.
    fn listing_function(&self, id: PaneId) -> Option<u64> {
        let listing = self.listing.as_ref()?;
        let line = listing.line(self.panes.get(&id)?.listing.cursor)?;
        listing.function_of(line.address).map(|(_, entry)| entry)
    }

    /// Select All in the focused pane: the C's whole text, or the
    /// listing's lines of the function under the cursor, its lit area
    /// (header to `endp`). The cursor goes to the start, the selection's
    /// fixed end to the end, so the view stays at the top.
    pub fn select_all(&mut self) {
        let id = self.layout.focused();
        if self.shows_c(id) {
            let Some(document) = self
                .layout
                .active(id)
                .and_then(|k| self.document(k))
                .cloned()
            else {
                return;
            };
            let Some(last) = document.lines.len().checked_sub(1) else {
                return;
            };
            let Some(state) = self.panes.get_mut(&id) else {
                return;
            };
            let end = TextPos::new(last, document.line_text(last).chars().count());
            state.c.selection.anchor = Some(end);
            state.c.selection.pressed = false;
            state.c.line = 0;
            state.c.column = 0;
            self.c_moved(id, &document);
            return;
        }
        if !self.shows_listing_text(id) {
            return;
        }
        let Some((first, last, total)) = self.listing_function(id).and_then(|entry| {
            let listing = self.listing.as_ref()?;
            let lines = listing.function_lines(entry)?;
            Some((lines.start, lines.end.checked_sub(1)?, listing.len()))
        }) else {
            return;
        };
        let rows = self.rows(id, self.settings.listing_line_height);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        state.listing.selection.anchor = Some(last);
        state.listing.selection.pressed = None;
        state.listing.cursor = first;
        state.listing.token = None;
        state
            .listing
            .scroll
            .reveal(state.listing.cursor, total, rows, 2);
        self.moved(id);
    }
}
