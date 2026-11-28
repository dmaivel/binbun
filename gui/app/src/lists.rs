//! The list tabs: the strings (Shift+F12), a filterable table of
//! address, size in bytes, encoding and text; and the cross-references to an item
//! (X), each reference as its line of C (the listing's line until
//! the C is here) with its function and address. Typing filters; arrows
//! move; a click goes there in a code pane's preview tab (a double click
//! pins it; Enter gives it the focus; Ctrl or the middle button: a new
//! tab).

use std::rc::Rc;
use std::sync::Arc;

use binbun_gui_view::cdoc::CDocument;
use binbun_gui_view::context::Surface;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::Role;
use binbun_gui_view::peek::how;
use binbun_gui_view::session::StringItem;
use binbun_gui_view::tabs::Opening;
use binbun_gui_view::{FunctionId, Stage, View};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, ClickEvent, Context, KeyDownEvent, MouseButton, MouseDownEvent, ScrollEvent,
    StyledText, TextRun, Window, div, px,
};

use crate::highlight::Highlight;
use crate::panes::measured;
use crate::scrolling::wheel;
use crate::sidebar::tabular;
use crate::tabs::row_click;
use crate::theme::hsla;
use crate::workspace::{ListState, ROW_PAD, TabKind, Workspace, f};

/// One reference as the cross-references tab shows it.
struct XrefRow {
    from: u64,
    kind: &'static str,
    function: Option<(FunctionId, u64)>,
}

/// The positions of `query` in `text` as a case-insensitive substring
/// (ASCII case), if it occurs.
fn find(text: &str, query: &str) -> Option<Vec<usize>> {
    if query.is_empty() {
        return Some(Vec::new());
    }
    let lower = text.to_ascii_lowercase();
    let at = lower.find(&query.to_ascii_lowercase())?;
    Some((at..at + query.len()).collect())
}

impl Workspace {
    /// The references to the `len` bytes from `of`, by target.
    fn xrefs_to(&self, of: u64, len: u64) -> Vec<XrefRow> {
        let (Some(listing), Some(db)) = (
            &self.listing,
            self.session
                .as_ref()
                .and_then(|s| s.database())
                .filter(|_| self.stage >= Stage::Referenced),
        ) else {
            return Vec::new();
        };
        db.references()
            .within(of..of.saturating_add(len))
            .iter()
            .map(|r| XrefRow {
                from: r.from,
                kind: how(r.kind),
                function: listing.function_of(r.from),
            })
            .collect()
    }

    /// A function's name as shown.
    pub(crate) fn shown_function(&self, entry: u64) -> String {
        self.listing
            .as_ref()
            .zip(self.session.as_ref())
            .and_then(|(l, s)| l.shown_name(entry, s.overlay()).map(str::to_owned))
            .unwrap_or_else(|| format!("sub_{entry:X}"))
    }

    /// Opens the cross-references to the name under the cursor, else to
    /// the cursor's item, else to its function (X).
    pub fn open_xrefs(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(listing) = self.listing.clone() else {
            return;
        };
        let Some(db) = self.session.as_ref().and_then(|s| s.database()) else {
            return;
        };
        let here = self.current_address();
        let candidates = [
            self.target_under_cursor(),
            here.and_then(|a| listing.line(listing.line_of(a)).map(|l| l.address)),
            here.and_then(|a| listing.function_of(a)).map(|(_, e)| e),
        ];
        let Some(of) = candidates
            .into_iter()
            .flatten()
            .find(|&a| !db.references().to(a).is_empty())
            .or(here)
        else {
            return;
        };
        self.open_xrefs_to(of, 1, window, cx);
    }

    /// Opens the cross-references to the `len` bytes from `of` in the
    /// bottom dock ([`Workspace::open_below`]).
    pub fn open_xrefs_to(
        &mut self,
        of: u64,
        len: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let id = self.open_below(TabKind::Xrefs { of, len }, true, cx);
        if let Some(state) = self.panes.get_mut(&id) {
            state.list = ListState::default();
        }
        self.refresh_list(id);
        self.ensure_documents();
        self.focus_pane(id, window, cx);
    }

    /// The functions whose C the shown cross-references want.
    pub fn xref_functions(&self) -> Vec<FunctionId> {
        let mut out = Vec::new();
        for pane in self.layout.panes() {
            let Some(&TabKind::Xrefs { of, len }) = pane.tabs.get(pane.active).map(|t| &t.content)
            else {
                continue;
            };
            let Some(state) = self.panes.get(&pane.id) else {
                continue;
            };
            let refs = self.xrefs_to(of, len);
            let rows = self.rows(pane.id, self.ui_line() + ROW_PAD);
            for (i, _) in state
                .list
                .rows
                .iter()
                .skip(usize::try_from(state.list.scroll.anchor.line).unwrap_or(usize::MAX))
                .take(usize::try_from(rows).unwrap_or(0))
            {
                if let Some((f, _)) = refs.get(*i).and_then(|r| r.function)
                    && !out.contains(&f)
                {
                    out.push(f);
                }
            }
        }
        out
    }

    /// Makes pane `id`'s list rows again if its list or filter changed.
    pub fn refresh_list(&mut self, id: PaneId) {
        let Some(kind) = self.layout.active(id).cloned() else {
            return;
        };
        let (refs, strings) = match &kind {
            TabKind::Xrefs { of, len } => (self.xrefs_to(*of, *len), false),
            TabKind::Strings => (Vec::new(), true),
            TabKind::Folder(key) => {
                self.refresh_folder(id, key);
                return;
            }
            TabKind::Listing
            | TabKind::C { .. }
            | TabKind::Settings
            | TabKind::Console
            | TabKind::Terminal(_)
            | TabKind::Struct(_)
            | TabKind::Found(_) => return,
        };
        let len = if strings {
            self.strings.len()
        } else {
            refs.len()
        };
        let Some(state) = self.panes.get(&id) else {
            return;
        };
        if state.list.made_for.as_ref() == Some(&(kind.clone(), len)) {
            return;
        }
        let query = state.list.query.clone();
        let rows: Vec<(usize, Vec<usize>)> = if strings {
            self.strings
                .iter()
                .enumerate()
                .filter_map(|(i, s)| find(&shown_string(s), &query).map(|p| (i, p)))
                .collect()
        } else {
            refs.iter()
                .enumerate()
                .filter_map(|(i, r)| {
                    let name = r
                        .function
                        .map(|(_, e)| self.shown_function(e))
                        .unwrap_or_default();
                    find(&name, &query).map(|_| (i, Vec::new()))
                })
                .collect()
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let list = &mut state.list;
        list.rows = rows;
        list.made_for = Some((kind, len));
        list.selected = list.selected.min(list.rows.len().saturating_sub(1));
        let line = list.scroll.anchor.line.min(list.selected as u64);
        if line != list.scroll.anchor.line {
            list.scroll.reset();
            list.scroll.anchor.line = line;
        }
    }

    /// The address of pane `id`'s selected list row.
    pub fn list_target(&self, id: PaneId) -> Option<u64> {
        let state = self.panes.get(&id)?;
        let (i, _) = state.list.rows.get(state.list.selected)?;
        match self.layout.active(id)? {
            TabKind::Strings => self.strings.get(*i).map(|s| s.address),
            TabKind::Xrefs { of, len } => self.xrefs_to(*of, *len).get(*i).map(|r| r.from),
            TabKind::Folder(key) => self.folder_target(id, key),
            TabKind::Listing
            | TabKind::C { .. }
            | TabKind::Settings
            | TabKind::Console
            | TabKind::Terminal(_)
            | TabKind::Struct(_)
            | TabKind::Found(_) => None,
        }
    }

    /// The pane showing code that navigation from a list or the map opens
    /// in: the listing first, the focused pane first among equals, never
    /// `except`.
    pub fn code_pane(&self, except: Option<PaneId>) -> Option<PaneId> {
        let focused = self.layout.focused();
        self.layout
            .panes()
            .filter(|p| Some(p.id) != except)
            .filter_map(|p| Some((p.id, &p.tabs.get(p.active)?.content)))
            .filter(|(_, kind)| matches!(kind, TabKind::Listing | TabKind::C { .. }))
            .min_by_key(|&(id, kind)| (!matches!(kind, TabKind::Listing), id != focused))
            .map(|(id, _)| id)
    }

    /// Opens `address` from pane `from` (a list's; the map gives
    /// [`Self::code_pane`]) as `opening` says ([`Workspace::open_at`]: in
    /// the linked panes, else in a new window tab). The code pane gets the
    /// focus unless the opening keeps it where it was. An address no
    /// section holds goes where [`Self::list_landing`] says.
    pub fn open_from_list(
        &mut self,
        from: PaneId,
        address: u64,
        opening: Opening,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(address) = self.list_landing(address) else {
            cx.notify();
            return;
        };
        self.open_at(from, address, opening, window, cx);
    }

    /// Where a list's `address` is shown: itself if a section holds it;
    /// else its last byte before if that ends a section (`_end`,
    /// `_edata`: a symbol marking a section's end holds no byte, so no
    /// line of the listing); else nowhere, the status bar saying why.
    fn list_landing(&mut self, address: u64) -> Option<u64> {
        let (Some(listing), Some(session)) = (&self.listing, &self.session) else {
            return Some(address);
        };
        let overlay = session.overlay();
        // `find` reads a hexadecimal address only if a section holds it.
        let mapped = |a: u64| listing.find(&format!("{a:X}"), overlay) == Some(a);
        if mapped(address) {
            return Some(address);
        }
        let before = address.checked_sub(1).filter(|&a| mapped(a));
        if before.is_some() {
            return before;
        }
        let name = listing
            .shown_name(address, overlay)
            .map_or_else(|| format!("{address:X}"), |n| format!("{n} ({address:X})"));
        self.error = Some(format!("{name} is outside every section of the image"));
        None
    }

    /// A click on row `k` of pane `id`'s list: selected, and its target
    /// opened as the click says (a folder's type: in the struct editor).
    pub(crate) fn list_row_click(
        &mut self,
        id: PaneId,
        k: usize,
        e: &ClickEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(s) = self.panes.get_mut(&id) {
            s.list.selected = k;
        }
        let opening = row_click(e, cx).on_row();
        self.list_open(id, opening, window, cx);
        cx.notify();
    }

    /// Opens pane `id`'s list's selected row as `opening` says: its
    /// address, or a folder's type in the struct editor.
    pub(crate) fn list_open(
        &mut self,
        id: PaneId,
        opening: Opening,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(address) = self.list_target(id) {
            self.open_from_list(id, address, opening, window, cx);
        } else if let Some(TabKind::Folder(key)) = self.layout.active(id).cloned() {
            self.open_folder_type(id, &key, window, cx);
        }
    }

    pub(crate) fn list_keys(
        &mut self,
        id: PaneId,
        e: &KeyDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let m = e.keystroke.modifiers;
        if m.control || m.alt || m.platform {
            return;
        }
        let rows = usize::try_from(self.rows(id, self.ui_line() + ROW_PAD)).unwrap_or(10);
        let page = rows.saturating_sub(2).max(1);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let list = &mut state.list;
        let end = list.rows.len().saturating_sub(1);
        match e.keystroke.key.as_str() {
            "up" => list.selected = list.selected.saturating_sub(1),
            "down" => list.selected = (list.selected + 1).min(end),
            "pageup" => list.selected = list.selected.saturating_sub(page),
            "pagedown" => list.selected = (list.selected + page).min(end),
            "home" => list.selected = 0,
            "end" => list.selected = end,
            "enter" => {
                self.list_open(id, Opening::Linked { focus: true }, window, cx);
                cx.stop_propagation();
                return;
            }
            "escape" => {
                list.query.clear();
                list.made_for = None;
                list.selected = 0;
            }
            "backspace" => {
                list.query.pop();
                list.made_for = None;
                list.selected = 0;
            }
            _ => {
                let Some(text) = e
                    .keystroke
                    .key_char
                    .as_deref()
                    .filter(|t| !t.is_empty() && !t.chars().any(char::is_control))
                else {
                    return;
                };
                list.query.push_str(text);
                list.made_for = None;
                list.selected = 0;
            }
        }
        // Under the header: the rows but one.
        let shown = rows.saturating_sub(1).max(1);
        list.scroll.reveal(
            list.selected as u64,
            list.rows.len() as u64,
            shown as u64,
            0,
        );
        self.ensure_documents();
        cx.stop_propagation();
        cx.notify();
    }

    /// A list tab's content: a header of column titles over the rows.
    #[expect(clippy::too_many_lines, reason = "the two lists' columns")]
    pub fn render_list(&mut self, id: PaneId, cx: &mut Context<Self>) -> AnyElement {
        self.refresh_list(id);
        let theme = self.theme;
        let row_h = self.row(self.ui_line() + ROW_PAD);
        let rows = usize::try_from(self.rows(id, self.ui_line() + ROW_PAD)).unwrap_or(0);
        let kind = self.layout.active(id).cloned();
        let focused = self.layout.focused() == id;
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        let bounds = Rc::clone(&state.bounds);
        // Under the header: the rows but one.
        let body_rows = rows.saturating_sub(1).max(1) as u64;
        let first = usize::try_from(state.list.scroll.anchor.line).unwrap_or(usize::MAX);
        let column = |w: f32| {
            div()
                .flex_none()
                .w(self.z(w))
                .overflow_hidden()
                .whitespace_nowrap()
        };
        let mut body = div()
            .id(("list-rows", id.0))
            .flex_1()
            .min_h_0()
            .relative()
            .overflow_hidden()
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                if let Some(s) = this.panes.get_mut(&id) {
                    let total = s.list.rows.len() as u64;
                    s.list.scroll.wheel(wheel(e), row_h, total, body_rows);
                }
                this.ensure_documents();
                cx.notify();
            }))
            .child(measured(bounds).absolute().size_full());
        let is_strings = kind == Some(TabKind::Strings);
        let header = if is_strings {
            div()
                .child(column(96.0).child("Address"))
                .child(column(64.0).child("Size"))
                .child(column(64.0).child("Kind"))
                .child(div().flex_1().child("Text"))
        } else {
            div()
                .child(column(220.0).child("Function"))
                .child(column(96.0).child("Address"))
                .child(column(64.0).child("Kind"))
                .child(div().flex_1().child("Line"))
        };
        let header = header
            .flex()
            .flex_none()
            .items_center()
            .h(px(row_h))
            .px(self.z(12.0))
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .text_color(hsla(theme.text_muted));
        let refs = match &kind {
            Some(TabKind::Xrefs { of, len }) => self.xrefs_to(*of, *len),
            Some(
                TabKind::Listing
                | TabKind::C { .. }
                | TabKind::Settings
                | TabKind::Console
                | TabKind::Terminal(_)
                | TabKind::Strings
                | TabKind::Struct(_)
                | TabKind::Found(_)
                | TabKind::Folder(_),
            )
            | None => Vec::new(),
        };
        let strings: &[StringItem] = &self.strings;
        let view = self.default_view();
        for (k, (i, positions)) in state
            .list
            .rows
            .iter()
            .enumerate()
            .skip(first)
            .take(rows + 1)
        {
            let selected = k == state.list.selected;
            let y = f((k - first) as u64) * row_h - state.list.scroll.anchor.offset;
            let mut row = div()
                .id(("list-row", k))
                .absolute()
                .top(px(y))
                .left_0()
                .right_0()
                .h(px(row_h))
                .px(self.z(12.0))
                .flex()
                .items_center()
                .whitespace_nowrap()
                .overflow_hidden()
                .when(selected, |d| {
                    d.bg(hsla(if focused {
                        theme.element_selected
                    } else {
                        theme.element_hover
                    }))
                })
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                        if let Some(s) = this.panes.get_mut(&id) {
                            s.list.selected = k;
                        }
                        this.focus_pane(id, window, cx);
                        this.menu_subject = this.list_target(id);
                        if this.menu_subject.is_some() {
                            this.open_context_menu(Surface::Row, e.position, window, cx);
                        }
                    }),
                )
                .on_click(cx.listener(move |this, e: &ClickEvent, window, cx| {
                    this.list_row_click(id, k, e, window, cx);
                }))
                .on_aux_click(cx.listener(move |this, e: &ClickEvent, window, cx| {
                    if e.is_middle_click() {
                        this.list_row_click(id, k, e, window, cx);
                    }
                }));
            if is_strings {
                let Some(s) = strings.get(*i) else {
                    continue;
                };
                let mut runs = Vec::new();
                let mut at = 0;
                if let (Some(&first), Some(&end)) = (positions.first(), positions.last()) {
                    runs.push(self.text_run(first, theme.string, None));
                    runs.push(self.text_run(
                        end + 1 - first,
                        theme.string,
                        Some(theme.search_match),
                    ));
                    at = end + 1;
                }
                let text = shown_string(s);
                runs.push(self.text_run(text.len().saturating_sub(at), theme.string, None));
                let runs: Vec<TextRun> = runs.into_iter().filter(|r| r.len > 0).collect();
                row = row
                    .child(
                        column(96.0)
                            .font_features(tabular())
                            .text_color(hsla(theme.text_muted))
                            .child(format!("{:X}", s.address)),
                    )
                    .child(
                        column(64.0)
                            .font_features(tabular())
                            .text_color(hsla(theme.text_muted))
                            .child(s.size.to_string()),
                    )
                    .child(
                        column(64.0)
                            .text_color(hsla(theme.text_muted))
                            .child(string_kind(s)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .font_family(self.settings.code_font.clone())
                            .text_size(px(self.code_size()))
                            .child(StyledText::new(text).with_runs(runs)),
                    );
            } else {
                let Some(r) = refs.get(*i) else {
                    continue;
                };
                let name = r
                    .function
                    .map(|(_, e)| self.shown_function(e))
                    .unwrap_or_default();
                let (text, runs) = self.excerpt(r, view);
                row = row
                    .child(column(220.0).pr(self.z(12.0)).text_ellipsis().child(name))
                    .child(
                        column(96.0)
                            .font_features(tabular())
                            .text_color(hsla(theme.text_muted))
                            .child(format!("{:X}", r.from)),
                    )
                    .child(
                        column(64.0)
                            .text_color(hsla(theme.text_muted))
                            .child(r.kind),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .font_family(self.settings.code_font.clone())
                            .text_size(px(self.code_size()))
                            .child(StyledText::new(text).with_runs(runs)),
                    );
            }
            body = body.child(row);
        }
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        div()
            .id(("list", id.0))
            .key_context("List")
            .track_focus(&state.focus)
            .size_full()
            .flex()
            .flex_col()
            .bg(hsla(theme.editor))
            .rounded_b(self.island_corner())
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, window, cx| this.focus_pane(id, window, cx)),
            )
            .capture_key_down(cx.listener(move |this, e: &KeyDownEvent, window, cx| {
                this.list_keys(id, e, window, cx);
            }))
            .child(header)
            .child(body)
            .into_any_element()
    }

    /// Reference `r`'s line: its C when its function's is here (trimmed),
    /// else its listing line without the address prefix.
    fn excerpt(&self, r: &XrefRow, view: View) -> (String, Vec<TextRun>) {
        let theme = self.theme;
        let document: Option<&Arc<CDocument>> = r
            .function
            .and_then(|(f, _)| self.session.as_ref()?.document(f, view));
        if let Some(document) = document
            && let Some(n) = document.line_for(r.from)
        {
            let shown = document.shown_line(n, None);
            let indent = shown.text.len() - shown.text.trim_start().len();
            let mut runs = Vec::new();
            for piece in &shown.pieces {
                let start = piece.range.start.max(indent);
                if start >= piece.range.end {
                    continue;
                }
                let len = piece.range.end - start;
                let color = piece
                    .span
                    .and_then(|s| document.spans.get(s))
                    .map_or(theme.variable, |span| theme.c(span));
                runs.push(self.text_run(len, color, None));
            }
            return (shown.text.get(indent..).unwrap_or("").to_owned(), runs);
        }
        let (Some(listing), Some(session)) = (&self.listing, &self.session) else {
            return (String::new(), Vec::new());
        };
        let Some(db) = session.database() else {
            return (String::new(), Vec::new());
        };
        let rendered = listing.render(db, listing.line_of(r.from), session.overlay());
        let mut text = String::new();
        let mut runs = Vec::new();
        for t in rendered
            .tokens
            .iter()
            .skip_while(|t| matches!(t.role, Role::Prefix | Role::Space))
        {
            if t.text.is_empty() {
                continue;
            }
            // The listing's alignment, one space here.
            let t_text = if t.text.trim().is_empty() {
                if text.is_empty() || text.ends_with(' ') {
                    continue;
                }
                " "
            } else if text.is_empty() {
                t.text.trim_start()
            } else {
                t.text.as_str()
            };
            if t_text.is_empty() {
                continue;
            }
            text.push_str(t_text);
            runs.push(self.text_run(t_text.len(), theme.token(t), None));
        }
        (text, runs)
    }
}

/// A string's kind as the strings tab says it.
fn string_kind(s: &StringItem) -> &'static str {
    if s.wide {
        "UTF-16"
    } else if s.text.is_ascii() {
        "ASCII"
    } else {
        "UTF-8"
    }
}

/// A string as one line: its control characters escaped (`\n`).
fn shown_string(s: &StringItem) -> String {
    s.text.escape_debug().to_string()
}

#[cfg(test)]
mod tests {
    use binbun_gui_view::session::StringItem;

    use super::{find, shown_string};

    #[test]
    fn the_filter_is_a_case_blind_substring_of_the_shown_line() {
        let s = StringItem {
            address: 0x10,
            text: "\nUsage:\t%s".to_owned(),
            size: 10,
            wide: false,
        };
        let shown = shown_string(&s);
        assert_eq!(shown, "\\nUsage:\\t%s");
        assert_eq!(find(&shown, "usage"), Some(vec![2, 3, 4, 5, 6]));
        assert_eq!(find(&shown, "\\t%"), Some(vec![8, 9, 10]));
        assert_eq!(find(&shown, "usages"), None);
        assert_eq!(find(&shown, ""), Some(Vec::new()));
    }
}
