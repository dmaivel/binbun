//! The cross-references tab's callers mode (every call decompiled in one
//! table, kept as a work-list): every call of the
//! function with its caller, the call's address, its C line and a column
//! per argument with what is known of it there (a constant, a range),
//! sortable by any column (a click on its title; again, the other way).
//! The tab can be kept (a preview tab pinned) as a work-list.

use binbun::calls::Node;
use binbun_gui_view::calls::{CallerRow, SortBy, argument_columns, argument_text, sort_rows};
use binbun_gui_view::commands::Command;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::{Answer, Asked, Question};
use gpui_kit::assets::IconName;
use gpui_kit::prelude::*;
use gpui_kit::{AnyElement, ClickEvent, Context, ElementId, MouseButton, Window, div, px};

use crate::sidebar::tabular;
use crate::tabs::row_click;
use crate::theme::hsla;
use crate::workspace::{ROW_PAD, TabKind, Workspace};

/// A cross-references tab's callers table.
#[derive(Default)]
pub struct CallersTab {
    /// Whether the tab shows it (else the references).
    pub on: bool,
    /// The function whose callers it lists (its entry).
    of: u64,
    /// The rows, in the order shown.
    rows: Vec<CallerRow>,
    /// What they are sorted by, and whether descending.
    sort: SortBy,
    descending: bool,
    /// The selected row.
    selected: usize,
    /// The question asked and not answered.
    asked: Option<Asked>,
}

impl Workspace {
    /// Whether pane `id` shows its cross-references tab as the callers
    /// table.
    pub fn shows_callers(&self, id: PaneId) -> bool {
        let Some(TabKind::Xrefs { of, .. }) = self.layout.active(id) else {
            return false;
        };
        self.calls
            .callers
            .get(&id)
            .is_some_and(|t| t.on && t.of == *of)
    }

    /// Switches the focused cross-references tab between the references
    /// and the callers table (asking for the callers' lines).
    pub fn toggle_caller_arguments(&mut self, id: PaneId) {
        let Some(TabKind::Xrefs { of, .. }) = self.layout.active(id).cloned() else {
            return;
        };
        if self.shows_callers(id) {
            if let Some(tab) = self.calls.callers.get_mut(&id) {
                tab.on = false;
            }
            return;
        }
        let Some(Node::Function(function)) = self.node_at(of) else {
            return;
        };
        let view = self.default_view();
        let Some(session) = &self.session else {
            return;
        };
        let asked = session.ask(function, view, Question::Callers);
        let tab = self.calls.callers.entry(id).or_default();
        if let Some(old) = tab.asked.replace(asked) {
            old.cancel();
        }
        if tab.of != of {
            tab.rows.clear();
            tab.selected = 0;
        }
        tab.of = of;
        tab.on = true;
    }

    /// Takes `answer` if it answers a callers table's question; whether
    /// it did.
    pub fn callers_answer(&mut self, request: u64, answer: &Answer) -> bool {
        let Answer::Calls(sites) = answer else {
            return false;
        };
        let Some(id) = self
            .calls
            .callers
            .iter()
            .find(|(_, t)| t.asked.as_ref().is_some_and(|a| a.request == request))
            .map(|(&id, _)| id)
        else {
            return false;
        };
        let rows: Vec<CallerRow> = sites
            .iter()
            .map(|site| {
                let entry = self
                    .session
                    .as_ref()
                    .and_then(|s| s.database()?.function(site.call.caller))
                    .map_or(0, |f| f.entry);
                CallerRow {
                    site: site.call.site,
                    caller: entry,
                    name: self.node_name(Node::Function(site.call.caller)).0,
                    line: site.line.clone(),
                    arguments: site.arguments.clone(),
                }
            })
            .collect();
        if let Some(tab) = self.calls.callers.get_mut(&id) {
            tab.asked = None;
            tab.rows = rows;
            sort_rows(&mut tab.rows, tab.sort, tab.descending);
        }
        true
    }

    /// A click on row `k` of pane `id`'s callers table: selected, its call
    /// site opened as the click says.
    fn callers_row_click(
        &mut self,
        id: PaneId,
        k: usize,
        site: u64,
        e: &ClickEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(t) = self.calls.callers.get_mut(&id) {
            t.selected = k;
        }
        let opening = row_click(e, cx).on_row();
        self.open_from_list(id, site, opening, window, cx);
        cx.notify();
    }

    /// Sorts pane `id`'s callers table by `by` (again: the other way).
    fn sort_callers(&mut self, id: PaneId, by: SortBy) {
        let Some(tab) = self.calls.callers.get_mut(&id) else {
            return;
        };
        tab.descending = tab.sort == by && !tab.descending;
        tab.sort = by;
        sort_rows(&mut tab.rows, by, tab.descending);
    }

    /// The cross-references tab's tools in pane `id`'s toolbar: the
    /// callers table's toggle and keeping the tab.
    pub fn xrefs_tools(&self, id: PaneId, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !matches!(self.layout.active(id), Some(TabKind::Xrefs { .. })) {
            return None;
        }
        let facts = self.facts();
        let preview = self
            .layout
            .pane(id)
            .and_then(|p| p.tabs.get(p.active))
            .is_some_and(|t| t.preview);
        let focus = move |this: &mut Self| {
            this.layout.focus(id);
        };
        Some(
            div()
                .flex()
                .items_center()
                .gap(self.z(2.0))
                .when(preview, |d| {
                    d.child(
                        self.icon_button(
                            ("keep-tab", id.0),
                            IconName::Pin,
                            Command::KeepTab,
                            true,
                            false,
                            cx,
                        )
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, _| focus(this)),
                        ),
                    )
                })
                .child(
                    self.icon_button(
                        ("caller-arguments", id.0),
                        IconName::Columns2,
                        Command::CallerArguments,
                        facts.stage >= 3 && self.node_at_tab(id),
                        self.shows_callers(id),
                        cx,
                    )
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, _| focus(this)),
                    ),
                )
                .into_any_element(),
        )
    }

    /// Whether pane `id`'s cross-references are to a function.
    fn node_at_tab(&self, id: PaneId) -> bool {
        matches!(
            self.layout.active(id),
            Some(TabKind::Xrefs { of, .. }) if matches!(self.node_at(*of), Some(Node::Function(_)))
        )
    }

    /// Pane `id`'s callers table: a header of column titles (a click
    /// sorts) over the rows (a double click goes to the call).
    #[expect(
        clippy::too_many_lines,
        reason = "the columns, the header and the rows"
    )]
    pub fn render_callers(&mut self, id: PaneId, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let row_h = self.row(self.ui_line() + ROW_PAD);
        let focused = self.layout.focused() == id;
        let code = self.settings.code_font.clone();
        let code_size = px(self.code_size());
        let Some(tab) = self.calls.callers.get(&id) else {
            return div().into_any_element();
        };
        let columns = argument_columns(&tab.rows);
        let column = |w: f32| {
            div()
                .flex_none()
                .w(self.z(w))
                .pr(self.z(8.0))
                .overflow_hidden()
                .whitespace_nowrap()
                .text_ellipsis()
        };
        let (sort, descending) = (tab.sort, tab.descending);
        let title = |text: String, by: SortBy, w: Option<f32>, cx: &mut Context<Self>| {
            let arrow = (sort == by).then_some(if descending { " ↓" } else { " ↑" });
            let cell = match w {
                Some(w) => column(w),
                None => div().flex_1().min_w_0(),
            };
            cell.id(title_id(by))
                .cursor_pointer()
                .hover(|s| s.text_color(hsla(theme.text)))
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    this.sort_callers(id, by);
                    cx.notify();
                }))
                .child(format!("{text}{}", arrow.unwrap_or("")))
        };
        let mut header = div()
            .flex()
            .flex_none()
            .items_center()
            .h(px(row_h))
            .px(self.z(12.0))
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .text_color(hsla(theme.text_muted))
            .child(title(
                "Function".to_owned(),
                SortBy::Caller,
                Some(200.0),
                cx,
            ))
            .child(title("Address".to_owned(), SortBy::Site, Some(96.0), cx));
        for k in 0..columns {
            header = header.child(title(
                format!("a{}", k + 1),
                SortBy::Argument(k),
                Some(110.0),
                cx,
            ));
        }
        header = header.child(title("Line".to_owned(), SortBy::Line, None, cx));
        let mut body = div()
            .id(("callers-rows", id.0))
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col();
        let pending = tab.asked.is_some() && tab.rows.is_empty();
        for (k, r) in tab.rows.iter().enumerate() {
            let selected = k == tab.selected;
            let site = r.site;
            let mut row = div()
                .id(("callers-row", k))
                .flex_none()
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
                .on_click(cx.listener(move |this, e: &ClickEvent, window, cx| {
                    this.callers_row_click(id, k, site, e, window, cx);
                }))
                .on_aux_click(cx.listener(move |this, e: &ClickEvent, window, cx| {
                    if e.is_middle_click() {
                        this.callers_row_click(id, k, site, e, window, cx);
                    }
                }))
                .child(
                    column(200.0)
                        .text_color(hsla(theme.function))
                        .child(r.name.clone()),
                )
                .child(
                    column(96.0)
                        .font_features(tabular())
                        .text_color(hsla(theme.text_muted))
                        .child(format!("{:X}", r.site)),
                );
            for c in 0..columns {
                let text = r.arguments.get(c).map(argument_text).unwrap_or_default();
                row = row.child(
                    column(110.0)
                        .font_family(code.clone())
                        .text_size(code_size)
                        .text_color(hsla(theme.number))
                        .child(text),
                );
            }
            row = row.child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .text_ellipsis()
                    .font_family(code.clone())
                    .text_size(code_size)
                    .child(r.line.clone().unwrap_or_default()),
            );
            body = body.child(row);
        }
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        div()
            .id(("callers", id.0))
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
            .child(header)
            .when(pending, |d| {
                d.child(
                    div()
                        .px(self.z(12.0))
                        .h(px(row_h))
                        .text_color(hsla(theme.text_placeholder))
                        .child("…"),
                )
            })
            .child(body)
            .into_any_element()
    }
}

/// A column title's element id, by what it sorts.
fn title_id(by: SortBy) -> ElementId {
    match by {
        SortBy::Site => "sort-site".into(),
        SortBy::Caller => "sort-caller".into(),
        SortBy::Line => "sort-line".into(),
        SortBy::Argument(k) => ("sort-argument", k).into(),
    }
}
