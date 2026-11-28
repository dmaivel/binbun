//! A folder of the map as a tab (Open as Tab): its
//! items as a table (`binbun_gui_view::folder`), the name and address
//! and the columns the kind has (a function's or a section's size, an
//! import's library, a global's type), sorted by a click on a column's
//! title (again: the other way), filtered by typing as the other lists;
//! a click or Enter goes there as in the other lists. The bookmarks'
//! folder opens the Bookmarks tab (`Ctrl+M`) instead.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use binbun_gui_view::Stage;
use binbun_gui_view::commands::Command;
use binbun_gui_view::context::Surface;
use binbun_gui_view::folder::{self, Column, Row, Sort, declared_type};
use binbun_gui_view::layout::{PaneId, TabId};
use binbun_gui_view::map::{Group, Kind};
use binbun_gui_view::session::StringItem;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, ClickEvent, Context, ElementId, KeyDownEvent, MouseButton, MouseDownEvent,
    ScrollEvent, StyledText, TextRun, Window, div, font, px,
};

use crate::panes::measured;
use crate::scrolling::wheel;
use crate::sidebar::tabular;
use crate::theme::hsla;
use crate::workspace::{ListState, ROW_PAD, TabKind, Workspace, f};

/// The map's folders opened as tabs.
#[derive(Default)]
pub struct FolderUi {
    /// Each folder's rows, by key, with the tree's build they are of.
    rows: HashMap<String, (u64, Arc<Vec<Row>>)>,
    /// Each folder tab's sort.
    sort: HashMap<TabId, Sort>,
}

/// A column's width (logical; the last takes the rest).
fn width(column: Column) -> f32 {
    match column {
        Column::Name => 320.0,
        Column::Address => 110.0,
        Column::Size | Column::Refs => 80.0,
        Column::Library => 200.0,
        Column::Type => 240.0,
    }
}

/// A column title's element id.
fn title_id(column: Column) -> ElementId {
    match column {
        Column::Name => "folder-sort-name".into(),
        Column::Address => "folder-sort-address".into(),
        Column::Size => "folder-sort-size".into(),
        Column::Library => "folder-sort-library".into(),
        Column::Type => "folder-sort-type".into(),
        Column::Refs => "folder-sort-refs".into(),
    }
}

impl Workspace {
    /// Opens the map's folder `key` as a list ([`Workspace::open_list`];
    /// the bookmarks' as the Bookmarks tab).
    pub fn open_folder(&mut self, key: String, window: &mut Window, cx: &mut Context<Self>) {
        if Group::of_key(&key) == Some(Group::Bookmarks) {
            self.run(Command::Bookmarks, window, cx);
            return;
        }
        let kind = TabKind::Folder(key);
        // One tab of a folder: brought back if open.
        let open = self
            .layout
            .panes()
            .find_map(|p| Some((p.id, p.tabs.iter().position(|t| t.content == kind)?)));
        let id = if let Some((id, index)) = open {
            self.layout.activate(id, index);
            id
        } else {
            let id = self.open_below(self.layout.focused(), kind, false, cx);
            if let Some(state) = self.panes.get_mut(&id) {
                state.list = ListState::default();
            }
            id
        };
        self.refresh_list(id);
        self.focus_pane(id, window, cx);
    }

    /// The tree's build the folder tabs' rows are of.
    fn map_built(&self) -> u64 {
        self.sidebar.as_ref().map_or(0, |s| s.built)
    }

    /// Folder `key`'s rows, made once per build of the tree.
    pub fn folder_rows(&mut self, key: &str) -> Arc<Vec<Row>> {
        let built = self.map_built();
        if let Some((of, rows)) = self.folders.rows.get(key)
            && *of == built
        {
            return Arc::clone(rows);
        }
        let rows = Arc::new(self.make_folder_rows(key));
        self.folders.rows.retain(|_, (of, _)| *of == built);
        self.folders
            .rows
            .insert(key.to_owned(), (built, Arc::clone(&rows)));
        rows
    }

    /// Folder `key`'s rows from the tree: its items, its folders' too.
    fn make_folder_rows(&self, key: &str) -> Vec<Row> {
        let Some(map) = self.sidebar.as_ref().map(|s| &s.map) else {
            return Vec::new();
        };
        let Some(folder) = map.folder(key) else {
            return Vec::new();
        };
        let leaves = map.leaves(folder);
        let session = self.session.as_ref();
        let db = session.and_then(|s| s.database());
        let group = Group::of_key(key);
        // The references are counted once the analysis has found them
        // (the map is built again then).
        let references = (group == Some(Group::Functions) && self.stage >= Stage::Referenced)
            .then_some(db)
            .flatten()
            .map(binbun::Database::references);
        // The functions' sizes (their blocks' bytes), by entry.
        let sizes: HashMap<u64, u64> = match (group, db) {
            (Some(Group::Functions), Some(db)) => {
                let program = db.program();
                db.functions()
                    .map(|(_, function)| {
                        let size = function
                            .blocks
                            .iter()
                            .filter_map(|&b| program.blocks.get(b))
                            .map(|b| b.end - b.start)
                            .sum();
                        (function.entry, size)
                    })
                    .collect()
            }
            (Some(Group::Sections), Some(db)) => db
                .image()
                .sections
                .iter()
                .map(|s| (s.start, s.size))
                .collect(),
            _ => HashMap::new(),
        };
        let strings: HashMap<u64, &StringItem> = if group == Some(Group::Data) {
            self.strings.iter().map(|s| (s.address, s)).collect()
        } else {
            HashMap::new()
        };
        leaves
            .into_iter()
            .filter_map(|(n, holder)| {
                let node = map.node(n)?;
                let library = (node.kind == Kind::Import)
                    .then(|| map.node(holder))
                    .flatten()
                    .filter(|h| h.kind == Kind::Library)
                    .map(|h| h.name.clone());
                let ty = (node.kind == Kind::Data)
                    .then(|| {
                        let typed = session?.global_type(node.address?)?;
                        declared_type(typed.c.as_deref()?, &typed.name)
                    })
                    .flatten()
                    .or_else(|| {
                        // A string: its characters' array, its terminator in.
                        let s = strings.get(&node.address?)?;
                        Some(if s.wide {
                            format!("char16_t[{}]", s.size / 2 + 1)
                        } else {
                            format!("char[{}]", s.size + 1)
                        })
                    });
                Some(Row {
                    name: node.name.clone(),
                    address: node.address,
                    size: node.address.and_then(|a| sizes.get(&a).copied()),
                    library,
                    ty,
                    refs: node.address.zip(references).map(|(a, r)| r.to(a).len()),
                })
            })
            .collect()
    }

    /// Folder tab `id`'s rows again from its rows, sort and filter.
    pub fn refresh_folder(&mut self, id: PaneId, key: &str) {
        let built = usize::try_from(self.map_built()).unwrap_or(usize::MAX);
        let kind = TabKind::Folder(key.to_owned());
        if self
            .panes
            .get(&id)
            .is_some_and(|s| s.list.made_for.as_ref() == Some(&(kind.clone(), built)))
        {
            return;
        }
        let rows = self.folder_rows(key);
        let sort = self.folder_sort(id);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let list = &mut state.list;
        list.rows = folder::filtered(&rows, &folder::order(&rows, sort), &list.query);
        list.made_for = Some((kind, built));
        list.selected = list.selected.min(list.rows.len().saturating_sub(1));
        let line = list.scroll.anchor.line.min(list.selected as u64);
        if line != list.scroll.anchor.line {
            list.scroll.reset();
            list.scroll.anchor.line = line;
        }
    }

    /// Pane `id`'s folder tab's sort.
    fn folder_sort(&self, id: PaneId) -> Sort {
        self.layout
            .active_tab(id)
            .and_then(|t| self.folders.sort.get(&t).copied())
            .unwrap_or_default()
    }

    /// A click on a column's title: sorted by it (again: the other way),
    /// the selected row kept.
    fn sort_folder(&mut self, id: PaneId, by: Column) {
        let Some(tab) = self.layout.active_tab(id) else {
            return;
        };
        let sort = self.folder_sort(id).toggled(by);
        self.folders.sort.insert(tab, sort);
        let kept = self
            .panes
            .get(&id)
            .and_then(|s| s.list.rows.get(s.list.selected).map(|(i, _)| *i));
        if let Some(state) = self.panes.get_mut(&id) {
            state.list.made_for = None;
        }
        if let Some(TabKind::Folder(key)) = self.layout.active(id).cloned() {
            self.refresh_folder(id, &key);
        }
        if let Some(state) = self.panes.get_mut(&id)
            && let Some(i) = kept
            && let Some(k) = state.list.rows.iter().position(|(r, _)| *r == i)
        {
            state.list.selected = k;
        }
    }

    /// Folder tab `id`'s selected row's address (of its rows as drawn).
    pub fn folder_target(&self, id: PaneId, key: &str) -> Option<u64> {
        let (_, rows) = self.folders.rows.get(key)?;
        let state = self.panes.get(&id)?;
        let (i, _) = state.list.rows.get(state.list.selected)?;
        rows.get(*i)?.address
    }

    /// Folder tab `id`'s selected row, if a type: opened in the struct
    /// editor, as the map opens it. Whether it was one.
    pub fn open_folder_type(
        &mut self,
        id: PaneId,
        key: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if Group::of_key(key) != Some(Group::Types) {
            return false;
        }
        let rows = self.folder_rows(key);
        let Some(name) = self
            .panes
            .get(&id)
            .and_then(|s| s.list.rows.get(s.list.selected))
            .and_then(|(i, _)| rows.get(*i))
            .map(|r| r.name.clone())
        else {
            return false;
        };
        if let Some(target) = self.struct_target(&name) {
            self.open_struct(&target, window, cx);
        }
        true
    }

    /// A folder tab's label and its folder's path in the tree (for the
    /// breadcrumb), from the root's folders down.
    pub fn folder_path(&self, key: &str) -> Vec<String> {
        let Some(map) = self.sidebar.as_ref().map(|s| &s.map) else {
            return Vec::new();
        };
        let mut path = Vec::new();
        let mut at = map.folder(key);
        while let Some(i) = at {
            let Some(node) = map.node(i) else {
                break;
            };
            if node.kind == Kind::File {
                break;
            }
            path.push(node.name.clone());
            at = map.parent(i);
        }
        if path.is_empty() {
            // Not in the tree (yet): the group's title.
            path.extend(Group::of_key(key).map(|g| g.title().to_owned()));
        }
        path.reverse();
        path
    }

    /// A folder tab's content: the column titles over the rows.
    #[expect(
        clippy::too_many_lines,
        reason = "the header, the rows and their cells"
    )]
    pub fn render_folder(&mut self, id: PaneId, key: &str, cx: &mut Context<Self>) -> AnyElement {
        self.refresh_folder(id, key);
        let rows = self.folder_rows(key);
        let theme = self.theme;
        let row_h = self.row(self.ui_line() + ROW_PAD);
        let shown = usize::try_from(self.rows(id, self.ui_line() + ROW_PAD)).unwrap_or(0);
        let focused = self.layout.focused() == id;
        let sort = self.folder_sort(id);
        let columns = Group::of_key(key).map_or(&[Column::Name][..], folder::columns);
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        let bounds = Rc::clone(&state.bounds);
        let body_rows = shown.saturating_sub(1).max(1) as u64;
        let first = usize::try_from(state.list.scroll.anchor.line).unwrap_or(usize::MAX);
        let last = columns.len().saturating_sub(1);
        let cell = |k: usize, column: Column| {
            let d = if k == last {
                div().flex_1().min_w_0()
            } else {
                div().flex_none().w(self.z(width(column))).pr(self.z(12.0))
            };
            d.overflow_hidden().whitespace_nowrap().text_ellipsis()
        };
        let mut header = div()
            .flex()
            .flex_none()
            .items_center()
            .h(px(row_h))
            .px(self.z(12.0))
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .text_color(hsla(theme.text_muted));
        for (k, &column) in columns.iter().enumerate() {
            let arrow = if sort.by != column {
                ""
            } else if sort.descending {
                " ↓"
            } else {
                " ↑"
            };
            header = header.child(
                cell(k, column)
                    .id(title_id(column))
                    .cursor_pointer()
                    .hover(|s| s.text_color(hsla(theme.text)))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.sort_folder(id, column);
                        cx.notify();
                    }))
                    .child(format!("{}{arrow}", column.title())),
            );
        }
        let mut body = div()
            .id(("folder-rows", id.0))
            .flex_1()
            .min_h_0()
            .relative()
            .overflow_hidden()
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                if let Some(s) = this.panes.get_mut(&id) {
                    let total = s.list.rows.len() as u64;
                    s.list.scroll.wheel(wheel(e), row_h, total, body_rows);
                }
                cx.notify();
            }))
            .child(measured(bounds).absolute().size_full());
        let ui = font(self.settings.ui_font.clone());
        for (k, (i, positions)) in state
            .list
            .rows
            .iter()
            .enumerate()
            .skip(first)
            .take(shown + 1)
        {
            let Some(r) = rows.get(*i) else {
                continue;
            };
            let selected = k == state.list.selected;
            let y = f((k - first) as u64) * row_h - state.list.scroll.anchor.offset;
            // The name, the filter's matches in the accent.
            let mut runs = Vec::new();
            let mut at = 0;
            let mut push = |len: usize, color: u32| {
                if len > 0 {
                    runs.push(TextRun {
                        len,
                        font: ui.clone(),
                        color: hsla(color),
                        background_color: None,
                        underline: None,
                        strikethrough: None,
                    });
                }
            };
            for &p in positions {
                let Some(c) = r.name.get(p..).and_then(|s| s.chars().next()) else {
                    continue;
                };
                push(p.saturating_sub(at), theme.editor_foreground);
                push(c.len_utf8(), theme.accent);
                at = p + c.len_utf8();
            }
            push(r.name.len().saturating_sub(at), theme.editor_foreground);
            let mut row = div()
                .id(("folder-row", k))
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
            for (c, &column) in columns.iter().enumerate() {
                let muted = |text: String| {
                    cell(c, column)
                        .text_color(hsla(theme.text_muted))
                        .font_features(tabular())
                        .child(text)
                };
                row = row.child(match column {
                    Column::Name => cell(c, column).child(
                        StyledText::new(r.name.clone()).with_runs(std::mem::take(&mut runs)),
                    ),
                    Column::Address => {
                        muted(r.address.map(|a| format!("{a:X}")).unwrap_or_default())
                    }
                    Column::Size => muted(r.size.map(|s| s.to_string()).unwrap_or_default()),
                    Column::Refs => muted(r.refs.map(|n| n.to_string()).unwrap_or_default()),
                    Column::Library => cell(c, column)
                        .text_color(hsla(theme.text_muted))
                        .child(r.library.clone().unwrap_or_default()),
                    Column::Type => cell(c, column)
                        .text_color(hsla(theme.type_))
                        .font_family(self.settings.code_font.clone())
                        .text_size(px(self.code_size()))
                        .child(r.ty.clone().unwrap_or_default()),
                });
            }
            body = body.child(row);
        }
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        div()
            .id(("folder", id.0))
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
}
