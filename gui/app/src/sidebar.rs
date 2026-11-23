//! The left sidebar: the binary's map (`binbun_gui_view::map`), drawn as
//! a file tree: rows flush from the top, a kind icon, the name, the
//! address right-aligned in muted tabular figures (unless the name already
//! says it: `sub_180001000`); folders open and close
//! in place. Keyboard first: arrows move, Left and Right close and open,
//! Enter goes there (or opens the folder); typing filters, Escape clears
//! the filter, then gives the focus back to the code. A click opens an
//! item in the code pane's preview tab, the focus kept here (a double
//! click pins it and gives it the focus; Ctrl+click or a middle click: a
//! new tab). The bookmarks are a folder pinned at the top (Delete removes
//! the selected one, undoably): one's own first (a private one locked),
//! then a folder per other person, their colour's dot before their name,
//! closed at first; a bookmark's context menu copies another's into one's
//! own, or makes one's own private or shared again. A folder's context
//! menu opens it as a tab.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use binbun_gui_view::map::{self, Group, Input, Kind, Map};
use binbun_gui_view::scroll::Scroller;
use binbun_gui_view::session::Session;
use binbun_gui_view::tabs::Opening;
use binbun_session::journal::PublicKey;
use gpui_kit::assets::IconName;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, ClickEvent, Context, FontFeatures, KeyDownEvent, MouseButton, MouseDownEvent,
    ScrollEvent, StyledText, TextRun, Window, div, font, px,
};

use crate::context_menu::OwnItem;
use crate::icons::icon;
use crate::panes::measured;
use crate::scrolling::wheel;
use crate::tabs::row_click;
use crate::theme::hsla;
use crate::workspace::{ICON, ROW_PAD, Sidebar, Workspace, whole_rows_in};

/// The sidebar's width at first (logical).
pub const WIDTH: f32 = 240.0;
/// The narrowest its edge drags it to.
pub const MIN_WIDTH: f32 = 160.0;
/// The widest its edge drags it to.
pub const MAX_WIDTH: f32 = 720.0;
/// One level of the tree's indent (logical).
const INDENT: f32 = 16.0;

/// The icon of a node of `kind` (open: a folder shown open).
pub fn kind_icon(kind: Kind, open: bool) -> IconName {
    match kind {
        Kind::File => IconName::Binary,
        Kind::Group(_) | Kind::Folder | Kind::Person if open => IconName::FolderOpen,
        Kind::Group(_) | Kind::Folder | Kind::Person => IconName::Folder,
        Kind::Library => IconName::Library,
        Kind::Section => IconName::Layers,
        Kind::Function => IconName::SquareFunction,
        Kind::Import => IconName::Import,
        Kind::Export => IconName::ArrowUpFromLine,
        Kind::Data => IconName::Database,
        Kind::Type => IconName::Braces,
        Kind::String => IconName::Quote,
        Kind::Bookmark | Kind::TheirBookmark => IconName::Bookmark,
        Kind::PrivateBookmark => IconName::Lock,
    }
}

/// Tabular figures, for addresses in the interface font.
pub fn tabular() -> FontFeatures {
    FontFeatures(Arc::new(vec![("tnum".to_owned(), 1)]))
}

/// Whether `name` ends in `address` in hex (`sub_180001000`).
fn says_address(name: &str, address: u64) -> bool {
    name.rsplit_once('_')
        .is_some_and(|(_, hex)| u64::from_str_radix(hex, 16) == Ok(address))
}

impl Workspace {
    /// Makes the sidebar's state.
    pub fn make_sidebar(&mut self, cx: &mut Context<Self>) {
        self.sidebar = Some(Sidebar {
            focus: cx.focus_handle(),
            map: Map::default(),
            open: Map::default_open(),
            query: String::new(),
            rows: Vec::new(),
            selected: 0,
            scroll: Scroller::default(),
            bounds: Rc::default(),
            built: 0,
        });
    }

    /// Builds the map again (the analysis or the user's names changed),
    /// and tells the feature map the library functions.
    pub fn refresh_sidebar(&mut self) {
        let input = self.map_input();
        self.set_library_functions(
            input
                .functions
                .iter()
                .filter(|f| f.library.is_some())
                .map(|f| f.address)
                .collect(),
        );
        if let Some(sidebar) = &mut self.sidebar {
            sidebar.map = Map::build(&input);
            sidebar.built += 1;
        }
        self.layout_map();
    }

    /// What the map shows now (the C++ classes read once per binary, the
    /// synthesised structs as last taken: [`Workspace::take_synthesised`]).
    fn map_input(&mut self) -> Input {
        let Some(session) = &self.session else {
            return Input::default();
        };
        let Some(listing) = &self.listing else {
            return Input {
                file: session.file_name(),
                ..Input::default()
            };
        };
        let types = match session.database() {
            Some(db) => self
                .map_types
                .names(|| map::types(db), session.definition_keys()),
            None => Vec::new(),
        };
        let names: HashMap<PublicKey, String> = session
            .others_bookmarks()
            .keys()
            .map(|&key| (key, self.person_name(key)))
            .collect();
        let name = |key: PublicKey| names.get(&key).cloned().unwrap_or_default();
        map::input(
            session,
            listing,
            &types,
            &self.strings,
            &mut self.demangled,
            &name,
        )
    }

    /// Takes the session's synthesised structs; the map built again when
    /// their names changed (the table found after the callers pass, or
    /// again after a type edit).
    pub fn take_synthesised(&mut self) {
        let synthesised = self.session.as_ref().and_then(Session::synthesised);
        if self.map_types.take(synthesised) {
            self.refresh_sidebar();
        }
    }

    /// Makes the rows again from the open folders and the filter, the
    /// selection kept on its node when it is still shown.
    fn layout_map(&mut self) {
        let Some(s) = &mut self.sidebar else {
            return;
        };
        let was = s.rows.get(s.selected).map(|r| r.node);
        s.rows = s.map.rows(&s.open, &s.query);
        s.selected = was
            .and_then(|n| s.rows.iter().position(|r| r.node == n))
            .unwrap_or(s.selected)
            .min(s.rows.len().saturating_sub(1));
        let line = s.scroll.anchor.line.min(s.selected as u64);
        if line != s.scroll.anchor.line {
            s.scroll.reset();
            s.scroll.anchor.line = line;
        }
    }

    /// Shows the map and focuses it on the functions (Shift+F3).
    pub fn focus_map(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.left_sidebar = true;
        if let Some(s) = &mut self.sidebar {
            s.open.insert(Group::Functions.key().to_owned());
        }
        self.layout_map();
        let rows = self.sidebar_rows();
        if let Some(s) = &mut self.sidebar {
            if let Some(k) = s.rows.iter().position(|r| {
                s.map
                    .node(r.node)
                    .is_some_and(|n| n.kind == Kind::Group(Group::Functions))
            }) {
                s.selected = k;
                s.scroll
                    .reveal(k as u64, s.rows.len() as u64, rows, rows / 3);
            }
            window.focus(&s.focus, cx);
        }
        cx.notify();
    }

    /// Opens or closes the folder of row `k`; else opens its address as
    /// `opening` says (a click: the preview tab; Enter: the preview tab,
    /// focused; a double click: pinned; Ctrl or the middle button: a new
    /// tab).
    fn map_activate(
        &mut self,
        k: usize,
        opening: Opening,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(s) = &mut self.sidebar else {
            return;
        };
        s.selected = k;
        let Some(node) = s.rows.get(k).and_then(|r| s.map.node(r.node)) else {
            return;
        };
        if node.kind.is_folder() {
            // A folder opens or closes once for a double click.
            if !matches!(opening, Opening::Linked { .. }) {
                return;
            }
            if !s.open.remove(&node.key) {
                s.open.insert(node.key.clone());
            }
            if !s.query.is_empty() {
                s.query.clear();
            }
            self.layout_map();
        } else if let Some(address) = node.address {
            // Where the lists open, whichever pane had the focus: the
            // listing first (data has no C; the C pane is not turned
            // into a listing).
            let to = self
                .code_pane(None)
                .unwrap_or_else(|| self.layout.focused());
            self.open_from_list(to, address, opening, window, cx);
        } else if node.kind == Kind::Type {
            let key = node.name.clone();
            if let Some(target) = self.struct_target(&key) {
                self.open_struct(&target, window, cx);
            }
        }
        cx.notify();
    }

    /// Opens (`open`) or closes the folder of the selected row; closing a
    /// leaf or a closed folder selects its parent, opening an open folder
    /// selects its first child.
    fn map_fold(&mut self, open: bool) {
        let Some(s) = &mut self.sidebar else {
            return;
        };
        let Some(row) = s.rows.get(s.selected).cloned() else {
            return;
        };
        let Some(node) = s.map.node(row.node) else {
            return;
        };
        let folder = node.kind.is_folder();
        match (open, folder, row.open) {
            (true, true, false) => {
                s.open.insert(node.key.clone());
            }
            (true, true, true) => s.selected += 1,
            (false, true, true) => {
                s.open.remove(&node.key);
            }
            (false, _, _) => {
                if let Some(parent) = s.map.parent(row.node)
                    && let Some(k) = s.rows.iter().position(|r| r.node == parent)
                {
                    s.selected = k;
                }
            }
            (true, false, _) => {}
        }
        self.layout_map();
    }

    fn map_keys(&mut self, e: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        let rows = usize::try_from(self.sidebar_rows()).unwrap_or(10);
        let m = e.keystroke.modifiers;
        if m.control || m.alt || m.platform {
            return;
        }
        let Some(s) = &self.sidebar else {
            return;
        };
        let last = s.rows.len().saturating_sub(1);
        let filtered = !s.query.is_empty();
        let page = rows.saturating_sub(1).max(1);
        let select = |this: &mut Self, to: &dyn Fn(usize) -> usize| {
            if let Some(s) = &mut this.sidebar {
                s.selected = to(s.selected).min(last);
            }
        };
        match e.keystroke.key.as_str() {
            "up" => select(self, &|k| k.saturating_sub(1)),
            "down" => select(self, &|k| k + 1),
            "pageup" => select(self, &|k| k.saturating_sub(page)),
            "pagedown" => select(self, &|k| k + page),
            "home" => select(self, &|_| 0),
            "end" => select(self, &|_| last),
            "left" => self.map_fold(false),
            "right" => self.map_fold(true),
            "delete" => self.map_delete_bookmark(),
            "enter" => {
                let k = s.selected;
                self.map_activate(k, Opening::Linked { focus: true }, window, cx);
            }
            "escape" if !filtered => {
                let to = self.layout.focused();
                self.focus_pane(to, window, cx);
            }
            "escape" | "backspace" => {
                if let Some(s) = &mut self.sidebar {
                    if e.keystroke.key == "escape" {
                        s.query.clear();
                    } else {
                        s.query.pop();
                    }
                }
                self.select_first_match();
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
                if let Some(s) = &mut self.sidebar {
                    s.query.push_str(text);
                }
                self.select_first_match();
            }
        }
        self.reveal_selected(rows);
        cx.stop_propagation();
        cx.notify();
    }

    /// Delete on one of one's own bookmarks: removed, undoably; the map
    /// built again.
    fn map_delete_bookmark(&mut self) {
        let Some(s) = &self.sidebar else {
            return;
        };
        let Some((kind, address)) = s
            .rows
            .get(s.selected)
            .and_then(|r| s.map.node(r.node))
            .filter(|n| matches!(n.kind, Kind::Bookmark | Kind::PrivateBookmark))
            .and_then(|n| Some((n.kind, n.address?)))
        else {
            return;
        };
        self.delete_bookmark(kind, address);
    }

    /// Removes one's own bookmark at `address` (shared or private).
    fn delete_bookmark(&mut self, kind: Kind, address: u64) {
        if let Some(session) = &mut self.session {
            if kind == Kind::PrivateBookmark {
                if let Err(why) = session.bookmark_private(address, None) {
                    self.error = Some(why);
                }
            } else {
                session.bookmark(address, None);
            }
        }
        self.refresh_sidebar();
    }

    /// A bookmark's context menu: another's copied into one's own; one's
    /// own made private or shared again, or deleted. What writes the log
    /// is off in a view-only session; a private bookmark's Delete is
    /// local.
    pub fn bookmark_menu(
        &self,
        kind: Kind,
        author: Option<PublicKey>,
        address: u64,
        name: &str,
    ) -> Vec<OwnItem> {
        let writes = self.edits_off().is_none();
        let item = |label: &str, run: Box<dyn Fn(&mut Self)>| OwnItem {
            enabled: writes,
            ..OwnItem::new(label.to_owned(), move |this, _, _| {
                run(this);
                this.refresh_sidebar();
            })
        };
        let name = name.to_owned();
        match kind {
            Kind::TheirBookmark if author.is_some() => vec![item(
                "Copy to My Bookmarks",
                Box::new(move |this| {
                    if let Some(session) = &mut this.session {
                        session.bookmark(address, Some(name.clone()));
                    }
                }),
            )],
            Kind::Bookmark => vec![
                item(
                    "Make Private",
                    Box::new(move |this| this.set_private(address, true)),
                ),
                item(
                    "Delete",
                    Box::new(move |this| this.delete_bookmark(Kind::Bookmark, address)),
                ),
            ],
            Kind::PrivateBookmark => vec![
                item(
                    "Share",
                    Box::new(move |this| this.set_private(address, false)),
                ),
                OwnItem::new("Delete", move |this, _, _| {
                    this.delete_bookmark(Kind::PrivateBookmark, address);
                }),
            ],
            Kind::TheirBookmark
            | Kind::File
            | Kind::Group(_)
            | Kind::Folder
            | Kind::Library
            | Kind::Section
            | Kind::Function
            | Kind::Import
            | Kind::Export
            | Kind::Data
            | Kind::Type
            | Kind::String
            | Kind::Person => Vec::new(),
        }
    }

    /// Makes one's bookmark at `address` private, or shared again.
    fn set_private(&mut self, address: u64, private: bool) {
        if let Some(session) = &mut self.session
            && let Err(why) = session.set_bookmark_private(address, private)
        {
            self.error = Some(why);
        }
    }

    /// The key of the map's folder Open as Tab opens: the context menu's,
    /// else the selected row's (not the file's).
    pub fn folder_key(&self) -> Option<String> {
        if let Some(key) = &self.menu_folder {
            return Some(key.clone());
        }
        let s = self.sidebar.as_ref()?;
        let node = s.rows.get(s.selected).and_then(|r| s.map.node(r.node))?;
        (node.kind.is_folder() && node.kind != Kind::File).then(|| node.key.clone())
    }

    /// After the filter changed: the rows again, the first match selected.
    fn select_first_match(&mut self) {
        self.layout_map();
        if let Some(s) = &mut self.sidebar {
            s.selected = s
                .rows
                .iter()
                .position(|r| !r.positions.is_empty())
                .unwrap_or(0);
        }
    }

    fn reveal_selected(&mut self, rows: usize) {
        let Some(s) = &mut self.sidebar else {
            return;
        };
        s.scroll
            .reveal(s.selected as u64, s.rows.len() as u64, rows as u64, 0);
    }

    /// The rows wholly in the sidebar's list, above the status bar: what
    /// its scrolling and its keys go by, so its last row, at the end,
    /// shows whole.
    fn sidebar_rows(&self) -> u64 {
        let h = self
            .sidebar
            .as_ref()
            .map_or(0.0, |s| f32::from(s.bounds.get().size.height));
        whole_rows_in(h.max(1.0), self.row(self.ui_line() + ROW_PAD))
    }

    /// The left sidebar.
    #[expect(clippy::too_many_lines, reason = "filter, rows, their parts")]
    pub fn render_sidebar(&mut self, window: &Window, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let rows = usize::try_from(self.sidebar_rows()).unwrap_or(0);
        let Some(sidebar) = &self.sidebar else {
            return div().into_any_element();
        };
        let focused = sidebar.focus.is_focused(window);
        // Unfocused, the map marks the cursor's function; focused, its own
        // selection.
        let here = self
            .current_address()
            .and_then(|a| self.listing.as_ref()?.function_of(a))
            .map(|(_, entry)| entry);
        let ui = font(self.settings.ui_font.clone());
        let row_h = self.row(self.ui_line() + ROW_PAD);
        let list_bounds = Rc::clone(&sidebar.bounds);
        let visible = rows as u64;
        let list = div()
            .id("map-rows")
            .flex_1()
            .min_h_0()
            .relative()
            .overflow_hidden()
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                if let Some(s) = &mut this.sidebar {
                    s.scroll
                        .wheel(wheel(e), row_h, s.rows.len() as u64, visible);
                }
                cx.notify();
            }))
            .child(measured(list_bounds).absolute().size_full());
        // The rows from the anchor's, moved up by its offset.
        let mut shown = div()
            .absolute()
            .left_0()
            .right_0()
            .top(px(-sidebar.scroll.anchor.offset));
        let first = usize::try_from(sidebar.scroll.anchor.line).unwrap_or(usize::MAX);
        // The whole rows, the one partly shown under them, and the one
        // coming in while scrolled by a part of a row.
        for (k, row) in sidebar.rows.iter().enumerate().skip(first).take(rows + 2) {
            let Some(node) = sidebar.map.node(row.node) else {
                continue;
            };
            let selected = if focused {
                k == sidebar.selected
            } else {
                node.kind == Kind::Function && node.address.is_some() && node.address == here
            };
            let label_color = if node.kind == Kind::File || matches!(node.kind, Kind::Group(_)) {
                theme.text
            } else if node.kind == Kind::String {
                theme.string
            } else {
                theme.editor_foreground
            };
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
            for &p in &row.positions {
                let Some(c) = node.name.get(p..).and_then(|s| s.chars().next()) else {
                    continue;
                };
                push(p.saturating_sub(at), label_color);
                push(c.len_utf8(), theme.accent);
                at = p + c.len_utf8();
            }
            push(node.name.len().saturating_sub(at), label_color);
            let indent = 8.0 + INDENT * f32::from(u16::try_from(row.depth).unwrap_or(u16::MAX));
            // Another person's folder: their colour's dot for its icon.
            let glyph = match (node.kind, node.author) {
                (Kind::Person, Some(author)) => div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .justify_center()
                    .size(self.z(ICON))
                    .child(
                        div()
                            .size(self.z(8.0))
                            .rounded_full()
                            .bg(self.person_color(author)),
                    )
                    .into_any_element(),
                _ => icon(
                    kind_icon(node.kind, row.open),
                    self.z(ICON),
                    hsla(theme.text_muted),
                )
                .into_any_element(),
            };
            shown = shown.child(
                div()
                    .id(("map-row", k))
                    .h(px(row_h))
                    .pl(self.z(indent))
                    .pr(self.z(8.0))
                    .flex()
                    .items_center()
                    .gap(self.z(6.0))
                    .border_1()
                    .border_color(hsla(if selected && focused {
                        theme.border_focused
                    } else {
                        0
                    }))
                    .when(selected, |d| d.bg(hsla(theme.element_selected)))
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, window, cx| {
                            if let Some(s) = &this.sidebar {
                                window.focus(&s.focus, cx);
                            }
                        }),
                    )
                    .on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                            this.map_context(k, e.position, window, cx);
                        }),
                    )
                    .on_click(cx.listener(move |this, e: &ClickEvent, window, cx| {
                        let opening = row_click(e, cx).on_row();
                        this.map_activate(k, opening, window, cx);
                    }))
                    .on_aux_click(cx.listener(move |this, e: &ClickEvent, window, cx| {
                        if e.is_middle_click() {
                            let opening = row_click(e, cx).on_row();
                            this.map_activate(k, opening, window, cx);
                        }
                    }))
                    .child(glyph)
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_ellipsis()
                            .child(StyledText::new(node.name.clone()).with_runs(runs)),
                    )
                    .when_some(
                        node.address.filter(|&a| !says_address(&node.name, a)),
                        |d, address| {
                            d.child(
                                div()
                                    .flex_none()
                                    .text_color(hsla(theme.text_placeholder))
                                    .font_features(tabular())
                                    .child(format!("{address:X}")),
                            )
                        },
                    )
                    .when_some(node.count, |d, count| {
                        d.child(
                            div()
                                .flex_none()
                                .text_color(hsla(theme.text_placeholder))
                                .font_features(tabular())
                                .child(count.to_string()),
                        )
                    }),
            );
        }
        let list = list.child(shown);
        let filter = (!sidebar.query.is_empty()).then(|| {
            div()
                .flex()
                .flex_none()
                .items_center()
                .gap(self.z(6.0))
                .h(px(row_h))
                .px(self.z(8.0))
                .border_b_1()
                .border_color(hsla(theme.border_variant))
                .child(icon(IconName::Search, self.z(ICON), hsla(theme.text_muted)))
                .child(sidebar.query.clone())
        });
        div()
            .id("sidebar")
            .key_context("Sidebar")
            .track_focus(&sidebar.focus)
            .size_full()
            .flex()
            .flex_col()
            .bg(hsla(theme.panel))
            .rounded(self.island_corner())
            .capture_key_down(
                cx.listener(|this, e: &KeyDownEvent, window, cx| this.map_keys(e, window, cx)),
            )
            .children(filter)
            .child(list)
            .into_any_element()
    }
}
