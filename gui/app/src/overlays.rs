//! What floats over the panes: the one-line prompts (`N` on a function's,
//! a global's or a frame slot's name),
//! go anywhere (`G`: names and addresses, the last query preselected),
//! the command palette (commands with their keys, settings with inline
//! toggles), and the peek card (a name's C
//! or typed bytes, its kind and address, its xrefs numbered 1–9).

use std::collections::HashSet;
use std::time::Duration;

use binbun_gui_view::NumberForm;
use binbun_gui_view::Stage;
use binbun_gui_view::cdoc::identifier;
use binbun_gui_view::commands::{self, COMMANDS, key_label};
use binbun_gui_view::corrections::Op;
use binbun_gui_view::fuzzy::{Query, filter, parse_address};
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::Role;
use binbun_gui_view::peek::{Kind as PeekKind, XREFS, peek, provenance};
use binbun_gui_view::projects::{project_title, share_of};
use binbun_gui_view::recent::Recent;
use binbun_gui_view::session::project;
use binbun_gui_view::settings::{Kind as SettingKind, SETTINGS, Setting, Theme as Mode};
use binbun_gui_view::slices;
use binbun_gui_view::structedit::StructTarget;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, Div, FontWeight, KeyDownEvent, MouseButton, MouseDownEvent, Pixels, Point,
    StyledText, Subscription, Window, div, point, px,
};

use crate::corrections::{address_typed, array_count_typed};
use crate::highlight::Highlight;
use crate::scrolling::Area;
use crate::theme::{hsla, solid};
use crate::workspace::{
    Candidate, PaletteItem, PeekCard, Picker, PickerKind, Prompt, PromptKind, TabKind, Workspace,
    f, same_file,
};

/// The most go-anywhere rows.
const GOTO_ROWS: usize = 12;
/// A picker row's height (logical).
const PICKER_ROW: f32 = 30.0;
/// The picker rows shown at once; more scroll.
const PICKER_ROWS: u64 = 12;
/// The C lines a peek card shows.
const PEEK_LINES: usize = 14;
/// The C lines a peek card holds (it scrolls through them).
const PEEK_MAX: usize = 400;

impl Workspace {
    // ---- cards ----

    /// A card over the panes (the peek card, the why card, a reveal's
    /// exact C): the popover surface, a border the editor's colour does not
    /// swallow and a shadow lifting it off the text under it.
    pub fn card(&self) -> Div {
        let theme = self.theme;
        div()
            .bg(hsla(solid(theme.panel)))
            .border_1()
            .border_color(hsla(theme.border))
            .rounded(self.z(6.0))
            .shadow(theme.card_shadow())
            .occlude()
    }

    // ---- prompts ----

    /// `N`: renames what is under the cursor: a variable in place, a
    /// function or global in a prompt.
    pub fn rename(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        if self.menu_subject.is_none()
            && matches!(self.layout.active(id), Some(TabKind::C { .. }))
            && self.open_field(id, window, cx)
        {
            return;
        }
        if self.menu_subject.is_none()
            && let Some((entry, offset, shown, default)) = self.slot_under_cursor()
        {
            self.open_prompt(
                PromptKind::Slot(entry, offset),
                &shown,
                &default,
                window,
                cx,
            );
            return;
        }
        let address = self.rename_target();
        if let Some(address) = address {
            let current = self.shown_name(address).unwrap_or_default();
            let default = self
                .listing
                .as_ref()
                .and_then(|l| l.name(address))
                .unwrap_or("")
                .to_owned();
            self.open_prompt(PromptKind::Rename(address), &current, &default, window, cx);
        }
    }

    /// What `N` names outside a variable: the name under the cursor, else
    /// the cursor's item (the function, in C).
    fn rename_target(&self) -> Option<u64> {
        if let Some(subject) = self.menu_subject {
            return Some(subject);
        }
        let id = self.layout.focused();
        let state = self.panes.get(&id)?;
        let listing = self.listing.as_ref()?;
        let session = self.session.as_ref()?;
        match self.layout.active(id)? {
            TabKind::Listing if state.unified.on => self.unified_subject(id),
            TabKind::Listing => {
                let db = session.database()?;
                let rendered = listing.render(db, state.listing.cursor, session.overlay());
                let named = state
                    .listing
                    .token
                    .and_then(|i| rendered.tokens.get(i))
                    .filter(|t| {
                        matches!(t.role, Role::CodeName | Role::DataName | Role::ImportName)
                    })
                    .and_then(|t| t.target);
                named.or_else(|| listing.line(state.listing.cursor).map(|l| l.address))
            }
            kind @ TabKind::C { .. } => {
                let document = self.document(kind)?;
                let by_name = state
                    .c
                    .span
                    .filter(|&s| document.variable(s).is_none())
                    .and_then(|s| self.c_name_address(document, s));
                Some(by_name.unwrap_or(document.entry))
            }
            TabKind::Settings
            | TabKind::Console
            | TabKind::Terminal(_)
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    /// The stack variable under the focused listing's cursor (`var_54`):
    /// its function's entry, its slot's offset from the stack pointer on
    /// entry, its name as shown and the listing's own.
    fn slot_under_cursor(&self) -> Option<(u64, i64, String, String)> {
        let id = self.layout.focused();
        if self.layout.active(id)? != &TabKind::Listing {
            return None;
        }
        let state = self.panes.get(&id)?;
        let listing = self.listing.as_ref()?;
        let session = self.session.as_ref()?;
        let db = session.database()?;
        let n = state.listing.cursor;
        let token = state.listing.token?;
        let own = listing
            .lines()
            .render(db, n)
            .tokens
            .into_iter()
            .nth(token)?;
        if own.role != Role::LocalName {
            return None;
        }
        let (entry, offset) = listing.lines().local(listing.line(n)?.address, &own.text)?;
        let shown = listing
            .render(db, n, session.overlay())
            .tokens
            .into_iter()
            .nth(token)
            .map_or_else(|| own.text.clone(), |t| t.text);
        Some((entry, offset, shown, own.text))
    }

    /// The name of `address` as shown.
    fn shown_name(&self, address: u64) -> Option<String> {
        let session = self.session.as_ref()?;
        self.listing
            .as_ref()?
            .shown_name(address, session.overlay())
            .map(str::to_owned)
    }

    pub(crate) fn open_prompt(
        &mut self,
        kind: PromptKind,
        current: &str,
        default: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let current = current.to_owned();
        let default = default.to_owned();
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(current)
                .placeholder(default)
        });
        let sub = cx.subscribe_in(
            &input,
            window,
            |this, input, e: &InputEvent, window, cx| match e {
                InputEvent::PressEnter { .. } => {
                    let text = input.read(cx).value().to_string();
                    this.commit_prompt(&text, window, cx);
                }
                InputEvent::Change => {
                    if let Some(prompt) = &mut this.prompt {
                        prompt.error = false;
                    }
                    cx.notify();
                }
                InputEvent::Focus | InputEvent::Blur => {}
            },
        );
        // A name is edited (the caret after it, as the C's rename field
        // opens); a bookmark's name or a number is typed anew.
        let edited = matches!(kind, PromptKind::Rename(_) | PromptKind::Slot(..));
        input.update(cx, |s, cx| {
            if edited {
                let end = s.value().len();
                s.set_selected_range(end..end, cx);
            } else {
                s.select_all(window, cx);
            }
            s.focus(window, cx);
        });
        self.prompt = Some(Prompt {
            kind,
            input,
            error: false,
            _sub: sub,
        });
        cx.notify();
    }

    fn commit_prompt(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(prompt) = &self.prompt else {
            return;
        };
        let kind = prompt.kind;
        let done = match kind {
            PromptKind::Rename(address) => match identifier(text) {
                Ok(name) => {
                    self.clocks.rename = Some(std::time::Instant::now());
                    self.session
                        .as_mut()
                        .map_or(Ok(()), |s| s.rename(address, name))
                }
                Err(error) => Err(error),
            },
            PromptKind::Slot(entry, offset) => match identifier(text) {
                Ok(name) => self
                    .session
                    .as_mut()
                    .map_or(Ok(()), |s| s.rename_slot(entry, offset, name)),
                Err(error) => Err(error),
            },
            PromptKind::Bookmark(address) => {
                let name = text.trim();
                if let Some(session) = self.session.as_mut() {
                    session.bookmark(address, Some(name.to_owned()));
                }
                Ok(())
            }
            PromptKind::Array(address) => {
                array_count_typed(text).and_then(|count| self.correct(Op::Array(count), address))
            }
            PromptKind::FunctionEnd(address) => {
                address_typed(text).and_then(|end| self.correct(Op::End(end), address))
            }
        };
        match done {
            Ok(()) => {
                self.prompt = None;
                let id = self.layout.focused();
                self.pin_active(id);
                self.ensure_documents();
                self.refresh_sidebar();
                self.focus_pane(id, window, cx);
            }
            Err(_) => {
                if let Some(prompt) = &mut self.prompt {
                    prompt.error = true;
                }
            }
        }
        cx.notify();
    }

    /// Closes every overlay; whether one was open.
    pub fn close_overlays(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let collab = self.close_collab_dialog();
        let folders = self.files_and_folders.close();
        let open = collab
            || folders
            || self.prompt.is_some()
            || self.picker.is_some()
            || self.field.is_some()
            || self.comment.is_some()
            || self.peek.is_some()
            || self.facts.card.is_some()
            || self.about
            || self.symbol_cache.question.is_some()
            || self.projects.question.is_some()
            || self.terminals.question.is_some()
            || self.close_ir_dropdowns();
        self.prompt = None;
        self.picker = None;
        self.slicing = None;
        self.choosing = None;
        // Escape (or a click away) from Select Theme restores the theme.
        if self.theme_preview.take().is_some() {
            self.apply_theme(window, cx);
        }
        self.field = None;
        self.comment = None;
        self.facts.card = None;
        self.about = false;
        self.symbol_cache.question = None;
        self.projects.question = None;
        // Not answered: the terminal's program keeps running, its tab back.
        if let Some(id) = self.terminals.question.take() {
            self.show_shell(TabKind::Terminal(id), false, window, cx);
        }
        self.close_peek();
        if open {
            let id = self.layout.focused();
            self.focus_pane(id, window, cx);
        }
        open
    }

    /// Esc closes the open overlays, and Enter the About card (and answers
    /// Clear Symbol Cache's and Import Project's questions, and chooses the
    /// row selected in a picker without a field, whose rows the arrows
    /// move through), whatever has the focus (none, after a menu closed):
    /// the keys are taken before any element sees them. An open menu keeps
    /// its Esc.
    pub fn intercept_overlay_keys(window: &Window, cx: &mut Context<Self>) -> Subscription {
        let this = cx.weak_entity();
        let handle = window.window_handle();
        cx.intercept_keystrokes(move |event, window, cx| {
            if window.window_handle() != handle || event.keystroke.modifiers.modified() {
                return;
            }
            let key = event.keystroke.key.as_str();
            if !matches!(key, "escape" | "enter" | "up" | "down") {
                return;
            }
            let closed = this
                .update(cx, |this, cx| {
                    let menu = this.menu.is_some() || this.context_menu.is_some();
                    if matches!(key, "up" | "down") {
                        let untyped = this.picker.as_ref().is_some_and(|p| !p.kind.typed());
                        if untyped && !menu {
                            this.move_picker(key == "up", cx);
                        }
                        return untyped && !menu;
                    }
                    if key == "enter"
                        && !menu
                        && (this.answer_clear_question(window, cx)
                            || this.answer_import_question(window, cx)
                            || this.confirm_untyped_picker(window, cx))
                    {
                        return true;
                    }
                    if menu || (key == "enter" && !this.about) {
                        return false;
                    }
                    // A find bar closes last, with nothing over it; then a
                    // selection goes (before Escape goes back).
                    let closed = this.close_overlays(window, cx)
                        || (key == "escape" && this.close_find(window, cx))
                        || (key == "escape" && this.clear_selection());
                    cx.notify();
                    closed
                })
                .unwrap_or(false);
            if closed {
                cx.stop_propagation();
            }
        })
    }

    /// Opens the About card, which takes the focus.
    pub fn open_about(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.close_overlays(window, cx);
        self.about = true;
        window.focus(&self.overlay_focus, cx);
        cx.notify();
    }

    // ---- pickers ----

    /// Opens go anywhere or the palette.
    pub fn open_picker(&mut self, kind: PickerKind, window: &mut Window, cx: &mut Context<Self>) {
        if kind == PickerKind::GoTo {
            self.candidates = self.goto_candidates();
        }
        let initial = match kind {
            PickerKind::GoTo => self.last_goto.clone(),
            PickerKind::Palette
            | PickerKind::Recent
            | PickerKind::Theme
            | PickerKind::Slice
            | PickerKind::Project
            | PickerKind::Enum
            | PickerKind::EditEnum => String::new(),
        };
        let input = cx.new(|cx| InputState::new(window, cx).default_value(initial));
        let sub = cx.subscribe_in(
            &input,
            window,
            |this, input, e: &InputEvent, window, cx| match e {
                InputEvent::PressEnter { .. } => this.confirm_picker(window, cx),
                InputEvent::Change => {
                    let text = input.read(cx).value().to_string();
                    this.filter_picker(&text);
                    this.preview_theme(cx);
                    cx.notify();
                }
                InputEvent::Focus | InputEvent::Blur => {}
            },
        );
        input.update(cx, |s, cx| {
            s.select_all(window, cx);
            if kind.typed() {
                s.focus(window, cx);
            }
        });
        if !kind.typed() {
            window.focus(&self.overlay_focus, cx);
        }
        self.picker = Some(Picker {
            kind,
            input,
            rows: Vec::new(),
            address: None,
            selected: 0,
            _sub: sub,
        });
        let text = match kind {
            PickerKind::GoTo => self.last_goto.clone(),
            PickerKind::Palette
            | PickerKind::Recent
            | PickerKind::Theme
            | PickerKind::Slice
            | PickerKind::Project
            | PickerKind::Enum
            | PickerKind::EditEnum => String::new(),
        };
        self.filter_picker(&text);
        if kind == PickerKind::Theme {
            // The theme shown now is selected first.
            let current = match &self.theme_preview {
                Some(name) => name.clone(),
                None if self.is_dark() => self.settings.dark_theme.clone(),
                None => self.settings.light_theme.clone(),
            };
            let list = self.themes.list();
            if let Some(picker) = &mut self.picker
                && let Some(k) = picker.rows.iter().position(|(i, _)| {
                    list.get(*i)
                        .is_some_and(|l| l.name.eq_ignore_ascii_case(&current))
                })
            {
                picker.selected = k;
            }
        }
        cx.notify();
    }

    /// Shows the theme selected in Select Theme, until it is kept (Enter)
    /// or the picker closes (the theme before comes back).
    fn preview_theme(&mut self, cx: &mut Context<Self>) {
        let Some(picker) = self.picker.as_ref().filter(|p| p.kind == PickerKind::Theme) else {
            return;
        };
        let list = self.themes.list();
        let name = picker
            .rows
            .get(picker.selected)
            .and_then(|(i, _)| list.get(*i))
            .map(|l| l.name.clone());
        if name.is_some() && name != self.theme_preview {
            self.theme_preview = name;
            self.resolve_theme(cx);
        }
    }

    /// Every name go anywhere knows: the user's, functions', symbols' and
    /// strings', each address once per name.
    fn goto_candidates(&self) -> Vec<Candidate> {
        let (Some(listing), Some(session)) = (&self.listing, &self.session) else {
            return Vec::new();
        };
        let Some(db) = session.database() else {
            return Vec::new();
        };
        let overlay = session.overlay();
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        let mut add = |name: &str, address: u64, badge: &'static str| {
            if seen.insert((address, name.to_owned())) {
                out.push(Candidate {
                    name: name.to_owned(),
                    address,
                    badge,
                });
            }
        };
        for (&address, name) in &overlay.bookmarks {
            add(name, address, "mark");
        }
        for (&address, name) in &overlay.names {
            let badge = if db.function_at(address).is_some() {
                "fn"
            } else {
                "data"
            };
            add(name, address, badge);
        }
        for &(entry, _) in &self.functions {
            if let Some(name) = listing.shown_name(entry, overlay) {
                add(name, entry, "fn");
            }
        }
        for (&address, name) in db.names() {
            let badge = if db.function_at(address).is_some() {
                "fn"
            } else {
                "sym"
            };
            add(name, address, badge);
        }
        for s in self.strings.iter() {
            if let Some(name) = listing.name(s.address) {
                add(name, s.address, "str");
            }
        }
        out
    }

    /// The palette's items, in order: commands ([`commands::in_palette`]:
    /// not the stages or cursor moves; the window's commands no menu
    /// holds, as the symbols bar's, too), then settings.
    pub fn palette_items() -> Vec<PaletteItem> {
        COMMANDS
            .iter()
            .filter(|i| commands::in_palette(i))
            .map(|i| PaletteItem::Command(i.command))
            .chain(SETTINGS.iter().map(|s| PaletteItem::Setting(s.key)))
            .collect()
    }

    /// A palette item's label.
    pub fn palette_label(item: PaletteItem) -> String {
        match item {
            PaletteItem::Command(c) => {
                commands::lookup(c).map_or_else(String::new, |i| i.title.to_owned())
            }
            PaletteItem::Setting(key) => binbun_gui_view::settings::info(key)
                .map_or_else(String::new, |i| format!("{}: {}", i.group, i.name)),
        }
    }

    fn filter_picker(&mut self, text: &str) {
        self.reset_area(Area::Picker);
        let Some(picker) = &mut self.picker else {
            return;
        };
        let query = Query::new(text);
        match picker.kind {
            PickerKind::GoTo => {
                picker.address = parse_address(text).filter(|&a| {
                    self.listing
                        .as_ref()
                        .zip(self.session.as_ref())
                        .and_then(|(l, s)| l.find(&format!("{a:X}"), s.overlay()))
                        .is_some()
                });
                let rows = if query.is_empty() {
                    Vec::new()
                } else {
                    filter(
                        &query,
                        self.candidates.iter().map(|c| c.name.as_str()),
                        GOTO_ROWS,
                    )
                };
                picker.rows = rows.into_iter().map(|(i, m)| (i, m.positions)).collect();
            }
            PickerKind::Palette => {
                let labels: Vec<String> = Self::palette_items()
                    .into_iter()
                    .map(Self::palette_label)
                    .collect();
                let rows = filter(&query, labels.iter().map(String::as_str), usize::MAX);
                picker.rows = rows.into_iter().map(|(i, m)| (i, m.positions)).collect();
            }
            PickerKind::Recent => {
                let paths: Vec<String> = self.recent.iter().map(recent_label).collect();
                let rows = filter(&query, paths.iter().map(String::as_str), usize::MAX);
                picker.rows = rows.into_iter().map(|(i, m)| (i, m.positions)).collect();
            }
            PickerKind::Theme => {
                let names: Vec<String> = self.themes.list().into_iter().map(|l| l.name).collect();
                let rows = filter(&query, names.iter().map(String::as_str), usize::MAX);
                picker.rows = rows.into_iter().map(|(i, m)| (i, m.positions)).collect();
            }
            PickerKind::Slice => {
                let arches = self
                    .slicing
                    .iter()
                    .flat_map(|slicing| &slicing.slices)
                    .map(|slice| slice.arch.as_str());
                let rows = filter(&query, arches, usize::MAX);
                picker.rows = rows.into_iter().map(|(i, m)| (i, m.positions)).collect();
            }
            PickerKind::Project => {
                let titles = self
                    .choosing
                    .iter()
                    .flat_map(|choosing| &choosing.rows)
                    .map(|row| row.title.as_str());
                let rows = filter(&query, titles, usize::MAX);
                picker.rows = rows.into_iter().map(|(i, m)| (i, m.positions)).collect();
            }
            PickerKind::Enum | PickerKind::EditEnum => {
                let names = self.enum_choices.iter().map(|(name, _)| enum_label(name));
                let rows = filter(&query, names, usize::MAX);
                picker.rows = rows.into_iter().map(|(i, m)| (i, m.positions)).collect();
            }
        }
        picker.selected = 0;
    }

    /// How many rows the picker shows (the address row first, if any).
    fn picker_len(&self) -> usize {
        self.picker
            .as_ref()
            .map_or(0, |p| p.rows.len() + usize::from(p.address.is_some()))
    }

    fn confirm_picker(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(picker) = &self.picker else {
            return;
        };
        let selected = picker.selected;
        match picker.kind {
            PickerKind::GoTo => {
                let text = picker.input.read(cx).value().to_string();
                let target = match (picker.address, selected) {
                    (Some(address), 0) => Some(address),
                    (address, k) => {
                        let k = k - usize::from(address.is_some());
                        picker
                            .rows
                            .get(k)
                            .and_then(|(i, _)| self.candidates.get(*i))
                            .map(|c| c.address)
                    }
                };
                if let Some(target) = target {
                    self.last_goto = text;
                    self.picker = None;
                    let id = self.layout.focused();
                    self.focus_pane(id, window, cx);
                    self.jump(target, cx);
                }
            }
            PickerKind::Palette => {
                let items = Self::palette_items();
                let Some(item) = picker
                    .rows
                    .get(selected)
                    .and_then(|(i, _)| items.get(*i))
                    .copied()
                else {
                    return;
                };
                self.palette_run(item, window, cx);
            }
            PickerKind::Recent => {
                let recent = picker
                    .rows
                    .get(selected)
                    .and_then(|(i, _)| self.recent.get(*i))
                    .cloned();
                if let Some(recent) = recent {
                    self.picker = None;
                    self.open_recent(&recent, window, cx);
                }
            }
            PickerKind::Theme => {
                let list = self.themes.list();
                let Some(chosen) = picker
                    .rows
                    .get(selected)
                    .and_then(|(i, _)| list.get(*i))
                    .cloned()
                else {
                    return;
                };
                self.picker = None;
                self.theme_preview = None;
                let key = if chosen.dark {
                    "window.dark_theme"
                } else {
                    "window.light_theme"
                };
                self.set_setting(key, &Setting::Text(chosen.name), window, cx);
                // A dark or light window switches to the kept theme's
                // appearance; the system's keeps following the system.
                if self.settings.theme != Mode::System && self.is_dark() != chosen.dark {
                    let mode = if chosen.dark { "dark" } else { "light" };
                    self.set_setting("window.theme", &Setting::Text(mode.to_owned()), window, cx);
                }
                let id = self.layout.focused();
                self.focus_pane(id, window, cx);
            }
            PickerKind::Slice => self.confirm_slice(window, cx),
            PickerKind::Project => self.confirm_project(window, cx),
            PickerKind::Enum | PickerKind::EditEnum => self.confirm_enum(window, cx),
        }
        cx.notify();
    }

    /// The picker's selection one row up (`up`) or down, round its ends,
    /// and shown.
    fn move_picker(&mut self, up: bool, cx: &mut Context<Self>) {
        let n = self.picker_len();
        if let Some(picker) = &mut self.picker
            && n > 0
        {
            picker.selected = if up {
                (picker.selected + n - 1) % n
            } else {
                (picker.selected + 1) % n
            };
        }
        self.preview_theme(cx);
        if let Some(selected) = self.picker.as_ref().map(|p| p.selected) {
            let top = 4.0 + f(selected as u64) * PICKER_ROW;
            let (top, height) = (f32::from(self.z(top)), f32::from(self.z(PICKER_ROW)));
            self.reveal_in_area(Area::Picker, top, height);
        }
        cx.notify();
    }

    /// Enter in a picker without a field ([`PickerKind::typed`]): its row
    /// selected chosen. Whether such a picker was open.
    fn confirm_untyped_picker(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if self
            .picker
            .as_ref()
            .is_none_or(|picker| picker.kind.typed())
        {
            return false;
        }
        self.confirm_picker(window, cx);
        true
    }

    /// Opens the binary the project picker asks about in the project
    /// selected.
    fn confirm_project(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(picker) = &self.picker else {
            return;
        };
        let Some(choosing) = self.choosing.take() else {
            return;
        };
        let Some(dir) = picker
            .rows
            .get(picker.selected)
            .and_then(|(i, _)| choosing.rows.get(*i))
            .map(|row| row.dir.clone())
        else {
            self.choosing = Some(choosing);
            return;
        };
        self.picker = None;
        self.open_project(choosing.path, choosing.arch, Some(dir), window, cx);
        let id = self.layout.focused();
        self.focus_pane(id, window, cx);
    }

    /// Opens the slice picker's selected slice of the fat binary, unless
    /// it is the one open.
    fn confirm_slice(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(picker) = &self.picker else {
            return;
        };
        let Some(slicing) = self.slicing.take() else {
            return;
        };
        let Some(arch) = picker
            .rows
            .get(picker.selected)
            .and_then(|(i, _)| slicing.slices.get(*i))
            .map(|slice| slice.arch.clone())
        else {
            self.slicing = Some(slicing);
            return;
        };
        self.picker = None;
        // The slice open already: nothing to do.
        let open = self.session.as_ref().is_some_and(|session| {
            session.slice() == Some(arch.as_str()) && same_file(session.path(), &slicing.path)
        });
        if !open {
            self.open_as(slicing.path, Some(arch), None, window, cx);
        }
        let id = self.layout.focused();
        self.focus_pane(id, window, cx);
    }

    /// Runs the enumeration picker's selected row: the number shown by
    /// that enumeration's constants (Enum…), or its definition opened in
    /// the struct editor (Edit Enum…).
    fn confirm_enum(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(picker) = &self.picker else {
            return;
        };
        let kind = picker.kind;
        let Some(name) = picker
            .rows
            .get(picker.selected)
            .and_then(|(i, _)| self.enum_choices.get(*i))
            .map(|(name, _)| name.clone())
        else {
            return;
        };
        self.picker = None;
        self.enum_choices = Vec::new();
        let id = self.layout.focused();
        self.focus_pane(id, window, cx);
        if kind == PickerKind::Enum {
            if let Some((address, written)) = self.enum_number.take() {
                self.number_form_at(address, written, NumberForm::Enum(name));
            }
        } else {
            self.open_struct(&StructTarget::Definition(name), window, cx);
        }
    }

    /// Runs a palette row: a command (the palette closes), a toggle or a
    /// choice setting changed in place (it stays open), another setting
    /// in the settings pane.
    fn palette_run(&mut self, item: PaletteItem, window: &mut Window, cx: &mut Context<Self>) {
        match item {
            PaletteItem::Command(command) => {
                let toggle = commands::state(command, &self.facts()).checked.is_some();
                if !toggle {
                    self.picker = None;
                    let id = self.layout.focused();
                    self.focus_pane(id, window, cx);
                }
                self.run(command, window, cx);
            }
            PaletteItem::Setting(key) => {
                let Some(info) = binbun_gui_view::settings::info(key) else {
                    return;
                };
                match info.kind {
                    SettingKind::Toggle => {
                        if let Some(Setting::Bool(on)) = self.settings.get(key) {
                            self.set_setting(key, &Setting::Bool(!on), window, cx);
                        }
                    }
                    SettingKind::Choice(_) => self.cycle_setting(key, window, cx),
                    SettingKind::Theme { .. } => self.open_picker(PickerKind::Theme, window, cx),
                    SettingKind::Number { .. }
                    | SettingKind::Font { .. }
                    | SettingKind::Program
                    | SettingKind::Relay => {
                        self.picker = None;
                        let id = self.layout.focused();
                        self.open_tab(id, TabKind::Settings, window, cx);
                    }
                }
            }
        }
    }

    /// Keys the overlays take before the panes (Esc is taken before
    /// anything: [`Self::intercept_overlay_keys`]): arrows move a picker's
    /// selection, a digit follows a peek card's xref.
    pub fn overlay_keys(&mut self, e: &KeyDownEvent, cx: &mut Context<Self>) -> bool {
        let key = e.keystroke.key.as_str();
        let plain = !e.keystroke.modifiers.modified();
        // A picker without a field has its arrows taken before
        // ([`Self::intercept_overlay_keys`]).
        let typed = self.picker.as_ref().is_some_and(|p| p.kind.typed());
        if typed && plain && matches!(key, "up" | "down") {
            self.move_picker(key == "up", cx);
            return true;
        }
        if let Some(card) = &self.peek
            && plain
            && self.picker.is_none()
            && self.prompt.is_none()
            && self.field.is_none()
            && let Some(k) = key
                .parse::<usize>()
                .ok()
                .filter(|k| (1..=XREFS).contains(k))
            && let Some(xref) = card.peek.xrefs.get(k - 1)
        {
            let from = xref.from;
            self.close_peek();
            self.jump(from, cx);
            return true;
        }
        false
    }

    /// The modal overlay (a prompt or a picker), if one is open.
    #[expect(clippy::too_many_lines, reason = "one branch per overlay")]
    pub fn render_modal(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        // A click anywhere but on the card closes it.
        let close = cx.listener(|this, _: &MouseDownEvent, window, cx| {
            this.close_overlays(window, cx);
            cx.notify();
        });
        let frame = move |this: &Self, width: f32, error: bool, content: AnyElement| {
            div()
                .id("modal-backdrop")
                .absolute()
                .inset_0()
                .pt(this.z(80.0))
                // A card taller than the window stops above its bottom;
                // its content scrolls (Connect an Agent's does).
                .pb(this.z(24.0))
                .flex()
                .items_start()
                .justify_center()
                .occlude()
                .on_any_mouse_down(close)
                .child(
                    div()
                        .id("modal")
                        .w(this.z(width))
                        .max_h_full()
                        .flex()
                        .flex_col()
                        .bg(hsla(solid(theme.panel)))
                        .border_1()
                        .border_color(hsla(if error {
                            theme.error
                        } else {
                            theme.border_variant
                        }))
                        .rounded(this.z(8.0))
                        .shadow_lg()
                        .overflow_hidden()
                        .on_any_mouse_down(|_, _, cx| cx.stop_propagation())
                        .child(content),
                )
                .into_any_element()
        };
        if let Some(prompt) = &self.prompt {
            let content = div()
                .p(self.z(4.0))
                .child(Input::new(&prompt.input).appearance(false))
                .into_any_element();
            return Some(frame(self, 420.0, prompt.error, content));
        }
        if self.about {
            let content = div()
                .id("about")
                .track_focus(&self.overlay_focus)
                .p(self.z(16.0))
                .flex()
                .flex_col()
                .gap(self.z(6.0))
                .child(
                    div()
                        .font_weight(FontWeight::BOLD)
                        .child(format!("binbun {}", env!("CARGO_PKG_VERSION"))),
                )
                .child(
                    div()
                        .text_color(hsla(theme.text_muted))
                        .child("Iosevka, Lilex, IBM Plex Sans: SIL Open Font License 1.1"),
                )
                .into_any_element();
            return Some(frame(self, 420.0, false, content));
        }
        if let Some(content) = self.render_clear_question(cx) {
            return Some(frame(self, 420.0, false, content));
        }
        if let Some(content) = self.render_terminal_question(cx) {
            return Some(frame(self, 420.0, false, content));
        }
        if let Some(content) = self.render_files_and_folders(cx) {
            return Some(frame(self, 560.0, false, content));
        }
        if let Some(content) = self.render_import_question(cx) {
            return Some(frame(self, 420.0, false, content));
        }
        if let Some((width, content)) = self.render_collab_dialog(cx) {
            return Some(frame(self, width, false, content));
        }
        let picker = self.picker.as_ref()?;
        let input = picker.input.clone();
        let kind = picker.kind;
        let rows = match kind {
            PickerKind::GoTo => self.goto_rows(cx),
            PickerKind::Palette => self.palette_rows(cx),
            PickerKind::Recent => self.recent_rows(cx),
            PickerKind::Theme => self.theme_rows(cx),
            PickerKind::Slice => self.slice_rows(cx),
            PickerKind::Project => self.project_rows(cx),
            PickerKind::Enum | PickerKind::EditEnum => self.enum_rows(cx),
        };
        let list = div().flex().flex_col().p(self.z(4.0)).children(rows);
        let list = self
            .scroll_area(Area::Picker, "picker-rows", list, cx)
            .max_h(self.z(PICKER_ROW * f(PICKER_ROWS) + 8.0));
        // A picker not narrowed by typing has no field: its rows only,
        // the keys taken with the focus on them.
        let field = kind.typed().then(|| {
            div()
                .px(self.z(4.0))
                .h(self.z(36.0))
                .flex()
                .items_center()
                .border_b_1()
                .border_color(hsla(theme.border_variant))
                .child(Input::new(&input).appearance(false))
        });
        let content = div()
            .id("picker")
            .when(!kind.typed(), |d| d.track_focus(&self.overlay_focus))
            .flex()
            .flex_col()
            .children(field)
            .child(list)
            .into_any_element();
        let width = match kind {
            PickerKind::Slice => 320.0,
            PickerKind::Project => 480.0,
            PickerKind::GoTo
            | PickerKind::Palette
            | PickerKind::Recent
            | PickerKind::Theme
            | PickerKind::Enum
            | PickerKind::EditEnum => 610.0,
        };
        Some(frame(self, width, false, content))
    }

    /// A picker row: selected or not, clickable to confirm.
    fn picker_row(&self, index: usize, cx: &mut Context<Self>) -> gpui_kit::Stateful<Div> {
        let theme = self.theme;
        let selected = self.picker.as_ref().is_some_and(|p| p.selected == index);
        div()
            .id(("picker-row", index))
            .h(self.z(PICKER_ROW))
            .px(self.z(8.0))
            .flex()
            .items_center()
            .justify_between()
            .rounded(self.z(4.0))
            .when(selected, |d| d.bg(hsla(theme.element_selected)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_click(cx.listener(move |this, _, window, cx| {
                if let Some(picker) = &mut this.picker {
                    picker.selected = index;
                }
                this.confirm_picker(window, cx);
            }))
    }

    /// `text` with the characters at `positions` (bytes) in the accent.
    fn matched(&self, text: &str, positions: &[usize], base: u32) -> StyledText {
        let theme = self.theme;
        let mut runs = Vec::new();
        let mut at = 0;
        let ui = gpui_kit::font(self.settings.ui_font.clone());
        let mut push = |len: usize, color: u32| {
            if len > 0 {
                runs.push(gpui_kit::TextRun {
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
            let Some(c) = text.get(p..).and_then(|s| s.chars().next()) else {
                continue;
            };
            push(p.saturating_sub(at), base);
            push(c.len_utf8(), theme.accent);
            at = p + c.len_utf8();
        }
        push(text.len().saturating_sub(at), base);
        StyledText::new(text.to_owned()).with_runs(runs)
    }

    fn goto_rows(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let Some(picker) = &self.picker else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let muted = |text: String| div().text_color(hsla(theme.text_muted)).child(text);
        let mut index = 0;
        if let Some(address) = picker.address {
            let place = self
                .listing
                .as_ref()
                .map(|l| l.describe(address))
                .unwrap_or_default();
            out.push(
                self.picker_row(index, cx)
                    .child(
                        div()
                            .flex()
                            .gap(self.z(8.0))
                            .child(muted("addr".to_owned()))
                            .child(place),
                    )
                    .child(muted(format!("{address:X}")))
                    .into_any_element(),
            );
            index += 1;
        }
        for (i, positions) in &picker.rows {
            let Some(c) = self.candidates.get(*i) else {
                continue;
            };
            out.push(
                self.picker_row(index, cx)
                    .child(
                        div()
                            .flex()
                            .gap(self.z(8.0))
                            .overflow_hidden()
                            .child(
                                div()
                                    .w(self.z(28.0))
                                    .text_color(hsla(theme.text_muted))
                                    .child(c.badge),
                            )
                            .child(self.matched(&c.name, positions, theme.text)),
                    )
                    .child(muted(format!("{:X}", c.address)))
                    .into_any_element(),
            );
            index += 1;
        }
        out
    }

    fn palette_rows(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let Some(picker) = &self.picker else {
            return Vec::new();
        };
        let items = Self::palette_items();
        let facts = self.facts();
        // Show a window of rows around the selection.
        let shown = 14;
        let start = picker.selected.saturating_sub(shown - 1);
        picker
            .rows
            .iter()
            .enumerate()
            .skip(start)
            .take(shown)
            .filter_map(|(index, (i, positions))| {
                let item = *items.get(*i)?;
                let label = Self::palette_label(item);
                let (right, enabled): (String, bool) = match item {
                    PaletteItem::Command(c) => {
                        let state = commands::state(c, &facts);
                        let key = key_label(&self.keymap, c).unwrap_or_default();
                        let right = match state.checked {
                            Some(true) => format!("on  {key}"),
                            Some(false) => format!("off  {key}"),
                            None => key,
                        };
                        // Off for a reason the window does not make plain:
                        // the reason, before the key.
                        let right = match commands::reason(c, &facts) {
                            Some(why) if !state.enabled => format!("{why}  {right}"),
                            Some(_) | None => right,
                        };
                        (right, state.enabled)
                    }
                    PaletteItem::Setting(key) => (self.setting_value(key), true),
                };
                let base = if enabled {
                    theme.text
                } else {
                    theme.text_placeholder
                };
                Some(
                    self.picker_row(index, cx)
                        .child(self.matched(&label, positions, base))
                        .child(
                            div()
                                .text_color(hsla(theme.text_muted))
                                .child(right.trim().to_owned()),
                        )
                        .into_any_element(),
                )
            })
            .collect()
    }

    fn recent_rows(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let Some(picker) = &self.picker else {
            return Vec::new();
        };
        picker
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, (i, positions))| {
                let path = recent_label(self.recent.get(*i)?);
                Some(
                    self.picker_row(index, cx)
                        .child(self.matched(&path, positions, theme.text))
                        .into_any_element(),
                )
            })
            .collect()
    }

    /// Setting `key`'s value as the palette shows it.
    pub fn setting_value(&self, key: &str) -> String {
        match self.settings.get(key) {
            Some(Setting::Bool(true)) => "on".to_owned(),
            Some(Setting::Bool(false)) => "off".to_owned(),
            Some(Setting::Number(n)) => format_number(n),
            Some(Setting::Text(t)) => t,
            None => String::new(),
        }
    }

    /// Select Theme's rows: each theme's name, whether it is dark or
    /// light, and whether it is the user's.
    fn theme_rows(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let Some(picker) = &self.picker else {
            return Vec::new();
        };
        let list = self.themes.list();
        picker
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, (i, positions))| {
                let listed = list.get(*i)?;
                let kind = match (listed.dark, listed.user) {
                    (true, false) => "dark",
                    (false, false) => "light",
                    (true, true) => "dark · yours",
                    (false, true) => "light · yours",
                };
                Some(
                    self.picker_row(index, cx)
                        .child(self.matched(&listed.name, positions, theme.text))
                        .child(div().text_color(hsla(theme.text_muted)).child(kind))
                        .into_any_element(),
                )
            })
            .collect()
    }

    /// The enumeration pickers' rows: each name, and how the number reads
    /// by it; a window of rows around the selection (a type library has
    /// thousands).
    fn enum_rows(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let Some(picker) = &self.picker else {
            return Vec::new();
        };
        let shown = usize::try_from(PICKER_ROWS).unwrap_or(12);
        let start = picker.selected.saturating_sub(shown - 1);
        picker
            .rows
            .iter()
            .enumerate()
            .skip(start)
            .take(shown)
            .filter_map(|(index, (i, positions))| {
                let (name, spelled) = self.enum_choices.get(*i)?;
                Some(
                    self.picker_row(index, cx)
                        .gap(self.z(16.0))
                        .child(self.matched(enum_label(name), positions, theme.text))
                        .child(
                            div()
                                .min_w_0()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .text_ellipsis()
                                .text_color(hsla(theme.text_muted))
                                .child(spelled.clone()),
                        )
                        .into_any_element(),
                )
            })
            .collect()
    }

    // ---- peek ----

    /// The slice picker's rows: each slice's architecture and its
    /// instruction set.
    fn slice_rows(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let (Some(picker), Some(slicing)) = (&self.picker, &self.slicing) else {
            return Vec::new();
        };
        picker
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, (i, positions))| {
                let slice = slicing.slices.get(*i)?;
                Some(
                    self.picker_row(index, cx)
                        .child(self.matched(&slice.arch, positions, theme.text))
                        .child(
                            div()
                                .text_color(hsla(theme.text_muted))
                                .child(slices::machine(slice)),
                        )
                        .into_any_element(),
                )
            })
            .collect()
    }

    /// The project picker's rows: each project's title ("bash, shared by
    /// Ann") and what it is, used last first.
    fn project_rows(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let (Some(picker), Some(choosing)) = (&self.picker, &self.choosing) else {
            return Vec::new();
        };
        picker
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, (i, positions))| {
                let row = choosing.rows.get(*i)?;
                Some(
                    self.picker_row(index, cx)
                        .child(self.matched(&row.title, positions, theme.text))
                        .child(
                            div()
                                .text_color(hsla(theme.text_muted))
                                .child(row.detail.clone()),
                        )
                        .into_any_element(),
                )
            })
            .collect()
    }

    /// The pointer is on a name naming `target` (or on none) at
    /// `position`: the card opens after the peek delay (saying `note`
    /// above its body, if one), or closes.
    pub fn hover_peek(
        &mut self,
        target: Option<u64>,
        note: Option<String>,
        position: Point<Pixels>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let showing = self.peek.as_ref().map(|c| c.peek.address);
        if target.is_some() && target == showing {
            self.peek_task = None;
            return;
        }
        let Some(target) = target else {
            if self.peek.is_some() && self.peek_task.is_none() {
                self.peek_task = Some(cx.spawn_in(window, async move |this, cx| {
                    cx.background_executor()
                        .timer(Duration::from_millis(250))
                        .await;
                    let _ = this.update(cx, |this, cx| {
                        this.peek_task = None;
                        if this.peek.as_ref().is_some_and(|c| !c.hovered) {
                            this.peek = None;
                            cx.notify();
                        }
                    });
                }));
            } else if self.peek.is_none() {
                self.peek_task = None;
            }
            return;
        };
        let delay = Duration::from_millis(u64::from(self.settings.peek_delay_ms));
        self.peek_task = Some(cx.spawn_in(window, async move |this, cx| {
            cx.background_executor().timer(delay).await;
            let _ = this.update(cx, |this, cx| {
                this.peek_task = None;
                this.show_peek(target, note, position);
                cx.notify();
            });
        }));
    }

    /// Opens the card for `address` at `position`, saying `note` above
    /// its body if one.
    pub fn show_peek(&mut self, address: u64, note: Option<String>, position: Point<Pixels>) {
        let (Some(listing), Some(session)) = (&self.listing, &self.session) else {
            return;
        };
        let Some(db) = session.database() else {
            return;
        };
        let referenced = self.stage >= Stage::Referenced;
        let mut card = peek(listing, db, session.overlay(), address, referenced);
        // A library function's card says which signature named it.
        card.note = note.or_else(|| {
            session
                .signature(address)
                .map(|identified| provenance(&identified))
        });
        self.peek = Some(PeekCard {
            peek: card,
            position,
            hovered: false,
        });
        self.reset_area(Area::Peek);
        self.ensure_documents();
    }

    /// Closes the card.
    pub fn close_peek(&mut self) {
        self.peek = None;
        self.peek_task = None;
    }

    /// The peek key: the card for the name under the cursor, which takes
    /// the focus (a card the pointer opened leaves it where it is).
    pub fn peek_at_cursor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(target) = self.target_under_cursor() else {
            return;
        };
        let Some(position) = self.under_cursor_line(self.layout.focused()) else {
            return;
        };
        self.show_peek(target, None, position);
        if self.peek.is_some() {
            window.focus(&self.overlay_focus, cx);
        }
        cx.notify();
    }

    /// Where a card opened from the keyboard goes in pane `id`: under its
    /// cursor's line, past the gutter.
    pub fn under_cursor_line(&self, id: PaneId) -> Option<Point<Pixels>> {
        let state = self.panes.get(&id)?;
        let b = state.bounds.get();
        let height = self.line_height(id);
        let (line, top) = match self.layout.active(id) {
            Some(TabKind::C { .. }) => (state.c.line as u64, state.c.scroll.anchor.line),
            _ => (state.listing.cursor, state.listing.scroll.anchor.line),
        };
        let y = f(line.saturating_sub(top) + 1) * self.row(height);
        Some(point(
            b.origin.x + px(self.gutter_width()),
            b.origin.y + px(y),
        ))
    }

    /// The peek card, if open.
    #[expect(clippy::too_many_lines, reason = "the card's three parts")]
    pub fn render_peek(&mut self, window: &Window, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let card = self.peek.as_ref()?;
        let p = &card.peek;
        let session = self.session.as_ref()?;
        let row_h = self.row(self.settings.listing_line_height);
        let name_color = match p.kind {
            PeekKind::Function | PeekKind::Code => theme.function,
            PeekKind::Import => theme.keyword,
            PeekKind::String | PeekKind::Data => theme.constant,
        };
        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(self.z(12.0))
            .px(self.z(10.0))
            .h(self.z(30.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(8.0))
                    .child(
                        div()
                            .text_color(hsla(theme.text_muted))
                            .child(p.kind.label()),
                    )
                    .child(
                        div()
                            .font_family(self.settings.code_font.clone())
                            .font_weight(FontWeight::BOLD)
                            .text_color(hsla(name_color))
                            .child(p.name.clone()),
                    ),
            )
            .child(
                div()
                    .font_family(self.settings.code_font.clone())
                    .text_color(hsla(theme.text_muted))
                    .child(format!("{:X}", p.address)),
            );
        let view = self.default_view();
        let body: Vec<AnyElement> = match p.function {
            Some(function) => match session.document(function, view) {
                Some(document) => (document.body_start()..document.lines.len())
                    .take(PEEK_MAX)
                    .map(|n| {
                        let shown = document.shown_line(n, None);
                        let runs = shown
                            .pieces
                            .iter()
                            .map(|piece| {
                                let len = piece.range.len();
                                let color = piece
                                    .span
                                    .and_then(|s| document.spans.get(s))
                                    .map_or(theme.variable, |span| theme.c(span));
                                self.text_run(len, color, None)
                            })
                            .collect::<Vec<_>>();
                        div()
                            .h(px(row_h))
                            .whitespace_nowrap()
                            .child(StyledText::new(shown.text).with_runs(runs))
                            .into_any_element()
                    })
                    .collect(),
                None => vec![
                    div()
                        .h(px(2.0))
                        .w_full()
                        .bg(hsla(theme.accent))
                        .into_any_element(),
                ],
            },
            None => p
                .lines
                .iter()
                .map(|rendered| {
                    let text = rendered.text();
                    let runs = rendered
                        .tokens
                        .iter()
                        .filter(|t| !t.text.is_empty())
                        .map(|t| self.text_run(t.text.len(), theme.token(t), None))
                        .collect::<Vec<_>>();
                    div()
                        .h(px(row_h))
                        .whitespace_nowrap()
                        .child(StyledText::new(text).with_runs(runs))
                        .into_any_element()
                })
                .collect(),
        };
        let xrefs: Vec<AnyElement> = p
            .xrefs
            .iter()
            .enumerate()
            .map(|(k, x)| {
                let from = x.from;
                div()
                    .id(("peek-xref", k))
                    .flex()
                    .gap(self.z(10.0))
                    .px(self.z(10.0))
                    .h(self.z(24.0))
                    .items_center()
                    .rounded(self.z(4.0))
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.close_peek();
                        this.jump(from, cx);
                    }))
                    .child(
                        div()
                            .text_color(hsla(theme.accent))
                            .child(format!("{}", k + 1)),
                    )
                    .child(
                        div()
                            .font_family(self.settings.code_font.clone())
                            .child(x.place.clone()),
                    )
                    .child(div().text_color(hsla(theme.text_muted)).child(x.how))
                    .into_any_element()
            })
            .collect();
        let more = p.total_xrefs.saturating_sub(p.xrefs.len());
        // The note, one paragraph a line, wraps: about 90 characters a
        // line at the card's width.
        let note_lines = p.note.as_ref().map_or(0, |note| {
            note.lines()
                .map(|line| line.chars().count().div_ceil(90).max(1) as u64)
                .sum()
        });
        let note = p.note.as_ref().map(|note| {
            div()
                .flex()
                .flex_col()
                .px(self.z(10.0))
                .py(self.z(4.0))
                .text_color(hsla(theme.text_muted))
                .children(note.lines().map(|line| div().child(line.to_owned())))
        });
        let width = self.z(600.0);
        let viewport = window.viewport_size();
        let x = card
            .position
            .x
            .min(viewport.width - width - self.z(8.0))
            .max(px(0.0));
        // Below the name if it fits, else above it.
        let lines = body.len().clamp(1, PEEK_LINES) as u64;
        let height = self.z(30.0
            + 12.0
            + 8.0
            + 24.0 * f(p.xrefs.len() as u64)
            + if more > 0 { 22.0 } else { 0.0 }
            + if note_lines > 0 {
                8.0 + 20.0 * f(note_lines)
            } else {
                0.0
            })
            + px(f(lines) * row_h);
        let below = card.position.y + self.z(4.0);
        let y = if below + height > viewport.height {
            (card.position.y - px(row_h) - height - self.z(4.0)).max(px(0.0))
        } else {
            below
        };
        // Its C (or bytes), the wheel scrolling through the rest.
        let body = div().px(self.z(10.0)).py(self.z(6.0)).children(body);
        let body = self
            .scroll_area(Area::Peek, "peek-body", body, cx)
            .h(px(f(lines) * row_h) + self.z(12.0))
            .border_t_1()
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .bg(hsla(solid(theme.editor)))
            .font_family(self.settings.code_font.clone())
            .font_features(self.font_features())
            .text_size(px(self.code_size()))
            .line_height(px(row_h));
        Some(
            self.card()
                .id("peek")
                .track_focus(&self.overlay_focus)
                .absolute()
                .left(x)
                .top(y)
                .w(width)
                .text_size(self.z(self.settings.ui_font_size))
                .on_hover(cx.listener(|this, hovered: &bool, _, cx| {
                    if let Some(card) = &mut this.peek {
                        card.hovered = *hovered;
                        if !*hovered {
                            this.peek = None;
                        }
                        cx.notify();
                    }
                }))
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                    this.close_peek();
                    cx.notify();
                }))
                .child(header)
                .children(note)
                .child(body)
                .child(div().py(self.z(4.0)).children(xrefs).when(more > 0, |d| {
                    d.child(
                        div()
                            .px(self.z(10.0))
                            .h(self.z(22.0))
                            .text_color(hsla(theme.text_muted))
                            .child(format!("{more} more")),
                    )
                }))
                .into_any_element(),
        )
    }
}

/// A setting's number as shown (no `.0` on whole numbers).
pub fn format_number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{n:.0}")
    } else {
        format!("{n:.1}")
    }
}

/// A recent file as Open Recent lists it: its path, and for a share's
/// project its title ("/usr/bin/bash — bash, shared by Ann").
fn recent_label(recent: &Recent) -> String {
    let path = recent.path.display().to_string();
    let dir = project::root()
        .zip(recent.project.as_ref())
        .map(|(root, name)| root.join(name))
        .filter(|dir| share_of(dir).is_some());
    match dir {
        Some(dir) => {
            let name = project::file_name(&recent.path);
            format!("{path} — {}", project_title(&name, Some(&dir)))
        }
        None => path,
    }
}

/// An enumeration as its pickers name it: its own name, its tag's
/// namespace (`enum Windows.Win32.Storage.FileSystem.FILE_ACCESS_RIGHTS`:
/// `FILE_ACCESS_RIGHTS`) and `enum` left out; a typedef's as it is.
pub fn enum_label(key: &str) -> &str {
    let tag = key.strip_prefix("enum ").unwrap_or(key);
    tag.rsplit('.').next().unwrap_or(tag)
}
