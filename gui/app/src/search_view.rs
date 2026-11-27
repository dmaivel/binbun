//! Searching in the window: the find bar over a pane (`Ctrl+F`: a
//! listing's lines as shown, a C pane's lines, a hex
//! view's bytes as hex or text; every match tinted, the count, the
//! current one revealed; the listing searched off the UI thread, the
//! cursor on the first match after it as soon as no earlier one can
//! come), the results tabs (Search Everywhere, Search Bytes, Search
//! Immediate: their query on top, results streaming in under it with a
//! quiet spinner while the search runs; the Bookmarks), and the bookmark
//! marks in the listing's and the C's gutters. The searching is the
//! session's (`binbun_gui_view::search`); this only draws and routes.

use std::collections::{BTreeMap, HashMap};
use std::f32::consts::TAU;
use std::ops::Range;
use std::rc::Rc;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use binbun_gui_view::cdoc::CDocument;
use binbun_gui_view::commands::{Command, Facts};
use binbun_gui_view::hex::Mode;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::scroll::Scroller;
use binbun_gui_view::search::{
    ByteHit, ByteMode, BytePattern, Found, Hit, Matcher, Plan, Query, Search, Source, TextHit,
    TextRows, immediate,
};
use binbun_gui_view::tabs::Opening;
use binbun_gui_view::{FunctionId, View};
use gpui_kit::assets::IconName;
use gpui_kit::component::Sizable as _;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, ClickEvent, Context, Div, Entity, Focusable, Hsla, KeyDownEvent, MouseButton,
    ScrollEvent, Stateful, StyledText, Subscription, TextRun, Transformation, Window, div, px,
    radians,
};

use crate::icons::icon;
use crate::panes::measured;
use crate::scrolling::wheel;
use crate::sidebar::tabular;
use crate::tabs::row_click;
use crate::theme::hsla;
use crate::workspace::{
    CHighlight, ICON, ICON_BUTTON, PromptKind, ROW_PAD, TOOLBAR_PAD, TabKind, Workspace, f,
};

/// How many listing lines a find takes at a time.
const FIND_CHUNK: u64 = 4096;

/// When the spinners started turning.
static STARTED: LazyLock<Instant> = LazyLock::new(Instant::now);

/// What a find bar searches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindKind {
    /// The listing's lines.
    Listing,
    /// A function's C in a view.
    C(FunctionId, View),
    /// A hex view's bytes in its space.
    Hex(Mode),
}

/// A pane's find bar.
pub struct FindBar {
    /// The query's field.
    pub input: Entity<InputState>,
    /// Its case and regex toggles (and the text).
    pub query: Query,
    /// In a hex view: the text read as hex bytes (else as a string).
    pub hex: bool,
    /// In the unified listing: the image's bytes searched for the text
    /// read as hex bytes (else the listing's text).
    pub bytes: bool,
    /// What it last searched.
    pub kind: Option<FindKind>,
    /// The matches.
    pub found: Found,
    /// The listing's search, while it runs.
    pub search: Option<Search<Hit>>,
    /// When the listing's search started (for the trace).
    pub started: Instant,
    /// The query does not parse.
    pub error: bool,
    pub(crate) _sub: Subscription,
}

/// What a results tab searches for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultsKind {
    /// Text in the listing and every function's C.
    Text,
    /// Bytes.
    Bytes,
    /// A value among instructions' operands and C literals.
    Immediate,
    /// The bookmarks (no query).
    Bookmarks,
}

/// A results tab's running search.
pub enum Running {
    /// Text or an immediate.
    Text(Search<TextHit>),
    /// Bytes.
    Bytes(Search<ByteHit>),
}

/// A results tab's rows.
#[derive(Clone, Debug)]
pub enum Rows {
    /// Lines found, in order, each declaration once.
    Text(TextRows),
    /// Bytes found, in order; over the file's offsets or not.
    Bytes(Vec<ByteHit>, bool),
}

/// A results tab.
pub struct ResultsTab {
    /// What it searches for.
    pub kind: ResultsKind,
    /// The query's field (none for the bookmarks).
    pub input: Option<Entity<InputState>>,
    /// The toggles (and the text last searched).
    pub query: Query,
    /// How bytes are read.
    pub bytes: ByteMode,
    /// Bytes are searched over the file's offsets.
    pub file: bool,
    /// What was searched for last, as typed.
    pub searched: Option<(String, Query, ByteMode)>,
    /// The rows found.
    pub rows: Rows,
    /// The search, while it runs.
    pub running: Option<Running>,
    /// When the search started (for the trace).
    pub started: Instant,
    /// The query does not parse.
    pub error: bool,
    /// The selected row.
    pub selected: usize,
    /// The rows' scrolling.
    pub scroll: Scroller,
    pub(crate) _sub: Option<Subscription>,
}

impl ResultsTab {
    /// How many rows it has (the bookmarks' are the workspace's).
    fn len(&self) -> usize {
        match &self.rows {
            Rows::Text(rows) => rows.rows().len(),
            Rows::Bytes(rows, _) => rows.len(),
        }
    }

    /// Whether its search runs.
    pub fn is_running(&self) -> bool {
        match &self.running {
            Some(Running::Text(s)) => s.is_running(),
            Some(Running::Bytes(s)) => s.is_running(),
            None => false,
        }
    }
}

/// The find bars, by pane, and the results tabs, by number.
#[derive(Default)]
pub struct SearchUi {
    /// Each pane's find bar.
    pub bars: HashMap<PaneId, FindBar>,
    /// Each results tab (its [`TabKind::Found`] number).
    pub tabs: HashMap<u32, ResultsTab>,
    /// The next results tab's number.
    pub next: u32,
}

/// `runs` (covering a line) with the bytes of each of `marks` on the
/// mark's background, split where a mark starts or ends.
pub fn marked(runs: Vec<TextRun>, marks: &[(Range<usize>, u32)]) -> Vec<TextRun> {
    if marks.is_empty() {
        return runs;
    }
    let mut out = Vec::with_capacity(runs.len() + 2 * marks.len());
    let mut at = 0;
    for run in runs {
        let end = at + run.len;
        // The cuts inside this run.
        let mut cuts: Vec<usize> = marks
            .iter()
            .flat_map(|(r, _)| [r.start, r.end])
            .filter(|&c| c > at && c < end)
            .collect();
        cuts.sort_unstable();
        cuts.dedup();
        let mut from = at;
        for to in cuts.into_iter().chain(std::iter::once(end)) {
            let mut piece = run.clone();
            piece.len = to - from;
            if let Some((_, color)) = marks.iter().find(|(r, _)| r.start <= from && from < r.end) {
                piece.background_color = Some(hsla(*color));
            }
            out.push(piece);
            from = to;
        }
        at = end;
    }
    out
}

impl Workspace {
    // ---- the find bar ----

    /// What pane `id` shows that a find bar searches.
    fn find_kind(&self, id: PaneId) -> Option<FindKind> {
        let state = self.panes.get(&id)?;
        match self.layout.active(id)? {
            TabKind::Listing
                if state.unified.on && self.search.bars.get(&id).is_some_and(|b| b.bytes) =>
            {
                Some(FindKind::Hex(Mode::Address))
            }
            TabKind::Listing if state.hex.on => Some(FindKind::Hex(state.hex.mode)),
            TabKind::Listing if self.shows_graph(id) || self.shows_calls(id) => None,
            TabKind::Listing => self.listing.as_ref().map(|_| FindKind::Listing),
            TabKind::C { function, view } if !self.shows_ir(id) => {
                function.map(|f| FindKind::C(f, *view))
            }
            TabKind::C { .. }
            | TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    /// `Ctrl+F`: opens the focused pane's find bar (or selects its text),
    /// the field taking the focus; its text the highlighted name if new.
    fn open_find(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        if self.find_kind(id).is_none() {
            return;
        }
        if let Some(bar) = self.search.bars.get(&id) {
            let input = bar.input.clone();
            input.update(cx, |s, cx| {
                s.select_all(window, cx);
                s.focus(window, cx);
            });
            return;
        }
        let initial = self.panes.get(&id).and_then(|s| {
            s.listing
                .highlight
                .clone()
                .or_else(|| match &s.c.highlight {
                    Some(CHighlight::Text(t)) => Some(t.clone()),
                    Some(CHighlight::Node(_)) | None => None,
                })
        });
        let input =
            cx.new(|cx| InputState::new(window, cx).default_value(initial.unwrap_or_default()));
        let sub = cx.subscribe_in(
            &input,
            window,
            move |this, _, e: &InputEvent, _, cx| match e {
                InputEvent::Change => {
                    this.refind(id, cx);
                    cx.notify();
                }
                InputEvent::PressEnter { shift, .. } => {
                    this.find_step(id, !shift);
                    cx.notify();
                }
                InputEvent::Focus | InputEvent::Blur => {}
            },
        );
        input.update(cx, |s, cx| {
            s.select_all(window, cx);
            s.focus(window, cx);
        });
        self.search.bars.insert(
            id,
            FindBar {
                input,
                query: Query::default(),
                hex: true,
                bytes: false,
                kind: None,
                found: Found::new(Plan::new(0, 1, 0)),
                search: None,
                started: Instant::now(),
                error: false,
                _sub: sub,
            },
        );
        self.refind(id, cx);
        cx.notify();
    }

    /// Closes the focused pane's find bar, the pane taking the focus;
    /// whether one was open (Esc).
    pub fn close_find(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let id = self.layout.focused();
        if self.search.bars.remove(&id).is_none() {
            return false;
        }
        self.focus_pane(id, window, cx);
        true
    }

    /// The cursor's line (or hex position) in pane `id`, for a find.
    fn find_origin(&self, id: PaneId, kind: &FindKind) -> u64 {
        let Some(state) = self.panes.get(&id) else {
            return 0;
        };
        match kind {
            FindKind::Listing => state.listing.cursor,
            FindKind::C(..) => state.c.line as u64,
            FindKind::Hex(_) if state.unified.on => self.unified_address(id).unwrap_or(0),
            FindKind::Hex(_) => state.hex.cursor,
        }
    }

    /// Searches pane `id` again for its bar's query (its text, toggles or
    /// what the pane shows changed).
    fn refind(&mut self, id: PaneId, cx: &mut Context<Self>) {
        let Some(kind) = self.find_kind(id) else {
            return;
        };
        let origin = self.find_origin(id, &kind);
        let Some(bar) = self.search.bars.get_mut(&id) else {
            return;
        };
        bar.query.text = bar.input.read(cx).value().to_string();
        bar.search = None;
        bar.error = false;
        bar.kind = Some(kind.clone());
        bar.found = Found::new(Plan::new(0, 1, 0));
        let (query, hex) = (bar.query.clone(), bar.hex);
        let revealed = match kind {
            FindKind::Hex(mode) => self.find_bytes(id, &query, hex, mode, origin),
            FindKind::C(function, view) => self.find_c(id, &query, function, view, origin),
            FindKind::Listing => {
                self.find_listing(id, &query, origin);
                None
            }
        };
        if let Some(hit) = revealed {
            self.find_land(id, &hit);
        }
    }

    /// Starts pane `id`'s listing search for `query` from line `origin`.
    fn find_listing(&mut self, id: PaneId, query: &Query, origin: u64) {
        let (Some(listing), Some(session)) = (self.listing.clone(), self.session.as_ref()) else {
            return;
        };
        let matcher = Matcher::new(query);
        let Some(bar) = self.search.bars.get_mut(&id) else {
            return;
        };
        match matcher {
            Ok(Some(matcher)) => {
                let plan = Plan::new(listing.len(), FIND_CHUNK, origin);
                bar.found = Found::new(plan);
                bar.search = Some(session.find_in_listing(&listing, &Arc::new(matcher), plan));
                bar.started = Instant::now();
            }
            Ok(None) => {}
            Err(_) => bar.error = true,
        }
    }

    /// Finds `query` in the C of `function` in `view` (here: a few hundred
    /// lines); the first match from line `origin` on.
    fn find_c(
        &mut self,
        id: PaneId,
        query: &Query,
        function: FunctionId,
        view: View,
        origin: u64,
    ) -> Option<Hit> {
        let document = Arc::clone(self.session.as_ref()?.document(function, view)?);
        let matcher = Matcher::new(query);
        let bar = self.search.bars.get_mut(&id)?;
        let matcher = match matcher {
            Ok(Some(m)) => m,
            Ok(None) => return None,
            Err(_) => {
                bar.error = true;
                return None;
            }
        };
        let lines = document.lines.len() as u64;
        let hits = (0..document.lines.len())
            .flat_map(|n| {
                matcher
                    .find(document.line_text(n))
                    .into_iter()
                    .map(move |r| Hit {
                        line: n as u64,
                        start: r.start,
                        end: r.end,
                    })
            })
            .collect();
        bar.found = Found::new(Plan::new(lines, lines, origin));
        bar.found.add(0, hits)
    }

    /// Finds `query` in pane `id`'s hex view's bytes in `mode` (as hex
    /// digits if `hex`, else as text); the first match from position
    /// `origin` on.
    fn find_bytes(
        &mut self,
        id: PaneId,
        query: &Query,
        hex: bool,
        mode: Mode,
        origin: u64,
    ) -> Option<Hit> {
        let (bytes, image) = self.session.as_ref()?.loaded()?;
        let bar = self.search.bars.get_mut(&id)?;
        if query.text.is_empty() {
            return None;
        }
        let read = if hex { ByteMode::Hex } else { ByteMode::Text };
        let Ok(pattern) = BytePattern::parse(&query.text, read, query.case) else {
            bar.error = true;
            return None;
        };
        let len = pattern.len();
        let positions: Vec<u64> = match mode {
            Mode::File => pattern
                .find_all(bytes)
                .into_iter()
                .map(|at| at as u64)
                .collect(),
            Mode::Address => image
                .segments
                .iter()
                .flat_map(|s| {
                    pattern
                        .find_all(s.bytes)
                        .into_iter()
                        .map(move |at| s.start + at as u64)
                })
                .collect(),
        };
        let hits = positions
            .into_iter()
            .map(|line| Hit {
                line,
                start: 0,
                end: len,
            })
            .collect();
        // Positions are the lines: one segment over all of them.
        bar.found = Found::new(Plan::new(u64::MAX, u64::MAX, origin));
        bar.found.add(0, hits)
    }

    /// Puts pane `id`'s cursor on `hit`, revealed.
    fn find_land(&mut self, id: PaneId, hit: &Hit) {
        let rows_l = self.rows(id, self.settings.listing_line_height);
        let rows_c = self.rows(id, self.settings.c_line_height);
        let kind = self.search.bars.get(&id).and_then(|b| b.kind.clone());
        match kind {
            Some(FindKind::Listing) => {
                let total = self.listing.as_ref().map_or(0, |l| l.len());
                let address = self
                    .listing
                    .as_ref()
                    .and_then(|l| l.line(hit.line))
                    .map(|l| l.address);
                if let Some(state) = self.panes.get_mut(&id) {
                    state.listing.scroll.smooth.stop();
                    state.listing.cursor = hit.line;
                    state.listing.token = None;
                    // The unified listing, if it shows the listing, there too.
                    if state.unified.on {
                        state.unified.target = address.map(|a| (a, true));
                    }
                    state
                        .listing
                        .scroll
                        .anchor
                        .reveal(hit.line, total, rows_l, rows_l / 3);
                }
                self.moved(id);
            }
            Some(FindKind::C(..)) => {
                let total = self
                    .layout
                    .active(id)
                    .cloned()
                    .and_then(|k| self.document(&k).map(|d| d.lines.len() as u64))
                    .unwrap_or(0);
                if let Some(state) = self.panes.get_mut(&id) {
                    state.c.scroll.smooth.stop();
                    state.c.line = usize::try_from(hit.line).unwrap_or(0);
                    state.c.span = None;
                    state
                        .c
                        .scroll
                        .anchor
                        .reveal(hit.line, total, rows_c, rows_c / 3);
                }
                self.moved(id);
            }
            Some(FindKind::Hex(_)) if self.shows_unified(id) => {
                if let Some(state) = self.panes.get_mut(&id) {
                    state.unified.target = Some((hit.line, true));
                }
                self.moved(id);
            }
            Some(FindKind::Hex(_)) => self.hex_land(id, hit.line),
            None => {}
        }
    }

    /// The next (`forward`) or previous match of pane `id`'s find bar from
    /// its cursor, made current and landed on.
    fn find_step(&mut self, id: PaneId, forward: bool) {
        let Some(kind) = self.search.bars.get(&id).and_then(|b| b.kind.clone()) else {
            return;
        };
        let line = self.find_origin(id, &kind);
        let Some(bar) = self.search.bars.get_mut(&id) else {
            return;
        };
        let column = bar
            .found
            .current()
            .filter(|(_, h)| h.line == line)
            .map_or(0, |(_, h)| h.start);
        if let Some(hit) = bar.found.step((line, column), forward) {
            self.find_land(id, &hit);
        }
    }

    /// The find bar's marks on line `n` of pane `id` showing `kind`: each
    /// match's bytes and its colour (the current one's own).
    pub fn find_marks(&self, id: PaneId, kind: &FindKind, n: u64) -> Vec<(Range<usize>, u32)> {
        let Some(bar) = self
            .search
            .bars
            .get(&id)
            .filter(|b| b.kind.as_ref() == Some(kind))
        else {
            return Vec::new();
        };
        let current = bar.found.current().map(|(_, h)| h.clone());
        bar.found
            .on_line(n)
            .iter()
            .map(|h| {
                let color = if current.as_ref() == Some(h) {
                    self.theme.active_match
                } else {
                    self.theme.search_match
                };
                (h.range(), color)
            })
            .collect()
    }

    /// The hex view's find match covering position `at` of pane `id`, if
    /// any: its colour.
    pub fn find_hex_mark(&self, id: PaneId, at: u64) -> Option<u32> {
        let bar = self.search.bars.get(&id)?;
        if !matches!(bar.kind, Some(FindKind::Hex(_))) {
            return None;
        }
        let hit = bar.found.covering(at)?;
        let current = bar.found.current().is_some_and(|(_, h)| h == hit);
        Some(if current {
            self.theme.active_match
        } else {
            self.theme.search_match
        })
    }

    /// Pane `id`'s find bar, if open: the field, the count, the toggles,
    /// previous and next, close.
    pub fn render_find_bar(&mut self, id: PaneId, cx: &mut Context<Self>) -> Option<AnyElement> {
        // The pane shows something else now (another function, the other
        // space): search that.
        let kind = self.find_kind(id);
        if self.search.bars.get(&id)?.kind != kind && kind.is_some() {
            self.refind(id, cx);
        }
        let theme = self.theme;
        let bar = self.search.bars.get(&id)?;
        let count = if bar.query.text.is_empty() {
            String::new()
        } else {
            match bar.found.current() {
                Some((i, _)) => format!("{}/{}", i + 1, bar.found.len()),
                None => bar.found.len().to_string(),
            }
        };
        let toggles = self.find_toggles(id, bar, cx);
        let step = |name: IconName, forward: bool, cx: &mut Context<Self>| {
            self.small_toggle(("find-step", u32::from(forward) + id.0 * 8), name, false)
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    this.find_step(id, forward);
                    cx.notify();
                }))
        };
        Some(
            div()
                .flex()
                .flex_none()
                .items_center()
                .gap(self.z(2.0))
                .h(self.bar(TOOLBAR_PAD))
                .px(self.z(8.0))
                .bg(hsla(theme.editor))
                .border_b_1()
                .border_color(hsla(theme.border_variant))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .max_w(self.z(420.0))
                        .px(self.z(6.0))
                        .rounded(self.z(4.0))
                        .border_1()
                        .border_color(hsla(if bar.error {
                            theme.error
                        } else {
                            theme.border_variant
                        }))
                        .font_family(self.settings.code_font.clone())
                        .child(Input::new(&bar.input).appearance(false).small()),
                )
                .child(
                    div()
                        .flex_none()
                        .min_w(self.z(48.0))
                        .px(self.z(6.0))
                        .font_features(tabular())
                        .text_color(hsla(theme.text_muted))
                        .child(count),
                )
                .children(toggles)
                .child(step(IconName::ChevronUp, false, cx))
                .child(step(IconName::ChevronDown, true, cx))
                .child(
                    self.small_toggle(("find-close", id.0), IconName::X, false)
                        .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                            this.search.bars.remove(&id);
                            this.focus_pane(id, window, cx);
                            cx.notify();
                        })),
                )
                .into_any_element(),
        )
    }

    /// Pane `id`'s find bar's toggles: in the unified listing, its bytes
    /// (else its text's case and regex); in a hex view, the text as hex
    /// and its case; else the case and regex.
    fn find_toggles(&self, id: PaneId, bar: &FindBar, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let toggle = |name: IconName, on: bool, which: u8, cx: &mut Context<Self>| {
            self.small_toggle(("find-toggle", u32::from(which) + id.0 * 8), name, on)
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    if let Some(bar) = this.search.bars.get_mut(&id) {
                        match which {
                            0 => bar.query.case = !bar.query.case,
                            1 => bar.query.regex = !bar.query.regex,
                            3 => bar.bytes = !bar.bytes,
                            _ => bar.hex = !bar.hex,
                        }
                    }
                    this.refind(id, cx);
                    cx.notify();
                }))
                .into_any_element()
        };
        let text = |cx: &mut Context<Self>| {
            [
                toggle(IconName::CaseSensitive, bar.query.case, 0, cx),
                toggle(IconName::Regex, bar.query.regex, 1, cx),
            ]
        };
        if self.shows_unified(id) {
            let mut toggles = vec![toggle(IconName::Binary, bar.bytes, 3, cx)];
            if !bar.bytes {
                toggles.extend(text(cx));
            }
            toggles
        } else if matches!(bar.kind, Some(FindKind::Hex(_))) {
            vec![
                toggle(IconName::Binary, bar.hex, 2, cx),
                toggle(IconName::CaseSensitive, bar.query.case, 0, cx),
            ]
        } else {
            text(cx).into()
        }
    }

    /// A small icon button of the search bars: muted at rest, filled when
    /// `on`.
    fn small_toggle(&self, id: (&'static str, u32), name: IconName, on: bool) -> Stateful<Div> {
        let theme = self.theme;
        div()
            .id(id)
            .flex()
            .flex_none()
            .items_center()
            .justify_center()
            .size(self.z(ICON_BUTTON))
            .rounded(self.z(4.0))
            .when(on, |d| d.bg(hsla(theme.element_selected)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
            .child(icon(
                name,
                self.z(ICON),
                hsla(if on { theme.text } else { theme.text_muted }),
            ))
    }

    // ---- results tabs ----

    /// Opens (or brings back) the results tab searching for `kind` in the
    /// focused pane, its field taking the focus, its text what is under
    /// the cursor.
    fn open_results(&mut self, kind: ResultsKind, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        // One tab per kind: an open one is brought back.
        let open = self.layout.panes().find_map(|p| {
            p.tabs.iter().enumerate().find_map(|(i, t)| {
                if let TabKind::Found(n) = &t.content
                    && self.search.tabs.get(n).is_some_and(|r| r.kind == kind)
                {
                    Some((p.id, i, *n))
                } else {
                    None
                }
            })
        });
        let file = self
            .panes
            .get(&id)
            .is_some_and(|s| s.hex.on && s.hex.mode == Mode::File)
            && self.shows_hex(id);
        let initial = self.results_initial(kind);
        if let Some((pane, i, n)) = open {
            self.layout.activate(pane, i);
            self.layout.focus(pane);
            if let Some(tab) = self.search.tabs.get_mut(&n) {
                if kind == ResultsKind::Bytes {
                    tab.file = file;
                }
                if let Some(input) = tab.input.clone() {
                    input.update(cx, |s, cx| {
                        if let Some(text) = initial {
                            s.set_value(text, window, cx);
                        }
                        s.select_all(window, cx);
                        s.focus(window, cx);
                    });
                    return;
                }
            }
            self.focus_pane(pane, window, cx);
            return;
        }
        let n = self.search.next;
        self.search.next += 1;
        let (input, sub) = if kind == ResultsKind::Bookmarks {
            (None, None)
        } else {
            let input =
                cx.new(|cx| InputState::new(window, cx).default_value(initial.unwrap_or_default()));
            let sub = cx.subscribe_in(
                &input,
                window,
                move |this, _, e: &InputEvent, window, cx| match e {
                    InputEvent::PressEnter { .. } => {
                        this.results_enter(n, window, cx);
                        cx.notify();
                    }
                    InputEvent::Change => {
                        if let Some(tab) = this.search.tabs.get_mut(&n) {
                            tab.error = false;
                        }
                        cx.notify();
                    }
                    InputEvent::Focus | InputEvent::Blur => {}
                },
            );
            input.update(cx, |s, cx| {
                s.select_all(window, cx);
                s.focus(window, cx);
            });
            (Some(input), Some(sub))
        };
        self.search.tabs.insert(
            n,
            ResultsTab {
                kind,
                input,
                query: Query::default(),
                bytes: ByteMode::Hex,
                file,
                searched: None,
                rows: Rows::Text(TextRows::default()),
                running: None,
                started: Instant::now(),
                error: false,
                selected: 0,
                scroll: Scroller::default(),
                _sub: sub,
            },
        );
        let id = self.open_list(id, TabKind::Found(n), false, cx);
        if kind == ResultsKind::Bookmarks {
            self.focus_pane(id, window, cx);
        }
    }

    /// What a results tab of `kind` starts with: the name or number under
    /// the cursor, the hex view's selected bytes.
    fn results_initial(&self, kind: ResultsKind) -> Option<String> {
        let id = self.layout.focused();
        if kind == ResultsKind::Text
            && let Some(key) = self.struct_tab_key(id)
        {
            return Some(key);
        }
        match kind {
            ResultsKind::Text => {
                let state = self.panes.get(&id)?;
                state
                    .listing
                    .highlight
                    .clone()
                    .or_else(|| match &state.c.highlight {
                        Some(CHighlight::Text(t)) => Some(t.clone()),
                        Some(CHighlight::Node(_)) | None => None,
                    })
            }
            ResultsKind::Immediate => self.number_under_cursor().map(|(_, written)| {
                if written.negative {
                    format!("-{:#x}", written.bits.wrapping_neg())
                } else {
                    format!("{:#x}", written.bits)
                }
            }),
            ResultsKind::Bytes | ResultsKind::Bookmarks => None,
        }
    }

    /// Enter in results tab `n`'s field: searches for what it says, unless
    /// that is what it shows (then goes to the selected row).
    fn results_enter(&mut self, n: u32, window: &mut Window, cx: &mut Context<Self>) {
        let Some(tab) = self.search.tabs.get(&n) else {
            return;
        };
        let text = tab
            .input
            .as_ref()
            .map(|i| i.read(cx).value().to_string())
            .unwrap_or_default();
        let wanted = (text.clone(), tab.query.clone(), tab.bytes);
        if tab.searched.as_ref() == Some(&wanted) && tab.len() > 0 {
            let id = self.layout.focused();
            self.results_go(id, n, Opening::Linked { focus: true }, window, cx);
            return;
        }
        self.results_run(n, &text);
    }

    /// Where the type shown in the focused pane's tab is used: Search
    /// Everywhere for its name as a whole word (`\bstruct pair\b`),
    /// run at once; whether the pane shows a type.
    pub fn uses_of_type(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let Some(key) = self.struct_tab_key(self.layout.focused()) else {
            return false;
        };
        self.open_results(ResultsKind::Text, window, cx);
        let Some(n) = self
            .search
            .tabs
            .iter()
            .find_map(|(n, t)| (t.kind == ResultsKind::Text).then_some(*n))
        else {
            return true;
        };
        // A type's key is words and spaces (`struct pair`, a typedef's
        // name): a pattern as it is.
        let words = key
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == ' ');
        let text = if words { format!("\\b{key}\\b") } else { key };
        if let Some(tab) = self.search.tabs.get_mut(&n) {
            tab.query.regex = words;
            tab.query.case = true;
            if let Some(input) = tab.input.clone() {
                input.update(cx, |s, cx| s.set_value(text.clone(), window, cx));
            }
        }
        self.results_run(n, &text);
        cx.notify();
        true
    }

    /// Runs results tab `n`'s search for `text`.
    fn results_run(&mut self, n: u32, text: &str) {
        let view = self.default_view();
        let listing = self.listing.clone();
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let Some(tab) = self.search.tabs.get_mut(&n) else {
            return;
        };
        tab.running = None;
        tab.selected = 0;
        tab.started = Instant::now();
        tab.scroll.reset();
        tab.error = false;
        text.clone_into(&mut tab.query.text);
        tab.searched = Some((text.to_owned(), tab.query.clone(), tab.bytes));
        match tab.kind {
            ResultsKind::Text => {
                tab.rows = Rows::Text(TextRows::default());
                match Matcher::new(&tab.query) {
                    Ok(Some(matcher)) => {
                        tab.running = Some(Running::Text(session.search_text(
                            listing.as_ref(),
                            view,
                            &Arc::new(matcher),
                        )));
                    }
                    Ok(None) => {}
                    Err(_) => tab.error = true,
                }
            }
            ResultsKind::Immediate => {
                tab.rows = Rows::Text(TextRows::default());
                match immediate(text) {
                    Ok(value) => {
                        tab.running = Some(Running::Text(session.search_immediate(
                            listing.as_ref(),
                            view,
                            value,
                        )));
                    }
                    Err(_) => tab.error = !text.trim().is_empty(),
                }
            }
            ResultsKind::Bytes => {
                tab.rows = Rows::Bytes(Vec::new(), tab.file);
                match BytePattern::parse(text, tab.bytes, true) {
                    Ok(pattern) => {
                        tab.running = session
                            .search_bytes(&Arc::new(pattern), tab.file)
                            .map(Running::Bytes);
                    }
                    Err(_) => tab.error = !text.trim().is_empty(),
                }
            }
            ResultsKind::Bookmarks => {}
        }
    }

    /// Takes the searches' results: a find's matches (landing on the first
    /// after the cursor once known), the results tabs' rows; forgets the
    /// tabs closed.
    pub fn poll_searches(&mut self) {
        let mut landings = Vec::new();
        for (&id, bar) in &mut self.search.bars {
            let Some(search) = &mut bar.search else {
                continue;
            };
            for batch in search.poll() {
                if let Some(hit) = bar.found.add(batch.segment, batch.items) {
                    trace!(
                        "find: first match at line {} in {:.1} ms",
                        hit.line,
                        bar.started.elapsed().as_secs_f64() * 1e3
                    );
                    landings.push((id, hit));
                }
            }
            if !search.is_running() {
                trace!(
                    "find: {} matches in the whole listing in {:.1} ms",
                    bar.found.len(),
                    bar.started.elapsed().as_secs_f64() * 1e3
                );
                bar.search = None;
            }
        }
        for (id, hit) in landings {
            if self.find_kind(id) == Some(FindKind::Listing) {
                self.find_land(id, &hit);
            }
        }
        let open: Vec<u32> = self
            .layout
            .panes()
            .flat_map(|p| p.tabs.iter())
            .filter_map(|t| {
                if let TabKind::Found(n) = t.content {
                    Some(n)
                } else {
                    None
                }
            })
            .collect();
        self.search.tabs.retain(|n, _| open.contains(n));
        for tab in self.search.tabs.values_mut() {
            let selected = tab.selected;
            match (&mut tab.running, &mut tab.rows) {
                (Some(Running::Text(search)), Rows::Text(rows)) => {
                    let new: Vec<TextHit> =
                        search.poll().into_iter().flat_map(|b| b.items).collect();
                    if !new.is_empty() {
                        let key = rows
                            .rows()
                            .get(selected)
                            .map(|h| (h.address, h.source, h.text.clone()));
                        rows.add(new);
                        if let Some(key) = key {
                            tab.selected = rows.rows().partition_point(|h| {
                                (h.address, h.source, h.text.as_str())
                                    < (key.0, key.1, key.2.as_str())
                            });
                        }
                    }
                }
                (Some(Running::Bytes(search)), Rows::Bytes(rows, _)) => {
                    let mut new: Vec<ByteHit> =
                        search.poll().into_iter().flat_map(|b| b.items).collect();
                    if !new.is_empty() {
                        let key = rows.get(selected).map(|h| h.at);
                        new.sort_by_key(|h| h.at);
                        *rows = merge(std::mem::take(rows), new, |a, b| a.at <= b.at);
                        if let Some(key) = key {
                            tab.selected = rows.partition_point(|h| h.at < key);
                        }
                    }
                }
                _ => {}
            }
            if tab.running.is_some() && !tab.is_running() {
                trace!(
                    "search: {} results in {:.1} ms",
                    tab.len(),
                    tab.started.elapsed().as_secs_f64() * 1e3
                );
                tab.running = None;
            }
        }
    }

    /// The bookmarks, by address, as the Bookmarks tab lists them.
    fn bookmark_rows(&self) -> Vec<(u64, String)> {
        self.session
            .as_ref()
            .map(|s| {
                s.overlay()
                    .bookmarks
                    .iter()
                    .map(|(&a, n)| (a, n.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The address of results tab `n`'s selected row, and whether it is a
    /// line of C.
    fn results_target(&self, n: u32) -> Option<(u64, bool)> {
        let tab = self.search.tabs.get(&n)?;
        match tab.kind {
            ResultsKind::Bookmarks => self
                .bookmark_rows()
                .get(tab.selected)
                .map(|(a, _)| (*a, false)),
            ResultsKind::Text | ResultsKind::Immediate | ResultsKind::Bytes => match &tab.rows {
                Rows::Text(rows) => rows
                    .rows()
                    .get(tab.selected)
                    .map(|h| (h.address, h.source == Source::C)),
                Rows::Bytes(rows, file) => {
                    let hit = rows.get(tab.selected)?;
                    let address = if *file {
                        self.hex_image()?.to_address(hit.at)?
                    } else {
                        hit.at
                    };
                    Some((address, false))
                }
            },
        }
    }

    /// A click on row `k` of results tab `n` in pane `id`: selected, its
    /// target opened as the click says.
    fn results_row_click(
        &mut self,
        id: PaneId,
        n: u32,
        k: usize,
        e: &ClickEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(tab) = self.search.tabs.get_mut(&n) {
            tab.selected = k;
        }
        self.layout.focus(id);
        let opening = row_click(e, cx).on_row();
        self.results_go(id, n, opening, window, cx);
        cx.notify();
    }

    /// Opens results tab `n`'s selected row from pane `from` as `opening`
    /// says: a line of C in a C pane if one shows, anything else as the
    /// lists go.
    fn results_go(
        &mut self,
        from: PaneId,
        n: u32,
        opening: Opening,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some((address, c)) = self.results_target(n) else {
            return;
        };
        let c_pane = c
            .then(|| {
                self.layout
                    .panes()
                    .find(|p| {
                        p.id != from
                            && matches!(
                                p.tabs.get(p.active).map(|t| &t.content),
                                Some(TabKind::C { .. })
                            )
                    })
                    .map(|p| p.id)
            })
            .flatten();
        match c_pane {
            Some(pane) => self.open_at(pane, address, opening, window, cx),
            None => self.open_from_list(from, address, opening, window, cx),
        }
    }

    /// Keys over results tab `n` in pane `id`: arrows, pages and ends move
    /// the selection (from the field too), Enter goes there, Delete
    /// removes a bookmark.
    fn results_keys(
        &mut self,
        id: PaneId,
        n: u32,
        e: &KeyDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let m = e.keystroke.modifiers;
        if m.control || m.alt || m.platform {
            return;
        }
        let shown = self.results_rows_shown(id);
        let len = match self.search.tabs.get(&n).map(|t| t.kind) {
            Some(ResultsKind::Bookmarks) => self.bookmark_rows().len(),
            Some(_) => self.search.tabs.get(&n).map_or(0, ResultsTab::len),
            None => return,
        };
        let input_focused = self
            .search
            .tabs
            .get(&n)
            .and_then(|t| t.input.as_ref())
            .is_some_and(|i| i.read(cx).focus_handle(cx).is_focused(window));
        let key = e.keystroke.key.as_str();
        if key == "delete" && !input_focused {
            if let Some((address, _)) = self.results_target(n)
                && self
                    .search
                    .tabs
                    .get(&n)
                    .is_some_and(|t| t.kind == ResultsKind::Bookmarks)
                && let Some(session) = &mut self.session
            {
                session.bookmark(address, None);
            }
            cx.stop_propagation();
            cx.notify();
            return;
        }
        if key == "enter" && !input_focused {
            self.results_go(id, n, Opening::Linked { focus: true }, window, cx);
            cx.stop_propagation();
            return;
        }
        let Some(tab) = self.search.tabs.get_mut(&n) else {
            return;
        };
        let end = len.saturating_sub(1);
        let page = shown.saturating_sub(2).max(1);
        match key {
            "up" => tab.selected = tab.selected.saturating_sub(1),
            "down" => tab.selected = (tab.selected + 1).min(end),
            "pageup" => tab.selected = tab.selected.saturating_sub(page),
            "pagedown" => tab.selected = (tab.selected + page).min(end),
            "home" if !input_focused => tab.selected = 0,
            "end" if !input_focused => tab.selected = end,
            _ => return,
        }
        tab.scroll
            .reveal(tab.selected as u64, len as u64, shown as u64, 0);
        cx.stop_propagation();
        cx.notify();
    }

    /// How many rows results tab of pane `id` shows under its bars.
    fn results_rows_shown(&self, id: PaneId) -> usize {
        let rows = usize::try_from(self.rows(id, self.ui_line() + ROW_PAD)).unwrap_or(10);
        rows.saturating_sub(3).max(1)
    }

    /// The name of the function at `entry` as shown.
    fn function_shown(&self, entry: u64) -> String {
        self.listing
            .as_ref()
            .zip(self.session.as_ref())
            .and_then(|(l, s)| l.shown_name(entry, s.overlay()).map(str::to_owned))
            .unwrap_or_else(|| format!("sub_{entry:X}"))
    }

    /// Results tab `n` in pane `id`: its query bar, a header, the rows.
    #[expect(
        clippy::too_many_lines,
        reason = "the bar, the header, each kind's row"
    )]
    pub fn render_results(
        &mut self,
        id: PaneId,
        n: u32,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let row_h = self.row(self.ui_line() + ROW_PAD);
        let shown = self.results_rows_shown(id);
        let focused = self.layout.focused() == id;
        let bookmarks = self.bookmark_rows();
        let Some(tab) = self.search.tabs.get(&n) else {
            return div().into_any_element();
        };
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        let kind = tab.kind;
        let bounds = Rc::clone(&state.bounds);
        let len = if kind == ResultsKind::Bookmarks {
            bookmarks.len()
        } else {
            tab.len()
        };
        let column = |w: f32| {
            div()
                .flex_none()
                .w(self.z(w))
                .pr(self.z(12.0))
                .overflow_hidden()
                .whitespace_nowrap()
                .text_ellipsis()
        };
        // The query bar: the field, the toggles, a spinner while it runs.
        let bar = tab.input.as_ref().map(|input| {
            let running = tab.is_running();
            if running {
                window.request_animation_frame();
            }
            let toggle = |name: IconName, on: bool, which: u8, cx: &mut Context<Self>| {
                self.small_toggle(("results-toggle", u32::from(which) + n * 8), name, on)
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        let input = this.search.tabs.get_mut(&n).and_then(|tab| {
                            match which {
                                0 => tab.query.case = !tab.query.case,
                                1 => tab.query.regex = !tab.query.regex,
                                2 => tab.bytes = ByteMode::Hex,
                                3 => tab.bytes = ByteMode::Text,
                                _ => tab.bytes = ByteMode::Utf16,
                            }
                            tab.input.clone()
                        });
                        if let Some(input) = input {
                            let text = input.read(cx).value().to_string();
                            this.results_run(n, &text);
                        }
                        cx.notify();
                    }))
                    .into_any_element()
            };
            let toggles: Vec<AnyElement> = match kind {
                ResultsKind::Text => vec![
                    toggle(IconName::CaseSensitive, tab.query.case, 0, cx),
                    toggle(IconName::Regex, tab.query.regex, 1, cx),
                ],
                ResultsKind::Bytes => vec![
                    toggle(IconName::Binary, tab.bytes == ByteMode::Hex, 2, cx),
                    toggle(IconName::Quote, tab.bytes == ByteMode::Text, 3, cx),
                    toggle(IconName::Hash, tab.bytes == ByteMode::Utf16, 4, cx),
                ],
                ResultsKind::Immediate | ResultsKind::Bookmarks => Vec::new(),
            };
            let turn = STARTED.elapsed().as_secs_f32().fract();
            div()
                .flex()
                .flex_none()
                .items_center()
                .gap(self.z(2.0))
                .h(px(row_h + f32::from(self.z(6.0))))
                .px(self.z(8.0))
                .border_b_1()
                .border_color(hsla(theme.border_variant))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .max_w(self.z(520.0))
                        .px(self.z(6.0))
                        .rounded(self.z(4.0))
                        .border_1()
                        .border_color(hsla(if tab.error {
                            theme.error
                        } else {
                            theme.border_variant
                        }))
                        .font_family(self.settings.code_font.clone())
                        .child(Input::new(input).appearance(false).small()),
                )
                .children(toggles)
                .child(
                    div()
                        .flex()
                        .flex_none()
                        .items_center()
                        .justify_center()
                        .size(self.z(ICON_BUTTON))
                        .when(running, |d| {
                            d.child(
                                icon(IconName::LoaderCircle, self.z(ICON), hsla(theme.text_muted))
                                    .with_transformation(Transformation::rotate(radians(
                                        turn * TAU,
                                    ))),
                            )
                        }),
                )
                .child(div().flex_1())
                .child(
                    div()
                        .flex_none()
                        .font_features(tabular())
                        .text_color(hsla(theme.text_muted))
                        .when(tab.searched.is_some(), |d| d.child(len.to_string())),
                )
        });
        let header = match kind {
            ResultsKind::Text | ResultsKind::Immediate => div()
                .child(column(220.0).child("Function"))
                .child(column(96.0).child("Address"))
                .child(column(56.0).child("In"))
                .child(div().flex_1().child("Line")),
            ResultsKind::Bytes => div()
                .child(column(96.0).child(if tab.file { "Offset" } else { "Address" }))
                .child(column(220.0).child("Item"))
                .child(div().flex_1().child("Bytes")),
            ResultsKind::Bookmarks => div()
                .child(column(220.0).child("Name"))
                .child(column(96.0).child("Address"))
                .child(column(220.0).child("Function"))
                .child(div().flex_1().child("Item")),
        }
        .flex()
        .flex_none()
        .items_center()
        .h(px(row_h))
        .px(self.z(12.0))
        .border_b_1()
        .border_color(hsla(theme.border_variant))
        .text_color(hsla(theme.text_muted));
        let first = usize::try_from(tab.scroll.anchor.line).unwrap_or(usize::MAX);
        let offset = tab.scroll.anchor.offset;
        let selected = tab.selected;
        let code = |text: String, runs: Vec<TextRun>| {
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .font_family(self.settings.code_font.clone())
                .text_size(px(self.code_size()))
                .child(StyledText::new(text).with_runs(runs))
        };
        let mut body = div()
            .id(("results-rows", n))
            .flex_1()
            .min_h_0()
            .relative()
            .overflow_hidden()
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                let shown = this.results_rows_shown(id) as u64;
                let len = match this.search.tabs.get(&n).map(|t| t.kind) {
                    Some(ResultsKind::Bookmarks) => this.bookmark_rows().len(),
                    _ => this.search.tabs.get(&n).map_or(0, ResultsTab::len),
                } as u64;
                if let Some(tab) = this.search.tabs.get_mut(&n) {
                    tab.scroll.wheel(wheel(e), row_h, len, shown);
                }
                cx.notify();
            }))
            .child(measured(bounds).absolute().size_full());
        for k in first..(first + shown + 1).min(len) {
            let y = f((k - first) as u64) * row_h - offset;
            let mut row = div()
                .id(("results-row", k))
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
                .when(k == selected, |d| {
                    d.bg(hsla(if focused {
                        theme.element_selected
                    } else {
                        theme.element_hover
                    }))
                })
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .on_click(cx.listener(move |this, e: &ClickEvent, window, cx| {
                    this.results_row_click(id, n, k, e, window, cx);
                }))
                .on_aux_click(cx.listener(move |this, e: &ClickEvent, window, cx| {
                    if e.is_middle_click() {
                        this.results_row_click(id, n, k, e, window, cx);
                    }
                }));
            match (&tab.rows, kind) {
                (_, ResultsKind::Bookmarks) => {
                    let Some((address, name)) = bookmarks.get(k) else {
                        continue;
                    };
                    let function = self
                        .listing
                        .as_ref()
                        .and_then(|l| l.function_of(*address))
                        .map(|(_, e)| self.function_shown(e))
                        .unwrap_or_default();
                    let item = self
                        .listing
                        .as_ref()
                        .map(|l| l.describe(*address))
                        .unwrap_or_default();
                    row = row
                        .child(column(220.0).child(name.clone()))
                        .child(
                            column(96.0)
                                .font_features(tabular())
                                .text_color(hsla(theme.text_muted))
                                .child(format!("{address:X}")),
                        )
                        .child(column(220.0).child(function))
                        .child(
                            div()
                                .flex_1()
                                .text_color(hsla(theme.text_muted))
                                .child(item),
                        );
                }
                (Rows::Text(rows), _) => {
                    let Some(hit) = rows.rows().get(k) else {
                        continue;
                    };
                    let name = hit
                        .function
                        .map(|e| self.function_shown(e))
                        .unwrap_or_default();
                    let runs = vec![self.text_run(hit.text.len(), theme.editor_foreground, None)];
                    let marks: Vec<(Range<usize>, u32)> = hit
                        .ranges
                        .iter()
                        .map(|r| (r.clone(), theme.search_match))
                        .collect();
                    row = row
                        .child(column(220.0).child(name))
                        .child(
                            column(96.0)
                                .font_features(tabular())
                                .text_color(hsla(theme.text_muted))
                                .child(format!("{:X}", hit.address)),
                        )
                        .child(column(56.0).text_color(hsla(theme.text_muted)).child(
                            match hit.source {
                                Source::Listing => "Listing",
                                Source::C => "C",
                                Source::Declaration => "Decl.",
                            },
                        ))
                        .child(code(hit.text.clone(), marked(runs, &marks)));
                }
                (Rows::Bytes(rows, file), _) => {
                    let Some(hit) = rows.get(k) else {
                        continue;
                    };
                    let address = if *file {
                        self.hex_image().and_then(|i| i.to_address(hit.at))
                    } else {
                        Some(hit.at)
                    };
                    let item = address
                        .zip(self.listing.as_ref())
                        .map(|(a, l)| l.describe(a))
                        .unwrap_or_default();
                    let hex = |bytes: &[u8]| {
                        bytes
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect::<Vec<_>>()
                            .join(" ")
                    };
                    let parts = [hex(&hit.before), hex(&hit.bytes), hex(&hit.after)];
                    let mut text = String::new();
                    let mut runs = Vec::new();
                    for (i, part) in parts.iter().enumerate() {
                        if part.is_empty() {
                            continue;
                        }
                        if !text.is_empty() {
                            text.push(' ');
                            runs.push(self.text_run(1, theme.text_muted, None));
                        }
                        text.push_str(part);
                        let (color, back) = if i == 1 {
                            (theme.editor_foreground, Some(theme.search_match))
                        } else {
                            (theme.text_muted, None)
                        };
                        runs.push(self.text_run(part.len(), color, back));
                    }
                    row = row
                        .child(
                            column(96.0)
                                .font_features(tabular())
                                .text_color(hsla(theme.text_muted))
                                .child(format!("{:X}", hit.at)),
                        )
                        .child(column(220.0).child(item))
                        .child(code(text, runs));
                }
            }
            body = body.child(row);
        }
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        div()
            .id(("results", n))
            .key_context("List")
            .track_focus(&state.focus)
            .size_full()
            .flex()
            .flex_col()
            .bg(hsla(theme.editor))
            .rounded_b(self.island_corner())
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, _| {
                    this.layout.focus(id);
                }),
            )
            .capture_key_down(cx.listener(move |this, e: &KeyDownEvent, window, cx| {
                this.results_keys(id, n, e, window, cx);
            }))
            .children(bar)
            .child(header)
            .child(body)
            .into_any_element()
    }

    /// Results tab `n`'s label.
    pub fn results_label(&self, n: u32) -> String {
        let Some(tab) = self.search.tabs.get(&n) else {
            return "Search".to_owned();
        };
        let what = match tab.kind {
            ResultsKind::Text => "Search",
            ResultsKind::Bytes => "Bytes",
            ResultsKind::Immediate => "Immediate",
            ResultsKind::Bookmarks => return "Bookmarks".to_owned(),
        };
        match &tab.searched {
            Some((text, ..)) if !text.is_empty() => format!("{what}: {text}"),
            _ => what.to_owned(),
        }
    }

    // ---- bookmarks ----

    /// `Alt+M`: names a bookmark at the cursor's address (its name if it
    /// has one, else the item's).
    fn open_bookmark(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(address) = self.current_address() else {
            return;
        };
        let current = self
            .session
            .as_ref()
            .and_then(|s| s.overlay().bookmarks.get(&address).cloned());
        let default = self
            .listing
            .as_ref()
            .map_or_else(|| format!("{address:X}"), |l| l.describe(address));
        let current = current.unwrap_or_else(|| default.clone());
        self.open_prompt(
            PromptKind::Bookmark(address),
            &current,
            &default,
            window,
            cx,
        );
    }

    /// Every bookmark's mark colours, by address: one's own (shared or
    /// private) in the muted text colour first, then each other person's
    /// in theirs (empty without a binary).
    pub fn bookmark_colors(&self) -> BTreeMap<u64, Vec<Hsla>> {
        let mut out: BTreeMap<u64, Vec<Hsla>> = BTreeMap::new();
        let Some(session) = &self.session else {
            return out;
        };
        let own = hsla(self.theme.text_muted);
        let mine = session
            .overlay()
            .bookmarks
            .keys()
            .chain(session.private_bookmarks().keys());
        for &address in mine {
            let colors = out.entry(address).or_default();
            if colors.is_empty() {
                colors.push(own);
            }
        }
        for (&key, marks) in session.others_bookmarks() {
            let color = self.person_color(key);
            for &address in marks.keys() {
                out.entry(address).or_default().push(color);
            }
        }
        out
    }

    /// The quiet marks of a bookmarked line in a gutter: a short bar per
    /// person whose bookmark it is, in `colors`, side by side from its
    /// left edge plus `start` (three at most).
    pub fn bookmark_marks(&self, colors: &[Hsla], row_h: f32, start: f32) -> Vec<AnyElement> {
        let h = (row_h * 0.6).round();
        colors
            .iter()
            .take(BOOKMARK_BARS)
            .enumerate()
            .map(|(i, &color)| {
                div()
                    .absolute()
                    .left(px(start) + self.z(2.0 + 4.0 * f(i as u64)))
                    .top(px(((row_h - h) / 2.0).round()))
                    .w(self.z(3.0))
                    .h(px(h))
                    .rounded(self.z(1.0))
                    .bg(color)
                    .into_any_element()
            })
            .collect()
    }

    // ---- commands ----

    /// The search commands' facts.
    pub fn search_facts(&self, facts: Facts) -> Facts {
        let id = self.layout.focused();
        let searching = match self.layout.active(id) {
            Some(TabKind::Found(n)) => self.search.tabs.get(n).is_some_and(ResultsTab::is_running),
            _ => false,
        };
        Facts {
            findable: self.find_kind(id).is_some(),
            finding: self.search.bars.contains_key(&id),
            searching,
            ..facts
        }
    }

    /// Runs `command` if it is a search command; whether it was.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "the search commands of the registry; `run` takes the rest"
    )]
    pub fn search_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let id = self.layout.focused();
        match command {
            Command::Find => self.open_find(window, cx),
            Command::FindNext => self.find_step(id, true),
            Command::FindPrevious => self.find_step(id, false),
            Command::SearchEverywhere => self.open_results(ResultsKind::Text, window, cx),
            Command::SearchBytes => self.open_results(ResultsKind::Bytes, window, cx),
            Command::SearchImmediate => self.open_results(ResultsKind::Immediate, window, cx),
            Command::Bookmarks => self.open_results(ResultsKind::Bookmarks, window, cx),
            Command::Bookmark => self.open_bookmark(window, cx),
            Command::StopSearch => {
                if let Some(TabKind::Found(n)) = self.layout.active(id)
                    && let Some(tab) = self.search.tabs.get_mut(n)
                {
                    tab.running = None;
                }
            }
            _ => return false,
        }
        true
    }
}

/// `a` and `b` (each in order by `le`) merged, in order.
fn merge<T>(a: Vec<T>, b: Vec<T>, le: impl Fn(&T, &T) -> bool) -> Vec<T> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let mut a = a.into_iter().peekable();
    let mut b = b.into_iter().peekable();
    loop {
        let take_a = match (a.peek(), b.peek()) {
            (Some(x), Some(y)) => le(x, y),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let next = if take_a { a.next() } else { b.next() };
        out.extend(next);
    }
    out
}

/// How many people's bookmark bars a gutter line shows at most.
const BOOKMARK_BARS: usize = 3;

/// A document's lines showing a bookmark, with the colours of whose
/// bookmarks they are (each once, in address order), as
/// [`CDocument::marked_lines`] places them (`inside`: the addresses of
/// the document's function).
pub fn bookmarked_lines(
    document: &CDocument,
    marks: &BTreeMap<u64, Vec<Hsla>>,
    inside: impl Fn(u64) -> bool,
) -> BTreeMap<usize, Vec<Hsla>> {
    document
        .marked_lines(marks, inside)
        .into_iter()
        .map(|(n, marks)| {
            let mut line: Vec<Hsla> = Vec::new();
            for color in marks.into_iter().flat_map(|(_, colors)| colors) {
                if !line.contains(color) {
                    line.push(*color);
                }
            }
            (n, line)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use gpui_kit::{TextRun, font};

    use super::{marked, merge};
    use crate::theme::hsla;

    fn run(len: usize) -> TextRun {
        TextRun {
            len,
            font: font("Iosevka"),
            color: hsla(0xffff_ffff),
            background_color: None,
            underline: None,
            strikethrough: None,
        }
    }

    #[test]
    fn marks_split_runs_where_they_start_and_end() {
        // Runs of 4 and 6 bytes; a mark across their boundary, one inside
        // the second.
        let out = marked(vec![run(4), run(6)], &[(2..5, 1), (7..9, 2)]);
        let lens: Vec<usize> = out.iter().map(|r| r.len).collect();
        assert_eq!(lens, vec![2, 2, 1, 2, 2, 1]);
        let marks: Vec<Option<_>> = out.iter().map(|r| r.background_color).collect();
        assert_eq!(
            marks,
            vec![
                None,
                Some(hsla(1)),
                Some(hsla(1)),
                None,
                Some(hsla(2)),
                None
            ]
        );
    }

    #[test]
    fn merging_keeps_order_and_every_element() {
        assert_eq!(
            merge(vec![1, 4, 9], vec![2, 4, 10], |a, b| a <= b),
            vec![1, 2, 4, 4, 9, 10]
        );
        assert_eq!(merge(Vec::new(), vec![3], |a, b| a <= b), vec![3]);
    }
}
