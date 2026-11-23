//! The IR viewer in a C pane:
//! the function through every stage of its decompilation
//! (`binbun_gui_view::ir`), dense as the listing, a stage scrubber in the
//! pane's toolbar (`<`, the stage, `>`, a dropdown of every stage with
//! its counts), the stage as a unified diff against the one before
//! (removed lines and each changed line's old form in place, the tokens
//! a changed line changed stronger) or, toggled, as it is (added and
//! changed lines as quiet tints, each group of removed lines one row a
//! click opens), the pass's reason on hover, and the cursor kept through
//! the stages and synced with the other panes.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;
use std::time::Instant;

use binbun::stages::{Change, Level, Stage, Stages};
use binbun_gui_view::commands::Command;
use binbun_gui_view::ir::{self, Role, Row, TokenDiff};
use binbun_gui_view::layout::{Axis, PaneId};
use binbun_gui_view::scroll::Wheel;
use binbun_gui_view::{Asked, FunctionId, Question, View};
use gpui_kit::assets::IconName;
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, MouseButton, MouseDownEvent, MouseMoveEvent, Pixels, ScrollEvent,
    StyledText, TextRun, Window, div, px,
};

use crate::listing_view::SCROLLBAR;
use crate::panes::measured;
use crate::scrolling::{scrolled, wheel};
use crate::sidebar::tabular;
use crate::theme::{Theme, dim, hsla, solid, with_alpha};
use crate::workspace::{ICON, ICON_BUTTON, TabKind, Workspace, f, rows_in};

/// What stages are kept by: the function and whether it is the reading
/// view.
type Key = (FunctionId, bool);

fn key(function: FunctionId, view: View) -> Key {
    (function, view == View::Reading)
}

/// What a stage's rows are kept by: its stages' key, the stage, whether
/// it is shown as a diff and the groups of removed lines opened.
type RowsKey = (Key, usize, bool, Vec<usize>);

/// The IR viewer's state beside the panes: each function's stages as
/// the session answered them, and the questions still out.
#[derive(Debug, Default)]
pub struct IrUi {
    /// The stages, or why there are none, by function and view.
    stages: HashMap<Key, Result<Arc<Stages>, String>>,
    /// The questions out, by what they ask for.
    asked: HashMap<Key, (Asked, Instant)>,
    /// The rows of each stage shown.
    rows: HashMap<RowsKey, Arc<Vec<Row>>>,
    /// The tokens each changed line changed, by its function, view,
    /// stage and line.
    tokens: HashMap<(Key, usize, usize), Arc<TokenDiff>>,
}

/// The alpha of a changed line's tint.
const TINT: u8 = 0x1c;

/// The alpha of the tint of the tokens a changed line changed.
const TOKEN_TINT: u8 = 0x38;

/// How a row of the IR viewer looks.
#[derive(Default)]
struct Look {
    /// Its text.
    text: String,
    /// Its line's number (`None`: a line of the stage before, folded
    /// lines).
    number: Option<usize>,
    /// The diff's sign in the gutter.
    sign: Option<char>,
    /// Its change's colour: the gutter's bar, the sign, the tokens' tint.
    color: Option<u32>,
    /// Its tint's colour.
    tint: Option<u32>,
    /// Its text dimmed (a line of the stage before).
    dimmed: bool,
    /// Its text in one quiet colour (folded lines).
    quiet: bool,
    /// The tokens its line changed.
    marks: Option<Arc<TokenDiff>>,
    /// It is a changed line's old form (its marks are the old ones).
    was: bool,
    /// The pass's reason.
    reason: Option<String>,
}

/// The colour of a token of `role`.
fn role_color(theme: &Theme, role: Role) -> u32 {
    match role {
        Role::Address | Role::Node => theme.comment_doc,
        Role::Mnemonic => theme.embedded,
        Role::Register | Role::Type => theme.type_,
        Role::Operation | Role::Function => theme.function,
        Role::Value => theme.parameter,
        Role::Variable | Role::Plain => theme.variable,
        Role::Block => theme.label,
        Role::Number => theme.number,
        Role::Keyword => theme.keyword,
        Role::String => theme.string,
        Role::Comment => theme.comment,
        Role::Punctuation => theme.punctuation,
    }
}

/// A change's colour: added in the theme's success colour, changed in its
/// accent, removed in its error colour.
fn change_color(theme: &Theme, change: Option<Change>) -> u32 {
    match change {
        Some(Change::Added) => theme.success,
        Some(Change::Changed) => theme.accent,
        None => theme.error,
    }
}

/// A level's name in the dropdown.
fn level_name(level: Level) -> &'static str {
    match level {
        Level::Machine => "asm",
        Level::L1 => "L1",
        Level::L2 => "L2",
        Level::C => "C",
    }
}

/// The tooltip of stage `index`'s row in the dropdown: its pass's counts
/// and refusals, if a pass made it.
fn pass_tip(stages: &Stages, index: usize) -> Option<String> {
    stages.pass(index).map(|p| {
        let mut tip = format!(
            "{}: ran {}, changed {}, refused {}",
            p.name, p.stats.runs, p.stats.changed, p.stats.refused
        );
        for refusal in &p.refusals {
            tip.push_str("\nrefused: ");
            tip.push_str(refusal);
        }
        tip
    })
}

impl Workspace {
    /// Whether pane `id` shows the IR viewer.
    pub fn shows_ir(&self, id: PaneId) -> bool {
        matches!(self.layout.active(id), Some(TabKind::C { .. }))
            && self.panes.get(&id).is_some_and(|s| s.ir.on)
    }

    /// The stages key of pane `id`'s C tab.
    fn ir_key(&self, id: PaneId) -> Option<Key> {
        match self.layout.active(id)? {
            TabKind::C {
                function: Some(function),
                view,
            } => Some(key(*function, *view)),
            TabKind::C { function: None, .. }
            | TabKind::Listing
            | TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    /// The stages pane `id` shows, if they are here.
    fn ir_stages(&self, id: PaneId) -> Option<Arc<Stages>> {
        let k = self.ir_key(id)?;
        self.ir.stages.get(&k)?.as_ref().ok().cloned()
    }

    /// The rows of stage `index` of the stages of `k`, as a diff or not,
    /// the groups of removed lines `open` opened (kept once made).
    fn ir_rows(
        &mut self,
        k: Key,
        stages: &Stages,
        index: usize,
        diff: bool,
        open: &[usize],
    ) -> Arc<Vec<Row>> {
        let Some(stage) = stages.stages.get(index) else {
            return Arc::default();
        };
        Arc::clone(
            self.ir
                .rows
                .entry((k, index, diff, open.to_vec()))
                .or_insert_with(|| Arc::new(ir::rows(stage, diff, open))),
        )
    }

    /// The tokens changed line `line` of stage `index` of the stages of
    /// `k` changed (kept once found).
    fn ir_tokens(&mut self, k: Key, stages: &Stages, index: usize, line: usize) -> Arc<TokenDiff> {
        let Some(stage) = stages.stages.get(index) else {
            return Arc::default();
        };
        let was = stage
            .lines
            .get(line)
            .and_then(|l| l.was)
            .zip(index.checked_sub(1).and_then(|i| stages.stages.get(i)))
            .map(|(was, before)| before.line_text(was));
        Arc::clone(self.ir.tokens.entry((k, index, line)).or_insert_with(|| {
            Arc::new(was.map_or_else(TokenDiff::default, |was| {
                ir::changed_tokens(stage.level, was, stage.line_text(line))
            }))
        }))
    }

    /// How row `row` of stage `index` of the stages of `k` looks, shown
    /// as a diff (`diff`) or not.
    fn ir_look(&mut self, k: Key, stages: &Stages, index: usize, row: Row, diff: bool) -> Look {
        let theme = self.theme;
        let Some(stage) = stages.stages.get(index) else {
            return Look::default();
        };
        let removed = |text: String| Look {
            text,
            sign: Some('\u{2212}'),
            color: Some(theme.error),
            tint: Some(theme.error),
            dimmed: true,
            ..Look::default()
        };
        match row {
            Row::Line(line) => {
                let at = stage.lines.get(line);
                let change = at.and_then(|l| l.change);
                // Diffing, a changed line shown below its old form is the
                // new one: added.
                let paired =
                    diff && change == Some(Change::Changed) && at.is_some_and(|l| l.was.is_some());
                let color = change.map(|c| {
                    if paired {
                        theme.success
                    } else {
                        change_color(theme, Some(c))
                    }
                });
                Look {
                    text: stage.line_text(line).to_owned(),
                    number: Some(line),
                    sign: (diff && (paired || change == Some(Change::Added))).then_some('+'),
                    color,
                    tint: color,
                    marks: paired.then(|| self.ir_tokens(k, stages, index, line)),
                    reason: at.and_then(|l| l.reason.clone()),
                    ..Look::default()
                }
            }
            Row::Was(line) => Look {
                marks: Some(self.ir_tokens(k, stages, index, line)),
                was: true,
                ..removed(
                    stage
                        .lines
                        .get(line)
                        .and_then(|l| l.was)
                        .zip(index.checked_sub(1).and_then(|i| stages.stages.get(i)))
                        .map(|(was, before)| before.line_text(was).to_owned())
                        .unwrap_or_default(),
                )
            },
            Row::Removed(r) => removed(
                stage
                    .removed
                    .get(r)
                    .map(|r| r.text.clone())
                    .unwrap_or_default(),
            ),
            Row::Folded { count, .. } => Look {
                text: format!("{count} removed"),
                color: Some(theme.error),
                quiet: true,
                ..Look::default()
            },
        }
    }

    /// How many rows pane `id`'s IR viewer has.
    pub fn ir_total(&self, id: PaneId) -> u64 {
        let (Some(k), Some(stages), Some(state)) =
            (self.ir_key(id), self.ir_stages(id), self.panes.get(&id))
        else {
            return 0;
        };
        let index = state.ir.stage(&stages);
        let made = self
            .ir
            .rows
            .get(&(k, index, state.ir.diff, state.ir.open.clone()));
        made.map_or_else(|| state.ir.rows(&stages).len(), |rows| rows.len()) as u64
    }

    /// The address pane `id`'s IR cursor stands for.
    pub fn ir_address(&self, id: PaneId) -> Option<u64> {
        let stages = self.ir_stages(id)?;
        let state = self.panes.get(&id)?;
        state.ir.address(&stages).or(Some(stages.entry))
    }

    /// Pane `id`'s IR cursor to the line standing for `address` (when its
    /// stages come, if they are on their way); `focus`: as a jump.
    pub fn ir_land(&mut self, id: PaneId, address: u64, focus: bool) {
        let stages = self.ir_stages(id);
        let rows = self.rows(id, self.settings.listing_line_height);
        let total = self.ir_total(id);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        state.ir.scroll.smooth.stop();
        let Some(stages) = stages else {
            state.ir.target = Some(address);
            state.ir.cursor = 0;
            state.ir.scroll.anchor = binbun_gui_view::scroll::ScrollAnchor::default();
            return;
        };
        state.ir.target = None;
        if state.ir.land(&stages, address) {
            let cursor = state.ir.cursor as u64;
            if focus {
                state.ir.scroll.anchor.focus(cursor, total, rows);
            } else {
                state.ir.scroll.anchor.reveal(cursor, total, rows, rows / 3);
            }
        }
    }

    /// Moves pane `id`'s IR cursor `delta` rows.
    pub fn ir_move(&mut self, id: PaneId, delta: i64) {
        let total = self.ir_total(id);
        let rows = self.rows(id, self.settings.listing_line_height);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        if total == 0 {
            return;
        }
        let current = state.ir.cursor as u64;
        let to = if delta < 0 {
            current.saturating_sub(delta.unsigned_abs())
        } else {
            current.saturating_add(delta.unsigned_abs()).min(total - 1)
        };
        state.ir.cursor = usize::try_from(to).unwrap_or(0);
        state.ir.scroll.reveal(to, total, rows, 2);
        self.moved(id);
    }

    /// Pane `id`'s IR viewer `delta` stages on, the cursor kept on what it
    /// stood for and on the same row of the pane.
    pub fn ir_step(&mut self, id: PaneId, delta: isize) {
        let Some(stages) = self.ir_stages(id) else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let screen = (state.ir.cursor as u64).saturating_sub(state.ir.scroll.anchor.line);
        if state.ir.step(&stages, delta) {
            self.ir_keep_row(id, screen);
        }
    }

    /// Shows stage `to` in pane `id`, the cursor kept as [`Self::ir_step`]
    /// keeps it.
    fn ir_go(&mut self, id: PaneId, to: usize) {
        let Some(stages) = self.ir_stages(id) else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        state.ir.dropdown = false;
        let screen = (state.ir.cursor as u64).saturating_sub(state.ir.scroll.anchor.line);
        if state.ir.go(&stages, to) {
            self.ir_keep_row(id, screen);
        }
    }

    /// Scrolls pane `id`'s IR viewer so its cursor is on the `screen`-th
    /// row.
    fn ir_keep_row(&mut self, id: PaneId, screen: u64) {
        let total = self.ir_total(id);
        let rows = self.rows(id, self.settings.listing_line_height);
        if let Some(state) = self.panes.get_mut(&id) {
            let cursor = state.ir.cursor as u64;
            state.ir.scroll.smooth.stop();
            state.ir.scroll.anchor.line = cursor
                .saturating_sub(screen)
                .min(binbun_gui_view::scroll::ScrollAnchor::max_line(total, rows));
            state.ir.scroll.anchor.offset = 0.0;
            state.ir.scroll.anchor.reveal(cursor, total, rows, 0);
        }
    }

    /// Shows or hides the removed lines in pane `id`'s IR viewer.
    pub fn toggle_ir_diff(&mut self, id: PaneId) {
        let Some(stages) = self.ir_stages(id) else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let screen = (state.ir.cursor as u64).saturating_sub(state.ir.scroll.anchor.line);
        let diff = !state.ir.diff;
        state.ir.set_diff(&stages, diff);
        self.ir_keep_row(id, screen);
    }

    /// The IR View command: in a C pane, its IR viewer on or off, the
    /// cursor kept; elsewhere, the IR viewer in the C pane beside (or a C
    /// tab here), on the cursor's function.
    pub fn show_in_ir(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        let address = self.current_address();
        let pane = if matches!(self.layout.active(id), Some(TabKind::C { .. })) {
            id
        } else if let Some(other) = self.layout.panes().find(|p| {
            p.id != id
                && matches!(
                    p.tabs.get(p.active).map(|t| &t.content),
                    Some(TabKind::C { .. })
                )
        }) {
            other.id
        } else {
            let view = self.default_view();
            match self.layout.split(
                id,
                Axis::Row,
                TabKind::C {
                    function: None,
                    view,
                },
            ) {
                Some(new) => {
                    self.ensure_pane(new, cx);
                    new
                }
                None => return,
            }
        };
        let on = pane != id || !self.shows_ir(pane);
        if let Some(state) = self.panes.get_mut(&pane) {
            state.ir.on = on;
            state.ir.dropdown = false;
        }
        if let Some(address) = address {
            self.set_cursor(pane, address, true);
        }
        self.focus_pane(pane, window, cx);
        self.ensure_documents();
    }

    /// Closes every IR dropdown; whether one was open.
    pub fn close_ir_dropdowns(&mut self) -> bool {
        let mut open = false;
        for state in self.panes.values_mut() {
            open |= std::mem::take(&mut state.ir.dropdown);
        }
        open
    }

    /// Asks for the stages every IR viewer shows, cancelling those no
    /// viewer shows any more.
    pub fn ensure_stages(&mut self) {
        let wanted: Vec<Key> = self
            .layout
            .panes()
            .map(|p| p.id)
            .filter(|&id| self.shows_ir(id))
            .filter_map(|id| self.ir_key(id))
            .collect();
        self.ir.asked.retain(|k, (asked, _)| {
            let keep = wanted.contains(k);
            if !keep {
                asked.cancel();
            }
            keep
        });
        let Some(session) = &self.session else {
            return;
        };
        for k in wanted {
            if self.ir.stages.contains_key(&k) || self.ir.asked.contains_key(&k) {
                continue;
            }
            let view = if k.1 { View::Reading } else { View::Exact };
            let asked = session.ask(k.0, view, Question::Stages);
            self.ir.asked.insert(k, (asked, Instant::now()));
        }
    }

    /// Takes the answer to the stages question `request`.
    pub fn on_stages(&mut self, request: u64, result: Result<Arc<Stages>, String>) {
        let Some(&k) = self
            .ir
            .asked
            .iter()
            .find(|(_, (asked, _))| asked.request == request)
            .map(|(k, _)| k)
        else {
            return;
        };
        if let Some((_, at)) = self.ir.asked.remove(&k) {
            trace!("stages {k:?}: {:.1} ms", at.elapsed().as_secs_f64() * 1e3);
        }
        self.ir.stages.insert(k, result);
        let ids: Vec<PaneId> = self.panes.keys().copied().collect();
        for id in ids {
            if self.ir_key(id) == Some(k)
                && let Some(address) = self.panes.get(&id).and_then(|s| s.ir.target)
            {
                self.ir_land(id, address, true);
            }
        }
    }

    /// The stage scrubber in pane `id`'s toolbar: `<`, the stage (a click
    /// opens the dropdown), `>`, and the diff toggle.
    pub fn ir_toolbar(&self, id: PaneId, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let Some(state) = self.panes.get(&id) else {
            return Vec::new();
        };
        let Some(stages) = self.ir_stages(id) else {
            return Vec::new();
        };
        let index = state.ir.stage(&stages);
        let label = stages
            .stages
            .get(index)
            .map(|s| s.label.clone())
            .unwrap_or_default();
        let last = stages.stages.len().saturating_sub(1);
        let focus =
            move |this: &mut Self, _: &MouseDownEvent, _: &mut Window, _: &mut Context<Self>| {
                this.layout.focus(id);
            };
        let previous = self
            .icon_button(
                ("ir-prev", id.0),
                IconName::ChevronLeft,
                Command::IrPreviousStage,
                index > 0,
                false,
                cx,
            )
            .on_mouse_down(MouseButton::Left, cx.listener(focus));
        let next = self
            .icon_button(
                ("ir-next", id.0),
                IconName::ChevronRight,
                Command::IrNextStage,
                index < last,
                false,
                cx,
            )
            .on_mouse_down(MouseButton::Left, cx.listener(focus));
        let open = state.ir.dropdown;
        let picker = div()
            .id(("ir-stage", id.0))
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(4.0))
            .h(self.z(ICON_BUTTON))
            .px(self.z(6.0))
            .rounded(self.z(4.0))
            .text_color(hsla(theme.text))
            .when(open, |d| d.bg(hsla(theme.element_selected)))
            .when(!open, |d| d.hover(|s| s.bg(hsla(theme.element_hover))))
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
            .on_click(cx.listener(move |this, _, _, cx| {
                this.layout.focus(id);
                if let Some(state) = this.panes.get_mut(&id) {
                    state.ir.dropdown = !state.ir.dropdown;
                }
                cx.notify();
            }))
            .child(label)
            .child(crate::icons::icon(
                IconName::ChevronDown,
                self.z(ICON),
                hsla(theme.text_muted),
            ));
        let diff = self
            .icon_button(
                ("ir-diff", id.0),
                IconName::Diff,
                Command::ToggleIrDiff,
                true,
                state.ir.diff,
                cx,
            )
            .on_mouse_down(MouseButton::Left, cx.listener(focus));
        vec![
            div()
                .flex()
                .flex_none()
                .items_center()
                .gap(px(1.0))
                .child(previous)
                .child(picker)
                .child(next)
                .into_any_element(),
            diff.into_any_element(),
        ]
    }

    /// Pane `id`'s IR viewer.
    #[expect(clippy::too_many_lines, reason = "one row's layers, in order")]
    pub fn render_ir(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let row_h = self.row(self.settings.listing_line_height);
        let rows = self.rows(id, self.settings.listing_line_height);
        let k = self.ir_key(id);
        let stages = self.ir_stages(id);
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        let bounds = std::rc::Rc::clone(&state.bounds);
        let focused = self.layout.focused() == id;
        let mut pane = div()
            .id(("ir-pane", id.0))
            .key_context("Code")
            .track_focus(&state.focus)
            .size_full()
            .relative()
            .overflow_hidden()
            .bg(hsla(theme.editor))
            .rounded_b(self.island_corner())
            .font_family(self.settings.code_font.clone())
            .font_features(self.font_features())
            .text_size(px(self.code_size()))
            .line_height(px(row_h))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.ir_down(id, e, window, cx);
                }),
            )
            .on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, _, cx| {
                if this.scrollbar_move(id, e) || this.sideways_move(id, e) {
                    cx.notify();
                }
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, _| {
                    this.scrollbar_drag = None;
                    this.sideways_drag = None;
                }),
            )
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                this.ir_wheel(id, e);
                cx.notify();
            }))
            .child(measured(bounds).absolute().size_full());
        let pending = k.is_some_and(|k| self.ir.asked.contains_key(&k));
        let error = k.and_then(|k| self.ir.stages.get(&k)?.as_ref().err().cloned());
        if pending {
            pane = pane.child(self.loading_bar(id, window));
        }
        if let Some(error) = error {
            return pane
                .child(
                    div()
                        .p(self.z(12.0))
                        .text_color(hsla(theme.text_muted))
                        .child(error),
                )
                .into_any_element();
        }
        let (Some(stages), Some(k)) = (stages, k) else {
            return pane.into_any_element();
        };
        let index = state.ir.stage(&stages);
        let Some(current) = stages.stages.get(index) else {
            return pane.into_any_element();
        };
        let diff = state.ir.diff;
        let open = state.ir.open.clone();
        let cursor = state.ir.cursor;
        let anchor = state.ir.scroll.anchor;
        let dropdown = state.ir.dropdown;
        // The text scrolled sideways past the gutter.
        let sx = state.ir.side.x;
        let shown = self.ir_rows(k, &stages, index, diff, &open);
        let total = shown.len();
        let digits = current.lines.len().max(1).to_string().len().max(3);
        let char_w = self.char_width.unwrap_or(8.0);
        let gutter = char_w * f(digits as u64 + 2);
        // The widest line drawn, from the text's left edge.
        let text_pad = f32::from(self.z(8.0));
        let mut widest: f32 = 0.0;
        for on_screen in 0..=rows {
            let Some(n) = usize::try_from(anchor.line + on_screen)
                .ok()
                .filter(|&n| n < total)
            else {
                break;
            };
            let Some(&row) = shown.get(n) else {
                break;
            };
            let look = self.ir_look(k, &stages, index, row, diff);
            let y = f(on_screen) * row_h - anchor.offset;
            let background = if n == cursor {
                Some(if focused {
                    theme.active_line
                } else {
                    theme.lit()
                })
            } else {
                look.tint.map(|c| with_alpha(c, TINT))
            };
            let runs: Vec<TextRun> = if look.quiet {
                vec![self.text_run(look.text.len(), theme.text_muted, None)]
            } else {
                let marked: &[Range<usize>] = match &look.marks {
                    Some(tokens) if look.was => &tokens.old,
                    Some(tokens) => &tokens.new,
                    None => &[],
                };
                let strong = look.color.map(|c| with_alpha(c, TOKEN_TINT));
                ir::marked_roles(current.level, &look.text, marked)
                    .into_iter()
                    .map(|(range, role, on)| {
                        let color = role_color(theme, role);
                        let color = if look.dimmed { dim(color) } else { color };
                        self.text_run(range.len(), color, strong.filter(|_| on))
                    })
                    .collect()
            };
            let number_color = if n == cursor {
                theme.active_line_number
            } else {
                theme.line_number
            };
            // The gutter's change bar: added, changed, removed.
            let bar = look.color.map(|color| {
                div()
                    .absolute()
                    .left_0()
                    .top_0()
                    .w(px(3.0))
                    .h_full()
                    .bg(hsla(color))
            });
            // The diff's sign: `+` added, `−` removed.
            let sign = look.sign.zip(look.color).map(|(sign, color)| {
                div()
                    .flex()
                    .flex_none()
                    .justify_center()
                    .w(px(char_w * 2.0))
                    .text_color(hsla(color))
                    .child(sign.to_string())
            });
            widest = widest.max(text_pad + f(look.text.chars().count() as u64 + 1) * char_w);
            let mut element = div()
                .id(("ir-row", n))
                .absolute()
                .top(px(y))
                .left_0()
                .right(self.z(SCROLLBAR))
                .h(px(row_h))
                .overflow_hidden()
                .when_some(background, |d, b| d.bg(hsla(b)))
                .child(scrolled(
                    gutter,
                    sx,
                    div()
                        .flex()
                        .whitespace_nowrap()
                        .child(div().flex_none().w(px(gutter)))
                        .child(
                            div()
                                .flex()
                                .flex_none()
                                .pl(px(text_pad))
                                .child(StyledText::new(look.text).with_runs(runs)),
                        ),
                ))
                .child(
                    div()
                        .absolute()
                        .top_0()
                        .left_0()
                        .flex()
                        .w(px(gutter))
                        .h_full()
                        .text_color(hsla(number_color))
                        .font_features(tabular())
                        .child(
                            div()
                                .flex()
                                .flex_none()
                                .justify_end()
                                .w(px(char_w * f(digits as u64)))
                                .children(look.number.map(|line| (line + 1).to_string())),
                        )
                        .children(sign)
                        .children(bar),
                )
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                        this.ir_click(id, n, e, window, cx);
                    }),
                );
            if let Some(reason) = look.reason {
                element = element
                    .tooltip(move |window, cx| Tooltip::new(reason.clone()).build(window, cx));
            }
            pane = pane.child(element);
        }
        pane = pane.child(self.scrollbar(id, total as u64, cursor as u64, anchor, rows));
        pane = pane.children(self.measured_sideways(id, gutter, widest));
        if dropdown {
            pane = pane.child(self.ir_dropdown(id, &stages, index, cx));
        }
        pane.into_any_element()
    }

    /// The dropdown of every stage: its label, level, lines and its
    /// change against the stage before; the pass's counts on hover.
    fn ir_dropdown(
        &self,
        id: PaneId,
        stages: &Stages,
        shown: usize,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let row_h = self.ui_line() + crate::workspace::ROW_PAD;
        let width = stages
            .stages
            .iter()
            .map(|s| s.label.len())
            .max()
            .unwrap_or(8);
        // The interface font's average advance, generously (labels are
        // lower case and hyphens).
        let char_w = self.settings.ui_font_size * 0.6;
        let mut list = div()
            .id(("ir-dropdown", id.0))
            .absolute()
            .top(self.z(4.0))
            .right(self.z(SCROLLBAR + 4.0))
            .flex()
            .flex_col()
            .py(self.z(4.0))
            .bg(hsla(solid(theme.panel)))
            .border_1()
            .border_color(hsla(theme.border))
            .rounded(self.z(6.0))
            .shadow_lg()
            .occlude()
            .font_family(self.settings.ui_font.clone())
            .line_height(self.z(self.ui_line()))
            .text_size(self.z(self.settings.ui_font_size))
            .whitespace_nowrap()
            .on_mouse_down_out(cx.listener(move |this, _, _, cx| {
                if let Some(state) = this.panes.get_mut(&id) {
                    state.ir.dropdown = false;
                }
                cx.notify();
            }))
            .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
            .on_scroll(|_, _, cx| cx.stop_propagation());
        let mut level = None;
        for (index, stage) in stages.stages.iter().enumerate() {
            if level.is_some_and(|l| l != stage.level) {
                list = list.child(
                    div()
                        .my(self.z(3.0))
                        .h(px(1.0))
                        .bg(hsla(theme.border_variant)),
                );
            }
            level = Some(stage.level);
            let pass = pass_tip(stages, index);
            let on = index == shown;
            let mut item = div()
                .id(("ir-stage-item", index))
                .flex()
                .items_center()
                .gap(self.z(12.0))
                .h(self.z(row_h))
                .px(self.z(10.0))
                .mx(self.z(4.0))
                .rounded(self.z(4.0))
                .when(on, |d| d.bg(hsla(theme.element_selected)))
                .when(!on, |d| d.hover(|s| s.bg(hsla(theme.element_hover))))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.ir_go(id, index);
                    this.moved(id);
                    cx.notify();
                }))
                .child(
                    div()
                        .w(self.z(char_w * f(width as u64)))
                        .text_color(hsla(theme.text))
                        .child(stage.label.clone()),
                )
                .child(
                    div()
                        .w(self.z(28.0))
                        .text_color(hsla(theme.text_muted))
                        .child(level_name(stage.level)),
                )
                .child(
                    div()
                        .w(self.z(44.0))
                        .flex()
                        .justify_end()
                        .font_features(tabular())
                        .text_color(hsla(theme.text_muted))
                        .child(stage.lines.len().to_string()),
                )
                .child(self.ir_counts(stage));
            if let Some(tip) = pass {
                item = item.tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx));
            }
            list = list.child(item);
        }
        list.into_any_element()
    }

    /// A stage's added, changed and removed counts, each in its colour.
    fn ir_counts(&self, stage: &Stage) -> AnyElement {
        let theme = self.theme;
        let (added, changed, removed) = if stage.compared {
            stage.counts()
        } else {
            (0, 0, 0)
        };
        let count = |n: usize, sign: char, color: u32| {
            div()
                .w(self.z(40.0))
                .flex()
                .justify_end()
                .text_color(hsla(if n > 0 { color } else { theme.text_placeholder }))
                .child(if n > 0 {
                    format!("{sign}{n}")
                } else {
                    String::new()
                })
        };
        div()
            .flex()
            .font_features(tabular())
            .child(count(added, '+', theme.success))
            .child(count(changed, '~', theme.accent))
            .child(count(removed, '-', theme.error))
            .into_any_element()
    }

    /// A click on row `n` of pane `id`'s IR viewer: the cursor there; on
    /// folded removed lines, they open in place.
    fn ir_click(
        &mut self,
        id: PaneId,
        n: usize,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.on_ir_scrollbar(id, e.position.x) || self.on_sideways_bar(id, e.position).is_some()
        {
            return;
        }
        if self.layout.focused() != id {
            self.focus_pane(id, window, cx);
        }
        let stages = self.ir_stages(id);
        if let Some(state) = self.panes.get_mut(&id) {
            if !stages.is_some_and(|stages| state.ir.unfold(&stages, n)) {
                state.ir.cursor = n;
            }
            state.ir.dropdown = false;
        }
        self.moved(id);
        cx.notify();
    }

    /// Whether `x` is on pane `id`'s scrollbar.
    fn on_ir_scrollbar(&self, id: PaneId, x: Pixels) -> bool {
        self.panes.get(&id).is_some_and(|s| {
            let b = s.bounds.get();
            f32::from(x - b.origin.x) > f32::from(b.size.width) - f32::from(self.z(SCROLLBAR))
        })
    }

    /// A press in pane `id`'s IR viewer: on a scrollbar, its drag or page;
    /// elsewhere the focus comes.
    fn ir_down(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.close_peek();
        if self.layout.focused() != id {
            self.focus_pane(id, window, cx);
        }
        if self.sideways_down(id, e) {
            cx.notify();
        } else if self.on_ir_scrollbar(id, e.position.x) {
            self.scrollbar_down(id, e.position.y);
            cx.notify();
        }
    }

    /// The wheel in pane `id`'s IR viewer.
    fn ir_wheel(&mut self, id: PaneId, e: &ScrollEvent) {
        let row = self.row(self.settings.listing_line_height);
        self.wheel_sideways(id, e, row);
        if e.modifiers.shift {
            return;
        }
        let rows = rows_in(
            self.panes
                .get(&id)
                .map_or(1.0, |s| f32::from(s.bounds.get().size.height)),
            row,
        );
        let total = self.ir_total(id);
        if let Some(state) = self.panes.get_mut(&id) {
            let given: Wheel = wheel(e);
            state.ir.scroll.wheel(given, row, total, rows);
        }
    }
}
