//! The console (Ctrl+backtick, View › Console): a tab of a pane, under
//! the code unless moved (dragged as any tab), running the user's Python
//! ([`binbun_gui_view::console`]) connected to this window's database.
//! One for the window: it keeps running while its tab is closed, moved or
//! in another window tab; Ctrl+backtick hides it where it is shown, else
//! brings it under the code of the window tab shown, from wherever it was.
//! Its transcript above (the cells run, coloured; output as it comes;
//! values; tracebacks; the undo step each cell made), only its visible
//! lines drawn; the input below: Python coloured, Enter runs the cell
//! once it is complete (else breaks the line, indented), Shift+Enter
//! breaks the line, Up and Down at the first and last line walk the
//! history; completions as typed (Tab or Enter takes one, the arrows move,
//! Escape closes) and the signature of the call typed above the input;
//! Ctrl+C interrupts the cell running, Ctrl+L clears. Its tab is saved
//! with the layout, as the others.

use std::cell::Cell;
use std::ops::Range;
use std::rc::Rc;
use std::sync::Arc;

use binbun_gui_view::console::python::{self, Kind as PyKind};
use binbun_gui_view::console::{Console, Item, Launch, Line, LineKind, Status, history};
use binbun_gui_view::layout::PaneId;
use gpui_kit::assets::IconName;
use gpui_kit::component::Sizable as _;
use gpui_kit::component::input::{
    Editor, EditorState, FoldRange, HighlightStyleResolver, InputEdit, InputEvent,
    InputHighlighter, Rope, TabSize,
};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Bounds, Context, Entity, Focusable as _, HighlightStyle, MouseButton, Pixels,
    ScrollEvent, SharedString, StyledText, Subscription, Task, Window, div, px,
};

use crate::highlight::{Highlight as _, runs};
use crate::icons::icon;
use crate::panes::measured;
use crate::scrolling::wheel;
use crate::serving;
use crate::theme::{Theme, hsla, solid};
use crate::workspace::{ICON, STATUS_PAD, TabKind, Workspace, f};

/// The input's most lines before it scrolls.
const INPUT_LINES: usize = 12;
/// The completions shown at once.
const COMPLETIONS: usize = 10;
/// The prompts.
const PROMPT: &str = ">>> ";
const CONTINUATION: &str = "... ";

/// The console: its Python, its input, its transcript's scrolling.
#[derive(Default)]
pub struct ConsoleUi {
    console: Option<Console>,
    input: Option<Entity<EditorState>>,
    /// The cell sent, until the console says whether it runs.
    pending: Option<String>,
    /// The transcript scrolled back from its end, in lines.
    scroll_back: usize,
    /// The transcript's bounds as last drawn.
    bounds: Rc<Cell<Bounds<Pixels>>>,
    /// The theme the input's colours are made for.
    coloured: Option<&'static Theme>,
    poll: Option<Task<()>>,
    subs: Vec<Subscription>,
}

impl ConsoleUi {
    /// Stops the console (its database closed): the process ended, the
    /// transcript dropped.
    pub fn stop(&mut self) {
        self.console = None;
        self.poll = None;
        self.pending = None;
        self.scroll_back = 0;
    }
}

/// The input's Python colours, from the theme.
struct Colours {
    tokens: Vec<python::Token>,
    theme: &'static Theme,
}

impl InputHighlighter for Colours {
    fn language(&self) -> SharedString {
        "python".into()
    }

    fn update(
        &mut self,
        _edit: Option<InputEdit>,
        text: &Rope,
        _folding: bool,
        _window: &mut Window,
        _cx: &mut Context<EditorState>,
    ) {
        self.tokens = python::tokens(&text.to_string());
    }

    fn styles(
        &self,
        range: &Range<usize>,
        _resolver: &dyn HighlightStyleResolver,
    ) -> Vec<(Range<usize>, HighlightStyle)> {
        let theme = self.theme;
        runs(
            self.tokens
                .iter()
                .map(|t| (t.range.clone(), theme.python(t.kind))),
            range,
        )
    }

    fn fold_ranges(&self, _text: &Rope) -> Vec<FoldRange> {
        Vec::new()
    }
}

fn colour(theme: &Theme, kind: PyKind) -> HighlightStyle {
    HighlightStyle {
        color: Some(hsla(theme.python(kind))),
        ..HighlightStyle::default()
    }
}

/// The icon of a completion of `kind` (jedi's types; rlcompleter sends
/// `function` and `instance`): the sidebar's where the meaning is the same
/// (a function, a type, a library), none for a kind not known.
fn completion_icon(kind: &str) -> Option<IconName> {
    Some(match kind {
        "function" => IconName::SquareFunction,
        "class" => IconName::Braces,
        "module" => IconName::Library,
        "instance" | "statement" | "param" => IconName::Variable,
        "property" => IconName::Wrench,
        "keyword" => IconName::CodeXml,
        "path" => IconName::File,
        _ => return None,
    })
}

/// The leading spaces of `line`, four more after a line ending in `:`.
fn indent_after(line: &str) -> String {
    let mut indent: String = line
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect();
    if line.trim_end().ends_with(':') {
        indent.push_str("    ");
    }
    indent
}

/// Whether the character before byte `at` of `code` is part of a name or
/// a dot (completions are asked there).
fn completable(code: &str, at: usize) -> bool {
    code.get(..at)
        .and_then(|before| before.chars().next_back())
        .is_some_and(|c| c == '_' || c == '.' || c.is_alphanumeric())
}

impl Workspace {
    /// Ctrl+backtick: hides the console where the window tab shown shows
    /// it (its tab closed: it keeps running; the focus back on a pane);
    /// else shows it, its input focused (started if it is not): its tab
    /// brought forward where this window tab has it, else opened under the
    /// code ([`Workspace::open_below`]), taken from the window tab that had
    /// it.
    pub fn toggle_console(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match self.console_place() {
            Some((pane, index, true)) => {
                self.layout.close_tab(pane, index);
                self.after_layout(window, cx);
            }
            Some((pane, index, false)) => {
                self.layout.activate(pane, index);
                self.focus_pane(pane, window, cx);
            }
            None => {
                self.take_parked(&TabKind::Console);
                let from = self.layout.focused();
                let id = self.open_below(from, TabKind::Console, false, cx);
                self.focus_pane(id, window, cx);
            }
        }
        cx.notify();
    }

    /// The console's tab in the window tab shown: its pane, its index
    /// there, and whether it is the tab the pane shows.
    fn console_place(&self) -> Option<(PaneId, usize, bool)> {
        self.layout.panes().find_map(|pane| {
            let index = pane
                .tabs
                .iter()
                .position(|t| t.content == TabKind::Console)?;
            Some((pane.id, index, pane.active == index))
        })
    }

    /// Whether the window tab shown shows the console.
    pub fn console_shown(&self) -> bool {
        self.console_place().is_some_and(|(_, _, shown)| shown)
    }

    /// The console's input takes the focus (the console started if it is
    /// not).
    pub fn focus_console(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.ensure_console(window, cx);
        if let Some(input) = &self.console.input {
            input.update(cx, |s, cx| s.focus(window, cx));
        }
    }

    /// What starts the console: the setting's interpreter, this window's
    /// socket and database.
    fn console_launch(&self) -> Option<Launch> {
        Some(Launch {
            interpreter: self.settings.python_interpreter.clone(),
            socket: serving::socket()?,
            database: self.session.as_ref()?.path().to_owned(),
        })
    }

    /// The input made and the console started (again, if what starts it
    /// changed: another interpreter, database or socket).
    fn ensure_console(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.console.input.is_none() {
            self.make_console_input(window, cx);
        }
        if self
            .console
            .coloured
            .is_none_or(|t| !std::ptr::eq(t, self.theme))
        {
            self.colour_console_input(cx);
        }
        let Some(launch) = self.console_launch() else {
            return;
        };
        match &mut self.console.console {
            Some(console) if *console.launch() == launch => {}
            Some(console) => {
                console.restart(Some(launch));
                self.console.pending = None;
            }
            None => {
                let (tx, rx) = async_channel::unbounded::<()>();
                let wake = Arc::new(move || {
                    let _ = tx.try_send(());
                });
                self.console.console = Some(Console::start(launch, history::path(), wake));
                self.console.poll = Some(cx.spawn_in(window, async move |this, cx| {
                    while rx.recv().await.is_ok() {
                        while rx.try_recv().is_ok() {}
                        if this.update_in(cx, Workspace::poll_console).is_err() {
                            break;
                        }
                    }
                }));
            }
        }
    }

    /// The input: a Python editor, its keys taken before the editor's.
    fn make_console_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let input = cx.new(|cx| {
            EditorState::new(window, cx)
                .line_number(false)
                .folding(false)
                .indent_guides(false)
                .searchable(false)
                .tab_size(TabSize {
                    tab_size: 4,
                    hard_tabs: false,
                })
        });
        let changes = cx.subscribe_in(&input, window, |this, input, e: &InputEvent, _, cx| {
            if matches!(e, InputEvent::Change) {
                let (code, cursor) = {
                    let state = input.read(cx);
                    (state.value().to_string(), state.cursor())
                };
                this.console_typed(&code, cursor);
                cx.notify();
            }
        });
        let this = cx.weak_entity();
        let handle = window.window_handle();
        let keys = cx.intercept_keystrokes(move |event, window, cx| {
            if window.window_handle() != handle {
                return;
            }
            let taken = this
                .update(cx, |this, cx| {
                    this.console_key(&event.keystroke, window, cx)
                })
                .unwrap_or(false);
            if taken {
                cx.stop_propagation();
            }
        });
        self.console.input = Some(input);
        self.console.subs = vec![changes, keys];
    }

    /// The input's colours made for the theme shown.
    fn colour_console_input(&mut self, cx: &mut Context<Self>) {
        let Some(input) = &self.console.input else {
            return;
        };
        let theme = self.theme;
        self.console.coloured = Some(theme);
        input.update(cx, |s, cx| {
            s.set_highlighter_factory(
                Rc::new(move |_: &str| {
                    let colours: Box<dyn InputHighlighter> = Box::new(Colours {
                        tokens: Vec::new(),
                        theme,
                    });
                    Some(colours)
                }),
                cx,
            );
        });
    }

    /// The input's text is `code`, its cursor at byte `cursor`: the
    /// history walk stops; the signature asked, and the completions where
    /// a name or a dot is typed.
    fn console_typed(&mut self, code: &str, cursor: usize) {
        let ui = &mut self.console;
        let Some(console) = &mut ui.console else {
            return;
        };
        if ui.pending.is_some() {
            return;
        }
        console.history.reset();
        let complete = completable(code, cursor);
        if !complete {
            console.completion = None;
        }
        console.ask(code, cursor, complete);
    }

    /// Takes what the console said: the input emptied once its cell is
    /// taken, a line broken where it is not complete.
    pub fn poll_console(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(console) = &mut self.console.console else {
            return;
        };
        let polled = console.poll();
        if !polled.changed {
            return;
        }
        if let Some(input) = self.console.input.clone() {
            if polled.accepted && self.console.pending.take().is_some() {
                input.update(cx, |s, cx| s.set_value("", window, cx));
                self.console.scroll_back = 0;
                if let Some(console) = &mut self.console.console {
                    console.dismiss();
                }
            }
            if polled.incomplete && self.console.pending.take().is_some() {
                input.update(cx, |s, cx| {
                    let code = s.value().to_string();
                    let at = s.cursor().min(code.len());
                    let line_start = code
                        .get(..at)
                        .and_then(|b| b.rfind('\n'))
                        .map_or(0, |n| n + 1);
                    let line = code.get(line_start..at).unwrap_or("");
                    s.insert(format!("\n{}", indent_after(line)), window, cx);
                });
            }
        }
        // A completion that is all of what is typed is not offered.
        if let (Some(console), Some(input)) = (&mut self.console.console, &self.console.input) {
            let state = input.read(cx);
            let (code, cursor) = (state.value().to_string(), state.cursor());
            if let Some(completion) = &console.completion {
                let shown = completion.shown(&code, cursor);
                let typed = code.get(completion.start..cursor).unwrap_or("");
                if shown.is_empty() || (shown.len() == 1 && shown.iter().all(|i| i.text == typed)) {
                    console.completion = None;
                }
            }
        }
        cx.notify();
    }

    /// The console's keys, before the input's: Enter, Tab, Up, Down,
    /// Escape, Ctrl+C and Ctrl+L; whether one was taken.
    fn console_key(
        &mut self,
        keystroke: &gpui_kit::Keystroke,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(input) = self.console.input.clone() else {
            return false;
        };
        if !self.console_shown() || !input.read(cx).focus_handle(cx).is_focused(window) {
            return false;
        }
        let m = &keystroke.modifiers;
        let key = keystroke.key.as_str();
        if m.control && !m.shift && !m.alt {
            return match key {
                "c" => self
                    .console
                    .console
                    .as_mut()
                    .is_some_and(Console::interrupt),
                "l" => {
                    if let Some(console) = &mut self.console.console {
                        console.transcript.clear();
                        self.console.scroll_back = 0;
                    }
                    cx.notify();
                    true
                }
                _ => false,
            };
        }
        if m.modified() {
            return false;
        }
        let taken = match key {
            "enter" => self.console_enter(&input, window, cx),
            "tab" => self.console_tab(&input, window, cx),
            "up" | "down" => self.console_arrow(key == "up", &input, window, cx),
            "escape" => {
                // The completions and the signature close; the focus
                // stays (keys typed after it must never reach a pane,
                // where letters are commands).
                match &mut self.console.console {
                    Some(console)
                        if console.completion.is_some() || console.signature.is_some() =>
                    {
                        console.dismiss();
                        true
                    }
                    Some(_) | None => false,
                }
            }
            _ => false,
        };
        if taken {
            cx.notify();
        }
        taken
    }

    /// The completions shown now: what the input holds and its cursor
    /// filter the last answer.
    fn shown_completions(&self, cx: &Context<Self>) -> Option<(usize, Vec<Item>, usize)> {
        let console = self.console.console.as_ref()?;
        let completion = console.completion.as_ref()?;
        let state = self.console.input.as_ref()?.read(cx);
        let (code, cursor) = (state.value().to_string(), state.cursor());
        if cursor < completion.start {
            return None;
        }
        let shown: Vec<Item> = completion
            .shown(&code, cursor)
            .into_iter()
            .cloned()
            .collect();
        (!shown.is_empty()).then(|| {
            let selected = completion.selected.min(shown.len() - 1);
            (completion.start, shown, selected)
        })
    }

    /// Takes the selected completion in place of what it completes;
    /// whether one was shown.
    fn take_console_completion(
        &mut self,
        input: &Entity<EditorState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some((start, shown, selected)) = self.shown_completions(cx) else {
            return false;
        };
        let Some(text) = shown.get(selected).map(|item| item.text.clone()) else {
            return false;
        };
        input.update(cx, |s, cx| {
            let cursor = s.cursor();
            s.set_selected_range(start..cursor, cx);
            s.replace(text, window, cx);
        });
        let (code, cursor) = {
            let state = input.read(cx);
            (state.value().to_string(), state.cursor())
        };
        if let Some(console) = &mut self.console.console {
            console.completion = None;
            console.ask(&code, cursor, false);
        }
        true
    }

    fn console_enter(
        &mut self,
        input: &Entity<EditorState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if self.take_console_completion(input, window, cx) {
            return true;
        }
        if self.console.pending.is_some() {
            return true;
        }
        let code = input.read(cx).value().to_string();
        if code.trim().is_empty() {
            return true;
        }
        let sent = self
            .console
            .console
            .as_mut()
            .is_some_and(|console| console.run(&code));
        if sent {
            self.console.pending = Some(code);
        }
        true
    }

    fn console_tab(
        &mut self,
        input: &Entity<EditorState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if self.take_console_completion(input, window, cx) {
            return true;
        }
        let (code, cursor) = {
            let state = input.read(cx);
            (state.value().to_string(), state.cursor())
        };
        if !completable(&code, cursor) {
            return false;
        }
        if let Some(console) = &mut self.console.console {
            console.ask(&code, cursor, true);
        }
        true
    }

    /// Up or Down: the completions' selection moved, else the history
    /// walked from the first or the last line; whether taken.
    fn console_arrow(
        &mut self,
        up: bool,
        input: &Entity<EditorState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if let Some((_, shown, selected)) = self.shown_completions(cx) {
            if let Some(completion) = self
                .console
                .console
                .as_mut()
                .and_then(|c| c.completion.as_mut())
            {
                let n = shown.len();
                completion.selected = if up {
                    (selected + n - 1) % n
                } else {
                    (selected + 1) % n
                };
            }
            return true;
        }
        let (code, line) = {
            let state = input.read(cx);
            (
                state.value().to_string(),
                state.cursor_position().line as usize,
            )
        };
        let last = code.matches('\n').count();
        if (up && line != 0) || (!up && line != last) {
            return false;
        }
        let Some(console) = &mut self.console.console else {
            return false;
        };
        let cell = if up {
            console.history.older(&code)
        } else {
            console.history.newer()
        };
        let Some(cell) = cell.map(str::to_owned) else {
            return up || !code.is_empty();
        };
        console.dismiss();
        input.update(cx, |s, cx| {
            s.set_value(cell.clone(), window, cx);
            let lines = cell.split('\n').count().saturating_sub(1);
            let column = cell.rsplit('\n').next().unwrap_or("").chars().count();
            s.set_cursor_position(
                gpui_kit::component::input::Position::new(
                    u32::try_from(lines).unwrap_or(0),
                    u32::try_from(column).unwrap_or(0),
                ),
                window,
                cx,
            );
        });
        true
    }

    /// The console as its pane shows it: its header, its transcript, the
    /// signature of the call typed, its input.
    pub fn render_console(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        self.ensure_console(window, cx);
        div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .child(self.console_header(cx))
            .child(self.console_transcript(cx))
            .children(self.console_signature(cx))
            .child(self.console_input(window, cx))
            .into_any_element()
    }

    /// The header (its tab names it): what the console is, Clear and
    /// Restart.
    fn console_header(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let status = self.console.console.as_ref().map(|c| match &c.status {
            Status::Starting => "Starting…".to_owned(),
            Status::Ready {
                python,
                completer,
                database,
            } => {
                let running = if c.running() {
                    " · running (Ctrl+C stops it)"
                } else {
                    ""
                };
                format!("Python {python} · {database} · {completer}{running}")
            }
            Status::Stopped(_) => "Stopped".to_owned(),
        });
        let button = |id: &'static str, label: &'static str| {
            div()
                .id(id)
                .px(self.z(6.0))
                .rounded(self.z(4.0))
                .text_color(hsla(theme.text_muted))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .child(label)
        };
        div()
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(8.0))
            .h(self.bar(STATUS_PAD))
            .px(self.z(8.0))
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .bg(hsla(theme.panel))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .text_color(hsla(theme.text_muted))
                    .children(status),
            )
            .child(
                button("console-clear", "Clear").on_click(cx.listener(|this, _, _, cx| {
                    if let Some(console) = &mut this.console.console {
                        console.transcript.clear();
                    }
                    this.console.scroll_back = 0;
                    cx.notify();
                })),
            )
            .child(button("console-restart", "Restart").on_click(cx.listener(
                |this, _, window, cx| {
                    if let Some(console) = &mut this.console.console {
                        console.restart(None);
                    }
                    this.console.pending = None;
                    this.ensure_console(window, cx);
                    cx.notify();
                },
            )))
            .into_any_element()
    }

    /// The transcript's lines in sight (the end, unless scrolled back),
    /// or why the console is not running.
    fn console_transcript(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let row_h = self.row(self.settings.c_line_height);
        let bounds = Rc::clone(&self.console.bounds);
        let rows = (f32::from(bounds.get().size.height) / row_h)
            .floor()
            .max(1.0);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "rows in sight"
        )]
        let rows = rows as usize;
        let mut shown: Vec<AnyElement> = Vec::new();
        if let Some(console) = &self.console.console {
            let lines = console.transcript.lines();
            let back = self
                .console
                .scroll_back
                .min(lines.len().saturating_sub(rows));
            self.console.scroll_back = back;
            let end = lines.len() - back;
            let start = end.saturating_sub(rows);
            shown.extend(
                lines
                    .range(start..end)
                    .map(|line| self.transcript_line(line, row_h)),
            );
            if let Status::Stopped(why) = &console.status {
                shown.push(
                    div()
                        .px(self.z(8.0))
                        .py(self.z(4.0))
                        .text_color(hsla(theme.error))
                        .child(why.clone())
                        .into_any_element(),
                );
            }
        } else if self.session.is_none() {
            shown.push(
                div()
                    .child("Open a binary to use the console.")
                    .into_any_element(),
            );
        }
        div()
            .id("console-transcript")
            .flex_1()
            .min_h_0()
            .relative()
            .overflow_hidden()
            .font_family(self.settings.code_font.clone())
            .text_size(px(self.code_size()))
            .line_height(px(row_h))
            .bg(hsla(solid(theme.editor)))
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                let y = match wheel(e) {
                    binbun_gui_view::scroll::Wheel::Lines(y) => y * 3.0,
                    binbun_gui_view::scroll::Wheel::Pixels(y) => y / row_h,
                };
                #[expect(clippy::cast_possible_truncation, reason = "a few lines")]
                let by = y.round() as i64;
                let back = i64::try_from(this.console.scroll_back).unwrap_or(0) + by;
                this.console.scroll_back = usize::try_from(back.max(0)).unwrap_or(0);
                cx.notify();
                cx.stop_propagation();
            }))
            .child(measured(bounds).absolute().size_full())
            .child(
                div()
                    .absolute()
                    .bottom_0()
                    .left_0()
                    .right_0()
                    .flex()
                    .flex_col()
                    .px(self.z(8.0))
                    .children(shown),
            )
            .into_any_element()
    }

    /// One transcript line: a cell's with its prompt and colours, output
    /// in its stream's colour, a value, a traceback, a note.
    fn transcript_line(&self, line: &Line, row_h: f32) -> AnyElement {
        let theme = self.theme;
        let row = div()
            .h(px(row_h))
            .flex_none()
            .whitespace_nowrap()
            .overflow_hidden()
            .text_ellipsis();
        match line.kind {
            LineKind::Input { first } => {
                let prompt = if first { PROMPT } else { CONTINUATION };
                let text = format!("{prompt}{}", line.text);
                let mut highlights: Vec<(Range<usize>, HighlightStyle)> = vec![(
                    0..prompt.len(),
                    HighlightStyle {
                        color: Some(hsla(theme.text_muted)),
                        ..HighlightStyle::default()
                    },
                )];
                highlights.extend(line.spans.iter().map(|(range, kind)| {
                    (
                        range.start + prompt.len()..range.end + prompt.len(),
                        colour(theme, *kind),
                    )
                }));
                row.text_color(hsla(theme.text))
                    .child(StyledText::new(text).with_highlights(highlights))
                    .into_any_element()
            }
            LineKind::Stdout | LineKind::Result => row
                .text_color(hsla(theme.text))
                .child(line.text.clone())
                .into_any_element(),
            LineKind::Stderr | LineKind::Error => row
                .text_color(hsla(theme.error))
                .child(line.text.clone())
                .into_any_element(),
            LineKind::Note => row
                .text_color(hsla(theme.text_muted))
                .italic()
                .child(line.text.clone())
                .into_any_element(),
        }
    }

    /// The signature of the call typed, its parameter typed underlined, a
    /// line of its documentation after it.
    fn console_signature(&self, _cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let signature = self.console.console.as_ref()?.signature.as_ref()?;
        let mut highlights = Vec::new();
        if let Some(active) = &signature.active {
            highlights.push((
                active.clone(),
                HighlightStyle {
                    color: Some(hsla(theme.accent)),
                    font_weight: Some(gpui_kit::FontWeight::BOLD),
                    ..HighlightStyle::default()
                },
            ));
        }
        let doc = (!signature.doc.is_empty()).then(|| {
            div()
                .min_w_0()
                .overflow_hidden()
                .text_ellipsis()
                .text_color(hsla(theme.text_muted))
                .child(format!("— {}", signature.doc))
        });
        Some(
            div()
                .flex()
                .flex_none()
                .gap(self.z(8.0))
                .px(self.z(8.0))
                .py(self.z(2.0))
                .whitespace_nowrap()
                .overflow_hidden()
                .border_t_1()
                .border_color(hsla(theme.border_variant))
                .bg(hsla(theme.panel))
                .font_family(self.settings.code_font.clone())
                .text_size(px(self.code_size()))
                .text_color(hsla(theme.text))
                .child(
                    div().flex_none().child(
                        StyledText::new(signature.label.clone()).with_highlights(highlights),
                    ),
                )
                .children(doc)
                .into_any_element(),
        )
    }

    /// The input with its prompt, the completions over it.
    fn console_input(&self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let Some(input) = &self.console.input else {
            return div().into_any_element();
        };
        let row_h = self.row(self.settings.c_line_height);
        let cw = self.char_width.unwrap_or(8.0);
        let state = input.read(cx);
        let code = state.value().to_string();
        let lines = code.split('\n').count();
        let cursor_line = state.cursor_position().line as usize;
        let focused = state.focus_handle(cx).is_focused(window);
        let ready = self.console.console.as_ref().is_some_and(Console::ready);
        let height = px(row_h * f(lines.clamp(1, INPUT_LINES) as u64) + 6.0);
        let prompts: Vec<AnyElement> = (0..lines.min(INPUT_LINES))
            .map(|n| {
                div()
                    .h(px(row_h))
                    .child(if n == 0 { PROMPT.trim_end() } else { "..." })
                    .into_any_element()
            })
            .collect();
        let popup = self.console_popup(&code, cursor_line, cx);
        div()
            .relative()
            .flex()
            .flex_none()
            .h(height)
            .pt(px(3.0))
            .border_t_1()
            .border_color(hsla(if focused {
                theme.border_focused
            } else {
                theme.border_variant
            }))
            .bg(hsla(solid(theme.editor)))
            .rounded_b(self.island_corner())
            .font_family(self.settings.code_font.clone())
            .text_size(px(self.code_size()))
            .line_height(px(row_h))
            .child(
                div()
                    .flex_none()
                    .w(px(cw * f(PROMPT.len() as u64)) + px(8.0))
                    .pl(px(8.0))
                    .text_color(hsla(if ready {
                        theme.text_muted
                    } else {
                        theme.text_placeholder
                    }))
                    .children(prompts),
            )
            .child(
                div().flex_1().min_w_0().h_full().child(
                    Editor::new(input)
                        .appearance(false)
                        .bordered(false)
                        .xsmall()
                        .h_full()
                        .font_family(self.settings.code_font.clone())
                        .text_size(px(self.code_size()))
                        .line_height(px(row_h)),
                ),
            )
            .on_mouse_down(MouseButton::Left, {
                let input = input.clone();
                move |_, window, cx| input.update(cx, |s, cx| s.focus(window, cx))
            })
            .children(popup)
            .into_any_element()
    }

    /// The completions over the input, at the column of what they
    /// complete, above the cursor's line (`cursor_line` of `code`).
    fn console_popup(
        &self,
        code: &str,
        cursor_line: usize,
        cx: &Context<Self>,
    ) -> Option<gpui_kit::Div> {
        let theme = self.theme;
        let row_h = self.row(self.settings.c_line_height);
        let cw = self.char_width.unwrap_or(8.0);
        let lines = code.split('\n').count();
        self.shown_completions(cx).map(|(start, shown, selected)| {
            let line_start = code
                .get(..start)
                .and_then(|b| b.rfind('\n'))
                .map_or(0, |n| n + 1);
            let column = code.get(line_start..start).map_or(0, |t| t.chars().count());
            let from = selected.saturating_sub(COMPLETIONS - 1);
            let rows: Vec<AnyElement> = shown
                .iter()
                .enumerate()
                .skip(from)
                .take(COMPLETIONS)
                .map(|(i, item)| {
                    let glyph = completion_icon(&item.kind).map_or_else(
                        || div().size(self.z(ICON)).into_any_element(),
                        |name| icon(name, self.z(ICON), hsla(theme.text_muted)).into_any_element(),
                    );
                    div()
                        .id(("console-completion", i))
                        .px(self.z(6.0))
                        .h(px(row_h))
                        .flex()
                        .items_center()
                        .gap(self.z(6.0))
                        .when(i == selected, |d| d.bg(hsla(theme.element_selected)))
                        .child(glyph)
                        .child(item.text.clone())
                        .into_any_element()
                })
                .collect();
            let x = cw * f(PROMPT.len() as u64) + 8.0 + cw * f(column as u64);
            let below = f(lines.saturating_sub(cursor_line + 1).min(INPUT_LINES) as u64) * row_h;
            div()
                .absolute()
                .left(px(x))
                .bottom(px(below + row_h + 4.0))
                .min_w(px(cw * 16.0))
                .flex()
                .flex_col()
                .bg(hsla(solid(theme.editor)))
                .border_1()
                .border_color(hsla(theme.border))
                .rounded(px(3.0))
                .shadow_lg()
                .text_color(hsla(theme.text))
                .children(rows)
        })
    }
}
