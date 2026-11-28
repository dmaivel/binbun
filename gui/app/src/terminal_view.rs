//! Terminals (Window › New Terminal, Ctrl+Shift+backtick): tabs of panes,
//! under the code unless moved (dragged as any tab), each running the
//! user's shell in the binary's folder through libghostty's emulator
//! ([`binbun_gui_view::terminal`]). A terminal's program runs while its
//! tab is shown, moved, in another window tab, or hidden by Ctrl+backtick
//! (which hides and brings back the console or the terminal used last);
//! closing its tab ends it, asked first while a program the shell started
//! runs; the shell ending without an error closes its tab. Keys go to the
//! program but binbun's: Ctrl+backtick, the Ctrl+Shift chords and the
//! platform's; Ctrl+Shift+C and Ctrl+Shift+V (Cmd+C and Cmd+V on macOS,
//! Shift+Insert elsewhere) copy the selection and paste. The mouse selects
//! (a drag; a word with two clicks, a line with three), or goes to a
//! program that asks for it (Shift held selects there); the wheel scrolls
//! back, or goes to the program. A saved layout's terminal comes back as a
//! fresh shell.
//!
//! A coding agent that says what it is (OSC 7501, `app=claude-code`) is
//! watched for its binbun server, which announces itself at its handshake
//! (`agents::announced`): none [`SERVER_AFTER`] after the agent started,
//! its harness does not run binbun, and a banner offers binbun's setup:
//! its harness's own `mcp add` command run (or Connect an Agent where a
//! config file takes it), or never again for it
//! (`binbun_paths::Place::QuietAgents`). One that announced a failure is
//! said with its reason.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun_gui_view::agents::{self, Announced, Harness, Setup, Start, setup_rows};
use binbun_gui_view::banners::{Action, Banner, Button as BannerButton, Kind, Priority, Tone};
use binbun_gui_view::commands::{self, Command};
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::scroll::Wheel;
use binbun_gui_view::terminal::{
    Button, Colors, Exit, Frame, Input, Launch, Mods, Pointer, Run, Shape, Size, State, Terminal,
};
use binbun_paths::Place;
use gpui_kit::assets::IconName;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, App, BorderStyle, Bounds, ClickEvent, ClipboardItem, Context, DispatchPhase,
    FocusHandle, Font, FontStyle, FontWeight, Hsla, Keystroke, Modifiers, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, Pixels, Point, ScrollEvent, StrikethroughStyle,
    Subscription, Task, TextAlign, TextRun, UnderlineStyle, Window, canvas, div, fill, outline,
    point, px, size,
};

use crate::context_menu::OwnItem;
use crate::panes::measured;
use crate::scrolling::wheel;
use crate::theme::{hsla, solid};
use crate::workspace::{ICON_BUTTON, TabKind, Workspace};

/// How long after a coding agent starts in a terminal its harness has to
/// start binbun's server (it announces itself at its handshake, a
/// harness's first milliseconds) before the agent is taken not to run it.
const SERVER_AFTER: Duration = Duration::from_secs(2);
/// How long the servers' announcements are read after an agent starts
/// (an interpreter failing says so once it has tried), and how often.
const WATCH: Duration = Duration::from_secs(15);
const WATCH_EVERY: Duration = Duration::from_millis(200);
/// How much earlier than its agent was seen a server may have started (a
/// harness starts its servers before it says what it is) and be its.
const SERVER_BEFORE: u64 = 10_000;

/// The window's terminals, by number.
#[derive(Default)]
pub struct TerminalsUi {
    list: BTreeMap<u32, TerminalUi>,
    /// The last number given.
    numbered: Cell<u32>,
    /// The terminal Ctrl+backtick shows and hides (the one used last), if
    /// not the console.
    pub last: Option<u32>,
    /// The terminal whose tab closed while a program runs in it: whether
    /// to end it, asked.
    pub question: Option<u32>,
    /// Wakes the window when a terminal shows something new.
    wake: Option<Arc<dyn Fn() + Send + Sync>>,
    poll: Option<Task<()>>,
    /// The keys taken while a terminal has the focus.
    keys: Option<Subscription>,
    /// The coding agents seen in terminals, by harness: binbun's setup
    /// offered to each that has not connected.
    offers: BTreeMap<&'static str, Offer>,
    /// The harnesses not to offer it to (Don't Ask Again), read once.
    quiet: Option<BTreeSet<String>>,
    /// The binbun servers announced, as last read while watching.
    announced: Vec<Announced>,
    /// Reads them while an agent has started lately.
    watching: Option<Task<()>>,
}

/// binbun's setup offered to a harness seen in a terminal: where it is,
/// since when.
struct Offer {
    progress: Progress,
    since: Instant,
}

/// Where an offer is.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Progress {
    /// Offered, once due.
    Offered,
    /// Its setup command runs.
    Running,
    /// Set up: the harness connects once restarted.
    Done,
    /// The setup command failed, saying this.
    Failed(String),
}

impl TerminalsUi {
    /// A number for a terminal (a saved layout's, started when shown).
    pub fn fresh(&self) -> u32 {
        let id = self.numbered.get() + 1;
        self.numbered.set(id);
        id
    }
}

/// A terminal as the window has it.
struct TerminalUi {
    /// Started when first drawn (its size known).
    terminal: Option<Terminal>,
    /// Why it did not start.
    error: Option<String>,
    focus: FocusHandle,
    /// The grid's bounds as last drawn.
    bounds: Rc<Cell<Bounds<Pixels>>>,
    /// Hidden by Ctrl+backtick: running with no tab.
    hidden: bool,
    /// The wheel's lines not sent yet (a touchpad's fractions).
    wheel: f32,
    /// The left button went down to select, not to the program.
    selecting: bool,
    /// The buttons the program was told went down.
    held: Vec<Button>,
    /// The focus and colours the program was told of.
    focused: bool,
    colors: Option<Colors>,
    /// The coding agent its program says it is, since its start.
    agent: Option<Seen>,
}

/// A coding agent seen starting in a terminal.
struct Seen {
    harness: &'static Harness,
    /// The terminal's probes when it started ([`Frame::probes`]): one more,
    /// it started again.
    probes: u64,
    since: Instant,
    /// The same, in Unix milliseconds (a server's announcement's clock).
    wall: u64,
}

/// How a grid is drawn.
struct Look {
    font: Font,
    size: Pixels,
    /// A cell's width and height.
    cell: (f32, f32),
    selection: Hsla,
    scrollbar: Hsla,
    focused: bool,
}

/// `0xRRGGBB` as a colour.
fn rgb(c: u32) -> Hsla {
    hsla((c << 8) | 0xff)
}

/// Now, in Unix milliseconds (the clock a server's announcement keeps).
fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn mods(m: Modifiers) -> Mods {
    Mods {
        shift: m.shift,
        control: m.control,
        alt: m.alt,
        platform: m.platform,
    }
}

/// The grid that fits `bounds` in cells of `cell` pixels; none if not one
/// cell does.
fn grid_size(bounds: Bounds<Pixels>, (cw, ch): (f32, f32)) -> Option<Size> {
    let (w, h) = (f32::from(bounds.size.width), f32::from(bounds.size.height));
    if w < cw || h < ch {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "cells in sight; a cell's pixels"
    )]
    let (cols, rows, cell_width, cell_height) = (
        (w / cw).floor().min(f32::from(u16::MAX)) as u16,
        (h / ch).floor().min(f32::from(u16::MAX)) as u16,
        cw.round().max(1.0) as u32,
        ch.round().max(1.0) as u32,
    );
    Some(Size {
        cols,
        rows,
        cell_width,
        cell_height,
    })
}

impl Workspace {
    /// Window › New Terminal: a shell opened under the code, focused.
    pub fn new_terminal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.terminals.fresh();
        let from = self.layout.focused();
        let pane = self.open_below(from, TabKind::Terminal(id), false, cx);
        self.focus_pane(pane, window, cx);
        cx.notify();
    }

    /// What Ctrl+backtick shows and hides: the terminal used last while it
    /// runs, else the console.
    pub fn shell_kind(&self) -> TabKind {
        match self.terminals.last {
            Some(id) if self.terminals.list.contains_key(&id) => TabKind::Terminal(id),
            _ => TabKind::Console,
        }
    }

    /// Marks the terminal `kind` is (if it is one) hidden or not: hidden,
    /// it runs with no tab.
    pub fn hide_terminal(&mut self, kind: &TabKind, hidden: bool) {
        if let TabKind::Terminal(id) = kind
            && let Some(ui) = self.terminals.list.get_mut(id)
        {
            ui.hidden = hidden;
        }
    }

    /// Terminal `id` takes the focus (its keys taken from then on).
    pub fn focus_terminal(&mut self, id: u32, window: &mut Window, cx: &mut Context<Self>) {
        self.terminals.last = Some(id);
        self.ensure_terminal_keys(window, cx);
        let focus = self.terminal_ui(id, cx).focus.clone();
        window.focus(&focus, cx);
    }

    /// Terminal `id`'s title: the program's, else its number's.
    pub fn terminal_title(&self, id: u32) -> String {
        let title = self
            .terminals
            .list
            .get(&id)
            .and_then(|ui| ui.terminal.as_ref())
            .map(|t| t.frame().title.trim().to_owned())
            .unwrap_or_default();
        match (title.is_empty(), id) {
            (false, _) => title,
            (true, 1) => "Terminal".to_owned(),
            (true, _) => format!("Terminal {id}"),
        }
    }

    fn terminal_ui(&mut self, id: u32, cx: &mut Context<Self>) -> &mut TerminalUi {
        self.terminals.list.entry(id).or_insert_with(|| TerminalUi {
            terminal: None,
            error: None,
            focus: cx.focus_handle(),
            bounds: Rc::default(),
            hidden: false,
            wheel: 0.0,
            selecting: false,
            held: Vec::new(),
            focused: false,
            colors: None,
            agent: None,
        })
    }

    /// A cell's width and height.
    fn terminal_cell(&self) -> (f32, f32) {
        (
            self.char_width.unwrap_or(8.0),
            self.row(self.settings.c_line_height),
        )
    }

    /// What a terminal starts: the user's shell, in the binary's folder.
    fn terminal_launch(&self) -> Launch {
        Launch {
            cwd: self
                .session
                .as_ref()
                .and_then(|s| s.path().parent())
                .filter(|p| !p.as_os_str().is_empty())
                .map(Path::to_path_buf),
            ..Launch::default()
        }
    }

    /// What a program leaves unset shows in: the code's colours.
    fn terminal_colors(&self) -> Colors {
        Colors {
            foreground: self.theme.editor_foreground >> 8,
            background: solid(self.theme.editor) >> 8,
            cursor: self.theme.editor_foreground >> 8,
        }
    }

    /// What wakes the window when a terminal shows something new (made
    /// with the task waiting on it once).
    fn terminal_wake(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Arc<dyn Fn() + Send + Sync> {
        if let Some(wake) = &self.terminals.wake {
            return Arc::clone(wake);
        }
        let (tx, rx) = async_channel::unbounded::<()>();
        let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let _ = tx.try_send(());
        });
        self.terminals.poll = Some(cx.spawn_in(window, async move |this, cx| {
            while rx.recv().await.is_ok() {
                while rx.try_recv().is_ok() {}
                if this.update_in(cx, Workspace::poll_terminals).is_err() {
                    break;
                }
            }
        }));
        self.terminals.wake = Some(Arc::clone(&wake));
        wake
    }

    /// A terminal showed something new: drawn again; one whose shell ended
    /// without an error closed.
    fn poll_terminals(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let ended: Vec<u32> = self
            .terminals
            .list
            .iter()
            .filter(|(_, ui)| {
                ui.terminal
                    .as_ref()
                    .is_some_and(|t| t.frame().exited == Some(Exit::Code(0)))
            })
            .map(|(&id, _)| id)
            .collect();
        for id in ended {
            self.end_terminal(id, window, cx);
        }
        self.watch_agents(window, cx);
        cx.notify();
    }

    /// Ends terminal `id`'s program; its tabs closed.
    fn end_terminal(&mut self, id: u32, window: &mut Window, cx: &mut Context<Self>) {
        self.terminals.list.remove(&id);
        if self.terminals.last == Some(id) {
            self.terminals.last = None;
        }
        let kind = TabKind::Terminal(id);
        self.take_parked(&kind);
        if let Some((pane, index, _)) = self.place_of(&kind) {
            self.layout.close_tab(pane, index);
            self.after_layout(window, cx);
        }
    }

    /// Ends the terminals whose tabs closed (but those hidden); one where a
    /// program the shell started runs is asked about first.
    pub fn forget_terminals(&mut self) {
        let gone: Vec<u32> = self
            .terminals
            .list
            .iter()
            .filter(|&(&id, ui)| !ui.hidden && !self.has_tab(&TabKind::Terminal(id)))
            .map(|(&id, _)| id)
            .collect();
        for id in gone {
            if self.terminals.question == Some(id) {
                continue;
            }
            let busy = self
                .terminals
                .list
                .get(&id)
                .and_then(|ui| ui.terminal.as_ref())
                .is_some_and(|t| t.frame().exited.is_none() && t.busy());
            if !busy {
                self.terminals.list.remove(&id);
            } else if self.terminals.question.is_none() {
                self.terminals.question = Some(id);
            }
        }
        if self
            .terminals
            .last
            .is_some_and(|id| !self.terminals.list.contains_key(&id))
        {
            self.terminals.last = None;
        }
    }

    /// The keys of the terminal with the focus taken before the window's
    /// (once for the window).
    fn ensure_terminal_keys(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.terminals.keys.is_some() {
            return;
        }
        let this = cx.weak_entity();
        let handle = window.window_handle();
        self.terminals.keys = Some(cx.intercept_keystrokes(move |event, window, cx| {
            if window.window_handle() != handle {
                return;
            }
            let taken = this
                .update(cx, |this, cx| {
                    this.terminal_key(&event.keystroke, window, cx)
                })
                .unwrap_or(false);
            if taken {
                cx.stop_propagation();
            }
        }));
    }

    /// `keystroke` with a terminal focused: whether it took it (binbun's
    /// chords left to the window).
    fn terminal_key(
        &mut self,
        keystroke: &Keystroke,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some((&id, ui)) = self
            .terminals
            .list
            .iter()
            .find(|(_, ui)| ui.focus.is_focused(window))
        else {
            return false;
        };
        let Some(terminal) = &ui.terminal else {
            return false;
        };
        let m = keystroke.modifiers;
        let key = keystroke.key.as_str();
        let chord = if cfg!(target_os = "macos") {
            m.platform && !m.control && !m.alt
        } else {
            m.control && m.shift && !m.alt && !m.platform
        };
        if chord && key == "c" {
            if let Some(text) = terminal.copy() {
                cx.write_to_clipboard(ClipboardItem::new_string(text));
            }
            return true;
        }
        let shift_insert = !cfg!(target_os = "macos") && m.shift && key == "insert";
        if (chord && key == "v") || shift_insert {
            if let Some(text) = cx.read_from_clipboard().and_then(|c| c.text()) {
                terminal.input(Input::Paste(text));
            }
            return true;
        }
        if m.platform || (m.control && m.shift) || (m.control && key == "`") {
            return false;
        }
        if terminal.frame().exited.is_some() {
            self.end_terminal(id, window, cx);
            return true;
        }
        terminal.input(Input::Key {
            key: key.to_owned(),
            text: keystroke.key_char.clone(),
            mods: mods(m),
            repeat: false,
        });
        true
    }

    /// Terminal `id` in pane `pane`: started at the size it is drawn at,
    /// resized with it, told its focus and colours.
    pub fn render_terminal(
        &mut self,
        pane: PaneId,
        id: u32,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let cw = self.char_width(window);
        let cell = (cw, self.row(self.settings.c_line_height));
        let colors = self.terminal_colors();
        let started = self
            .terminals
            .list
            .get(&id)
            .is_some_and(|ui| ui.terminal.is_some() || ui.error.is_some());
        let launch = (!started).then(|| self.terminal_launch());
        let wake = (!started).then(|| self.terminal_wake(window, cx));
        let ui = self.terminal_ui(id, cx);
        let size = grid_size(ui.bounds.get(), cell);
        match (&ui.terminal, size, launch.zip(wake)) {
            (None, Some(size), Some((launch, wake))) => {
                match Terminal::start(&launch, size, colors, wake) {
                    Ok(t) => ui.terminal = Some(t),
                    Err(e) => ui.error = Some(format!("The shell did not start: {e}")),
                }
                ui.colors = Some(colors);
            }
            (Some(t), Some(size), _) if t.size() != size => t.resize(size),
            _ => {}
        }
        let focused = ui.focus.is_focused(window);
        if let Some(t) = &ui.terminal {
            if ui.focused != focused {
                t.input(Input::Focus(focused));
            }
            if ui.colors != Some(colors) {
                t.input(Input::Colors(colors));
            }
        }
        ui.focused = focused;
        ui.colors = Some(colors);
        self.terminal_body(pane, id, focused, cx)
    }

    /// The terminal's grid drawn, its mouse and wheel taken; the program's
    /// end or failure to start said at its foot.
    fn terminal_body(
        &mut self,
        pane: PaneId,
        id: u32,
        focused: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let look = Look {
            font: self.code_font(),
            size: px(self.code_size()),
            cell: self.terminal_cell(),
            selection: hsla(theme.selection),
            scrollbar: hsla(theme.scrollbar_thumb),
            focused,
        };
        let Some(ui) = self.terminals.list.get(&id) else {
            return div().into_any_element();
        };
        let frame = ui.terminal.as_ref().map(Terminal::frame);
        let background = frame
            .as_ref()
            .map_or_else(|| hsla(solid(theme.editor)), |f| rgb(f.background));
        let note = match (&ui.error, frame.as_ref().and_then(|f| f.exited)) {
            (Some(error), _) => Some(error.clone()),
            (None, Some(Exit::Code(code))) => Some(format!(
                "The shell ended with exit code {code}: a key closes the tab."
            )),
            (None, Some(Exit::Signal)) => {
                Some("The shell was killed: a key closes the tab.".to_owned())
            }
            (None, None) => None,
        };
        let weak = cx.weak_entity();
        let grid = canvas(
            |_, _, _| {},
            move |bounds, (), window, cx| {
                if let Some(frame) = &frame {
                    paint_grid(frame, &look, bounds, window, cx);
                }
                // A drag selects, and a button comes up, beyond the grid.
                let moved = weak.clone();
                window.on_mouse_event(move |e: &MouseMoveEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble {
                        let _ = moved.update(cx, |this, _| this.terminal_moved(id, e, bounds));
                    }
                });
                window.on_mouse_event(move |e: &MouseUpEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble {
                        let _ = weak.update(cx, |this, _| this.terminal_released(id, e));
                    }
                });
            },
        );
        let pressed = || {
            cx.listener(move |this: &mut Self, e: &MouseDownEvent, window, cx| {
                this.terminal_pressed(pane, id, e, window, cx);
            })
        };
        div()
            .id(("terminal", id))
            .track_focus(&ui.focus)
            .size_full()
            .relative()
            .overflow_hidden()
            .bg(background)
            .p(self.z(4.0))
            .on_mouse_down(MouseButton::Left, pressed())
            .on_mouse_down(MouseButton::Middle, pressed())
            .on_mouse_down(MouseButton::Right, pressed())
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                this.terminal_wheel(id, e);
                cx.stop_propagation();
            }))
            .child(
                div()
                    .size_full()
                    .relative()
                    .child(measured(Rc::clone(&ui.bounds)).absolute().size_full())
                    .child(grid.absolute().size_full()),
            )
            .children(note.map(|note| {
                div()
                    .absolute()
                    .left_0()
                    .right_0()
                    .bottom_0()
                    .px(self.z(8.0))
                    .py(self.z(4.0))
                    .bg(hsla(solid(theme.panel)))
                    .border_t_1()
                    .border_color(hsla(theme.border_variant))
                    .text_color(hsla(theme.text_muted))
                    .child(note)
            }))
            .into_any_element()
    }

    /// `at` in the grid of terminal `id`, in its pixels (whole ones a
    /// cell).
    fn grid_point(&self, id: u32, at: Point<Pixels>) -> Option<(f32, f32)> {
        let ui = self.terminals.list.get(&id)?;
        let size = ui.terminal.as_ref()?.size();
        let origin = ui.bounds.get().origin;
        let (cw, ch) = self.terminal_cell();
        #[expect(clippy::cast_precision_loss, reason = "a cell's pixels")]
        let (width, height) = (size.cell_width as f32, size.cell_height as f32);
        Some((
            f32::from(at.x - origin.x) / cw * width,
            f32::from(at.y - origin.y) / ch * height,
        ))
    }

    /// A button down on terminal `id`: to the program where it takes the
    /// pointer (Shift not held), else the left one selects, the right one
    /// opens the menu.
    fn terminal_pressed(
        &mut self,
        pane: PaneId,
        id: u32,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.focus_pane(pane, window, cx);
        cx.stop_propagation();
        let Some((x, y)) = self.grid_point(id, e.position) else {
            return;
        };
        let button = match e.button {
            MouseButton::Left => Button::Left,
            MouseButton::Middle => Button::Middle,
            MouseButton::Right => Button::Right,
            MouseButton::Navigate(_) => return,
        };
        let Some(ui) = self.terminals.list.get_mut(&id) else {
            return;
        };
        let Some(terminal) = &ui.terminal else {
            return;
        };
        if terminal.frame().pointer && !e.modifiers.shift {
            ui.held.push(button);
            terminal.input(Input::Pointer {
                what: Pointer::Press(button),
                x,
                y,
                mods: mods(e.modifiers),
            });
        } else if button == Button::Left {
            ui.selecting = true;
            terminal.input(Input::SelectFrom {
                x,
                y,
                clicks: e.click_count,
            });
        } else if button == Button::Right {
            let copy = terminal.copy().is_some();
            self.terminal_menu(id, copy, e.position, window, cx);
        }
    }

    /// The pointer moved, anywhere: a drag from terminal `id` selects; over
    /// its grid `bounds`, a program taking the pointer is told.
    fn terminal_moved(&self, id: u32, e: &MouseMoveEvent, bounds: Bounds<Pixels>) {
        let Some(ui) = self.terminals.list.get(&id) else {
            return;
        };
        let (Some(terminal), Some((x, y))) = (&ui.terminal, self.grid_point(id, e.position)) else {
            return;
        };
        if ui.selecting && e.pressed_button == Some(MouseButton::Left) {
            terminal.input(Input::SelectTo { x, y });
        } else if (!ui.held.is_empty() || bounds.contains(&e.position)) && terminal.frame().pointer
        {
            terminal.input(Input::Pointer {
                what: Pointer::Move,
                x,
                y,
                mods: mods(e.modifiers),
            });
        }
    }

    /// A button came up, anywhere: the selection from terminal `id` ends,
    /// or the program that had it go down is told.
    fn terminal_released(&mut self, id: u32, e: &MouseUpEvent) {
        let point = self.grid_point(id, e.position);
        let Some(ui) = self.terminals.list.get_mut(&id) else {
            return;
        };
        let button = match e.button {
            MouseButton::Left => {
                ui.selecting = false;
                Button::Left
            }
            MouseButton::Middle => Button::Middle,
            MouseButton::Right => Button::Right,
            MouseButton::Navigate(_) => return,
        };
        let Some(at) = ui.held.iter().position(|&b| b == button) else {
            return;
        };
        ui.held.remove(at);
        if let (Some(terminal), Some((x, y))) = (&ui.terminal, point) {
            terminal.input(Input::Pointer {
                what: Pointer::Release(button),
                x,
                y,
                mods: mods(e.modifiers),
            });
        }
    }

    /// The wheel over terminal `id`: three lines a notch.
    fn terminal_wheel(&mut self, id: u32, e: &ScrollEvent) {
        let (_, ch) = self.terminal_cell();
        let back = match wheel(e) {
            Wheel::Lines(y) => y * 3.0,
            Wheel::Pixels(y) => y / ch,
        };
        let point = self.grid_point(id, e.position);
        let Some(ui) = self.terminals.list.get_mut(&id) else {
            return;
        };
        let (Some(terminal), Some((x, y))) = (&ui.terminal, point) else {
            return;
        };
        ui.wheel -= back;
        let lines = ui.wheel.trunc();
        ui.wheel -= lines;
        #[expect(clippy::cast_possible_truncation, reason = "a few lines")]
        let lines = lines as isize;
        if lines != 0 {
            terminal.input(Input::Wheel {
                lines,
                x,
                y,
                mods: mods(e.modifiers),
            });
        }
    }

    /// Terminal `id`'s menu: Copy (if something is selected) and Paste.
    fn terminal_menu(
        &mut self,
        id: u32,
        copy: bool,
        at: Point<Pixels>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let chord = |key: &str| {
            if cfg!(target_os = "macos") {
                format!("⌘{key}")
            } else {
                format!("Ctrl+Shift+{key}")
            }
        };
        let items = vec![
            OwnItem {
                enabled: copy,
                key: Some(chord("C")),
                ..OwnItem::new("Copy", move |this, _, cx| {
                    let text = this
                        .terminals
                        .list
                        .get(&id)
                        .and_then(|ui| ui.terminal.as_ref()?.copy());
                    if let Some(text) = text {
                        cx.write_to_clipboard(ClipboardItem::new_string(text));
                    }
                })
            },
            OwnItem {
                key: Some(chord("V")),
                ..OwnItem::new("Paste", move |this, window, cx| {
                    let text = cx.read_from_clipboard().and_then(|c| c.text());
                    if let (Some(text), Some(terminal)) = (
                        text,
                        this.terminals
                            .list
                            .get(&id)
                            .and_then(|ui| ui.terminal.as_ref()),
                    ) {
                        terminal.input(Input::Paste(text));
                    }
                    this.focus_terminal(id, window, cx);
                })
            },
        ];
        self.toggle_own_menu(format!("terminal-{id}"), at, items, window, cx);
    }

    /// The status bar's console button's menu: the console, each terminal,
    /// a new one.
    pub fn shell_menu(&mut self, at: Point<Pixels>, window: &mut Window, cx: &mut Context<Self>) {
        let shown = |kind: &TabKind| self.place_of(kind).is_some_and(|(_, _, shown)| shown);
        let mut items = vec![OwnItem {
            checked: shown(&TabKind::Console),
            ..OwnItem::new("Console", |this, window, cx| {
                this.show_shell(TabKind::Console, false, window, cx);
            })
        }];
        for &id in self.terminals.list.keys() {
            items.push(OwnItem {
                checked: shown(&TabKind::Terminal(id)),
                ..OwnItem::new(self.terminal_title(id), move |this, window, cx| {
                    this.show_shell(TabKind::Terminal(id), false, window, cx);
                })
            });
        }
        items.push(OwnItem {
            key: commands::key_label(&self.keymap, Command::NewTerminal),
            ..OwnItem::new("New Terminal", Workspace::new_terminal)
        });
        self.toggle_own_menu("console-toggle", at, items, window, cx);
    }

    /// The question asked when a terminal's tab closed while a program
    /// runs in it: end it, or keep it (its tab back).
    pub fn render_terminal_question(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let id = self.terminals.question?;
        let theme = self.theme;
        let button = |name: &'static str, label: &'static str, default: bool| {
            div()
                .id(name)
                .flex()
                .items_center()
                .h(self.z(ICON_BUTTON))
                .px(self.z(10.0))
                .rounded(self.z(4.0))
                .text_color(hsla(theme.text))
                .when(default, |d| d.bg(hsla(theme.element_selected)))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .on_mouse_down(MouseButton::Left, |_, window, cx| {
                    window.prevent_default();
                    cx.stop_propagation();
                })
                .child(label)
        };
        Some(
            div()
                .id("end-terminal")
                .track_focus(&self.overlay_focus)
                .p(self.z(12.0))
                .flex()
                .flex_col()
                .gap(self.z(4.0))
                .child(format!(
                    "A program is running in {}. End it?",
                    self.terminal_title(id)
                ))
                .child(
                    div()
                        .text_color(hsla(theme.text_muted))
                        .child("Kept, it comes back in a tab."),
                )
                .child(
                    div()
                        .pt(self.z(8.0))
                        .flex()
                        .justify_end()
                        .gap(self.z(6.0))
                        .child(
                            button("terminal-keep", "Keep It", false).on_click(cx.listener(
                                |this, _: &ClickEvent, window, cx| {
                                    this.close_overlays(window, cx);
                                    cx.notify();
                                },
                            )),
                        )
                        .child(button("terminal-end", "End It", true).on_click(cx.listener(
                            move |this, _: &ClickEvent, window, cx| {
                                this.terminals.question = None;
                                this.end_terminal(id, window, cx);
                                this.forget_terminals();
                                this.close_overlays(window, cx);
                                cx.notify();
                            },
                        ))),
                )
                .into_any_element(),
        )
    }
}

impl Workspace {
    /// Whether an agent of `harness` is connected to this window.
    fn harness_connected(&self, harness: &Harness) -> bool {
        self.served.as_ref().is_some_and(|(_, ui, _)| {
            ui.agents()
                .iter()
                .any(|agent| agents::harness(&agent.name).is_some_and(|h| h.name == harness.name))
        })
    }

    /// The offers whose harness has an agent connected now, done with: one
    /// that leaves later is not offered binbun again (a later start that
    /// does not connect makes a new offer). One setting up is kept.
    pub fn retire_agent_offers(&mut self) {
        let connected: Vec<&'static str> = self
            .terminals
            .offers
            .iter()
            .filter(|(_, offer)| offer.progress != Progress::Running)
            .filter_map(|(&name, _)| {
                agents::harness(name)
                    .filter(|harness| self.harness_connected(harness))
                    .map(|_| name)
            })
            .collect();
        for name in connected {
            self.terminals.offers.remove(name);
        }
    }

    /// The coding agents the terminals' programs say they are, each
    /// noted when it starts (its harness known, with a setup; or started
    /// again, the terminal probed again): an offer made for its harness if
    /// there is none, the window drawn again when it is due.
    fn watch_agents(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let now = Instant::now();
        let wall = unix_millis();
        let mut started = Vec::new();
        for ui in self.terminals.list.values_mut() {
            let Some(frame) = ui.terminal.as_ref().map(Terminal::frame) else {
                continue;
            };
            let harness = frame
                .status
                .as_ref()
                .and_then(|status| agents::harness(&status.app))
                .filter(|harness| harness.setup.is_some());
            let same = match (&ui.agent, harness) {
                (Some(seen), Some(harness)) => {
                    seen.harness.name == harness.name && seen.probes == frame.probes
                }
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            };
            if same {
                continue;
            }
            ui.agent = harness.map(|harness| Seen {
                harness,
                probes: frame.probes,
                since: now,
                wall,
            });
            started.extend(harness.map(|harness| harness.name));
        }
        if started.is_empty() {
            return;
        }
        // Its binbun mcp runs the Python the settings name.
        self.check_python(cx);
        if self.terminals.quiet.is_none() {
            self.terminals.quiet = Some(
                agents::quiet_path()
                    .map(|path| agents::read_quiet(&path))
                    .unwrap_or_default(),
            );
        }
        for name in started {
            self.terminals.offers.entry(name).or_insert(Offer {
                progress: Progress::Offered,
                since: now,
            });
        }
        cx.spawn_in(window, async move |this, cx| {
            cx.background_executor().timer(SERVER_AFTER).await;
            let _ = this.update(cx, |_, cx| cx.notify());
        })
        .detach();
        self.terminals.watching = Some(cx.spawn_in(window, async move |this, cx| {
            while now.elapsed() < WATCH {
                let read = cx
                    .background_executor()
                    .spawn(async {
                        Place::Servers
                            .path()
                            .map(|dir| agents::announced(&dir))
                            .unwrap_or_default()
                    })
                    .await;
                let changed = this.update(cx, |this, cx| {
                    if this.terminals.announced != read {
                        this.terminals.announced = read;
                        cx.notify();
                    }
                });
                if changed.is_err() {
                    break;
                }
                cx.background_executor().timer(WATCH_EVERY).await;
            }
        }));
    }

    /// The banners offering binbun's setup to the coding agents in
    /// terminals that have not connected, or saying how their setup went
    /// (the stack shows the first not put away).
    pub fn agent_banners(&self) -> Vec<Banner> {
        self.terminals
            .offers
            .iter()
            .filter_map(|(&name, offer)| self.agent_banner(name, offer))
            .collect()
    }

    /// The latest start of the harness `name`'s agent in a terminal still
    /// running it: the terminal, when, and the binbun server it started
    /// (announced from shortly before on), if one.
    fn agent_start(&self, name: &str) -> Option<(u32, Instant, Option<&Announced>)> {
        let (id, seen) = self
            .terminals
            .list
            .iter()
            .filter_map(|(&id, ui)| {
                Some((
                    id,
                    ui.agent.as_ref().filter(|seen| seen.harness.name == name)?,
                ))
            })
            .max_by_key(|(_, seen)| seen.since)?;
        let server = self
            .terminals
            .announced
            .iter()
            .filter(|server| {
                server.started + SERVER_BEFORE >= seen.wall
                    && agents::harness(&server.agent).is_some_and(|h| h.name == name)
            })
            .max_by_key(|server| server.started);
        Some((id, seen.since, server))
    }

    /// Offer `offer`'s banner for the harness `name`, if it has one now:
    /// none once an agent of it is connected, or while the server its
    /// agent started starts. Its server failed, why; none [`SERVER_AFTER`]
    /// after it started: offered, or (set up) a restart said, or (set up
    /// and restarted) that it still does not run binbun.
    fn agent_banner(&self, name: &'static str, offer: &Offer) -> Option<Banner> {
        let harness = agents::harness(name)?;
        if offer.progress != Progress::Running && self.harness_connected(harness) {
            return None;
        }
        let start = self.agent_start(name);
        let (terminal, since) = (start.map(|s| s.0), start.map(|s| s.1));
        let server = start.and_then(|s| s.2).map(|server| &server.start);
        let due = since.is_some_and(|since| since.elapsed() >= SERVER_AFTER);
        let banner = |tone, text: String, buttons, closable| Banner {
            kind: Kind::Agent,
            priority: Priority::Question,
            about: format!("{name}\n{terminal:?}\n{text}"),
            text,
            tone,
            buttons,
            closable,
        };
        let button = |label: &str, action| BannerButton {
            label: label.to_owned(),
            action,
        };
        let connect = || {
            vec![button(
                "Connect an Agent…",
                Action::Command(Command::ConnectAgent),
            )]
        };
        match (&offer.progress, server) {
            (Progress::Running, _) => Some(banner(
                Tone::Busy,
                format!("Adding binbun to {name}…"),
                Vec::new(),
                false,
            )),
            // Its Python set up since: it takes it at its next call.
            (_, Some(Start::Failed(_))) if self.python_set_up() => None,
            (_, Some(Start::Failed(error))) => Some(banner(
                Tone::Error,
                format!("{name}'s binbun server could not start: {error}"),
                if self.python_broken() {
                    vec![button("Set Up Python", Action::SetUpPython)]
                } else {
                    connect()
                },
                true,
            )),
            (_, Some(Start::Starting | Start::Ready)) => None,
            (Progress::Offered, None) => {
                let quiet = self
                    .terminals
                    .quiet
                    .as_ref()
                    .is_some_and(|q| q.contains(name));
                if quiet || !due {
                    return None;
                }
                let set_up = match harness.setup {
                    Some(Setup::Shell(_)) => "Set Up",
                    Some(Setup::Json { .. }) | None => "Set Up…",
                };
                Some(banner(
                    Tone::Info,
                    format!("{name} is running in a terminal but isn't connected to binbun."),
                    vec![
                        button(set_up, Action::SetUpAgent(name.to_owned())),
                        button("Don't Ask Again", Action::QuietAgent(name.to_owned())),
                    ],
                    true,
                ))
            }
            (Progress::Done, None) if due && since.is_some_and(|since| since > offer.since) => {
                Some(banner(
                    Tone::Error,
                    format!(
                        "{name} restarted without starting binbun's server: its setup isn't \
                         where this {name} reads it."
                    ),
                    connect(),
                    true,
                ))
            }
            (Progress::Done, None) => Some(banner(
                Tone::Info,
                format!("binbun is added to {name}: restart it to connect."),
                Vec::new(),
                true,
            )),
            (Progress::Failed(error), None) => Some(banner(
                Tone::Error,
                format!("Adding binbun to {name} failed: {error}"),
                connect(),
                true,
            )),
        }
    }

    /// Terminal `id`'s tab icon and its colour: what its program says it
    /// is doing (OSC 7501: a program that knows the terminal takes the
    /// reports leaves its title's own mark out), else a terminal's.
    pub fn terminal_icon(&self, id: u32) -> (IconName, u32) {
        let theme = self.theme;
        let state = self
            .terminals
            .list
            .get(&id)
            .and_then(|ui| ui.terminal.as_ref())
            .and_then(|t| t.frame().status.as_ref().map(|status| status.state));
        match state {
            Some(State::Working) => (IconName::LoaderCircle, theme.accent),
            Some(State::Blocked) => (IconName::CircleAlert, theme.accent),
            Some(State::Done) => (IconName::CircleCheck, theme.success),
            Some(State::Error) => (IconName::CircleX, theme.error),
            Some(State::Idle) | None => (IconName::Terminal, theme.text_muted),
        }
    }

    /// The banner's Set Up: the harness's own command run for this
    /// binbun, off the UI thread; Connect an Agent where a config file
    /// takes it.
    pub fn set_up_agent(&mut self, name: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(harness) = agents::harness(name) else {
            return;
        };
        let row = match harness.setup {
            Some(Setup::Shell(_)) => setup_rows(&agents::this_binbun())
                .into_iter()
                .find(|row| row.name == harness.name),
            Some(Setup::Json { .. }) | None => None,
        };
        let (Some(row), Some(offer)) = (row, self.terminals.offers.get_mut(harness.name)) else {
            self.run(Command::ConnectAgent, window, cx);
            return;
        };
        offer.progress = Progress::Running;
        let ran = cx
            .background_executor()
            .spawn(async move { agents::run_setup(&row.text) });
        let name = harness.name;
        cx.spawn(async move |this, cx| {
            let result = ran.await;
            let _ = this.update(cx, |this, cx| {
                if let Some(offer) = this.terminals.offers.get_mut(name) {
                    offer.progress = match result {
                        Ok(()) => Progress::Done,
                        Err(error) => Progress::Failed(error),
                    };
                    // An agent starting from now has the setup.
                    offer.since = Instant::now();
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// The banner's Don't Ask Again: the harness named never offered
    /// binbun's setup again (kept with the other harnesses so named).
    pub fn quiet_agent(&mut self, name: &str) {
        let quiet = self.terminals.quiet.get_or_insert_with(BTreeSet::new);
        quiet.insert(name.to_owned());
        if let Some(path) = agents::quiet_path()
            && let Err(error) = agents::write_quiet(&path, quiet)
        {
            self.error = Some(error);
        }
    }
}

/// `frame` painted in `bounds`: each run's background, selection and
/// text, the cursor, where the grid is in the scrollback.
fn paint_grid(
    frame: &Frame,
    look: &Look,
    bounds: Bounds<Pixels>,
    window: &mut Window,
    cx: &mut App,
) {
    let (cw, ch) = look.cell;
    for (y, runs) in frame.rows.iter().enumerate() {
        #[expect(clippy::cast_precision_loss, reason = "a row in sight")]
        let top = bounds.origin.y + px(y as f32 * ch);
        for run in runs {
            let left = bounds.origin.x + px(f32::from(run.column) * cw);
            let cell = Bounds::new(
                point(left, top),
                size(px(f32::from(run.columns) * cw), px(ch)),
            );
            if let Some(bg) = run.bg {
                window.paint_quad(fill(cell, rgb(bg)));
            }
            if run.selected {
                window.paint_quad(fill(cell, look.selection));
            }
            if run.text.trim().is_empty() && !run.underline && !run.strikethrough {
                continue;
            }
            let color = if run.faint {
                rgb(run.fg).opacity(0.6)
            } else {
                rgb(run.fg)
            };
            paint_text(&run.text, run, color, point(left, top), look, window, cx);
        }
    }
    paint_cursor(frame, look, bounds, window, cx);
    paint_scroll(frame, look, bounds, window);
}

/// `text` in `run`'s style and `color` at `origin`, a glyph a column (a
/// character the font lacks takes another's advance, which would push what
/// follows it off its columns; a wide character is a run of its own).
fn paint_text(
    text: &str,
    run: &Run,
    color: Hsla,
    origin: Point<Pixels>,
    look: &Look,
    window: &mut Window,
    cx: &mut App,
) {
    let font = Font {
        weight: if run.bold {
            FontWeight::BOLD
        } else {
            look.font.weight
        },
        style: if run.italic {
            FontStyle::Italic
        } else {
            look.font.style
        },
        ..look.font.clone()
    };
    let style = TextRun {
        len: text.len(),
        font,
        color,
        background_color: None,
        underline: run.underline.then_some(UnderlineStyle {
            thickness: px(1.0),
            color: Some(color),
            wavy: false,
        }),
        strikethrough: run.strikethrough.then_some(StrikethroughStyle {
            thickness: px(1.0),
            color: Some(color),
        }),
    };
    let line = window.text_system().shape_line(
        text.to_owned().into(),
        look.size,
        &[style],
        Some(px(look.cell.0)),
    );
    let _ = line.paint(origin, px(look.cell.1), TextAlign::Left, None, window, cx);
}

/// The cursor in its shape (its cell's outline where the terminal has not
/// the focus); a block's character drawn over it in the background's
/// colour.
fn paint_cursor(
    frame: &Frame,
    look: &Look,
    bounds: Bounds<Pixels>,
    window: &mut Window,
    cx: &mut App,
) {
    let Some(cursor) = frame.cursor else {
        return;
    };
    let (cw, ch) = look.cell;
    let origin = point(
        bounds.origin.x + px(f32::from(cursor.column) * cw),
        bounds.origin.y + px(f32::from(cursor.row) * ch),
    );
    let color = rgb(cursor.color);
    let thin = px((cw / 8.0).round().max(1.0));
    let cell = Bounds::new(origin, size(px(cw), px(ch)));
    let shape = if look.focused {
        cursor.shape
    } else {
        Shape::Hollow
    };
    match shape {
        Shape::Block => {
            window.paint_quad(fill(cell, color));
            let under = frame
                .rows
                .get(usize::from(cursor.row))
                .and_then(|runs| {
                    runs.iter()
                        .find(|r| (r.column..r.column + r.columns).contains(&cursor.column))
                })
                .and_then(|run| {
                    let c = run
                        .text
                        .chars()
                        .nth(usize::from(cursor.column - run.column))?;
                    Some((c, run))
                });
            if let Some((c, run)) = under.filter(|(c, _)| !c.is_whitespace()) {
                let text = c.to_string();
                paint_text(&text, run, rgb(frame.background), origin, look, window, cx);
            }
        }
        Shape::Bar => window.paint_quad(fill(Bounds::new(origin, size(thin, px(ch))), color)),
        Shape::Underline => window.paint_quad(fill(
            Bounds::new(
                point(origin.x, origin.y + px(ch) - thin),
                size(px(cw), thin),
            ),
            color,
        )),
        Shape::Hollow => window.paint_quad(outline(cell, color, BorderStyle::Solid)),
    }
}

/// Where the grid is in the scrollback, at the right edge, while it is
/// scrolled back.
fn paint_scroll(frame: &Frame, look: &Look, bounds: Bounds<Pixels>, window: &mut Window) {
    let s = frame.scroll;
    if s.total <= s.len || s.offset + s.len >= s.total {
        return;
    }
    let h = f32::from(bounds.size.height);
    #[expect(clippy::cast_precision_loss, reason = "a proportion")]
    let (top, len) = (
        s.offset as f32 / s.total as f32 * h,
        (s.len as f32 / s.total as f32 * h).max(16.0),
    );
    window.paint_quad(fill(
        Bounds::new(
            point(bounds.right() - px(4.0), bounds.origin.y + px(top)),
            size(px(3.0), px(len)),
        ),
        look.scrollbar,
    ));
}
