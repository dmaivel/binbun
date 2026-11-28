//! A terminal: a program on a pseudo-terminal (the user's shell, unless
//! another is given), its output run through libghostty-vt, Ghostty's
//! terminal emulation ([`ghostty_vt`]), on a thread of its own (its handles
//! are not `Send`), each change published as a [`Frame`] for the GUI to
//! paint; keys, text, pastes, the pointer, the selection and the size go
//! the other way as [`Input`]. The program sees `TERM=xterm-ghostty`
//! (Ghostty's terminfo, written to a cache directory once) and its answers
//! to what it asks the terminal (its size, its attributes, colours) come
//! from libghostty-vt.
//!
//! The names of keys and their codes, and which modes change what a key
//! or the wheel sends, follow gpui-cn's terminal (Apache-2.0).

use std::io::{Read as _, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use ghostty_vt::key;
use ghostty_vt::mouse;
use ghostty_vt::render::{CellIterator, CursorVisualStyle, RenderState, RowIteration, RowIterator};
use ghostty_vt::screen::{CellWide, Screen};
use ghostty_vt::selection::{FormatOptions, SelectLineOptions, SelectWordOptions, Selection};
use ghostty_vt::style::{RgbColor, Underline};
use ghostty_vt::terminal::{
    Event, Mode, Options, Point, PointCoordinate, ScrollViewport, Terminal as Vt,
};
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};

/// The most scrollback a terminal keeps, in bytes (Ghostty's default).
const SCROLLBACK: usize = 10_000_000;
/// How long a program may hold the screen (synchronized output) before
/// it is shown anyway.
const HOLD: Duration = Duration::from_secs(1);
/// The most output read before a frame is published, so a flood of it
/// still shows as it goes.
const BATCH: usize = 1 << 20;

/// What a terminal runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Launch {
    /// The program and its arguments; empty: the user's shell.
    pub command: Vec<String>,
    /// Where it starts.
    pub cwd: Option<PathBuf>,
    /// What it has in its environment besides the GUI's own and the
    /// terminal's (`TERM`, `COLORTERM`, `TERM_PROGRAM`).
    pub env: Vec<(String, String)>,
}

/// A terminal's size: its grid, and a cell's size in pixels (which a
/// program may ask, to size images).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    /// Its columns.
    pub cols: u16,
    /// Its rows.
    pub rows: u16,
    /// A cell's width in pixels.
    pub cell_width: u32,
    /// A cell's height in pixels.
    pub cell_height: u32,
}

impl Size {
    /// The pseudo-terminal's size.
    fn pty(self) -> PtySize {
        PtySize {
            rows: self.rows,
            cols: self.cols,
            pixel_width: u16::try_from(u32::from(self.cols) * self.cell_width).unwrap_or(u16::MAX),
            pixel_height: u16::try_from(u32::from(self.rows) * self.cell_height)
                .unwrap_or(u16::MAX),
        }
    }

    /// The cell at `(x, y)` pixels from the grid's top left, in it.
    fn cell(self, x: f32, y: f32) -> (u16, u16) {
        let at = |pixels: f32, cell: u32, count: u16| {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "a cell index, clamped"
            )]
            let index =
                (pixels.max(0.0) / f32::from(u16::try_from(cell.max(1)).unwrap_or(1))) as u32;
            u16::try_from(index)
                .unwrap_or(u16::MAX)
                .min(count.saturating_sub(1))
        };
        (
            at(x, self.cell_width, self.cols),
            at(y, self.cell_height, self.rows),
        )
    }
}

/// The colours a terminal shows what the program leaves unset with
/// (`0xRRGGBB`): the GUI's theme's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Colors {
    /// Text.
    pub foreground: u32,
    /// The background.
    pub background: u32,
    /// The cursor.
    pub cursor: u32,
}

/// Modifier keys held.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the modifier keys, each held or not"
)]
pub struct Mods {
    /// Shift.
    pub shift: bool,
    /// Control.
    pub control: bool,
    /// Alt (Option).
    pub alt: bool,
    /// The platform key (Super, Windows, Command).
    pub platform: bool,
}

impl Mods {
    fn ghostty(self) -> key::Mods {
        let mut mods = key::Mods::empty();
        mods.set(key::Mods::SHIFT, self.shift);
        mods.set(key::Mods::CTRL, self.control);
        mods.set(key::Mods::ALT, self.alt);
        mods.set(key::Mods::SUPER, self.platform);
        mods
    }
}

/// A mouse button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Button {
    /// The left one.
    Left,
    /// The middle one.
    Middle,
    /// The right one.
    Right,
}

/// What the pointer did, for a program that asks for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pointer {
    /// A button went down.
    Press(Button),
    /// A button came up.
    Release(Button),
    /// It moved (a button held or not).
    Move,
}

/// What the GUI sends a terminal.
#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    /// A key: its name as the GUI has it (`a`, `enter`, `up`, `f5`), the
    /// text it types, the modifiers held, whether it repeats.
    Key {
        /// The key's name.
        key: String,
        /// The text it types.
        text: Option<String>,
        /// The modifiers held.
        mods: Mods,
        /// It is held down, repeating.
        repeat: bool,
    },
    /// Text typed (an input method's).
    Text(String),
    /// Text pasted: bracketed where the program asks.
    Paste(String),
    /// The wheel, in lines (up negative) at `(x, y)` pixels: to the
    /// program where it asks for the pointer, as arrow keys on the
    /// alternate screen where it asks for that, else the scrollback.
    Wheel {
        /// Lines, up negative.
        lines: isize,
        /// Where, in pixels from the grid's top left.
        x: f32,
        /// Where.
        y: f32,
        /// The modifiers held.
        mods: Mods,
    },
    /// The pointer, to a program that asks for it, at `(x, y)` pixels.
    Pointer {
        /// What it did.
        what: Pointer,
        /// Where, in pixels from the grid's top left.
        x: f32,
        /// Where.
        y: f32,
        /// The modifiers held.
        mods: Mods,
    },
    /// A selection starts at `(x, y)` pixels: a cell's (one click), a
    /// word's (two), a line's (three or more).
    SelectFrom {
        /// Where, in pixels from the grid's top left.
        x: f32,
        /// Where.
        y: f32,
        /// How many clicks.
        clicks: usize,
    },
    /// The selection reaches `(x, y)` pixels.
    SelectTo {
        /// Where, in pixels from the grid's top left.
        x: f32,
        /// Where.
        y: f32,
    },
    /// No selection.
    Unselect,
    /// The terminal has the focus, or not (said to a program that asks).
    Focus(bool),
    /// The colours for what the program leaves unset.
    Colors(Colors),
}

/// A run of cells in one style: each a column wide, or a lone wide
/// character's two (so its characters can be drawn a column apart).
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a style's attributes, each on or off"
)]
pub struct Run {
    /// Its text (a cell a wide character leaves blank has none).
    pub text: String,
    /// Its first column.
    pub column: u16,
    /// How many columns it covers.
    pub columns: u16,
    /// Its text's colour (`0xRRGGBB`, inverse resolved).
    pub fg: u32,
    /// Its background's, where the program set one (or inverse did).
    pub bg: Option<u32>,
    /// Bold.
    pub bold: bool,
    /// Italic.
    pub italic: bool,
    /// Faint.
    pub faint: bool,
    /// Underlined.
    pub underline: bool,
    /// Struck through.
    pub strikethrough: bool,
    /// Selected.
    pub selected: bool,
}

/// The cursor's shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A filled cell.
    Block,
    /// A bar before the cell.
    Bar,
    /// A line under the cell.
    Underline,
    /// The cell's outline.
    Hollow,
}

/// The cursor where it is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// Its column.
    pub column: u16,
    /// Its row in the grid.
    pub row: u16,
    /// Its shape.
    pub shape: Shape,
    /// Its colour (`0xRRGGBB`).
    pub color: u32,
}

/// Where the grid is in what the terminal holds, in rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scroll {
    /// All of them, the scrollback's and the screen's.
    pub total: u64,
    /// The grid's first.
    pub offset: u64,
    /// The grid's.
    pub len: u64,
}

/// What a terminal shows: its grid's rows, each a run of styles; its
/// cursor; its colours; where it is scrolled; what the program asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Its columns.
    pub cols: u16,
    /// Each row's runs, top to bottom.
    pub rows: Vec<Vec<Run>>,
    /// The cursor, where it shows.
    pub cursor: Option<Cursor>,
    /// Its background (`0xRRGGBB`).
    pub background: u32,
    /// Its text's colour.
    pub foreground: u32,
    /// Where the grid is in the scrollback.
    pub scroll: Scroll,
    /// The program takes the pointer (its clicks and moves are sent to it).
    pub pointer: bool,
    /// The program shows its alternate screen (a full-screen program).
    pub alternate: bool,
    /// The title the program set.
    pub title: String,
    /// How many times it rang the bell.
    pub bells: u64,
    /// How the program ended, once it has.
    pub exited: Option<Exit>,
    /// What the program running says it is and does (OSC 7501).
    pub status: Option<Status>,
}

/// What a program says of itself through the program status protocol
/// (OSC 7501): its name, its state. Claude Code, Pi and Crush send it,
/// once the terminal answers that it takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// Its name (`claude-code`); empty if it gave none.
    pub app: String,
    /// What it is doing.
    pub state: State,
}

/// A program's state, as it says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// At rest, at its own prompt.
    Idle,
    /// Running on its own.
    Working,
    /// Finished something the user has not looked at.
    Done,
    /// Waiting on the user (an approval, an answer, a login).
    Blocked,
    /// Failed and stopped.
    Error,
}

/// How a program ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// It exited with this code.
    Code(u32),
    /// A signal ended it.
    Signal,
}

impl Frame {
    /// A frame of nothing yet, in `colors`.
    fn empty(size: Size, colors: Colors) -> Self {
        Self {
            cols: size.cols,
            rows: Vec::new(),
            cursor: None,
            background: colors.background,
            foreground: colors.foreground,
            scroll: Scroll::default(),
            pointer: false,
            alternate: false,
            title: String::new(),
            bells: 0,
            exited: None,
            status: None,
        }
    }

    /// Its rows' text, each trimmed at its end (for tests and copying a
    /// screen).
    pub fn text(&self) -> Vec<String> {
        self.rows
            .iter()
            .map(|runs| {
                let mut line = String::new();
                for run in runs {
                    let at = usize::from(run.column);
                    while line.chars().count() < at {
                        line.push(' ');
                    }
                    line.push_str(&run.text);
                }
                line.trim_end().to_owned()
            })
            .collect()
    }
}

/// What the threads of a terminal send its engine.
enum Message {
    /// The program wrote.
    Output(Vec<u8>),
    /// The program ended.
    Exited(Exit),
    /// The GUI's.
    Input(Input),
    /// The new size.
    Resize(Size),
    /// The selection's text is wanted.
    Copy(Sender<Option<String>>),
}

/// A terminal: the program on its pseudo-terminal, the latest [`Frame`].
/// Dropping it ends the program.
pub struct Terminal {
    to_engine: Sender<Message>,
    frame: Arc<Mutex<Arc<Frame>>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    pid: Option<u32>,
    size: Mutex<Size>,
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Terminal")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

impl Terminal {
    /// Starts `launch` on a pseudo-terminal of `size`, in `colors`; `wake`
    /// is called (on another thread) each time a new frame is there.
    ///
    /// # Errors
    ///
    /// The pseudo-terminal cannot be made, or the program not started.
    pub fn start(
        launch: &Launch,
        size: Size,
        colors: Colors,
        wake: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Self, String> {
        let pair = native_pty_system()
            .openpty(size.pty())
            .map_err(|e| format!("cannot open a pseudo-terminal: {e}"))?;
        let mut command = match launch.command.split_first() {
            Some((program, args)) => {
                let mut command = CommandBuilder::new(program);
                command.args(args);
                command
            }
            None => CommandBuilder::new_default_prog(),
        };
        if let Some(cwd) = &launch.cwd {
            command.cwd(cwd);
        }
        match ghostty_vt::terminfo::dir() {
            Ok(dir) => {
                command.env("TERM", "xterm-ghostty");
                command.env("TERMINFO", dir);
            }
            Err(_) => command.env("TERM", "xterm-256color"),
        }
        command.env("COLORTERM", "truecolor");
        command.env("TERM_PROGRAM", "binbun");
        command.env("TERM_PROGRAM_VERSION", env!("CARGO_PKG_VERSION"));
        for (name, value) in &launch.env {
            command.env(name, value);
        }
        let mut child = pair
            .slave
            .spawn_command(command)
            .map_err(|e| format!("cannot start the program: {e}"))?;
        drop(pair.slave);
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| format!("cannot read the pseudo-terminal: {e}"))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| format!("cannot write the pseudo-terminal: {e}"))?;
        let pid = child.process_id();
        let killer = child.clone_killer();
        let frame = Arc::new(Mutex::new(Arc::new(Frame::empty(size, colors))));
        let (to_engine, messages) = mpsc::channel();
        let output = to_engine.clone();
        thread::Builder::new()
            .name("terminal output".to_owned())
            .spawn(move || read_output(reader, &output))
            .map_err(|e| e.to_string())?;
        let exit = to_engine.clone();
        thread::Builder::new()
            .name("terminal program".to_owned())
            .spawn(move || {
                let ended = match child.wait() {
                    Ok(status) if status.signal().is_none() => Exit::Code(status.exit_code()),
                    Ok(_) | Err(_) => Exit::Signal,
                };
                let _ = exit.send(Message::Exited(ended));
            })
            .map_err(|e| e.to_string())?;
        let published = Arc::clone(&frame);
        thread::Builder::new()
            .name("terminal".to_owned())
            .spawn(move || run(&messages, writer, size, colors, &published, wake.as_ref()))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            to_engine,
            frame,
            master: Mutex::new(pair.master),
            killer: Mutex::new(killer),
            pid,
            size: Mutex::new(size),
        })
    }

    /// What it shows now.
    pub fn frame(&self) -> Arc<Frame> {
        Arc::clone(&self.frame.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Sends `input`.
    pub fn input(&self, input: Input) {
        let _ = self.to_engine.send(Message::Input(input));
    }

    /// Its size now.
    pub fn size(&self) -> Size {
        *self.size.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// It is `size` now (the program told, the screen reflowed).
    pub fn resize(&self, size: Size) {
        let mut current = self.size.lock().unwrap_or_else(PoisonError::into_inner);
        if *current == size || size.cols == 0 || size.rows == 0 {
            return;
        }
        *current = size;
        let _ = self
            .master
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .resize(size.pty());
        let _ = self.to_engine.send(Message::Resize(size));
    }

    /// The selection's text, its lines' ends trimmed, soft wraps joined;
    /// `None` without one.
    pub fn copy(&self) -> Option<String> {
        let (reply, answer) = mpsc::channel();
        self.to_engine.send(Message::Copy(reply)).ok()?;
        answer.recv_timeout(Duration::from_secs(1)).ok().flatten()
    }

    /// Whether a program other than the one it started runs in it now (one
    /// the shell started holds the terminal). Never on Windows, which does
    /// not say.
    pub fn busy(&self) -> bool {
        #[cfg(unix)]
        {
            let leader = self
                .master
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .process_group_leader();
            match (leader, self.pid) {
                (Some(leader), Some(pid)) => u32::try_from(leader).ok() != Some(pid),
                _ => false,
            }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self
            .killer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .kill();
    }
}

/// Sends what the program writes to the engine, until it ends.
fn read_output(mut reader: Box<dyn std::io::Read + Send>, to: &Sender<Message>) {
    let mut buffer = vec![0; 1 << 16];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let Some(read) = buffer.get(..n) else {
                    return;
                };
                if to.send(Message::Output(read.to_vec())).is_err() {
                    return;
                }
            }
        }
    }
}

/// The engine: the terminal's state on this thread, until the handle goes
/// (and with it the senders but the program's own threads', which end
/// with it).
fn run(
    messages: &Receiver<Message>,
    mut writer: Box<dyn Write + Send>,
    size: Size,
    colors: Colors,
    published: &Mutex<Arc<Frame>>,
    wake: &(dyn Fn() + Send + Sync),
) {
    let Ok(mut engine) = Engine::new(size, colors) else {
        return;
    };
    while let Ok(first) = messages.recv() {
        let mut read = engine.take(first, &mut *writer);
        while read < BATCH
            && let Ok(next) = messages.try_recv()
        {
            read += engine.take(next, &mut *writer);
        }
        if engine.held() {
            continue;
        }
        if let Some(frame) = engine.frame() {
            *published.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(frame);
            wake();
        }
    }
}

/// The terminal's state and what draws and encodes it.
struct Engine {
    vt: Vt,
    render: RenderState,
    rows: RowIterator,
    cells: CellIterator,
    keys: key::Encoder,
    pointer: mouse::Encoder,
    size: Size,
    colors: Colors,
    /// Where a selection started (a cell of the grid).
    anchor: Option<(u16, u16)>,
    /// The buttons held, for a program that asks for the pointer.
    held: Vec<Button>,
    /// Since when the program holds the screen.
    hold: Option<Instant>,
    title: String,
    bells: u64,
    exited: Option<Exit>,
    /// The program status reports in the output.
    reports: Reports,
    /// The program's status: the last report of its first record.
    status: Option<Status>,
    /// Something changed since the last frame.
    changed: bool,
}

impl Engine {
    fn new(size: Size, colors: Colors) -> Result<Self, ghostty_vt::Error> {
        let mut vt = Vt::new(Options {
            cols: size.cols.max(1),
            rows: size.rows.max(1),
            max_scrollback: SCROLLBACK,
        })?;
        vt.resize(
            size.cols.max(1),
            size.rows.max(1),
            size.cell_width,
            size.cell_height,
        )?;
        let mut engine = Self {
            vt,
            render: RenderState::new()?,
            rows: RowIterator::new()?,
            cells: CellIterator::new()?,
            keys: key::Encoder::new()?,
            pointer: mouse::Encoder::new()?,
            size,
            colors,
            anchor: None,
            held: Vec::new(),
            hold: None,
            title: String::new(),
            bells: 0,
            exited: None,
            reports: Reports::default(),
            status: None,
            changed: true,
        };
        engine.set_colors(colors);
        Ok(engine)
    }

    /// Whether the program holds the screen (synchronized output), not
    /// for longer than [`HOLD`].
    fn held(&mut self) -> bool {
        match self.hold {
            Some(since) if since.elapsed() < HOLD => true,
            Some(_) => {
                self.hold = None;
                false
            }
            None => false,
        }
    }

    fn set_colors(&mut self, colors: Colors) {
        self.colors = colors;
        let _ = self.vt.set_default_fg_color(Some(rgb(colors.foreground)));
        let _ = self.vt.set_default_bg_color(Some(rgb(colors.background)));
        let _ = self.vt.set_default_cursor_color(Some(rgb(colors.cursor)));
        self.changed = true;
    }

    /// Takes `message`: output run, input encoded and written to the
    /// program. How much output it was.
    fn take(&mut self, message: Message, writer: &mut dyn Write) -> usize {
        match message {
            Message::Output(bytes) => {
                // Answered ahead of what follows it, as libghostty would
                // (a program asks, then asks for the device attributes:
                // their answer first means no).
                for payload in self.reports.feed(&bytes) {
                    match report(&payload) {
                        Some(Report::Probe) => {
                            let _ = writer.write_all(PROBE_REPLY).and_then(|()| writer.flush());
                        }
                        Some(Report::Record { id, status }) if id.is_empty() => {
                            self.status = status;
                        }
                        Some(Report::Record { .. }) | None => {}
                    }
                }
                self.vt.vt_write(&bytes);
                self.drain(writer);
                self.changed = true;
                bytes.len()
            }
            Message::Exited(ended) => {
                self.exited = Some(ended);
                self.changed = true;
                0
            }
            Message::Resize(size) => {
                self.size = size;
                let _ = self.vt.resize(
                    size.cols.max(1),
                    size.rows.max(1),
                    size.cell_width,
                    size.cell_height,
                );
                self.changed = true;
                0
            }
            Message::Copy(reply) => {
                let text = self
                    .vt
                    .format_selection_alloc(FormatOptions::new().with_unwrap(true).with_trim(true))
                    .ok()
                    .flatten()
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
                let _ = reply.send(text);
                0
            }
            Message::Input(input) => {
                let bytes = self.input(input);
                if !bytes.is_empty() {
                    let _ = writer.write_all(&bytes).and_then(|()| writer.flush());
                }
                self.changed = true;
                0
            }
        }
    }

    /// The terminal's effects of what it ran: its answers written to the
    /// program, the title and the bell kept, the screen held.
    fn drain(&mut self, writer: &mut dyn Write) {
        let events: Vec<Event> = self.vt.events().collect();
        for event in events {
            match event {
                Event::PtyWrite(bytes) => {
                    let _ = writer.write_all(&bytes).and_then(|()| writer.flush());
                }
                Event::Bell => self.bells += 1,
                Event::TitleChanged(title) => self.title = title,
                Event::RenderHold(true) => self.hold = Some(Instant::now()),
                Event::RenderHold(false) => self.hold = None,
                Event::PwdChanged(_)
                | Event::ClipboardWrite(_)
                | Event::DesktopNotification { .. }
                | Event::ProgressReport { .. } => {}
            }
        }
    }

    fn mode(&self, mode: Mode) -> bool {
        self.vt.mode(mode).unwrap_or(false)
    }

    /// What `input` sends the program (the selection, the scrollback and
    /// the colours change here).
    fn input(&mut self, input: Input) -> Vec<u8> {
        let bytes = match input {
            Input::Key {
                key,
                text,
                mods,
                repeat,
            } => self.key(&key, text.as_deref(), mods, repeat),
            Input::Text(text) => text.into_bytes(),
            Input::Paste(text) => self.paste(text),
            Input::Wheel { lines, x, y, mods } => return self.wheel(lines, x, y, mods),
            Input::Pointer { what, x, y, mods } => return self.pointer(what, x, y, mods),
            Input::SelectFrom { x, y, clicks } => {
                self.select_from(self.size.cell(x, y), clicks);
                return Vec::new();
            }
            Input::SelectTo { x, y } => {
                self.select_to(self.size.cell(x, y));
                return Vec::new();
            }
            Input::Unselect => {
                self.anchor = None;
                let _ = self.vt.set_selection(None);
                return Vec::new();
            }
            Input::Focus(focused) => return self.focus(focused),
            Input::Colors(colors) => {
                self.set_colors(colors);
                return Vec::new();
            }
        };
        // What is typed shows the screen's end, the selection gone.
        if !bytes.is_empty() {
            self.vt.scroll_viewport(ScrollViewport::Bottom);
            self.anchor = None;
            let _ = self.vt.set_selection(None);
        }
        bytes
    }

    /// The key named `name` typing `text`, encoded as the program's modes
    /// say (Shift+Enter a line feed, which agents' prompts take as a new
    /// line).
    fn key(&mut self, name: &str, text: Option<&str>, mods: Mods, repeat: bool) -> Vec<u8> {
        if matches!(name, "enter" | "return")
            && mods.shift
            && !mods.control
            && !mods.alt
            && !mods.platform
        {
            return vec![b'\n'];
        }
        let Ok(mut event) = key::Event::new() else {
            return Vec::new();
        };
        event
            .set_action(if repeat {
                key::Action::Repeat
            } else {
                key::Action::Press
            })
            .set_key(key_code(name))
            .set_mods(mods.ghostty());
        let single = name.chars().count() == 1;
        match text.filter(|t| !t.is_empty()) {
            Some(text) => event.set_utf8(Some(text)),
            None if single => event.set_utf8(Some(name)),
            None => event.set_utf8(None::<&str>),
        };
        if let Some(c) = name.chars().next().filter(|_| single) {
            event.set_unshifted_codepoint(c);
        }
        self.keys.set_options_from_terminal(&self.vt);
        let mut out = Vec::new();
        let _ = self.keys.encode_to_vec(&event, &mut out);
        out
    }

    /// `text` pasted, bracketed where the program asks.
    fn paste(&self, text: String) -> Vec<u8> {
        let bracketed = self.mode(Mode::BRACKETED_PASTE);
        let mut data = text.into_bytes();
        let mut out = vec![0; data.len() + 16];
        match ghostty_vt::paste::encode(&mut data, bracketed, &mut out) {
            Ok(n) => out.truncate(n),
            Err(ghostty_vt::Error::OutOfSpace { required }) => {
                out.resize(required, 0);
                match ghostty_vt::paste::encode(&mut data, bracketed, &mut out) {
                    Ok(n) => out.truncate(n),
                    Err(_) => out.clear(),
                }
            }
            Err(_) => out.clear(),
        }
        out
    }

    /// The wheel: to the program where it takes the pointer, arrow keys on
    /// the alternate screen where it asks, else the scrollback.
    fn wheel(&mut self, lines: isize, x: f32, y: f32, mods: Mods) -> Vec<u8> {
        if lines == 0 {
            return Vec::new();
        }
        if self.vt.is_mouse_tracking().unwrap_or(false) {
            let button = if lines < 0 {
                mouse::Button::Four
            } else {
                mouse::Button::Five
            };
            let mut out = Vec::new();
            for _ in 0..lines.unsigned_abs() {
                out.extend(self.encode_pointer(mouse::Action::Press, Some(button), x, y, mods));
            }
            return out;
        }
        let alternate = self.vt.active_screen().ok() == Some(Screen::Alternate);
        if alternate && self.mode(Mode::ALT_SCROLL) {
            let arrow = if lines < 0 { "up" } else { "down" };
            let mut out = Vec::new();
            for _ in 0..lines.unsigned_abs() {
                out.extend(self.key(arrow, None, Mods::default(), false));
            }
            return out;
        }
        self.vt.scroll_viewport(ScrollViewport::Delta(lines));
        Vec::new()
    }

    /// The pointer, to a program that takes it.
    fn pointer(&mut self, what: Pointer, x: f32, y: f32, mods: Mods) -> Vec<u8> {
        if !self.vt.is_mouse_tracking().unwrap_or(false) {
            self.held.clear();
            return Vec::new();
        }
        let (action, button) = match what {
            Pointer::Press(button) => {
                if !self.held.contains(&button) {
                    self.held.push(button);
                }
                (mouse::Action::Press, Some(button))
            }
            Pointer::Release(button) => {
                self.held.retain(|held| *held != button);
                (mouse::Action::Release, Some(button))
            }
            Pointer::Move => (mouse::Action::Motion, self.held.first().copied()),
        };
        let button = button.map(|button| match button {
            Button::Left => mouse::Button::Left,
            Button::Middle => mouse::Button::Middle,
            Button::Right => mouse::Button::Right,
        });
        self.encode_pointer(action, button, x, y, mods)
    }

    fn encode_pointer(
        &mut self,
        action: mouse::Action,
        button: Option<mouse::Button>,
        x: f32,
        y: f32,
        mods: Mods,
    ) -> Vec<u8> {
        let size = self.size;
        self.pointer
            .set_options_from_terminal(&self.vt)
            .set_any_button_pressed(!self.held.is_empty())
            .set_size(mouse::EncoderSize {
                screen_width: u32::from(size.cols) * size.cell_width,
                screen_height: u32::from(size.rows) * size.cell_height,
                cell_width: size.cell_width,
                cell_height: size.cell_height,
                padding_top: 0,
                padding_bottom: 0,
                padding_right: 0,
                padding_left: 0,
            });
        let Ok(mut event) = mouse::Event::new() else {
            return Vec::new();
        };
        event
            .set_action(action)
            .set_button(button)
            .set_mods(mods.ghostty())
            .set_position(mouse::Position {
                x: x.max(0.0),
                y: y.max(0.0),
            });
        let mut out = Vec::new();
        let _ = self.pointer.encode_to_vec(&event, &mut out);
        out
    }

    /// The focus, said to a program that asks.
    fn focus(&self, focused: bool) -> Vec<u8> {
        if !self.mode(Mode::FOCUS_EVENT) {
            return Vec::new();
        }
        let event = if focused {
            ghostty_vt::focus::Event::Gained
        } else {
            ghostty_vt::focus::Event::Lost
        };
        let mut buffer = [0; 8];
        event
            .encode(&mut buffer)
            .ok()
            .and_then(|n| buffer.get(..n))
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }

    /// The grid's cell `(x, y)` as the terminal knows it.
    fn point((x, y): (u16, u16)) -> Point {
        Point::Viewport(PointCoordinate { x, y: u32::from(y) })
    }

    /// A selection from `cell`: none yet (one click), its word (two), its
    /// line (three).
    fn select_from(&mut self, cell: (u16, u16), clicks: usize) {
        self.anchor = Some(cell);
        let Ok(at) = self.vt.grid_ref(Self::point(cell)) else {
            return;
        };
        let selection = match clicks {
            0 | 1 => None,
            2 => self
                .vt
                .select_word(SelectWordOptions::new(at))
                .ok()
                .flatten(),
            _ => self
                .vt
                .select_line(SelectLineOptions::new(at))
                .ok()
                .flatten(),
        };
        let _ = self.vt.set_selection(selection.as_ref());
        if clicks > 1 {
            self.anchor = None;
        }
    }

    /// The selection from where it started to `cell`.
    fn select_to(&mut self, cell: (u16, u16)) {
        let Some(anchor) = self.anchor else {
            return;
        };
        let (Ok(start), Ok(end)) = (
            self.vt.grid_ref(Self::point(anchor)),
            self.vt.grid_ref(Self::point(cell)),
        ) else {
            return;
        };
        let selection = Selection::new(start, end, false);
        let _ = self.vt.set_selection(Some(&selection));
    }

    /// The frame of the terminal as it is, if something changed.
    fn frame(&mut self) -> Option<Frame> {
        if !std::mem::take(&mut self.changed) {
            return None;
        }
        let snapshot = self.render.update(&self.vt).ok()?;
        let colors = snapshot.colors().ok()?;
        let foreground = hex(colors.foreground);
        let background = hex(colors.background);
        let cursor = snapshot.cursor().ok().and_then(|cursor| {
            let at = cursor.viewport.filter(|_| cursor.visible)?;
            Some(Cursor {
                column: at.x,
                row: at.y,
                shape: match cursor.visual_style {
                    CursorVisualStyle::Bar => Shape::Bar,
                    CursorVisualStyle::Underline => Shape::Underline,
                    CursorVisualStyle::BlockHollow => Shape::Hollow,
                    // A style a later Ghostty adds: a block.
                    CursorVisualStyle::Block | _ => Shape::Block,
                },
                color: colors.cursor.map_or(self.colors.cursor, hex),
            })
        });
        let mut rows = Vec::new();
        let mut row_iteration = self.rows.update(&snapshot).ok()?;
        while let Some(row) = row_iteration.next() {
            rows.push(row_runs(&mut self.cells, row, (foreground, background)));
        }
        let _ = snapshot.clean();
        let scroll = self
            .vt
            .scrollbar()
            .ok()
            .map_or_else(Scroll::default, |s| Scroll {
                total: s.total,
                offset: s.offset,
                len: s.len,
            });
        Some(Frame {
            cols: self.size.cols,
            rows,
            cursor,
            background,
            foreground,
            scroll,
            pointer: self.vt.is_mouse_tracking().unwrap_or(false),
            alternate: self.vt.active_screen().ok() == Some(Screen::Alternate),
            title: self.title.clone(),
            bells: self.bells,
            exited: self.exited,
            status: self.status.clone(),
        })
    }
}

/// `0xRRGGBB` as the terminal's colour.
fn rgb(color: u32) -> RgbColor {
    let [_, r, g, b] = color.to_be_bytes();
    RgbColor { r, g, b }
}

/// The terminal's colour as `0xRRGGBB`.
fn hex(color: RgbColor) -> u32 {
    u32::from_be_bytes([0, color.r, color.g, color.b])
}

/// The runs of `row`, its cells read with `cells`, what the program leaves
/// unset in `(foreground, background)`.
fn row_runs(
    cells: &mut CellIterator,
    row: &RowIteration<'_>,
    (foreground, background): (u32, u32),
) -> Vec<Run> {
    let selected = row.selection().ok().flatten();
    let mut runs: Vec<Run> = Vec::new();
    let Ok(mut iteration) = cells.update(row) else {
        return runs;
    };
    let mut column: u16 = 0;
    let mut text = String::new();
    // The last run is a wide character's: nothing joins it.
    let mut wide_last = false;
    while let Some(cell) = iteration.next() {
        let at = column;
        column = column.saturating_add(1);
        let wide = cell
            .raw_cell()
            .and_then(ghostty_vt::screen::Cell::wide)
            .unwrap_or(CellWide::Narrow);
        let width: u16 = match wide {
            CellWide::SpacerTail | CellWide::SpacerHead => continue,
            CellWide::Wide => 2,
            CellWide::Narrow => 1,
        };
        text.clear();
        if cell.graphemes_utf8(&mut text).is_err() || text.is_empty() {
            text.push(' ');
        }
        let style = cell.style().unwrap_or_default();
        let mut fg = cell.fg_color().ok().flatten().map_or(foreground, hex);
        let mut bg = cell.bg_color().ok().flatten().map(hex);
        if style.inverse {
            let back = bg.unwrap_or(background);
            bg = Some(fg);
            fg = back;
        }
        if style.invisible {
            fg = bg.unwrap_or(background);
        }
        let run = Run {
            text: String::new(),
            column: at,
            columns: width,
            fg,
            bg,
            bold: style.bold,
            italic: style.italic,
            faint: style.faint,
            underline: style.underline != Underline::None,
            strikethrough: style.strikethrough,
            selected: selected.is_some_and(|s| (s.start_x..=s.end_x).contains(&at)),
        };
        // The same style right after the last run: it grows, but for a wide
        // character, which is a run of its own.
        match runs.last_mut() {
            Some(last)
                if width == 1
                    && !wide_last
                    && last.column + last.columns == at
                    && Run {
                        text: String::new(),
                        column: at,
                        columns: width,
                        ..last.clone()
                    } == run =>
            {
                last.text.push_str(&text);
                last.columns += width;
            }
            Some(_) | None => runs.push(Run {
                text: text.clone(),
                ..run
            }),
        }
        wide_last = width == 2;
    }
    runs
}

/// The answer to a program asking whether the terminal takes program
/// status reports (`OSC 7501 ; ?`): yes, every state and kind, as
/// libghostty answers when its embedder takes them.
const PROBE_REPLY: &[u8] =
    b"\x1b]7501;?:states=idle,working,done,blocked,error:kinds=permission,question,auth\x1b\\";
/// The longest report the protocol allows, in bytes.
const REPORT: usize = 4096;

/// The program status reports (`OSC 7501 ; …` ended by BEL or `ESC \`)
/// in a program's output, found as it comes, in pieces. libghostty-vt
/// parses them too, but its Rust crate does not hand them on.
#[derive(Debug, Default)]
struct Reports {
    scan: Scan,
    payload: Vec<u8>,
}

/// Where [`Reports`] is in the output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Scan {
    /// Outside a report.
    #[default]
    Ground,
    /// After ESC.
    Escape,
    /// After `ESC ]` and this many bytes of `7501;`.
    Code(usize),
    /// In a report's payload.
    Payload,
    /// In a payload, after ESC (`ESC \` ends it).
    PayloadEscape,
}

impl Reports {
    /// The payloads `bytes` completes, in order (one longer than
    /// [`REPORT`] dropped).
    fn feed(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        const CODE: &[u8] = b"7501;";
        let mut done = Vec::new();
        for &byte in bytes {
            self.scan = match (self.scan, byte) {
                (Scan::Payload, 0x07) | (Scan::PayloadEscape, b'\\') => {
                    done.push(std::mem::take(&mut self.payload));
                    Scan::Ground
                }
                (Scan::Payload, 0x1b) => Scan::PayloadEscape,
                (Scan::Payload, _) if self.payload.len() < REPORT => {
                    self.payload.push(byte);
                    Scan::Payload
                }
                (Scan::Payload | Scan::PayloadEscape, _) => {
                    self.payload.clear();
                    match byte {
                        0x1b => Scan::Escape,
                        b']' if self.scan == Scan::PayloadEscape => Scan::Code(0),
                        _ => Scan::Ground,
                    }
                }
                (Scan::Ground | Scan::Escape | Scan::Code(_), 0x1b) => Scan::Escape,
                (Scan::Escape, b']') => Scan::Code(0),
                (Scan::Code(at), _) if CODE.get(at) == Some(&byte) => {
                    if at + 1 == CODE.len() {
                        Scan::Payload
                    } else {
                        Scan::Code(at + 1)
                    }
                }
                (Scan::Ground | Scan::Escape | Scan::Code(_), _) => Scan::Ground,
            };
        }
        done
    }
}

/// What a program status report says.
#[derive(Debug, PartialEq, Eq)]
enum Report {
    /// `?`: whether the terminal takes them.
    Probe,
    /// Record `id`'s new state (the first record's: empty); `None`:
    /// cleared.
    Record {
        /// The record.
        id: String,
        /// Its program and state.
        status: Option<Status>,
    },
}

/// The report `payload` (`key=value` pairs joined by `:`) makes; `None`
/// if it is not one (no state, or one the protocol has not).
fn report(payload: &[u8]) -> Option<Report> {
    let text = std::str::from_utf8(payload).ok()?;
    if text.starts_with('?') {
        return Some(Report::Probe);
    }
    let (mut state, mut id, mut app) = (None, "", "");
    for pair in text.split(':') {
        match pair.split_once('=')? {
            ("state", value) => state = Some(value),
            ("id", value) => id = value,
            ("app", value) => app = value,
            _ => {}
        }
    }
    let state = match state? {
        "idle" => Some(State::Idle),
        "working" => Some(State::Working),
        "done" => Some(State::Done),
        "blocked" => Some(State::Blocked),
        "error" => Some(State::Error),
        "clear" => None,
        _ => return None,
    };
    Some(Report::Record {
        id: id.to_owned(),
        status: state.map(|state| Status {
            app: app.to_owned(),
            state,
        }),
    })
}

/// The key GPUI names `name`.
fn key_code(name: &str) -> key::Key {
    use key::Key;
    let mut chars = name.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        if c.is_ascii_alphabetic() {
            let index = i32::from(c.to_ascii_lowercase() as u8 - b'a');
            return Key::try_from(Key::A as i32 + index).unwrap_or(Key::Unidentified);
        }
        if let Some(digit) = c.to_digit(10) {
            let index = i32::try_from(digit).unwrap_or(0);
            return Key::try_from(Key::Digit0 as i32 + index).unwrap_or(Key::Unidentified);
        }
    }
    if let Some(number) = name
        .strip_prefix('f')
        .and_then(|n| n.parse::<i32>().ok())
        .filter(|n| (1..=25).contains(n))
    {
        return Key::try_from(Key::F1 as i32 + number - 1).unwrap_or(Key::Unidentified);
    }
    match name {
        "enter" | "return" => Key::Enter,
        "escape" => Key::Escape,
        "backspace" => Key::Backspace,
        "tab" => Key::Tab,
        "space" | " " => Key::Space,
        "up" => Key::ArrowUp,
        "down" => Key::ArrowDown,
        "left" => Key::ArrowLeft,
        "right" => Key::ArrowRight,
        "home" => Key::Home,
        "end" => Key::End,
        "pageup" => Key::PageUp,
        "pagedown" => Key::PageDown,
        "delete" => Key::Delete,
        "insert" => Key::Insert,
        "-" => Key::Minus,
        "=" => Key::Equal,
        "[" => Key::BracketLeft,
        "]" => Key::BracketRight,
        "\\" => Key::Backslash,
        ";" => Key::Semicolon,
        "'" => Key::Quote,
        "," => Key::Comma,
        "." => Key::Period,
        "/" => Key::Slash,
        "`" => Key::Backquote,
        _ => Key::Unidentified,
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;

    const IDLE: &[u8] = b"state=idle:app=claude-code";

    /// A report is found however the output is cut, ended by BEL or by
    /// `ESC \`; other OSCs and one too long are not reports.
    #[test]
    fn reports_are_found_in_output_cut_anywhere() {
        let mut output = b"text\x1b]0;a title\x07\x1b]7501;".to_vec();
        output.extend_from_slice(IDLE);
        output.extend_from_slice(b"\x07more\x1b]7501;?\x1b\\");
        for cut in 0..=output.len() {
            let (head, tail) = output.split_at(cut);
            let mut reports = Reports::default();
            let mut found = reports.feed(head);
            found.extend(reports.feed(tail));
            assert_eq!(found, [IDLE.to_vec(), b"?".to_vec()], "cut at {cut}");
        }
        let mut long = b"\x1b]7501;".to_vec();
        long.resize(long.len() + REPORT + 1, b'a');
        long.extend_from_slice(b"\x07\x1b]7501;state=done\x07");
        assert_eq!(Reports::default().feed(&long), [b"state=done".to_vec()]);
    }

    #[test]
    fn a_report_says_its_program_and_state() {
        assert_eq!(
            report(b"state=blocked:kind=permission:app=terraform:msg=QXBwbHk/"),
            Some(Report::Record {
                id: String::new(),
                status: Some(Status {
                    app: "terraform".to_owned(),
                    state: State::Blocked
                })
            })
        );
        assert_eq!(report(b"?"), Some(Report::Probe));
        assert_eq!(
            report(b"state=clear:id=build"),
            Some(Report::Record {
                id: "build".to_owned(),
                status: None
            })
        );
        assert_eq!(report(b"state=napping"), None);
        assert_eq!(report(b"app=claude-code"), None);
    }
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests fail loudly"
    )]

    use super::*;

    const SIZE: Size = Size {
        cols: 40,
        rows: 10,
        cell_width: 8,
        cell_height: 16,
    };
    const COLORS: Colors = Colors {
        foreground: 0x00dd_dddd,
        background: 0x0010_1010,
        cursor: 0x00ff_ffff,
    };

    fn start(command: &[&str]) -> Terminal {
        let launch = Launch {
            command: command.iter().map(|&s| s.to_owned()).collect(),
            ..Launch::default()
        };
        Terminal::start(&launch, SIZE, COLORS, Arc::new(|| {})).unwrap()
    }

    /// The frame once `ready` holds of it (within ten seconds).
    fn until(terminal: &Terminal, ready: impl Fn(&Frame) -> bool) -> Arc<Frame> {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let frame = terminal.frame();
            if ready(&frame) {
                return frame;
            }
            assert!(Instant::now() < end, "never: {:?}", frame.text());
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn key(name: &str) -> Input {
        Input::Key {
            key: name.to_owned(),
            text: (name.chars().count() == 1).then(|| name.to_owned()),
            mods: Mods::default(),
            repeat: false,
        }
    }

    fn selected(frame: &Frame) -> String {
        frame.rows[0]
            .iter()
            .filter(|r| r.selected)
            .map(|r| r.text.as_str())
            .collect()
    }

    /// What a program prints is in the frame in its styles: SGR colours
    /// resolved, inverse swapping the theme's colours, the rest the
    /// theme's.
    #[test]
    fn a_programs_output_is_in_the_frame_styled() {
        let t = start(&[
            "sh",
            "-c",
            "printf 'plain \\033[1;31mred\\033[0m \\033[7minv\\033[0m'; sleep 10",
        ]);
        let frame = until(&t, |f| f.text().first().is_some_and(|l| l.contains("inv")));
        let runs = &frame.rows[0];
        let red = runs.iter().find(|r| r.text == "red").unwrap();
        let [_, r, g, b] = red.fg.to_be_bytes();
        assert!(red.bold && r > 0x80 && g < 0x80 && b < 0x80, "{red:?}");
        let plain = runs.iter().find(|r| r.text.starts_with("plain")).unwrap();
        assert_eq!(
            (plain.fg, plain.bg, plain.bold),
            (COLORS.foreground, None, false)
        );
        let inverse = runs.iter().find(|r| r.text == "inv").unwrap();
        assert_eq!(
            (inverse.fg, inverse.bg),
            (COLORS.background, Some(COLORS.foreground))
        );
        assert_eq!((frame.cols, frame.rows.len()), (40, 10));
    }

    /// Keys typed reach the program; a resize reaches it (`stty size`)
    /// and the grid.
    #[test]
    fn keys_reach_the_program_and_a_resize_its_size() {
        let t = start(&[
            "sh",
            "-c",
            "while read -r line; do echo \"got $line\"; stty size; done",
        ]);
        for name in ["h", "i", "enter"] {
            t.input(key(name));
        }
        until(&t, |f| {
            let text = f.text();
            text.iter().any(|l| l == "got hi") && text.iter().any(|l| l == "10 40")
        });
        t.resize(Size {
            cols: 30,
            rows: 8,
            ..SIZE
        });
        t.input(Input::Text("x\r".to_owned()));
        let frame = until(&t, |f| f.text().iter().any(|l| l == "8 30"));
        assert_eq!((frame.cols, frame.rows.len()), (30, 8));
    }

    #[test]
    fn the_programs_end_is_in_the_frame() {
        let t = start(&["sh", "-c", "exit 3"]);
        until(&t, |f| f.exited == Some(Exit::Code(3)));
    }

    /// A wide character is a run of its own, two columns wide, between
    /// those of its style around it: the GUI draws a glyph a column.
    #[test]
    fn a_wide_character_is_a_run_of_its_own() {
        let t = start(&["sh", "-c", "printf 'a\\344\\270\\226b'; sleep 10"]);
        let frame = until(&t, |f| f.text().first().is_some_and(|l| l.contains('b')));
        let runs: Vec<(&str, u16, u16)> = frame.rows[0]
            .iter()
            .take(3)
            .map(|r| (r.text.trim_end(), r.column, r.columns))
            .collect();
        assert_eq!(runs[..2], [("a", 0, 1), ("\u{4e16}", 1, 2)]);
        assert_eq!((runs[2].0, runs[2].1), ("b", 3));
    }

    /// A program asking whether the terminal takes status reports is
    /// answered yes, and the one it then sends is in the frame.
    #[test]
    fn a_programs_status_is_answered_and_in_the_frame() {
        let t = start(&[
            "sh",
            "-c",
            r"stty -echo -icanon min 1; printf '\033]7501;?\033\\'; head -c 9 | tr '\033' E; echo; printf '\033]7501;state=idle:app=claude-code\007'; sleep 10",
        ]);
        let frame = until(&t, |f| f.status.is_some());
        assert!(
            frame.text().iter().any(|l| l == "E]7501;?:"),
            "{:?}",
            frame.text()
        );
        assert_eq!(
            frame.status,
            Some(Status {
                app: "claude-code".to_owned(),
                state: State::Idle
            })
        );
    }

    /// A double click selects a word, a drag from a cell what it spans;
    /// either is what Copy takes.
    #[test]
    fn a_selection_is_shown_and_copied() {
        let t = start(&["sh", "-c", "printf 'hello world'; sleep 10"]);
        until(&t, |f| f.text().first().is_some_and(|l| l == "hello world"));
        // Column 8 (in "world"), row 0, in pixels.
        t.input(Input::SelectFrom {
            x: 8.5 * 8.0,
            y: 4.0,
            clicks: 2,
        });
        until(&t, |f| selected(f) == "world");
        assert_eq!(t.copy().as_deref(), Some("world"));
        t.input(Input::SelectFrom {
            x: 0.5 * 8.0,
            y: 4.0,
            clicks: 1,
        });
        t.input(Input::SelectTo {
            x: 4.5 * 8.0,
            y: 4.0,
        });
        until(&t, |f| selected(f) == "hello");
        assert_eq!(t.copy().as_deref(), Some("hello"));
        t.input(Input::Unselect);
        until(&t, |f| selected(f).is_empty());
        assert_eq!(t.copy(), None);
    }

    /// A program the shell runs makes the terminal busy; the shell alone
    /// does not.
    #[test]
    fn a_program_the_shell_runs_makes_it_busy() {
        let t = start(&["sh"]);
        thread::sleep(Duration::from_millis(300));
        assert!(!t.busy());
        t.input(Input::Text("sleep 30\r".to_owned()));
        let end = Instant::now() + Duration::from_secs(10);
        while !t.busy() {
            assert!(Instant::now() < end, "never busy");
            thread::sleep(Duration::from_millis(20));
        }
    }
}
