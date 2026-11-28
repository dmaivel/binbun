//! The console pane's model: the user's Python (`python -m binbun.console`
//! run with the `python.interpreter` setting, connected to this window's
//! database over the GUI's socket), spoken to in lines of JSON on its
//! standard input and output (the protocol is `binbun.console`'s
//! docstring); the transcript of what ran and what it printed, capped;
//! the history ([`history`]); the completions and the signature of the
//! call being typed; Python coloured for the input ([`python`]).
//!
//! The GUI never loads Python: a missing interpreter, or one without
//! `binbun`, is said in the pane with how to install it. Ctrl+C sends
//! SIGINT to the console's process (never the GUI's); on Windows, where
//! sending `CTRL_BREAK` needs `GenerateConsoleCtrlEvent` (foreign code this
//! crate forbids) and a console the child has not, the console is asked to
//! interrupt its cell itself (it raises SIGINT in its own process), which
//! stops Python code and the waits Python makes interruptible
//! (`time.sleep`...), not other blocking calls.

pub mod history;
pub mod python;

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::ops::Range;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::session::Wake;
use history::History;

/// The console protocol's version this GUI speaks.
pub const PROTOCOL: u64 = 1;
/// The most transcript lines kept (the oldest dropped).
pub const MAX_LINES: usize = 20_000;
/// The most bytes of a transcript line kept (the rest cut).
pub const MAX_LINE: usize = 4_000;
/// The most bytes of the console's standard error kept for a message.
const STDERR_TAIL: usize = 8 * 1024;
/// How often the reader looks whether the process ended.
const REAP: Duration = Duration::from_millis(20);

/// What starts the console.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    /// The interpreter: a path (`~/` is the home directory) or a name
    /// looked up on `PATH`.
    pub interpreter: String,
    /// The GUI's socket.
    pub socket: PathBuf,
    /// The database's path (which of the socket's databases).
    pub database: PathBuf,
}

impl Launch {
    /// The interpreter's program, `~/` expanded ([`binbun_paths::home`]).
    pub fn program(&self) -> PathBuf {
        match (self.interpreter.strip_prefix("~/"), binbun_paths::home()) {
            (Some(rest), Some(home)) => home.join(rest),
            _ => PathBuf::from(self.interpreter.trim()),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(self.program());
        command
            .args(["-m", "binbun.console", "--socket"])
            .arg(&self.socket)
            .arg("--database")
            .arg(&self.database)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

/// A stream of the console's output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// A completion offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// What it inserts.
    pub text: String,
    /// What it is (`function`, `instance`, `module`, `keyword`...).
    pub kind: String,
}

/// The signature of the call being typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// It as text (`get_at(ea: int)`).
    pub label: String,
    /// The bytes of the parameter being typed in it.
    pub active: Option<Range<usize>>,
    /// The first paragraph of its documentation.
    pub doc: String,
}

/// What the console said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// It is connected and takes cells.
    Ready {
        /// Its protocol version.
        protocol: u64,
        /// Python's version.
        python: String,
        /// `jedi` or `rlcompleter`.
        completer: String,
        /// The database's name.
        database: String,
    },
    /// It could not connect (then it ends).
    Failed(String),
    /// The cell needs more lines.
    Incomplete(u64),
    /// The cell will run.
    Accepted(u64),
    /// A cell started (`None`: `startup.py`).
    Started(Option<u64>),
    /// Output.
    Output(Stream, String),
    /// The `repr` of a cell's value.
    Result(String),
    /// A cell's traceback.
    Error(String),
    /// A cell ended: its undo step's label, a note.
    Done {
        /// The undo step it made, if it wrote.
        step: Option<String>,
        /// What to say of its writes.
        note: Option<String>,
    },
    /// A note.
    Note(String),
    /// Completions asked for as request `id`: where the text they replace
    /// starts (code points of the code sent).
    Completions {
        /// The request.
        id: u64,
        /// The start, in code points.
        start: usize,
        /// The completions.
        items: Vec<Item>,
    },
    /// The signature asked for as request `id`.
    Signature {
        /// The request.
        id: u64,
        /// The signature, if the cursor is in a call.
        signature: Option<Signature>,
    },
    /// The process ended: its exit code, the end of its standard error.
    Exited {
        /// Its exit code.
        code: Option<i32>,
        /// The end of its standard error.
        stderr: String,
    },
}

/// The event a line of the console's output says, if it is one.
pub fn parse_event(line: &str) -> Option<Event> {
    let value: Value = serde_json::from_str(line).ok()?;
    let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    let id = || value.get("id").and_then(Value::as_u64);
    let index = |v: &Value| v.as_u64().and_then(|n| usize::try_from(n).ok());
    Some(match value.get("event")?.as_str()? {
        "ready" => Event::Ready {
            protocol: value.get("protocol").and_then(Value::as_u64).unwrap_or(0),
            python: text("python").unwrap_or_default(),
            completer: text("completer").unwrap_or_default(),
            database: text("database").unwrap_or_default(),
        },
        "failed" => Event::Failed(text("message").unwrap_or_default()),
        "incomplete" => Event::Incomplete(id()?),
        "accepted" => Event::Accepted(id()?),
        "started" => Event::Started(id()),
        "output" => {
            let stream = if text("stream").as_deref() == Some("stderr") {
                Stream::Stderr
            } else {
                Stream::Stdout
            };
            Event::Output(stream, text("text")?)
        }
        "result" => Event::Result(text("text")?),
        "error" => Event::Error(text("text")?),
        "done" => Event::Done {
            step: text("step"),
            note: text("note"),
        },
        "note" => Event::Note(text("text")?),
        "completions" => Event::Completions {
            id: id()?,
            start: value.get("start").and_then(index)?,
            items: value
                .get("items")?
                .as_array()?
                .iter()
                .filter_map(|item| {
                    Some(Item {
                        text: item.get("text")?.as_str()?.to_owned(),
                        kind: item
                            .get("kind")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned(),
                    })
                })
                .collect(),
        },
        "signature" => Event::Signature {
            id: id()?,
            signature: text("label").map(|label| {
                // Sent in code points of the label; kept in bytes.
                let active = value
                    .get("active")
                    .and_then(Value::as_array)
                    .and_then(|a| Some(index(a.first()?)?..index(a.get(1)?)?))
                    .map(|cps| byte_of(&label, cps.start)..byte_of(&label, cps.end));
                Signature {
                    label,
                    active,
                    doc: text("doc").unwrap_or_default(),
                }
            }),
        },
        _ => return None,
    })
}

/// The byte of `text` at code point `cp` (its end past it).
pub fn byte_of(text: &str, cp: usize) -> usize {
    text.char_indices().nth(cp).map_or(text.len(), |(i, _)| i)
}

/// The code point of `text` at byte `byte`.
pub fn cp_of(text: &str, byte: usize) -> usize {
    text.get(..byte.min(text.len()))
        .map_or_else(|| text.chars().count(), |before| before.chars().count())
}

/// Why the console is not running, said in the pane.
pub fn stopped_message(
    interpreter: &str,
    ever_ready: bool,
    code: Option<i32>,
    stderr: &str,
) -> String {
    if !ever_ready
        && (stderr.contains("No module named binbun") || stderr.contains("No module named 'binbun"))
    {
        return format!(
            "binbun is not installed for {interpreter}. Set Up Python, in the banner above, \
             makes binbun a Python of its own; or install it into that interpreter \
             (`{interpreter} -m pip install binbun`), or set python.interpreter to a Python \
             that has it."
        );
    }
    let last = stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let code = code.map_or_else(|| "a signal".to_owned(), |c| format!("exit code {c}"));
    if last.is_empty() {
        format!("The console stopped ({code}).")
    } else {
        format!("The console stopped ({code}): {last}")
    }
}

/// What the console is doing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Starting: not connected yet.
    Starting,
    /// Connected, taking cells.
    Ready {
        /// Python's version.
        python: String,
        /// `jedi` or `rlcompleter`.
        completer: String,
        /// The database's name.
        database: String,
    },
    /// Not running, and why (how to fix it).
    Stopped(String),
}

/// What a transcript line is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    /// A line of a cell run (`first`: its first, after the prompt).
    Input {
        /// The cell's first line.
        first: bool,
    },
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A cell's value.
    Result,
    /// A traceback.
    Error,
    /// A note (the console's, or the undo step a cell made).
    Note,
}

/// A transcript line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// What it is.
    pub kind: LineKind,
    /// Its text.
    pub text: String,
    /// Its coloured bytes (an input line's).
    pub spans: Vec<(Range<usize>, python::Kind)>,
}

/// What ran and what it printed: at most [`MAX_LINES`] lines of at most
/// [`MAX_LINE`] bytes, output streamed into its last line until a line
/// break (a carriage return starts the line over, as a terminal's).
#[derive(Debug, Default)]
pub struct Transcript {
    lines: VecDeque<Line>,
    /// The last line takes more output of its stream.
    open: Option<LineKind>,
    /// Lines dropped from the top.
    dropped: u64,
}

impl Transcript {
    /// The lines kept.
    pub fn lines(&self) -> &VecDeque<Line> {
        &self.lines
    }

    /// How many lines were dropped from the top.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Clears it.
    pub fn clear(&mut self) {
        self.lines.clear();
        self.open = None;
    }

    /// A cell run: its lines, coloured.
    pub fn input(&mut self, code: &str) {
        self.open = None;
        let code = code.trim_end_matches('\n');
        let tokens = python::tokens(code);
        let mut start = 0;
        for (n, line) in code.split('\n').enumerate() {
            let end = start + line.len();
            let spans = tokens
                .iter()
                .filter(|t| t.range.start < end && t.range.end > start)
                .map(|t| {
                    (
                        t.range.start.max(start) - start..t.range.end.min(end) - start,
                        t.kind,
                    )
                })
                .collect();
            self.add(Line {
                kind: LineKind::Input { first: n == 0 },
                text: line.to_owned(),
                spans,
            });
            start = end + 1;
        }
    }

    /// `text` of `kind`: output joins the open line of its stream; other
    /// kinds are whole lines.
    pub fn push(&mut self, kind: LineKind, text: &str) {
        let streamed = matches!(kind, LineKind::Stdout | LineKind::Stderr);
        if !streamed {
            self.open = None;
        }
        let mut pieces = text.split('\n').peekable();
        while let Some(piece) = pieces.next() {
            let last = pieces.peek().is_none();
            if streamed && last && piece.is_empty() {
                // The text ended its line.
                self.open = None;
                break;
            }
            if self.open == Some(kind) {
                if let Some(line) = self.lines.back_mut() {
                    write_over(&mut line.text, piece);
                }
            } else {
                let mut line = String::new();
                write_over(&mut line, piece);
                self.add(Line {
                    kind,
                    text: line,
                    spans: Vec::new(),
                });
            }
            self.open = (streamed && last).then_some(kind);
        }
        if !streamed {
            self.open = None;
        }
    }

    fn add(&mut self, mut line: Line) {
        cut(&mut line.text);
        self.lines.push_back(line);
        while self.lines.len() > MAX_LINES {
            self.lines.pop_front();
            self.dropped += 1;
        }
    }
}

/// `piece` written onto `line` as a terminal would: after a carriage
/// return, over the line from its start.
fn write_over(line: &mut String, piece: &str) {
    match piece.rsplit_once('\r') {
        Some((_, after)) => after.clone_into(line),
        None => line.push_str(piece),
    }
    cut(line);
}

/// `text` cut to [`MAX_LINE`] bytes (on a character's boundary), saying
/// so.
fn cut(text: &mut String) {
    if text.len() <= MAX_LINE {
        return;
    }
    let mut end = MAX_LINE;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let more = text.len() - end;
    text.truncate(end);
    let _ = write!(text, " \u{2026} ({more} more bytes)");
}

/// The completions shown: what they replace and which is selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The byte the text they replace starts at.
    pub start: usize,
    /// Every completion offered.
    pub items: Vec<Item>,
    /// The one selected, among those [`Self::shown`].
    pub selected: usize,
}

impl Completion {
    /// The completions fitting what is typed from `start` to `cursor` in
    /// `code` (the answer may be older than the last keystroke).
    pub fn shown<'a>(&'a self, code: &str, cursor: usize) -> Vec<&'a Item> {
        let typed = code.get(self.start..cursor).unwrap_or("");
        self.items
            .iter()
            .filter(|item| item.text.starts_with(typed))
            .collect()
    }
}

/// The process and its pipes.
#[derive(Debug)]
struct Process {
    child: Arc<Mutex<Child>>,
    stdin: Option<ChildStdin>,
}

impl Process {
    /// Starts `launch`'s console; what it says sent on `sender`, `wake`
    /// called after each.
    fn spawn(launch: &Launch, sender: Sender<Event>, wake: Wake) -> io::Result<Self> {
        let mut child = launch.command().spawn()?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let child = Arc::new(Mutex::new(child));
        let tail = Arc::new(Mutex::new(String::new()));
        let errors = {
            let tail = Arc::clone(&tail);
            thread::Builder::new()
                .name("binbun-console-stderr".to_owned())
                .spawn(move || {
                    let Some(mut stderr) = stderr else { return };
                    let mut buffer = [0_u8; 4096];
                    while let Ok(n @ 1..) = stderr.read(&mut buffer) {
                        let mut kept = tail.lock().unwrap_or_else(PoisonError::into_inner);
                        kept.push_str(&String::from_utf8_lossy(buffer.get(..n).unwrap_or(&[])));
                        if kept.len() > STDERR_TAIL {
                            let mut from = kept.len() - STDERR_TAIL;
                            while !kept.is_char_boundary(from) {
                                from += 1;
                            }
                            kept.drain(..from);
                        }
                    }
                })?
        };
        let reaped = Arc::clone(&child);
        thread::Builder::new()
            .name("binbun-console".to_owned())
            .spawn(move || {
                if let Some(stdout) = stdout {
                    for line in BufReader::new(stdout).lines() {
                        let Ok(line) = line else { break };
                        if let Some(event) = parse_event(&line) {
                            if sender.send(event).is_err() {
                                break;
                            }
                            wake();
                        }
                    }
                }
                let _ = errors.join();
                let code = loop {
                    let waited = reaped
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .try_wait();
                    match waited {
                        Ok(Some(status)) => break status.code(),
                        Ok(None) => thread::sleep(REAP),
                        Err(_) => break None,
                    }
                };
                let stderr =
                    std::mem::take(&mut *tail.lock().unwrap_or_else(PoisonError::into_inner));
                let _ = sender.send(Event::Exited { code, stderr });
                wake();
            })?;
        Ok(Self { child, stdin })
    }

    /// Sends `request` (a line of JSON).
    fn send(&mut self, request: &Value) {
        if let Some(stdin) = &mut self.stdin {
            let line = request.to_string() + "\n";
            if stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.flush())
                .is_err()
            {
                self.stdin = None;
            }
        }
    }

    /// Interrupts the cell running: SIGINT to the process (on Unix).
    fn interrupt(&mut self) {
        #[cfg(unix)]
        {
            let child = self.child.lock().unwrap_or_else(PoisonError::into_inner);
            let pid = rustix::process::Pid::from_child(&child);
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
        }
        #[cfg(not(unix))]
        self.send(&json!({"op": "interrupt"}));
    }
}

impl Drop for Process {
    /// Its input closed, which ends the console once its work in hand is
    /// done (jedi's warm-up writes parso's cache: killed halfway, a
    /// cache file cut short breaks completion in later consoles); killed
    /// if it has not ended within three seconds (a cell still running),
    /// on a thread of its own so nothing waits for it.
    fn drop(&mut self) {
        self.stdin = None;
        let child = Arc::clone(&self.child);
        let reap = move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let mut child = child.lock().unwrap_or_else(PoisonError::into_inner);
                if !matches!(child.try_wait(), Ok(None)) {
                    return;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                drop(child);
                thread::sleep(Duration::from_millis(50));
            }
        };
        if thread::Builder::new()
            .name("console-reap".to_owned())
            .spawn(reap)
            .is_err()
        {
            let _ = self
                .child
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .kill();
        }
    }
}

/// What a poll brought that the pane acts on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Polled {
    /// Something changed: draw again.
    pub changed: bool,
    /// The cell sent needs more lines: Enter breaks the line instead.
    pub incomplete: bool,
    /// The cell sent was taken: the input empties.
    pub accepted: bool,
}

/// The console.
#[derive(Debug)]
pub struct Console {
    launch: Launch,
    process: Option<Process>,
    events: Receiver<Event>,
    sender: Sender<Event>,
    wake: WakeDebug,
    /// What it is doing.
    pub status: Status,
    /// What ran and what it printed.
    pub transcript: Transcript,
    /// The cells run before.
    pub history: History,
    /// A problem keeping the history, said once.
    pub history_error: Option<String>,
    /// Whether it was ever ready (else its end says why it never was).
    ever_ready: bool,
    next: u64,
    /// The cells sent, by request, until they start.
    sent: BTreeMap<u64, String>,
    /// The cell running.
    running: Option<u64>,
    /// The completions shown.
    pub completion: Option<Completion>,
    /// The signature of the call typed.
    pub signature: Option<Signature>,
    /// The latest completion and signature requests, and the code each
    /// was asked for.
    asked: [(u64, String); 2],
}

/// A [`Wake`] that formats.
struct WakeDebug(Wake);

impl std::fmt::Debug for WakeDebug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Wake")
    }
}

impl Console {
    /// Starts the console of `launch`, its history kept at
    /// `history_path`; `wake` called when it has said something.
    pub fn start(launch: Launch, history_path: Option<PathBuf>, wake: Wake) -> Self {
        let (sender, events) = mpsc::channel();
        let mut console = Self {
            launch,
            process: None,
            events,
            sender,
            wake: WakeDebug(wake),
            status: Status::Starting,
            transcript: Transcript::default(),
            history: History::load(history_path),
            history_error: None,
            ever_ready: false,
            next: 0,
            sent: BTreeMap::new(),
            running: None,
            completion: None,
            signature: None,
            asked: [(0, String::new()), (0, String::new())],
        };
        console.spawn();
        console
    }

    /// What it was started with.
    pub fn launch(&self) -> &Launch {
        &self.launch
    }

    fn spawn(&mut self) {
        // A new channel: what the process before says no longer counts.
        let (sender, events) = mpsc::channel();
        self.sender = sender;
        self.events = events;
        self.ever_ready = false;
        self.running = None;
        self.sent.clear();
        self.status = Status::Starting;
        match Process::spawn(&self.launch, self.sender.clone(), Arc::clone(&self.wake.0)) {
            Ok(process) => self.process = Some(process),
            Err(error) => {
                self.process = None;
                let interpreter = &self.launch.interpreter;
                self.status = Status::Stopped(if error.kind() == io::ErrorKind::NotFound {
                    format!(
                        "No Python at {interpreter}. Set Up Python, in the banner above, makes \
                         binbun a Python of its own; or set python.interpreter to a Python 3.11 \
                         or newer with binbun installed (`python3 -m pip install binbun`)."
                    )
                } else {
                    format!("{interpreter} could not be started: {error}")
                });
            }
        }
    }

    /// Starts the console again (with `launch`, if given), the
    /// transcript kept.
    pub fn restart(&mut self, launch: Option<Launch>) {
        if let Some(launch) = launch {
            self.launch = launch;
        }
        self.process = None;
        self.transcript.push(LineKind::Note, "Restarted.");
        self.spawn();
    }

    /// Whether a cell is running.
    pub fn running(&self) -> bool {
        self.running.is_some()
    }

    /// Whether it takes cells.
    pub fn ready(&self) -> bool {
        matches!(self.status, Status::Ready { .. })
    }

    /// Sends cell `code` to run (the console says whether it is complete);
    /// whether it was sent.
    pub fn run(&mut self, code: &str) -> bool {
        let Some(process) = self.process.as_mut().filter(|_| self.ever_ready) else {
            return false;
        };
        self.next += 1;
        let id = self.next;
        self.sent.insert(id, code.to_owned());
        process.send(&json!({"op": "run", "id": id, "code": code}));
        true
    }

    /// Asks for the signature of the call at byte `cursor` of `code`, and
    /// with `complete` the completions there.
    pub fn ask(&mut self, code: &str, cursor: usize, complete: bool) {
        let Some(process) = self.process.as_mut().filter(|_| self.ever_ready) else {
            return;
        };
        let at = cp_of(code, cursor);
        for (slot, op) in [(1, "signature"), (0, "complete")] {
            if op == "complete" && !complete {
                continue;
            }
            self.next += 1;
            if let Some(asked) = self.asked.get_mut(slot) {
                *asked = (self.next, code.to_owned());
            }
            process.send(&json!({"op": op, "id": self.next, "code": code, "cursor": at}));
        }
    }

    /// Stops asking: the completions and signature dropped, late answers
    /// ignored.
    pub fn dismiss(&mut self) {
        self.completion = None;
        self.signature = None;
        self.next += 1;
        self.asked = [(self.next, String::new()), (self.next, String::new())];
    }

    /// Ctrl+C: the cell running interrupted; whether one was.
    pub fn interrupt(&mut self) -> bool {
        match (&mut self.process, self.running) {
            (Some(process), Some(_)) => {
                process.interrupt();
                true
            }
            _ => false,
        }
    }

    /// Takes what the console said.
    pub fn poll(&mut self) -> Polled {
        let mut polled = Polled::default();
        while let Ok(event) = self.events.try_recv() {
            polled.changed = true;
            self.take(event, &mut polled);
        }
        polled
    }

    fn take(&mut self, event: Event, polled: &mut Polled) {
        match event {
            Event::Ready {
                protocol,
                python,
                completer,
                database,
            } => {
                if protocol == PROTOCOL {
                    self.ever_ready = true;
                    self.status = Status::Ready {
                        python,
                        completer,
                        database,
                    };
                } else {
                    let interpreter = &self.launch.interpreter;
                    self.status = Status::Stopped(format!(
                        "binbun for {interpreter} speaks console protocol {protocol}, this \
                         binbun {PROTOCOL}: install the same version there \
                         (`{interpreter} -m pip install -U binbun`)."
                    ));
                    self.process = None;
                }
            }
            Event::Failed(message) => {
                self.status = Status::Stopped(format!("The console could not connect: {message}"));
            }
            Event::Incomplete(id) => {
                self.sent.remove(&id);
                polled.incomplete = true;
            }
            Event::Accepted(id) => {
                if let Some(code) = self.sent.get(&id)
                    && let Err(error) = self.history.push(code)
                    && self.history_error.is_none()
                {
                    self.history_error = Some(error);
                }
                polled.accepted = true;
            }
            Event::Started(id) => {
                self.running = Some(id.unwrap_or(0));
                if let Some(code) = id.and_then(|id| self.sent.remove(&id)) {
                    self.transcript.input(&code);
                }
            }
            Event::Output(stream, text) => {
                let kind = match stream {
                    Stream::Stdout => LineKind::Stdout,
                    Stream::Stderr => LineKind::Stderr,
                };
                self.transcript.push(kind, &text);
            }
            Event::Result(text) => self.transcript.push(LineKind::Result, &text),
            Event::Error(text) => self.transcript.push(LineKind::Error, text.trim_end()),
            Event::Done { step, note } => {
                self.running = None;
                if let Some(note) = note {
                    self.transcript.push(LineKind::Note, &note);
                }
                if let Some(step) = step {
                    self.transcript
                        .push(LineKind::Note, &format!("One undo step: {step}"));
                }
            }
            Event::Note(text) => self.transcript.push(LineKind::Note, &text),
            Event::Completions { id, start, items } => self.completions(id, start, items),
            Event::Signature { id, signature } => self.signature(id, signature),
            Event::Exited { code, stderr } => {
                self.running = None;
                self.process = None;
                if !matches!(self.status, Status::Stopped(_)) {
                    self.status = Status::Stopped(stopped_message(
                        &self.launch.interpreter,
                        self.ever_ready,
                        code,
                        &stderr,
                    ));
                }
                self.ever_ready = false;
            }
        }
    }

    fn completions(&mut self, id: u64, start: usize, items: Vec<Item>) {
        let [(asked, code), _] = &self.asked;
        if id != *asked {
            return;
        }
        self.completion = (!items.is_empty()).then(|| Completion {
            start: byte_of(code, start),
            items,
            selected: 0,
        });
    }

    fn signature(&mut self, id: u64, signature: Option<Signature>) {
        let [_, (asked, _)] = &self.asked;
        if id != *asked {
            return;
        }
        self.signature = signature;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::{
        Console, Event, Launch, LineKind, MAX_LINE, MAX_LINES, Status, Stream, Transcript, byte_of,
        cp_of, parse_event, stopped_message,
    };

    #[test]
    fn events_read_as_the_console_writes_them() {
        assert_eq!(
            parse_event(r#"{"event": "output", "stream": "stderr", "text": "x\n"}"#),
            Some(Event::Output(Stream::Stderr, "x\n".to_owned()))
        );
        let Some(Event::Completions { id, start, items }) = parse_event(
            r#"{"event": "completions", "id": 7, "start": 3, "items": [{"text": "functions", "kind": "instance"}]}"#,
        ) else {
            panic!("not completions");
        };
        assert_eq!((id, start, items[0].text.as_str()), (7, 3, "functions"));
        // The active parameter is sent in code points, kept in bytes.
        let Some(Event::Signature {
            id: 2,
            signature: Some(signature),
        }) = parse_event(
            r#"{"event": "signature", "id": 2, "label": "f(é: int, ü: str)", "active": [10, 16], "doc": "d"}"#,
        )
        else {
            panic!("not a signature");
        };
        assert_eq!(&signature.label[signature.active.unwrap()], "ü: str");
        assert_eq!(signature.doc, "d");
        assert_eq!(
            parse_event(r#"{"event": "signature", "id": 2, "label": null}"#),
            Some(Event::Signature {
                id: 2,
                signature: None
            })
        );
        assert_eq!(parse_event("not json"), None);
        assert_eq!(parse_event(r#"{"event": "incomplete"}"#), None);
    }

    #[test]
    fn code_points_and_bytes_convert_both_ways() {
        let text = "é = 'ü'.up";
        assert_eq!(byte_of(text, 2), 3);
        assert_eq!(cp_of(text, 3), 2);
        assert_eq!(byte_of(text, 99), text.len());
        assert_eq!(cp_of(text, text.len()), text.chars().count());
    }

    #[test]
    fn output_streams_into_its_line_and_the_transcript_is_capped() {
        let mut t = Transcript::default();
        t.input("for i in range(2):\n    print(i)\n");
        t.push(LineKind::Stdout, "a");
        t.push(LineKind::Stdout, "b\nc");
        t.push(LineKind::Stderr, "warn\n");
        t.push(LineKind::Stdout, "d\n");
        t.push(LineKind::Stdout, "50%\r100%\n");
        let shown: Vec<(LineKind, &str)> = t
            .lines()
            .iter()
            .map(|l| (l.kind, l.text.as_str()))
            .collect();
        assert_eq!(
            shown,
            [
                (LineKind::Input { first: true }, "for i in range(2):"),
                (LineKind::Input { first: false }, "    print(i)"),
                (LineKind::Stdout, "ab"),
                (LineKind::Stdout, "c"),
                (LineKind::Stderr, "warn"),
                (LineKind::Stdout, "d"),
                (LineKind::Stdout, "100%"),
            ]
        );
        // The input's colours are per line.
        let second = &t.lines()[1];
        assert!(
            second
                .spans
                .iter()
                .any(|(r, _)| &second.text[r.clone()] == "print")
        );

        let mut big = Transcript::default();
        big.push(LineKind::Stdout, &"x\n".repeat(MAX_LINES + 10));
        assert_eq!(big.lines().len(), MAX_LINES);
        assert_eq!(big.dropped(), 10);
        big.push(LineKind::Result, &"é".repeat(MAX_LINE));
        let last = &big.lines().back().unwrap().text;
        assert!(last.len() < MAX_LINE + 40 && last.ends_with("more bytes)"));
    }

    #[test]
    fn a_python_without_binbun_is_said_with_how_to_install_it() {
        let said = stopped_message(
            "/usr/bin/python3",
            false,
            Some(1),
            "/usr/bin/python3: Error while finding module specification for 'binbun.console' (ModuleNotFoundError: No module named 'binbun')\n",
        );
        assert!(said.contains("binbun is not installed for /usr/bin/python3"));
        assert!(said.contains("Set Up Python"));
        assert!(said.contains("-m pip install binbun"));
        let crashed = stopped_message(
            "python3",
            true,
            Some(1),
            "Traceback...\nRuntimeError: boom\n",
        );
        assert!(crashed.contains("RuntimeError: boom"), "{crashed}");
        assert!(!crashed.contains("pip install"), "{crashed}");
    }

    /// Polls `console` until `done` says so (or 20 s pass).
    fn poll_until(console: &mut Console, done: impl Fn(&Console) -> bool) {
        let start = Instant::now();
        while !done(console) && start.elapsed() < Duration::from_secs(20) {
            console.poll();
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn launch(interpreter: &str) -> Launch {
        Launch {
            interpreter: interpreter.to_owned(),
            socket: "/nonexistent/binbun.sock".into(),
            database: "/bin/true".into(),
        }
    }

    #[test]
    fn a_missing_interpreter_is_said_without_starting_anything() {
        let console = Console::start(launch("/nonexistent/python3"), None, Arc::new(|| {}));
        let Status::Stopped(said) = &console.status else {
            panic!("{:?}", console.status);
        };
        assert!(
            said.starts_with("No Python at /nonexistent/python3."),
            "{said}"
        );
        assert!(!console.ready());
    }

    #[test]
    fn an_interpreter_without_binbun_ends_with_the_install_hint() {
        // A real child stands in for a Python without binbun, as `python -m
        // binbun.console` there fails: a shell script, a batch file on
        // Windows (which runs only executables and batch files).
        let dir =
            std::env::temp_dir().join(format!("binbun-console-nobinbun-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(not(windows))]
        let (name, script) = (
            "python",
            "#!/bin/sh\necho \"$0: Error while finding module specification for 'binbun.console' (ModuleNotFoundError: No module named 'binbun')\" >&2\nexit 1\n",
        );
        #[cfg(windows)]
        let (name, script) = (
            "python.cmd",
            "@>&2 echo %~0: Error while finding module specification for 'binbun.console' (ModuleNotFoundError: No module named 'binbun')\r\n@exit /b 1\r\n",
        );
        let fake = dir.join(name);
        std::fs::write(&fake, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Another test's child, forked while the script was being written,
        // holds its write handle until it execs, and running the script then
        // fails with ETXTBSY. Once one run starts, nothing holds it open for
        // writing any more.
        for _ in 0..200 {
            match std::process::Command::new(&fake).output() {
                Err(error) if error.raw_os_error() == Some(26) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                _ => break,
            }
        }
        let interpreter = fake.display().to_string();
        let mut console = Console::start(launch(&interpreter), None, Arc::new(|| {}));
        poll_until(&mut console, |c| matches!(c.status, Status::Stopped(_)));
        let Status::Stopped(said) = &console.status else {
            panic!("{:?}", console.status);
        };
        assert!(
            said.contains(&format!("binbun is not installed for {interpreter}")),
            "{said}"
        );
        assert!(!console.run("1 + 1"), "a stopped console takes no cell");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
