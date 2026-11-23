//! `binbun.connect()`: a connection to a running GUI (or a script's
//! `db.serve()`), found through the user's
//! discovery files ([`Connection`]). Over the socket go the writes, the
//! transactions, undo and history, events, the GUI's cursor and
//! selection, the cheap reads and the change log; `mode="remote"` reads
//! through it only (`binbun._remote`), `mode="local"` opens the same binary
//! in process and follows the GUI's change log ([`Link::pull`], on each
//! history notification), its writes still made in the GUI.
//!
//! Writes made outside a transaction open the **run group** (labelled by
//! `connect(label=)` or the script's name), one undo step committed by
//! `db.commit()`, `db.close()` or the interpreter's exit; a transaction
//! begun while it is open commits it first, so that the transaction is a
//! step of its own. A connection lost or killed leaves its open group to
//! the server, which rolls it back.
//!
//! The console (`python -m binbun.console`) runs each cell as a run group
//! of its own ([`Connection::cell`]): labelled by the cell, opened by its
//! first write or transaction, the transactions begun in it joining it,
//! so that a cell is one undo step.
//!
//! [`Server`]: `db.serve()`, the same server the GUI runs, over a
//! database opened in process.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::Duration;

use binbun_protocol::base64;
use binbun_protocol::client::{Client, Pending, read_as};
use binbun_protocol::discovery;
use binbun_protocol::handshake::{
    AgentHello, DatabaseInfo, Initialize, PROTOCOL_VERSION, capability,
};
use binbun_protocol::messages::{
    Apply, Begin, Changes, ChangesSince, CommitResult, Cursor, Entries, Member, Presence, Settle,
    Span, Subscribe, method, notification,
};
use binbun_protocol::server::{ConnectedAgent, Server as Serving, Ui};
use binbun_protocol::{Applied, Fault, HistoryItem, Host, Owner, Write, sync, talk};
use binbun_session::journal::Origin;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyTuple;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::database::Db;
use crate::errors::{Raise, fault};
use crate::wait::wait_for;
use crate::writes::{HistoryEntry, script, settle};

/// The owner the local mirror of the GUI's open group writes as.
const MIRROR: Owner = Owner::MAX;

/// The capability a method needs (checked before it is sent).
fn needed(method: &str) -> Option<&'static str> {
    Some(match method {
        method::BEGIN | method::COMMIT | method::ROLLBACK | method::APPLY | method::SETTLE => {
            capability::WRITES
        }
        method::UNDO | method::REDO | method::HISTORY => capability::UNDO,
        method::SUBSCRIBE => capability::EVENTS,
        method::CURSOR | method::SELECTION => capability::UI,
        method::FUNCTIONS
        | method::ENTRIES
        | method::FUNCTION
        | method::CONTAINING
        | method::NAME
        | method::COMMENTS
        | method::BOOKMARKS => capability::READS,
        method::TEXT => capability::C_TEXT,
        method::CHANGES_SINCE => capability::SYNC,
        method::MEMBERS | method::PRESENCE => capability::MEMBERS,
        _ if method.starts_with("ir.") => capability::IR,
        _ if method.starts_with("threads.") => capability::THREADS,
        _ if method.starts_with("suggestions.") => capability::SUGGESTIONS,
        _ => return None,
    })
}

/// The group this client has open in the server.
#[derive(Debug, Default)]
struct Groups {
    /// How many deep (its transactions and the run group).
    depth: u32,
    /// Whether the outermost is the run group.
    run: bool,
}

/// What the run group is.
#[derive(Debug)]
struct Run {
    /// Its label.
    label: String,
    /// A console cell's: transactions join it instead of committing it
    /// first, and one opens it.
    cell: bool,
}

/// A database in process following the server's (`mode="local"`).
#[derive(Debug)]
struct Mirror {
    host: Arc<Host>,
    /// Held while taking the server's changes, so that two takes never
    /// interleave.
    pulling: Mutex<()>,
}

/// A connection, as the database objects share it.
#[derive(Debug)]
pub(crate) struct Link {
    client: Client,
    /// The run group's label and kind; its author.
    run: Mutex<Run>,
    author: Origin,
    groups: Mutex<Groups>,
    mirror: OnceLock<Mirror>,
    /// Requests sent (a call refused before sending is not one).
    sent: AtomicU64,
    closed: AtomicBool,
}

impl Link {
    fn groups(&self) -> MutexGuard<'_, Groups> {
        self.groups.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn run(&self) -> MutexGuard<'_, Run> {
        self.run.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens the run group.
    fn open_run(&self, py: Python<'_>) -> PyResult<()> {
        let label = self.run().label.clone();
        let author = self.author.clone();
        self.open(py, &label, &author)?;
        self.groups().run = true;
        Ok(())
    }

    /// Request `method` with `params`, waited for in slices (Ctrl-C stops
    /// the wait; the server goes on).
    ///
    /// # Errors
    ///
    /// The server lacks the capability (nothing sent); the server's fault;
    /// the connection lost; Ctrl-C.
    pub(crate) fn call(
        &self,
        py: Python<'_>,
        method: &str,
        params: impl Serialize,
    ) -> PyResult<Value> {
        self.call_within(py, method, params, None)
    }

    /// [`Self::call`], waiting up to `timeout` seconds (`None`: as long as
    /// it takes).
    ///
    /// # Errors
    ///
    /// As [`Self::call`]; the timeout ([`Raise::Timeout`]).
    fn call_within(
        &self,
        py: Python<'_>,
        method: &str,
        params: impl Serialize,
        timeout: Option<f64>,
    ) -> PyResult<Value> {
        if let Some(needed) = needed(method)
            && !self.client.has(needed)
        {
            return Err(Raise::Capability.err(
                py,
                format!("{method} needs the server's {needed:?} capability, which it lacks"),
            ));
        }
        let pending: Pending = self.client.send(method, params).map_err(|f| fault(py, f))?;
        self.sent.fetch_add(1, Ordering::Relaxed);
        wait_for(py, timeout, method, move |slice| pending.wait(slice), || {})?
            .map_err(|f| fault(py, f))
    }

    /// [`Self::call`], its result read as `R`.
    fn call_as<R: DeserializeOwned>(
        &self,
        py: Python<'_>,
        method: &str,
        params: impl Serialize,
    ) -> PyResult<R> {
        read_as(self.call(py, method, params)?).map_err(|f| fault(py, f))
    }

    /// The GUI's cursor, sent to `goto` first if given.
    ///
    /// # Errors
    ///
    /// The server has no window ([`Raise::Capability`]); the connection.
    pub(crate) fn cursor(&self, py: Python<'_>, goto: Option<u64>) -> PyResult<Option<u64>> {
        let cursor: Cursor = self.call_as(py, method::CURSOR, Cursor { address: goto })?;
        Ok(cursor.address)
    }

    /// The GUI's selection, `(start, end)`, if one is made.
    ///
    /// # Errors
    ///
    /// As [`Self::cursor`].
    pub(crate) fn selection(&self, py: Python<'_>) -> PyResult<Option<(u64, u64)>> {
        let span: Option<Span> = self.call_as(py, method::SELECTION, ())?;
        Ok(span.map(|span| (span.start, span.end)))
    }

    /// Opens a group in the server labelled `label`, by `author`; the
    /// mirror's too.
    fn open(&self, py: Python<'_>, label: &str, author: &Origin) -> PyResult<()> {
        self.call(
            py,
            method::BEGIN,
            Begin {
                label: label.to_owned(),
                author: Some(author.to_string()),
            },
        )?;
        self.groups().depth += 1;
        if let Some(mirror) = self.mirror.get() {
            mirror
                .host
                .begin(MIRROR, label, author.clone(), None)
                .map_err(|f| fault(py, f))?;
        }
        Ok(())
    }

    /// Opens a transaction labelled `label`, by `author`: the run group
    /// open is committed first; in a console cell, the transaction joins
    /// the cell's run group (opened by it if no write did).
    ///
    /// # Errors
    ///
    /// The server refuses (another's transaction open); the connection.
    pub(crate) fn begin(&self, py: Python<'_>, label: &str, author: &Origin) -> PyResult<()> {
        let (run, open) = {
            let groups = self.groups();
            (groups.run && groups.depth == 1, groups.depth > 0)
        };
        if self.run().cell {
            if !open {
                self.open_run(py)?;
            }
        } else if run {
            self.finish(py)?;
        }
        self.open(py, label, author)
    }

    /// The outermost group closed in the server: the mirror's dropped and
    /// what the server made taken instead.
    fn closed_outermost(&self, py: Python<'_>) -> PyResult<()> {
        if let Some(mirror) = self.mirror.get() {
            let _ = mirror.host.abandon(MIRROR);
            self.pull(py)?;
        }
        Ok(())
    }

    /// Commits the group open.
    ///
    /// # Errors
    ///
    /// None is open, or an inner one rolled it back; the connection.
    pub(crate) fn commit(&self, py: Python<'_>) -> PyResult<CommitResult> {
        let committed: Result<CommitResult, PyErr> = self.call_as(py, method::COMMIT, ());
        let outermost = {
            let mut groups = self.groups();
            groups.depth = groups.depth.saturating_sub(1);
            if groups.depth == 0 {
                groups.run = false;
            }
            groups.depth == 0
        };
        if outermost {
            self.closed_outermost(py)?;
        } else if let Some(mirror) = self.mirror.get() {
            let _ = mirror.host.commit(MIRROR);
        }
        committed
    }

    /// Rolls the group open back.
    ///
    /// # Errors
    ///
    /// None is open; the connection.
    pub(crate) fn rollback(&self, py: Python<'_>) -> PyResult<()> {
        let rolled = self.call(py, method::ROLLBACK, ());
        let outermost = {
            let mut groups = self.groups();
            groups.depth = groups.depth.saturating_sub(1);
            if groups.depth == 0 {
                groups.run = false;
            }
            groups.depth == 0
        };
        if let Some(mirror) = self.mirror.get() {
            let _ = mirror.host.rollback(MIRROR);
        }
        if outermost {
            self.closed_outermost(py)?;
        }
        rolled.map(drop)
    }

    /// Commits the run group, if it is open: the change it made.
    ///
    /// # Errors
    ///
    /// The server refuses; the connection.
    pub(crate) fn finish(&self, py: Python<'_>) -> PyResult<Option<HistoryItem>> {
        let run = {
            let groups = self.groups();
            groups.run && groups.depth == 1
        };
        if !run {
            return Ok(None);
        }
        Ok(self.commit(py)?.entry)
    }

    /// Makes `write` in the server: in the group open, else in the run
    /// group (opened by it); the mirror makes it too. What it did.
    ///
    /// # Errors
    ///
    /// The server refuses it (as its fault's exception); the connection.
    pub(crate) fn write(&self, py: Python<'_>, write: &Write) -> PyResult<Applied> {
        let open = self.groups().depth > 0;
        if !open {
            self.open_run(py)?;
        }
        let applied: Applied = self.call_as(
            py,
            method::APPLY,
            Apply {
                write: write.clone(),
            },
        )?;
        if let Some(mirror) = self.mirror.get() {
            mirror
                .host
                .apply(MIRROR, &self.author, None, write)
                .map_err(|f| fault(py, f))?;
        }
        Ok(applied)
    }

    /// Undoes (or with `redo`, makes again) this install's last change in
    /// the server; the mirror takes what it wrote.
    ///
    /// # Errors
    ///
    /// A group is open; the connection.
    pub(crate) fn replay(&self, py: Python<'_>, redo: bool) -> PyResult<Option<HistoryItem>> {
        let method = if redo { method::REDO } else { method::UNDO };
        let done: Option<HistoryItem> = self.call_as(py, method, ())?;
        self.pull(py)?;
        Ok(done)
    }

    /// The server's history, newest first.
    ///
    /// # Errors
    ///
    /// The connection.
    pub(crate) fn history(&self, py: Python<'_>) -> PyResult<Vec<HistoryItem>> {
        self.call_as(py, method::HISTORY, ())
    }

    /// Waits until no new analysis is under way in the server (then in
    /// the mirror, which analyses anew with the corrections it took).
    ///
    /// # Errors
    ///
    /// The new analysis stopped; the connection; Ctrl-C.
    pub(crate) fn settle(&self, py: Python<'_>) -> PyResult<()> {
        while !self.call_as::<bool>(py, method::SETTLE, Settle { timeout_ms: 1000 })? {}
        if let Some(mirror) = self.mirror.get() {
            self.pull(py)?;
            settle(py, &mirror.host)?;
        }
        Ok(())
    }

    /// Takes the server's changes the mirror lacks (none without one, or
    /// while the mirror's group is open).
    ///
    /// # Errors
    ///
    /// The connection; a change that does not read.
    pub(crate) fn pull(&self, py: Python<'_>) -> PyResult<()> {
        let Some(mirror) = self.mirror.get() else {
            return Ok(());
        };
        py.detach(|| self.take(mirror)).map_err(|f| fault(py, f))
    }

    /// [`Self::pull`] without the GIL (the follower's thread too).
    fn take(&self, mirror: &Mirror) -> Result<(), Fault> {
        let _pulling = mirror
            .pulling
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if mirror.host.holder().is_some() {
            return Ok(());
        }
        let session = mirror.host.lineage().session();
        let changes: Changes = self.client.call(
            method::CHANGES_SINCE,
            ChangesSince {
                frontier: sync::frontier(&session),
            },
        )?;
        if changes.changes.is_empty() {
            return Ok(());
        }
        // The mirror's chains are the server's: it takes those of what the
        // server's are of (once, before it holds any).
        session.follow(sync::of(&changes.binding)?);
        let signed = changes
            .changes
            .iter()
            .map(|change| sync::decode(change))
            .collect::<Result<Vec<_>, _>>()?;
        let applied = session.receive(signed);
        if applied.reanalyse {
            mirror
                .host
                .lineage()
                .reanalyse()
                .map_err(|error| Fault::session(&error, None))?;
        }
        Ok(())
    }

    /// Ends the connection: the run group committed first if `commit`.
    pub(crate) fn close(&self, py: Python<'_>, commit: bool) -> PyResult<()> {
        if self.closed.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        let finished = if commit {
            self.finish(py).map(drop)
        } else {
            Ok(())
        };
        self.client.close();
        finished
    }

    /// The server's identity key (hexadecimal), if it says.
    pub(crate) fn identity(&self) -> Option<String> {
        self.client.initialized().identity.clone()
    }
}

/// Follows the server's change log into `link`'s mirror: a pull on each
/// history notification, until the connection ends.
fn follow(link: &Arc<Link>) {
    let link = Arc::downgrade(link);
    let _ = thread::Builder::new()
        .name("binbun-follow".to_owned())
        .spawn(move || {
            loop {
                let Some(strong) = link.upgrade() else { break };
                if strong.closed.load(Ordering::Relaxed) || strong.client.is_lost() {
                    break;
                }
                let note = strong.client.notification(Duration::from_millis(200));
                if note.is_some_and(|note| note.method == notification::HISTORY)
                    && let Some(mirror) = strong.mirror.get()
                {
                    let _ = strong.take(mirror);
                }
            }
        });
}

/// A connection to a server (a running GUI, a script's `db.serve()`),
/// found by its discovery file: the one database open, or the one at
/// `target` (a path; `slice`: its slice, of a universal Mach-O file) or
/// with SHA-256 `sha256`, or the server at `socket`.
/// Made by `binbun.connect()`, which wraps it.
#[pyclass(frozen, weakref, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Connection {
    pub(crate) link: Arc<Link>,
}

#[pymethods]
impl Connection {
    #[new]
    #[expect(
        clippy::too_many_arguments,
        reason = "the constructor's keyword arguments"
    )]
    #[pyo3(signature = (target = None, *, slice = None, sha256 = None, socket = None, label = None, author = None, agent = None, agent_version = None, protocol = (1, PROTOCOL_VERSION)))]
    fn new(
        py: Python<'_>,
        target: Option<&str>,
        slice: Option<&str>,
        sha256: Option<&str>,
        socket: Option<PathBuf>,
        label: Option<String>,
        author: Option<&str>,
        agent: Option<&str>,
        agent_version: Option<&str>,
        protocol: (u32, u32),
    ) -> PyResult<Self> {
        let agent = agent.map(str::trim).filter(|name| !name.is_empty());
        let origin = match (author, agent) {
            (None, Some(_)) => Origin::Agent,
            (None, None) => script(py),
            (Some(author), _) => Origin::parse(author).ok_or_else(|| {
                PyValueError::new_err(format!(
                    "author {author:?}: user, agent, script:<name> or plugin:<id>"
                ))
            })?,
        };
        let label = label.unwrap_or_else(|| match (&origin, agent) {
            (_, Some(agent)) => agent.to_owned(),
            (Origin::Script(name), None) => name.clone(),
            _ => origin.to_string(),
        });
        let (socket, database) = if let Some(socket) = socket {
            // Its database the one named, if its discovery file says.
            let named = (target.is_some() || slice.is_some() || sha256.is_some())
                .then(|| {
                    let dir = discovery::dir().ok()?;
                    let servers: Vec<_> = discovery::servers(&dir)
                        .ok()?
                        .into_iter()
                        .filter(|server| server.socket == socket)
                        .collect();
                    (!servers.is_empty()).then_some(servers)
                })
                .flatten();
            match named {
                Some(servers) => {
                    let (_, id) = discovery::choose(&servers, target.map(Path::new), slice, sha256)
                        .map_err(|f| fault(py, f))?;
                    (socket, Some(id))
                }
                None => (socket, None),
            }
        } else {
            let dir = discovery::dir().map_err(|f| fault(py, f))?;
            let servers = discovery::servers(&dir).map_err(|f| fault(py, f))?;
            let (socket, id) = discovery::choose(&servers, target.map(Path::new), slice, sha256)
                .map_err(|f| fault(py, f))?;
            (socket, Some(id))
        };
        let initialize = Initialize {
            client: format!("binbun-py/{}", env!("CARGO_PKG_VERSION")),
            protocol: [protocol.0, protocol.1],
            api: [0, 5],
            database,
            author: Some(origin.to_string()),
            agent: agent.map(|name| AgentHello {
                name: name.to_owned(),
                version: agent_version.map(str::to_owned),
            }),
        };
        let client = py
            .detach(|| Client::connect(&socket, &initialize))
            .map_err(|f| fault(py, f))?;
        Ok(Self {
            link: Arc::new(Link {
                client,
                run: Mutex::new(Run { label, cell: false }),
                author: origin,
                groups: Mutex::new(Groups::default()),
                mirror: OnceLock::new(),
                sent: AtomicU64::new(0),
                closed: AtomicBool::new(false),
            }),
        })
    }

    /// The server: `binbun-gui/` and the app's version.
    #[getter]
    fn server(&self) -> String {
        self.link.client.initialized().server.clone()
    }

    /// The protocol version chosen.
    #[getter]
    fn protocol(&self) -> u32 {
        self.link.client.initialized().protocol
    }

    /// The server's engine version.
    #[getter]
    fn engine(&self) -> String {
        self.link.client.initialized().engine.clone()
    }

    /// What the server can do.
    #[getter]
    fn capabilities(&self) -> Vec<String> {
        self.link.client.initialized().capabilities.clone()
    }

    /// The server's identity key (hexadecimal): the key its changes are
    /// signed by, which a mention of its scripts names.
    #[getter]
    fn identity(&self) -> Option<String> {
        self.link.identity()
    }

    /// The database attached: `{"id", "path", "name", "sha256",
    /// "debug" (the debug file its analysis read), "stage", "revision"}`.
    #[getter]
    fn database(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let info: &DatabaseInfo = &self.link.client.initialized().database;
        to_python(py, &serde_json::to_value(info).unwrap_or_default())
    }

    /// The run group's label.
    #[getter]
    fn label(&self) -> String {
        self.link.run().label.clone()
    }

    /// Makes the run group a console cell's from now on: labelled `label`,
    /// opened by the first write or transaction, the transactions begun
    /// in it joining it (an inner one rolled back rolls the cell's writes
    /// back too, as nested transactions do), committed by `finish()`.
    /// The run group open, if any, keeps its label.
    fn cell(&self, label: String) {
        *self.link.run() = Run { label, cell: true };
    }

    /// Who makes the writes outside a transaction.
    #[getter]
    fn author(&self) -> String {
        self.link.author.to_string()
    }

    /// The agent's identity key (hexadecimal) if this connection is an
    /// agent's (`agent=`): the key its writes are signed by, which a
    /// mention of it names.
    #[getter]
    fn agent(&self) -> Option<String> {
        self.link.client.initialized().agent.clone()
    }

    /// Says where the agent's code works (its cursor in the GUI, as a
    /// collaborator's); nothing for a connection of no agent, or a server
    /// without it.
    fn presence(&self, py: Python<'_>, address: Option<u64>) -> PyResult<()> {
        let initialized = self.link.client.initialized();
        if initialized.agent.is_none()
            || !initialized
                .capabilities
                .iter()
                .any(|c| c == capability::MEMBERS)
        {
            return Ok(());
        }
        let client = &self.link.client;
        py.detach(|| {
            client
                .send(method::PRESENCE, Presence { address })
                .map(drop)
        })
        .map_err(|f| fault(py, f))
    }

    /// How many requests were sent (a call refused for a capability the
    /// server lacks sends none).
    #[getter]
    fn requests(&self) -> u64 {
        self.link.sent.load(Ordering::Relaxed)
    }

    /// Whether the connection is lost or closed.
    #[getter]
    fn closed(&self) -> bool {
        self.link.closed.load(Ordering::Relaxed) || self.link.client.is_lost()
    }

    /// Request `method` with `params` (JSON-able), its result as Python
    /// values. `CapabilityError` before sending when the server lacks
    /// what it needs; `TimeoutError` if no answer comes within `timeout`
    /// seconds (the server goes on).
    #[pyo3(signature = (method, params = None, *, timeout = None))]
    fn call(
        &self,
        py: Python<'_>,
        method: &str,
        params: Option<&Bound<'_, PyAny>>,
        timeout: Option<f64>,
    ) -> PyResult<Py<PyAny>> {
        let params = from_python(py, params)?;
        let value = self.link.call_within(py, method, params, timeout)?;
        to_python(py, &value)
    }

    /// Every function's entry, in order, in one request
    /// (`functions.entries`, packed).
    fn function_entries(&self, py: Python<'_>) -> PyResult<Vec<u64>> {
        let packed: Entries = self.link.call_as(py, method::ENTRIES, ())?;
        let bytes = base64::decode(&packed.entries).map_err(|why| Raise::Protocol.err(py, why))?;
        Ok(bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|&word| u64::from_le_bytes(word))
            .collect())
    }

    /// Makes `write` (a dict in the protocol's form, `{"write": "comment",
    /// "address": "0x…", "text": …}`): in the transaction open, else in
    /// the run group. What it did (`{"key": …, "corrected": …}`).
    fn write(&self, py: Python<'_>, write: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let write: Write = serde_json::from_value(from_python(py, Some(write))?)
            .map_err(|error| PyValueError::new_err(format!("not a write: {error}")))?;
        let applied = self.link.write(py, &write)?;
        to_python(py, &serde_json::to_value(applied).unwrap_or_default())
    }

    /// Opens a transaction (the run group committed first).
    #[pyo3(signature = (label, author = None))]
    fn begin(&self, py: Python<'_>, label: &str, author: Option<&str>) -> PyResult<()> {
        let author = match author {
            None => self.link.author.clone(),
            Some(author) => Origin::parse(author)
                .ok_or_else(|| PyValueError::new_err(format!("author {author:?}")))?,
        };
        self.link.begin(py, label, &author)
    }

    /// Commits the transaction open: the change made, whether the binary
    /// is analysed anew.
    fn commit(&self, py: Python<'_>) -> PyResult<(Option<HistoryEntry>, bool)> {
        let committed = self.link.commit(py)?;
        Ok((
            committed.entry.map(HistoryEntry::from),
            committed.reanalysing,
        ))
    }

    /// Rolls the transaction open back.
    fn rollback(&self, py: Python<'_>) -> PyResult<()> {
        self.link.rollback(py)
    }

    /// Commits the run group, if open: the change it made.
    fn finish(&self, py: Python<'_>) -> PyResult<Option<HistoryEntry>> {
        Ok(self.link.finish(py)?.map(HistoryEntry::from))
    }

    /// Undoes this install's last change in the server.
    fn undo(&self, py: Python<'_>) -> PyResult<Option<HistoryEntry>> {
        Ok(self.link.replay(py, false)?.map(HistoryEntry::from))
    }

    /// Makes the last change undone again.
    fn redo(&self, py: Python<'_>) -> PyResult<Option<HistoryEntry>> {
        Ok(self.link.replay(py, true)?.map(HistoryEntry::from))
    }

    /// The server's history, newest first.
    fn history(&self, py: Python<'_>) -> PyResult<Vec<HistoryEntry>> {
        Ok(self
            .link
            .history(py)?
            .into_iter()
            .map(HistoryEntry::from)
            .collect())
    }

    /// Waits until no new analysis is under way.
    fn settle(&self, py: Python<'_>) -> PyResult<()> {
        self.link.settle(py)
    }

    /// The next notification, `(method, params)`, if one comes within
    /// `timeout` seconds (after `call("events.subscribe")`).
    #[pyo3(signature = (timeout = 0.0))]
    fn notification(&self, py: Python<'_>, timeout: f64) -> PyResult<Option<(String, Py<PyAny>)>> {
        let timeout = Duration::try_from_secs_f64(timeout)
            .map_err(|_| PyValueError::new_err(format!("timeout must be >= 0, not {timeout}")))?;
        let client = &self.link.client;
        let note = wait_for(
            py,
            None,
            "a notification",
            {
                let mut left = timeout;
                move |slice| {
                    let wait = slice.min(left);
                    left = left.saturating_sub(wait);
                    match client.notification(wait) {
                        Some(note) => Some(Some(note)),
                        None if left.is_zero() => Some(None),
                        None => None,
                    }
                }
            },
            || {},
        )?;
        note.map(|note| Ok((note.method, to_python(py, &note.params)?)))
            .transpose()
    }

    /// Ends the connection; with `commit` (the default), the run group
    /// committed first. A transaction left open is rolled back by the
    /// server.
    #[pyo3(signature = (*, commit = true))]
    fn close(&self, py: Python<'_>, commit: bool) -> PyResult<()> {
        self.link.close(py, commit)
    }

    fn __repr__(&self) -> String {
        let initialized = self.link.client.initialized();
        format!(
            "<binbun.Connection {} on {}>",
            initialized.database.path, initialized.server
        )
    }
}

/// Makes `db` (opened in process) follow `connection`'s server: the
/// server's changes taken now and on each history notification, `db`'s
/// writes made in the server.
///
/// # Errors
///
/// It follows one already; the connection.
pub(crate) fn follow_with(py: Python<'_>, db: &Arc<Db>, connection: &Connection) -> PyResult<()> {
    let link = Arc::clone(&connection.link);
    let host = db.host(py)?;
    link.mirror
        .set(Mirror {
            host,
            pulling: Mutex::new(()),
        })
        .map_err(|_| {
            Raise::Binbun.err(py, "this connection has a database following it already")
        })?;
    // The server's mentions, and the connection's agent's, are this
    // copy's to tell too.
    let session = db.session(py)?;
    for key in [link.identity(), link.client.initialized().agent.clone()]
        .iter()
        .flatten()
        .filter_map(|key| talk::parse_key(key).ok())
    {
        session.answer_for(key);
    }
    link.call(
        py,
        method::SUBSCRIBE,
        Subscribe {
            kinds: vec![notification::HISTORY.to_owned()],
        },
    )?;
    link.pull(py)?;
    db.follow(Arc::clone(&link));
    follow(&link);
    Ok(())
}

/// `value` (any JSON-able Python value) as JSON.
pub(crate) fn from_python(py: Python<'_>, value: Option<&Bound<'_, PyAny>>) -> PyResult<Value> {
    let Some(value) = value.filter(|value| !value.is_none()) else {
        return Ok(Value::Null);
    };
    let text: String = py
        .import("json")?
        .call_method1("dumps", (value,))?
        .extract()?;
    serde_json::from_str(&text).map_err(|error| PyValueError::new_err(error.to_string()))
}

/// `value` as Python values.
pub(crate) fn to_python(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    Ok(py
        .import("json")?
        .call_method1("loads", (value.to_string(),))?
        .unbind())
}

/// What a query result is cited as when given as evidence (its `_cite`):
/// `reference` as `binbun._talk` sends it.
pub(crate) fn cited(py: Python<'_>, reference: &talk::EvidenceRefData) -> PyResult<Py<PyAny>> {
    let value = serde_json::to_value(reference)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    to_python(py, &value)
}

/// `db.serve()`: a server over a database opened in process, as the GUI
/// runs one (its socket in `$XDG_RUNTIME_DIR/binbun/`, on Windows a named
/// pipe told in `%LOCALAPPDATA%\binbun\run\`; found by
/// `binbun.connect()`), until closed; with `ui=True`, standing in for a
/// GUI's window too: a cursor and a selection its clients read with
/// `ui.cursor` and `ui.selection` (a client's jump moves the cursor).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Server {
    serving: Mutex<Option<Serving>>,
    socket: PathBuf,
    ui: Option<Arc<Shown>>,
}

/// A server's window as plain data: its cursor and selection, the agents
/// connected and where each one's code works.
#[derive(Debug, Default)]
struct Shown {
    cursor: Mutex<Option<u64>>,
    selection: Mutex<Option<(u64, u64)>>,
    agents: Mutex<BTreeMap<u64, (ConnectedAgent, Option<u64>)>>,
}

impl Shown {
    fn agents(&self) -> MutexGuard<'_, BTreeMap<u64, (ConnectedAgent, Option<u64>)>> {
        self.agents.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Ui for Shown {
    fn cursor(&self) -> Option<u64> {
        *self.cursor.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn goto(&self, address: u64) {
        *self.cursor.lock().unwrap_or_else(PoisonError::into_inner) = Some(address);
    }

    fn selection(&self) -> Option<(u64, u64)> {
        *self
            .selection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn agent(&self, connection: u64, agent: Option<ConnectedAgent>) {
        let mut agents = self.agents();
        match agent {
            Some(agent) => {
                agents.insert(connection, (agent, None));
            }
            None => {
                agents.remove(&connection);
            }
        }
    }

    fn agent_at(&self, connection: u64, address: Option<u64>) {
        if let Some((_, at)) = self.agents().get_mut(&connection) {
            *at = address;
        }
    }

    fn people(&self) -> Vec<Member> {
        Vec::new()
    }
}

impl Server {
    /// Serves `db`, with a window's cursor and selection if `ui`.
    ///
    /// # Errors
    ///
    /// No `XDG_RUNTIME_DIR` (on Windows, nor `LOCALAPPDATA`); its `binbun`
    /// directory is open to others; the socket cannot be bound.
    pub(crate) fn start(py: Python<'_>, db: &Arc<Db>, ui: bool) -> PyResult<Self> {
        let host = db.host(py)?;
        let dir = discovery::dir().map_err(|f| fault(py, f))?;
        let serving = Serving::start(&dir, &format!("binbun-py/{}", env!("CARGO_PKG_VERSION")))
            .map_err(|f| fault(py, f))?;
        let ui = ui.then(|| Arc::new(Shown::default()));
        serving
            .add(
                &db.path,
                host,
                ui.as_ref().map(|ui| Arc::clone(ui) as Arc<dyn Ui>),
            )
            .map_err(|f| fault(py, f))?;
        Ok(Self {
            socket: serving.socket().to_owned(),
            serving: Mutex::new(Some(serving)),
            ui,
        })
    }

    /// Its window, or why it has none.
    fn shown(&self) -> PyResult<&Shown> {
        self.ui
            .as_deref()
            .ok_or_else(|| PyValueError::new_err("this server has no window: serve(ui=True)"))
    }
}

#[pymethods]
impl Server {
    /// Its socket.
    #[getter]
    fn socket(&self) -> String {
        self.socket.display().to_string()
    }

    /// The cursor its clients read (`ui.cursor`; `db.jump()` moves it);
    /// `serve(ui=True)` only.
    #[getter]
    fn get_cursor(&self) -> PyResult<Option<u64>> {
        Ok(self.shown()?.cursor())
    }

    #[setter]
    fn set_cursor(&self, address: Option<u64>) -> PyResult<()> {
        *self
            .shown()?
            .cursor
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = address;
        Ok(())
    }

    /// The selection its clients read (`ui.selection`): `(start, end)`;
    /// `serve(ui=True)` only.
    #[getter]
    fn get_selection(&self) -> PyResult<Option<(u64, u64)>> {
        Ok(self.shown()?.selection())
    }

    #[setter]
    fn set_selection(&self, span: Option<(u64, u64)>) -> PyResult<()> {
        *self
            .shown()?
            .selection
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = span;
        Ok(())
    }

    /// The agents connected, as its window would show them: each one's
    /// `name`, `key` (hexadecimal), `version` and `address` (where its
    /// code works, if it said); `serve(ui=True)` only.
    #[getter]
    fn agents(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let agents: Vec<Value> = self
            .shown()?
            .agents()
            .values()
            .map(|(agent, address)| {
                serde_json::json!({
                    "name": agent.name,
                    "key": agent.key.to_string(),
                    "version": agent.version,
                    "address": address,
                })
            })
            .collect();
        to_python(py, &Value::Array(agents))
    }

    /// Stops serving: the socket and discovery file removed; connections
    /// end.
    fn close(&self, py: Python<'_>) {
        let taken = self
            .serving
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        py.detach(|| drop(taken));
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_exc))]
    fn __exit__(&self, py: Python<'_>, _exc: &Bound<'_, PyTuple>) {
        self.close(py);
    }

    fn __repr__(&self) -> String {
        format!("<binbun.Server {}>", self.socket.display())
    }
}
