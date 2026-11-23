//! `db.events`: the database's events, pulled (no Python callback ever runs
//! on a binbun thread): stages reached, warming progress, what an edit or
//! a stage changed, failures, edits that no longer resolve, changes
//! entering the history, a new analysis swapped in, conversation (threads
//! and suggestions written or taken) and posts mentioning this identity.
//! The same classes carry a server's notifications (`binbun.connect()`,
//! [`_event`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, TryLockError};

use binbun_protocol::HistoryItem;
use binbun_protocol::messages::{
    ChangedNote, HistoryNote, ReanalysedNote, StageNote, notification,
};
use binbun_protocol::talk::{MentionedNote, ThreadNote, id_text, notification as talk_note};
use binbun_session::{Event, Stage};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyTuple;
use serde::de::DeserializeOwned;

use crate::database::{Db, Revision, revision, stage_object, stage_of};
use crate::errors::class;
use crate::functions::Function;
use crate::remote::from_python;
use crate::wait::wait_for;
use crate::writes::{HistoryEntry, author};

/// The analysis reached a stage.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct StageReached {
    stage: Stage,
}

#[pymethods]
impl StageReached {
    /// The stage: a `Stage`.
    #[getter]
    fn stage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        stage_object(py, self.stage)
    }

    fn __repr__(&self) -> String {
        let name = format!("{:?}", self.stage).to_ascii_uppercase();
        format!("StageReached(Stage.{name})")
    }
}

/// The warming went on: `warmed` of `total` functions' interfaces found.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Progress {
    /// Functions warmed.
    warmed: usize,
    /// Functions to warm.
    total: usize,
}

#[pymethods]
impl Progress {
    fn __repr__(&self) -> String {
        format!("Progress({}/{})", self.warmed, self.total)
    }
}

/// An edit or a stage changed documents or listing lines.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Changed {
    /// The revision after it (`None` from a server, which does not say).
    #[pyo3(get)]
    revision: Option<Revision>,
    /// The functions whose C reads differently now (`binbun.Function`s;
    /// from a server, `binbun.RemoteFunction`s).
    functions: Vec<Py<PyAny>>,
    /// The address ranges whose listing lines read differently:
    /// `(start, end)` pairs.
    #[pyo3(get)]
    listing_ranges: Vec<(u64, u64)>,
}

#[pymethods]
impl Changed {
    fn __repr__(&self) -> String {
        format!(
            "Changed({} functions, {} ranges)",
            self.functions.len(),
            self.listing_ranges.len()
        )
    }

    /// The functions whose C reads differently now.
    #[getter]
    fn functions(&self, py: Python<'_>) -> Vec<Py<PyAny>> {
        self.functions.iter().map(|f| f.clone_ref(py)).collect()
    }
}

/// Opening failed, or an edit could not be saved.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Failed {
    /// Why.
    message: String,
}

#[pymethods]
impl Failed {
    fn __repr__(&self) -> String {
        format!("Failed({:?})", self.message)
    }
}

/// Edits found not to resolve (their function or address gone).
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Unresolved {
    /// Each edit and why, as text.
    edits: Vec<String>,
}

#[pymethods]
impl Unresolved {
    fn __repr__(&self) -> String {
        format!("Unresolved({} edits)", self.edits.len())
    }
}

/// Changes entered the history (made, undone, made again): newest first.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct HistoryChanged {
    /// The changes.
    entries: Vec<HistoryEntry>,
}

#[pymethods]
impl HistoryChanged {
    fn __repr__(&self) -> String {
        format!("HistoryChanged({} changes)", self.entries.len())
    }
}

/// The binary analysed anew (corrections, debug information fetched)
/// took the place of the analysis before: handles find their functions
/// again by entry.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Reanalysed {
    /// The revision of the new analysis.
    revision: Revision,
    /// How many functions of the analysis before the new one has too
    /// (`None` from a server, which does not say).
    kept: Option<usize>,
}

#[pymethods]
impl Reanalysed {
    fn __repr__(&self) -> String {
        format!(
            "Reanalysed(Revision(analysis={}, edits={}))",
            self.revision.analysis, self.revision.edits
        )
    }
}

/// Conversation came, made here or taken from elsewhere: threads opened,
/// posted to, resolved; posts edited or deleted; suggestions made or
/// decided (`db.threads.get(id)`, `db.suggestions.get(id)`).
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct ThreadChanged {
    /// The threads with something new, by id.
    threads: Vec<String>,
    /// The suggestions made or decided, by id.
    suggestions: Vec<String>,
}

#[pymethods]
impl ThreadChanged {
    fn __repr__(&self) -> String {
        format!(
            "ThreadChanged({} threads, {} suggestions)",
            self.threads.len(),
            self.suggestions.len()
        )
    }
}

/// A new post mentions this database's identity: the person, or one of
/// its scripts or agents (`mention.agent`: `"script:helper"`, whom a
/// script compares with its own author).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Mentioned {
    /// The post's thread, by id.
    #[pyo3(get)]
    thread: String,
    /// The post, by id.
    #[pyo3(get)]
    post: String,
    /// Who posted it: their identity key (hexadecimal).
    by_key: String,
    /// As whom they posted it (`user`, `script:<name>`, `agent`).
    by: String,
    /// The identity mentioned (hexadecimal).
    key: String,
    /// Its script or agent mentioned; `None`: the person.
    agent: Option<String>,
    /// What the post says.
    #[pyo3(get)]
    body: String,
}

#[pymethods]
impl Mentioned {
    fn __repr__(&self) -> String {
        format!(
            "Mentioned({} by {}, in {})",
            self.agent.as_deref().unwrap_or("the person"),
            self.by,
            self.thread
        )
    }

    /// Who posted it: a `binbun.Author`.
    #[getter]
    fn author<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        author(py, &self.by_key, &self.by)
    }

    /// Whom it mentions: a `binbun.Mention` (this identity's `key`, and its
    /// script or agent, `agent`; `None`: the person).
    #[getter]
    fn mention<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let kwargs = pyo3::types::PyDict::new(py);
        kwargs.set_item("key", &self.key)?;
        kwargs.set_item("agent", &self.agent)?;
        py.import("binbun._talk")?
            .getattr("Mention")?
            .call((), Some(&kwargs))
    }
}

/// The events of a database ([`EventQueue`]s).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Events {
    db: Arc<Db>,
}

impl Events {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Events {
    /// A queue of every event from now on (of `kinds`, event classes, if
    /// given); the first is the stage reached.
    #[pyo3(signature = (*kinds))]
    fn subscribe(&self, py: Python<'_>, kinds: &Bound<'_, PyTuple>) -> PyResult<EventQueue> {
        let host = self.db.host(py)?;
        Ok(EventQueue {
            db: Arc::clone(&self.db),
            received: Mutex::new(Some(host.lineage().subscribe(None))),
            closed: AtomicBool::new(false),
            kinds: kinds.iter().map(Bound::unbind).collect(),
        })
    }
}

/// Events as they come, pulled with `get` or by iterating (which ends
/// when the database closes or the queue is closed).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct EventQueue {
    db: Arc<Db>,
    received: Mutex<Option<Receiver<Event>>>,
    closed: AtomicBool,
    kinds: Vec<Py<PyAny>>,
}

/// What a wait on the queue came to.
enum Pulled {
    Event(Event),
    Gone,
}

impl EventQueue {
    /// The next event wanted, as a Python object, waiting up to `timeout`
    /// (`None`: as long as it takes); `Ok(None)` when the queue is closed
    /// or the database gone, or (with a timeout) none came.
    fn next_event<'py>(
        &self,
        py: Python<'py>,
        timeout: Option<f64>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        loop {
            // Never blocks with the GIL held: another thread waiting on
            // the queue releases the GIL and would need it back.
            let mut guard = match self.received.try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    return Err(PyRuntimeError::new_err(
                        "another thread is reading this event queue",
                    ));
                }
            };
            let Some(received) = guard.as_mut() else {
                return Ok(None);
            };
            let closed = &self.closed;
            let waited = wait_for(
                py,
                timeout,
                "waiting for an event",
                move |slice| {
                    if closed.load(Ordering::Relaxed) {
                        return Some(Pulled::Gone);
                    }
                    match received.recv_timeout(slice) {
                        Ok(event) => Some(Pulled::Event(event)),
                        Err(RecvTimeoutError::Timeout) => None,
                        Err(RecvTimeoutError::Disconnected) => Some(Pulled::Gone),
                    }
                },
                || {},
            );
            let event = match waited {
                Ok(Pulled::Event(event)) => event,
                Ok(Pulled::Gone) => {
                    *guard = None;
                    return Ok(None);
                }
                Err(error) if timeout.is_some() && is_timeout(py, &error) => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            drop(guard);
            let Some(object) = self.object(py, event)? else {
                continue;
            };
            if self.kinds.is_empty()
                || self
                    .kinds
                    .iter()
                    .any(|kind| object.is_instance(kind.bind(py)).unwrap_or(false))
            {
                return Ok(Some(object));
            }
        }
    }

    /// `event` as a Python event, if it is one a script sees.
    fn object<'py>(&self, py: Python<'py>, event: Event) -> PyResult<Option<Bound<'py, PyAny>>> {
        let object = match event {
            Event::Stage(stage) => Bound::new(py, StageReached { stage })?.into_any(),
            Event::Progress { warmed, total } => {
                Bound::new(py, Progress { warmed, total })?.into_any()
            }
            Event::Changed(change) => {
                let session = self.db.session(py)?;
                let functions = change
                    .documents
                    .iter()
                    .filter_map(|&id| session.database()?.function(id))
                    .map(|f| {
                        Ok(Bound::new(py, Function::new(&self.db, f.entry))?
                            .into_any()
                            .unbind())
                    })
                    .collect::<PyResult<_>>()?;
                Bound::new(
                    py,
                    Changed {
                        revision: Some(revision(session.revision())),
                        functions,
                        listing_ranges: change.listing.iter().map(|r| (r.start, r.end)).collect(),
                    },
                )?
                .into_any()
            }
            Event::Failed(message) => Bound::new(py, Failed { message })?.into_any(),
            Event::Unresolved(unresolved) => Bound::new(
                py,
                Unresolved {
                    edits: unresolved
                        .iter()
                        .map(|u| format!("{}: {}", u.edit, u.why))
                        .collect(),
                },
            )?
            .into_any(),
            Event::History(entries) => Bound::new(
                py,
                HistoryChanged {
                    entries: entries
                        .iter()
                        .map(|entry| HistoryEntry::from(HistoryItem::of(entry, &[])))
                        .collect(),
                },
            )?
            .into_any(),
            Event::Reanalysed {
                revision: now,
                functions,
            } => Bound::new(
                py,
                Reanalysed {
                    revision: revision(now),
                    kept: Some(functions.len()),
                },
            )?
            .into_any(),
            Event::Document { .. }
            | Event::Answer { .. }
            | Event::Symbols(_)
            | Event::Conflicts(_)
            | Event::Bookmarks => return Ok(None),
            Event::Thread(talked) => Bound::new(
                py,
                ThreadChanged {
                    threads: talked.threads.iter().copied().map(id_text).collect(),
                    suggestions: talked.suggestions.iter().copied().map(id_text).collect(),
                },
            )?
            .into_any(),
            Event::Mentioned(mentioned) => Bound::new(
                py,
                Mentioned {
                    thread: id_text(mentioned.thread),
                    post: id_text(mentioned.post),
                    by_key: mentioned.by.key.to_string(),
                    by: mentioned.by.origin.to_string(),
                    key: mentioned.mention.key.to_string(),
                    agent: mentioned.mention.agent.clone(),
                    body: mentioned.body.clone(),
                },
            )?
            .into_any(),
        };
        Ok(Some(object))
    }
}

/// Whether `error` is binbun's `TimeoutError`.
fn is_timeout(py: Python<'_>, error: &PyErr) -> bool {
    class(py, "binbun._errors", "TimeoutError").is_ok_and(|class| error.is_instance(py, &class))
}

/// `params` read as `T`.
fn note<T: DeserializeOwned>(py: Python<'_>, params: &Bound<'_, PyAny>) -> PyResult<T> {
    serde_json::from_value(from_python(py, Some(params))?)
        .map_err(|error| PyValueError::new_err(format!("not a notification: {error}")))
}

/// A server's notification `method` with `params` as the event a script
/// in process gets (`binbun.RemoteEvents`): `Changed`'s functions are
/// `functions` (the caller's handles of the functions the notification
/// names, in order); `None` for a notification no event class carries.
///
/// # Errors
///
/// The parameters are not the notification's.
#[pyfunction]
#[pyo3(signature = (method, params, functions = Vec::new()))]
pub(crate) fn _event(
    py: Python<'_>,
    method: &str,
    params: &Bound<'_, PyAny>,
    functions: Vec<Py<PyAny>>,
) -> PyResult<Option<Py<PyAny>>> {
    let object = match method {
        notification::STAGE => {
            let stage: StageNote = note(py, params)?;
            let stage = stage_of(stage.stage)?;
            Bound::new(py, StageReached { stage })?.into_any()
        }
        notification::CHANGED => {
            let changed: ChangedNote = note(py, params)?;
            Bound::new(
                py,
                Changed {
                    revision: None,
                    functions,
                    listing_ranges: changed.listing.iter().map(|r| (r.start, r.end)).collect(),
                },
            )?
            .into_any()
        }
        notification::HISTORY => {
            let history: HistoryNote = note(py, params)?;
            Bound::new(
                py,
                HistoryChanged {
                    entries: history
                        .entries
                        .into_iter()
                        .map(HistoryEntry::from)
                        .collect(),
                },
            )?
            .into_any()
        }
        notification::REANALYSED => {
            let reanalysed: ReanalysedNote = note(py, params)?;
            Bound::new(
                py,
                Reanalysed {
                    revision: Revision {
                        analysis: reanalysed.revision.analysis,
                        edits: reanalysed.revision.edits,
                    },
                    kept: None,
                },
            )?
            .into_any()
        }
        talk_note::THREAD => {
            let thread: ThreadNote = note(py, params)?;
            Bound::new(
                py,
                ThreadChanged {
                    threads: thread.threads,
                    suggestions: thread.suggestions,
                },
            )?
            .into_any()
        }
        talk_note::MENTIONED => {
            let mentioned: MentionedNote = note(py, params)?;
            Bound::new(
                py,
                Mentioned {
                    thread: mentioned.thread,
                    post: mentioned.post,
                    by_key: mentioned.by.key,
                    by: mentioned.by.author,
                    key: mentioned.mention.key.unwrap_or_default(),
                    agent: mentioned.mention.agent,
                    body: mentioned.body,
                },
            )?
            .into_any()
        }
        _ => return Ok(None),
    };
    Ok(Some(object.unbind()))
}

#[pymethods]
impl EventQueue {
    /// The next event, waiting up to `timeout` seconds (`None`: until one
    /// comes); `None` if none came, or the queue is closed.
    #[pyo3(signature = (timeout = None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        timeout: Option<f64>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.next_event(py, timeout)
    }

    /// Stops the queue: no more events.
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __next__<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.next_event(py, None)
    }
}
