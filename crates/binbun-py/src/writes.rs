//! Writes: every setter goes through
//! [`write`] to the database's host ([`binbun_protocol::Host`]): inside a
//! transaction of the calling thread ([`Transaction`]: one undo step,
//! rolled back on an exception, corrections analysed anew once at
//! commit), else as an undo step of its own; authored `script:<argv0>`
//! unless a transaction says otherwise; recorded instead while the
//! calling thread drafts a suggestion ([`record`]). Undo, redo and the
//! history ([`HistoryEntry`]); the types (`db.types`, [`Types`]) and the
//! corrections of recovery (`db.corrections`, [`Corrections`]).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use binbun::corrections::{Bounds, Item};
use binbun_protocol::{Applied, Correction, Fault, HistoryItem, Host, Member, Owner, Write};
use binbun_session::journal::Origin;
use binbun_session::{Error, Session, StructLayout as Layout, Typed};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::database::{Address, Db, Entry};
use crate::document::CVariable;
use crate::errors::{Raise, fault, named};
use crate::functions::Function;
use crate::remote::{from_python, to_python};
use crate::wait::wait_for;

/// The next thread's number as an owner of transactions.
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// This thread's number as an owner of transactions.
    static OWNER: Owner = NEXT_OWNER.fetch_add(1, Ordering::Relaxed);
}

/// The calling thread, as an owner of transactions.
pub(crate) fn owner() -> Owner {
    OWNER.with(|owner| *owner)
}

/// `script:<the script's file name>` (`sys.argv[0]`; run with `python -m`,
/// the module's package; `python` if none).
pub(crate) fn script(py: Python<'_>) -> Origin {
    let argv0: String = py
        .import("sys")
        .and_then(|sys| sys.getattr("argv"))
        .and_then(|argv| argv.get_item(0))
        .and_then(|first| first.extract())
        .unwrap_or_default();
    let path = Path::new(&argv0);
    let path = if path.file_name().is_some_and(|name| name == "__main__.py") {
        path.parent().unwrap_or(path)
    } else {
        path
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("python");
    Origin::Script(name.to_owned())
}

/// The origin `author` names (`user`, `script:<name>`, `plugin:<id>`,
/// `agent`); the script's if `None`.
///
/// # Errors
///
/// It names none.
fn origin(py: Python<'_>, author: Option<&str>) -> PyResult<Origin> {
    match author {
        None => Ok(script(py)),
        Some(author) => Origin::parse(author).ok_or_else(|| {
            PyValueError::new_err(format!(
                "author {author:?}: user, agent, script:<name> or plugin:<id>"
            ))
        }),
    }
}

/// Makes `write` in `db` for the calling thread; outside a transaction, a
/// correction waits for the new analysis to be swapped in. What it did.
/// While the thread drafts a suggestion, the write is recorded instead,
/// once the host drafts it beside those recorded before.
///
/// # Errors
///
/// The host refuses it (as its fault's exception); Ctrl-C while waiting.
pub(crate) fn write(py: Python<'_>, db: &Arc<Db>, write: &Write) -> PyResult<Applied> {
    if let Some(applied) = record_write(py, db, write)? {
        return Ok(applied);
    }
    if let Some(link) = db.link() {
        return link.write(py, write);
    }
    let host = db.host(py)?;
    let origin = script(py);
    let owner = owner();
    let applied = py
        .detach(|| host.apply(owner, &origin, None, write))
        .map_err(|f| fault(py, f))?;
    if applied.corrected {
        settle(py, &host)?;
    }
    Ok(applied)
}

/// The writes recorded by each thread drafting a suggestion of `db`.
fn recordings(db: &Db) -> MutexGuard<'_, HashMap<Owner, Vec<Write>>> {
    db.recording.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Records `write` if the calling thread drafts a suggestion of `db`: what
/// it would do, drafted after those recorded before (none written).
///
/// # Errors
///
/// The host refuses it, after those recorded (then it is not recorded).
fn record_write(py: Python<'_>, db: &Arc<Db>, write: &Write) -> PyResult<Option<Applied>> {
    let owner = owner();
    let Some(mut writes) = recordings(db).get(&owner).cloned() else {
        return Ok(None);
    };
    writes.push(write.clone());
    let host = db.host(py)?;
    let (mut applied, _) = py
        .detach(|| host.draft(owner, &writes))
        .map_err(|f| fault(py, f))?;
    if let Some(recorded) = recordings(db).get_mut(&owner) {
        recorded.push(write.clone());
    }
    Ok(Some(applied.pop().unwrap_or_default()))
}

/// Whether the calling thread drafts a suggestion of `db`.
pub(crate) fn recording(db: &Db) -> bool {
    recordings(db).contains_key(&owner())
}

/// The error of `what` attempted while the calling thread drafts a
/// suggestion.
fn drafting(py: Python<'_>, what: &str) -> PyErr {
    Raise::Transaction.err(
        py,
        format!("{what} inside a suggestion: its block records writes, accepted as one change"),
    )
}

/// Records the calling thread's writes of `db` from now on instead of
/// making them.
///
/// # Errors
///
/// It records already.
pub(crate) fn record(py: Python<'_>, db: &Db) -> PyResult<()> {
    let mut recordings = recordings(db);
    if recordings.contains_key(&owner()) {
        return Err(drafting(py, "a suggestion"));
    }
    recordings.insert(owner(), Vec::new());
    Ok(())
}

/// Stops recording the calling thread's writes of `db`: those recorded,
/// as `edits.apply` states them (a list of dicts; empty if none).
///
/// # Errors
///
/// A write does not convert (never).
pub(crate) fn recorded(py: Python<'_>, db: &Db) -> PyResult<Py<PyAny>> {
    let writes = recordings(db).remove(&owner()).unwrap_or_default();
    let value =
        serde_json::to_value(&writes).map_err(|error| PyValueError::new_err(error.to_string()))?;
    to_python(py, &value)
}

/// Waits (Ctrl-C stops the wait, not the analysis) until every new
/// analysis under way is swapped in.
///
/// # Errors
///
/// The new analysis stopped; Ctrl-C.
pub(crate) fn settle(py: Python<'_>, host: &Arc<Host>) -> PyResult<()> {
    wait_for(
        py,
        None,
        "waiting for the new analysis",
        |slice| match host.settle(slice) {
            Ok(true) => Some(Ok(())),
            Ok(false) => None,
            Err(failure) => Some(Err(failure)),
        },
        || {},
    )?
    .map_err(|f| fault(py, f))
}

/// `binbun._talk.Author(key, via)`: who acted, an identity key
/// (hexadecimal) and as whom (`user`, `script:<name>`, `agent`, ...).
pub(crate) fn author<'py>(py: Python<'py>, key: &str, via: &str) -> PyResult<Bound<'py, PyAny>> {
    py.import("binbun._talk")?
        .getattr("Author")?
        .call1((key, via))
}

/// A change in the history: what it did, who made it, when.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Clone, Debug)]
pub(crate) struct HistoryEntry {
    /// The change's id (its author's chain and its number there); empty
    /// for a private bookmark's edit undone or made again alone (the
    /// GUI's, local: no change).
    #[pyo3(get)]
    id: String,
    /// What it did (`Rename crypto helpers`, `Undo: Comment`).
    #[pyo3(get)]
    label: String,
    /// As whom it was made: `user`, `script:<name>`, `plugin:<id>`,
    /// `agent`, or an undo's or redo's.
    via: String,
    /// Its author's identity key, hexadecimal.
    key: String,
    /// When, in seconds since the Unix epoch.
    #[pyo3(get)]
    time: f64,
    /// How many edits it made.
    #[pyo3(get)]
    edits: usize,
    /// Whether this install made it.
    #[pyo3(get)]
    mine: bool,
    /// What an undo or redo left alone (changed by someone since).
    #[pyo3(get)]
    skipped: Vec<String>,
    /// Who made the suggestion it accepted, if it accepted one: key and
    /// as whom.
    suggested_by: Option<(String, String)>,
}

impl From<HistoryItem> for HistoryEntry {
    fn from(item: HistoryItem) -> Self {
        #[expect(clippy::cast_precision_loss, reason = "milliseconds since 1970 fit")]
        let time = item.millis as f64 / 1000.0;
        Self {
            id: item.id,
            label: item.label,
            via: item.author,
            key: item.key,
            time,
            edits: item.edits,
            mine: item.mine,
            skipped: item.skipped,
            suggested_by: item.suggested_by.map(|by| (by.key, by.author)),
        }
    }
}

#[pymethods]
impl HistoryEntry {
    fn __repr__(&self) -> String {
        format!(
            "HistoryEntry({:?} by {}, {} edits)",
            self.label, self.via, self.edits
        )
    }

    /// Who made it: a `binbun.Author` (`via`: `user`, `script:<name>`,
    /// `plugin:<id>`, `agent`, or `undo`, `redo`, `accept`...).
    #[getter]
    fn author<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        author(py, &self.key, &self.via)
    }

    /// Who made the suggestion it accepted, if it accepted one (a
    /// `binbun.Author`; `author` is then the person who accepted it, via
    /// `accept`).
    #[getter]
    fn suggested_by<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.suggested_by
            .as_ref()
            .map(|(key, via)| author(py, key, via))
            .transpose()
    }
}

/// A change as the protocol states it (`suggestions.accept`'s `entry`), as
/// a [`HistoryEntry`].
///
/// # Errors
///
/// It is not one.
#[pyfunction]
pub(crate) fn _history_entry(py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<HistoryEntry> {
    let item: HistoryItem = serde_json::from_value(from_python(py, Some(data))?)
        .map_err(|error| PyValueError::new_err(format!("not a change: {error}")))?;
    Ok(HistoryEntry::from(item))
}

/// A transaction (`with db.transaction(label):`): one undo step of the
/// writes made in it on this thread, rolled back if an exception leaves
/// it; an inner one joins the outer. Corrections made in it are analysed
/// anew once, at commit; with `wait`, leaving it returns once the new
/// analysis is swapped in.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Transaction {
    db: Arc<Db>,
    /// What it does.
    #[pyo3(get)]
    label: String,
    origin: Origin,
    wait: bool,
    /// The change it made, once committed.
    entry: Mutex<Option<HistoryEntry>>,
}

impl Transaction {
    /// A transaction of `db` labelled `label`, made by `author` (`None`:
    /// the script).
    ///
    /// # Errors
    ///
    /// `author` names no origin.
    pub(crate) fn new(
        py: Python<'_>,
        db: &Arc<Db>,
        label: &str,
        author: Option<&str>,
        wait: bool,
    ) -> PyResult<Self> {
        Ok(Self {
            db: Arc::clone(db),
            label: label.to_owned(),
            origin: origin(py, author)?,
            wait,
            entry: Mutex::new(None),
        })
    }
}

#[pymethods]
impl Transaction {
    fn __enter__(slf: Bound<'_, Self>) -> PyResult<Bound<'_, Self>> {
        let py = slf.py();
        let this = slf.get();
        if recording(&this.db) {
            return Err(drafting(py, "a transaction"));
        }
        if let Some(link) = this.db.link() {
            link.begin(py, &this.label, &this.origin)?;
            return Ok(slf);
        }
        let host = this.db.host(py)?;
        host.begin(owner(), &this.label, this.origin.clone(), None)
            .map_err(|f| fault(py, f))?;
        Ok(slf)
    }

    #[pyo3(signature = (exc_type, _exc = None, _traceback = None))]
    fn __exit__(
        &self,
        py: Python<'_>,
        exc_type: Option<&Bound<'_, PyAny>>,
        _exc: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        let failed = exc_type.is_some_and(|exc| !exc.is_none());
        if let Some(link) = self.db.link() {
            if failed {
                link.rollback(py)?;
                return Ok(false);
            }
            let committed = link.commit(py)?;
            *self.entry.lock().unwrap_or_else(PoisonError::into_inner) =
                committed.entry.map(HistoryEntry::from);
            if committed.reanalysing && self.wait {
                link.settle(py)?;
            }
            return Ok(false);
        }
        let host = self.db.host(py)?;
        let owner = owner();
        if failed {
            host.rollback(owner).map_err(|f| fault(py, f))?;
            return Ok(false);
        }
        let committed = py.detach(|| host.commit(owner)).map_err(|f| fault(py, f))?;
        *self.entry.lock().unwrap_or_else(PoisonError::into_inner) =
            committed.entry.map(HistoryEntry::from);
        if committed.reanalysing && self.wait {
            settle(py, &host)?;
        }
        Ok(false)
    }

    /// Who makes it: `script:<name>` unless given.
    #[getter]
    fn author(&self) -> String {
        self.origin.to_string()
    }

    /// The change it made, once committed (`None` before, for an inner
    /// transaction, or if it wrote nothing).
    #[getter]
    fn entry(&self) -> Option<HistoryEntry> {
        self.entry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn __repr__(&self) -> String {
        format!("<binbun.Transaction {:?} by {}>", self.label, self.origin)
    }
}

/// Undoes (or with `redo`, makes again) this install's last change of
/// `db`, waiting for a new analysis if a correction was undone.
///
/// # Errors
///
/// A transaction is open; Ctrl-C while waiting.
pub(crate) fn replay(
    py: Python<'_>,
    db: &Arc<Db>,
    redo: bool,
    wait: bool,
) -> PyResult<Option<HistoryEntry>> {
    if recording(db) {
        return Err(drafting(py, if redo { "a redo" } else { "an undo" }));
    }
    if let Some(link) = db.link() {
        let done = link.replay(py, redo)?;
        if wait {
            link.settle(py)?;
        }
        return Ok(done.map(HistoryEntry::from));
    }
    let host = db.host(py)?;
    let done = py
        .detach(|| if redo { host.redo() } else { host.undo() })
        .map_err(|f| fault(py, f))?;
    if wait {
        settle(py, &host)?;
    }
    Ok(done.map(HistoryEntry::from))
}

/// The history of `db`, newest first.
///
/// # Errors
///
/// The database is closed.
pub(crate) fn history(py: Python<'_>, db: &Arc<Db>) -> PyResult<Vec<HistoryEntry>> {
    if let Some(link) = db.link() {
        return Ok(link
            .history(py)?
            .into_iter()
            .map(HistoryEntry::from)
            .collect());
    }
    Ok(db
        .host(py)?
        .history()
        .into_iter()
        .map(HistoryEntry::from)
        .collect())
}

/// A member of a [`StructLayout`].
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Clone, Debug)]
pub(crate) struct StructMember {
    /// Its name (empty: an anonymous struct or union).
    name: String,
    /// Its offset in bits.
    bit_offset: u64,
    /// Its size in bytes.
    size: u64,
    /// A bit-field's width in bits.
    bit_width: Option<u32>,
}

/// A struct's layout as C defines it (`db.types.layout`).
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Clone, Debug)]
pub(crate) struct StructLayout {
    /// Its key (`struct pair`).
    key: String,
    /// Its size in bytes.
    size: u64,
    /// Its members, in order.
    members: Vec<StructMember>,
}

impl From<Layout> for StructLayout {
    fn from(layout: Layout) -> Self {
        Self {
            key: layout.key,
            size: layout.size,
            members: layout
                .members
                .into_iter()
                .map(|member| StructMember {
                    name: member.name,
                    bit_offset: member.bit_offset,
                    size: member.size,
                    bit_width: member.bit_width,
                })
                .collect(),
        }
    }
}

#[pymethods]
impl StructLayout {
    fn __repr__(&self) -> String {
        format!(
            "StructLayout({:?}, {} bytes, {} members)",
            self.key,
            self.size,
            self.members.len()
        )
    }
}

/// The user's types (`db.types`): definitions, globals' and synthesised
/// structs' types, members; C checked without writing.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Types {
    db: Arc<Db>,
}

impl Types {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }

    /// The session once analysed.
    fn session(&self, py: Python<'_>) -> PyResult<Arc<Session>> {
        self.db.analysed(py)
    }

    /// Changes member `member` of struct `key` by `edit`.
    fn edit_member(
        &self,
        py: Python<'_>,
        key: String,
        member: String,
        edit: Member,
    ) -> PyResult<()> {
        write(py, &self.db, &Write::Member { key, member, edit }).map(drop)
    }
}

/// What `target` types: a `Function` (its prototype), a `CVariable`, or
/// an address (a global).
///
/// # Errors
///
/// It is none of those.
fn typed(target: &Bound<'_, PyAny>) -> PyResult<Typed> {
    if let Ok(function) = target.cast::<Function>() {
        return Ok(Typed::Prototype(function.get().entry));
    }
    if let Ok(variable) = target.cast::<CVariable>() {
        return Ok(Typed::Variable(variable.get().reference().identity()));
    }
    let Address(address) = target.extract()?;
    Ok(Typed::Global(address))
}

/// `c` refused by `error` as a `CDeclarationError`.
fn refused(py: Python<'_>, error: &Error, c: &str) -> PyErr {
    fault(py, Fault::session(error, Some(c)))
}

#[pymethods]
impl Types {
    /// Defines the struct, union, enumeration or typedef C `c` defines (the
    /// last, if several) as the user's; the key it defines (`struct
    /// pair`). `CDeclarationError` (with `.span`) if the C is refused.
    fn define(&self, py: Python<'_>, c: String) -> PyResult<String> {
        let applied = write(py, &self.db, &Write::Define { c })?;
        applied
            .key
            .ok_or_else(|| Raise::Binbun.err(py, "the definition defined nothing"))
    }

    /// Drops the user's definition of `key`.
    fn undefine(&self, py: Python<'_>, key: String) -> PyResult<()> {
        write(py, &self.db, &Write::Undefine { key }).map(drop)
    }

    /// Types the global at `ea` as C `c` (`None`: as analysis types it).
    fn set_global_type(&self, py: Python<'_>, ea: Address, c: Option<String>) -> PyResult<()> {
        write(py, &self.db, &Write::GlobalType { address: ea.0, c }).map(drop)
    }

    /// Gives a synthesised struct (its key, `struct struct_main_1`, or
    /// `(function entry, number)`) the user's definition `c` (`None`: the
    /// table's again).
    fn set_struct(
        &self,
        py: Python<'_>,
        r#struct: &Bound<'_, PyAny>,
        c: Option<String>,
    ) -> PyResult<()> {
        let (function, k) = if let Ok(key) = r#struct.extract::<String>() {
            let session = self.session(py)?;
            let listed = py.detach(|| session.synthesised()).unwrap_or_default();
            let found = listed
                .iter()
                .find(|s| s.key == key)
                .ok_or_else(|| Raise::Binbun.err(py, format!("no synthesised struct {key}")))?;
            (found.function, found.k)
        } else {
            let (Entry(function), k) = r#struct.extract::<(Entry, u32)>()?;
            (function, k)
        };
        write(py, &self.db, &Write::StructType { function, k, c }).map(drop)
    }

    /// Names member `member` of struct `key` (`struct pair`) `name` (a C
    /// identifier).
    fn rename_member(
        &self,
        py: Python<'_>,
        key: String,
        member: String,
        name: String,
    ) -> PyResult<()> {
        self.edit_member(py, key, member, Member::Rename(name))
    }

    /// Types member `member` of struct `key` as C `c`, as wide as it is.
    fn retype_member(
        &self,
        py: Python<'_>,
        key: String,
        member: String,
        c: String,
    ) -> PyResult<()> {
        self.edit_member(py, key, member, Member::Retype(c))
    }

    /// Types member `member` of struct `key` as C `c`, of any width the
    /// layout holds (the GUI's `D`).
    fn resize_member(
        &self,
        py: Python<'_>,
        key: String,
        member: String,
        c: String,
    ) -> PyResult<()> {
        self.edit_member(py, key, member, Member::Resize(c))
    }

    /// Whether C `c` can type `target` (a `Function`'s prototype, a
    /// `CVariable`, a global's address), without writing:
    /// `CDeclarationError` if not.
    fn check(&self, py: Python<'_>, target: &Bound<'_, PyAny>, c: &str) -> PyResult<()> {
        let typed = typed(target)?;
        let session = self.session(py)?;
        py.detach(|| session.check_type(&typed, c))
            .map_err(|error| refused(py, &error, c))
    }

    /// The layout of the struct C `c` defines, without defining it.
    fn layout(&self, py: Python<'_>, c: &str) -> PyResult<StructLayout> {
        let session = self.session(py)?;
        py.detach(|| session.struct_layout(c))
            .map(StructLayout::from)
            .map_err(|error| refused(py, &error, c))
    }

    /// The definition of `key` as C: the user's, else the type
    /// library's, if either defines it.
    fn definition(&self, py: Python<'_>, key: &str) -> PyResult<Option<String>> {
        Ok(self.db.session(py)?.definition_text(key))
    }

    /// The names a type may be written with, sorted.
    fn names(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        Ok(self.session(py)?.type_names())
    }

    /// The user's type of the global at `ea`, as C.
    fn get_global_type(&self, py: Python<'_>, ea: Address) -> PyResult<Option<String>> {
        Ok(self.db.session(py)?.type_of(&Typed::Global(ea.0)))
    }

    /// The user's definitions, by key: `binbun.Definition(key, c)`s
    /// (`names()` lists the type library's too).
    fn definitions<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let session = self.db.session(py)?;
        let edits = session.edits();
        edits
            .definitions()
            .iter()
            .map(|(key, c)| named(py, "Definition", (key.as_str(), c.as_str())))
            .collect()
    }
}

/// The user's corrections of recovery (`db.corrections`, the GUI's `C`, `U`,
/// `D`, `A`, `*`): each is a write; the binary is analysed anew with
/// them (once per transaction) and swapped in.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Corrections {
    db: Arc<Db>,
}

impl Corrections {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }

    /// Makes `correction`.
    fn make(&self, py: Python<'_>, correction: Correction) -> PyResult<()> {
        write(py, &self.db, &Write::Correction { correction }).map(drop)
    }
}

/// The value of `binbun.Unit` member `unit` (or its name).
fn unit_name(unit: &Bound<'_, PyAny>) -> PyResult<String> {
    unit.getattr("value")
        .unwrap_or_else(|_| unit.clone())
        .extract()
}

#[pymethods]
impl Corrections {
    /// Code from `ea` (the GUI's `C`).
    fn make_code(&self, py: Python<'_>, ea: Address) -> PyResult<()> {
        self.make(py, Correction::Code { address: ea.0 })
    }

    /// `count` units of `unit` (a `Unit`) at `ea` (the GUI's `D`, `*`).
    #[pyo3(signature = (ea, unit, count = 1))]
    fn make_data(
        &self,
        py: Python<'_>,
        ea: Address,
        unit: &Bound<'_, PyAny>,
        count: u64,
    ) -> PyResult<()> {
        let unit = unit_name(unit)?;
        self.make(
            py,
            Correction::Data {
                address: ea.0,
                unit,
                count,
            },
        )
    }

    /// The string the bytes at `ea` start, C or UTF-16 by what they are
    /// (the GUI's `A`).
    fn make_string(&self, py: Python<'_>, ea: Address) -> PyResult<()> {
        self.make(py, Correction::String { address: ea.0 })
    }

    /// `size` bytes from `ea` typed as nothing (the GUI's `U`).
    fn undefine(&self, py: Python<'_>, ea: Address, size: u64) -> PyResult<()> {
        self.make(
            py,
            Correction::Undefine {
                address: ea.0,
                size,
            },
        )
    }

    /// Drops the user's item starting at `ea`.
    fn clear(&self, py: Python<'_>, ea: Address) -> PyResult<()> {
        self.make(py, Correction::Clear { address: ea.0 })
    }

    /// The user's items: `binbun.CorrectedItem(address, kind, size)`s,
    /// kind `code`, `undefined` or a unit's name (`dword`, `string`);
    /// size in bytes.
    fn items<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let corrections = self.db.session(py)?.corrections();
        corrections
            .items()
            .iter()
            .map(|(&address, &item)| {
                let kind = match item {
                    Item::Code => "code",
                    Item::Undefined { .. } => "undefined",
                    Item::Data(data) => data.unit.name(),
                };
                named(py, "CorrectedItem", (address, kind, item.size()))
            })
            .collect()
    }

    /// The functions the user made or ended:
    /// `binbun.CorrectedFunction(start, end)`s (`end` `None`: where
    /// recovery ends it). Those deleted: `deleted()`.
    fn functions<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let corrections = self.db.session(py)?.corrections();
        corrections
            .functions()
            .iter()
            .filter_map(|(&entry, &bounds)| match bounds {
                Bounds::Function { end } => Some((entry, end)),
                Bounds::Deleted => None,
            })
            .map(|fields| named(py, "CorrectedFunction", fields))
            .collect()
    }

    /// The entries of the functions the user deleted.
    fn deleted(&self, py: Python<'_>) -> PyResult<Vec<u64>> {
        let corrections = self.db.session(py)?.corrections();
        Ok(corrections
            .functions()
            .iter()
            .filter(|&(_, &bounds)| bounds == Bounds::Deleted)
            .map(|(&entry, _)| entry)
            .collect())
    }
}
